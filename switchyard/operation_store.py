"""Private SQLite receipts, plans and placement intents, shared by broker processes."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid


def now():
    return datetime.now(timezone.utc).isoformat()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def process_identity(pid=None):
    pid = os.getpid() if pid is None else pid
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
        fields = text[text.rindex(")") + 2:].split()
        if fields[0] == "Z":
            return None
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip() + ":" + fields[19]
    except (OSError, ValueError, IndexError):
        return None


# Store metadata key (workload store) recording that the journal's old `workloads` placement table was moved.
MIGRATION_KEY = "managed_placements_migration"


def legacy_placements(db):
    """Rows of the journal's old placement table (before 2026-11-23 placements moved to the workload store)."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='workloads'").fetchone():
        return []
    return [[row[0], row[1], row[2]] for row in db.execute("SELECT id, ownership_id, placement FROM workloads ORDER BY id")]


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("Operation state must be an owned private directory")
        self.directory.chmod(0o700)
        self.path = self.directory / "operations.sqlite3"
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError("Operation store must be an owned private regular file")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        with self._transaction() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value INTEGER NOT NULL);
                INSERT OR IGNORE INTO metadata VALUES('revision',0);
                CREATE TABLE IF NOT EXISTS plans(id TEXT PRIMARY KEY, data TEXT NOT NULL,
                    fingerprint TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL,
                    intent_hash TEXT NOT NULL, receipt TEXT NOT NULL, pid INTEGER NOT NULL, birth TEXT);
                CREATE INDEX IF NOT EXISTS operations_status ON operations(json_extract(receipt,'$.status'));
                CREATE TABLE IF NOT EXISTS placement_intents(id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workload_id TEXT NOT NULL, sequence INTEGER NOT NULL, ownership_id TEXT NOT NULL,
                    placement TEXT, recorded_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS fleet_keys(id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS lifecycle_inspections(workload_id TEXT PRIMARY KEY,
                    authority_fingerprint TEXT NOT NULL, inspection TEXT NOT NULL,
                    inspected_at TEXT NOT NULL, revision TEXT NOT NULL);
            ''')
            legacy = legacy_placements(db)
        # Managed placements live in the workload store beside this journal (deploy.sqlite3).
        from .workload_store import WorkloadStore
        self.workloads = WorkloadStore(self.directory)
        self._legacy_problem = None
        if legacy:
            with self.workloads.reading() as wdb:
                moved = WorkloadStore.meta(wdb, MIGRATION_KEY)
            if moved is None:
                self._legacy_problem = (
                    f"Managed placements are still in the operation journal ({self.path}, table workloads). Move them "
                    "into the workload store once with `switchyard migrate-operations` (it also converts the operations "
                    "policy file); nothing reads or changes a managed placement until then")
            elif moved["legacy_sha256"] != digest(legacy):
                self._legacy_problem = (
                    f"The operation journal's old placement table ({self.path}, table workloads) changed after it was "
                    "moved into the workload store, so older code has acted on this state since; inspect both before "
                    "any managed operation")
        if self._legacy_problem is None:
            self.drain()

    @contextmanager
    def _transaction(self):
        db = sqlite3.connect(self.path, timeout=3, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @contextmanager
    def transaction(self):
        """One journal transaction. Placement intents it records are applied to the workload store right after
        it commits (and, if this process dies first, by the next process that opens the journal)."""
        with self._transaction() as db:
            yield db
            pending = db.execute("SELECT EXISTS(SELECT 1 FROM placement_intents)").fetchone()[0]
        if pending:
            self.drain()

    # Managed placements -------------------------------------------------------------------------------------------
    # The placement's one home is the workload store (`managed_placements`). A change is recorded here as an intent
    # in the same transaction as the receipt that explains it, then applied to the store and removed. Readers
    # inside a journal transaction see the latest unapplied intent first, so a crash between the two commits never
    # shows a placement that disagrees with its receipt; the next open applies what is left.
    def _check_legacy(self):
        if self._legacy_problem:
            raise ValueError(self._legacy_problem)

    def placement(self, db, workload_id):
        """`{ownership_id, placement, sequence}` of a managed workload inside journal transaction `db`, or None."""
        self._check_legacy()
        row = db.execute("SELECT ownership_id, placement, sequence FROM placement_intents WHERE workload_id=? "
                         "ORDER BY id DESC LIMIT 1", (workload_id,)).fetchone()
        if row is not None:
            return {"ownership_id": row[0], "placement": json.loads(row[1]) if row[1] else None, "sequence": row[2]}
        with self.workloads.reading() as wdb:
            return self.workloads.managed_placement(wdb, workload_id)

    def placements(self, db):
        """Every recorded managed placement, `{workload_id: placement}`, inside journal transaction `db`."""
        self._check_legacy()
        with self.workloads.reading() as wdb:
            current = {key: value["placement"] for key, value in self.workloads.managed_placement_rows(wdb).items()}
        for row in db.execute("SELECT workload_id, placement FROM placement_intents ORDER BY id"):
            current[row[0]] = json.loads(row[1]) if row[1] else None
        return {key: value for key, value in current.items() if value is not None}

    def ownership(self, db, workload_id):
        """The managed workload's `{ownership_id, placement}`, giving it an ownership ID first if it has none."""
        found = self.placement(db, workload_id)
        if found is None:
            found = {"ownership_id": self.workloads.ensure_ownership(workload_id, str(uuid.uuid4())),
                     "placement": None, "sequence": 0}
        return found

    def record_placement(self, db, workload_id, placement):
        """Record a placement change in journal transaction `db` (the receipt's own transaction)."""
        current = self.placement(db, workload_id)
        if current is None or current["placement"] == placement:
            return
        db.execute("INSERT INTO placement_intents(workload_id,sequence,ownership_id,placement,recorded_at) VALUES(?,?,?,?,?)",
                   (workload_id, current["sequence"] + 1, current["ownership_id"],
                    None if placement is None else encode(placement), now()))

    def drain(self):
        """Apply recorded placement intents to the workload store, then forget them. Idempotent."""
        self._check_legacy()
        with self._transaction() as db:
            intents = [tuple(row) for row in db.execute(
                "SELECT id, sequence, workload_id, ownership_id, placement FROM placement_intents ORDER BY id")]
        if not intents:
            return
        self.workloads.apply_placement_intents([intent[1:] for intent in intents])
        with self._transaction() as db:
            db.execute("DELETE FROM placement_intents WHERE id <= ?", (intents[-1][0],))

    @staticmethod
    def bump(db):
        db.execute("UPDATE metadata SET value=value+1 WHERE key='revision'")

    def reconcile(self, db):
        for row in db.execute("SELECT * FROM operations WHERE json_extract(receipt,'$.status')='running'").fetchall():
            receipt = json.loads(row["receipt"])
            if receipt["status"] == "running" and (not row["birth"] or process_identity(row["pid"]) != row["birth"]):
                self.finish(db, row["id"], {"status": "needs-inspection",
                    "error": "Operation worker interrupted; inspect remote effects before another action"})

    def get(self, operation_id):
        with self.transaction() as db:
            self.reconcile(db)
            row = db.execute("SELECT receipt FROM operations WHERE id=?", (operation_id,)).fetchone()
            if row is None:
                raise ValueError("Unknown operation receipt")
            return json.loads(row[0])

    def event(self, operation_id, event, data):
        # Only trusted structured lifecycle metadata is accepted by the internal worker.
        encoded = encode(data)
        if len(encoded.encode()) > 16384 or not isinstance(event, str) or len(event) > 80:
            raise ValueError("Operation event exceeds metadata bounds")
        with self.transaction() as db:
            row = db.execute("SELECT receipt FROM operations WHERE id=?", (operation_id,)).fetchone()
            receipt = json.loads(row[0])
            if receipt["status"] != "running":
                raise RuntimeError("Operation is no longer active")
            if len(receipt["events"]) >= 128:
                raise ValueError("Operation event limit exceeded")
            receipt["events"].append({"at": now(), "event": event, "data": data})
            workload_id = receipt.get("workload_id")
            if event == "recovery-intent" and workload_id:
                current = self.placement(db, workload_id)
                if current and current["placement"]:
                    self.record_placement(db, workload_id, {**current["placement"], "recovery": data,
                                                            "lifecycle": "unknown", "uncertain": True})
            if event == "deployment-intent" and workload_id:
                self.record_placement(db, workload_id, {**data, "lifecycle": "unknown", "uncertain": True})
            db.execute("UPDATE operations SET receipt=? WHERE id=?", (encode(receipt), operation_id))
            self.bump(db)

    def finish(self, db, operation_id, result):
        row = db.execute("SELECT receipt FROM operations WHERE id=?", (operation_id,)).fetchone()
        receipt = json.loads(row[0])
        if receipt["status"] != "running":
            return receipt
        status = result.get("status")
        if status not in {"succeeded", "failed", "busy", "needs-inspection"}:
            status = "needs-inspection"
        receipt.update(status=status, finished_at=now())
        for key in ("error", "exit_code"):
            if result.get(key) is not None:
                receipt[key] = result[key]
        if receipt["kind"] == "lifecycle":
            if result.get("inspection") is not None:
                if len(encode(result["inspection"]).encode()) > 65536:
                    raise ValueError("Lifecycle receipt inspection exceeds bounds")
                receipt["inspection"] = result["inspection"]
            for key in ("inspected_at", "inspection_fingerprint"):
                if key in result:
                    receipt[key] = result[key]
            if status in {"failed", "needs-inspection"}:
                db.execute("DELETE FROM lifecycle_inspections WHERE workload_id=?", (receipt.get("workload_id"),))
        workload_id = receipt.get("workload_id")
        if workload_id and receipt["kind"] == "managed":
            placement = result.get("placement")
            current = self.placement(db, workload_id)
            if placement is None and current and current["placement"]:
                placement = current["placement"]
            if placement is not None:
                if status == "needs-inspection":
                    placement = {**placement, "lifecycle": "unknown", "uncertain": True}
                elif result.get("placement") is not None and status == "succeeded":
                    placement = {**placement, "uncertain": bool(placement.get("uncertain", False))}
                self.record_placement(db, workload_id, placement)
        receipt["events"].append({"at": now(), "event": "finished", "data": {"status": status}})
        db.execute("UPDATE operations SET receipt=? WHERE id=?", (encode(receipt), operation_id))
        self.bump(db)
        return receipt
