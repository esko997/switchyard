"""Durable local lease authority. A reservation ends only on explicit completion or breakglass.

SQLite transactions cover state changes, never the work performed under a lease.
Historical ledgers are import sources, not a second locking authority.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
import uuid


class LeaseBusy(RuntimeError):
    pass


_ID = re.compile(r"[0-9a-f]{32}\Z")
_LABEL = re.compile(r"[A-Z0-9]{1,64}\Z")
_TERMINAL = {"released", "error", "completed", "broken", "cancelled", "failed"}


def boot_id():
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip() or None
    except OSError:
        return None


def process_started(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_bytes().rsplit(b")", 1)[1].split()
        return None if fields[0] == b"Z" else int(fields[19])
    except (OSError, ValueError, IndexError):
        return None


def resource_label(resource, path=None):
    name = Path(path).name if path is not None else ""
    if name.startswith("DEVICE_ACCESS_") and name.endswith(".md"):
        label = name[len("DEVICE_ACCESS_"):-3]
    else:
        label = re.sub(r"[^A-Z0-9]", "", resource.upper())
    return _label(label)


def _label(value):
    if not isinstance(value, str) or not _LABEL.fullmatch(value):
        raise ValueError("Invalid lease device label")
    return value


def _id(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("Invalid Switchyard lease ID")
    return value


def _text(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 4096 or any(ord(c) < 32 for c in value):
        raise ValueError("Lease evidence must be bounded nonempty text")
    return value


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _public(value, fields):
    """Only bounded scalar attribution crosses the read-only UI boundary."""
    result = {}
    for key in fields:
        item = value.get(key)
        if isinstance(item, str):
            item = "".join(c if ord(c) >= 32 and not 127 <= ord(c) <= 159 else " " for c in item).strip()[:512] or None
        elif item is not None and type(item) not in (bool, int):
            item = None
        result[key] = item
    return result


class LeaseStore:
    """Private SQLite state at ``root/leases.sqlite3``.

    ``allow_legacy`` permits opening an unmigrated store for ``import_legacy``;
    it never permits acquisition. ``legacy_dir`` explicitly identifies historical
    ledger directories; isolated stores never inspect global operator files.
    ``update`` retains the old mutable-dict callback API but cannot free a grant.
    """
    def __init__(self, root, *, allow_legacy=False, legacy_dir=None, legacy_paths=(), clock=time.time):
        self.directory = Path(root).absolute()
        self.root = self.directory
        self.path = self.directory / "leases.sqlite3"
        self.clock = clock
        if legacy_dir is None:
            self.legacy_dirs = ()
        elif isinstance(legacy_dir, (str, os.PathLike)):
            self.legacy_dirs = (Path(legacy_dir),)
        else:
            self.legacy_dirs = tuple(Path(path) for path in legacy_dir)
        self.legacy_paths = tuple(map(Path, legacy_paths))
        self._prepare()
        with self._transaction(guard=False) as db:
            for statement in (
                "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS leases (lease_id TEXT PRIMARY KEY, label TEXT, state TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS grants (label TEXT PRIMARY KEY, lease_id TEXT NOT NULL UNIQUE REFERENCES leases(lease_id))",
                "CREATE TABLE IF NOT EXISTS blocks (label TEXT PRIMARY KEY, state TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL, state TEXT NOT NULL)",
                "CREATE INDEX IF NOT EXISTS events_label ON events(label, sequence)",
                "CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'lease events are append-only'); END",
                "CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, 'lease events are append-only'); END",
            ):
                db.execute(statement)
            if not allow_legacy:
                self._guard(db)
                self._reconcile(db)

    def _prepare(self):
        self.directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.mkdir(mode=0o700, exist_ok=True)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Lease state directory must be private, owned and not a symlink")
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
            fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        for path in (self.path, *(Path(str(self.path) + suffix) for suffix in ("-journal", "-wal", "-shm"))):
            try:
                info = path.lstat()
            except FileNotFoundError:
                if path == self.path:
                    raise
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                raise ValueError("Lease database must be a private owned regular file without links")

    @contextmanager
    def _transaction(self, *, guard=True):
        self._prepare()
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("BEGIN IMMEDIATE")
            if guard:
                self._guard(db)
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _has_legacy(self):
        if (any(self.directory.glob("*.json")) or any(self.directory.glob("*.jsonl"))
                or any(path.exists() or path.is_symlink() for path in self.legacy_paths)):
            return True
        for directory in self.legacy_dirs:
            if any(directory.glob("DEVICE_ACCESS_*.md")):
                return True
        return False

    def _guard(self, db):
        migrated = db.execute("SELECT value FROM metadata WHERE key='legacy_import'").fetchone()
        if migrated is None and self._has_legacy():
            raise ValueError("Legacy lease state or source history requires explicit migration before using SQLite leases")

    def _now(self):
        return datetime.fromtimestamp(self.clock(), timezone.utc).isoformat()

    def _event(self, db, label, event, state=None, **extra):
        record = {**(state or {}), **extra, "at": self._now(), "event": event, "resource": label, "device": label}
        db.execute("INSERT INTO events(label,state) VALUES (?,?)", (label, _json(record)))
        return record

    @staticmethod
    def _read(db, lease_id):
        row = db.execute("SELECT state FROM leases WHERE lease_id=?", (lease_id,)).fetchone()
        if row is None:
            raise FileNotFoundError(lease_id)
        return json.loads(row[0])

    @staticmethod
    def _save(db, value):
        db.execute("UPDATE leases SET label=?,state=? WHERE lease_id=?", (value.get("device"), _json(value), value["lease_id"]))

    def _suspect(self, db, value, cause):
        value.update(status="suspect", suspect=True, suspect_since=value.get("suspect_since") or self._now(), suspect_cause=cause)
        self._save(db, value)
        self._event(db, value["device"], "SUSPECT", value, cause=cause)
        return value

    def _reconcile(self, db):
        for (raw,) in db.execute("SELECT l.state FROM grants g JOIN leases l ON l.lease_id=g.lease_id").fetchall():
            value = json.loads(raw)
            if value.get("suspect") or value.get("status") == "suspect":
                continue
            cause = None
            if value.get("expires_at") is not None:
                try:
                    expiry = datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
                    if expiry.tzinfo is None:
                        raise ValueError("Expiry must include timezone")
                    if expiry.timestamp() <= self.clock():
                        cause = "lease expired without confirmed completion"
                except (ValueError, TypeError, AttributeError, OverflowError):
                    cause = "lease expiry cannot be verified"
            if cause is None:
                current_boot = boot_id()
                if not current_boot or value.get("boot_id") != current_boot:
                    cause = "holder boot identity changed or cannot be verified"
                elif not (value.get("detached") is True and value.get("mode") == "hold"):
                    if not isinstance(value.get("pid"), int) or value["pid"] <= 0 or value.get("pid_started") is None:
                        cause = "holder process identity cannot be verified"
                    elif process_started(value["pid"]) != value["pid_started"]:
                        cause = "holder process exited or its identity changed"
            if cause is not None:
                self._suspect(db, value, cause)

    def claim(self, state):
        value = dict(state)
        token, label = _id(value.get("lease_id")), _label(value.get("device"))
        busy = None
        with self._transaction() as db:
            self._reconcile(db)
            block = db.execute("SELECT state FROM blocks WHERE label=?", (label,)).fetchone()
            grant = db.execute("SELECT lease_id FROM grants WHERE label=?", (label,)).fetchone()
            if block:
                busy = LeaseBusy(f"{label}: blocked pending operator attestation: {json.loads(block[0]).get('reason') or 'unknown outcome'}")
            elif grant:
                holder = self._read(db, grant[0])
                busy = LeaseBusy(f"{label}: held by {holder.get('owner') or 'unknown owner'} ({holder.get('status')}; lease {grant[0]})")
            else:
                previous = db.execute("SELECT state FROM leases WHERE lease_id=?", (token,)).fetchone()
                if previous:
                    old = json.loads(previous[0])
                    if old.get("device") not in (None, label) or old.get("status") not in ("starting", "acquiring"):
                        raise ValueError("Lease ID already used")
                    value = {**old, **value}
                value.update(status="claimed", claimed_at=self._now())
                value.setdefault("boot_id", boot_id())
                if value.get("pid") == os.getpid() and value.get("pid_started") is None:
                    value["pid_started"] = process_started(os.getpid())
                db.execute("INSERT INTO leases(lease_id,label,state) VALUES (?,?,?) ON CONFLICT(lease_id) DO UPDATE SET label=excluded.label,state=excluded.state", (token, label, _json(value)))
                db.execute("INSERT INTO grants(label,lease_id) VALUES (?,?)", (label, token))
                self._event(db, label, "CLAIM", value)
        if busy is not None:
            raise busy
        return value

    def read(self, lease_id):
        _id(lease_id)
        with self._transaction() as db:
            self._reconcile(db)
            return self._read(db, lease_id)

    def update(self, lease_id, change, *, create=False):
        _id(lease_id)
        with self._transaction() as db:
            if create:
                if db.execute("SELECT 1 FROM leases WHERE lease_id=?", (lease_id,)).fetchone():
                    raise ValueError("Lease ID already exists")
                value = {"lease_id": lease_id}
            else:
                value = self._read(db, lease_id)
            old_label = value.get("device")
            uncertainty = {key: value.get(key) for key in ("suspect", "suspect_since", "suspect_cause")}
            change(value)
            if value.get("lease_id") != lease_id:
                raise ValueError("Cannot change lease ID")
            label = value.get("device")
            if label is not None:
                _label(label)
            if old_label is not None and label != old_label:
                raise ValueError("Cannot change lease device")
            granted = db.execute("SELECT 1 FROM grants WHERE lease_id=?", (lease_id,)).fetchone()
            if granted and uncertainty["suspect"]:
                value.update(uncertainty, status="suspect")
            elif granted and value.get("status") not in {"claimed", "suspect"}:
                value.update(status="suspect", suspect=True, suspect_since=self._now(),
                             suspect_cause="state changed without explicit confirmed completion")
            if create:
                db.execute("INSERT INTO leases(lease_id,label,state) VALUES (?,?,?)", (lease_id, label, _json(value)))
            else:
                self._save(db, value)
            if label is not None:
                self._event(db, label, "UPDATE", value)
            return value

    def records(self):
        with self._transaction() as db:
            self._reconcile(db)
            return [json.loads(row[0]) for row in db.execute("SELECT state FROM leases ORDER BY rowid")]

    def current(self, label):
        _label(label)
        with self._transaction() as db:
            self._reconcile(db)
            row = db.execute("SELECT lease_id FROM grants WHERE label=?", (label,)).fetchone()
            return self._read(db, row[0]) if row else None

    def block(self, label):
        _label(label)
        with self._transaction() as db:
            row = db.execute("SELECT state FROM blocks WHERE label=?", (label,)).fetchone()
            return json.loads(row[0]) if row else None

    def suspect(self, lease_id, cause):
        _id(lease_id)
        _text(cause)
        with self._transaction() as db:
            value = self._read(db, lease_id)
            label = value.get("device")
            grant = db.execute("SELECT lease_id FROM grants WHERE label=?", (label,)).fetchone()
            if not grant and value.get("status") in {"starting", "acquiring"}:
                _label(label)
                if not db.execute("SELECT 1 FROM blocks WHERE label=?", (label,)).fetchone():
                    db.execute("INSERT INTO grants(label,lease_id) VALUES (?,?)", (label, lease_id))
            elif grant and grant[0] != lease_id:
                if value.get("status") not in {"starting", "acquiring"}:
                    return value
            elif not grant:
                return value
            return self._suspect(db, value, cause)

    def finish(self, lease_id, *, reason, outcome="completed", details=None):
        _id(lease_id)
        _text(reason)
        _text(outcome)
        with self._transaction() as db:
            value = self._read(db, lease_id)
            removed = db.execute("DELETE FROM grants WHERE label=? AND lease_id=?", (value.get("device"), lease_id)).rowcount
            if not removed and value.get("status") not in {"starting", "acquiring"}:
                return False
            value.update(status="released", outcome=outcome, reason=reason, released_at=self._now())
            if details is not None:
                value["details"] = details
                if isinstance(details, dict):
                    value.update({key: details[key] for key in ("error", "busy") if key in details})
            self._save(db, value)
            self._event(db, value["device"], "RELEASE", value, details=details)
            return bool(removed)

    def break_device(self, label, *, reason, operator, attest_stopped=None, expected_id=None):
        _label(label)
        _text(reason)
        _text(operator)
        if attest_stopped is not None:
            _text(attest_stopped)
        if expected_id is not None:
            _id(expected_id)
        with self._transaction() as db:
            row = db.execute("SELECT lease_id FROM grants WHERE label=?", (label,)).fetchone()
            token = row[0] if row else None
            if expected_id is not None and token != expected_id:
                raise LeaseBusy(f"{label}: current lease changed; inspect again before breaking")
            existing = db.execute("SELECT state FROM blocks WHERE label=?", (label,)).fetchone()
            revoked = []
            if token:
                value = self._read(db, token)
                value.update(status="broken", reason=reason, outcome="broken", released_at=self._now(), broken_by=operator)
                self._save(db, value)
                revoked.append(value)
                db.execute("DELETE FROM grants WHERE label=? AND lease_id=?", (label, token))
            blocked = attest_stopped is None or existing is not None
            record = self._event(db, label, "BREAK", lease_id=token, operator=operator, reason=reason,
                                 revoked=revoked, blocked=blocked, attested_stopped=attest_stopped is not None,
                                 attestation=attest_stopped, block_id=uuid.uuid4().hex)
            if attest_stopped is None:
                db.execute("INSERT INTO blocks(label,state) VALUES (?,?) ON CONFLICT(label) DO UPDATE SET state=excluded.state", (label, _json(record)))
            return record

    def clear(self, label, *, operator, attest_stopped, expected_block):
        _label(label)
        _text(operator)
        _text(attest_stopped)
        with self._transaction() as db:
            row = db.execute("SELECT state FROM blocks WHERE label=?", (label,)).fetchone()
            block = json.loads(row[0]) if row else None
            if block is None or expected_block is None or block != expected_block:
                raise LeaseBusy(f"{label}: block changed; inspect again before clearing")
            record = self._event(db, label, "CLEAR", lease_id=block.get("lease_id"), operator=operator,
                                 attestation=attest_stopped, break_at=block.get("at"), block_id=block.get("block_id"))
            db.execute("DELETE FROM blocks WHERE label=?", (label,))
            return record

    def rows(self, labels):
        with self._transaction() as db:
            self._reconcile(db)
            rows = []
            for label, path in labels.items():
                _label(label)
                grant = db.execute("SELECT lease_id FROM grants WHERE label=?", (label,)).fetchone()
                current = self._read(db, grant[0]) if grant else None
                block = db.execute("SELECT state FROM blocks WHERE label=?", (label,)).fetchone()
                entries = [_public(json.loads(row[0]), ("at", "event", "owner", "scope"))
                           for row in db.execute("SELECT state FROM events WHERE label=? ORDER BY sequence DESC LIMIT 12", (label,))][::-1]
                holders = []
                public_lease = None
                if current:
                    holders.append(_public(current, ("pid", "owner", "paseo_agent_id"))
                                   | {"verified": not current.get("suspect", False)})
                    public_lease = _public(current, ("lease_id", "owner", "scope", "expires_at", "holder_unit"))
                    if current.get("suspect"):
                        public_lease.update(_public(current, ("suspect", "suspect_since", "suspect_cause")))
                public_block = None
                if block:
                    block = json.loads(block[0])
                    public_block = _public(block, ("device", "at", "operator", "reason", "pending", "error"))
                    public_block["revoked"] = [_public(item, ("lease_id", "owner", "scope", "mode", "pid", "suspect", "suspect_cause", "ended"))
                                               for item in block.get("revoked") or [] if isinstance(item, dict)]
                rows.append({"device": label, "path": str(path) if path is not None else None,
                             "state": "held" if current else "free", "status": current.get("status") if current else "free",
                             "holders": holders, "switchyard_lease": public_lease, "current": public_lease,
                             "blocked": public_block, "last_entries": entries, "anomaly": None})
            return {"observed_at": self._now(), "authority": "sqlite", "ledgers": rows}

    def history(self, limit=100):
        if type(limit) is not int or not 1 <= limit <= 10000:
            raise ValueError("History limit must be 1-10000 per resource")
        with self._transaction() as db:
            return [json.loads(row[0]) for row in db.execute(
                "SELECT state FROM (SELECT state,sequence,ROW_NUMBER() OVER (PARTITION BY label ORDER BY sequence DESC) AS n FROM events) WHERE n<=? ORDER BY sequence DESC", (limit,))]

    def import_legacy(self, rows, blocks, events):
        """Atomically import once; identical retries are harmless, changed retries fail.

        Rows are old lease dictionaries. Blocks may be a list of dictionaries or
        a label-to-block mapping. Events are dictionaries with ``device`` or
        ``resource`` labels; their original fields (including human text) survive.
        Every unresolved legacy lease is suspect. Ambiguous same-label holders
        produce a persistent block retaining all conflicting IDs as evidence.
        """
        rows, events = list(rows), list(events)
        if isinstance(blocks, dict):
            blocks = [{**value, "device": label} for label, value in blocks.items()]
        else:
            blocks = list(blocks)
        fingerprint = hashlib.sha256(_json({"rows": rows, "blocks": blocks, "events": events}).encode()).hexdigest()
        with self._transaction(guard=False) as db:
            previous = db.execute("SELECT value FROM metadata WHERE key='legacy_import'").fetchone()
            if previous:
                if previous[0] != fingerprint:
                    raise ValueError("Legacy leases were already migrated from different input")
                return False
            if db.execute("SELECT 1 FROM leases UNION ALL SELECT 1 FROM blocks UNION ALL SELECT 1 FROM events LIMIT 1").fetchone():
                raise ValueError("Cannot import legacy leases into a nonempty authority")
            candidates = {}
            for source in rows:
                value = dict(source)
                token, label = _id(value.get("lease_id")), _label(value.get("device"))
                if value.get("status") not in _TERMINAL:
                    value.update(status="suspect", suspect=True, suspect_since=self._now(), suspect_cause="legacy lease imported without confirmed completion")
                    candidates.setdefault(label, []).append(token)
                db.execute("INSERT INTO leases(lease_id,label,state) VALUES (?,?,?)", (token, label, _json(value)))
            for source in events:
                value = dict(source)
                label = _label(value.get("device") or value.get("resource"))
                value.setdefault("at", self._now())
                db.execute("INSERT INTO events(label,state) VALUES (?,?)", (label, _json(value)))
            block_map = {}
            for source in blocks:
                value = dict(source)
                label = _label(value.get("device") or value.get("resource"))
                value.update(device=label)
                value.setdefault("at", self._now())
                value.setdefault("block_id", uuid.uuid4().hex)
                block_map[label] = value
            for label, tokens in candidates.items():
                if len(tokens) == 1 and label not in block_map:
                    db.execute("INSERT INTO grants(label,lease_id) VALUES (?,?)", (label, tokens[0]))
                elif len(tokens) > 1:
                    block_map[label] = {**block_map.get(label, {}), "device": label, "at": self._now(),
                                        "block_id": uuid.uuid4().hex, "reason": "ambiguous legacy reservations",
                                        "lease_ids": tokens, "pending": True}
            for label, value in block_map.items():
                db.execute("INSERT INTO blocks(label,state) VALUES (?,?)", (label, _json(value)))
            for label in sorted(set(candidates) | set(block_map)):
                self._event(db, label, "IMPORT", lease_ids=candidates.get(label, []), blocked=label in block_map)
            db.execute("INSERT INTO metadata(key,value) VALUES ('legacy_import',?)", (fingerprint,))
            return True
