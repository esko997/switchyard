"""The workload store: the one authority for which workloads exist and how Switchyard relates to each.

One private SQLite database (`deploy.sqlite3` in the broker store directory, its historical name) holds every
workload as a revisioned record in the workload-spec format, with one `relation`:

- `observed`: Switchyard only watches it (a Bundle: one Application with observed components, one declared
  adopted Placement binding its units and containers);
- `registered`: described by its owner, no lifecycle authority, may hold start tokens (the owner's Bundle);
- `deployed`: Switchyard created it and holds its placements (the instance Application; placements, port
  claims, verifications and generation journal in their own tables, written by the leased worker).

Templates, application groups and store metadata live here too. Current records are in `workloads`; every
revision, byte for byte, in `workload_revisions`. Records change only by compare-and-swap on their revision;
the whole store has a content revision (`revision()`) for callers that edit against a snapshot.
Stored v1alpha2 records are upgraded in memory on read; their stored bytes and hashes stay.
No transaction spans a remote call.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
from ipaddress import ip_address
import json
import os
from pathlib import Path
import sqlite3
import stat

from . import spec
from .operation_store import encode, now

GATE_ID = "generation-gate"  # the one gate Switchyard generates for a deployed .kube component

WILDCARDS = {"0.0.0.0", "::"}
RELATIONS = ("observed", "registered", "deployed")
# Tables of the separate instance and registration journals this store replaced (2026-11-23). Seeding copies
# them once into `workloads`; they stay untouched afterwards so the seed can be undone.
LEGACY_TABLES = ("instances", "instance_revisions", "registrations")


def family(address):
    return 6 if ip_address(address).version == 6 else 4


def overlaps(a_address, b_address):
    """Wildcards of either family conflict with everything (conservative dual-stack)."""
    return a_address == b_address or a_address in WILDCARDS or b_address in WILDCARDS


class WorkloadStore:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("Workload store must be an owned private directory")
        self.path = self.directory / "deploy.sqlite3"
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError("Workload store must be an owned private regular file")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        with self.transaction() as db:
            names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            # A journal from before the workload store: keep its exact pre-change file before adding any table.
            backup = self.backup("pre-store") if "workloads" not in names and set(LEGACY_TABLES) & names else None
            db.executescript('''
                CREATE TABLE IF NOT EXISTS workloads(id TEXT PRIMARY KEY,
                    relation TEXT NOT NULL CHECK(relation IN ('observed','registered','deployed')),
                    revision INTEGER NOT NULL, content_sha256 TEXT NOT NULL, template_id TEXT, template_revision INTEGER,
                    data TEXT NOT NULL, meta TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS workload_revisions(id TEXT NOT NULL, revision INTEGER NOT NULL,
                    relation TEXT NOT NULL CHECK(relation IN ('observed','registered','deployed')),
                    content_sha256 TEXT NOT NULL, data TEXT NOT NULL, meta TEXT NOT NULL, created_at TEXT NOT NULL,
                    PRIMARY KEY(id, revision));
                CREATE TABLE IF NOT EXISTS workload_groups(id TEXT PRIMARY KEY, position INTEGER NOT NULL, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS store_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS templates(id TEXT NOT NULL, revision INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL, data TEXT NOT NULL, saved_at TEXT NOT NULL,
                    PRIMARY KEY(id, revision));
                CREATE TABLE IF NOT EXISTS placements(instance_id TEXT NOT NULL, generation INTEGER NOT NULL,
                    host_id TEXT NOT NULL, state TEXT NOT NULL, data TEXT NOT NULL, meta TEXT NOT NULL,
                    revision INTEGER NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(instance_id, generation));
                CREATE TABLE IF NOT EXISTS claims(host_id TEXT NOT NULL, family INTEGER NOT NULL,
                    address TEXT NOT NULL, protocol TEXT NOT NULL, port INTEGER NOT NULL,
                    owner_kind TEXT NOT NULL CHECK(owner_kind IN ('plan','placement')), owner_id TEXT NOT NULL,
                    endpoint TEXT NOT NULL, generation INTEGER NOT NULL, expires_at TEXT,
                    PRIMARY KEY(host_id, address, protocol, port, owner_kind, owner_id));
                CREATE TABLE IF NOT EXISTS inspections(operation_id TEXT PRIMARY KEY, data TEXT NOT NULL,
                    created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS verifications(instance_id TEXT NOT NULL, generation INTEGER NOT NULL,
                    operation_id TEXT NOT NULL, data TEXT NOT NULL, verified_at TEXT NOT NULL,
                    PRIMARY KEY(instance_id, generation));
                CREATE TABLE IF NOT EXISTS tokens(application TEXT NOT NULL, component TEXT NOT NULL, host_id TEXT NOT NULL,
                    generation INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('valid','revoked','unknown')),
                    data TEXT NOT NULL, revision INTEGER NOT NULL, updated_at TEXT NOT NULL, verification TEXT,
                    PRIMARY KEY(application, component, host_id));
                CREATE TABLE IF NOT EXISTS managed_placements(workload_id TEXT PRIMARY KEY, ownership_id TEXT NOT NULL,
                    placement TEXT, sequence INTEGER NOT NULL, updated_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS pulls(host_id TEXT NOT NULL, digest TEXT NOT NULL, reference TEXT NOT NULL,
                    state TEXT NOT NULL, data TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(host_id, digest));
            ''')
            if backup is not None:
                db.execute("INSERT OR IGNORE INTO store_meta VALUES('pre_store_backup', ?)", (encode(str(backup)),))

    @contextmanager
    def transaction(self):
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
    def reading(self):
        """A read-only snapshot (deferred transaction: shared lock only while reading)."""
        db = sqlite3.connect(self.path, timeout=3, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN")
            yield db
        finally:
            db.rollback()
            db.close()

    # Managed placements: where a workload Switchyard manages itself under the operations policy (Foobar's
    # static-web recipe) runs, and the ownership ID its native resources carry. The placement changes only
    # through operation receipts: the operation journal records each change as a placement intent in the same
    # transaction as the receipt (`operation_store.Store`) and applies it here in journal sequence order. An
    # older sequence never overwrites a newer one, so applying an intent twice, or two drains racing, is harmless.
    @staticmethod
    def managed_placement(db, workload_id):
        row = db.execute("SELECT * FROM managed_placements WHERE workload_id=?", (workload_id,)).fetchone()
        if row is None:
            return None
        return {"ownership_id": row["ownership_id"], "placement": json.loads(row["placement"]) if row["placement"] else None,
                "sequence": row["sequence"]}

    @staticmethod
    def managed_placement_rows(db):
        return {row["workload_id"]: {"ownership_id": row["ownership_id"], "sequence": row["sequence"],
                                     "placement": json.loads(row["placement"]) if row["placement"] else None}
                for row in db.execute("SELECT * FROM managed_placements ORDER BY workload_id")}

    def ensure_ownership(self, workload_id, ownership_id):
        """The workload's ownership ID, recording `ownership_id` first if it has none."""
        with self.transaction() as db:
            db.execute("INSERT OR IGNORE INTO managed_placements VALUES(?,?,NULL,0,?)", (workload_id, ownership_id, now()))
            return db.execute("SELECT ownership_id FROM managed_placements WHERE workload_id=?", (workload_id,)).fetchone()[0]

    def apply_placement_intents(self, intents):
        """Apply journal intents `(sequence, workload_id, ownership_id, placement JSON or None)`, newest sequence wins."""
        with self.transaction() as db:
            for sequence, workload_id, ownership_id, placement in intents:
                db.execute("INSERT INTO managed_placements VALUES(?,?,?,?,?) ON CONFLICT(workload_id) DO UPDATE SET "
                           "ownership_id=excluded.ownership_id, placement=excluded.placement, sequence=excluded.sequence, "
                           "updated_at=excluded.updated_at WHERE managed_placements.sequence < excluded.sequence",
                           (workload_id, ownership_id, placement, sequence, now()))

    # Workload records ------------------------------------------------------------------------------------------
    @staticmethod
    def _record(row):
        return {"id": row["id"], "relation": row["relation"], "revision": row["revision"],
                "content_sha256": row["content_sha256"],
                "template_ref": {"id": row["template_id"], "revision": row["template_revision"]} if row["template_id"] else None,
                "data": json.loads(row["data"]), "meta": json.loads(row["meta"]),
                "created_at": row["created_at"], "updated_at": row["updated_at"]}

    @classmethod
    def record(cls, db, workload_id, relation=None):
        row = db.execute("SELECT * FROM workloads WHERE id=?", (workload_id,)).fetchone()
        if row is None or relation is not None and row["relation"] != relation:
            return None
        return cls._record(row)

    @classmethod
    def records(cls, db, relation=None):
        query, args = "SELECT * FROM workloads", ()
        if relation is not None:
            query, args = query + " WHERE relation=?", (relation,)
        return [cls._record(row) for row in db.execute(query + " ORDER BY id", args)]

    @staticmethod
    def relation_of(db, workload_id):
        row = db.execute("SELECT relation FROM workloads WHERE id=?", (workload_id,)).fetchone()
        return row[0] if row else None

    @staticmethod
    def revision(db):
        """Content revision of the whole store: every record's identity and revision, and the groups."""
        rows = [list(row) for row in db.execute("SELECT id, relation, revision, content_sha256, updated_at FROM workloads ORDER BY id")]
        groups = [row[0] for row in db.execute("SELECT data FROM workload_groups ORDER BY position")]
        return hashlib.sha256(encode({"workloads": rows, "groups": groups}).encode()).hexdigest()

    def current_revision(self):
        with self.transaction() as db:
            return self.revision(db)

    @staticmethod
    def put_record(db, *, workload_id, relation, expected_revision, revision, content_sha256, data, meta,
                   template_ref=None, stamp=None):
        """Insert (expected revision 0) or replace a record by compare-and-swap; every revision is kept."""
        if relation not in RELATIONS:
            raise ValueError("Unknown workload relation")
        if type(expected_revision) is not int or type(revision) is not int or revision <= expected_revision:
            raise ValueError("A new record revision must follow its expected revision")
        stamp = stamp or now()
        current = db.execute("SELECT relation, revision FROM workloads WHERE id=?", (workload_id,)).fetchone()
        if current is not None and current["relation"] != relation:
            raise ValueError("ID " + workload_id + " already belongs to a " + current["relation"] + " workload")
        if (current["revision"] if current else 0) != expected_revision:
            raise ValueError(f"Workload revision conflict: {workload_id} is at {current['revision'] if current else 0}, "
                             f"expected {expected_revision}")
        ref = template_ref or {}
        if current is None:
            db.execute("INSERT INTO workloads VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (workload_id, relation, revision, content_sha256, ref.get("id"), ref.get("revision"),
                        encode(data), encode(meta), stamp, stamp))
        else:
            db.execute("UPDATE workloads SET revision=?, content_sha256=?, template_id=?, template_revision=?, data=?, meta=?, "
                       "updated_at=? WHERE id=? AND revision=?",
                       (revision, content_sha256, ref.get("id"), ref.get("revision"), encode(data), encode(meta), stamp,
                        workload_id, expected_revision))
        db.execute("INSERT INTO workload_revisions VALUES(?,?,?,?,?,?,?)",
                   (workload_id, revision, relation, content_sha256, encode(data), encode(meta), stamp))

    @staticmethod
    def delete_record(db, workload_id, relation, *, expected_revision):
        """Remove a record and all its revisions (compare-and-swap)."""
        current = db.execute("SELECT revision FROM workloads WHERE id=? AND relation=?", (workload_id, relation)).fetchone()
        if current is None:
            raise ValueError("Unknown " + relation + " workload")
        if current[0] != expected_revision:
            raise ValueError(f"Workload revision conflict: {workload_id} is at {current[0]}, expected {expected_revision}")
        db.execute("DELETE FROM workloads WHERE id=?", (workload_id,))
        return db.execute("DELETE FROM workload_revisions WHERE id=? AND relation=?", (workload_id, relation)).rowcount

    @staticmethod
    def record_revision(db, workload_id, revision, relation=None):
        row = db.execute("SELECT * FROM workload_revisions WHERE id=? AND revision=?", (workload_id, revision)).fetchone()
        if row is None or relation is not None and row["relation"] != relation:
            return None
        return {"id": row["id"], "revision": row["revision"], "relation": row["relation"],
                "content_sha256": row["content_sha256"], "data": json.loads(row["data"]), "meta": json.loads(row["meta"]),
                "created_at": row["created_at"]}

    # Application groups (operator associations; never lifecycle authority) ---------------------------------------
    @staticmethod
    def groups(db):
        return [json.loads(row[0]) for row in db.execute("SELECT data FROM workload_groups ORDER BY position")]

    @staticmethod
    def replace_groups(db, groups):
        db.execute("DELETE FROM workload_groups")
        for position, group in enumerate(groups):
            db.execute("INSERT INTO workload_groups VALUES(?,?,?)", (group["id"], position, encode(group)))

    # Store metadata: seeding ---------------------------------------------------------------------------------------
    @staticmethod
    def meta(db, key):
        row = db.execute("SELECT value FROM store_meta WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    @staticmethod
    def set_meta(db, key, value):
        db.execute("INSERT OR REPLACE INTO store_meta VALUES(?,?)", (key, encode(value)))

    def seeded(self):
        with self.transaction() as db:
            return self.meta(db, "seed") is not None

    @staticmethod
    def legacy_tables(db):
        names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        return [name for name in LEGACY_TABLES if name in names]

    @classmethod
    def legacy_summary(cls, db):
        """What the replaced instance and registration journals hold (nothing when they never existed here)."""
        tables = cls.legacy_tables(db)
        names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        present = {row[0] for row in db.execute("SELECT id FROM workloads")} if "workloads" in names else set()
        deployed, registered = [], []
        if "instances" in tables:
            for row in db.execute("SELECT id, revision, template_id, template_revision FROM instances ORDER BY id").fetchall():
                revisions = {row["revision"]}
                if "instance_revisions" in tables:
                    revisions |= {r[0] for r in db.execute("SELECT revision FROM instance_revisions WHERE id=?", (row["id"],))}
                deployed.append({"id": row["id"], "relation": "deployed", "revision": row["revision"],
                                 "revisions": sorted(revisions), "template_ref": {"id": row["template_id"], "revision": row["template_revision"]},
                                 "already_in_store": row["id"] in present})
        if "registrations" in tables:
            for identity in [r[0] for r in db.execute("SELECT DISTINCT id FROM registrations ORDER BY id")]:
                revisions = [r[0] for r in db.execute("SELECT revision FROM registrations WHERE id=? ORDER BY revision", (identity,))]
                registered.append({"id": identity, "relation": "registered", "revision": revisions[-1], "revisions": revisions,
                                   "already_in_store": identity in present})
        journal = {}
        for name in ("templates", "placements", "claims", "verifications", "tokens"):
            if name in names:
                journal[name] = db.execute(f"SELECT count(*) FROM {name}").fetchone()[0]
        return {"tables": {name: db.execute(f"SELECT count(*) FROM {name}").fetchone()[0] for name in tables},
                "deployed": deployed, "registered": registered, "journal": journal}

    @staticmethod
    def reader(names):
        """Read-only stand-in for seed planning on a store file that may predate this schema (dry runs)."""
        class Reader:
            legacy_summary = WorkloadStore.legacy_summary

            @staticmethod
            def records(db):
                return WorkloadStore.records(db) if "workloads" in names else []
        return Reader

    @classmethod
    def copy_legacy(cls, db):
        """Copy the replaced journals into `workloads`/`workload_revisions`, stored bytes and hashes verbatim.
        Records already present are left alone; the legacy tables themselves are not changed."""
        tables = cls.legacy_tables(db)
        present = {row[0] for row in db.execute("SELECT id FROM workloads")}
        copied = {"deployed": {}, "registered": {}}
        if "instances" in tables:
            for row in db.execute("SELECT * FROM instances ORDER BY id").fetchall():
                if row["id"] in present:
                    continue
                revisions = {}
                if "instance_revisions" in tables:
                    revisions = {r["revision"]: r for r in db.execute("SELECT * FROM instance_revisions WHERE id=?", (row["id"],))}
                current = revisions.get(row["revision"])
                for revision in sorted(set(revisions) | {row["revision"]}):
                    if revision == row["revision"] and current is None:
                        # The current row predates the revision table: it is its own revision (archive semantics).
                        values = (row["content_sha256"], row["data"], row["meta"], row["created_at"])
                    else:
                        item = revisions[revision]
                        values = (item["content_sha256"], item["data"],
                                  row["meta"] if revision == row["revision"] else "{}", item["created_at"])
                    db.execute("INSERT INTO workload_revisions VALUES(?,?,?,?,?,?,?)", (row["id"], revision, "deployed", *values))
                db.execute("INSERT INTO workloads VALUES(?,?,?,?,?,?,?,?,?,?)",
                           (row["id"], "deployed", row["revision"], row["content_sha256"], row["template_id"],
                            row["template_revision"], row["data"], row["meta"], row["created_at"],
                            current["created_at"] if current is not None else row["created_at"]))
                copied["deployed"][row["id"]] = sorted(set(revisions) | {row["revision"]})
        if "registrations" in tables:
            rows = db.execute("SELECT * FROM registrations ORDER BY id, revision").fetchall()
            for identity in dict.fromkeys(row["id"] for row in rows):
                if identity in present:
                    continue
                history = [row for row in rows if row["id"] == identity]
                for row in history:
                    db.execute("INSERT INTO workload_revisions VALUES(?,?,?,?,?,?,?)",
                               (identity, row["revision"], "registered", json.loads(row["meta"])["document_sha256"],
                                row["data"], row["meta"], row["registered_at"]))
                latest = history[-1]
                db.execute("INSERT INTO workloads VALUES(?,?,?,?,?,?,?,?,?,?)",
                           (identity, "registered", latest["revision"], json.loads(latest["meta"])["document_sha256"], None, None,
                            latest["data"], latest["meta"], history[0]["registered_at"], latest["registered_at"]))
                copied["registered"][identity] = [row["revision"] for row in history]
        return copied

    @classmethod
    def verify_legacy_copy(cls, db):
        """Every legacy instance and registration revision present in the store, byte for byte. Returns problems."""
        tables = cls.legacy_tables(db)
        problems = []
        expected = []
        if "instances" in tables:
            for row in db.execute("SELECT * FROM instances").fetchall():
                expected.append((row["id"], "deployed", row["revision"], row["data"], row["content_sha256"]))
                current = db.execute("SELECT relation, revision, data, content_sha256, meta FROM workloads WHERE id=?", (row["id"],)).fetchone()
                if current is None or tuple(current) != ("deployed", row["revision"], row["data"], row["content_sha256"], row["meta"]):
                    problems.append(f"deployed instance {row['id']}: current record does not match the instances table")
            if "instance_revisions" in tables:
                expected += [(row["id"], "deployed", row["revision"], row["data"], row["content_sha256"])
                             for row in db.execute("SELECT * FROM instance_revisions").fetchall()]
        if "registrations" in tables:
            for row in db.execute("SELECT * FROM registrations").fetchall():
                expected.append((row["id"], "registered", row["revision"], row["data"], json.loads(row["meta"])["document_sha256"]))
                stored = db.execute("SELECT meta FROM workload_revisions WHERE id=? AND revision=?", (row["id"], row["revision"])).fetchone()
                if stored is None or stored[0] != row["meta"]:
                    problems.append(f"registration {row['id']}@{row['revision']}: provenance not carried over")
        for identity, relation, revision, data, digest in expected:
            stored = db.execute("SELECT relation, data, content_sha256 FROM workload_revisions WHERE id=? AND revision=?",
                                (identity, revision)).fetchone()
            if stored is None or tuple(stored) != (relation, data, digest):
                problems.append(f"{relation} {identity}@{revision}: revision missing or different in the store")
        return problems

    def backup(self, label):
        """Byte-consistent copy of the whole store beside it (mode 0600); call while holding a write transaction."""
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        target = self.directory / f"deploy.sqlite3.{label}-{stamp}.bak"
        fd = os.open(target, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        os.close(fd)
        source, destination = sqlite3.connect(self.path, timeout=3), sqlite3.connect(target)
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()
        return target

    # Templates: immutable content-hashed revisions, saved by CAS on the latest revision.
    @staticmethod
    def latest_template_revision(db, template_id):
        return db.execute("SELECT coalesce(max(revision),0) FROM templates WHERE id=?", (template_id,)).fetchone()[0]

    def save_template(self, application, *, expected_revision):
        with self.transaction() as db:
            current = self.latest_template_revision(db, application.id)
            if current != expected_revision:
                raise ValueError(f"Template revision conflict: latest is {current}, expected {expected_revision}")
            if application.revision != current + 1:
                raise ValueError(f"Template file must declare revision {current + 1}")
            digest = application.content_sha256()
            db.execute("INSERT INTO templates VALUES(?,?,?,?,?)", (application.id, application.revision, digest,
                       encode(application.model_dump(mode="json")), now()))
        return {"id": application.id, "revision": application.revision, "content_sha256": digest}

    def template(self, template_id, revision=None):
        """A stored revision; v1alpha2 content is upgraded in memory, its stored hash stays its identity."""
        with self.transaction() as db:
            if revision is None:
                revision = self.latest_template_revision(db, template_id)
            row = db.execute("SELECT * FROM templates WHERE id=? AND revision=?", (template_id, revision)).fetchone()
        if row is None:
            raise ValueError("Unknown template revision")
        application, upgraded_from = spec.upgrade(json.loads(row["data"]))
        result = {"id": row["id"], "revision": row["revision"], "content_sha256": row["content_sha256"],
                  "saved_at": row["saved_at"], "application": application}
        if upgraded_from:
            result["upgraded_from"] = upgraded_from
        return result

    def templates(self):
        with self.transaction() as db:
            rows = db.execute("SELECT id, revision, content_sha256, saved_at FROM templates ORDER BY id, revision").fetchall()
        result = {}
        for row in rows:
            result.setdefault(row["id"], []).append({"revision": row["revision"], "content_sha256": row["content_sha256"],
                                                     "saved_at": row["saved_at"]})
        return [{"id": key, "latest_revision": value[-1]["revision"], "revisions": value} for key, value in result.items()]

    # Deployed instances: `deployed` records holding the instance Application. Placements are separate rows.
    @staticmethod
    def instance_row(db, instance_id):
        row = db.execute("SELECT * FROM workloads WHERE id=? AND relation='deployed'", (instance_id,)).fetchone()
        if row is None:
            return None
        application, upgraded_from = spec.upgrade(json.loads(row["data"]))
        result = {"id": row["id"], "revision": row["revision"], "template_ref": {"id": row["template_id"], "revision": row["template_revision"]},
                  "content_sha256": row["content_sha256"], "application": application,
                  "meta": json.loads(row["meta"]), "created_at": row["created_at"]}
        if upgraded_from:
            result["upgraded_from"] = upgraded_from
        return result

    @staticmethod
    def raw_instance(db, instance_id):
        row = db.execute("SELECT * FROM workloads WHERE id=? AND relation='deployed'", (instance_id,)).fetchone()
        return tuple(row) if row else None

    @classmethod
    def replace_instance(cls, db, instance_id, expected_revision, application, meta):
        """New instance revision (for example a v1alpha2 → v1alpha3 upgrade), compare-and-swap on revision.
        The previous revision stays retrievable, byte for byte, in `workload_revisions`."""
        current = db.execute("SELECT template_id, template_revision FROM workloads WHERE id=? AND relation='deployed'",
                             (instance_id,)).fetchone()
        if current is None:
            raise ValueError("Instance revision changed concurrently")
        try:
            cls.put_record(db, workload_id=instance_id, relation="deployed", expected_revision=expected_revision,
                           revision=application["revision"], content_sha256=meta["content_sha256"], data=application,
                           meta=meta, template_ref=application.get("template_ref") or {"id": current[0], "revision": current[1]})
        except ValueError:
            raise ValueError("Instance revision changed concurrently") from None

    @staticmethod
    def restore_instance(db, row, withdrawn_revision):
        """Withdraw an unexecuted new revision: restore the previous current row, drop only the new revision."""
        db.execute("DELETE FROM workload_revisions WHERE id=? AND revision=?", (row[0], withdrawn_revision))
        db.execute("INSERT OR REPLACE INTO workloads VALUES(?,?,?,?,?,?,?,?,?,?)", row)

    @classmethod
    def insert_instance(cls, db, application, meta):
        if db.execute("SELECT 1 FROM workloads WHERE id=?", (application["id"],)).fetchone():
            raise ValueError("Instance already exists")
        cls.put_record(db, workload_id=application["id"], relation="deployed", expected_revision=0,
                       revision=application["revision"], content_sha256=meta["content_sha256"], data=application,
                       meta=meta, template_ref=application["template_ref"])

    @staticmethod
    def withdraw_instance(db, instance_id):
        """Remove an instance whose first deploy wrote nothing on the host (journal intent withdrawn)."""
        db.execute("DELETE FROM workloads WHERE id=? AND relation='deployed'", (instance_id,))
        db.execute("DELETE FROM workload_revisions WHERE id=? AND relation='deployed'", (instance_id,))

    @classmethod
    def instance_revision(cls, db, instance_id, revision):
        """One stored revision: its exact stored document and hash, plus the in-memory v1alpha3 form."""
        row = cls.record_revision(db, instance_id, revision, "deployed")
        if row is None:
            return None
        stored = row["data"]
        application, upgraded_from = spec.upgrade(stored)
        return {"id": row["id"], "revision": row["revision"], "content_sha256": row["content_sha256"],
                "created_at": row["created_at"], "stored_application": stored, "application": application,
                "upgraded_from": upgraded_from}

    @staticmethod
    def instance_revisions(db, instance_id):
        return [dict(row) for row in db.execute("SELECT revision, content_sha256, created_at FROM workload_revisions "
                                                "WHERE id=? AND relation='deployed' ORDER BY revision", (instance_id,))]

    @staticmethod
    def update_instance_meta(db, instance_id, meta):
        """Journal bookkeeping beside the record (never a new revision)."""
        db.execute("UPDATE workloads SET meta=? WHERE id=? AND relation='deployed'", (encode(meta), instance_id))

    @staticmethod
    def placement_row(db, instance_id, generation=None):
        if generation is None:
            row = db.execute("SELECT * FROM placements WHERE instance_id=? ORDER BY generation DESC LIMIT 1", (instance_id,)).fetchone()
        else:
            row = db.execute("SELECT * FROM placements WHERE instance_id=? AND generation=?", (instance_id, generation)).fetchone()
        if row is None:
            return None
        placement, _ = spec.upgrade(json.loads(row["data"]), gate_ids={"exec-start-pre": GATE_ID})
        return {"instance_id": row["instance_id"], "generation": row["generation"], "host_id": row["host_id"],
                "state": row["state"], "placement": placement, "meta": json.loads(row["meta"]),
                "revision": row["revision"], "updated_at": row["updated_at"]}

    @staticmethod
    def insert_placement(db, placement, meta):
        latest = db.execute("SELECT state FROM placements WHERE instance_id=? ORDER BY generation DESC LIMIT 1",
                            (placement["application_id"],)).fetchone()
        if latest is not None and latest["state"] != "retired":
            raise ValueError("Instance already has a non-retired placement")
        db.execute("INSERT INTO placements VALUES(?,?,?,?,?,?,?,?)", (placement["application_id"], placement["generation"],
                   placement["host_id"], placement["state"], encode(placement), encode(meta), 1, now()))

    @staticmethod
    def cas_placement(db, instance_id, generation, expected_revision, placement, meta):
        changed = db.execute("UPDATE placements SET state=?, data=?, meta=?, revision=revision+1, updated_at=? "
                             "WHERE instance_id=? AND generation=? AND revision=?",
                             (placement["state"], encode(placement), encode(meta), now(), instance_id, generation,
                              expected_revision)).rowcount
        if not changed:
            raise ValueError("Placement changed concurrently; inspect and plan again")
        return expected_revision + 1

    @staticmethod
    def delete_placement(db, instance_id, generation, expected_revision):
        if not db.execute("DELETE FROM placements WHERE instance_id=? AND generation=? AND revision=?",
                          (instance_id, generation, expected_revision)).rowcount:
            raise ValueError("Placement changed concurrently")

    def instances(self):
        with self.transaction() as db:
            ids = [row[0] for row in db.execute("SELECT id FROM workloads WHERE relation='deployed' ORDER BY id")]
            return [(self.instance_row(db, item), self.placement_row(db, item)) for item in ids]

    # Port registry.
    @staticmethod
    def conflicts(db, host_id, address, protocol, port, *, ignore_owner=None):
        stamp = now()
        result = []
        for row in db.execute("SELECT * FROM claims WHERE host_id=? AND protocol=? AND port=?", (host_id, protocol, port)):
            if row["owner_kind"] == "plan" and (row["expires_at"] is None or row["expires_at"] <= stamp):
                continue
            if ignore_owner is not None and row["owner_id"] == ignore_owner:
                continue
            if overlaps(row["address"], address):
                result.append({key: row[key] for key in ("address", "protocol", "port", "owner_kind", "owner_id", "endpoint")})
        return result

    @classmethod
    def reserve(cls, db, host_id, claims, *, plan_id, generation, expires_at, ignore_owner=None):
        db.execute("DELETE FROM claims WHERE owner_kind='plan' AND (expires_at IS NULL OR expires_at <= ?)", (now(),))
        for claim in claims:
            found = cls.conflicts(db, host_id, claim["address"], claim["protocol"], claim["port"], ignore_owner=ignore_owner)
            if found:
                raise ValueError(f"Port {claim['protocol']}/{claim['address']}:{claim['port']} conflicts with registry claim {found[0]}")
            db.execute("INSERT INTO claims VALUES(?,?,?,?,?,?,?,?,?,?)", (host_id, family(claim["address"]), claim["address"],
                       claim["protocol"], claim["port"], "plan", plan_id, claim["endpoint"], generation, expires_at))

    @classmethod
    def convert_reservation(cls, db, host_id, claims, *, plan_id, instance_id, generation):
        """Plan reservation becomes a placement claim; the claim must still be free of others."""
        db.execute("DELETE FROM claims WHERE owner_kind='plan' AND owner_id=?", (plan_id,))
        for claim in claims:
            found = cls.conflicts(db, host_id, claim["address"], claim["protocol"], claim["port"], ignore_owner=instance_id)
            if found:
                raise ValueError(f"Port claim {claim['address']}:{claim['port']} was taken since planning: {found[0]}")
            db.execute("INSERT INTO claims VALUES(?,?,?,?,?,?,?,?,?,NULL)", (host_id, family(claim["address"]), claim["address"],
                       claim["protocol"], claim["port"], "placement", instance_id, claim["endpoint"], generation))

    @staticmethod
    def release_claims(db, instance_id):
        db.execute("DELETE FROM claims WHERE owner_kind='placement' AND owner_id=?", (instance_id,))

    @staticmethod
    def claims_for(db, owner_id):
        return [dict(row) for row in db.execute("SELECT host_id,address,protocol,port,endpoint,owner_kind,generation,expires_at "
                                                "FROM claims WHERE owner_id=? ORDER BY port", (owner_id,))]

    def all_claims(self):
        with self.transaction() as db:
            db.execute("DELETE FROM claims WHERE owner_kind='plan' AND (expires_at IS NULL OR expires_at <= ?)", (now(),))
            return [dict(row) for row in db.execute("SELECT * FROM claims ORDER BY host_id, port")]

    # Plan-time inspections written by the leased worker, read once by the planner.
    def put_inspection(self, operation_id, data):
        with self.transaction() as db:
            db.execute("DELETE FROM inspections WHERE created_at < ?",
                       (datetime.fromtimestamp(datetime.now(timezone.utc).timestamp() - 3600, timezone.utc).isoformat(),))
            db.execute("INSERT OR REPLACE INTO inspections VALUES(?,?,?)", (operation_id, encode(data), now()))

    def take_inspection(self, operation_id):
        with self.transaction() as db:
            row = db.execute("SELECT data FROM inspections WHERE operation_id=?", (operation_id,)).fetchone()
            db.execute("DELETE FROM inspections WHERE operation_id=?", (operation_id,))
        return json.loads(row[0]) if row else None

    # Registrations of adopted applications: `registered` records holding the owner's Bundle (metadata only;
    # never lifecycle authority). Every revision is kept; unregistering removes them all.
    @staticmethod
    def latest_registration_revision(db, registration_id):
        row = db.execute("SELECT revision FROM workloads WHERE id=? AND relation='registered'", (registration_id,)).fetchone()
        return row[0] if row else 0

    def save_registration(self, registration_id, bundle, meta, *, expected_revision):
        with self.transaction() as db:
            current = self.latest_registration_revision(db, registration_id)
            if current != expected_revision:
                raise ValueError(f"Registration revision conflict: latest is {current}, expected {expected_revision}")
            stamp = now()
            self.put_record(db, workload_id=registration_id, relation="registered", expected_revision=current,
                            revision=current + 1, content_sha256=meta["document_sha256"], data=bundle, meta=meta, stamp=stamp)
        return current + 1, stamp

    @classmethod
    def registration_in(cls, db, registration_id, revision=None):
        if revision is None:
            revision = cls.latest_registration_revision(db, registration_id)
        row = cls.record_revision(db, registration_id, revision, "registered")
        if row is None:
            return None
        return {"id": row["id"], "revision": row["revision"], "registered_at": row["created_at"],
                "meta": row["meta"], "bundle": row["data"]}

    def registration(self, registration_id, revision=None):
        with self.transaction() as db:
            return self.registration_in(db, registration_id, revision)

    def registrations(self):
        with self.transaction() as db:
            ids = [row[0] for row in db.execute("SELECT id FROM workloads WHERE relation='registered' ORDER BY id")]
            return [self.registration_in(db, item) for item in ids]

    def delete_registration(self, registration_id, *, expected_revision):
        with self.transaction() as db:
            current = self.latest_registration_revision(db, registration_id)
            if current == 0:
                raise ValueError("Unknown registration")
            if current != expected_revision:
                raise ValueError(f"Registration revision conflict: latest is {current}, expected {expected_revision}")
            return self.delete_record(db, registration_id, "registered", expected_revision=current)

    # Last read-only verification per placement (separate table: recording it never bumps the placement revision).
    def save_verification(self, instance_id, generation, operation_id, data):
        with self.transaction() as db:
            db.execute("INSERT OR REPLACE INTO verifications VALUES(?,?,?,?,?)",
                       (instance_id, generation, operation_id, encode(data), data["verified_at"]))

    @staticmethod
    def verification(db, instance_id, generation):
        row = db.execute("SELECT data FROM verifications WHERE instance_id=? AND generation=?", (instance_id, generation)).fetchone()
        return json.loads(row[0]) if row else None

    def verifications_for(self, operation_id):
        with self.transaction() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT data FROM verifications WHERE operation_id=? ORDER BY instance_id",
                                                             (operation_id,))]

    # Detached image pulls (deploy pull-start): the last known state of one image's pull per host, recorded before
    # the pull is started and after every leased status read, so no pull runs unseen.
    def save_pull(self, host_id, digest, reference, state, data):
        with self.transaction() as db:
            db.execute("INSERT OR REPLACE INTO pulls VALUES(?,?,?,?,?,?)", (host_id, digest, reference, state, encode(data), now()))

    def pull(self, host_id, digest):
        with self.transaction() as db:
            row = db.execute("SELECT * FROM pulls WHERE host_id=? AND digest=?", (host_id, digest)).fetchone()
        return self._pull(row) if row else None

    def pulls(self):
        with self.transaction() as db:
            return [self._pull(row) for row in db.execute("SELECT * FROM pulls ORDER BY updated_at DESC")]

    @staticmethod
    def _pull(row):
        return {"host_id": row["host_id"], "digest": row["digest"], "reference": row["reference"], "state": row["state"],
                "updated_at": row["updated_at"], **json.loads(row["data"])}

    # Start tokens of adopted (registered) applications. `generation` is the journal high-water mark:
    # it is raised before a write (intent precedes effect) and never lowered.
    @staticmethod
    def token_row(db, application, component, host_id):
        row = db.execute("SELECT * FROM tokens WHERE application=? AND component=? AND host_id=?",
                         (application, component, host_id)).fetchone()
        if row is None:
            return None
        return {"application": row["application"], "component": row["component"], "host_id": row["host_id"],
                "generation": row["generation"], "state": row["state"], "data": json.loads(row["data"]),
                "revision": row["revision"], "updated_at": row["updated_at"],
                "last_verification": json.loads(row["verification"]) if row["verification"] else None}

    @staticmethod
    def put_token(db, application, component, host_id, *, expected_revision, generation, state, data):
        """Compare-and-swap on revision (0 = new record); the generation never moves backwards."""
        if expected_revision == 0:
            if db.execute("SELECT 1 FROM tokens WHERE application=? AND component=? AND host_id=?",
                          (application, component, host_id)).fetchone():
                raise ValueError("Token record changed concurrently")
            db.execute("INSERT INTO tokens VALUES(?,?,?,?,?,?,?,?,NULL)",
                       (application, component, host_id, generation, state, encode(data), 1, now()))
            return 1
        changed = db.execute("UPDATE tokens SET generation=?, state=?, data=?, revision=revision+1, updated_at=? "
                             "WHERE application=? AND component=? AND host_id=? AND revision=? AND generation<=?",
                             (generation, state, encode(data), now(), application, component, host_id,
                              expected_revision, generation)).rowcount
        if not changed:
            raise ValueError("Token record changed concurrently (or the generation would move backwards)")
        return expected_revision + 1

    @staticmethod
    def token_rows(db, application, component=None, host_id=None):
        query, args = "SELECT application, component, host_id FROM tokens WHERE application=?", [application]
        if component:
            query, args = query + " AND component=?", args + [component]
        if host_id:
            query, args = query + " AND host_id=?", args + [host_id]
        keys = db.execute(query + " ORDER BY host_id, component", args).fetchall()
        return [WorkloadStore.token_row(db, *key) for key in keys]

    @staticmethod
    def save_token_verification(db, application, component, host_id, verification):
        """Recorded beside the token; never bumps its revision."""
        db.execute("UPDATE tokens SET verification=? WHERE application=? AND component=? AND host_id=?",
                   (encode(verification), application, component, host_id))
