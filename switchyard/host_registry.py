"""Private, revision-safe host declarations and collector authority."""
from contextlib import contextmanager
from copy import deepcopy
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

from . import collector, host_keys

IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
DESCRIPTION = {"name", "platform", "architecture", "capabilities", "notes"}
CONNECTION = {"target", "port", "expected_hostname"}
ALLOWLISTS = {"user_units", "system_units", "container_engines", "storage_mounts", "monitor", "paseo"}
CONNECTION_FIELDS = {"transport", "target", "port", "expected_hostname", "ledger"}
FIELDS = {"id", *DESCRIPTION, "provenance", "collector", "host_keys", "connection_revision", "verified_revision"}


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def authority(record):
    config = record["collector"]
    return digest({"collector": {key: value for key, value in config.items() if key not in {"monitor", "known_hosts"}}
                   if config else None, "host_keys": record["host_keys"]})


def validate(record):
    if not isinstance(record, dict) or set(record) != FIELDS:
        raise ValueError("Invalid registry host fields")
    record = deepcopy(record)
    if not isinstance(record["id"], str) or not IDENTIFIER.fullmatch(record["id"]):
        raise ValueError("Invalid registry host ID")
    for key in DESCRIPTION - {"capabilities"} | {"provenance"}:
        value = record[key]
        if not isinstance(value, str) or not value.strip() or len(value) > 8192 or any(ord(c) < 32 and c not in "\n\t" for c in value):
            raise ValueError(f"{key} must be bounded nonempty text")
    values = record["capabilities"]
    if not isinstance(values, list) or len(values) > 128 or any(not isinstance(v, str) or not v.strip() or len(v) > 256 for v in values):
        raise ValueError("Invalid host capabilities")
    config = record["collector"]
    if config is not None:
        if not isinstance(config, dict) or "known_hosts" in config:
            raise ValueError("known_hosts is managed by the registry")
        config = collector._validate_config(config)
        if config["host_id"] != record["id"]:
            raise ValueError("Collector host ID must match registry host ID")
        record["collector"] = config
    keys = record["host_keys"]
    if not isinstance(keys, list) or len(keys) > 16 or any(not isinstance(key, str) for key in keys):
        raise ValueError("Invalid pinned host keys")
    for key in keys:
        host_keys.fingerprint(key)
    if keys and (not config or config["transport"] != "ssh"):
        raise ValueError("Only SSH hosts can have pinned host keys")
    record["host_keys"] = sorted(set(keys))
    if type(record["connection_revision"]) is not int or record["connection_revision"] < 1:
        raise ValueError("Invalid connection revision")
    record["verified_revision"] = None  # Verification is never operator-editable.
    return record


class HostRegistry:
    def __init__(self, root, catalog_path, *, clock=time.time):
        self.clock = clock
        # Canonical root: on hosts where /home is a symlink (e.g. /var/home), pin files must use the real path.
        root = Path(root).expanduser().resolve()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("Registry state root must be owned by you and mode 0700")
        self.directory = root / "registry"
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("Host registry must be an owned private directory")
        self.directory.chmod(0o700)
        namespace = hashlib.sha256(str(Path(catalog_path).resolve()).encode()).hexdigest()
        self.path = self.directory / (namespace + ".sqlite3")
        self.pins_path = self.directory / (namespace + ".known_hosts")
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError("Host registry must be an owned private regular file")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        with self.transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS hosts(id TEXT PRIMARY KEY, data TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS metadata(revision INTEGER NOT NULL, seeded INTEGER NOT NULL)")
            if not db.execute("SELECT 1 FROM metadata").fetchone():
                db.execute("INSERT INTO metadata VALUES(0,0)")
            db.execute("CREATE TABLE IF NOT EXISTS verification(host_id TEXT PRIMARY KEY, connection_revision INTEGER NOT NULL, verified_at TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, host_id TEXT NOT NULL, authority TEXT NOT NULL, data TEXT NOT NULL, expires REAL NOT NULL)")

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path, timeout=3, isolation_level=None)
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

    def _read(self, db):
        # Operator order (seed order, then additions) is meaningful to every view; rowid preserves it.
        records = [json.loads(row[0]) for row in db.execute("SELECT data FROM hosts ORDER BY rowid")]
        normalized = False
        for record in records:
            config = record["collector"]
            if isinstance(config, dict) and "lease_wrapper" in config:
                del config["lease_wrapper"]
                record["connection_revision"] += 1
                record["verified_revision"] = None
                db.execute("UPDATE hosts SET data=? WHERE id=?", (encode(record), record["id"]))
                db.execute("DELETE FROM verification WHERE host_id=?", (record["id"],))
                db.execute("DELETE FROM scans WHERE host_id=?", (record["id"],))
                normalized = True
        if normalized:
            db.execute("UPDATE metadata SET revision=revision+1")
        return records, digest(records)

    def _pins(self, records):
        host_keys.write_pins(self.pins_path, {r["id"]: r["host_keys"] for r in records if r["host_keys"]})

    def read(self):
        with self.transaction() as db:
            records, revision = self._read(db)
            verified = {row[0]: row[1:] for row in db.execute("SELECT host_id,connection_revision,verified_at FROM verification")}
            for record in records:
                value = verified.get(record["id"])
                record["verified_revision"] = value[0] if value else None
                record["verification"] = {"state": "no-collector" if not record["collector"] else
                    "unpinned" if record["collector"]["transport"] == "ssh" and not record["host_keys"] else
                    "verified" if value and value[0] == record["connection_revision"] else "unverified",
                    "connection_revision": record["connection_revision"], "verified_revision": record["verified_revision"],
                    "verified_at": value[1] if value else None}
                record["pins"] = [{"key": key, "fingerprint": host_keys.fingerprint(key)} for key in record["host_keys"]]
            return {"revision": revision, "hosts": records}

    def initialized(self):
        with self.transaction() as db:
            return bool(db.execute("SELECT seeded FROM metadata").fetchone()[0])

    @staticmethod
    def seed_records(devices, configs):
        if not set(configs) <= {device["id"] for device in devices}:
            raise ValueError("Collectors reference a host outside this catalog")
        result = []
        for device in devices:
            config = deepcopy(configs.get(device["id"]))
            if isinstance(config, dict):
                config.pop("lease_wrapper", None)
            keys = host_keys.bootstrap(config["target"].split("@", 1)[1], config.get("port", 22)) if config and config["transport"] == "ssh" else []
            result.append(validate({**{key: device[key] for key in {"id", *DESCRIPTION, "provenance"}},
                                   "collector": config, "host_keys": keys, "connection_revision": 1, "verified_revision": None}))
        return result

    def seed(self, records):
        with self.transaction() as db:
            if db.execute("SELECT seeded FROM metadata").fetchone()[0]:
                return
            self._replace(db, records)

    def _replace(self, db, records):
        db.execute("DELETE FROM hosts")
        db.execute("DELETE FROM verification")
        db.execute("DELETE FROM scans")
        for record in records:
            db.execute("INSERT INTO hosts VALUES(?,?)", (record["id"], encode(record)))
        db.execute("UPDATE metadata SET revision=revision+1,seeded=1")
        self._pins(records)

    def mutate(self, expected_revision, change, *, validate_hosts=None):
        if not isinstance(expected_revision, str) or not expected_revision:
            raise ValueError("expected_revision is required")
        with self.transaction() as db:
            records, revision = self._read(db)
            if revision != expected_revision:
                raise ValueError("Host registry revision changed; review the current hosts before saving")
            result = change(records, db)
            records = [validate(record) for record in records]
            if len({record["id"] for record in records}) != len(records) or len(records) > 128:
                raise ValueError("Invalid or duplicate registry hosts")
            if validate_hosts:
                validate_hosts(records)
            ids = {r["id"] for r in records}
            db.execute("DELETE FROM hosts")
            for record in records:
                db.execute("INSERT INTO hosts VALUES(?,?)", (record["id"], encode(record)))
            for row in db.execute("SELECT host_id FROM verification").fetchall():
                if row[0] not in ids:
                    db.execute("DELETE FROM verification WHERE host_id=?", row)
            db.execute("UPDATE metadata SET revision=revision+1")
            self._pins(records)
            return result

    def verify(self, host_id, fingerprint):
        with self.transaction() as db:
            records, _ = self._read(db)
            record = next((record for record in records if record["id"] == host_id), None)
            if record and authority(record) == fingerprint:
                at = datetime.fromtimestamp(self.clock(), timezone.utc).isoformat()
                db.execute("INSERT INTO verification VALUES(?,?,?) ON CONFLICT(host_id) DO UPDATE SET connection_revision=excluded.connection_revision,verified_at=excluded.verified_at",
                           (host_id, record["connection_revision"], at))

    def save_scan(self, host_id, fingerprint, data):
        scan_id = uuid.uuid4().hex
        expires = self.clock() + 600
        with self.transaction() as db:
            db.execute("DELETE FROM scans WHERE expires<=?", (self.clock(),))
            db.execute("INSERT INTO scans VALUES(?,?,?,?,?)", (scan_id, host_id, fingerprint, encode(data), expires))
        return {"scan_id": scan_id, **data, "expires_at": datetime.fromtimestamp(expires, timezone.utc).isoformat()}

    def scanned_keys(self, db, host_id, record, scan_id, fingerprints):
        if not isinstance(scan_id, str) or not re.fullmatch(r"[0-9a-f]{32}", scan_id):
            raise ValueError("Invalid host key scan ID")
        row = db.execute("SELECT authority,data,expires FROM scans WHERE id=? AND host_id=?", (scan_id, host_id)).fetchone()
        if not row or row[2] <= self.clock() or row[0] != authority(record):
            raise ValueError("Host key scan expired or connection changed; scan again")
        data = json.loads(row[1])
        if (not isinstance(fingerprints, list) or not 1 <= len(fingerprints) <= 16
                or any(not isinstance(value, str) for value in fingerprints)
                or sorted(fingerprints) != sorted(data["fingerprints"])):
            raise ValueError("Confirm exactly every fingerprint from the host key scan")
        db.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        return data["keys"]
