"""Ansible host initialization: playbook registrations, registry-generated inventory, check-mode plans and
approved applies under the host's canonical lease, with durable receipts. See docs/ansible.md.

Contract: inspect (repo commit, registration, generated inventory) -> check-mode plan under the lease ->
explicit approval with a request ID -> apply under the lease -> receipt. No automatic retries; an unknown
outcome is `needs-inspection`. Playbook registrations live in the private Ansible database (seeded once from
the configuration file); the file keeps only the runner pin. A become password is never stored or logged:
the operator may type one for a single run, and it reaches ansible-playbook through a pipe on its stdin
(`--become-password-file -`). Without one, a plan that needs privilege prints the operator's own leased
terminal command instead.
"""
from collections import OrderedDict
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sqlite3
import stat
import subprocess
import threading
import time
import uuid

from . import ansible_discovery as discovery, host_registry
from .ansible_runner import (COLLECTION, VERSION, EventStream, Runner, _stdin_pipe, parse_events, parse_records,
                             private_dir, run_process, write_private)
from .leases import LedgerBroker, LeaseBusy
from .operation_store import process_identity

PLAN_TTL = 1800
PLAN_TIMEOUT = 900
APPLY_TIMEOUT = 3600
PREFLIGHT_TIMEOUT = 30
MAX_LEASE_WAIT = 60
DESK_LEASE_WAIT = 5
TOP_REQUIRED = {"schema_version", "runner"}
TOP_OPTIONAL = {"playbooks"}
RUNNER_KEYS = {"ansible_core", "collections"}
PLAYBOOK_REQUIRED = {"repo", "playbook", "allowed_hosts", "become", "check_mode", "extra_vars_allowed",
                     "description", "groups"}
PLAYBOOK_OPTIONAL = {"inventory", "secret_vars"}
CHECK_MODES = {"full", "partial", "unsupported"}
PLAYBOOK_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
VAR_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
GROUP = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
PLAN_ID = re.compile(r"[0-9a-f]{32}\Z")
RESERVED_VAR_PREFIXES = ("ansible_", "switchyard_")
ACTIVE_RUNS = ("queued", "running")
SUPPLIED = "password supplied by the operator for this run"
SUDO_REFUSED = ("sudo refused the password; nothing past that point ran, and it was not retried (repeated "
                "failures can lock the account on some hosts). Check the password and start a new run.")
# ansible-core's own wording when sudo rejects or lacks the become password.
REFUSED_PASSWORD = re.compile(r"incorrect (sudo |become )?password|incorrect password attempt|"
                              r"missing (sudo|become) password|sorry, try again", re.I)
# Exit codes of the fixed preflight script (identity + sudo -n probe).
PREFLIGHT_SCRIPT = ('[ "$(uname -n)" = {hostname} ] || exit 78; [ "$(id -u)" -ne 0 ] || exit 78; '
                    'if sudo -n true >/dev/null 2>&1; then exit 0; else exit 10; fi')


def now_iso(seconds=None):
    return datetime.fromtimestamp(time.time() if seconds is None else seconds, timezone.utc).isoformat()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def _text(value, name, limit=2048):
    if not isinstance(value, str) or not value.strip() or len(value) > limit or any(
            ord(c) < 32 and c not in "\n\t" for c in value):
        raise ValueError(f"{name} must be bounded nonempty text")
    return value


def _relative(value, name):
    _text(value, name, 1024)
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or value.startswith("-") or not path.parts:
        raise ValueError(f"{name} must be a relative path inside the repo")
    return value


def _names(value, name, pattern, *, minimum=0, maximum=32):
    if (not isinstance(value, list) or not minimum <= len(value) <= maximum
            or any(not isinstance(item, str) or not pattern.fullmatch(item) for item in value)
            or len(set(value)) != len(value)):
        raise ValueError(f"Invalid {name}")
    return list(value)


def validate_playbook(playbook_id, entry):
    """One registration: strict keys, relative paths inside the repo, no reserved variable names."""
    if not isinstance(playbook_id, str) or not PLAYBOOK_ID.fullmatch(playbook_id):
        raise ValueError("Playbook ID must be lowercase letters, digits and hyphens (at most 64)")
    if not isinstance(entry, dict):
        raise ValueError(f"Playbook {playbook_id} must be an object")
    missing, unknown = PLAYBOOK_REQUIRED - set(entry), set(entry) - PLAYBOOK_REQUIRED - PLAYBOOK_OPTIONAL
    if missing or unknown:
        raise ValueError(f"Playbook {playbook_id}: missing {sorted(missing)}, unknown {sorted(unknown)}")
    repo = Path(_text(entry["repo"], "repo", 1024)).expanduser()
    if not repo.is_absolute():
        raise ValueError(f"Playbook {playbook_id}: repo must be an absolute path (~ allowed)")
    spec = {"repo": str(repo), "playbook": _relative(entry["playbook"], "playbook"),
            "allowed_hosts": _names(entry["allowed_hosts"], "allowed_hosts", host_registry.IDENTIFIER,
                                    minimum=1, maximum=128),
            "groups": _names(entry["groups"], "groups", GROUP, minimum=1, maximum=16),
            "extra_vars_allowed": sorted(_names(entry["extra_vars_allowed"], "extra_vars_allowed", VAR_NAME)),
            "secret_vars": sorted(_names(entry.get("secret_vars", []), "secret_vars", VAR_NAME)),
            "description": _text(entry["description"], "description")}
    if not spec["playbook"].endswith((".yml", ".yaml")):
        raise ValueError(f"Playbook {playbook_id}: playbook must be a .yml/.yaml file")
    if {"all", "ungrouped"} & set(spec["groups"]):
        raise ValueError("groups cannot name the implicit all/ungrouped groups")
    if any(name.startswith(RESERVED_VAR_PREFIXES) for name in spec["extra_vars_allowed"] + spec["secret_vars"]):
        raise ValueError("Extra vars cannot override ansible_* connection/become or switchyard_* variables")
    if type(entry["become"]) is not bool:
        raise ValueError("become must be true or false")
    if entry["check_mode"] not in CHECK_MODES:
        raise ValueError("check_mode must be full, partial or unsupported")
    spec.update(become=entry["become"], check_mode=entry["check_mode"])
    if entry.get("inventory") is not None:
        spec["inventory"] = _relative(entry["inventory"], "inventory")
    return spec


def validate_config(data):
    """The tool configuration (runner pin) plus optional seed registrations; unknown keys are rejected."""
    if not isinstance(data, dict) or not TOP_REQUIRED <= set(data) <= TOP_REQUIRED | TOP_OPTIONAL:
        raise ValueError("Ansible config needs exactly schema_version and runner (and optionally playbooks)")
    if data["schema_version"] != 1 or type(data["schema_version"]) is not int:
        raise ValueError("Expected Ansible config schema_version 1")
    runner = data["runner"]
    if not isinstance(runner, dict) or set(runner) != RUNNER_KEYS:
        raise ValueError("runner needs exactly ansible_core and collections")
    if not isinstance(runner["ansible_core"], str) or not VERSION.fullmatch(runner["ansible_core"]):
        raise ValueError("runner.ansible_core must pin an exact version such as 2.19.15")
    collections = runner["collections"]
    if not isinstance(collections, list) or len(collections) > 32:
        raise ValueError("runner.collections must be a list")
    for item in collections:
        if (not isinstance(item, dict) or set(item) != {"name", "version"} or not isinstance(item["name"], str)
                or not COLLECTION.fullmatch(item["name"]) or not isinstance(item["version"], str)
                or not VERSION.fullmatch(item["version"])):
            raise ValueError("Each collection needs exactly name (namespace.collection) and an exact version")
    if len({item["name"] for item in collections}) != len(collections):
        raise ValueError("Duplicate pinned collection")
    playbooks = data.get("playbooks", {})
    if not isinstance(playbooks, dict) or len(playbooks) > 64:
        raise ValueError("playbooks must map at most 64 playbook IDs to entries")
    return {"schema_version": 1, "runner": deepcopy(runner),
            "playbooks": {playbook_id: validate_playbook(playbook_id, entry) for playbook_id, entry in playbooks.items()}}


def read_config(path):
    with Path(path).expanduser().open("rb") as stream:
        raw = stream.read(262145)
    if len(raw) > 262144:
        raise ValueError("Ansible config exceeds 256 KiB")
    return validate_config(json.loads(raw.decode("utf-8"))), hashlib.sha256(raw).hexdigest()


def load_config(path):
    return read_config(path)[0]


def ssh_options(host_id, pins_path):
    """The same trust Switchyard uses: only the registry's pinned keys, under a host-ID alias."""
    return ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={pins_path}", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", f"HostKeyAlias=switchyard-{host_id}", "-o", "UpdateHostKeys=no",
            "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ProxyCommand=none",
            "-o", "ProxyJump=none", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
            "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no", "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4"]


def connection_vars(record, pins_path):
    config = record["collector"]
    user, address = config["target"].split("@", 1)
    return {"ansible_connection": "ssh", "ansible_host": address, "ansible_user": user,
            "ansible_port": config.get("port", 22), "ansible_host_key_checking": True,
            "ansible_ssh_args": shlex.join(ssh_options(record["id"], pins_path)),
            "ansible_ssh_common_args": "", "ansible_ssh_extra_args": "",
            "switchyard_host_id": record["id"], "switchyard_expected_hostname": config["expected_hostname"]}


def registry_digest(record):
    config = record["collector"]
    return digest({"id": record["id"], "target": config["target"], "port": config.get("port", 22),
                   "expected_hostname": config["expected_hostname"], "ledger": config.get("ledger"),
                   "host_keys": sorted(record["host_keys"]), "connection_revision": record["connection_revision"]})


def _git(repo, *arguments):
    result = subprocess.run(["git", "-C", str(repo), *arguments], stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=60, env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"}, check=False)
    if result.returncode != 0:
        raise ValueError(f"git {arguments[0]} failed in the playbook repo")
    return result.stdout


def repo_state(repo):
    """HEAD commit plus a fingerprint of any uncommitted content (tracked diff and untracked files)."""
    repo = Path(repo)
    if Path(_git(repo, "rev-parse", "--show-toplevel").decode().strip()).resolve() != repo:
        raise ValueError("Playbook repo must be the root of a Git work tree")
    commit = _git(repo, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    status = _git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    fingerprint = hashlib.sha256(commit.encode())
    if status:
        fingerprint.update(status)
        fingerprint.update(_git(repo, "diff", "HEAD", "--binary", "--no-ext-diff", "--no-textconv"))
        for name in sorted(_git(repo, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0")):
            if not name:
                continue
            path = repo / os.fsdecode(name)
            fingerprint.update(name + b"\0")
            if path.is_symlink():
                fingerprint.update(os.fsencode(os.readlink(path)))
            elif path.is_file():
                fingerprint.update(hashlib.sha256(path.read_bytes()).digest())
    return {"commit": commit, "dirty": bool(status), "fingerprint": fingerprint.hexdigest(),
            "changed_paths": len([entry for entry in status.split(b"\0") if entry[:3].strip()])}


class BecomePassword:
    """The operator's become password for one run. It lives in this object from the request until the runner
    has exited (progress and output are scrubbed of it), then `take`/`clear` drop the only reference. Never
    stored, logged or printed; `repr` and `str` show nothing."""

    def __init__(self, value=None):
        if value is not None and (not isinstance(value, str) or not value or len(value) > 1024
                                  or any(character in value for character in "\0\r\n")):
            raise ValueError("The sudo password must be 1-1024 characters on one line")
        self._value = value

    def __bool__(self):
        return self._value is not None

    def take(self):
        value, self._value = self._value, None
        return value

    def clear(self):
        self._value = None

    def __repr__(self):
        return "<become password>" if self._value is not None else "<no become password>"

    __str__ = __repr__


def _leaves(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _leaves(item)
    elif isinstance(value, list):
        for item in value:
            yield from _leaves(item)


class AnsibleStore:
    """Private SQLite registrations, plans, runs and receipts under <state>/ansible/; request IDs are unique."""

    def __init__(self, directory):
        self.directory = private_dir(directory)
        self.inventories = private_dir(self.directory / "inventories")
        self.manual = private_dir(self.directory / "manual")
        self.path = self.directory / "ansible.sqlite3"
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError("Ansible store must be an owned private regular file")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        with self.transaction() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS plans(id TEXT PRIMARY KEY, created REAL NOT NULL, data TEXT NOT NULL,
                    consumed_by TEXT);
                CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL,
                    plan_id TEXT NOT NULL, created REAL NOT NULL, data TEXT NOT NULL, pid INTEGER, birth TEXT);
                CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS playbooks(id TEXT PRIMARY KEY, revision INTEGER NOT NULL, data TEXT NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, host_id TEXT NOT NULL, created REAL NOT NULL,
                    data TEXT NOT NULL, pid INTEGER, birth TEXT);
                CREATE TABLE IF NOT EXISTS host_privilege(host_id TEXT PRIMARY KEY, passwordless_sudo INTEGER,
                    checked_at TEXT NOT NULL);
            """)

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
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

    @staticmethod
    def _touch_audit(db):
        db.execute("INSERT INTO meta VALUES('audit_revision', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                   (uuid.uuid4().hex,))

    # ---- registrations ----

    def seed(self, playbooks, *, source, sha256):
        """Seed registrations once from the configuration file. Idempotent: after the first seed (even an
        empty one) the file's playbooks are never read into the database again, and an existing row is never
        overwritten."""
        with self.transaction() as db:
            if db.execute("SELECT 1 FROM meta WHERE key='seeded_at'").fetchone():
                return False
            at = now_iso()
            for playbook_id, spec in sorted(playbooks.items()):
                db.execute("INSERT OR IGNORE INTO playbooks VALUES(?,1,?,?,?,?)",
                           (playbook_id, encode(spec), at, at, f"seed from {source}"))
            for key, value in (("seeded_at", at), ("seed_source", str(source)), ("seed_sha256", sha256),
                               ("seed_ids", encode(sorted(playbooks)))):
                db.execute("INSERT INTO meta VALUES(?,?)", (key, value))
        return True

    def seed_info(self):
        with self.transaction() as db:
            rows = dict(db.execute("SELECT key, value FROM meta WHERE key LIKE 'seed%'").fetchall())
        return {"seeded_at": rows.get("seeded_at"), "source": rows.get("seed_source"),
                "sha256": rows.get("seed_sha256"), "ids": json.loads(rows.get("seed_ids") or "[]")}

    @staticmethod
    def _registration(row):
        return {"id": row[0], "revision": row[1], "spec": json.loads(row[2]), "created_at": row[3],
                "updated_at": row[4], "updated_by": row[5]}

    def registrations(self):
        with self.transaction() as db:
            rows = db.execute("SELECT id, revision, data, created_at, updated_at, updated_by FROM playbooks "
                              "ORDER BY id").fetchall()
        return [self._registration(row) for row in rows]

    def registration(self, playbook_id):
        with self.transaction() as db:
            row = db.execute("SELECT id, revision, data, created_at, updated_at, updated_by FROM playbooks WHERE id=?",
                             (playbook_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown Ansible playbook ID")
        return self._registration(row)

    def add(self, playbook_id, spec, *, by):
        at = now_iso()
        with self.transaction() as db:
            if db.execute("SELECT 1 FROM playbooks WHERE id=?", (playbook_id,)).fetchone():
                raise ValueError(f"A playbook named {playbook_id} is already registered")
            db.execute("INSERT INTO playbooks VALUES(?,1,?,?,?,?)", (playbook_id, encode(spec), at, at, by))
        return self.registration(playbook_id)

    def update(self, playbook_id, spec, *, expected_revision, by):
        with self.transaction() as db:
            changed = db.execute("UPDATE playbooks SET revision=revision+1, data=?, updated_at=?, updated_by=? "
                                 "WHERE id=? AND revision=?",
                                 (encode(spec), now_iso(), by, playbook_id, expected_revision)).rowcount
            if not changed:
                self._stale(db, playbook_id)
        return self.registration(playbook_id)

    def remove(self, playbook_id, *, expected_revision):
        with self.transaction() as db:
            if not db.execute("DELETE FROM playbooks WHERE id=? AND revision=?", (playbook_id, expected_revision)).rowcount:
                self._stale(db, playbook_id)
        return {"id": playbook_id, "removed": True}

    @staticmethod
    def _stale(db, playbook_id):
        row = db.execute("SELECT revision FROM playbooks WHERE id=?", (playbook_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown Ansible playbook ID")
        raise ValueError(f"The registration changed since you read it (now revision {row[0]}); reload it and "
                         "make your change again")

    # ---- host privilege (last preflight) ----

    def record_privilege(self, host_id, preflight):
        if not preflight.get("reachable") or not preflight.get("identity_ok"):
            return
        with self.transaction() as db:
            db.execute("INSERT INTO host_privilege VALUES(?,?,?) ON CONFLICT(host_id) DO UPDATE SET "
                       "passwordless_sudo=excluded.passwordless_sudo, checked_at=excluded.checked_at",
                       (host_id, int(bool(preflight["passwordless_sudo"])), now_iso()))

    def privilege(self):
        with self.transaction() as db:
            rows = db.execute("SELECT host_id, passwordless_sudo, checked_at FROM host_privilege").fetchall()
        return {row[0]: {"passwordless_sudo": bool(row[1]), "checked_at": row[2]} for row in rows}

    # ---- runs (background and CLI progress) ----

    def _reconcile_runs(self, db):
        for row in db.execute("SELECT id, data, pid, birth FROM runs").fetchall():
            run = json.loads(row[1])
            if run["status"] in ACTIVE_RUNS and (not row[3] or process_identity(row[2]) != row[3]):
                run.update(status="needs-inspection" if run["kind"] == "apply" and run.get("started_playbook")
                           else "interrupted", finished_at=now_iso(), phase="ended",
                           error="Switchyard stopped during this run" + (
                               "; inspect the host before another apply" if run["kind"] == "apply" else ""))
                db.execute("UPDATE runs SET data=? WHERE id=?", (encode(run), row[0]))

    def begin_run(self, run):
        """Record a run; refused while another run for the same host is active (one run per host)."""
        with self.transaction() as db:
            self._reconcile_runs(db)
            for (data,) in db.execute("SELECT data FROM runs WHERE host_id=?", (run["host_id"],)).fetchall():
                other = json.loads(data)
                if other["status"] in ACTIVE_RUNS:
                    raise ValueError(f"{run['host_id']} already has a run in progress ({other['kind']} of "
                                     f"{other['playbook_id']}, run {other['id']}); one run per host at a time")
            db.execute("INSERT INTO runs VALUES(?,?,?,?,?,?)", (run["id"], run["host_id"], time.time(), encode(run),
                                                                os.getpid(), process_identity()))
        return run

    def update_run(self, run_id, **updates):
        with self.transaction() as db:
            row = db.execute("SELECT data FROM runs WHERE id=?", (run_id,)).fetchone()
            run = json.loads(row[0])
            run.update(updates, updated_at=now_iso())
            db.execute("UPDATE runs SET data=? WHERE id=?", (encode(run), run_id))
        return run

    def run(self, run_id):
        with self.transaction() as db:
            self._reconcile_runs(db)
            row = db.execute("SELECT data FROM runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown Ansible run")
        return json.loads(row[0])

    def runs(self, limit=50):
        with self.transaction() as db:
            self._reconcile_runs(db)
            rows = db.execute("SELECT data FROM runs ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    # ---- plans and receipts ----

    def save_plan(self, plan, created):
        with self.transaction() as db:
            db.execute("INSERT INTO plans VALUES(?,?,?,NULL)", (plan["id"], created, encode(plan)))

    def plan(self, plan_id):
        with self.transaction() as db:
            row = db.execute("SELECT data, consumed_by FROM plans WHERE id=?", (plan_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown Ansible plan")
        return {**json.loads(row[0]), "consumed_by": row[1]}

    def plans(self, limit=50):
        with self.transaction() as db:
            rows = db.execute("SELECT data, consumed_by FROM plans ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
        return [{**json.loads(row[0]), "consumed_by": row[1]} for row in rows]

    def _reconcile(self, db):
        for row in db.execute("SELECT id, data, pid, birth FROM receipts "
                              "WHERE json_extract(data,'$.status')='running'").fetchall():
            if not row[3] or process_identity(row[2]) != row[3]:
                receipt = json.loads(row[1])
                receipt.update(status="needs-inspection", finished_at=now_iso(),
                               error="Switchyard process ended during the run; inspect the host before another apply")
                db.execute("UPDATE receipts SET data=? WHERE id=?", (encode(receipt), row[0]))
                self._touch_audit(db)

    def by_request(self, request_id):
        with self.transaction() as db:
            self._reconcile(db)
            row = db.execute("SELECT data FROM receipts WHERE request_id=?", (request_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def begin(self, receipt):
        """Consume the plan and record a running receipt atomically; replay an existing request ID."""
        with self.transaction() as db:
            self._reconcile(db)
            row = db.execute("SELECT data FROM receipts WHERE request_id=?", (receipt["request_id"],)).fetchone()
            if row:
                existing = json.loads(row[0])
                if existing["plan_id"] != receipt["plan_id"]:
                    raise ValueError("Request ID was already used for a different Ansible plan")
                return existing, True
            consumed = db.execute("SELECT consumed_by FROM plans WHERE id=?", (receipt["plan_id"],)).fetchone()
            if consumed is None:
                raise ValueError("Unknown Ansible plan")
            if consumed[0]:
                raise ValueError(f"Plan was already used by receipt {consumed[0]}; make a new plan")
            db.execute("UPDATE plans SET consumed_by=? WHERE id=? AND consumed_by IS NULL",
                       (receipt["id"], receipt["plan_id"]))
            db.execute("INSERT INTO receipts VALUES(?,?,?,?,?,?,?)",
                       (receipt["id"], receipt["request_id"], receipt["plan_id"], time.time(), encode(receipt),
                        os.getpid(), process_identity()))
            self._touch_audit(db)
        return receipt, False

    def finish(self, receipt_id, updates):
        with self.transaction() as db:
            receipt = json.loads(db.execute("SELECT data FROM receipts WHERE id=?", (receipt_id,)).fetchone()[0])
            receipt.update(updates)
            receipt.setdefault("finished_at", now_iso())
            db.execute("UPDATE receipts SET data=? WHERE id=?", (encode(receipt), receipt_id))
            self._touch_audit(db)
        return receipt

    def receipt(self, reference):
        with self.transaction() as db:
            self._reconcile(db)
            row = db.execute("SELECT data FROM receipts WHERE id=? OR request_id=?", (reference, reference)).fetchone()
        if row is None:
            raise ValueError("Unknown Ansible receipt")
        return json.loads(row[0])

    def receipts(self, limit=50):
        with self.transaction() as db:
            self._reconcile(db)
            rows = db.execute("SELECT data FROM receipts ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(row[0]) for row in rows]


# ---- the Audit log view (read-only; never creates the store) --------------------------------------

def _read_only(state_dir):
    path = Path(state_dir) / "ansible" / "ansible.sqlite3"
    if not path.is_file():
        return None
    try:
        return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=3)
    except sqlite3.Error:
        return None


def audit_revision(state_dir):
    db = _read_only(state_dir)
    if db is None:
        return "none"
    try:
        row = db.execute("SELECT value FROM meta WHERE key='audit_revision'").fetchone()
        return row[0] if row else "none"
    except sqlite3.Error:
        return "unavailable"
    finally:
        db.close()


def _audit_entry(receipt, pid, birth):
    if receipt.get("status") == "running" and (not birth or process_identity(pid) != birth):
        receipt = {**receipt, "status": "needs-inspection",
                   "error": "Switchyard process ended during the run; inspect the host before another apply"}
    return {**receipt, "host_ids": [receipt["host_id"]], "action": "ansible-apply"}


def audit_receipts(state_dir, limit=200):
    """Ansible apply receipts shaped for the Audit log (`host_ids`, `action`). A receipt whose process died is
    shown as needs-inspection here; the store records that on its next write."""
    db = _read_only(state_dir)
    if db is None:
        return []
    try:
        rows = db.execute("SELECT data, pid, birth FROM receipts ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
    except sqlite3.Error:
        return []
    finally:
        db.close()
    return [_audit_entry(json.loads(row[0]), row[1], row[2]) for row in rows]


def audit_receipt(state_dir, receipt_id):
    db = _read_only(state_dir)
    if db is None:
        raise ValueError("Unknown operation")
    try:
        row = db.execute("SELECT data, pid, birth FROM receipts WHERE id=?", (receipt_id,)).fetchone()
    finally:
        db.close()
    if row is None:
        raise ValueError("Unknown operation")
    return _audit_entry(json.loads(row[0]), row[1], row[2])


# ---- background runs ----------------------------------------------------------------------------

class Jobs:
    """Desk-started plans and applies run in daemon threads of the web process. `shutdown` stops every runner
    group (as a deadline would), so each job finishes its receipt and releases its lease before exit."""

    def __init__(self):
        self._lock = threading.Lock()
        self._jobs = {}

    def start(self, run_id, target):
        cancel = threading.Event()

        def body():
            try:
                target(cancel)
            except BaseException:
                pass  # The job recorded its own outcome on the run before raising.
            finally:
                with self._lock:
                    self._jobs.pop(run_id, None)

        thread = threading.Thread(target=body, name=f"ansible-{run_id[:8]}", daemon=True)
        with self._lock:
            self._jobs[run_id] = (thread, cancel)
        thread.start()

    def active(self):
        with self._lock:
            return sorted(self._jobs)

    def shutdown(self, timeout=30.0):
        with self._lock:
            jobs = list(self._jobs.values())
        for _, cancel in jobs:
            cancel.set()
        deadline = time.monotonic() + timeout
        for thread, _ in jobs:
            thread.join(max(0.0, deadline - time.monotonic()))


JOBS = Jobs()
_DISCOVERY = OrderedDict()
_DISCOVERY_LOCK = threading.Lock()


def _safe_error(error):
    """Errors recorded on runs: Switchyard's own messages (no values or passwords); anything else by type."""
    if isinstance(error, (ValueError, LeaseBusy, OSError, subprocess.SubprocessError)):
        return str(error)[:600]
    return f"Unexpected error ({type(error).__name__}); inspect the host before another apply"


class AnsibleOps:
    def __init__(self, config_path, *, hosts, pins_path, state_dir, cache_dir=None, clock=time.time,
                 plan_timeout=PLAN_TIMEOUT, apply_timeout=APPLY_TIMEOUT, owner=None, paseo_agents=None, home=None):
        self.config_path = Path(config_path).expanduser()
        self.config, self.config_sha256 = read_config(self.config_path)
        self.hosts = {record["id"]: record for record in hosts}
        self.pins_path = Path(pins_path)
        self.state_dir = Path(state_dir)
        self.home = Path(home) if home is not None else Path.home()
        cache_dir = cache_dir or Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "switchyard" / "ansible"
        self.runner = Runner(self.config["runner"], self.state_dir, cache_dir)
        self.store = AnsibleStore(self.state_dir / "ansible")
        self.store.seed(self.config["playbooks"], source=self.config_path, sha256=self.config_sha256)
        self.clock = clock
        self.plan_timeout = plan_timeout
        self.apply_timeout = apply_timeout
        self._owner = owner
        self._paseo_agents = paseo_agents or {}

    # ---- registrations and repo ------------------------------------------------------------

    def _playbook(self, playbook_id):
        if not isinstance(playbook_id, str) or not PLAYBOOK_ID.fullmatch(playbook_id):
            raise ValueError("Unknown Ansible playbook ID")
        return self.store.registration(playbook_id)["spec"]

    def _host(self, host_id):
        record = self.hosts.get(host_id) if isinstance(host_id, str) else None
        if record is None:
            raise ValueError("Unknown registry host ID")
        config = record.get("collector") or {}
        if config.get("transport") != "ssh":
            raise ValueError(f"{host_id} is not an SSH host; Ansible inventory covers SSH hosts only")
        if not record.get("host_keys"):
            raise ValueError(f"{host_id} has no pinned SSH host keys; pin them (host-scan-key, host-pin-key) first")
        try:
            pins = self.pins_path.read_text()
        except OSError as error:
            raise ValueError("Switchyard's SSH pin file is unavailable") from error
        if not any(line.startswith(f"switchyard-{host_id} ") for line in pins.splitlines()):
            raise ValueError(f"{host_id} is missing from Switchyard's SSH pin file")
        return record

    def _repo(self, spec):
        """The registered repo and playbook: inside the operator's home, the operator's own files, no symlink
        leading outside the repo."""
        repo = discovery.owned_root(spec["repo"], self.home)
        playbook = discovery.owned_file(repo, spec["playbook"], "Playbook")
        return repo, playbook

    def _repo_layer(self, spec, record, repo):
        """The repo's own inventory vars for this host (matched by registry ID, then expected hostname)."""
        if "inventory" not in spec:
            return {}, set(), {}
        path = discovery.owned_file(repo, spec["inventory"], "Inventory")
        listing = discovery.inventory_listing(self.runner, repo, path, (repo / spec["playbook"]).resolve().parent)
        names = [record["id"], record["collector"]["expected_hostname"]]
        match, found, variables = discovery.membership(listing, names)
        if match is None:
            raise ValueError(f"{record['id']} is not in the repo inventory as {' or '.join(dict.fromkeys(names))}")
        if discovery.vaulted(variables):
            raise ValueError("Vault-encrypted or malformed repo inventory vars are not supported")
        kept = {key: value for key, value in variables.items() if not key.startswith(RESERVED_VAR_PREFIXES)}
        return kept, found, {"repo_inventory_host": match, "repo_vars": sorted(kept),
                             "repo_vars_replaced": sorted(set(variables) - set(kept))}

    def _inventory_for(self, spec, record, repo):
        layered, groups, info = self._repo_layer(spec, record, repo)
        groups = sorted(set(spec["groups"]) | groups)
        variables = {**layered, **connection_vars(record, self.pins_path)}
        inventory = {"all": {"hosts": {record["id"]: variables},
                             "children": {group: {"hosts": {record["id"]: {}}} for group in groups}}}
        return inventory, {"groups": groups, **info}

    def _registration_spec(self, playbook_id, entry):
        """A registration from the desk or CLI: the seed rules plus path, ownership and registry checks."""
        spec = validate_playbook(playbook_id, entry)
        repo = discovery.owned_root(spec["repo"], self.home)
        spec["repo"] = str(repo)
        repo_state(repo)
        discovery.owned_file(repo, spec["playbook"], "Playbook")
        if "inventory" in spec:
            discovery.owned_file(repo, spec["inventory"], "Inventory")
        for host_id in spec["allowed_hosts"]:
            record = self.hosts.get(host_id)
            if record is None or (record.get("collector") or {}).get("transport") != "ssh":
                raise ValueError(f"{host_id} is not an SSH host in the host registry")
        return spec

    def _editor(self):
        return self._lease_owner()

    def register(self, playbook_id, entry):
        spec = self._registration_spec(playbook_id, entry)
        return self.store.add(playbook_id, spec, by=self._editor())

    def update_registration(self, playbook_id, entry, *, expected_revision):
        self._playbook(playbook_id)
        if type(expected_revision) is not int:
            raise ValueError("expected_revision must be the registration's revision number")
        spec = self._registration_spec(playbook_id, entry)
        return self.store.update(playbook_id, spec, expected_revision=expected_revision, by=self._editor())

    def remove_registration(self, playbook_id, *, expected_revision):
        self._playbook(playbook_id)
        if type(expected_revision) is not int:
            raise ValueError("expected_revision must be the registration's revision number")
        return self.store.remove(playbook_id, expected_revision=expected_revision)

    # ---- reads -------------------------------------------------------------------------

    def _host_rows(self, spec, privilege):
        hosts = []
        for host_id in spec["allowed_hosts"]:
            row = {"host_id": host_id, "eligible": True, **(privilege.get(host_id) or {"passwordless_sudo": None})}
            try:
                self._host(host_id)
            except ValueError as error:
                row.update(eligible=False, reason=str(error))
            hosts.append(row)
        return hosts

    def _row(self, registration, privilege):
        spec = registration["spec"]
        try:
            repo, _ = self._repo(spec)
            state = repo_state(repo)
            repo_view = {"commit": state["commit"], "dirty": state["dirty"], "changed_paths": state["changed_paths"]}
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            repo_view = {"error": str(error)}
        return {"id": registration["id"], "revision": registration["revision"], **deepcopy(spec),
                "registered": {key: registration[key] for key in ("created_at", "updated_at", "updated_by")},
                "repo_state": repo_view, "hosts": self._host_rows(spec, privilege)}

    def playbooks(self):
        privilege = self.store.privilege()
        rows = [self._row(registration, privilege) for registration in self.store.registrations()]
        seed = self.store.seed_info()
        file_differs = sorted(playbook_id for playbook_id, spec in self.config["playbooks"].items()
                              if not any(row["id"] == playbook_id and {key: row[key] for key in spec} == spec
                                         for row in rows))
        return {"config": str(self.config_path), "runner": deepcopy(self.config["runner"]),
                "registry": {"authority": "database", "path": str(self.store.path), "seed": seed,
                             "config_playbooks_not_in_database": file_differs},
                "playbooks": rows}

    def discover(self, playbook_id):
        """Variables, plays and roles the playbook exposes, plus what the repo inventory sets per allowed host.
        Local only (pinned runner's YAML parser and ansible-inventory); cached per repo content."""
        spec = self._playbook(playbook_id)
        repo, _ = self._repo(spec)
        state = repo_state(repo)
        hosts = {host_id: (self.hosts.get(host_id) or {}).get("collector", {}).get("expected_hostname")
                 for host_id in spec["allowed_hosts"]}
        key = digest([playbook_id, spec, state["fingerprint"], self.runner.version, hosts, str(self.home)])
        with _DISCOVERY_LOCK:
            if key in _DISCOVERY:
                _DISCOVERY.move_to_end(key)
                return deepcopy(_DISCOVERY[key])
        self.runner.prepare()
        scanned = discovery.scan(repo)
        loaded = discovery.load_yaml(self.runner, repo, scanned["yaml"])
        found = discovery.model(loaded, repo, spec["playbook"])
        layers, problems = {}, list(found["problems"])
        listing = None
        if "inventory" in spec:
            try:
                path = discovery.owned_file(repo, spec["inventory"], "Inventory")
                listing = discovery.inventory_listing(self.runner, repo, path, (repo / spec["playbook"]).parent)
            except ValueError as error:
                problems.append(str(error))
        for host_id in spec["allowed_hosts"]:
            record = self.hosts.get(host_id)
            if record is None:
                layers[host_id] = {"values": {}, "error": "not in the host registry"}
            elif listing is None:
                layers[host_id] = {"values": {}, "error": "no repository inventory registered" if "inventory" not in spec
                                   else "the repository inventory could not be read"}
            else:
                layers[host_id] = discovery.host_values(listing, loaded, record, inventory=spec["inventory"],
                                                        playbook=spec["playbook"])
        variables = discovery.finish(found["variables"], allowed=spec["extra_vars_allowed"],
                                     secret_flags=spec["secret_vars"], host_layers=layers)
        secret = {var["name"] for var in variables if var["secret"]}
        host_view = {}
        for host_id, layer in layers.items():
            values = {name: ({"origin": entry["origin"], "hidden": True} if entry["vaulted"] or name in secret
                             else {"origin": entry["origin"], "value": entry["value"], "templated": entry["templated"]})
                      for name, entry in sorted((layer.get("values") or {}).items())}
            host_view[host_id] = {"inventory_host": layer.get("inventory_host"), "groups": layer.get("groups", []),
                                  "error": layer.get("error"), "values": values}
        result = {"playbook_id": playbook_id, "commit": state["commit"], "dirty": state["dirty"],
                  "plays": found["plays"], "roles": found["roles"], "variables": variables, "hosts": host_view,
                  "become_in_plays": any(play.get("become") for play in found["plays"]),
                  "problems": problems[:50], "skipped": scanned["skipped"], "truncated": scanned["truncated"]}
        with _DISCOVERY_LOCK:
            _DISCOVERY[key] = deepcopy(result)
            while len(_DISCOVERY) > 16:
                _DISCOVERY.popitem(last=False)
        return result

    def playbook(self, playbook_id):
        """One registration with its repo state, variables, roles, and recent plans, runs and receipts."""
        self._playbook(playbook_id)
        registration = self.store.registration(playbook_id)
        row = self._row(registration, self.store.privilege())
        try:
            row["discovery"] = self.discover(playbook_id)
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            row["discovery"] = {"error": str(error)}
        row["plans"] = [self._plan_summary(plan) for plan in self.plans() if plan["playbook_id"] == playbook_id][:10]
        row["receipts"] = [receipt for receipt in self.receipts() if receipt["playbook_id"] == playbook_id][:10]
        row["runs"] = [run for run in self.store.runs() if run["playbook_id"] == playbook_id][:10]
        return row

    @staticmethod
    def _plan_summary(plan):
        check = plan.get("check") or {}
        return {key: plan.get(key) for key in ("id", "status", "applicable", "host_id", "created_at", "expires_at",
                                               "consumed_by", "blockers")} | {
            "commit": (plan.get("repo") or {}).get("commit"), "changed_tasks": check.get("changed_tasks", [])}

    def inspect_directory(self, path):
        """What a directory offers for registration: Git state, playbooks, inventories, roles and variables.
        Read-only and local; refuses paths outside the operator's home and files that are not the operator's."""
        repo = discovery.owned_root(path, self.home)
        try:
            state = repo_state(repo)
            git = {"repository": True, "commit": state["commit"], "dirty": state["dirty"]}
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            git = {"repository": False, "error": str(error)}
        self.runner.prepare()
        scanned = discovery.scan(repo)
        loaded = discovery.load_yaml(self.runner, repo, scanned["yaml"])
        playbooks = []
        for relative in scanned["yaml"]:
            if len(Path(relative).parts) > 2 or not discovery.looks_like_playbook((loaded.get(relative) or {}).get("data")):
                continue
            if len(playbooks) >= discovery.MAX_PLAYBOOKS:
                break
            found = discovery.model(loaded, repo, relative)
            playbooks.append({"path": relative, "plays": found["plays"], "roles": found["roles"],
                              "variables": discovery.finish(found["variables"], allowed=[], secret_flags=[], host_layers={}),
                              "problems": found["problems"][:20]})
        registry = {record["id"]: record for record in self.hosts.values()
                    if (record.get("collector") or {}).get("transport") == "ssh"}
        inventories = []
        for relative in dict.fromkeys(scanned["inventory"]):
            parts = Path(relative).parts
            if {"group_vars", "host_vars"} & set(parts):
                continue
            data = (loaded.get(relative) or {}).get("data")
            if relative.endswith(discovery.YAML_SUFFIXES) and not (isinstance(data, dict) and data):
                continue
            if len(inventories) >= discovery.MAX_INVENTORIES:
                break
            entry = {"path": relative}
            try:
                listing = discovery.inventory_listing(self.runner, repo, discovery.owned_file(repo, relative, "Inventory"), repo)
                entry["groups"], entry["hosts"] = discovery.inventory_summary(listing)
                entry["registry_hosts"] = sorted(
                    host_id for host_id, record in registry.items()
                    if discovery.membership(listing, [host_id, record["collector"].get("expected_hostname")])[0])
            except ValueError as error:
                entry["error"] = str(error)
            inventories.append(entry)
        return {"path": str(repo), "git": git, "playbooks": playbooks, "inventories": inventories,
                "ssh_hosts": sorted(registry), "skipped": scanned["skipped"], "truncated": scanned["truncated"]}

    def inventory(self, host_id=None, playbook_id=None):
        """Generated inventory. Local only; with a playbook it also runs the pinned ansible-inventory on the
        repo's inventory to layer its vars and groups."""
        if playbook_id is not None:
            spec = self._playbook(playbook_id)
            if host_id is None:
                raise ValueError("--playbook needs --host")
            if host_id not in spec["allowed_hosts"]:
                raise ValueError(f"{host_id} is not allowed for playbook {playbook_id}")
            repo, _ = self._repo(spec)
            self.runner.prepare()
            inventory, info = self._inventory_for(spec, self._host(host_id), repo)
            return {"inventory": inventory, "sha256": digest(inventory), "layering": info, "refused": []}
        selected = [host_id] if host_id is not None else list(self.hosts)
        hosts, refused = {}, []
        for identity in selected:
            try:
                hosts[identity] = connection_vars(self._host(identity), self.pins_path)
            except ValueError as error:
                if host_id is not None:
                    raise
                if (self.hosts[identity].get("collector") or {}).get("transport") == "ssh":
                    refused.append({"host_id": identity, "reason": str(error)})
        inventory = {"all": {"hosts": hosts}}
        return {"inventory": inventory, "sha256": digest(inventory), "refused": refused}

    @staticmethod
    def _public_plan(plan):
        return deepcopy(plan)

    def plans(self):
        return [self._public_plan(plan) for plan in self.store.plans()]

    def plan_record(self, plan_id):
        if not isinstance(plan_id, str) or not PLAN_ID.fullmatch(plan_id):
            raise ValueError("Invalid Ansible plan ID")
        return self._public_plan(self.store.plan(plan_id))

    def receipts(self):
        return self.store.receipts()

    def receipt(self, reference):
        if not isinstance(reference, str) or not REQUEST_ID.fullmatch(reference):
            raise ValueError("Invalid receipt or request ID")
        return self.store.receipt(reference)

    def runs(self):
        return self.store.runs()

    def run(self, run_id):
        if not isinstance(run_id, str) or not PLAN_ID.fullmatch(run_id):
            raise ValueError("Invalid Ansible run ID")
        run = self.store.run(run_id)
        if run.get("plan_id") and run["kind"] == "plan" and run["status"] not in ACTIVE_RUNS:
            try:
                run["plan"] = self.plan_record(run["plan_id"])
            except ValueError:
                pass
        if run.get("receipt_id"):
            try:
                run["receipt"] = self.store.receipt(run["receipt_id"])
            except ValueError:
                pass
        return run

    # ---- leases and preflight ------------------------------------------------------------

    def _lease_owner(self):
        if self._owner:
            return self._owner
        try:
            from .agent_leases import caller_identity
            return caller_identity(self._paseo_agents)["owner"]
        except Exception:
            import getpass
            return getpass.getuser()

    def _busy(self, ledger):
        """Name the holder of a busy ledger (read-only lock observation, as `switchyard lease status`)."""
        try:
            from . import locks
            from .agent_leases import busy_message
            observed = locks.device_locks(ledger.parent, self._paseo_agents, lease_state_dir=self.state_dir / "leases")
            row = next(row for row in observed["ledgers"] if Path(row["path"]).resolve() == ledger.resolve())
            return busy_message(row)
        except Exception:
            return f"{ledger.name[len('DEVICE_ACCESS_'):-3]} busy: holder unknown"

    @contextmanager
    def _lease(self, record, scope, wait):
        if isinstance(wait, bool) or not isinstance(wait, (int, float)) or not 0 <= wait <= MAX_LEASE_WAIT:
            raise ValueError(f"Lease wait must be 0-{MAX_LEASE_WAIT} seconds")
        ledger = Path(record["collector"]["ledger"])
        broker = LedgerBroker({record["id"]: ledger})
        context = broker.hold(record["id"], owner=self._lease_owner(), scope=scope,
                              worktree=str(Path(__file__).resolve().parents[1]),
                              metadata={"pid": os.getpid(), "via": "switchyard ansible"}, wait=wait)
        try:
            lease = context.__enter__()
        except LeaseBusy:
            raise LeaseBusy(self._busy(ledger)) from None
        try:
            # A device the operator broke a lease on stays off-limits until `lease clear`; checked while
            # holding its ledger so a concurrent break cannot slip in between.
            from .agent_leases import block_for_ledger, blocked_message
            block = block_for_ledger(self.state_dir / "leases", ledger)
            if block:
                raise LeaseBusy(blocked_message(ledger.name[len("DEVICE_ACCESS_"):-3], block))
            yield lease
        except BaseException as error:
            if not context.__exit__(type(error), error, error.__traceback__):
                raise
        else:
            context.__exit__(None, None, None)

    def _preflight(self, record):
        """Under the lease: identity (hostname, non-root) and `sudo -n true`, over the pinned SSH trust."""
        config = record["collector"]
        script = PREFLIGHT_SCRIPT.format(hostname=shlex.quote(config["expected_hostname"]))
        # SSH invokes the account's login shell, which may be fish. Run POSIX syntax under sh.
        remote_command = shlex.join(("/bin/sh", "-c", script))
        command = ["ssh", "-T", *ssh_options(record["id"], self.pins_path), "-p", str(config.get("port", 22)),
                   "--", config["target"], remote_command]
        environment = {key: os.environ[key] for key in ("PATH", "HOME", "USER", "LOGNAME", "SSH_AUTH_SOCK")
                       if key in os.environ}
        result = run_process(command, cwd=str(self.runner.root), env=environment, timeout=PREFLIGHT_TIMEOUT)
        if result.exit_code == 0:
            preflight = {"reachable": True, "identity_ok": True, "passwordless_sudo": True}
        elif result.exit_code == 10:
            preflight = {"reachable": True, "identity_ok": True, "passwordless_sudo": False}
        elif result.exit_code == 78:
            preflight = {"reachable": True, "identity_ok": False, "passwordless_sudo": None,
                         "error": "Host identity mismatch (hostname or root login); nothing executed"}
        else:
            preflight = {"reachable": False, "identity_ok": None, "passwordless_sudo": None,
                         "error": "SSH preflight failed" + (" (timeout)" if result.timed_out else f" (exit {result.exit_code})")}
        self.store.record_privilege(record["id"], preflight)
        return preflight

    def probe(self, host_id, *, wait=30):
        """Read-only connectivity proof under the lease: preflight, then Ansible `setup` with a small fact subset."""
        record = self._host(host_id)
        self.runner.prepare()
        version = self.runner.check_version()
        run_dir = self.runner.run_dir()
        try:
            inventory = run_dir / "inventory.yml"
            write_private(inventory, json.dumps({"all": {"hosts": {host_id: connection_vars(record, self.pins_path)}}}))
            arguments = json.dumps({"gather_subset": ["!all"], "filter": [
                "ansible_distribution", "ansible_distribution_version", "ansible_hostname",
                "ansible_python_version", "ansible_user_id"]})
            with self._lease(record, f"ansible probe {host_id} (read-only setup facts, sudo -n probe)", wait) as lease:
                preflight = self._preflight(record)
                facts = None
                if preflight["reachable"] and preflight["identity_ok"]:
                    environment = self.runner.environment()
                    environment["ANSIBLE_LOAD_CALLBACK_PLUGINS"] = "False"
                    result = run_process(self.runner.command("ansible", host_id, "-i", str(inventory), "--one-line",
                                                             "-m", "ansible.builtin.setup", "-a", arguments),
                                         cwd=str(self.runner.root), env=environment, timeout=120,
                                         stdout_limit=262144)
                    facts = _oneline_facts(result.stdout.decode("utf-8", "replace"), host_id)
                    facts["exit_code"] = result.exit_code
                lease["release"].update(ansible_probe=host_id)
            return {"host_id": host_id, "ansible_core": version, "lease_id": lease["lease_id"],
                    "preflight": preflight, "setup": facts}
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    # ---- running -------------------------------------------------------------------------

    def _run_playbook(self, plan, record, playbook, values, *, check, timeout, secrets=(), become_password=None,
                      progress=None, cancel=None):
        """One ansible-playbook run. Overrides go in a private extra-vars file in the run's scratch directory
        (deleted afterwards); a become password goes into an anonymous pipe on the runner's stdin, read by
        `--become-password-file -`. The callback's events go through a FIFO into memory and are scrubbed of
        secret values and the password line by line before anything keeps them (nothing reaches the disk);
        the stderr tail is scrubbed too. This frame drops the password when the run ends."""
        run_dir = self.runner.run_dir()
        scrub = [item for item in secrets if item] + ([become_password] if become_password else [])
        stream = None
        try:
            # Task names are templated and failure messages are free text: either can carry a secret value.
            stream = EventStream(run_dir, lambda event: redact(event, scrub))
            arguments = ["-i", plan["inventory"]["path"], "--limit", record["id"]]
            if values:
                variables = run_dir / "extra-vars.json"
                write_private(variables, json.dumps(values))
                arguments += ["-e", "@" + str(variables)]
            # Connection vars again as extra vars: highest precedence, so no repo/play var can redirect SSH.
            arguments += ["-e", "@" + plan["inventory"]["connection_path"]]
            if become_password:
                arguments += ["--become-password-file", "-"]  # "-": ansible-core reads stdin to EOF.
            arguments += (["--check"] if check else []) + ["--diff", str(playbook)]
            command = self.runner.command("ansible-playbook", *arguments)
            environment = self.runner.environment(events=stream.path)
            tick = (lambda: progress(parse_records(stream.records()))) if progress else None
            stdin_fd = _stdin_pipe(become_password.encode()) if become_password else None
            result = run_process(command, cwd=plan["playbook"]["repo"], env=environment, timeout=timeout,
                                 stdin_fd=stdin_fd, tick=tick, cancel=cancel)
            stream.close()  # The runner has exited: drain the last events.
            summary = parse_records(stream.records())
            if progress:
                progress(summary)  # The final snapshot: every task, not only those seen by the last tick.
            return result, summary, self._scrub(result.stderr_tail, scrub)
        finally:
            if stream is not None:
                stream.close()
            scrub.clear()
            become_password = None
            shutil.rmtree(run_dir, ignore_errors=True)

    @staticmethod
    def _scrub(text, secrets):
        return redact(text, secrets)[-1024:]

    def _write_inventory(self, plan_id, inventory, record):
        path = self.store.inventories / f"{plan_id}.yml"
        connection = self.store.inventories / f"{plan_id}.connection.json"
        write_private(path, json.dumps(inventory, indent=2, sort_keys=True) + "\n")
        write_private(connection, json.dumps(connection_vars(record, self.pins_path), indent=2, sort_keys=True) + "\n")
        return str(path), str(connection)

    def _variables(self, playbook_id, spec):
        """The discovered variable list; without a readable repository, every overridable name is text and
        secret (the conservative reading)."""
        try:
            return self.discover(playbook_id)["variables"]
        except (ValueError, OSError, subprocess.SubprocessError):
            return [{"name": name, "type": "str", "choices": None, "elements": None, "secret": True,
                     "overridable": True} for name in spec["extra_vars_allowed"]]

    def _operator_commands(self, plan, spec, record, playbook, values, secret_names):
        repo = plan["playbook"]["repo"]
        environment = self.runner.ansible_environment(operator=True)
        environment["TMPDIR"] = str(self.runner.tmp)
        base = ["-i", plan["inventory"]["path"], "--limit", record["id"]]
        if values:
            # Recorded (non-secret) overrides are already part of the plan; secret ones stay placeholders.
            variables = self.store.inventories / f"{plan['id']}.extra-vars.json"
            write_private(variables, json.dumps(values, indent=2, sort_keys=True) + "\n")
            base += ["-e", "@" + str(variables)]
        for name in secret_names:
            base += ["-e", f"{name}=<value>"]
        base += ["-e", "@" + plan["inventory"]["connection_path"], "--ask-become-pass"]
        events = self.store.manual / f"{plan['id']}-apply.jsonl"
        commands = {}
        for label, flags, extra_env in (("check", ["--check", "--diff"], {}),
                                        ("apply", ["--diff"], {"SWITCHYARD_ANSIBLE_EVENTS": str(events)})):
            assignments = [f"{key}={value}" for key, value in sorted({**environment, **extra_env}.items())]
            runner = self.runner.command("ansible-playbook", *base, *flags, str(playbook))
            scope = f"ansible {plan['playbook_id']} {label} on {record['id']} (operator, become; plan {plan['id'][:8]})"
            commands[label] = shlex.join(["switchyard", "lease", "run", record["id"], "--scope", scope, "--wait", "60",
                                          "--", "env", "-C", repo, *assignments, *runner])
        commands["record"] = shlex.join(["switchyard", "ansible", "record-manual", plan["id"], "--request-id",
                                         "<new request ID>"])
        return commands

    def _new_run(self, kind, playbook_id, host_id, **extra):
        return self.store.begin_run({"id": uuid.uuid4().hex, "kind": kind, "status": "running", "phase": "preparing",
                                     "playbook_id": playbook_id, "host_id": host_id, "created_at": now_iso(),
                                     "updated_at": now_iso(), "requested_by": self._lease_owner(),
                                     "progress": None, **extra})

    def _progress(self, run_id):
        def record(summary):
            tasks = summary["tasks"]
            counts = {}
            for task in tasks:
                counts[task.get("status")] = counts.get(task.get("status"), 0) + 1
            self.store.update_run(run_id, progress={
                "play": summary.get("current_play"), "task": summary.get("current_task"), "counts": counts,
                "tasks": tasks[-120:], "truncated": summary["truncated"] or len(tasks) > 120})
        return record

    @staticmethod
    def _refused(summary):
        return any(REFUSED_PASSWORD.search(str(task.get("msg") or "")) for task in summary["tasks"]
                   if task.get("status") in {"failed", "unreachable"})

    def _launch(self, run, job, background):
        if background:
            JOBS.start(run["id"], job)
            return run
        return job(None)

    def _guard(self, run, body):
        """Record the run's outcome whatever happens, then re-raise."""
        def job(cancel):
            try:
                return body(cancel)
            except LeaseBusy as error:
                self.store.update_run(run["id"], status="busy", phase="ended", finished_at=now_iso(),
                                      error=_safe_error(error))
                raise
            except BaseException as error:
                current = self.store.run(run["id"])
                if current["status"] in ACTIVE_RUNS:
                    started = current.get("started_playbook") and run["kind"] == "apply"
                    self.store.update_run(run["id"], status="needs-inspection" if started else "failed",
                                          phase="ended", finished_at=now_iso(), error=_safe_error(error))
                raise
        return job

    # ---- plan ----------------------------------------------------------------------------

    def plan(self, playbook_id, host_id, *, extra_vars=None, allow_dirty=False, wait=30, become_password=None,
             background=False):
        """Validate now; then (in the background, or here) a check-mode run under the host's lease. Returns the
        run record when backgrounded, else the plan. `become_password` is a BecomePassword."""
        password = become_password if isinstance(become_password, BecomePassword) else BecomePassword(become_password)
        try:
            spec = self._playbook(playbook_id)
            if host_id not in spec["allowed_hosts"]:
                raise ValueError(f"{host_id} is not allowed for playbook {playbook_id}")
            record = self._host(host_id)
            if password and not spec["become"]:
                raise ValueError("This playbook is not registered as using become; no sudo password is needed")
            if type(allow_dirty) is not bool:
                raise ValueError("allow_dirty must be true or false")
            repo, playbook = self._repo(spec)
            state = repo_state(repo)
            if state["dirty"] and not allow_dirty:
                raise ValueError("Playbook repo has uncommitted changes; commit them, or pass --allow-dirty "
                                 "(recorded in the plan and receipt)")
            variables = self._variables(playbook_id, spec)
            values = discovery.validate_values(variables, extra_vars or {})
            secret_names = sorted(name for name in values if any(var["name"] == name and var["secret"] for var in variables))
            run = self._new_run("plan", playbook_id, host_id, overrides=sorted(values),
                                become_password=SUPPLIED if password else None)
        except BaseException:
            password.clear()
            raise
        body = lambda cancel: self._plan_body(run, spec, record, repo, playbook, state, values, secret_names,
                                             allow_dirty, wait, password, cancel)
        return self._launch(run, self._guard(run, body), background)

    def _plan_body(self, run, spec, record, repo, playbook, state, values, secret_names, allow_dirty, wait,
                   password, cancel):
        try:
            self.runner.prepare()
            version = self.runner.check_version()
            inventory, layering = self._inventory_for(spec, record, repo)
            playbook_id, host_id = run["playbook_id"], run["host_id"]
            plan_id = uuid.uuid4().hex
            created = self.clock()
            inventory_path, connection_path = self._write_inventory(plan_id, inventory, record)
            secret_values = [leaf for name in secret_names for leaf in _leaves(values[name])]
            plan = {"id": plan_id, "kind": "ansible-plan", "status": "failed", "applicable": False, "blockers": [],
                    "created_at": now_iso(created), "expires_at": now_iso(created + PLAN_TTL),
                    "playbook_id": playbook_id,
                    "playbook": {"repo": str(repo), "path": spec["playbook"], "become": spec["become"],
                                 "check_mode": spec["check_mode"], "spec_sha256": digest(spec)},
                    "host_id": host_id, "registry_sha256": registry_digest(record),
                    "repo": state, "allow_dirty": allow_dirty, "ansible_core": version,
                    "inventory": {"path": inventory_path, "connection_path": connection_path,
                                  "sha256": digest(inventory), **layering},
                    "extra_vars": {"names": sorted(values),
                                   "values": {name: value for name, value in values.items() if name not in secret_names},
                                   "secret_names": secret_names},
                    "check": {"ran": False}, "run_id": run["id"]}
            self.store.update_run(run["id"], plan_id=plan_id, phase="waiting for the lease")
            scope = f"ansible plan {playbook_id} on {host_id} (check mode; plan {plan_id[:8]})"
            with self._lease(record, scope, wait) as lease:
                plan["lease_id"] = lease["lease_id"]
                self.store.update_run(run["id"], phase="preflight: identity and sudo -n", lease_id=lease["lease_id"])
                preflight = self._preflight(record)
                plan["preflight"] = preflight
                needs_password = spec["become"] and preflight["passwordless_sudo"] is False
                if not preflight["reachable"] or not preflight["identity_ok"]:
                    plan["blockers"].append(preflight["error"])
                elif needs_password and not password:
                    plan["status"] = "needs-operator-privilege"
                    plan["blockers"].append("The playbook uses sudo and this host has no passwordless sudo, so the check "
                                            "did not run. Plan again with the sudo password for one run, or run the "
                                            "plan's leased commands (operator_commands) in your own terminal.")
                elif spec["check_mode"] == "unsupported":
                    plan["status"] = "planned"
                    plan["check"] = {"ran": False, "reason": "Playbook is registered as not supporting check mode; "
                                     "nothing is predicted"}
                else:
                    if needs_password:
                        plan["become_password"] = SUPPLIED
                    self.store.update_run(run["id"], phase="check-mode run")
                    result, summary, stderr = self._run_playbook(
                        plan, record, playbook, values, check=True, timeout=self.plan_timeout, secrets=secret_values,
                        become_password=password.take() if needs_password else None,
                        progress=self._progress(run["id"]), cancel=cancel)
                    plan["check"] = {"ran": True, "exit_code": result.exit_code, "timed_out": result.timed_out,
                                     "duration_seconds": round(result.finished - result.started, 1),
                                     "stderr_tail": stderr, **summary}
                    if result.cancelled:
                        plan["blockers"].append("Switchyard stopped during the check run; nothing was applied")
                    elif result.timed_out:
                        plan["blockers"].append(f"Check run exceeded {self.plan_timeout} s and was killed")
                    elif needs_password and self._refused(summary):
                        plan["become_refused"] = True
                        plan["blockers"].append(SUDO_REFUSED)
                    elif result.exit_code != 0 or summary["ended"] is None:
                        plan["blockers"].append(f"Check run failed (exit {result.exit_code}); failed tasks: "
                                                + (", ".join(summary["failed_tasks"] + summary["unreachable_tasks"]) or "none recorded"))
                    elif summary["no_hosts_matched"]:
                        plan["blockers"].append("Playbook matched no hosts; check the registry groups")
                    else:
                        plan["status"] = "planned"
                lease["release"].update(ansible_plan=plan_id, plan_status=plan["status"])
        finally:
            password.clear()
        if plan["status"] == "planned":
            plan["applicable"] = True
        if plan["status"] == "needs-operator-privilege":
            plan["operator_commands"] = self._operator_commands(plan, spec, record, playbook,
                                                                plan["extra_vars"]["values"], secret_names)
        self.store.save_plan(plan, created)
        self.store.update_run(run["id"], status=plan["status"], phase="ended", finished_at=now_iso(),
                              error="; ".join(plan["blockers"]) or None)
        return self._public_plan(plan)

    # ---- apply ---------------------------------------------------------------------------

    def _verify_plan(self, plan, secret_values, *, require_applicable=True):
        """Refuse expiry, a moved repo, a changed registration/registry entry/inventory or other secret values;
        the recorded (non-secret) overrides come from the plan itself."""
        if plan.get("consumed_by"):
            raise ValueError(f"Plan was already used by receipt {plan['consumed_by']}; make a new plan")
        if require_applicable and not plan["applicable"]:
            raise ValueError(f"Plan is {plan['status']}, not applicable: " + "; ".join(plan["blockers"]))
        if require_applicable and self.clock() >= datetime.fromisoformat(plan["expires_at"]).timestamp():
            raise ValueError("Plan expired; make a new plan")
        spec = self._playbook(plan["playbook_id"])
        if digest(spec) != plan["playbook"]["spec_sha256"]:
            raise ValueError("Playbook registration changed since the plan; make a new plan")
        record = self._host(plan["host_id"])
        if registry_digest(record) != plan["registry_sha256"]:
            raise ValueError("Host registry entry changed since the plan; make a new plan")
        repo, playbook = self._repo(spec)
        state = repo_state(repo)
        if state["commit"] != plan["repo"]["commit"]:
            raise ValueError("Playbook repo HEAD moved since the plan; make a new plan")
        if state["fingerprint"] != plan["repo"]["fingerprint"]:
            raise ValueError("Playbook repo content changed since the plan; make a new plan")
        secret_values = {} if secret_values is None else secret_values
        if not isinstance(secret_values, dict):
            raise ValueError("Secret variables must be a mapping")
        expected = plan["extra_vars"]["secret_names"]
        if sorted(secret_values) != expected:
            extra = sorted(set(secret_values) - set(expected))
            raise ValueError(("Apply uses the overrides recorded in the plan; only its secret variables are typed "
                              "again: " + (", ".join(expected) or "none") + (f" (not secret in this plan: {', '.join(extra)})"
                                                                              if extra else "")))
        variables = self._variables(plan["playbook_id"], spec)
        checked = discovery.validate_values(variables, secret_values)
        values = {**plan["extra_vars"]["values"], **checked}
        return spec, record, repo, playbook, values

    def apply(self, plan_id, *, approved, request_id, extra_vars=None, wait=30, become_password=None, background=False):
        """Apply one exact plan. `extra_vars` carries only the plan's secret variables, typed again;
        `become_password` (a BecomePassword) is asked again for every apply, never carried from the plan."""
        password = become_password if isinstance(become_password, BecomePassword) else BecomePassword(become_password)
        try:
            if approved is not True:
                raise ValueError("Apply requires explicit approval (--approve)")
            if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
                raise ValueError("Invalid request ID")
            if not isinstance(plan_id, str) or not PLAN_ID.fullmatch(plan_id):
                raise ValueError("Invalid Ansible plan ID")
            existing = self.store.by_request(request_id)
            if existing:
                password.clear()
                if existing["plan_id"] != plan_id:
                    raise ValueError("Request ID was already used for a different Ansible plan")
                return {**existing, "replayed": True}
            plan = self.store.plan(plan_id)
            spec, record, repo, playbook, values = self._verify_plan(plan, extra_vars)
            if password and not spec["become"]:
                raise ValueError("This playbook is not registered as using become; no sudo password is needed")
            if spec["become"] and (plan.get("preflight") or {}).get("passwordless_sudo") is False and not password:
                # Refused here, before the plan is consumed: the password is asked again for every run.
                raise ValueError("This host has no passwordless sudo: type the sudo password for this apply (asked "
                                 "for every run, never stored)")
            run = self._new_run("apply", plan["playbook_id"], plan["host_id"], plan_id=plan_id, request_id=request_id,
                                become_password=SUPPLIED if password else None)
        except BaseException:
            password.clear()
            raise
        secrets_ = {name: extra_vars[name] for name in plan["extra_vars"]["secret_names"]}
        body = lambda cancel: self._apply_body(run, plan_id, request_id, secrets_, wait, password, cancel)
        return self._launch(run, self._guard(run, body), background)

    def _apply_body(self, run, plan_id, request_id, secret_values, wait, password, cancel):
        try:
            self.runner.prepare()
            version = self.runner.check_version()
            plan = self.store.plan(plan_id)
            if version != plan["ansible_core"]:
                raise ValueError("Pinned ansible-core changed since the plan; make a new plan")
            record = self._host(plan["host_id"])
            self.store.update_run(run["id"], phase="waiting for the lease")
            scope = f"ansible apply {plan['playbook_id']} on {record['id']} (plan {plan_id[:8]}, request {request_id[:40]})"
            with self._lease(record, scope, wait) as lease:
                # Re-verify under the lease, then regenerate the inventory exactly as planned.
                plan = self.store.plan(plan_id)
                spec, record, repo, playbook, values = self._verify_plan(plan, secret_values)
                inventory, _ = self._inventory_for(spec, record, repo)
                if digest(inventory) != plan["inventory"]["sha256"]:
                    raise ValueError("Generated inventory changed since the plan; make a new plan")
                self._write_inventory(plan_id, inventory, record)
                secret_leaves = [leaf for name in plan["extra_vars"]["secret_names"] for leaf in _leaves(values[name])]
                receipt = {"id": uuid.uuid4().hex, "kind": "ansible-apply", "request_id": request_id, "plan_id": plan_id,
                           "status": "running", "executor": "switchyard", "playbook_id": plan["playbook_id"],
                           "host_id": record["id"], "commit": plan["repo"]["commit"], "dirty": plan["repo"]["dirty"],
                           "allow_dirty": plan["allow_dirty"], "repo_fingerprint": plan["repo"]["fingerprint"],
                           "ansible_core": version, "become": spec["become"], "inventory_sha256": plan["inventory"]["sha256"],
                           "extra_vars": deepcopy(plan["extra_vars"]), "lease_id": lease["lease_id"],
                           "started_at": now_iso(), "run_id": run["id"]}
                receipt, replayed = self.store.begin(receipt)
                if replayed:
                    self.store.update_run(run["id"], status=receipt["status"], phase="ended", finished_at=now_iso(),
                                          receipt_id=receipt["id"])
                    return {**receipt, "replayed": True}
                self.store.update_run(run["id"], receipt_id=receipt["id"], lease_id=lease["lease_id"],
                                      phase="preflight: identity and sudo -n")
                lease["release"].update(ansible_receipt=receipt["id"])
                started = False
                try:
                    preflight = self._preflight(record)
                    needs_password = spec["become"] and preflight["passwordless_sudo"] is False
                    if not preflight["reachable"] or not preflight["identity_ok"] or (needs_password and not password):
                        reason = preflight.get("error") or ("Passwordless sudo is not available and no sudo password was "
                                                            "given for this run")
                        final = self.store.finish(receipt["id"], {"status": "failed", "preflight": preflight,
                                                                  "error": reason + "; playbook not started"})
                    else:
                        started = True
                        self.store.update_run(run["id"], phase="applying", started_playbook=True)
                        result, summary, stderr = self._run_playbook(
                            plan, record, playbook, values, check=False, timeout=self.apply_timeout, secrets=secret_leaves,
                            become_password=password.take() if needs_password else None,
                            progress=self._progress(run["id"]), cancel=cancel)
                        status, error = outcome(result.exit_code, result.timed_out, summary, record["id"],
                                                self.apply_timeout)
                        if result.cancelled:
                            status, error = "needs-inspection", "Switchyard stopped during the run; inspect the host"
                        elif needs_password and self._refused(summary):
                            status, error = "failed", SUDO_REFUSED
                        final = self.store.finish(receipt["id"], {
                            "status": status, "error": error, "exit_code": result.exit_code, "timed_out": result.timed_out,
                            "stats": (summary["stats"] or {}).get(record["id"]), "changed_tasks": summary["changed_tasks"],
                            "failed_tasks": summary["failed_tasks"], "unreachable_tasks": summary["unreachable_tasks"],
                            "tasks_truncated": summary["truncated"], "preflight": preflight, "stderr_tail": stderr,
                            **({"become_password": SUPPLIED} if needs_password else {})})
                except BaseException as error:
                    self.store.finish(receipt["id"], {
                        "status": "needs-inspection" if started else "failed",
                        "error": ("Apply interrupted after the runner started; inspect the host" if started
                                  else "Apply interrupted before the runner started") + f" ({type(error).__name__})"})
                    raise
                lease["release"].update(ansible_status=final["status"])
        finally:
            password.clear()
        self.store.update_run(run["id"], status=final["status"], phase="ended", finished_at=now_iso(),
                              error=final.get("error"))
        return final

    def record_manual(self, plan_id, *, request_id):
        """Record an operator's own leased become run from the events its printed command wrote."""
        if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
            raise ValueError("Invalid request ID")
        if not isinstance(plan_id, str) or not PLAN_ID.fullmatch(plan_id):
            raise ValueError("Invalid Ansible plan ID")
        existing = self.store.by_request(request_id)
        if existing:
            if existing["plan_id"] != plan_id:
                raise ValueError("Request ID was already used for a different Ansible plan")
            return {**existing, "replayed": True}
        plan = self.store.plan(plan_id)
        if plan["status"] != "needs-operator-privilege":
            raise ValueError("record-manual only records operator runs of plans that needed operator privilege")
        if plan.get("consumed_by"):
            raise ValueError(f"Plan was already used by receipt {plan['consumed_by']}")
        summary = parse_events(self.store.manual / f"{plan_id}-apply.jsonl")
        if summary["started"] is None or summary["check_mode"]:
            raise ValueError("No operator apply run recorded for this plan; run its printed apply command first")
        if summary["started"] < datetime.fromisoformat(plan["created_at"]).timestamp():
            raise ValueError("Recorded run predates the plan")
        spec = self._playbook(plan["playbook_id"])
        try:
            state = repo_state(self._repo(spec)[0])
            repo_unchanged = state["fingerprint"] == plan["repo"]["fingerprint"]
        except (ValueError, OSError, subprocess.SubprocessError):
            repo_unchanged = False
        status, error = outcome(0 if summary["ended"] else None, False, summary, plan["host_id"], None)
        receipt = {"id": uuid.uuid4().hex, "kind": "ansible-apply", "request_id": request_id, "plan_id": plan_id,
                   "status": status, "error": error, "executor": "operator",
                   "evidence": "Events written by the Switchyard callback during the operator's own leased run; "
                               "Switchyard did not run the command or hold the lease. The ledger CLAIM/RELEASE is "
                               "the lease record.",
                   "playbook_id": plan["playbook_id"], "host_id": plan["host_id"], "commit": plan["repo"]["commit"],
                   "dirty": plan["repo"]["dirty"], "allow_dirty": plan["allow_dirty"],
                   "repo_unchanged_since_plan": repo_unchanged, "ansible_core": plan["ansible_core"],
                   "become": plan["playbook"]["become"], "inventory_sha256": plan["inventory"]["sha256"],
                   "extra_vars": deepcopy(plan["extra_vars"]),
                   "started_at": now_iso(summary["started"]),
                   "finished_at": now_iso(summary["ended"]) if summary["ended"] else None,
                   "stats": (summary["stats"] or {}).get(plan["host_id"]), "changed_tasks": summary["changed_tasks"],
                   "failed_tasks": summary["failed_tasks"], "unreachable_tasks": summary["unreachable_tasks"],
                   "tasks_truncated": summary["truncated"]}
        receipt, replayed = self.store.begin(receipt)
        return {**receipt, "replayed": True} if replayed else receipt


def redact(value, secrets):
    """Replace every secret string (secret extra-var values, the become password) in strings, dict keys and
    nested lists with ***."""
    secrets_ = sorted((item for item in secrets if isinstance(item, str) and item), key=len, reverse=True)
    if not secrets_:
        return value

    def walk(item):
        if isinstance(item, str):
            for secret in secrets_:
                item = item.replace(secret, "***")
            return item
        if isinstance(item, dict):
            return {walk(key): walk(child) for key, child in item.items()}
        if isinstance(item, list):
            return [walk(child) for child in item]
        return item

    return walk(value)


def outcome(exit_code, timed_out, summary, host_id, timeout):
    """Receipt status for a non-check run; anything uncertain is needs-inspection."""
    if timed_out:
        return "needs-inspection", f"Runner exceeded {timeout} s and its process group was killed; inspect the host"
    stats = (summary["stats"] or {}).get(host_id)
    if summary["ended"] is None or exit_code is None:
        return "needs-inspection", f"Runner ended without a final summary (exit {exit_code}); inspect the host"
    if summary["no_hosts_matched"]:
        return "failed", "Playbook matched no hosts; nothing executed"
    acted = any(task.get("status") in {"ok", "changed"} for task in summary["tasks"] if task.get("host") == host_id)
    if stats and stats.get("unreachable"):
        if acted:
            return "needs-inspection", "Host became unreachable mid-run; inspect the host"
        return "failed", "Host unreachable before any task ran"
    if stats and stats.get("failures"):
        return "failed", f"{stats['failures']} task(s) failed; tasks changed before the failure are listed"
    if exit_code == 0 and stats is not None:
        return "succeeded", None
    return "needs-inspection", f"Unexpected runner exit {exit_code}; inspect the host"


def _oneline_facts(text, host_id):
    for line in text.splitlines():
        prefix = f"{host_id} | "
        if line.startswith(prefix) and " => " in line:
            state, _, payload = line[len(prefix):].partition(" => ")
            try:
                facts = json.loads(payload).get("ansible_facts", {})
            except (ValueError, AttributeError):
                facts = {}
            return {"state": state.strip(), "facts": {key: facts[key] for key in sorted(facts)
                                                      if isinstance(facts[key], (str, int, float, bool))}}
    return {"state": "no result", "facts": {}}


# ---- CLI (wired into switchyard/cli.py) -------------------------------------------------------

def register_cli(commands):
    parser = commands.add_parser("ansible", help="Ansible host initialization: registrations, check-mode plans, approved applies")
    parser.add_argument("--config", dest="ansible_config",
                        help="Runner configuration and one-time seed of registrations (default: SWITCHYARD_ANSIBLE, "
                             "else <catalog name>.ansible.json beside --catalog)")
    sub = parser.add_subparsers(dest="ansible_command", required=True)
    sub.add_parser("playbooks", help="Registered playbooks and per-host eligibility; no host access")
    show = sub.add_parser("show", help="One registration with its variables, roles, plans and receipts; no host access")
    show.add_argument("playbook_id")
    variables = sub.add_parser("variables", help="Variables the playbook exposes and per-host starting values; no host access")
    variables.add_argument("playbook_id")
    variables.add_argument("--host", help="Only this allowed host's effective values")
    inspect = sub.add_parser("inspect", help="What a directory offers for registration; read-only, no host access")
    inspect.add_argument("path")
    for name in ("add", "edit"):
        registration = sub.add_parser(name, help=("Register a playbook (operator only)" if name == "add"
                                                  else "Replace a registration (operator only; all fields)"))
        registration.add_argument("playbook_id")
        registration.add_argument("--repo", required=True)
        registration.add_argument("--playbook", required=True, help="Playbook file, relative to the repo")
        registration.add_argument("--inventory", help="Repo inventory, relative to the repo")
        registration.add_argument("--group", action="append", required=True, help="Group the host joins (repeatable)")
        registration.add_argument("--host", action="append", required=True, help="Allowed registry host (repeatable)")
        registration.add_argument("--become", action="store_true", help="The playbook escalates privilege")
        registration.add_argument("--check-mode", required=True, choices=sorted(CHECK_MODES))
        registration.add_argument("--description", required=True)
        registration.add_argument("--var", action="append", default=[], help="Variable that may be overridden (repeatable)")
        registration.add_argument("--secret-var", action="append", default=[], help="Variable whose values are never stored")
        if name == "edit":
            registration.add_argument("--expected-revision", type=int, required=True)
    remove = sub.add_parser("remove", help="Remove a registration (operator only)")
    remove.add_argument("playbook_id")
    remove.add_argument("--expected-revision", type=int, required=True)
    inventory = sub.add_parser("inventory", help="Print the registry-generated inventory; no host access")
    inventory.add_argument("--host")
    inventory.add_argument("--playbook", help="Layer this playbook's groups and repo inventory vars (needs --host)")
    probe = sub.add_parser("probe", help="Leased read-only connectivity proof: identity, sudo -n, setup facts")
    probe.add_argument("--host", required=True)
    probe.add_argument("--wait", type=float, default=30)
    plan = sub.add_parser("plan", help="Leased check-mode run; stores an expiring plan, never applies")
    plan.add_argument("playbook_id")
    plan.add_argument("--host", required=True)
    plan.add_argument("--extra-var", action="append", default=[], metavar="NAME=VALUE",
                      help="Override (text for str variables, JSON otherwise)")
    plan.add_argument("--allow-dirty", action="store_true", help="Plan an uncommitted repo (recorded)")
    plan.add_argument("--wait", type=float, default=30, help="Seconds to wait for a busy lease (max 60)")
    plan.add_argument("--ask-become-pass", action="store_true",
                      help="Prompt for the sudo password (terminal only); used for this run, never stored")
    apply = sub.add_parser("apply", help="Apply one exact plan with explicit approval")
    apply.add_argument("plan_id")
    apply.add_argument("--approve", action="store_true", required=True)
    apply.add_argument("--request-id", required=True)
    apply.add_argument("--extra-var", action="append", default=[], metavar="NAME=VALUE",
                       help="The plan's secret variables, typed again")
    apply.add_argument("--wait", type=float, default=30)
    apply.add_argument("--ask-become-pass", action="store_true",
                       help="Prompt for the sudo password (terminal only); used for this run, never stored")
    plans = sub.add_parser("plans", help="Stored plans; no host access")
    plans.add_argument("plan_id", nargs="?")
    runs = sub.add_parser("runs", help="Plan and apply runs with their progress; no host access")
    runs.add_argument("run_id", nargs="?")
    receipts = sub.add_parser("receipts", help="Apply receipts; no host access")
    receipts.add_argument("receipt_id", nargs="?", help="Receipt ID or request ID")
    record = sub.add_parser("record-manual", help="Record the operator's own become run of a plan")
    record.add_argument("plan_id")
    record.add_argument("--request-id", required=True)


def parse_extra_vars(pairs, variables=None):
    """NAME=VALUE pairs; with the discovered variables, values are typed (JSON for non-text variables)."""
    known = {var["name"]: var for var in variables or []}
    values = {}
    for pair in pairs or []:
        name, separator, value = pair.partition("=")
        if not separator or not VAR_NAME.fullmatch(name):
            raise ValueError("Extra vars must be NAME=VALUE")
        if name in values:
            raise ValueError(f"Duplicate extra var {name}")
        values[name] = discovery.parse_text(known[name], value) if name in known else value
    return values


def ask_become_password(prompt="sudo password for this run (never stored): "):
    """getpass on a terminal only; nothing is echoed, stored or logged."""
    import getpass
    import sys
    if not sys.stdin.isatty():
        raise ValueError("--ask-become-pass needs a terminal; Switchyard never reads a sudo password from a pipe or file")
    return BecomePassword(getpass.getpass(prompt))


def config_path(args):
    if getattr(args, "ansible_config", None):
        return args.ansible_config
    if os.environ.get("SWITCHYARD_ANSIBLE"):
        return os.environ["SWITCHYARD_ANSIBLE"]
    catalog = Path(args.catalog).resolve()
    return str(catalog.with_name(catalog.stem + ".ansible.json"))  # catalogs/home-lab.json -> home-lab.ansible.json


def from_service(service, path, **kwargs):
    return AnsibleOps(path, hosts=service.hosts()["hosts"], pins_path=service.ssh_pins_path(),
                      state_dir=service.state_dir, paseo_agents=service.paseo_agent_names(), **kwargs)


def _entry(args):
    entry = {"repo": args.repo, "playbook": args.playbook, "groups": args.group, "allowed_hosts": args.host,
             "become": args.become, "check_mode": args.check_mode, "description": args.description,
             "extra_vars_allowed": args.var, "secret_vars": args.secret_var}
    if args.inventory:
        entry["inventory"] = args.inventory
    return entry


def handle_cli(args, service):
    if args.command != "ansible":
        return None
    ops = from_service(service, config_path(args))
    command = args.ansible_command
    if command == "playbooks":
        return ops.playbooks()
    if command == "show":
        return ops.playbook(args.playbook_id)
    if command == "variables":
        found = ops.discover(args.playbook_id)
        if args.host:
            if args.host not in found["hosts"]:
                raise ValueError(f"{args.host} is not allowed for playbook {args.playbook_id}")
            return {"host_id": args.host, "variables": [
                {key: var[key] for key in ("name", "type", "overridable", "secret", "description")}
                | {"effective": var["effective"].get(args.host)} for var in found["variables"]],
                "inventory": found["hosts"][args.host]}
        return found
    if command == "inspect":
        return ops.inspect_directory(args.path)
    if command in {"add", "edit", "remove"}:
        from .auth import operator_identity
        operator_identity()  # Registration changes are operator-only (refused under agent ancestry).
        if command == "add":
            return ops.register(args.playbook_id, _entry(args))
        if command == "edit":
            return ops.update_registration(args.playbook_id, _entry(args), expected_revision=args.expected_revision)
        return ops.remove_registration(args.playbook_id, expected_revision=args.expected_revision)
    if command == "inventory":
        return ops.inventory(args.host, args.playbook)
    if command == "probe":
        return ops.probe(args.host, wait=args.wait)
    if command == "plan":
        variables = ops._variables(args.playbook_id, ops._playbook(args.playbook_id)) if args.extra_var else None
        password = ask_become_password() if args.ask_become_pass else None
        return ops.plan(args.playbook_id, args.host, extra_vars=parse_extra_vars(args.extra_var, variables),
                        allow_dirty=args.allow_dirty, wait=args.wait, become_password=password)
    if command == "apply":
        variables = None
        if args.extra_var:
            plan = ops.plan_record(args.plan_id)
            variables = ops._variables(plan["playbook_id"], ops._playbook(plan["playbook_id"]))
        password = ask_become_password() if args.ask_become_pass else None
        return ops.apply(args.plan_id, approved=args.approve, request_id=args.request_id,
                         extra_vars=parse_extra_vars(args.extra_var, variables), wait=args.wait,
                         become_password=password)
    if command == "plans":
        return ops.plan_record(args.plan_id) if args.plan_id else ops.plans()
    if command == "runs":
        return ops.run(args.run_id) if args.run_id else ops.runs()
    if command == "receipts":
        return ops.receipt(args.receipt_id) if args.receipt_id else ops.receipts()
    if command == "record-manual":
        return ops.record_manual(args.plan_id, request_id=args.request_id)
    raise ValueError("Unknown ansible command")
