"""Private SQLite state for operator login, sessions, enrollment requests and scoped keys.

`<state_dir>/auth/auth.sqlite3` (0600 in a 0700 directory), separate from the operations and deploy
stores. Stored secrets are hashes only: the password as salted scrypt, session tokens and API keys as
SHA-256. CSRF tokens are random values bound to a session (a CSRF token alone grants nothing).
"""
import base64
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 17, 8, 1
SCRYPT_LENGTH = 32
SESSION_IDLE_SECONDS = 12 * 3600
SESSION_ABSOLUTE_SECONDS = 7 * 86400
TOUCH_SECONDS = 60
AUDIT_ROWS = 5000
# Failures inside the throttle window are never pruned, so flooding the bounded audit log (for example
# with throttled attempts) cannot evict the rows the login throttle counts. Throttling itself caps how many
# such rows can exist (per address and globally), so the table stays bounded.
THROTTLE_WINDOW = 15 * 60
RECENT_DECIDED_SECONDS = 7 * 86400


def _b64(data):
    return base64.b64encode(data).decode()


def hash_password(password, *, n=None, salt=None):
    """Salted scrypt; parameters are stored with the hash so they can be raised later."""
    n = n or SCRYPT_N
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=SCRYPT_R, p=SCRYPT_P,
                            maxmem=2 * 128 * SCRYPT_R * n + 1048576, dklen=SCRYPT_LENGTH)
    return json.dumps({"alg": "scrypt", "n": n, "r": SCRYPT_R, "p": SCRYPT_P, "salt": _b64(salt), "hash": _b64(digest)})


def verify_password(password, encoded):
    record = json.loads(encoded)
    if record.get("alg") != "scrypt":
        return False
    n, r, p = int(record["n"]), int(record["r"]), int(record["p"])
    expected = base64.b64decode(record["hash"])
    digest = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(record["salt"]), n=n, r=r, p=p,
                            maxmem=2 * 128 * r * n + 1048576, dklen=len(expected))
    return hmac.compare_digest(digest, expected)


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AuthStore:
    def __init__(self, state_dir, *, clock=time.time):
        self.clock = clock
        self.directory = Path(state_dir) / "auth"
        # The state root too: Switchyard's registry refuses a root that is not 0700.
        self.directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.mkdir(mode=0o700, exist_ok=True)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("Auth state must be an owned private directory")
        self.directory.chmod(0o700)
        self.path = self.directory / "auth.sqlite3"
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError("Auth store must be an owned private regular file")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        with self.transaction() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS operator(id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL,
                    password TEXT NOT NULL, updated REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions(token_sha256 TEXT PRIMARY KEY, csrf TEXT NOT NULL,
                    username TEXT NOT NULL, listener TEXT NOT NULL, client TEXT, created REAL NOT NULL,
                    last_seen REAL NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL,
                    kind TEXT NOT NULL, client TEXT, username TEXT, outcome TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS audit_failures ON audit(kind, outcome, at);
                CREATE TABLE IF NOT EXISTS enrollments(id TEXT PRIMARY KEY, created REAL NOT NULL,
                    expires REAL NOT NULL, key_sha256 TEXT NOT NULL, code TEXT NOT NULL, data TEXT NOT NULL,
                    status TEXT NOT NULL, decided_by TEXT, decided_at REAL, key_id TEXT);
                CREATE TABLE IF NOT EXISTS keys(id TEXT PRIMARY KEY, key_sha256 TEXT UNIQUE NOT NULL,
                    data TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL, last_used REAL,
                    last_used_from TEXT, revoked REAL);
                CREATE TABLE IF NOT EXISTS lease_owners(lease_id TEXT PRIMARY KEY, key_id TEXT NOT NULL,
                    created REAL NOT NULL);
            """)

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
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

    # ---- operator ------------------------------------------------------------------------------

    def operator(self):
        with self.transaction() as db:
            row = db.execute("SELECT username, password, updated FROM operator").fetchone()
        return dict(row) if row else None

    def set_operator(self, username, encoded):
        """Replace the one operator account; every session ends."""
        with self.transaction() as db:
            db.execute("INSERT INTO operator VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                       "username=excluded.username, password=excluded.password, updated=excluded.updated",
                       (username, encoded, self.clock()))
            db.execute("DELETE FROM sessions")

    # ---- sessions ------------------------------------------------------------------------------

    def create_session(self, username, listener, client, *, replace=None):
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        now = self.clock()
        expires = now + SESSION_ABSOLUTE_SECONDS
        with self.transaction() as db:
            db.execute("DELETE FROM sessions WHERE expires<=? OR last_seen<=?", (now, now - SESSION_IDLE_SECONDS))
            if replace:
                db.execute("DELETE FROM sessions WHERE token_sha256=?", (sha256_hex(replace),))
            db.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?)",
                       (sha256_hex(token), csrf, username, listener, client, now, now, expires))
        return {"token": token, "csrf_token": csrf, "username": username, "expires": expires}

    def session(self, token, listener):
        """The live session for `token` on this listener, refreshing its idle clock; None otherwise."""
        now = self.clock()
        key = sha256_hex(token)
        with self.transaction() as db:
            row = db.execute("SELECT * FROM sessions WHERE token_sha256=?", (key,)).fetchone()
            if row is None:
                return None
            if row["expires"] <= now or row["last_seen"] <= now - SESSION_IDLE_SECONDS:
                db.execute("DELETE FROM sessions WHERE token_sha256=?", (key,))
                return None
            if row["listener"] != listener:
                return None
            if now - row["last_seen"] >= TOUCH_SECONDS:
                db.execute("UPDATE sessions SET last_seen=? WHERE token_sha256=?", (now, key))
        return {"username": row["username"], "csrf_token": row["csrf"], "expires": row["expires"],
                "created": row["created"]}

    def delete_session(self, token):
        with self.transaction() as db:
            db.execute("DELETE FROM sessions WHERE token_sha256=?", (sha256_hex(token),))

    def delete_sessions(self):
        with self.transaction() as db:
            return db.execute("DELETE FROM sessions").rowcount

    def session_count(self):
        now = self.clock()
        with self.transaction() as db:
            return db.execute("SELECT count(*) FROM sessions WHERE expires>? AND last_seen>?",
                              (now, now - SESSION_IDLE_SECONDS)).fetchone()[0]

    # ---- audit ---------------------------------------------------------------------------------

    def audit(self, kind, outcome, *, client=None, username=None):
        with self.transaction() as db:
            db.execute("INSERT INTO audit(at,kind,client,username,outcome) VALUES(?,?,?,?,?)",
                       (self.clock(), kind, (client or "")[:64] or None, (username or "")[:64] or None, outcome))
            db.execute("DELETE FROM audit WHERE id <= (SELECT max(id) FROM audit) - ? "
                       "AND NOT (outcome='failure' AND at >= ?)", (AUDIT_ROWS, self.clock() - THROTTLE_WINDOW))

    def failures(self, kind, since, client=None):
        with self.transaction() as db:
            if client is None:
                return db.execute("SELECT count(*), min(at) FROM audit WHERE kind=? AND outcome='failure' AND at>=?",
                                  (kind, since)).fetchone()
            return db.execute("SELECT count(*), min(at) FROM audit WHERE kind=? AND outcome='failure' AND at>=? "
                              "AND client=?", (kind, since, client)).fetchone()

    def audit_tail(self, limit=20):
        with self.transaction() as db:
            rows = db.execute("SELECT at,kind,client,username,outcome FROM audit ORDER BY id DESC LIMIT ?",
                              (limit,)).fetchall()
        return [dict(row) for row in rows]

    # ---- enrollments ---------------------------------------------------------------------------

    def _expire(self, db):
        now = self.clock()
        db.execute("UPDATE enrollments SET status='expired' WHERE status='pending' AND expires<=?", (now,))
        db.execute("DELETE FROM enrollments WHERE status!='pending' AND coalesce(decided_at, expires)<=?",
                   (now - RECENT_DECIDED_SECONDS,))

    def create_enrollment(self, record, *, max_pending):
        """Insert a pending request; raises OverflowError at the pending cap, ValueError for a reused key."""
        with self.transaction() as db:
            self._expire(db)
            if db.execute("SELECT count(*) FROM enrollments WHERE status='pending'").fetchone()[0] >= max_pending:
                raise OverflowError("Too many pending access requests; try again later")
            if db.execute("SELECT 1 FROM enrollments WHERE key_sha256=? AND status IN ('pending','approved') "
                          "UNION SELECT 1 FROM keys WHERE key_sha256=?",
                          (record["key_sha256"], record["key_sha256"])).fetchone():
                raise ValueError("This key was already submitted; generate a new key")
            data = {key: value for key, value in record.items()
                    if key not in {"id", "created", "expires", "key_sha256", "code"}}
            db.execute("INSERT INTO enrollments(id,created,expires,key_sha256,code,data,status) VALUES(?,?,?,?,?,?,'pending')",
                       (record["id"], record["created"], record["expires"], record["key_sha256"], record["code"],
                        json.dumps(data, sort_keys=True)))

    @staticmethod
    def _enrollment(row):
        return {**json.loads(row["data"]), "id": row["id"], "code": row["code"], "key_sha256": row["key_sha256"],
                "created": row["created"], "expires": row["expires"], "status": row["status"],
                "decided_by": row["decided_by"], "decided_at": row["decided_at"], "key_id": row["key_id"]}

    def enrollment(self, enrollment_id):
        with self.transaction() as db:
            self._expire(db)
            row = db.execute("SELECT * FROM enrollments WHERE id=?", (enrollment_id,)).fetchone()
        return self._enrollment(row) if row else None

    def enrollments(self):
        with self.transaction() as db:
            self._expire(db)
            rows = db.execute("SELECT * FROM enrollments ORDER BY created DESC LIMIT 200").fetchall()
        return [self._enrollment(row) for row in rows]

    def approve(self, enrollment_id, *, decided_by, key):
        """Atomically turn a pending, unexpired request into an active key."""
        now = self.clock()
        with self.transaction() as db:
            self._expire(db)
            row = db.execute("SELECT * FROM enrollments WHERE id=?", (enrollment_id,)).fetchone()
            if row is None:
                raise LookupError("Unknown access request")
            if row["status"] != "pending":
                raise ValueError(f"Access request is {row['status']}")
            data = {name: value for name, value in key.items()
                    if name not in {"id", "key_sha256", "created", "expires"}}
            db.execute("INSERT INTO keys(id,key_sha256,data,created,expires) VALUES(?,?,?,?,?)",
                       (key["id"], row["key_sha256"], json.dumps(data, sort_keys=True), now, key["expires"]))
            db.execute("UPDATE enrollments SET status='approved', decided_by=?, decided_at=?, key_id=? WHERE id=?",
                       (decided_by, now, key["id"], enrollment_id))
        return self.key(key["id"])

    def deny(self, enrollment_id, *, decided_by):
        with self.transaction() as db:
            self._expire(db)
            row = db.execute("SELECT status FROM enrollments WHERE id=?", (enrollment_id,)).fetchone()
            if row is None:
                raise LookupError("Unknown access request")
            if row["status"] != "pending":
                raise ValueError(f"Access request is {row['status']}")
            db.execute("UPDATE enrollments SET status='denied', decided_by=?, decided_at=? WHERE id=?",
                       (decided_by, self.clock(), enrollment_id))

    # ---- keys ----------------------------------------------------------------------------------

    @staticmethod
    def _key(row):
        return {**json.loads(row["data"]), "id": row["id"], "created": row["created"], "expires": row["expires"],
                "last_used": row["last_used"], "last_used_from": row["last_used_from"], "revoked": row["revoked"]}

    def key(self, key_id):
        with self.transaction() as db:
            row = db.execute("SELECT * FROM keys WHERE id=?", (key_id,)).fetchone()
        return self._key(row) if row else None

    def key_by_hash(self, key_sha256):
        with self.transaction() as db:
            row = db.execute("SELECT * FROM keys WHERE key_sha256=?", (key_sha256,)).fetchone()
        return self._key(row) if row else None

    def keys(self):
        with self.transaction() as db:
            rows = db.execute("SELECT * FROM keys ORDER BY created DESC").fetchall()
        return [self._key(row) for row in rows]

    def touch_key(self, key_id, client):
        """Record use at most once a minute per key."""
        now = self.clock()
        with self.transaction() as db:
            db.execute("UPDATE keys SET last_used=?, last_used_from=? WHERE id=? AND "
                       "(last_used IS NULL OR last_used<=?)", (now, (client or "")[:64] or None, key_id, now - TOUCH_SECONDS))

    def revoke_key(self, key_id):
        with self.transaction() as db:
            row = db.execute("SELECT revoked FROM keys WHERE id=?", (key_id,)).fetchone()
            if row is None:
                raise LookupError("Unknown key")
            if row["revoked"] is None:
                db.execute("UPDATE keys SET revoked=? WHERE id=?", (self.clock(), key_id))

    # ---- HTTP lease ownership ------------------------------------------------------------------

    def record_lease(self, lease_id, key_id):
        with self.transaction() as db:
            db.execute("DELETE FROM lease_owners WHERE created<=?", (self.clock() - 86400,))
            db.execute("INSERT OR REPLACE INTO lease_owners VALUES(?,?,?)", (lease_id, key_id, self.clock()))

    def lease_owner(self, lease_id):
        with self.transaction() as db:
            row = db.execute("SELECT key_id FROM lease_owners WHERE lease_id=?", (lease_id,)).fetchone()
        return row["key_id"] if row else None
