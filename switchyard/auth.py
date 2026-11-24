"""Operator login, enrollment requests and scoped API keys (see docs/auth.md).

Identity kinds: `operator` (session cookie), `local` (loopback caller without a session), `key` (bearer),
`view` (the legacy read-only LAN view) and `None` (unauthenticated). The web layer resolves the caller
once per request and checks one route table; this module holds the rules that table refers to.
"""
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import getpass
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import sys
import threading
import time

from .auth_store import THROTTLE_WINDOW, AuthStore, hash_password, sha256_hex, verify_password

SCOPES = ("read", "lease", "operate")
HOST_SCOPES = {"lease", "operate"}
BEARER = re.compile(r"sy1_[A-Za-z0-9_-]{43}\Z")
KEY_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")
KEY_ID = re.compile(r"[0-9a-f]{16}\Z")
USERNAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,63}\Z")
HOST_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
PASEO_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
MIN_PASSWORD, MAX_PASSWORD = 12, 1024
LOGIN_WINDOW = THROTTLE_WINDOW
LOGIN_FAILURES_PER_CLIENT = 5
LOGIN_FAILURES_GLOBAL = 50
MAX_CONCURRENT_LOGINS = 2
ENROLL_TTL = 15 * 60
MAX_PENDING = 16
POLL_AFTER_SECONDS = 3
DEFAULT_KEY_DAYS, MAX_KEY_DAYS = 90, 365
LOGIN_FAILED = "Sign-in failed"


class AuthError(Exception):
    """An HTTP-mappable refusal: status and a message safe to show to the caller."""

    def __init__(self, status, message, retry_after=None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


def iso(seconds):
    return None if seconds is None else datetime.fromtimestamp(seconds, timezone.utc).isoformat()


def enrollment_code(leaf_sha256_hex, key_sha256, request_id):
    """`XXXX-XXXX`: first 40 bits of SHA-256("<leaf cert DER sha256 hex>:<key_sha256>:<id>") in RFC 4648 base32."""
    digest = hashlib.sha256(f"{leaf_sha256_hex}:{key_sha256}:{request_id}".encode()).digest()
    text = base64.b32encode(digest[:5]).decode()
    return text[:4] + "-" + text[4:]


def bearer_sha256(bearer):
    return sha256_hex(bearer)


@dataclass
class Identity:
    kind: str | None  # operator, local, key, view or None
    username: str | None = None
    key: dict | None = None
    session: dict | None = None
    token: str | None = None  # Session token (cookie value), for logout.
    bearer_error: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def actor(self):
        if self.kind == "operator":
            return f"operator:{self.username}"
        return "local (loopback, no session)" if self.kind == "local" else str(self.kind)


def key_view(key):
    """Public key record: never the hash."""
    return {"id": key["id"], "label": key["label"], "name": key["name"], "user": key["user"],
            "host_id": key.get("host_id"), "agent_id": key.get("agent_id"), "scope": key["scope"],
            "hosts": list(key.get("hosts") or []), "created_at": iso(key["created"]), "expires_at": iso(key["expires"]),
            "last_used_at": iso(key.get("last_used")), "last_used_from": key.get("last_used_from"),
            "revoked_at": iso(key.get("revoked")), "enrollment_id": key.get("enrollment_id")}


def key_summary(key):
    return {"id": key["id"], "label": key["label"], "scope": key["scope"], "hosts": list(key.get("hosts") or []),
            "expires_at": iso(key["expires"])}


def enrollment_view(record, now):
    status = record["status"]
    if status == "pending" and record["expires"] <= now:
        status = "expired"
    return {"id": record["id"], "code": record["code"], "name": record["name"], "user": record["user"],
            "host_id": record.get("host_id"), "agent_id": record.get("agent_id"),
            "requested_scope": record["scope"], "requested_hosts": list(record.get("hosts") or []),
            "client": record.get("client"), "source_address": record.get("source_address"),
            "created_at": iso(record["created"]), "expires_at": iso(record["expires"]), "status": status,
            "decided_by": record.get("decided_by"), "decided_at": iso(record.get("decided_at")),
            "key_id": record.get("key_id")}


def _text(value, name, limit):
    if not isinstance(value, str) or not value.strip() or len(value) > limit or any(
            ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f"{name} must be bounded text without control characters")
    return value.strip()


class Auth:
    """Shared by every listener of one state directory; the store is created on first use."""

    def __init__(self, state_dir, *, clock=time.time, registry_hosts=None):
        self.state_dir = Path(state_dir)
        self.clock = clock
        self.registry_hosts = registry_hosts or (lambda: [])
        self._store = None
        self._store_lock = threading.Lock()
        self._logins = threading.BoundedSemaphore(MAX_CONCURRENT_LOGINS)
        self._dummy = None

    @property
    def store(self):
        with self._store_lock:
            if self._store is None:
                self._store = AuthStore(self.state_dir, clock=self.clock)
            return self._store

    # ---- operator account ------------------------------------------------------------------

    def operator_configured(self):
        return self.store.operator() is not None

    def set_password(self, username, password, *, scrypt_n=None):
        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            raise ValueError("Username: 1-64 letters, digits, '.', '_' or '-'")
        if not isinstance(password, str) or not MIN_PASSWORD <= len(password) <= MAX_PASSWORD:
            raise ValueError(f"Password must be {MIN_PASSWORD}-{MAX_PASSWORD} characters")
        self.store.set_operator(username, hash_password(password, n=scrypt_n))
        self.store.audit("password", "success", username=username, client="cli")
        return {"username": username, "sessions": "all signed out"}

    def _dummy_hash(self):
        if self._dummy is None:
            self._dummy = hash_password(secrets.token_urlsafe(16))
        return self._dummy

    def login(self, username, password, *, client, listener, replace=None):
        """Verify the one operator; one generic failure; 5 failures per address (and a global cap) in 15 min."""
        store = self.store
        now = self.clock()
        since = now - LOGIN_WINDOW
        count, first = store.failures("login", since, client)
        total, first_total = store.failures("login", since)
        if count >= LOGIN_FAILURES_PER_CLIENT or total >= LOGIN_FAILURES_GLOBAL:
            oldest = first if count >= LOGIN_FAILURES_PER_CLIENT else first_total
            store.audit("login", "throttled", client=client, username=username if isinstance(username, str) else None)
            raise AuthError(429, "Too many failed sign-ins; try again later",
                            retry_after=max(1, int(oldest + LOGIN_WINDOW - now)))
        if not isinstance(username, str) or not isinstance(password, str) or len(username) > 64 \
                or len(password) > MAX_PASSWORD:
            store.audit("login", "failure", client=client)
            raise AuthError(401, LOGIN_FAILED)
        if not self._logins.acquire(blocking=False):
            raise AuthError(503, "Sign-in is busy; try again in a moment")
        try:
            account = store.operator()
            # Unknown username or no account: still pay for one hash, so timing does not reveal it.
            encoded = account["password"] if account and hmac.compare_digest(account["username"].encode(),
                                                                            username.encode()) else None
            verified = verify_password(password, encoded or self._dummy_hash()) and encoded is not None
        finally:
            self._logins.release()
        if not verified:
            store.audit("login", "failure", client=client, username=username)
            raise AuthError(401, LOGIN_FAILED)
        session = store.create_session(account["username"], listener, client, replace=replace)
        store.audit("login", "success", client=client, username=account["username"])
        return session

    def session(self, token, listener):
        if not isinstance(token, str) or not 1 <= len(token) <= 128:
            return None
        return self.store.session(token, listener)

    def logout(self, token):
        if token:
            self.store.delete_session(token)

    def logout_all(self):
        count = self.store.delete_sessions()
        self.store.audit("logout-all", "success", client="cli")
        return {"sessions_ended": count}

    # ---- keys ------------------------------------------------------------------------------

    def key_for_bearer(self, bearer, client):
        """The active key for a bearer string, recording use; AuthError 401 otherwise."""
        if not isinstance(bearer, str) or not BEARER.fullmatch(bearer):
            raise AuthError(401, "Invalid key")
        key = self.store.key_by_hash(bearer_sha256(bearer))
        if key is None:
            raise AuthError(401, "Unknown key")
        if key.get("revoked") is not None:
            raise AuthError(401, "Key is revoked; enroll again")
        if key["expires"] <= self.clock():
            raise AuthError(401, "Key has expired; enroll again")
        self.store.touch_key(key["id"], client)
        return key

    def keys(self):
        return [key_view(key) for key in self.store.keys()]

    def revoke(self, key_id, identity):
        if not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id):
            raise AuthError(404, "Unknown key")
        if identity.kind != "operator":
            raise AuthError(403, "Revoking another key needs the operator: sign in")
        try:
            self.store.revoke_key(key_id)
        except LookupError:
            raise AuthError(404, "Unknown key") from None
        self.store.audit("revoke", "success", username=identity.actor, client=key_id)

    def revoke_self(self, key):
        self.store.revoke_key(key["id"])
        self.store.audit("revoke-self", "success", client=key["id"])

    # ---- enrollment ------------------------------------------------------------------------

    def create_enrollment(self, data, *, source_address, leaf_sha256, base_url):
        allowed = {"name", "user", "host_id", "agent_id", "scope", "hosts", "key_sha256", "client"}
        if not isinstance(data, dict) or not {"name", "user", "scope", "key_sha256"} <= set(data) <= allowed:
            raise ValueError("Enrollment needs name, user, scope and key_sha256 (optional host_id, agent_id, hosts, client)")
        record = {"name": _text(data["name"], "name", 128)}
        if not isinstance(data["user"], str) or not USERNAME.fullmatch(data["user"]):
            raise ValueError("user must be a login name")
        record["user"] = data["user"]
        for name, pattern in (("host_id", HOST_ID), ("agent_id", PASEO_ID)):
            value = data.get(name)
            if value is not None and (not isinstance(value, str) or not pattern.fullmatch(value)):
                raise ValueError(f"Invalid {name}")
            record[name] = value
        if data["scope"] not in SCOPES:
            raise ValueError("scope must be read, lease or operate")
        record["scope"] = data["scope"]
        hosts = data.get("hosts") or []
        if not isinstance(hosts, list) or len(hosts) > 64 or len(set(hosts)) != len(hosts) or any(
                not isinstance(host, str) or not HOST_ID.fullmatch(host) for host in hosts):
            raise ValueError("hosts must be a list of distinct host IDs")
        if record["scope"] == "read" and hosts:
            raise ValueError("A read request has no host list")
        record["hosts"] = sorted(hosts)
        if not isinstance(data["key_sha256"], str) or not KEY_SHA256.fullmatch(data["key_sha256"]):
            raise ValueError("key_sha256 must be the lowercase hex SHA-256 of the bearer key")
        client = data.get("client")
        if client is not None:
            if isinstance(client, str):
                client = _text(client, "client", 256)
            elif isinstance(client, dict) and len(json.dumps(client)) <= 512 and all(
                    isinstance(k, str) and isinstance(v, (str, int, float, bool)) for k, v in client.items()):
                client = dict(client)
            else:
                raise ValueError("client must be short text or a small flat object")
        record["client"] = client
        now = self.clock()
        request_id = secrets.token_hex(16)
        code = enrollment_code(leaf_sha256, data["key_sha256"], request_id)
        record.update(id=request_id, created=now, expires=now + ENROLL_TTL, key_sha256=data["key_sha256"],
                      code=code, source_address=source_address)
        try:
            self.store.create_enrollment(record, max_pending=MAX_PENDING)
        except OverflowError as error:
            raise AuthError(429, str(error)) from None
        self.store.audit("enroll", "requested", client=source_address, username=record["user"])
        return {"id": request_id, "code": code, "approve_url": f"{base_url}/#access/{request_id}",
                "expires_at": iso(record["expires"]), "poll_after_seconds": POLL_AFTER_SECONDS}

    def poll_enrollment(self, request_id, bearer):
        """Status for the requester only: the bearer must hash to the request's key_sha256 (else 404)."""
        if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
            raise AuthError(404, "Unknown access request")
        record = self.store.enrollment(request_id)
        if record is None or not isinstance(bearer, str) or not BEARER.fullmatch(bearer) or not hmac.compare_digest(
                record["key_sha256"], bearer_sha256(bearer)):
            raise AuthError(404, "Unknown access request")
        view = enrollment_view(record, self.clock())
        result = {"status": view["status"]}
        if view["status"] == "approved":
            key = self.store.key(record["key_id"])
            if key is not None:
                result["key"] = key_summary(key)
        return result

    def enrollments(self):
        now = self.clock()
        views = [enrollment_view(record, now) for record in self.store.enrollments()]
        return {"pending": [view for view in views if view["status"] == "pending"],
                "recent": [view for view in views if view["status"] != "pending"][:50]}

    def approve(self, request_id, identity, *, scope=None, hosts=None, expires_in_days=None, label=None):
        """`local` may approve `read` only; scope may narrow, never widen; lease/operate need registry hosts."""
        if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
            raise AuthError(404, "Unknown access request")
        record = self.store.enrollment(request_id)
        if record is None:
            raise AuthError(404, "Unknown access request")
        if record["status"] != "pending" or record["expires"] <= self.clock():
            raise AuthError(409, f"Access request is {enrollment_view(record, self.clock())['status']}")
        granted = record["scope"] if scope is None else scope
        if granted not in SCOPES:
            raise ValueError("scope must be read, lease or operate")
        if SCOPES.index(granted) > SCOPES.index(record["scope"]):
            raise ValueError(f"Cannot grant {granted}: the client asked for {record['scope']}")
        if granted in HOST_SCOPES and identity.kind != "operator":
            raise AuthError(403, f"Approving {granted} access needs the operator: sign in")
        if identity.kind not in {"operator", "local"}:
            raise AuthError(403, "Only the operator or the control host's desk may approve access")
        if granted == "read":
            if hosts:
                raise ValueError("A read key has no host list")
            hosts = []
        else:
            hosts = list(record.get("hosts") or []) if hosts is None else hosts
            registry = set(self.registry_hosts())
            if not isinstance(hosts, list) or not hosts or len(set(hosts)) != len(hosts) or any(
                    not isinstance(host, str) or host not in registry for host in hosts):
                raise ValueError(f"{granted} needs a non-empty list of registry host IDs")
            hosts = sorted(hosts)
        days = DEFAULT_KEY_DAYS if expires_in_days is None else expires_in_days
        if type(days) is not int or not 1 <= days <= MAX_KEY_DAYS:
            raise ValueError(f"expires_in_days must be 1-{MAX_KEY_DAYS}")
        label = record["name"] if label is None else _text(label, "label", 128)
        key = {"id": secrets.token_hex(8), "label": label, "name": record["name"], "user": record["user"],
               "host_id": record.get("host_id"), "agent_id": record.get("agent_id"), "scope": granted,
               "hosts": hosts, "expires": self.clock() + days * 86400, "enrollment_id": request_id,
               "approved_by": identity.actor}
        try:
            created = self.store.approve(request_id, decided_by=identity.actor, key=key)
        except LookupError:
            raise AuthError(404, "Unknown access request") from None
        except ValueError as error:
            raise AuthError(409, str(error)) from None
        self.store.audit("approve", "success", username=identity.actor, client=request_id)
        return key_view(created)

    def deny(self, request_id, identity):
        if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
            raise AuthError(404, "Unknown access request")
        if identity.kind != "operator":
            raise AuthError(403, "Denying a request needs the operator: sign in")
        try:
            self.store.deny(request_id, decided_by=identity.actor)
        except LookupError:
            raise AuthError(404, "Unknown access request") from None
        except ValueError as error:
            raise AuthError(409, str(error)) from None
        self.store.audit("deny", "success", username=identity.actor, client=request_id)

    def status(self):
        account = self.store.operator()
        enrollments = self.enrollments()
        keys = self.store.keys()
        now = self.clock()
        return {"operator_configured": account is not None, "username": account["username"] if account else None,
                "password_updated_at": iso(account["updated"]) if account else None,
                "active_sessions": self.store.session_count(), "pending_requests": len(enrollments["pending"]),
                "active_keys": sum(1 for key in keys if key["revoked"] is None and key["expires"] > now),
                "recent_audit": [{**row, "at": iso(row["at"])} for row in self.store.audit_tail(10)],
                "state": str(self.store.path)}


# ---- CLI (wired by the parent into switchyard/cli.py) --------------------------------------------

def register_cli(commands):
    auth = commands.add_parser("auth", help="Operator login, access requests and scoped keys")
    sub = auth.add_subparsers(dest="auth_command", required=True)
    password = sub.add_parser("set-password", help="Operator only, at a terminal: set the one operator password")
    password.add_argument("--username", default=None, help="Default: the current login name")
    sub.add_parser("status", help="Operator account, sessions, pending requests, keys, recent sign-in events")
    sub.add_parser("requests", help="Pending and recent access requests")
    sub.add_parser("keys", help="Issued keys with scope, hosts, expiry and last use")
    approve = sub.add_parser("approve", help="Approve a request (scope read needs no operator; lease/operate do)")
    approve.add_argument("request_id")
    approve.add_argument("--scope", choices=SCOPES)
    approve.add_argument("--hosts", help="Comma-separated registry host IDs (lease/operate)")
    approve.add_argument("--days", type=int)
    approve.add_argument("--label")
    deny = sub.add_parser("deny", help="Operator only: deny a request")
    deny.add_argument("request_id")
    revoke = sub.add_parser("revoke", help="Operator only: revoke a key")
    revoke.add_argument("key_id")
    sub.add_parser("logout-all", help="Operator only: end every browser session")
    tls = commands.add_parser("tls", help="Local CA and server certificate for the HTTPS listener")
    tsub = tls.add_subparsers(dest="tls_command", required=True)
    init = tsub.add_parser("init", help="Create the local CA (once) and a server certificate for --name values")
    init.add_argument("--name", action="append", default=[], help="IP address or DNS name (repeatable)")
    tsub.add_parser("show", help="CA fingerprint, server names and expiry")
    export = tsub.add_parser("export-ca", help="Write the CA certificate (public) to PATH")
    export.add_argument("path")
    renew = tsub.add_parser("renew", help="Issue a new server certificate (same names plus any --name)")
    renew.add_argument("--name", action="append", default=[])


def operator_identity(*, agent_check=None):
    """CLI operator check, as for `lease break`: refused under agent ancestry (best effort)."""
    from .agent_leases import BREAK_REFUSED, agent_ancestry
    reason = (agent_check or agent_ancestry)()
    if reason:
        raise ValueError(BREAK_REFUSED.replace("lease break", "this command") + f" ({reason})")
    return Identity("operator", username=getpass.getuser())


def cli_identity(*, agent_check=None):
    """Operator when no agent ancestry is found, else `local` (may approve read only)."""
    try:
        return operator_identity(agent_check=agent_check)
    except ValueError:
        return Identity("local")


def state_dir_of(service):
    # Parent: replace with a public Service accessor (`state_dir`) when adding it.
    return Path(getattr(service, "state_dir", None) or service._state_dir)


def registry_hosts_of(service):
    return lambda: [record["id"] for record in service.hosts()["hosts"]]


def read_new_password(*, stdin=None, prompt=getpass.getpass):
    stdin = stdin or sys.stdin
    if not stdin.isatty():
        raise ValueError("set-password needs an interactive terminal; it never reads a password from a pipe or argument")
    first = prompt("New operator password (12 or more characters): ")
    second = prompt("Repeat it: ")
    if not hmac.compare_digest(first.encode(), second.encode()):
        raise ValueError("Passwords do not match; nothing changed")
    return first


def handle_cli(args, service, *, agent_check=None, password_reader=read_new_password):
    if args.command == "tls":
        from .tls import TLSStore
        store = TLSStore(state_dir_of(service))
        if args.tls_command == "init":
            return store.init(args.name)
        if args.tls_command == "show":
            return store.show()
        if args.tls_command == "export-ca":
            return store.export_ca(args.path)
        if args.tls_command == "renew":
            return store.renew(args.name)
        raise ValueError("Unknown tls command")
    if args.command != "auth":
        return None
    auth = Auth(state_dir_of(service), registry_hosts=registry_hosts_of(service))
    command = args.auth_command
    if command == "status":
        return auth.status()
    if command == "requests":
        return auth.enrollments()
    if command == "keys":
        return auth.keys()
    if command == "set-password":
        operator = operator_identity(agent_check=agent_check)
        username = args.username or operator.username
        password = password_reader()
        return auth.set_password(username, password)
    if command == "approve":
        identity = cli_identity(agent_check=agent_check)
        hosts = None if args.hosts is None else [host.strip() for host in args.hosts.split(",") if host.strip()]
        try:
            return auth.approve(args.request_id, identity, scope=args.scope, hosts=hosts,
                                expires_in_days=args.days, label=args.label)
        except AuthError as error:
            raise ValueError(str(error)) from None
    operator = operator_identity(agent_check=agent_check)
    try:
        if command == "deny":
            auth.deny(args.request_id, operator)
            return {"denied": args.request_id}
        if command == "revoke":
            auth.revoke(args.key_id, operator)
            return {"revoked": args.key_id}
        if command == "logout-all":
            return auth.logout_all()
    except AuthError as error:
        raise ValueError(str(error)) from None
    raise ValueError("Unknown auth command")
