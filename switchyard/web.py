"""Desk HTTP server: loopback desk, HTTPS LAN listener with login and keys, and the legacy read-only LAN view.

Three listener kinds share one `Service` per process and one auth store per state directory:
- loopback (`127.0.0.1`, plain HTTP): callers without a session are `local` and keep today's desk;
  operator-only routes need an operator session even here (agents on this host reach loopback).
- LAN (`lan=True`, HTTPS with the local CA's server certificate): every route needs an operator session or a
  scoped key, except the page shell, static assets and the public auth/enrollment/CA routes.
- legacy read-only LAN view (`lan_read_only=True`, plain HTTP): GET-only, unauthenticated, receipts redacted.

Enforcement is in one place: `_dispatch` resolves the caller once, then `ROUTES` maps every method and path to
its minimum authority; a route without an entry does not exist. Host/Origin/Sec-Fetch-Site checks mitigate
DNS rebinding and cross-site requests; they do not isolate other local processes. HTTP workers, streams,
headers, body, backlog, TLS handshakes and connection lifetimes are bounded. Paths stay startup-only.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import hmac
import http.client
import ipaddress
import json
import os
import re
import select
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any, Sequence

from .ansible_ops import DESK_LEASE_WAIT
from .auth import Auth, AuthError, Identity, key_summary
from .core import Service
from .leases import LeaseBusy

MAX_BODY_BYTES = 100 * 1024  # Includes JSON escaping for a 16 KiB script.
MAX_SMALL_BODY_BYTES = 4096  # Login, enrollment and access decisions.
MAX_HEADER_BYTES = 16384
MAX_REQUEST_LINE_BYTES = 2048
CONNECTION_TIMEOUT_SECONDS = 5.0
OBSERVATION_TIMEOUT_SECONDS = 30.0
OPERATION_TIMEOUT_SECONDS = 300.0
EXECUTE_TIMEOUT_SECONDS = 450.0
LAN_ROUTE_TIMEOUT_SECONDS = 900.0
LEASE_TIMEOUT_SECONDS = 30.0
MAX_MUTATION_REQUESTS = 2
MAX_HTTP_WORKERS = 12
MAX_SSE_CONNECTIONS = 4  # Several operator/agent tabs; streams never take more than a third of the workers.
SSE_LIFETIME_SECONDS = 60.0
SSE_HEARTBEAT_SECONDS = 10.0
SSE_POLL_SECONDS = 0.5
SSE_WRITE_TIMEOUT_SECONDS = 2.0
MAX_SSE_EVENT_BYTES = 8 * 1024 * 1024
_HOST_DESCRIPTION_FIELDS = {"name", "platform", "architecture", "capabilities", "notes"}
_HOST_CONNECTION_FIELDS = {"target", "port", "expected_hostname"}
# Static assets: any file directly in switchyard/static/ with one of these suffixes (served publicly).
_STATIC_ASSET = re.compile(r"/([a-z0-9][a-z0-9.-]{0,63}\.(html|js|css|woff2|svg|png|ico))\Z")
_CONTENT_TYPES = {"html": "text/html; charset=utf-8", "js": "text/javascript; charset=utf-8",
                  "css": "text/css; charset=utf-8", "woff2": "font/woff2", "svg": "image/svg+xml",
                  "png": "image/png", "ico": "image/x-icon"}
SESSION_COOKIE = {True: "__Host-switchyard-session", False: "switchyard-session"}
CSRF_HEADER = "X-Switchyard-CSRF"
AUTHORITIES = ("public", "read", "lease", "operate", "desk", "operator", "self")


@dataclass(frozen=True)
class Route:
    """One method + path. `authority`: public, read, lease, operate, desk (operator or loopback local),
    operator, or self (a key acting on itself). `hosts`: for operate, a handler method returning the host IDs
    the request touches (keys must hold all of them)."""
    method: str
    path: str  # Exact, or a pattern with `{id}`/`{asset}` placeholders.
    authority: str
    handler: str
    hosts: str | None = None
    body_limit: int = MAX_BODY_BYTES
    empty_body: bool = False  # POST without a body is accepted as {}.

    @property
    def exact(self):
        return "{" not in self.path

    def pattern(self):
        return re.compile(re.escape(self.path).replace(r"\{id\}", r"([A-Za-z0-9._:-]{1,128})")
                          .replace(r"/\{asset\}", _STATIC_ASSET.pattern[:-2]) + r"\Z")


_READS = {
    "/api/inventory": "inventory", "/api/hosts": "hosts", "/api/locks": "device_locks", "/api/agents": "agents",
    "/api/fleet-keys": "fleet_keys", "/api/definitions": "definition_inventory", "/api/store": "store_status",
}
ROUTES = (
    # Page and public auth/enrollment.
    Route("GET", "/", "public", "_r_static"),
    Route("GET", "/{asset}", "public", "_r_static"),
    Route("GET", "/api/auth/session", "public", "_r_session"),
    Route("POST", "/api/auth/login", "public", "_r_login", body_limit=MAX_SMALL_BODY_BYTES),
    Route("POST", "/api/auth/logout", "public", "_r_logout", body_limit=MAX_SMALL_BODY_BYTES, empty_body=True),
    Route("GET", "/api/tls/ca", "public", "_r_tls_ca"),
    Route("POST", "/api/enroll", "public", "_r_enroll", body_limit=MAX_SMALL_BODY_BYTES),
    Route("GET", "/api/enroll/{id}", "public", "_r_enroll_poll"),
    # Cached reads.
    *(Route("GET", path, "read", "_r_read") for path in _READS),
    Route("GET", "/api/fleet", "read", "_r_fleet"),
    Route("GET", "/api/events", "read", "_r_events"),
    Route("GET", "/api/operations", "read", "_r_receipts"),
    Route("GET", "/api/operations/{id}", "read", "_r_receipt"),
    # Access management.
    Route("GET", "/api/enrollments", "desk", "_r_enrollments"),
    Route("POST", "/api/enrollments/{id}/approve", "desk", "_r_approve", body_limit=MAX_SMALL_BODY_BYTES, empty_body=True),
    Route("POST", "/api/enrollments/{id}/deny", "operator", "_r_deny", body_limit=MAX_SMALL_BODY_BYTES, empty_body=True),
    Route("GET", "/api/keys", "desk", "_r_keys"),
    Route("POST", "/api/keys/self/revoke", "self", "_r_revoke_self", body_limit=MAX_SMALL_BODY_BYTES, empty_body=True),
    Route("POST", "/api/keys/{id}/revoke", "operator", "_r_revoke", body_limit=MAX_SMALL_BODY_BYTES, empty_body=True),
    # Leases over HTTP (detached holds attributed to the key).
    Route("GET", "/api/leases", "lease", "_r_leases"),
    Route("POST", "/api/leases", "lease", "_r_lease_hold", body_limit=MAX_SMALL_BODY_BYTES),
    Route("POST", "/api/leases/{id}/renew", "lease", "_r_lease_renew", body_limit=MAX_SMALL_BODY_BYTES, empty_body=True),
    Route("POST", "/api/leases/{id}/release", "lease", "_r_lease_release", body_limit=MAX_SMALL_BODY_BYTES, empty_body=True),
    # Host-touching actions with hosts known from the request.
    Route("POST", "/api/observations/host", "operate", "_r_observe_host", hosts="_hosts_observe"),
    Route("POST", "/api/operations/shell", "operate", "_r_operation", hosts="_hosts_shell"),
    # Desk actions whose hosts cannot be determined before execution (refused for keys).
    Route("POST", "/api/plans/migration", "desk", "_r_migration"),
    Route("POST", "/api/observations/local", "desk", "_r_observe_local"),
    Route("POST", "/api/operations/inspect", "desk", "_r_operation"),
    Route("POST", "/api/operations/plan", "desk", "_r_operation"),
    Route("POST", "/api/operations/execute", "desk", "_r_operation"),
    Route("POST", "/api/fleet-keys/inspect", "desk", "_r_enrollment"),
    Route("POST", "/api/definitions/propose", "desk", "_r_enrollment"),
    Route("POST", "/api/hosts/scan-key", "desk", "_r_host_mutation"),
    # Operator only: registry, fleet-key and definition changes.
    Route("POST", "/api/fleet-keys/plan", "operator", "_r_enrollment"),
    Route("POST", "/api/fleet-keys/execute", "operator", "_r_enrollment"),
    Route("POST", "/api/definitions/save", "operator", "_r_enrollment"),
    Route("POST", "/api/definitions/update", "operator", "_r_enrollment"),
    Route("POST", "/api/hosts/update", "operator", "_r_host_mutation"),
    Route("POST", "/api/hosts/pin-key", "operator", "_r_host_mutation"),
    Route("POST", "/api/hosts/paseo", "operator", "_r_host_mutation"),
    Route("GET", "/api/lan-urls", "read", "_r_lan_urls"),
    Route("POST", "/api/lan-urls/plan", "operator", "_r_lan_url_plan", body_limit=MAX_SMALL_BODY_BYTES),
    Route("POST", "/api/lan-urls/apply", "operator", "_r_lan_url_apply", body_limit=MAX_SMALL_BODY_BYTES),
    # Ansible (docs/ansible.md): browsing is read; registering, planning and applying need the operator's session
    # on every listener (a playbook with become is root on its host). Keys cannot run playbooks.
    Route("GET", "/api/ansible/playbooks", "read", "_r_ansible_playbooks"),
    Route("GET", "/api/ansible/playbooks/{id}", "read", "_r_ansible_playbook"),
    Route("GET", "/api/ansible/runs", "read", "_r_ansible_runs"),
    Route("GET", "/api/ansible/runs/{id}", "read", "_r_ansible_run"),
    Route("POST", "/api/ansible/inspect", "operator", "_r_ansible_inspect", body_limit=MAX_SMALL_BODY_BYTES),
    Route("POST", "/api/ansible/playbooks", "operator", "_r_ansible_register"),
    Route("POST", "/api/ansible/playbooks/{id}/update", "operator", "_r_ansible_update"),
    Route("POST", "/api/ansible/playbooks/{id}/remove", "operator", "_r_ansible_remove", body_limit=MAX_SMALL_BODY_BYTES),
    Route("POST", "/api/ansible/plan", "operator", "_r_ansible_plan"),
    Route("POST", "/api/ansible/apply", "operator", "_r_ansible_apply"),
    Route("POST", "/api/ansible/plans/{id}/record-manual", "operator", "_r_ansible_record_manual",
          body_limit=MAX_SMALL_BODY_BYTES),
)
_COMPILED = [(route, route.pattern()) for route in ROUTES]


def match_route(method: str, path: str):
    """(route, captured groups) for method+path; `None, 405` for a known path with another method; `None, 404`."""
    candidates = [(route, regex.fullmatch(path)) for route, regex in _COMPILED]
    candidates = [(route, found) for route, found in candidates if found]
    if any(route.exact for route, _ in candidates):
        candidates = [(route, found) for route, found in candidates if route.exact]
    for route, found in candidates:
        if route.method == method:
            return route, found.groups()
    return None, 405 if candidates else 404


class _HeaderReader:
    def __init__(self, source: Any):
        self.source = source
        self.remaining = MAX_HEADER_BYTES

    def readline(self, limit: int = -1) -> bytes:
        size = self.remaining + 1
        line = self.source.readline(min(limit, size) if limit >= 0 else size)
        self.remaining -= len(line)
        if self.remaining < 0:
            raise http.client.LineTooLong("request headers")
        return line


class _LoopbackServer(HTTPServer):
    # No executor queue: reject excess connections before creating a worker.
    request_queue_size = 8
    allow_reuse_address = True

    read_only = False
    allowed_clients: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    listener = "loopback"  # loopback, lan (HTTPS, authenticated) or view (legacy read-only LAN view)
    tls_context: ssl.SSLContext | None = None
    leaf_sha256: str | None = None  # Served certificate, for enrollment codes.
    tls_store: Any = None
    auth: Auth | None = None
    catalog: Path | None = None  # For the Ansible runner configuration's default location.

    def __init__(self, address: tuple[str, int], service: Service):
        self.service = service
        self.stopping = threading.Event()
        self._workers = threading.BoundedSemaphore(MAX_HTTP_WORKERS)
        self.stream_slots = threading.BoundedSemaphore(MAX_SSE_CONNECTIONS)
        self.mutation_slots = threading.BoundedSemaphore(MAX_MUTATION_REQUESTS)
        self._threads: set[threading.Thread] = set()
        self._threads_lock = threading.Lock()
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, _Handler)
        self.set_names(())

    @property
    def secure(self) -> bool:
        return self.tls_context is not None

    @property
    def scheme(self) -> str:
        return "https" if self.secure else "http"

    def set_names(self, extra: Sequence[str]) -> None:
        """Accepted Host authorities: the bound literal (plus localhost on plain HTTP) and certificate names."""
        host, port = self.server_address[:2]
        literal = f"[{host}]" if ":" in host else host
        names = {literal, *extra} | (set() if self.secure else {"localhost"})
        default = 443 if self.secure else 80
        self.allowed_hosts = {f"{name}:{port}" for name in names}
        if port == default:
            self.allowed_hosts.update(names)
        self.allowed_origins = {f"{self.scheme}://{name}" for name in self.allowed_hosts}

    def get_request(self) -> tuple[socket.socket, Any]:
        connection, address = super().get_request()
        connection.settimeout(CONNECTION_TIMEOUT_SECONDS)
        return connection, address

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if self.allowed_clients is not None and ipaddress.ip_address(client_address[0]) not in self.allowed_clients:
            # LAN view: refuse clients outside the configured private network before any parsing.
            self.shutdown_request(request)
            return
        if self.stopping.is_set() or not self._workers.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        thread = threading.Thread(target=self._run_request, args=(request, client_address), daemon=True)
        with self._threads_lock:
            self._threads.add(thread)
        try:
            thread.start()
        except RuntimeError:
            with self._threads_lock:
                self._threads.discard(thread)
            self._workers.release()
            self.shutdown_request(request)

    def _run_request(self, request: socket.socket, client_address: Any) -> None:
        connection = request
        try:
            if self.tls_context is not None:
                wrapped = self._handshake(request)
                if wrapped is None:
                    return  # Closed; `request` was detached by the wrap, so closing it again is harmless.
                connection = wrapped
            self.finish_request(connection, client_address)
        finally:
            self.shutdown_request(connection)
            self._workers.release()
            with self._threads_lock:
                self._threads.discard(threading.current_thread())

    def _handshake(self, request: socket.socket) -> ssl.SSLSocket | None:
        """TLS in the worker thread, under one absolute deadline (a dribbling client cannot hold the accept loop)."""
        wrapped = self.tls_context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)

        def expire() -> None:
            try:
                socket.socket.shutdown(wrapped, socket.SHUT_RDWR)
            except OSError:
                pass

        timer = threading.Timer(CONNECTION_TIMEOUT_SECONDS, expire)
        timer.daemon = True
        timer.start()
        try:
            wrapped.do_handshake()
            return wrapped
        except (ssl.SSLError, OSError, ValueError):
            try:
                wrapped.close()
            except OSError:
                pass
            return None
        finally:
            timer.cancel()

    def shutdown(self) -> None:
        self.stopping.set()
        super().shutdown()

    def server_close(self) -> None:
        self.stopping.set()
        super().server_close()
        with self._threads_lock:
            threads = list(self._threads)
        for thread in threads:
            thread.join(timeout=OBSERVATION_TIMEOUT_SECONDS + CONNECTION_TIMEOUT_SECONDS)


class _Handler(BaseHTTPRequestHandler):
    server: _LoopbackServer
    protocol_version = "HTTP/1.0"  # One request per connection, no keepalive queue.
    server_version = "Switchyard"
    sys_version = ""

    def handle(self) -> None:
        # Keep the short absolute input deadline even for a dribbling client.
        # Only validated observations and streams may rearm it.
        self._deadline_lock = threading.Lock()
        self._expired = False
        self._deadline_at = time.monotonic() + CONNECTION_TIMEOUT_SECONDS
        self._deadline = threading.Timer(CONNECTION_TIMEOUT_SECONDS, self._expire)
        self._deadline.daemon = True
        self._deadline.start()
        try:
            super().handle()
        except OSError:
            pass  # Disconnects/deadlines cannot expose an exception to clients.
        finally:
            with self._deadline_lock:
                self._deadline.cancel()

    def _expire(self) -> None:
        with self._deadline_lock:
            # A cancelled input timer may already be waiting on this lock.
            # Never let it terminate the validated collection's new window.
            if time.monotonic() < self._deadline_at:
                return
            self._expired = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _allow_observation(self) -> None:
        self._allow_deadline(OBSERVATION_TIMEOUT_SECONDS)

    def _allow_deadline(self, seconds: float) -> None:
        with self._deadline_lock:
            if self._expired or time.monotonic() >= self._deadline_at:
                raise TimeoutError("input deadline exceeded")
            self._deadline.cancel()
            self._deadline_at = time.monotonic() + seconds
            self._deadline = threading.Timer(seconds, self._expire)
            self._deadline.daemon = True
            self._deadline.start()

    def _allow_stream(self) -> None:
        with self._deadline_lock:
            if self._expired or time.monotonic() >= self._deadline_at:
                raise TimeoutError("input deadline exceeded")
            self._deadline.cancel()
            self._deadline_at = time.monotonic() + SSE_LIFETIME_SECONDS
            self._deadline = threading.Timer(SSE_LIFETIME_SECONDS, self._expire)
            self._deadline.daemon = True
            self._deadline.start()
        self.connection.settimeout(SSE_WRITE_TIMEOUT_SECONDS)

    def _fleet(self) -> dict[str, Any]:
        # The page hides action controls on a listener that would refuse them with 403.
        snapshot = self.server.service.fleet()
        if self._redacted() and isinstance(snapshot.get("operations"), list):
            snapshot = {**snapshot, "operations": [_redact_receipt(item) for item in snapshot["operations"]]}
        return {**snapshot, "read_only_view": True} if self.server.read_only else snapshot

    def _redacted(self) -> bool:
        """Keys see receipts without shell scripts (as the read-only LAN view, which sets it on its Service)."""
        identity = getattr(self, "identity", None)
        return identity is not None and identity.kind == "key"

    def _events(self) -> None:
        if not self.server.stream_slots.acquire(blocking=False):
            self._json(503, {"error": "Live-update slots are busy; read the cached fleet instead."})
            return
        try:
            self._allow_stream()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"retry: 3000\n\n")
            self.wfile.flush()
            revision = None
            heartbeat = time.monotonic()
            deadline = heartbeat + SSE_LIFETIME_SECONDS
            while not self.server.stopping.is_set() and time.monotonic() < deadline:
                # SSE clients send no further bytes. EOF or pipelined input ends
                # this single-request connection and promptly returns its slot.
                if select.select([self.connection], [], [], 0)[0]:
                    return
                current = self.server.service.fleet_revision()
                if current != revision:
                    # Never attach a newer revision to an older cache read.
                    snapshot = self._fleet()
                    if current != self.server.service.fleet_revision():
                        self.server.stopping.wait(SSE_POLL_SECONDS)
                        continue
                    payload = json.dumps(snapshot, ensure_ascii=True, allow_nan=False).encode("utf-8")
                    if len(payload) > MAX_SSE_EVENT_BYTES:
                        return
                    self.wfile.write(b"event: fleet\ndata: " + payload + b"\n\n")
                    self.wfile.flush()
                    revision = current
                    heartbeat = time.monotonic()
                elif time.monotonic() - heartbeat >= SSE_HEARTBEAT_SECONDS:
                    self.wfile.write(b": cached fleet heartbeat\n\n")
                    self.wfile.flush()
                    heartbeat = time.monotonic()
                self.server.stopping.wait(SSE_POLL_SECONDS)
        finally:
            self.server.stream_slots.release()

    def parse_request(self) -> bool:
        if len(self.raw_requestline) > MAX_REQUEST_LINE_BYTES:
            self.requestline = ""
            self.request_version = "HTTP/1.0"
            self.command = None
            self.send_error(414, "request target too long")
            return False
        original = self.rfile
        self.rfile = _HeaderReader(original)
        try:
            if not super().parse_request():
                return False
        finally:
            self.rfile = original
        self.close_connection = True
        if not self.path.startswith("/") or self.path.startswith("//"):
            self.send_error(400, "only origin-form request targets are accepted")
            return False
        hosts = self.headers.get_all("Host", [])
        if len(hosts) != 1 or hosts[0] not in self.server.allowed_hosts:
            self.send_error(403, "invalid Host")
            return False
        origins = self.headers.get_all("Origin", [])
        if len(origins) > 1 or (origins and origins[0] not in self.server.allowed_origins):
            self.send_error(403, "cross-origin requests are forbidden")
            return False
        # An origin must match this request's authority, not another permitted
        # loopback alias: localhost and 127.0.0.1 are different browser origins.
        if origins and origins[0] != f"{self.server.scheme}://{hosts[0]}":
            self.send_error(403, "cross-origin requests are forbidden")
            return False
        sites = self.headers.get_all("Sec-Fetch-Site", [])
        if len(sites) > 1 or (sites and sites[0] not in {"same-origin", "none"}):
            self.send_error(403, "cross-site requests are forbidden")
            return False
        if self.headers.get_all("Transfer-Encoding"):
            self.send_error(400, "transfer encoding is not supported")
            return False
        if self.headers.get_all("Expect"):
            self.send_error(417, "expectations are not supported")
            return False
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) > 1 or (lengths and (not lengths[0].isascii() or not lengths[0].isdecimal())):
            self.send_error(400, "invalid Content-Length")
            return False
        if lengths and (len(lengths[0]) > 8 or int(lengths[0]) > MAX_BODY_BYTES):
            self.send_error(413, "request body too large")
            return False
        self.body_length = int(lengths[0]) if lengths else 0
        if self.command not in {"GET", "POST"}:
            self.send_error(405, "method not allowed")
            return False
        if self.server.read_only and self.command != "GET":
            self._json(403, {"error": "Read-only LAN view: actions are only available on the desk itself (http://127.0.0.1:8710)."})
            return False
        if self.command == "GET" and self.body_length:
            self.send_error(400, "GET requests cannot have a body")
            return False
        if self.command == "POST" and not lengths:
            self.send_error(411, "Content-Length is required")
            return False
        return True

    def handle_expect_100(self) -> bool:
        self.send_error(417, "expectations are not supported")
        return False

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.send_header("Connection", "close")
        super().end_headers()

    def _send(self, status: int, body: bytes, content_type: str, headers: Sequence[tuple[str, str]] = ()) -> None:
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if status == 405:
            self.send_header("Allow", "GET, POST")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, value: Any, headers: Sequence[tuple[str, str]] = ()) -> None:
        self._send(status, json.dumps(value, ensure_ascii=True, allow_nan=False).encode("utf-8"),
                   "application/json; charset=utf-8", headers)

    def _empty(self, headers: Sequence[tuple[str, str]] = ()) -> None:
        self.close_connection = True
        self.send_response(204)
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        # Do not echo request targets, header values, or internal exceptions.
        self._json(code, {"error": self.responses.get(code, ("request rejected",))[0]})

    def log_message(self, format: str, *args: Any) -> None:
        # No untrusted request/header logging or stdout pollution for local tools.
        pass

    def do_GET(self) -> None:
        self._dispatch()

    def do_POST(self) -> None:
        self._dispatch()

    # ---- enforcement: one place ----------------------------------------------------------------

    def _dispatch(self) -> None:
        route, groups = match_route(self.command, self.path)
        if route is None:
            self.send_error(groups)
            return
        try:
            self.identity = self._resolve_identity()
            self._authorize(route)
            data = self._read_body(route) if self.command == "POST" else None
            if data is None and self.command == "POST":
                return  # _read_body already answered (415).
            if route.hosts and self.identity.kind == "key":
                touched = getattr(self, route.hosts)(data)
                outside = sorted(set(touched) - set(self.identity.key.get("hosts") or []))
                if outside:
                    raise AuthError(403, "This key may not act on: " + ", ".join(outside))
            getattr(self, route.handler)(groups, data)
        except AuthError as error:
            headers = [("Retry-After", str(error.retry_after))] if error.retry_after else []
            if error.status == 401 and self.server.secure:
                headers.append(("WWW-Authenticate", 'Bearer realm="switchyard"'))
            self._json(error.status, {"error": str(error)}, headers)
        except (ValueError, UnicodeError, RecursionError):
            self.send_error(400)

    def _cookie(self) -> str | None:
        name = SESSION_COOKIE[self.server.secure]
        values = []
        for header in self.headers.get_all("Cookie", []):
            for part in header.split(";"):
                key, separator, value = part.strip().partition("=")
                if separator and key == name:
                    values.append(value)
        return values[0] if len(values) == 1 else None  # Duplicates (cookie tossing) count as no session.

    def _resolve_identity(self) -> Identity:
        """Once per request: bearer key, else session cookie, else the listener's anonymous kind."""
        if self.server.listener == "view":
            return Identity("view")
        authorizations = self.headers.get_all("Authorization", [])
        cookie = self._cookie()
        if len(authorizations) > 1:
            raise AuthError(400, "Send one Authorization header")
        if authorizations:
            if cookie is not None:
                raise AuthError(400, "Send either a key or a session cookie, not both")
            scheme, _, token = authorizations[0].strip().partition(" ")
            token = token.strip()
            if scheme.lower() != "bearer" or not token:
                return Identity(None, bearer_error="Use Authorization: Bearer <key>")
            try:
                key = self.server.auth.key_for_bearer(token, self.client_address[0])
            except AuthError as error:
                identity = Identity(None, bearer_error=str(error))
                identity.extra["bearer"] = token  # A pending enrollment's key proves its request on poll.
                return identity
            return Identity("key", key=key, extra={"bearer": token})
        if cookie is not None:
            session = self.server.auth.session(cookie, self.server.listener)
            if session is not None:
                return Identity("operator", username=session["username"], session=session, token=cookie)
        return Identity("local" if self.server.listener == "loopback" else None, token=cookie)

    def _authorize(self, route: Route) -> None:
        identity, level = self.identity, route.authority
        kind = identity.kind
        if kind == "operator" and self.command == "POST" and route.handler != "_r_login":
            supplied = self.headers.get_all(CSRF_HEADER, [])
            if len(supplied) != 1 or not _equal(supplied[0], identity.session["csrf_token"]):
                raise AuthError(403, "Missing or wrong X-Switchyard-CSRF token; reload the page")
        if level == "public":
            return
        if kind is None:
            raise AuthError(401, identity.bearer_error or "Sign in, or present a valid key")
        if level == "read":
            return
        if kind == "view":
            raise AuthError(403, "Read-only LAN view")
        scope = (identity.key or {}).get("scope")
        if level == "self":
            if kind != "key":
                raise AuthError(403, "Only a key can revoke itself")
        elif level == "lease":
            if kind == "local":
                raise AuthError(403, "HTTP leases need a lease key or the operator; on this host use `switchyard lease`")
            if kind == "key" and scope not in {"lease", "operate"}:
                raise AuthError(403, f"A {scope} key cannot take leases")
        elif level == "operate":
            if kind == "key" and scope != "operate":
                raise AuthError(403, f"A {scope} key cannot run operations")
        elif level == "desk":
            if kind == "key":
                raise AuthError(403, "Not available to keys (only the operator or the control host's desk)")
        elif level == "operator":
            if kind != "operator":
                raise AuthError(403, "This needs the operator: sign in")
        else:
            raise AuthError(403, "Unknown route authority")

    def _read_body(self, route: Route) -> dict[str, Any] | None:
        if self.body_length > route.body_limit:
            raise AuthError(413, "Request body too large")
        if self.body_length == 0 and route.empty_body:
            return {}
        content_types = self.headers.get_all("Content-Type", [])
        parts = [part.strip().lower() for part in content_types[0].split(";")] if len(content_types) == 1 else []
        if not parts or parts[0] != "application/json" or (
                len(parts) > 1 and parts[1:] not in (["charset=utf-8"], ['charset="utf-8"'])):
            self.send_error(415)
            return None
        body = self.rfile.read(self.body_length)
        if len(body) != self.body_length:
            raise ValueError("incomplete body")
        data = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        if not isinstance(data, dict):
            raise ValueError("JSON object required")
        return data

    # ---- host scopes for operate routes ----------------------------------------------------------

    def _hosts_observe(self, data: dict[str, Any]) -> list[str]:
        if not _valid_id(data.get("host_id")):
            raise ValueError("host_id is required")
        return [data["host_id"]]

    def _hosts_shell(self, data: dict[str, Any]) -> list[str]:
        extra = data.get("extra_host_ids", [])
        if not _valid_id(data.get("host_id")) or not _valid_ids(extra):
            raise ValueError("host_id and extra_host_ids are required to be host IDs")
        return [data["host_id"], *extra]

    # ---- route handlers ------------------------------------------------------------------------

    def _r_static(self, groups: tuple, data: None) -> None:
        name, suffix = groups if groups else ("index.html", "html")
        try:
            body = files("switchyard").joinpath("static", name).read_bytes()
        except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
            self.send_error(404)
            return
        self._send(200, body, _CONTENT_TYPES[suffix])

    def _r_read(self, groups: tuple, data: None) -> None:
        self._json(200, getattr(self.server.service, _READS[self.path])())

    def _r_fleet(self, groups: tuple, data: None) -> None:
        self._json(200, self._fleet())

    def _r_lan_urls(self, groups: tuple, data: None) -> None:
        try:
            manager = self.server.service.lan_routes()
            result = manager.list() if manager else {"configured": False, "revision": 0, "routes": [],
                                                      "endpoints": [], "pending": None}
        except ValueError as error:
            raise AuthError(409, str(error)) from None
        self._json(200, result)

    def _r_lan_url_plan(self, groups: tuple, data: dict[str, Any]) -> None:
        try:
            manager = self.server.service.lan_routes()
            if manager is None:
                raise AuthError(404, "No LAN gateway is configured")
            result = manager.plan(data)
        except ValueError as error:
            raise AuthError(400, str(error)) from None
        self._json(200, result)

    def _r_lan_url_apply(self, groups: tuple, data: dict[str, Any]) -> None:
        if set(data) != {"plan_id", "approved", "request_id"} or data["approved"] is not True \
                or not all(_valid_id(data[key]) for key in ("plan_id", "request_id")):
            raise AuthError(400, "Give a plan ID, request ID and explicit approval")
        if not self.server.mutation_slots.acquire(blocking=False):
            raise AuthError(503, "Operation slots are busy; inspect the LAN URLs view before trying again")
        try:
            self._allow_deadline(LAN_ROUTE_TIMEOUT_SECONDS)
            manager = self.server.service.lan_routes()
            if manager is None:
                raise AuthError(404, "No LAN gateway is configured")
            result = manager.apply(data["plan_id"], approved=True, request_id=data["request_id"])
        except ValueError as error:
            raise AuthError(409, str(error)) from None
        finally:
            self.server.mutation_slots.release()
        self._json(200, result)

    def _r_events(self, groups: tuple, data: None) -> None:
        self._events()

    def _r_receipts(self, groups: tuple, data: None) -> None:
        receipts = self.server.service.operation_receipts()
        self._json(200, [_redact_receipt(item) for item in receipts] if self._redacted() else receipts)

    def _r_receipt(self, groups: tuple, data: None) -> None:
        try:
            result = self.server.service.operation_receipt(groups[0])
        except ValueError:
            self.send_error(404)
            return
        self._json(200, _redact_receipt(result) if self._redacted() else result)

    def _r_session(self, groups: tuple, data: None) -> None:
        identity, server = self.identity, self.server
        kind = identity.kind if identity.kind in {"operator", "key", "local"} else None
        result: dict[str, Any] = {
            "authenticated": kind in {"operator", "key"}, "kind": kind,
            "login_required": server.listener == "lan" and kind not in {"operator", "key"},
            "operator_configured": server.auth.operator_configured() if server.auth else False,
            "tls": {"enabled": server.secure},
        }
        fingerprint = self._ca_fingerprint()
        if fingerprint:
            result["tls"]["ca_fingerprint_sha256"] = fingerprint
        if kind == "operator":
            result.update(username=identity.username, csrf_token=identity.session["csrf_token"],
                          expires_at=_iso(identity.session["expires"]))
        elif kind == "key":
            result["key"] = key_summary(identity.key)
        self._json(200, result)

    def _ca_fingerprint(self) -> str | None:
        store = self.server.tls_store
        try:
            return store.ca_fingerprint() if store is not None and store.ca_cert.is_file() else None
        except (OSError, ValueError):
            return None

    def _cookie_header(self, token: str, max_age: int) -> tuple[str, str]:
        name = SESSION_COOKIE[self.server.secure]
        secure = "; Secure" if self.server.secure else ""
        return ("Set-Cookie", f"{name}={token}; Max-Age={max_age}; Path=/; HttpOnly; SameSite=Strict{secure}")

    def _r_login(self, groups: tuple, data: dict[str, Any]) -> None:
        if self.server.auth is None:
            raise AuthError(404, "Not Found")
        if set(data) != {"username", "password"}:
            raise AuthError(400, "username and password are required")
        session = self.server.auth.login(data["username"], data["password"], client=self.client_address[0],
                                         listener=self.server.listener, replace=self.identity.token)
        max_age = max(1, int(session["expires"] - time.time()))
        self._json(200, {"username": session["username"], "csrf_token": session["csrf_token"],
                         "expires_at": _iso(session["expires"])}, [self._cookie_header(session["token"], max_age)])

    def _r_logout(self, groups: tuple, data: dict[str, Any]) -> None:
        if self.identity.kind == "operator":
            self.server.auth.logout(self.identity.token)
        self._empty([self._cookie_header("", 0)])

    def _r_tls_ca(self, groups: tuple, data: None) -> None:
        store = self.server.tls_store
        if store is None or not store.ca_cert.is_file():
            raise AuthError(404, "TLS is not initialized on this desk")
        self._send(200, store.ca_pem().encode(), "application/x-pem-file")

    def _r_enroll(self, groups: tuple, data: dict[str, Any]) -> None:
        if not self.server.secure or not self.server.leaf_sha256:
            raise AuthError(404, "Enrollment is served on the HTTPS listener only")
        base = f"https://{self.headers['Host']}"
        result = self.server.auth.create_enrollment(data, source_address=self.client_address[0],
                                                    leaf_sha256=self.server.leaf_sha256, base_url=base)
        self._json(201, result)

    def _r_enroll_poll(self, groups: tuple, data: None) -> None:
        self._json(200, self.server.auth.poll_enrollment(groups[0], self.identity.extra.get("bearer")))

    def _r_enrollments(self, groups: tuple, data: None) -> None:
        self._json(200, self.server.auth.enrollments())

    def _r_approve(self, groups: tuple, data: dict[str, Any]) -> None:
        if not set(data) <= {"scope", "hosts", "expires_in_days", "label"}:
            raise AuthError(400, "Only scope, hosts, expires_in_days and label are accepted")
        try:
            key = self.server.auth.approve(groups[0], self.identity, **data)
        except ValueError as error:
            raise AuthError(400, str(error)[:300]) from None
        self._json(200, key)

    def _r_deny(self, groups: tuple, data: dict[str, Any]) -> None:
        if data:
            raise AuthError(400, "deny takes no arguments")
        self.server.auth.deny(groups[0], self.identity)
        self._empty()

    def _r_keys(self, groups: tuple, data: None) -> None:
        self._json(200, self.server.auth.keys())

    def _r_revoke(self, groups: tuple, data: dict[str, Any]) -> None:
        if data:
            raise AuthError(400, "revoke takes no arguments")
        self.server.auth.revoke(groups[0], self.identity)
        self._empty()

    def _r_revoke_self(self, groups: tuple, data: dict[str, Any]) -> None:
        if data:
            raise AuthError(400, "revoke takes no arguments")
        self.server.auth.revoke_self(self.identity.key)
        self._empty()

    # ---- leases over HTTP ----------------------------------------------------------------------

    def _device_hosts(self, device: str) -> list[str]:
        """Registry host IDs behind a lease device name: the host ID itself, else every host on that ledger."""
        from .agent_leases import host_label
        records = self.server.service.hosts()["hosts"]
        direct = [record["id"] for record in records if record["id"].lower() == device.lower()]
        if direct:
            return direct
        label = device.upper()
        return [record["id"] for record in records if host_label(record["id"]) == label or Path(
            (record.get("collector") or {}).get("ledger") or "/").name == f"DEVICE_ACCESS_{label}.md"]

    def _ttl(self, data: dict[str, Any]) -> int:
        minutes = data.get("ttl_minutes", 60)
        if type(minutes) is not int or not 1 <= minutes <= 120:
            raise AuthError(400, "ttl_minutes must be an integer from 1 to 120")
        return minutes * 60

    def _lease_call(self, call):
        self._allow_deadline(LEASE_TIMEOUT_SECONDS)
        try:
            return call()
        except LeaseBusy as error:
            raise AuthError(409, str(error)[:500]) from None
        except ValueError as error:
            raise AuthError(400, str(error)[:500]) from None

    def _r_leases(self, groups: tuple, data: None) -> None:
        self._json(200, self.server.service.agent_leases().list())

    def _r_lease_hold(self, groups: tuple, data: dict[str, Any]) -> None:
        if not {"device", "scope"} <= set(data) <= {"device", "scope", "ttl_minutes"}:
            raise AuthError(400, "device and scope are required (optional ttl_minutes)")
        device, scope = data["device"], data["scope"]
        if not _valid_id(device) or not isinstance(scope, str) or not 1 <= len(scope) <= 512:
            raise AuthError(400, "Invalid device or scope")
        ttl = self._ttl(data)
        identity = self.identity
        if identity.kind == "key":
            # Amendment 1: a key's hosts bound its leases; refused before any lock is attempted.
            hosts = self._device_hosts(device)
            allowed = set(identity.key.get("hosts") or [])
            if not hosts or not set(hosts) <= allowed:
                raise AuthError(403, f"This key may not lease {device}: not in its hosts")
            key = identity.key
            registry = {record["id"] for record in self.server.service.hosts()["hosts"]}
            origin = key.get("host_id") if key.get("host_id") in registry else None
            agent = f", paseo:{key['agent_id'][:8]}" if key.get("agent_id") else ""
            owner = f"{key['name']} ({key['user']}{agent}; key {key['id'][:8]})"
            if key.get("host_id") and not origin:
                owner += f" from {key['host_id']}"
            kwargs = {"owner": owner, "worktree": f"https-key:{key['id']}", "origin_host": origin,
                      "agent_id": key.get("agent_id") if origin else None,
                      "origin_user": key["user"] if origin else None}
        else:
            kwargs = {"owner": f"operator:{identity.username} (web)", "worktree": "switchyard web"}
        manager = self.server.service.agent_leases()
        result = self._lease_call(lambda: manager.hold(device, scope=scope, ttl=ttl, detached=True, **kwargs))
        if identity.kind == "key":
            self.server.auth.store.record_lease(result["lease_id"], identity.key["id"])
        self._json(200, {key: result.get(key) for key in ("lease_id", "device", "expires_at")})

    def _lease_owned(self, lease_id: str) -> None:
        if self.identity.kind == "key" and self.server.auth.store.lease_owner(lease_id) != self.identity.key["id"]:
            raise AuthError(403, "Only the key that took this lease (or the operator) may change it")

    def _r_lease_renew(self, groups: tuple, data: dict[str, Any]) -> None:
        if not set(data) <= {"ttl_minutes"}:
            raise AuthError(400, "Only ttl_minutes is accepted")
        self._lease_owned(groups[0])
        ttl = self._ttl(data)
        manager = self.server.service.agent_leases()
        result = self._lease_call(lambda: manager.renew(groups[0], ttl=ttl))
        self._json(200, {key: result.get(key) for key in ("lease_id", "device", "expires_at")})

    def _r_lease_release(self, groups: tuple, data: dict[str, Any]) -> None:
        if data:
            raise AuthError(400, "release takes no arguments")
        self._lease_owned(groups[0])
        manager = self.server.service.agent_leases()
        self._json(200, self._lease_call(lambda: manager.release(groups[0])))

    # ---- existing desk actions -----------------------------------------------------------------

    def _r_observe_local(self, groups: tuple, data: dict[str, Any]) -> None:
        if data:
            raise ValueError("observation takes no arguments")
        self._json(200, self.server.service.observe_local())

    def _r_observe_host(self, groups: tuple, data: dict[str, Any]) -> None:
        if set(data) != {"host_id"}:
            raise ValueError("only host_id is accepted")
        host_id = data["host_id"]
        if not isinstance(host_id, str) or not 1 <= len(host_id) <= 128:
            raise ValueError("host_id must be a nonempty string of at most 128 characters")
        if not any(host["id"] == host_id and host["collection_enabled"]
                   for host in self.server.service.fleet()["hosts"]):
            raise ValueError("unknown or unconfigured host")
        self._allow_observation()
        self._json(200, self.server.service.collect_host(host_id))

    def _r_migration(self, groups: tuple, data: dict[str, Any]) -> None:
        if set(data) != {"workload_id", "target_id"}:
            raise ValueError("only workload_id and target_id are accepted")
        if any(not isinstance(value, str) or not 1 <= len(value) <= 128 for value in data.values()):
            raise ValueError("IDs must be nonempty strings of at most 128 characters")
        self._json(200, self.server.service.plan_migration(data["workload_id"], data["target_id"]))

    def _r_host_mutation(self, groups: tuple, data: dict[str, Any]) -> None:
        self._host_mutation(data)

    def _r_enrollment(self, groups: tuple, data: dict[str, Any]) -> None:
        self._enrollment(data)

    def _r_operation(self, groups: tuple, data: dict[str, Any]) -> None:
        self._operation(data)

    def _host_mutation(self, data: dict[str, Any]) -> None:
        route = self.path
        if route == "/api/hosts/update":
            if set(data) != {"host_id", "changes", "expected_revision", "connection"} or type(data["connection"]) is not bool:
                raise ValueError("invalid host update arguments")
            changes = data["changes"]
            allowed = _HOST_DESCRIPTION_FIELDS | (_HOST_CONNECTION_FIELDS if data["connection"] else set())
            if not isinstance(changes, dict) or not changes or not set(changes) <= allowed:
                raise ValueError("unsupported host changes")
            for key, value in changes.items():
                if key == "capabilities":
                    if not _valid_ids(value):
                        raise ValueError("invalid capabilities")
                elif key == "port":
                    if type(value) is not int or not 1 <= value <= 65535:
                        raise ValueError("invalid port")
                elif not isinstance(value, str) or len(value) > 8192:
                    raise ValueError("invalid host description or connection")
        elif route == "/api/hosts/paseo":
            if set(data) != {"host_id", "enabled", "listen", "cli", "expected_revision"} or type(data["enabled"]) is not bool:
                raise ValueError("invalid Paseo configuration arguments")
            if not isinstance(data["listen"], str) or not 1 <= len(data["listen"]) <= 256:
                raise ValueError("invalid Paseo listen address")
            if data["cli"] is not None and (not isinstance(data["cli"], str) or not 1 <= len(data["cli"]) <= 4096):
                raise ValueError("invalid Paseo CLI candidate")
        elif route == "/api/hosts/scan-key":
            if set(data) != {"host_id", "request_id"} or not _valid_id(data["request_id"]):
                raise ValueError("invalid host key scan arguments")
        else:
            if set(data) != {"host_id", "scan_id", "fingerprints", "expected_revision"} or not _valid_id(data["scan_id"]):
                raise ValueError("invalid host key confirmation")
            if not _valid_ids(data["fingerprints"]) or not data["fingerprints"]:
                raise ValueError("fingerprints must be a nonempty unique list")
        if not _valid_id(data["host_id"]) or ("expected_revision" in data and not _valid_id(data["expected_revision"])):
            raise ValueError("invalid host or revision")
        if not self.server.mutation_slots.acquire(blocking=False):
            self._json(503, {"error": "Request slots are busy. Read current hosts before another request; do not automatically retry."})
            return
        try:
            self._allow_deadline(OPERATION_TIMEOUT_SECONDS)
            try:
                service = self.server.service
                if route == "/api/hosts/update":
                    result = service.update_host(data["host_id"], data["changes"],
                                                 expected_revision=data["expected_revision"], connection=data["connection"])
                elif route == "/api/hosts/paseo":
                    result = service.configure_paseo(data["host_id"], enabled=data["enabled"], listen=data["listen"],
                                                     cli=data["cli"], expected_revision=data["expected_revision"])
                elif route == "/api/hosts/scan-key":
                    result = service.scan_host_key(data["host_id"], request_id=data["request_id"])
                else:
                    result = service.pin_host_key(data["host_id"], scan_id=data["scan_id"],
                                                  fingerprints=data["fingerprints"], expected_revision=data["expected_revision"])
            except ValueError as failure:
                self._json(400, {"error": str(failure)[:500]})
                return
            except OSError:
                self._json(503, {"error": "Host state could not be saved. Read current hosts before another request."})
                return
            self._json(200, result)
        finally:
            self.server.mutation_slots.release()

    def _operation(self, data: dict[str, Any]) -> None:
        service = self.server.service
        if self.path == "/api/operations/plan":
            if not {"action", "workload_id"} <= set(data) <= {"action", "workload_id", "target_id"}:
                raise ValueError("only action, workload_id and optional target_id are accepted")
            if not all(_valid_id(data[key]) for key in ("action", "workload_id")):
                raise ValueError("invalid operation IDs")
            if data.get("target_id") is not None and not _valid_id(data["target_id"]):
                raise ValueError("invalid target_id")
            self._json(200, service.plan_operation(data["action"], data["workload_id"], data.get("target_id")))
            return
        if self.path == "/api/operations/inspect":
            if set(data) != {"workload_id", "request_id"} or not all(_valid_id(value) for value in data.values()):
                raise ValueError("only valid workload_id and request_id are accepted")
        elif self.path == "/api/operations/execute":
            if set(data) != {"plan_id", "approved", "request_id"}:
                raise ValueError("only plan_id, approved and request_id are accepted")
            if not _valid_id(data["plan_id"]) or not _valid_id(data["request_id"]) or type(data["approved"]) is not bool:
                raise ValueError("invalid plan approval or request ID")
        else:
            if not {"host_id", "script", "request_id"} <= set(data) <= {
                "host_id", "script", "request_id", "timeout_seconds", "extra_host_ids"
            }:
                raise ValueError("unsupported shell arguments")
            if not _valid_id(data["host_id"]) or not _valid_id(data["request_id"]):
                raise ValueError("invalid host or request ID")
            script = data["script"]
            if not isinstance(script, str) or not script or len(script.encode("utf-8")) > 16384:
                raise ValueError("script must be a nonempty UTF-8 string of at most 16 KiB")
            timeout = data.get("timeout_seconds", 30)
            if type(timeout) is not int or not 1 <= timeout <= 240:
                raise ValueError("timeout_seconds must be an integer from 1 to 240")
            extra = data.get("extra_host_ids", [])
            if not isinstance(extra, list) or len(extra) > 128 or not all(_valid_id(item) for item in extra):
                raise ValueError("extra_host_ids must be a bounded list of host IDs")
        if not self.server.mutation_slots.acquire(blocking=False):
            self._json(503, {"error": "Operation slots are busy. Inspect receipts; do not automatically retry."})
            return
        try:
            self._allow_deadline(EXECUTE_TIMEOUT_SECONDS if self.path == "/api/operations/execute"
                                 else OPERATION_TIMEOUT_SECONDS)
            if self.path == "/api/operations/inspect":
                result = service.inspect_workload(data["workload_id"], request_id=data["request_id"])
            elif self.path == "/api/operations/execute":
                result = service.execute_operation(data["plan_id"], approved=data["approved"], request_id=data["request_id"])
            else:
                result = service.run_shell(data["host_id"], script, timeout_seconds=timeout,
                                           request_id=data["request_id"], extra_host_ids=extra)
            self._json(200, result)
        finally:
            self.server.mutation_slots.release()

    def _enrollment(self, data: dict[str, Any]) -> None:
        service = self.server.service
        route = self.path
        if route == "/api/fleet-keys/inspect":
            if set(data) != {"host_ids", "request_id"} or not _valid_id(data["request_id"]):
                raise ValueError("only host_ids and request_id are accepted")
        elif route == "/api/fleet-keys/plan":
            if set(data) != {"action", "host_ids"} or data["action"] not in ("enroll", "remove", "rotate", "reconcile"):
                raise ValueError("invalid fleet-key action")
        elif route == "/api/fleet-keys/execute":
            if set(data) != {"plan_id", "approved", "request_id"} or not all(
                _valid_id(data[key]) for key in ("plan_id", "request_id")
            ) or type(data["approved"]) is not bool:
                raise ValueError("invalid fleet-key approval")
        elif route == "/api/definitions/propose":
            if not {"resource_id", "workload_id", "name", "purpose"} <= set(data) <= {
                "resource_id", "workload_id", "name", "purpose", "supporting_resource_ids"
            } or not all(_valid_id(data[key]) for key in ("resource_id", "workload_id")):
                raise ValueError("invalid definition proposal arguments")
            if not isinstance(data["name"], str) or not 1 <= len(data["name"]) <= 4096:
                raise ValueError("invalid name")
            if not isinstance(data["purpose"], str) or not 1 <= len(data["purpose"]) <= 8192:
                raise ValueError("invalid purpose")
            if data.get("supporting_resource_ids") is not None and not _valid_ids(data["supporting_resource_ids"]):
                raise ValueError("invalid supporting resources")
        else:
            expected = {"definition", "expected_revision"}
            if route == "/api/definitions/update":
                expected.add("workload_id")
            if set(data) != expected or not isinstance(data["definition"], dict) or not _valid_id(data["expected_revision"]):
                raise ValueError("invalid definition or revision")
            if "workload_id" in data and not _valid_id(data["workload_id"]):
                raise ValueError("invalid workload ID")
        if "host_ids" in data and not _valid_ids(data["host_ids"]):
            raise ValueError("host_ids must be a bounded list of unique host IDs")
        if not self.server.mutation_slots.acquire(blocking=False):
            self._json(503, {"error": "Request slots are busy. Inspect receipts or review definitions; do not automatically retry."})
            return
        try:
            self._allow_deadline(OPERATION_TIMEOUT_SECONDS)
            try:
                if route == "/api/fleet-keys/inspect":
                    result = service.inspect_fleet_keys(data["host_ids"], request_id=data["request_id"])
                elif route == "/api/fleet-keys/plan":
                    result = service.plan_fleet_keys(data["action"], data["host_ids"])
                elif route == "/api/fleet-keys/execute":
                    result = service.execute_fleet_keys(data["plan_id"], approved=data["approved"], request_id=data["request_id"])
                elif route == "/api/definitions/propose":
                    result = service.propose_workload_definition(
                        data["resource_id"], workload_id=data["workload_id"], name=data["name"], purpose=data["purpose"],
                        supporting_resource_ids=data.get("supporting_resource_ids"),
                    )
                elif route == "/api/definitions/save":
                    result = service.save_workload_definition(data["definition"], expected_revision=data["expected_revision"])
                else:
                    result = service.update_workload_definition(
                        data["workload_id"], data["definition"], expected_revision=data["expected_revision"],
                    )
            except ValueError as failure:
                # Definition errors contain validation/revision context, not remote
                # command output. Preserve it so a stale draft can be reviewed.
                message = str(failure)[:500] if route.startswith("/api/definitions/") else "Fleet-key request rejected. Review cached inspection, configured authority and receipt history."
                self._json(400, {"error": message})
                return
            except OSError:
                self._json(503, {"error": "Local state could not be saved. Read current definitions or receipts before another request."})
                return
            self._json(200, result)
        finally:
            self.server.mutation_slots.release()

    # ---- Ansible ---------------------------------------------------------------------------------

    def _ansible(self):
        from types import SimpleNamespace
        from . import ansible_ops
        identity = self.identity
        owner = f"operator:{identity.username} (web)" if identity.kind == "operator" else None
        # The same resolution as the CLI and MCP: SWITCHYARD_ANSIBLE, else the default beside the catalog.
        path = ansible_ops.config_path(SimpleNamespace(catalog=str(self.server.catalog), ansible_config=None))
        if not Path(path).expanduser().is_file():
            raise AuthError(404, f"Ansible is not configured on this desk: no runner configuration at {path}")
        return ansible_ops.from_service(self.server.service, path, owner=owner)

    def _ansible_call(self, call, *, status: int = 200, slot: bool = False) -> None:
        """Errors from the Ansible backend are Switchyard's own messages (never values or passwords)."""
        if slot and not self.server.mutation_slots.acquire(blocking=False):
            self._json(503, {"error": "Request slots are busy. Read the run list before another request; do not automatically retry."})
            return
        try:
            self._allow_deadline(OPERATION_TIMEOUT_SECONDS)
            try:
                result = call(self._ansible())
            except LeaseBusy as error:
                raise AuthError(409, str(error)[:600]) from None
            except (ValueError, OSError, subprocess.SubprocessError) as error:
                raise AuthError(400, str(error)[:600]) from None
            self._json(status, result)
        finally:
            if slot:
                self.server.mutation_slots.release()

    def _become_password(self, data: dict[str, Any]):
        """Take the operator's sudo password out of the request body at once. Accepted only where the browser
        cannot have sent it in clear text across the network: the loopback desk or the HTTPS listener."""
        from .ansible_ops import BecomePassword
        value = data.pop("become_password", None)
        if value is None:
            return BecomePassword()
        if not (self.server.listener == "loopback" or self.server.secure):
            raise AuthError(400, "A sudo password is accepted only over HTTPS or on the desk itself")
        try:
            return BecomePassword(value)
        except ValueError as error:
            raise AuthError(400, str(error)) from None

    def _r_ansible_playbooks(self, groups: tuple, data: None) -> None:
        try:
            self._ansible_call(lambda ops: {"configured": True, **ops.playbooks()})
        except AuthError as error:
            if error.status != 404:
                raise
            self._json(200, {"configured": False, "error": str(error), "playbooks": []})

    def _r_ansible_playbook(self, groups: tuple, data: None) -> None:
        self._ansible_call(lambda ops: ops.playbook(groups[0]))

    def _r_ansible_runs(self, groups: tuple, data: None) -> None:
        self._ansible_call(lambda ops: {"runs": ops.runs()})

    def _r_ansible_run(self, groups: tuple, data: None) -> None:
        self._ansible_call(lambda ops: ops.run(groups[0]))

    def _r_ansible_inspect(self, groups: tuple, data: dict[str, Any]) -> None:
        if set(data) != {"path"} or not isinstance(data["path"], str):
            raise AuthError(400, "Give the directory as path")
        self._ansible_call(lambda ops: ops.inspect_directory(data["path"]), slot=True)

    def _r_ansible_register(self, groups: tuple, data: dict[str, Any]) -> None:
        if set(data) != {"playbook_id", "registration"}:
            raise AuthError(400, "playbook_id and registration are required")
        self._ansible_call(lambda ops: ops.register(data["playbook_id"], data["registration"]), slot=True)

    def _r_ansible_update(self, groups: tuple, data: dict[str, Any]) -> None:
        if set(data) != {"registration", "expected_revision"}:
            raise AuthError(400, "registration and expected_revision are required")
        self._ansible_call(lambda ops: ops.update_registration(groups[0], data["registration"],
                                                               expected_revision=data["expected_revision"]), slot=True)

    def _r_ansible_remove(self, groups: tuple, data: dict[str, Any]) -> None:
        if set(data) != {"expected_revision"}:
            raise AuthError(400, "expected_revision is required")
        self._ansible_call(lambda ops: ops.remove_registration(groups[0], expected_revision=data["expected_revision"]),
                           slot=True)

    def _r_ansible_plan(self, groups: tuple, data: dict[str, Any]) -> None:
        password = self._become_password(data)
        try:
            if not {"playbook_id", "host_id"} <= set(data) <= {"playbook_id", "host_id", "extra_vars", "allow_dirty"}:
                raise AuthError(400, "playbook_id and host_id are required (optional extra_vars, allow_dirty, become_password)")
            if not _valid_id(data["host_id"]) or not _valid_id(data["playbook_id"]):
                raise AuthError(400, "Invalid playbook or host ID")
            # The job gets the password itself (`take`); if the call never reaches the backend, `clear` drops it.
            self._ansible_call(lambda ops: ops.plan(
                data["playbook_id"], data["host_id"], extra_vars=data.get("extra_vars") or {},
                allow_dirty=data.get("allow_dirty", False), wait=DESK_LEASE_WAIT, become_password=password.take(),
                background=True), status=202, slot=True)
        finally:
            password.clear()

    def _r_ansible_apply(self, groups: tuple, data: dict[str, Any]) -> None:
        password = self._become_password(data)
        try:
            if not {"plan_id", "approved", "request_id"} <= set(data) <= {"plan_id", "approved", "request_id", "secret_vars"}:
                raise AuthError(400, "plan_id, approved and request_id are required (optional secret_vars, become_password)")
            self._ansible_call(lambda ops: ops.apply(
                data["plan_id"], approved=data["approved"], request_id=data["request_id"],
                extra_vars=data.get("secret_vars") or {}, wait=DESK_LEASE_WAIT, become_password=password.take(),
                background=True), status=202, slot=True)
        finally:
            password.clear()

    def _r_ansible_record_manual(self, groups: tuple, data: dict[str, Any]) -> None:
        if set(data) != {"request_id"}:
            raise AuthError(400, "request_id is required")
        self._ansible_call(lambda ops: ops.record_manual(groups[0], request_id=data["request_id"]), slot=True)


def _valid_id(value: Any) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 128


def _valid_ids(value: Any) -> bool:
    return isinstance(value, list) and len(value) <= 128 and all(_valid_id(item) for item in value) and len(set(value)) == len(value)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("non-finite JSON number")


def _equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8", "replace"), right.encode("utf-8", "replace"))


def _iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


def _redact_receipt(receipt: Any) -> Any:
    """Receipt without its shell script or script preview (`Service._public_receipt` with redact_commands)."""
    if not isinstance(receipt, dict) or not ({"script", "script_preview"} & set(receipt)):
        return receipt
    result = {key: value for key, value in receipt.items() if key not in {"script", "script_preview"}}
    result["script_redacted"] = True
    return result


def default_state_dir() -> Path:
    """The Service default, without constructing a Service."""
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "switchyard"


def _private_lan(address: Any, allowed_clients: str | None):
    # A narrow, portable default: one ordinary LAN subnet around the exact
    # bind address, never every private network.
    network = (ipaddress.ip_network(allowed_clients, strict=True) if allowed_clients is not None
               else ipaddress.ip_network(f"{address}/{24 if address.version == 4 else 64}", strict=False))
    if not address.is_private or address.is_loopback or address.is_unspecified or address not in network \
            or not network.is_private or network.prefixlen < (16 if network.version == 4 else 48):
        raise ValueError("LAN listeners must bind one private literal address inside a private client network (/16 or narrower)")
    return network


def enable_https(server: _LoopbackServer, state_root: str | Path, names: Sequence[str] = (),
                 network: Any = None) -> None:
    """Turn a bound listener into the authenticated HTTPS LAN listener (create_server(lan=True) uses this;
    tests use it on loopback). Issues or renews the server certificate if it does not cover the bound address
    and `names`, or has fewer than 30 days left; the CA key is read only by that openssl run."""
    from .tls import TLSStore, normalize_name
    store = TLSStore(state_root)
    host = server.server_address[0]
    wanted = [normalize_name(host), *(normalize_name(name) for name in names)]
    store.ensure_server(wanted)
    server.tls_store = store
    server.tls_context = store.server_context()
    server.leaf_sha256 = store.leaf_sha256()
    server.listener = "lan"
    server.allowed_clients = network
    server.set_names([name for name in store.names() if name != host])


def create_server(
    catalog: str | Path, host: str = "127.0.0.1", port: int = 8710, *,
    state_dir: str | Path | None = None, collectors_path: str | Path | None = None,
    operations_path: str | Path | None = None, lan_read_only: bool = False,
    allowed_clients: str | None = None, lan: bool = False, names: Sequence[str] = (),
) -> HTTPServer:
    """Bind the loopback desk; with `lan` the authenticated HTTPS LAN listener; with `lan_read_only` the legacy
    read-only plain-HTTP LAN view. Callers own close/shutdown.

    Port zero is supported for isolated tests. Hostnames other than localhost
    are rejected without DNS lookup; localhost binds explicitly to 127.0.0.1.
    """
    if host == "localhost":
        host = "127.0.0.1"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError("web listener must use a literal address or localhost") from None
    if "%" in host:
        raise ValueError("web listener must not use a scoped address")
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("port must be an integer from 0 to 65535")
    if lan and lan_read_only:
        raise ValueError("Choose either the HTTPS LAN listener or the read-only LAN view")
    network = None
    if lan or lan_read_only:
        network = _private_lan(address, allowed_clients)
    elif not address.is_loopback:
        raise ValueError("full-control web listener must bind to loopback; use --lan (HTTPS) for other machines")
    if names and not lan:
        raise ValueError("Certificate names apply to the HTTPS LAN listener only")
    root = Path(state_dir) if state_dir is not None else default_state_dir()
    service = Service(catalog, state_dir=state_dir, collectors_path=collectors_path, operations_path=operations_path)
    server = _LoopbackServer((str(address), port), service)
    server.catalog = Path(catalog)
    try:
        if lan_read_only:
            server.listener = "view"
            server.read_only = True
            server.service.redact_commands = True  # Shell scripts in receipts stay on the control host.
            server.allowed_clients = network
        else:
            server.auth = Auth(root, registry_hosts=lambda: [record["id"] for record in service.hosts()["hosts"]])
            if lan:
                enable_https(server, root, names, network)
            else:
                from .tls import TLSStore
                server.tls_store = TLSStore(root)  # Only to show the CA fingerprint and serve the CA certificate.
    except BaseException:
        server.server_close()
        raise
    return server


def serve(
    catalog: str | Path, host: str = "127.0.0.1", port: int = 8710, *,
    state_dir: str | Path | None = None, collectors_path: str | Path | None = None,
    operations_path: str | Path | None = None, lan_read_only: bool = False,
    allowed_clients: str | None = None, lan: bool = False, names: Sequence[str] = (),
) -> None:
    """Serve until interrupted. Desk-started Ansible runs are stopped first (their runner groups killed, receipts
    finished, leases released) on SIGTERM or Ctrl-C; with none running, SIGTERM ends the process as before."""
    import signal
    from .ansible_ops import JOBS

    def terminate(signum, frame):
        JOBS.shutdown()
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    extra = {"lan": True, "names": tuple(names)} if lan else {}
    with create_server(catalog, host, port, state_dir=state_dir, collectors_path=collectors_path,
                       operations_path=operations_path, lan_read_only=lan_read_only,
                       allowed_clients=allowed_clients, **extra) as server:
        previous = signal.signal(signal.SIGTERM, terminate)
        try:
            server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt:
            pass
        finally:
            JOBS.shutdown()
            signal.signal(signal.SIGTERM, previous)
