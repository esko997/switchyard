"""Remote client enrollment and keyed HTTPS access (tools/switchyard-remote) against a stub HTTPS server.

The stub implements the round 11 contract's client-facing routes with a throwaway CA and certificates made
by the openssl CLI; the TLS tests are skipped when openssl is absent. No real hosts, ledgers or keys.
"""
from contextlib import redirect_stderr, redirect_stdout
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import stat
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

CLIENT = Path(__file__).resolve().parents[1] / "tools/switchyard-remote"
OPENSSL = shutil.which("openssl")


def load_client():
    loader = importlib.machinery.SourceFileLoader("switchyard_remote_http", str(CLIENT))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


def contract_code(leaf_der, key_sha256, request_id):
    """Independent implementation of the contract's code formula (the stub's side)."""
    leaf_hex = hashlib.sha256(leaf_der).hexdigest()
    text = base64.b32encode(hashlib.sha256(f"{leaf_hex}:{key_sha256}:{request_id}".encode()).digest()[:5]).decode()
    return f"{text[:4]}-{text[4:]}"


def make_chain(directory, name):
    """A CA and a server certificate for IP 127.0.0.1 only (so `localhost` fails the hostname check)."""
    directory = Path(directory)
    ca_key, ca_pem = directory / f"{name}-ca.key", directory / f"{name}-ca.pem"
    leaf_key, leaf_csr, leaf_pem = directory / f"{name}.key", directory / f"{name}.csr", directory / f"{name}.pem"
    extensions = directory / f"{name}.ext"
    extensions.write_text("subjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\n"
                          "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
                          "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    run = lambda *argv: subprocess.run([OPENSSL, *argv], check=True, capture_output=True)
    run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(ca_key),
        "-out", str(ca_pem), "-days", "2", "-subj", f"/CN={name} test CA",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(leaf_key),
        "-out", str(leaf_csr), "-subj", f"/CN={name} server")
    run("x509", "-req", "-in", str(leaf_csr), "-CA", str(ca_pem), "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(leaf_pem), "-days", "2", "-extfile", str(extensions))
    return {"ca_pem": ca_pem.read_text(), "leaf": str(leaf_pem), "key": str(leaf_key),
            "leaf_der": ssl.PEM_cert_to_DER_cert(leaf_pem.read_text()),
            "ca_fingerprint": "sha256:" + hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca_pem.read_text())).hexdigest()}


class Stub:
    """The contract's client-facing routes. Records every request (method, path, headers, body)."""

    def __init__(self, chain, port=0):
        self.chain, self.requests, self.enrollments, self.keys, self.leases = chain, [], {}, {}, {}
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                stub.handle(self, "GET")

            def do_POST(self):
                stub.handle(self, "POST")

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(chain["leaf"], chain["key"])
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.url = f"https://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def paths(self):
        return [(method, path) for method, path, _, _ in self.requests]

    def decide(self, request_id, status, scope=None, hosts=None):
        entry = self.enrollments[request_id]
        entry["status"] = status
        if status == "approved":
            scope = scope or entry["body"]["scope"]
            hosts = entry["body"].get("hosts", []) if hosts is None else hosts
            self.keys[entry["body"]["key_sha256"]] = {"id": f"key-{request_id}", "label": entry["body"]["name"],
                                                      "scope": scope, "hosts": [] if scope == "read" else hosts,
                                                      "expires_at": "2027-02-21T00:00:00+00:00", "revoked": False}

    def key_for(self, handler):
        header = handler.headers.get("Authorization") or ""
        if not header.startswith("Bearer sy1_"):
            return None, None
        digest = hashlib.sha256(header[len("Bearer "):].encode()).hexdigest()
        return digest, self.keys.get(digest)

    def handle(self, handler, method):
        length = int(handler.headers.get("Content-Length") or 0)
        raw = handler.rfile.read(length) if length else b""
        body = json.loads(raw) if raw else None
        path = handler.path
        self.requests.append((method, path, dict(handler.headers), body))
        digest, key = self.key_for(handler)
        active = key is not None and not key["revoked"]

        def send(status, value=None, content_type="application/json"):
            data = b"" if value is None else (value if isinstance(value, bytes) else json.dumps(value).encode())
            handler.send_response(status)
            handler.send_header("Content-Type", content_type)
            handler.send_header("Content-Length", str(len(data)))
            handler.end_headers()
            handler.wfile.write(data)

        if (method, path) == ("GET", "/api/tls/ca"):
            return send(200, self.chain["ca_pem"].encode(), "application/x-pem-file")
        if (method, path) == ("POST", "/api/enroll"):
            request_id = f"req{len(self.enrollments) + 1}"
            self.enrollments[request_id] = {"body": body, "status": "pending"}
            return send(201, {"id": request_id, "code": contract_code(self.chain["leaf_der"], body["key_sha256"], request_id),
                              "approve_url": f"{self.url}/#access/{request_id}",
                              "expires_at": "2099-01-01T00:00:00+00:00", "poll_after_seconds": 0})
        match = re.fullmatch(r"/api/enroll/([A-Za-z0-9_-]+)", path)
        if method == "GET" and match:
            entry = self.enrollments.get(match[1])
            if entry is None or entry["body"]["key_sha256"] != digest:
                return send(404, {"error": "not found"})
            result = {"status": entry["status"]}
            if entry["status"] == "approved":
                result["key"] = {k: v for k, v in key.items() if k != "revoked"}
            return send(200, result)
        if not active:
            return send(401, {"error": "authentication required"})
        public = {k: v for k, v in key.items() if k != "revoked"}
        if (method, path) == ("GET", "/api/auth/session"):
            return send(200, {"authenticated": True, "kind": "key", "key": public, "login_required": False,
                              "operator_configured": True, "tls": {"enabled": True}})
        if (method, path) == ("POST", "/api/keys/self/revoke"):
            key["revoked"] = True
            return send(204)
        if (method, path) == ("GET", "/api/hosts"):
            return send(200, {"hosts": [{"id": "host-b"}]})
        if (method, path) == ("GET", "/api/forbidden"):
            return send(403, {"error": "operator only"})
        if not path.startswith("/api/leases"):
            return send(404, {"error": "not found"})
        if key["scope"] == "read":
            return send(403, {"error": "this key may not lease"})
        if (method, path) == ("GET", "/api/leases"):
            return send(200, {"ledgers": []})
        if (method, path) == ("POST", "/api/leases"):
            if body["device"] == "busy":
                return send(409, {"error": "BUSY busy: SomeAgent; firmware flash; 3s ago"})
            if body["device"] not in key["hosts"]:
                return send(403, {"error": f"{body['device']} is not in this key's hosts", "allowed_hosts": key["hosts"]})
            lease_id = f"{len(self.leases) + 1:032x}"
            self.leases[lease_id] = body
            return send(201, {"lease_id": lease_id, "device": body["device"].upper(), "expires_at": "2099-01-01T01:00:00+00:00"})
        match = re.fullmatch(r"/api/leases/([0-9a-f]{32})/(renew|release)", path)
        if method == "POST" and match and match[1] in self.leases:
            return send(204) if match[2] == "release" else send(200, {"lease_id": match[1], "expires_at": "2099"})
        return send(404, {"error": "no such lease"})


class CodeAndKeyTests(unittest.TestCase):
    def test_code_vectors_and_key_format(self):
        client = load_client()
        key_sha = hashlib.sha256(b"sy1_" + b"A" * 43).hexdigest()
        self.assertEqual(client.enrollment_code(b"leaf-der-vector-1", key_sha, "req1"), "UNAH-E5XA")
        self.assertEqual(client.enrollment_code(b"", "f" * 64, "abc"), "3SHA-BT5V")
        self.assertEqual(client.enrollment_code(b"x", key_sha, "r"), contract_code(b"x", key_sha, "r"))
        bearers = set()
        for _ in range(20):
            bearer, digest = client.new_key()
            self.assertRegex(bearer, r"^sy1_[A-Za-z0-9_-]{43}$")
            self.assertEqual(len(base64.urlsafe_b64decode(bearer[4:] + "=")), 32)
            self.assertEqual(digest, hashlib.sha256(bearer.encode()).hexdigest())
            bearers.add(bearer)
        self.assertEqual(len(bearers), 20)
        for value in ("sha256:" + "AB" * 32, ":".join(["ab"] * 32), "ab" * 32):
            self.assertEqual(client.normalize_fingerprint(value), "sha256:" + "ab" * 32)


@unittest.skipUnless(OPENSSL, "openssl CLI not available")
class EnrollmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certificates = tempfile.TemporaryDirectory()
        cls.chain = make_chain(cls.certificates.name, "real")
        cls.other = make_chain(cls.certificates.name, "intercept")

    @classmethod
    def tearDownClass(cls):
        cls.certificates.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / "config"
        environment = patch.dict(os.environ, {"SWITCHYARD_CONFIG_DIR": str(self.config),
                                              "SWITCHYARD_REMOTE_CONFIG": str(self.root / "remote.json")})
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop("PASEO_AGENT_ID", None)
        self.client = load_client()
        self.client.MIN_POLL_SECONDS = 0
        self.stub = Stub(self.chain)
        self.addCleanup(self.stub.stop)
        self.outputs = []

    def run_client(self, *argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                code = self.client.main(list(argv))
            except SystemExit as error:
                code = error.code
        self.outputs.append(stdout.getvalue() + stderr.getvalue())
        return code, stdout.getvalue(), stderr.getvalue()

    def tearDown(self):
        # No bearer ever appears in output: collect every bearer the stub saw.
        bearers = {headers.get("Authorization", "")[len("Bearer "):] for _, _, headers, _ in self.stub.requests
                   if headers.get("Authorization")}
        for bearer in bearers:
            for output in self.outputs:
                self.assertNotIn(bearer, output)
        for _, _, _, body in self.stub.requests:
            self.assertNotIn("sy1_", json.dumps(body or {}))

    def bearer(self):
        return (self.config / "key").read_text().strip()

    def state(self):
        return json.loads((self.config / "client.json").read_text())

    def enroll(self, *extra):
        return self.run_client("enroll", "--server", self.stub.url, *extra)

    def enroll_approved(self, scope="read", hosts=None):
        extra = ["--scope", scope] + (["--hosts", ",".join(hosts)] if hosts else [])
        code, stdout, _ = self.enroll("--no-wait", *extra)
        self.assertEqual(code, 0)
        request_id = self.state()["request_id"]
        self.stub.decide(request_id, "approved")
        self.assertEqual(self.run_client("enroll", "--status")[0], 0)
        return request_id

    def test_trust_on_first_use_no_wait_status_whoami_api_unenroll_and_file_modes(self):
        (self.root / "remote.json").write_text(json.dumps({"host_id": "host-b"}))
        os.environ["PASEO_AGENT_ID"] = "agent-1234"
        code, stdout, stderr = self.enroll("--no-wait", "--name", "test-client-b")
        self.assertEqual(code, 0, stderr)
        # The first request is the CA download, without any credential; then exactly one enrollment POST.
        self.assertEqual(self.stub.paths(), [("GET", "/api/tls/ca"), ("POST", "/api/enroll")])
        self.assertNotIn("Authorization", self.stub.requests[0][2])
        body = self.stub.requests[1][3]
        self.assertEqual((body["name"], body["host_id"], body["agent_id"], body["scope"]), ("test-client-b", "host-b", "agent-1234", "read"))
        self.assertNotIn("hosts", body)
        self.assertEqual(body["key_sha256"], hashlib.sha256(self.bearer().encode()).hexdigest())
        self.assertIn(self.chain["ca_fingerprint"], stdout)
        self.assertIn("switchyard tls show", stdout)
        request_id = self.state()["request_id"]
        expected = contract_code(self.chain["leaf_der"], body["key_sha256"], request_id)
        lines = stdout.splitlines()
        url_line = next(index for index, line in enumerate(lines) if f"{self.stub.url}/#access/{request_id}" in line)
        code_line = next(index for index, line in enumerate(lines) if line == f"Code: {expected}")
        check_line = next(index for index, line in enumerate(lines) if "same code" in line)
        self.assertLess(url_line, code_line)
        self.assertLess(code_line, check_line)
        self.assertNotIn("WARNING", stderr)
        # Files: directory 0700, everything 0600, no secret outside the key file.
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o700)
        for name in ("key", "ca.pem", "client.json"):
            self.assertEqual(stat.S_IMODE((self.config / name).stat().st_mode), 0o600, name)
        self.assertNotIn("sy1_", (self.config / "client.json").read_text())
        self.assertEqual(self.state()["ca_fingerprint"], self.chain["ca_fingerprint"])
        # Pending, then approved.
        self.assertEqual(self.run_client("enroll", "--status")[0], 3)
        self.stub.decide(request_id, "approved")
        code, stdout, _ = self.run_client("enroll", "--status")
        self.assertEqual(code, 0)
        self.assertIn("scope: read", stdout)
        self.assertEqual(self.state()["status"], "approved")
        code, stdout, _ = self.run_client("whoami")
        self.assertEqual(code, 0)
        self.assertIn("kind: key", stdout)
        self.assertIn(f"key: key-{request_id} (test-client-b)", stdout)
        code, stdout, _ = self.run_client("api", "GET", "/api/hosts")
        self.assertEqual((code, json.loads(stdout)), (0, {"hosts": [{"id": "host-b"}]}))
        self.assertEqual(self.run_client("api", "GET", "/api/forbidden")[0], 77)
        # Every request after the CA download carried the bearer on a verified connection.
        self.assertTrue(all(headers.get("Authorization") for method, path, headers, _ in self.stub.requests[2:]))
        code, stdout, _ = self.run_client("unenroll")
        self.assertEqual(code, 0)
        self.assertEqual(self.stub.paths()[-1], ("POST", "/api/keys/self/revoke"))
        self.assertFalse((self.config / "key").exists())
        self.assertEqual(self.state()["status"], "revoked")
        code, _, stderr = self.run_client("whoami")
        self.assertEqual(code, 1)
        self.assertIn("no key", stderr)

    def test_pinned_fingerprint_and_waiting_until_approved(self):
        def approve(_seconds):
            self.stub.decide(self.state()["request_id"], "approved", scope="lease", hosts=["host-b"])
        with patch.object(self.client, "pause", side_effect=approve):
            code, stdout, stderr = self.enroll("--ca-fingerprint", self.chain["ca_fingerprint"].upper().replace("SHA256:", "sha256:"),
                                               "--scope", "lease", "--hosts", "host-b")
        self.assertEqual(code, 0, stderr)
        self.assertNotIn("first use", stdout)
        self.assertIn("Approved.", stdout)
        self.assertIn("hosts: host-b", stdout)
        self.assertEqual(self.stub.requests[1][3]["hosts"], ["host-b"])

    def test_wrong_fingerprint_refuses_before_sending_anything(self):
        code, _, stderr = self.enroll("--ca-fingerprint", "sha256:" + "0" * 64)
        self.assertEqual(code, 1)
        self.assertIn("refusing (nothing was sent)", stderr)
        self.assertEqual(self.stub.paths(), [("GET", "/api/tls/ca")])
        self.assertFalse((self.config / "key").exists())
        self.assertFalse((self.config / "ca.pem").exists())

    def test_address_missing_from_the_certificate_refuses(self):
        code, _, stderr = self.run_client("enroll", "--server", f"https://localhost:{self.stub.port}", "--no-wait")
        self.assertEqual(code, 1)
        self.assertIn("does not name this address", stderr)
        self.assertIn("nothing was sent", stderr)
        self.assertEqual(self.stub.paths(), [("GET", "/api/tls/ca")])
        self.assertFalse((self.config / "ca.pem").exists())

    def test_a_different_certificate_on_a_later_connection_is_refused(self):
        self.enroll_approved(scope="lease", hosts=["host-b"])
        port = self.stub.port
        self.stub.stop()
        impostor = Stub(self.other, port=port)
        self.addCleanup(impostor.stop)
        for argv in (("whoami",), ("api", "GET", "/api/hosts"), ("http-lease", "list"), ("unenroll",)):
            code, _, stderr = self.run_client(*argv)
            self.assertEqual(code, 1, argv)
            self.assertIn("does not match the stored CA", stderr)
            self.assertIn("nothing was sent", stderr)
        self.assertEqual(impostor.requests, [])
        # A new enrollment to the same server is verified against the stored CA as well (no new TOFU).
        code, _, stderr = self.run_client("enroll", "--server", impostor.url, "--replace", "--no-wait")
        self.assertEqual(code, 1)
        self.assertEqual(impostor.requests, [])

    def test_denial_and_expiry_delete_the_unused_key(self):
        self.enroll("--no-wait")
        self.stub.decide(self.state()["request_id"], "denied")
        code, stdout, _ = self.run_client("enroll", "--status")
        self.assertEqual(code, 1)
        self.assertIn("denied", stdout)
        self.assertFalse((self.config / "key").exists())
        self.assertEqual(self.state()["status"], "denied")
        self.assertTrue((self.config / "ca.pem").exists())  # The pinned CA stays for the next attempt.
        with patch.object(self.client, "pause", side_effect=lambda _: self.stub.decide(self.state()["request_id"], "expired")):
            code, stdout, _ = self.enroll()
        self.assertEqual(code, 1)
        self.assertIn("expired", stdout)
        self.assertFalse((self.config / "key").exists())
        self.assertEqual(self.stub.paths().count(("GET", "/api/tls/ca")), 1)  # Second attempt used the stored CA.

    def test_ctrl_c_leaves_a_resumable_pending_request(self):
        with patch.object(self.client, "pause", side_effect=KeyboardInterrupt):
            code, _, stderr = self.enroll()
        self.assertEqual(code, 130)
        self.assertIn("enroll --status", stderr)
        self.assertEqual(self.state()["status"], "pending")
        self.assertTrue((self.config / "key").exists())
        self.assertEqual([path for path in os.listdir(self.config) if path.startswith(".")], [])
        self.assertEqual(self.run_client("enroll", "--status")[0], 3)
        code, _, stderr = self.enroll("--no-wait")
        self.assertEqual(code, 2)
        self.assertIn("already pending", stderr)

    def test_replace_revokes_the_old_key_first(self):
        old_request = self.enroll_approved()
        old_bearer = self.bearer()
        code, _, stderr = self.enroll("--no-wait")
        self.assertEqual(code, 2)
        self.assertIn("--replace", stderr)
        code, stdout, _ = self.enroll("--no-wait", "--replace")
        self.assertEqual(code, 0)
        self.assertIn(f"Revoked the old key key-{old_request}", stdout)
        revoke = next(request for request in self.stub.requests if request[1] == "/api/keys/self/revoke")
        self.assertEqual(revoke[2]["Authorization"], f"Bearer {old_bearer}")
        self.assertTrue(self.stub.keys[hashlib.sha256(old_bearer.encode()).hexdigest()]["revoked"])
        self.assertNotEqual(self.bearer(), old_bearer)
        self.assertEqual(self.state()["status"], "pending")

    def test_http_lease_exit_codes(self):
        self.enroll_approved(scope="lease", hosts=["host-b"])
        code, stdout, _ = self.run_client("http-lease", "hold", "host-b", "--scope", "flash test", "--ttl", "30")
        self.assertEqual(code, 0)
        lease = json.loads(stdout)
        self.assertEqual(self.stub.requests[-1][3], {"device": "host-b", "scope": "flash test", "ttl_minutes": 30})
        self.assertEqual(self.run_client("http-lease", "renew", lease["lease_id"], "--ttl", "10")[0], 0)
        self.assertEqual(self.run_client("http-lease", "release", lease["lease_id"])[0], 0)
        self.assertEqual(self.run_client("http-lease", "list")[0], 0)
        code, _, stderr = self.run_client("http-lease", "hold", "busy", "--scope", "s")
        self.assertEqual(code, 75)
        self.assertIn("SomeAgent", stderr)
        code, _, stderr = self.run_client("http-lease", "hold", "test-handheld", "--scope", "s")
        self.assertEqual(code, 77)
        self.assertIn("allowed hosts (the server): host-b", stderr)
        self.assertEqual(self.run_client("http-lease", "release", "f" * 32)[0], 1)
        self.assertEqual(self.run_client("http-lease", "renew", "not-a-lease")[0], 2)

    def test_revoked_key_gets_the_enroll_again_message(self):
        self.enroll_approved(scope="lease", hosts=["host-b"])
        for key in self.stub.keys.values():
            key["revoked"] = True
        code, _, stderr = self.run_client("http-lease", "list")
        self.assertEqual(code, 1)
        self.assertIn("the key is expired or revoked; enroll again", stderr)

    def test_read_key_cannot_lease_and_lease_scope_without_hosts(self):
        self.enroll_approved()
        requests = len(self.stub.requests)
        code, _, stderr = self.run_client("http-lease", "hold", "host-b", "--scope", "s")
        self.assertEqual(code, 77)
        self.assertEqual(len(self.stub.requests), requests)
        code, stdout, _ = self.enroll("--replace", "--no-wait", "--scope", "lease")
        self.assertEqual(code, 0)
        self.assertIn("the operator chooses which hosts this key may lease", stdout)
        self.assertNotIn("hosts", self.stub.requests[-1][3])
        code, _, stderr = self.enroll("--replace", "--no-wait", "--scope", "read", "--hosts", "host-b")
        self.assertEqual(code, 2)
        self.assertIn("a read key has no host list", stderr)

    def test_api_refuses_anything_but_get_on_a_server_path(self):
        self.enroll_approved()
        requests = len(self.stub.requests)
        for argv in (("api", "POST", "/api/leases"), ("api", "GET", "https://elsewhere/api/hosts"),
                     ("api", "GET", "//elsewhere/api"), ("api", "GET")):
            self.assertEqual(self.run_client(*argv)[0], 2, argv)
        self.assertEqual(len(self.stub.requests), requests)

    def test_key_file_with_loose_permissions_is_refused(self):
        self.enroll_approved()
        os.chmod(self.config / "key", 0o644)
        code, _, stderr = self.run_client("whoami")
        self.assertEqual(code, 2)
        self.assertIn("mode 0600", stderr)


if __name__ == "__main__":
    unittest.main()
