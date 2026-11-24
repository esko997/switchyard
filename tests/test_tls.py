"""Local CA and server certificate via the openssl CLI, and a real HTTPS listener on loopback; temp state only."""
import http.client
import json
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import unittest

from switchyard import tls
from switchyard.tls import TLSStore, der_sha256

try:
    OPENSSL = tls.find_openssl()
except ValueError:
    OPENSSL = None


@unittest.skipUnless(OPENSSL, "openssl CLI not available")
class TLSStoreTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.store = TLSStore(self.root)

    def openssl(self, *arguments):
        return subprocess.run([OPENSSL, *arguments], capture_output=True, text=True, check=True).stdout

    def test_chain_verifies_with_sans_modes_and_fingerprints(self):
        shown = self.store.init(["192.168.50.68", "Desk.LAN"])
        self.assertTrue(shown["ca_created"])
        self.assertEqual(shown["server"]["names"], ["192.168.50.68", "desk.lan"])
        self.assertIn("OK", self.openssl("verify", "-CAfile", str(self.store.ca_cert), str(self.store.server_cert)))
        text = self.openssl("x509", "-in", str(self.store.server_cert), "-noout", "-text")
        self.assertIn("IP Address:192.168.50.68", text)
        self.assertIn("DNS:desk.lan", text)
        self.assertIn("TLS Web Server Authentication", text)
        self.assertIn("prime256v1", text)
        ca_text = self.openssl("x509", "-in", str(self.store.ca_cert), "-noout", "-text")
        self.assertIn("CA:TRUE", ca_text)
        for path in (self.store.ca_key, self.store.server_key):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.store.directory.stat().st_mode), 0o700)
        self.assertEqual(shown["ca"]["fingerprint_sha256"], der_sha256(self.store.ca_cert.read_text()))
        days = (self.store.not_after() - tls.datetime.now(tls.timezone.utc).timestamp()) / 86400
        self.assertTrue(396 <= days <= 397.1, days)
        self.assertEqual(list(self.store.directory.glob(".issue-*")), [])  # No leftover scratch with key material.

    def test_ca_is_never_replaced_and_renewal_keeps_names(self):
        self.store.init(["192.168.50.1"])
        ca = self.store.ca_cert.read_bytes()
        leaf = self.store.leaf_sha256()
        again = self.store.init(["192.168.50.2"])
        self.assertFalse(again["ca_created"])
        self.assertEqual(self.store.ca_cert.read_bytes(), ca)
        self.assertEqual(self.store.names(), ["192.168.50.2"])  # init issues exactly the names given
        renewed = self.store.renew(["desk.lan"])
        self.assertEqual(renewed["server"]["names"], ["192.168.50.2", "desk.lan"])
        self.assertNotEqual(self.store.leaf_sha256(), leaf)
        self.store.ca_cert.unlink()
        with self.assertRaisesRegex(ValueError, "never replaces"):
            self.store.init()

    def test_fresh_state_root_is_created_private(self):
        # `tls init` can run before any Service exists; the registry refuses a state root that is not 0700.
        from switchyard.auth_store import AuthStore
        for make in (lambda root: TLSStore(root).init(), lambda root: AuthStore(root)):
            root = self.root / f"fresh-{id(make)}" / "switchyard"
            make(root)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)

    def test_listener_start_renews_only_when_needed(self):
        with self.assertRaises(tls.TLSNotInitialized):
            self.store.ensure_server(["127.0.0.1"])
        self.store.init()
        self.assertTrue(self.store.ensure_server(["127.0.0.1"]))   # No certificate yet.
        self.assertFalse(self.store.ensure_server(["127.0.0.1"]))  # Covers the address, years left.
        self.assertTrue(self.store.ensure_server(["127.0.0.2"]))   # New address.
        self.assertEqual(self.store.names(), ["127.0.0.1", "127.0.0.2"])
        expiry = self.store.not_after()
        self.store.clock = lambda: expiry - 29 * 86400            # Fewer than 30 days left.
        self.assertTrue(self.store.ensure_server(["127.0.0.1"]))
        for bad in ("bad name!", "", "a" * 300):
            with self.assertRaises(ValueError):
                self.store.issue([bad])


@unittest.skipUnless(OPENSSL, "openssl CLI not available")
class HTTPSListenerTests(unittest.TestCase):
    def setUp(self):
        from tests.test_interfaces import write_catalog, write_collectors
        from switchyard.web import create_server, enable_https
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.state = Path(temp.name) / "state"
        catalog = write_catalog(temp.name)
        self.server = create_server(catalog, port=0, state_dir=self.state, collectors_path=write_collectors(temp.name))
        TLSStore(self.state).init(["desk.lan"])
        enable_https(self.server, self.state)
        thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        self.addCleanup(lambda: (self.server.shutdown(), thread.join(7), self.server.server_close()))
        self.port = self.server.server_address[1]
        self.context = ssl.create_default_context(cafile=str(self.state / "tls/ca.pem"))

    def get(self, path, context=None, host="127.0.0.1"):
        connection = http.client.HTTPSConnection(host, self.port, timeout=7, context=context or self.context)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            return response.status, response.getheader("Content-Type"), response.read()
        finally:
            connection.close()

    def test_serves_https_verified_against_the_local_ca(self):
        status, content_type, body = self.get("/api/auth/session")
        self.assertEqual(status, 200)
        session = json.loads(body)
        self.assertEqual(session["tls"], {"enabled": True, "ca_fingerprint_sha256": TLSStore(self.state).ca_fingerprint()})
        self.assertTrue(session["login_required"])
        status, content_type, pem = self.get("/api/tls/ca")
        self.assertEqual((status, content_type), (200, "application/x-pem-file"))
        self.assertEqual(pem.decode(), (self.state / "tls/ca.pem").read_text())
        # The certificate was (re)issued for the bound address plus the init names.
        self.assertEqual(TLSStore(self.state).names(), ["127.0.0.1", "desk.lan"])

    def test_untrusted_clients_old_tls_and_plain_http_are_refused(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.get("/api/auth/session", context=ssl.create_default_context())
        self.assertEqual(self.server.tls_context.minimum_version, ssl.TLSVersion.TLSv1_2)
        with socket.create_connection(("127.0.0.1", self.port), timeout=7) as connection:
            connection.sendall(b"GET /api/fleet HTTP/1.0\r\nHost: x\r\n\r\n")
            try:
                reply = connection.recv(4096)
            except ConnectionResetError:
                reply = b""
            self.assertNotIn(b"HTTP/1.0 200", reply)
        # The listener keeps serving after refused handshakes.
        self.assertEqual(self.get("/api/auth/session")[0], 200)


if __name__ == "__main__":
    unittest.main()
