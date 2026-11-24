"""Exercise the gateway marker probe with real sockets, SNI and certificate verification."""
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import ssl
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

from switchyard import deploy_remote
from switchyard.lan_route_config import PROBE_PATH
from switchyard.tls import TLSStore


class GatewayProbeTests(unittest.TestCase):
    def test_requires_pinned_ca_and_exact_marker_on_the_requested_host(self):
        name, ip, marker = "app.example.test", "192.168.50.3", "9" * 64
        with TemporaryDirectory() as root:
            store = TLSStore(Path(root))
            store.init([name])
            pem = (Path(root) / "tls/ca.pem").read_bytes()
            digest = sha256(ssl.PEM_cert_to_DER_cert(pem.decode())).hexdigest()
            received = []

            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_GET(self):
                    received.append((self.path, self.headers["Host"]))
                    if self.path == "/caddy-root.crt" and self.headers["Host"] == ip:
                        content = pem
                    elif self.path == PROBE_PATH and self.headers["Host"] == name:
                        content = marker.encode()
                    else:
                        self.send_error(404)
                        return
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)

            with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as redirect, \
                    ThreadingHTTPServer(("127.0.0.1", 0), Handler) as gateway:
                gateway.socket = store.server_context().wrap_socket(gateway.socket, server_side=True)
                mapping = {80: redirect.server_port, 443: gateway.server_port}
                connect = socket.create_connection

                def connect_fixture(addr, *args, **kwargs):
                    self.assertEqual(addr[0], ip)
                    return connect(("127.0.0.1", mapping[addr[1]]), *args, **kwargs)

                threads = [threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
                           for server in (redirect, gateway)]
                for thread in threads:
                    thread.start()
                owned = {"owner_present": True, "missing": [], "pod": {"id": "caddy"},
                         "unit_state": {"ActiveState": "active"}, "token": {"state": "valid"}}
                data = {"address": ip, "ca_sha256": digest, "probes": {name: marker},
                        "claims": [{"address": ip, "port": port, "protocol": "tcp"} for port in mapping]}
                try:
                    with patch.object(deploy_remote, "verify_owned", return_value=owned), \
                            patch.object(socket, "create_connection", side_effect=connect_fixture):
                        self.assertEqual(deploy_remote.lan_route_probe(data), {"status": "succeeded", "verified": [name]})
                        wrong = deploy_remote.lan_route_probe({**data, "probes": {name: "8" * 64}})
                        self.assertEqual((wrong["status"], wrong["verified"]), ("failed", []))
                        with self.assertRaisesRegex(deploy_remote.Refusal, "fingerprint changed"):
                            deploy_remote.lan_route_probe({**data, "ca_sha256": "0" * 64})
                finally:
                    for server, thread in zip((redirect, gateway), threads, strict=True):
                        server.shutdown()
                        thread.join(timeout=2)
                self.assertEqual(received, [("/caddy-root.crt", ip), (PROBE_PATH, name)] * 2 + [("/caddy-root.crt", ip)])

    def test_dns_waits_for_both_protocols_to_serve_the_change(self):
        address, zone = "192.168.50.3", "example.test"
        added, removed = f"new.{zone}", f"old.{zone}"
        ipv6 = "fd12::3"
        owned = {"owner_present": True, "missing": [], "pod": {"id": "dns"},
                 "unit_state": {"ActiveState": "active"}, "token": {"state": "valid"}}
        traffic = []

        def query(address_arg, port, name, record_type, _timeout, protocol):
            self.assertEqual((address_arg, port), (address, 53))
            prior = (name, protocol, record_type) in traffic
            traffic.append((name, protocol, record_type))
            if name == added or (protocol == "tcp" and record_type == "A" and not prior):
                value = ipv6 if name == added else address
                return {"rcode": "NOERROR", "truncated": False, "authoritative": True,
                        "answers": [{"name": name, "type": record_type, "value": value}]}
            return {"rcode": "NXDOMAIN", "truncated": False, "authoritative": True, "answers": []}

        data = {"zone": zone, "records": {added: ipv6, removed: None},
                "claims": [{"address": address, "port": 53, "protocol": part} for part in ("udp", "tcp")]}
        with patch.object(deploy_remote, "verify_owned", return_value=owned), patch.object(deploy_remote, "dns_query", query):
            self.assertEqual(deploy_remote.lan_dns_probe(data), {"status": "succeeded", "verified": data["records"]})
        self.assertCountEqual(traffic, [(added, "udp", "AAAA"), (added, "tcp", "AAAA"),
                                        (removed, "udp", "A"), (removed, "tcp", "A"), (removed, "tcp", "A"),
                                        (removed, "udp", "AAAA"), (removed, "tcp", "AAAA")])
