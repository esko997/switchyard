"""Host registry boundaries through real HTTP and the official MCP protocol; no hosts contacted."""

import copy
import http.client
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import anyio
from mcp import ClientSession, StdioServerParameters, stdio_client

from switchyard.web import MAX_BODY_BYTES, create_server
from tests.test_interfaces import operator_headers, operator_only


class RegistryFixture:
    """Service fixture shared by the HTTP server and isolated stdio child."""

    def __init__(self, *args, **kwargs):
        self.revision = "revision-1"
        self.record = {
            "id": "source", "name": "Source", "platform": "linux", "architecture": "x86_64",
            "capabilities": ["ssh"], "notes": "", "provenance": "fixture",
            "collector": {"host_id": "source", "transport": "ssh", "target": "user@source.test", "port": 22},
            "host_keys": [], "connection_revision": 1, "verified_revision": None,
            "verification": {"state": "unpinned", "connection_revision": 1, "verified_revision": None, "verified_at": None},
            "pins": [],
        }
        self.calls = []

    def inventory(self):
        return {"devices": [{"id": "source"}], "workloads": []}

    def definition_inventory(self):
        return {"revision": "store-revision", "workloads": []}

    def fleet(self):
        return {"hosts": [{"id": "source", "collection_enabled": True}]}

    def hosts(self):
        return {"revision": self.revision, "hosts": [copy.deepcopy(self.record)]}

    def update_host(self, host_id, changes, *, expected_revision, connection):
        self.calls.append(("update", host_id, changes, expected_revision, connection))
        if expected_revision != self.revision:
            raise ValueError("Host registry revision changed; review current hosts")
        self.record.update(changes)
        self.revision = "revision-2"
        return {"host": copy.deepcopy(self.record), "revision": self.revision}

    def scan_host_key(self, host_id, *, request_id):
        self.calls.append(("scan", host_id, request_id))
        return {"scan_id": "scan-1", "keys": ["ssh-ed25519 fixture"], "fingerprints": ["SHA256:fixture"],
                "expires_at": "2099-01-01T00:00:00+00:00"}

    def pin_host_key(self, host_id, *, scan_id, fingerprints, expected_revision):
        self.calls.append(("pin", host_id, scan_id, fingerprints, expected_revision))
        if expected_revision != self.revision:
            raise ValueError("Host registry revision changed; scan again")
        self.record["pins"] = [{"key": "ssh-ed25519 fixture", "fingerprint": fingerprints[0]}]
        self.revision = "revision-pinned"
        return {"host": copy.deepcopy(self.record), "revision": self.revision}


class HostHTTPTests(unittest.TestCase):
    def setUp(self):
        self.fixture = RegistryFixture()
        temp = tempfile.TemporaryDirectory()  # Auth state (operator sessions) stays out of the real state dir.
        self.addCleanup(temp.cleanup)
        with patch("switchyard.web.Service", return_value=self.fixture):
            self.server = create_server("unused-fixture.json", port=0, state_dir=temp.name)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.port = self.server.server_address[1]
        self.origin = f"http://127.0.0.1:{self.port}"

    def stop_server(self):
        self.server.shutdown()
        self.thread.join(timeout=7)
        self.server.server_close()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def post(self, route, data, **headers):
        # Operator-only routes need an operator session even on loopback (see docs/auth.md).
        session = operator_headers(self.server, self.port) if operator_only(route) else {}
        return self.request("POST", route, json.dumps(data).encode(),
                            {"Content-Type": "application/json", "Origin": self.origin, **session, **headers})

    def update(self, **changes):
        return {"host_id": "source", "changes": {"name": "Edited"},
                "expected_revision": "revision-1", "connection": False, **changes}

    def test_hosts_read_and_exact_mutations(self):
        self.assertEqual(self.request("GET", "/api/hosts"), (200, self.fixture.hosts()))
        self.assertEqual(self.fixture.calls, [])
        status, scan = self.post("/api/hosts/scan-key", {"host_id": "source", "request_id": "scan-request"})
        self.assertEqual(status, 200)
        self.assertEqual(self.fixture.calls[-1], ("scan", "source", "scan-request"))
        status, pinned = self.post("/api/hosts/pin-key", {
            "host_id": "source", "scan_id": scan["scan_id"], "fingerprints": scan["fingerprints"],
            "expected_revision": "revision-1",
        })
        self.assertEqual(status, 200)
        self.assertEqual(pinned["host"]["pins"][0]["fingerprint"], "SHA256:fixture")
        self.assertEqual(self.fixture.calls[-1], ("pin", "source", "scan-1", ["SHA256:fixture"], "revision-1"))
        payload = self.update(expected_revision=pinned["revision"], connection=True,
                              changes={"target": "new@other.test", "port": 2222, "expected_hostname": "other"})
        self.assertEqual(self.post("/api/hosts/update", payload)[0], 200)
        self.assertEqual(self.fixture.calls[-1], ("update", "source", payload["changes"], pinned["revision"], True))

    def test_unknown_keys_strict_types_and_no_allowlist_authority(self):
        cases = [
            ("/api/hosts/update", self.update(force=True)),
            ("/api/hosts/update", self.update(connection=1)),
            ("/api/hosts/update", self.update(connection="true")),
            ("/api/hosts/update", self.update(connection=None)),
            ("/api/hosts/update", self.update(changes={"target": "new@other.test"})),
            ("/api/hosts/update", self.update(connection=True, changes={"port": True})),
            ("/api/hosts/update", self.update(connection=True, changes={"port": 65536})),
            ("/api/hosts/update", self.update(connection=True, changes={"user_units": ["other.service"]})),
            ("/api/hosts/update", self.update(connection=True, changes={"known_hosts": "/tmp/trust"})),
            ("/api/hosts/update", self.update(changes={"capabilities": [1]})),
            ("/api/hosts/update", self.update(changes={"notes": False})),
            ("/api/hosts/update", self.update(changes=[])),
            ("/api/hosts/scan-key", {"host_id": "source", "request_id": "r", "address": "other"}),
            ("/api/hosts/pin-key", {"host_id": "source", "scan_id": "s", "fingerprints": [], "expected_revision": "r"}),
            ("/api/hosts/pin-key", {"host_id": "source", "scan_id": "s", "fingerprints": [True], "expected_revision": "r"}),
            ("/api/hosts/pin-key", {"host_id": "source", "scan_id": "s", "fingerprints": ["f"], "expected_revision": "r", "approved": True}),
        ]
        for route, payload in cases:
            with self.subTest(route=route, payload=payload):
                self.assertEqual(self.post(route, payload)[0], 400)
        self.assertEqual(self.fixture.calls, [])

    def test_origin_body_and_method_boundaries(self):
        routes = {
            "/api/hosts/update": self.update(),
            "/api/hosts/scan-key": {"host_id": "source", "request_id": "r"},
            "/api/hosts/pin-key": {"host_id": "source", "scan_id": "s", "fingerprints": ["f"], "expected_revision": "r"},
        }
        for route, payload in routes.items():
            with self.subTest(route=route):
                self.assertEqual(self.post(route, payload, Origin="https://untrusted.example")[0], 403)
                self.assertEqual(self.request("POST", route, b"x" * (MAX_BODY_BYTES + 1),
                                              {"Content-Type": "application/json"})[0], 413)
                self.assertEqual(self.request("GET", route)[0], 405)
        self.assertEqual(self.post("/api/hosts", {})[0], 405)
        self.assertEqual(self.fixture.calls, [])

    def test_revision_errors_surface_and_capacity_is_released(self):
        status, result = self.post("/api/hosts/update", self.update(expected_revision="stale"))
        self.assertEqual(status, 400)
        self.assertIn("revision changed", result["error"])
        self.assertEqual(self.fixture.record["name"], "Source")
        acquired = []
        try:
            for _ in range(2):
                self.assertTrue(self.server.mutation_slots.acquire(blocking=False))
                acquired.append(True)
            for route, payload in (
                ("/api/hosts/update", self.update()),
                ("/api/hosts/scan-key", {"host_id": "source", "request_id": "r"}),
                ("/api/hosts/pin-key", {"host_id": "source", "scan_id": "s", "fingerprints": ["f"], "expected_revision": "r"}),
            ):
                self.assertEqual(self.post(route, payload)[0], 503)
            self.assertEqual(self.request("GET", "/api/hosts")[0], 200)
            self.assertEqual(len(self.fixture.calls), 1)
        finally:
            for _ in acquired:
                self.server.mutation_slots.release()
        self.assertEqual(self.post("/api/hosts/update", self.update())[0], 200)

    def test_validated_scan_rearms_short_input_deadline(self):
        def slow_scan(host_id, *, request_id):
            time.sleep(0.25)
            return {"scan_id": "slow", "keys": [], "fingerprints": [], "expires_at": "later"}
        with patch("switchyard.web.CONNECTION_TIMEOUT_SECONDS", 0.1), patch(
            "switchyard.web.OPERATION_TIMEOUT_SECONDS", 2
        ), patch.object(self.fixture, "scan_host_key", side_effect=slow_scan):
            self.assertEqual(self.post("/api/hosts/scan-key", {"host_id": "source", "request_id": "slow"})[0], 200)


class HostMCPTests(unittest.IsolatedAsyncioTestCase):
    async def test_official_stdio_hosts_description_and_conflicts(self):
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-c", "from tests.test_host_interfaces import RegistryFixture; import switchyard.mcp_server as adapter; adapter.Service = RegistryFixture; adapter.create_mcp('unused-fixture.json').run(transport='stdio')"],
            cwd=Path(__file__).resolve().parents[1],
        )
        with anyio.fail_after(20):
            async with stdio_client(parameters) as (reader, writer):
                async with ClientSession(reader, writer) as session:
                    await session.initialize()
                    tools = {tool.name: tool for tool in (await session.list_tools()).tools}
                    self.assertTrue(tools["hosts"].annotations.readOnlyHint)
                    update = tools["update_host_description"]
                    self.assertFalse(update.annotations.readOnlyHint)
                    self.assertFalse(update.annotations.openWorldHint)
                    self.assertFalse(update.annotations.destructiveHint)
                    self.assertFalse(update.inputSchema["additionalProperties"])
                    self.assertNotIn("connection", update.inputSchema["properties"])
                    before = await session.call_tool("hosts", {})
                    self.assertFalse(before.isError)
                    revision = before.structuredContent["revision"]
                    base = {"host_id": "source", "changes": {"name": "Edited by MCP"}, "expected_revision": revision}
                    for name, payload in (
                        ("hosts", {"scan": True}),
                        ("update_host_description", {**base, "connection": True}),
                        ("update_host_description", {**base, "changes": {"target": "other@host"}}),
                        ("update_host_description", {**base, "changes": {"port": 2222}}),
                        ("update_host_description", {**base, "changes": {"expected_hostname": "other"}}),
                        ("update_host_description", {**base, "changes": {"host_keys": []}}),
                        ("update_host_description", {**base, "changes": {"notes": False}}),
                        ("update_host_description", {**base, "changes": {"capabilities": [1]}}),
                        ("scan_host_key", {"host_id": "source", "request_id": "r"}),
                        ("pin_host_key", {"host_id": "source"}),
                    ):
                        with self.subTest(name=name, payload=payload):
                            self.assertTrue((await session.call_tool(name, payload)).isError)
                    unchanged = await session.call_tool("hosts", {})
                    self.assertEqual(unchanged.structuredContent, before.structuredContent)
                    saved = await session.call_tool("update_host_description", base)
                    self.assertFalse(saved.isError)
                    self.assertEqual(saved.structuredContent["host"]["name"], "Edited by MCP")
                    stale = await session.call_tool("update_host_description", base)
                    self.assertTrue(stale.isError)
                    self.assertIn("revision changed", " ".join(item.text for item in stale.content if hasattr(item, "text")))
                    after = await session.call_tool("hosts", {})
                    self.assertEqual(after.structuredContent["hosts"][0]["collector"], before.structuredContent["hosts"][0]["collector"])


if __name__ == "__main__":
    unittest.main()
