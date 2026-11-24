"""Agents/lock boundaries over loopback HTTP and the official MCP SDK; fixture data only."""

import copy
from html.parser import HTMLParser
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import anyio
from mcp import ClientSession, StdioServerParameters, stdio_client

from tests import test_host_interfaces as host_interfaces
from switchyard.web import MAX_BODY_BYTES, create_server


class AgentsFixture(host_interfaces.RegistryFixture):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.paseo = {
            "configured": False,
            "daemon": {"state": "running", "version": "0.10.3", "listen": "127.0.0.1:6767", "providers": []},
            "agents": [{"id": "agent-1", "name": "TestAgent", "provider": "codex", "status": "running",
                        "cwd": "/fixture/project", "created_at": "8 hours ago"}],
            "cli_candidates": ["/fixture/bin/paseo"],
        }
        self.ledgers = [{
            "device": "FIXTURE", "path": "/fixture/DEVICE_ACCESS_FIXTURE.md", "state": "held", "host_ids": ["source"],
            "holders": [{"pid": 123, "comm": "omp", "cmdline": "omp", "cwd": "/fixture/project",
                         "started_at": "2026-11-22T10:00:00Z", "paseo_agent_id": "agent-1", "paseo_agent_name": "TestAgent"}],
            "last_entries": [{"at": "2026-11-22T11:00:00Z", "event": "RELEASE", "owner": "fixture", "scope": "test"}],
            "anomaly": "held-after-release",
        }]

    def device_locks(self):
        return {"observed_at": "2026-11-22T12:00:00Z", "ledgers": copy.deepcopy(self.ledgers)}

    def agents(self):
        return {"hosts": [{"host_id": "source", "host_name": "Source", "paseo": copy.deepcopy(self.paseo),
                           "freshness": "fresh", "observed_at": "2026-11-22T12:00:00Z"}],
                "locks": copy.deepcopy(self.ledgers)}

    def configure_paseo(self, host_id, *, enabled, listen, cli, expected_revision):
        self.calls.append(("paseo", host_id, enabled, listen, cli, expected_revision))
        if expected_revision != self.revision:
            raise ValueError("Host registry revision changed; review current hosts")
        if host_id != "source":
            raise ValueError("Unknown host")
        if cli is not None and cli not in self.paseo["cli_candidates"]:
            raise ValueError("CLI must be a last observed candidate")
        if listen != "127.0.0.1:6767":
            raise ValueError("Paseo listen must be a loopback address")
        if enabled:
            self.record["collector"]["paseo"] = {"listen": listen, **({"cli": cli} if cli else {})}
        else:
            self.record["collector"].pop("paseo", None)
        self.paseo["configured"] = enabled
        self.revision = "paseo-enabled" if enabled else "paseo-disabled"
        return {"host": copy.deepcopy(self.record), "revision": self.revision}


class AgentsHTTPTests(unittest.TestCase):
    request = host_interfaces.HostHTTPTests.request
    post = host_interfaces.HostHTTPTests.post
    stop_server = host_interfaces.HostHTTPTests.stop_server

    def setUp(self):
        self.fixture = AgentsFixture()
        temp = tempfile.TemporaryDirectory()  # Auth state (operator sessions) stays out of the real state dir.
        self.addCleanup(temp.cleanup)
        with patch("switchyard.web.Service", return_value=self.fixture):
            self.server = create_server("unused-fixture.json", port=0, state_dir=temp.name)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.port = self.server.server_address[1]
        self.origin = f"http://127.0.0.1:{self.port}"

    def payload(self, **changes):
        return {"host_id": "source", "enabled": True, "listen": "127.0.0.1:6767", "cli": "/fixture/bin/paseo",
                "expected_revision": self.fixture.revision, **changes}

    def test_read_routes_are_metadata_only_and_method_restricted(self):
        for path, expected in (("/api/locks", self.fixture.device_locks()), ("/api/agents", self.fixture.agents())):
            with self.subTest(path=path):
                self.assertEqual(self.request("GET", path), (200, expected))
                self.assertEqual(self.post(path, {})[0], 405)
                self.assertEqual(self.request("GET", path + "?refresh=true")[0], 404)
                self.assertEqual(self.request("GET", path, headers={"Origin": "https://outside.example"})[0], 403)
        self.assertEqual(self.fixture.calls, [])

    def test_configure_exact_arguments_http_only_and_disable(self):
        payload = self.payload()
        status, result = self.post("/api/hosts/paseo", payload)
        self.assertEqual(status, 200)
        self.assertEqual(self.fixture.calls, [("paseo", "source", True, payload["listen"], payload["cli"], "revision-1")])
        self.assertEqual(result["host"]["collector"]["paseo"], {"listen": payload["listen"], "cli": payload["cli"]})
        self.assertEqual(self.post("/api/hosts/paseo", self.payload(cli=None))[0], 200)
        self.assertNotIn("cli", self.fixture.record["collector"]["paseo"])
        self.assertEqual(self.post("/api/hosts/paseo", self.payload(enabled=False, cli=None))[0], 200)
        self.assertNotIn("paseo", self.fixture.record["collector"])

    def test_configure_rejects_unknown_missing_keys_and_unbounded_types(self):
        cases = [self.payload(**changes) for changes in (
            {"force": True}, {"enabled": 1}, {"enabled": "true"}, {"enabled": None},
            {"host_id": ""}, {"host_id": 1}, {"host_id": "x" * 129},
            {"expected_revision": ""}, {"expected_revision": True}, {"expected_revision": "x" * 129},
            {"listen": None}, {"listen": ""}, {"listen": "x" * 257},
            {"cli": False}, {"cli": []}, {"cli": ""}, {"cli": "x" * 4097},
        )]
        for key in self.payload():
            incomplete = self.payload()
            del incomplete[key]
            cases.append(incomplete)
        for payload in cases:
            with self.subTest(payload=payload):
                self.assertEqual(self.post("/api/hosts/paseo", payload)[0], 400)
        self.assertEqual(self.fixture.calls, [])
        duplicate = json.dumps(self.payload())[:-1] + ', "enabled": false}'
        self.assertEqual(self.request("POST", "/api/hosts/paseo", duplicate,
                                      {"Content-Type": "application/json", "Origin": self.origin,
                                       **host_interfaces.operator_headers(self.server, self.port)})[0], 400)

    def test_configure_origin_body_and_content_boundaries(self):
        self.assertEqual(self.request("GET", "/api/hosts/paseo")[0], 405)
        self.assertEqual(self.post("/api/hosts/paseo", self.payload(), Origin="https://outside.example")[0], 403)
        self.assertEqual(self.post("/api/hosts/paseo", self.payload(), Origin=f"http://localhost:{self.port}")[0], 403)
        self.assertEqual(self.post("/api/hosts/paseo", self.payload(), **{"Sec-Fetch-Site": "cross-site"})[0], 403)
        self.assertEqual(self.request("POST", "/api/hosts/paseo", b"x" * (MAX_BODY_BYTES + 1),
                                      {"Content-Type": "application/json"})[0], 413)
        self.assertEqual(self.request("POST", "/api/hosts/paseo", json.dumps(self.payload()),
                                      {"Content-Type": "text/plain",
                                       **host_interfaces.operator_headers(self.server, self.port)})[0], 415)
        self.assertEqual(self.fixture.calls, [])

    def test_service_errors_are_visible_without_overwriting_saved_configuration(self):
        original = copy.deepcopy(self.fixture.record)
        for payload, message in ((self.payload(expected_revision="stale"), "revision changed"),
                                 (self.payload(cli="/unobserved/paseo"), "last observed candidate"),
                                 (self.payload(listen="0.0.0.0:6767"), "loopback")):
            with self.subTest(payload=payload):
                status, result = self.post("/api/hosts/paseo", payload)
                self.assertEqual(status, 400)
                self.assertIn(message, result["error"])
                self.assertEqual(self.fixture.record, original)
        with patch.object(self.fixture, "configure_paseo", side_effect=OSError("fixture disk failure")):
            self.assertEqual(self.post("/api/hosts/paseo", self.payload())[0], 503)
        self.assertEqual(self.post("/api/hosts/paseo", self.payload())[0], 200)

    def test_busy_mutation_slots_prevent_configuration_and_are_not_leaked(self):
        acquired = 0
        try:
            for _ in range(2):
                self.assertTrue(self.server.mutation_slots.acquire(blocking=False))
                acquired += 1
            self.assertEqual(self.post("/api/hosts/paseo", self.payload())[0], 503)
            self.assertEqual(self.fixture.calls, [])
            self.assertEqual(self.request("GET", "/api/agents")[0], 200)
        finally:
            for _ in range(acquired):
                self.server.mutation_slots.release()
        self.assertEqual(self.post("/api/hosts/paseo", self.payload(expected_revision="stale"))[0], 400)
        self.assertEqual(self.post("/api/hosts/paseo", self.payload())[0], 200)


class AgentsMCPTests(unittest.IsolatedAsyncioTestCase):
    async def test_official_sdk_exposes_strict_read_only_metadata_tools(self):
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-c", "from tests.test_agents_ui import AgentsFixture; import switchyard.mcp_server as adapter; adapter.Service = AgentsFixture; adapter.create_mcp('unused-fixture.json').run(transport='stdio')"],
            cwd=Path(__file__).resolve().parents[1],
        )
        fixture = AgentsFixture()
        with anyio.fail_after(20):
            async with stdio_client(parameters) as (reader, writer):
                async with ClientSession(reader, writer) as session:
                    await session.initialize()
                    tools = {tool.name: tool for tool in (await session.list_tools()).tools}
                    self.assertNotIn("configure_paseo", tools)
                    for name, expected in (("device_locks", fixture.device_locks()), ("agents", fixture.agents())):
                        with self.subTest(tool=name):
                            tool = tools[name]
                            self.assertTrue(tool.annotations.readOnlyHint)
                            self.assertTrue(tool.annotations.idempotentHint)
                            self.assertFalse(tool.annotations.destructiveHint)
                            self.assertFalse(tool.annotations.openWorldHint)
                            self.assertFalse(tool.inputSchema["additionalProperties"])
                            self.assertEqual(tool.inputSchema["properties"], {})
                            result = await session.call_tool(name, {})
                            self.assertFalse(result.isError)
                            self.assertEqual(result.structuredContent, expected)
                            for args in ({"refresh": True}, {"host_id": "source"}, {"enabled": True}):
                                self.assertTrue((await session.call_tool(name, args)).isError)
                    self.assertTrue((await session.call_tool("configure_paseo", {"host_id": "source"})).isError)


class AgentsMarkupTests(unittest.TestCase):
    def test_agents_tab_editor_and_lock_section_are_accessible(self):
        class Elements(HTMLParser):
            def __init__(self):
                super().__init__()
                self.elements = []

            def handle_starttag(self, tag, attrs):
                self.elements.append((tag, dict(attrs)))

        static = Path(__file__).resolve().parents[1] / "switchyard" / "static"
        parser = Elements()
        parser.feed((static / "index.html").read_text())
        ids = [attrs["id"] for _, attrs in parser.elements if "id" in attrs]
        self.assertEqual(len(ids), len(set(ids)))
        tabs = [attrs["id"] for _, attrs in parser.elements if attrs.get("role") == "tab"]
        self.assertEqual(tabs, ["tab-workloads", "tab-lan-urls", "tab-hosts", "tab-agents", "tab-playbooks", "tab-access", "tab-migration", "tab-receipts"])
        attributes = {attrs["id"]: attrs for _, attrs in parser.elements if "id" in attrs}
        self.assertEqual(attributes["tab-agents"]["aria-controls"], "panel-agents")
        self.assertEqual(attributes["panel-agents"]["aria-labelledby"], "tab-agents")
        self.assertIn("hidden", attributes["panel-agents"])
        self.assertIn("hidden", attributes["paseo-editor"])
        self.assertIn("disabled", attributes["save-paseo"])
        for field in ("agents-list", "device-locks", "paseo-listen", "paseo-cli", "paseo-review", "agents-error", "paseo-error"):
            self.assertIn(field, attributes)
        self.assertEqual(attributes["agents-error"]["role"], "alert")
        self.assertEqual(attributes["paseo-error"]["role"], "alert")


if __name__ == "__main__":
    unittest.main()
