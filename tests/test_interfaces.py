"""Real loopback HTTP and official SDK stdio tests; no device access."""

import http.client
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import json
import io
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
import time
from unittest.mock import patch

import anyio
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.server.fastmcp.exceptions import ToolError

from switchyard.mcp_server import create_mcp
from switchyard.observations import ObservationCache
from switchyard.web import MAX_BODY_BYTES, MAX_HEADER_BYTES, create_server, match_route


def write_catalog(directory: str) -> Path:
    # Use the complete current definition and recipe, not a parallel legacy schema.
    catalog = json.loads((Path(__file__).resolve().parents[1] / "catalogs/example.json").read_text())
    path = Path(directory) / "catalog.json"
    path.write_text(json.dumps(catalog), encoding="utf-8")
    return path


def write_collectors(directory: str) -> Path:
    path = Path(directory) / "collectors.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "hosts": [{"host_id": "source", "transport": "local",
                   "expected_hostname": "synthetic", "user_units": [], "system_units": ["example.service"]}],
    }), encoding="utf-8")
    return path


def snapshot() -> dict:
    observed_at = datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": 1, "host_id": "source", "collector": "linux-v1",
        "observed_at": observed_at,
        "host": {"hostname": "synthetic", "os": "Linux", "distribution": "Test", "architecture": "x86_64"},
        "cpu": {"model": None, "logical_count": None, "utilization_percent": None, "sample_seconds": None, "load_1m": None},
        "memory": {"total_bytes": None, "available_bytes": None, "swap_total_bytes": None, "swap_free_bytes": None},
        "gpus": [], "storage": {"devices": [], "filesystems": []},
        "workloads": [{
            "id": "observed-example", "host_id": "source", "backend": "systemd",
            "scope": "system", "native_id": "example.service", "name": "Observed example",
            "kind": "service", "lifecycle": "running", "health": "unknown",
            "management": "discovered", "observed_at": observed_at,
            "extensions": {"systemd.v1": {"active_state": "active", "sub_state": "running"}},
        }],
        "coverage": [{"scope": "systemd:system", "status": "complete", "message": "Test unit allowlist"}],
        "warnings": [],
    }


TOOL_NAMES = {
    "inventory", "fleet", "collect_host", "plan_migration", "observe_local", "operation_policy",
    "inspect_workload", "plan_operation", "execute_operation", "shell", "operation_receipts", "operation_receipt",
    "fleet_keys", "inspect_fleet_keys", "plan_fleet_keys", "execute_fleet_keys",
    "definition_inventory", "store_status", "propose_workload_definition", "save_workload_definition", "update_workload_definition",
    "hosts", "update_host_description", "device_locks", "agents",
    "lease_hold", "lease_release", "lease_renew",
    "templates", "template", "deployments", "deployment", "deploy_plan", "deploy_apply", "deploy_action", "deploy_verify",
    "deploy_refresh_plan", "deploy_refresh_apply", "deploy_switch_plan", "deploy_switch_apply", "deploy_upgrade_plan",
    "deploy_pull_start", "deploy_pull_status", "deploy_pulls",
    "undeploy_plan", "undeploy_apply", "ansible_playbooks", "ansible_playbook", "ansible_variables", "ansible_plans",
    "ansible_receipts",
    "registered_applications", "registered_application", "register_application",
    "token_show", "token_gate", "token_verify", "token_issue", "token_revoke",
    "enrollment_requests", "access_keys", "enrollment_approve",
}

def read_fleet_event(response: http.client.HTTPResponse) -> dict:
    event = None
    while True:
        line = response.readline()
        if not line:
            raise AssertionError("Stream closed before a fleet event")
        if line == b"event: fleet\n":
            event = "fleet"
        elif event == "fleet" and line.startswith(b"data: "):
            return json.loads(line[6:])

OPERATOR_PASSWORD = "correct horse battery staple"


def operator_headers(server, port: int) -> dict:
    """Sign in on a loopback test server (fast scrypt parameters); returns Cookie + CSRF headers."""
    if not server.auth.operator_configured():
        server.auth.set_password("operator", OPERATOR_PASSWORD, scrypt_n=2 ** 10)
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=7)
    try:
        connection.request("POST", "/api/auth/login", json.dumps({"username": "operator", "password": OPERATOR_PASSWORD}),
                           {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}"})
        response = connection.getresponse()
        body = json.loads(response.read())
        cookie = response.getheader("Set-Cookie").split(";", 1)[0]
    finally:
        connection.close()
    return {"Cookie": cookie, "X-Switchyard-CSRF": body["csrf_token"]}


def operator_only(path: str) -> bool:
    route, _ = match_route("POST", path)
    return route is not None and route.authority == "operator"


class HTTPInterfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.catalog = write_catalog(self.temp.name)
        self.state_dir = Path(self.temp.name) / "state"
        self.collectors = write_collectors(self.temp.name)
        self.server = create_server(self.catalog, port=0, state_dir=self.state_dir, collectors_path=self.collectors)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.port = self.server.server_address[1]
        self.authority = f"127.0.0.1:{self.port}"
        self.origin = f"http://{self.authority}"

    def stop_server(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=7)
        self.server.server_close()

    def request(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None) -> tuple[int, dict, bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=7)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def raw_request(self, request: bytes) -> tuple[int, bytes]:
        with socket.create_connection(("127.0.0.1", self.port), timeout=7) as connection:
            connection.sendall(request)
            response = http.client.HTTPResponse(connection)
            response.begin()
            return response.status, response.read()

    def post(self, path: str, data: object, **headers: str) -> tuple[int, dict, bytes]:
        # Operator-only routes need an operator session even on loopback; desk routes stay `local`.
        session = operator_headers(self.server, self.port) if operator_only(path) else {}
        return self.request("POST", path, json.dumps(data).encode(),
                            {"Content-Type": "application/json", "Origin": self.origin, **session, **headers})

    def assert_json_error(self, status: int, body: bytes, expected: int) -> None:
        self.assertEqual(status, expected)
        self.assertIsInstance(json.loads(body)["error"], str)

    def test_inventory_and_security_headers(self) -> None:
        status, headers, body = self.request("GET", "/api/inventory")
        inventory = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(inventory["mode"], "proposal-only")
        self.assertEqual([d["id"] for d in inventory["devices"]], ["source", "destination"])
        self.assertTrue(all(d["observed_at"] is None for d in inventory["devices"]))
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["Cross-Origin-Resource-Policy"], "same-origin")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertEqual(headers["Connection"], "close")

    def test_proposal_is_real_deterministic_and_never_executable(self) -> None:
        status, _, body = self.post("/api/plans/migration", {"workload_id": "foobar", "target_id": "destination"})
        proposal = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(proposal["status"], "proposal")
        self.assertIs(proposal["executable"], False)
        self.assertEqual(proposal["source_id"], "source")
        self.assertEqual(proposal["target_id"], "destination")
        self.assertTrue(proposal["blockers"])
        self.assertTrue(proposal["steps"])
        self.assertEqual(body, self.post("/api/plans/migration", {"workload_id": "foobar", "target_id": "destination"})[2])

    def test_explicit_local_observation_does_not_change_inventory(self) -> None:
        before = self.request("GET", "/api/inventory")[2]
        status, _, body = self.post("/api/observations/local", {})
        self.assertEqual(status, 200)
        observation = json.loads(body)
        self.assertEqual(observation["backend"], "local-host")
        self.assertEqual(observation["scope"], "control-plane host only")
        self.assertIn("hostname", observation["facts"])
        self.assertEqual(before, self.request("GET", "/api/inventory")[2])

    def test_fleet_reads_cache_and_only_explicit_host_post_collects(self) -> None:
        with patch("switchyard.core.collect_host", return_value=snapshot()) as collect:
            before = self.request("GET", "/api/inventory")[2]
            status, _, body = self.request("GET", "/api/fleet")
            fleet = json.loads(body)
            self.assertEqual(status, 200)
            self.assertEqual(fleet["mode"], "observe-and-propose")
            self.assertIsNone(fleet["hosts"][0]["observation"]["snapshot"])
            self.assertEqual([item["id"] for item in fleet["workloads"]], ["foobar", "notes-sync"])  # catalogs/example.json
            self.assertEqual(fleet["resources"], [])
            self.assertEqual(fleet["environments"], [])
            self.assertIn("monitoring", fleet)
            self.assertNotIn("candidates", fleet)
            self.assertTrue(fleet["hosts"][0]["collection_enabled"])
            self.assertFalse(fleet["hosts"][1]["collection_enabled"])
            collect.assert_not_called()
            status, _, body = self.post("/api/observations/host", {"host_id": "source"})
            self.assertEqual(status, 200)
            observed = json.loads(body)["hosts"][0]["observation"]
            self.assertEqual(observed["last_attempt"]["status"], "success")
            self.assertEqual(observed["snapshot"]["host"]["hostname"], "synthetic")
            collect.assert_called_once()
            self.assertEqual(json.loads(body)["resources"][0]["id"], "observed-example")
            self.assertEqual(json.loads(body)["workloads"][0]["id"], "foobar")
            self.request("GET", "/")
            self.request("GET", "/api/fleet")
            self.assertEqual(before, self.request("GET", "/api/inventory")[2])
            self.post("/api/observations/host", {"host_id": "source"})
            collect.assert_called_once()  # Cooldown cannot be bypassed through HTTP.
            mcp = create_mcp(self.catalog, state_dir=self.state_dir, collectors_path=self.collectors)
            tools = anyio.run(mcp.call_tool, "fleet", {})
            self.assertEqual(tools[1]["hosts"][0]["observation"]["snapshot"], observed["snapshot"])
            collect.assert_called_once()  # MCP shares the HTTP cache without probing.

    def test_failed_refresh_preserves_last_known_snapshot_and_reports_error(self) -> None:
        clock = [time.time()]
        self.server.service._cache.clock = lambda: clock[0]
        with patch("switchyard.core.collect_host", return_value=snapshot()):
            first = json.loads(self.post("/api/observations/host", {"host_id": "source"})[2])
        clock[0] += 61
        with patch("switchyard.core.collect_host", side_effect=RuntimeError("secret remote stderr")):
            status, _, body = self.post("/api/observations/host", {"host_id": "source"})
        self.assertEqual(status, 200)
        failed = json.loads(body)["hosts"][0]["observation"]
        self.assertEqual(failed["snapshot"], first["hosts"][0]["observation"]["snapshot"])
        self.assertEqual(failed["last_attempt"]["status"], "error")
        self.assertNotIn(b"secret remote stderr", body)
        cached = json.loads(self.request("GET", "/api/fleet")[2])["hosts"][0]["observation"]
        self.assertEqual(cached["last_attempt"], failed["last_attempt"])

    def test_collection_accepts_only_configured_ids_and_exact_fields(self) -> None:
        invalid = [{}, {"host_id": "missing"}, {"host_id": "destination"}, {"host_id": []},
                   {"host_id": ""}, {"host_id": "x" * 129},
                   {"host_id": "source", "force": True}, {"host_id": "source", "command": "no"},
                   {"host_id": "source", "collectors_path": "/tmp/other"},
                   {"host_id": "source", "target": "user@elsewhere"}]
        with patch("switchyard.core.collect_host") as collect, patch(
            "switchyard.web._Handler._allow_observation", side_effect=AssertionError("unvalidated extension")
        ):
            for data in invalid:
                with self.subTest(data=data):
                    status, _, body = self.post("/api/observations/host", data)
                    self.assert_json_error(status, body, 400)
            self.assertEqual(self.post("/api/observations/host", {"host_id": "source"}, Origin="https://evil.example")[0], 403)
            self.assertEqual(self.request("GET", "/api/observations/host")[0], 405)
            self.assertEqual(self.post("/api/fleet", {})[0], 405)
            collect.assert_not_called()

    def test_collection_execution_outlives_input_deadline_and_server_remains_usable(self) -> None:
        def bounded_collection(config: dict) -> dict:
            time.sleep(0.3)
            return snapshot()

        with patch("switchyard.web.CONNECTION_TIMEOUT_SECONDS", 0.1), patch(
            "switchyard.web.OBSERVATION_TIMEOUT_SECONDS", 2
        ), patch("switchyard.core.collect_host", side_effect=bounded_collection):
            self.assertEqual(self.post("/api/observations/host", {"host_id": "source"})[0], 200)
            self.assertEqual(self.request("GET", "/api/fleet")[0], 200)

    def test_incomplete_observation_input_keeps_short_absolute_deadline(self) -> None:
        with patch("switchyard.web.CONNECTION_TIMEOUT_SECONDS", 0.15), patch("switchyard.core.collect_host") as collect:
            with socket.create_connection(("127.0.0.1", self.port), timeout=2) as connection:
                prefix = (f"POST /api/observations/host HTTP/1.1\r\nHost: {self.authority}\r\n"
                          "Content-Type: application/json\r\nContent-Length: 20\r\n\r\n").encode()
                connection.sendall(prefix + b'{"host_id":')
                self.assertEqual(connection.recv(1), b"")
            collect.assert_not_called()
            self.assertEqual(self.request("GET", "/api/fleet")[0], 200)

    def test_cross_origin_requests_denied(self) -> None:
        for origin in ("https://evil.example", "null", f"http://localhost:{self.port}", "http://127.0.0.1:1"):
            with self.subTest(origin=origin):
                status, _, body = self.post("/api/plans/migration", {"workload_id": "foobar", "target_id": "destination"}, Origin=origin)
                self.assert_json_error(status, body, 403)
        status, _, body = self.post("/api/observations/local", {}, **{"Sec-Fetch-Site": "cross-site"})
        self.assert_json_error(status, body, 403)
        status, _, body = self.request("GET", "/api/inventory", headers={"Origin": "https://evil.example"})
        self.assert_json_error(status, body, 403)

    def test_host_is_mandatory_exact_and_unambiguous(self) -> None:
        for host in ("evil.example", "127.0.0.1", f"127.0.0.1:{self.port}.evil.example", f"user@{self.authority}"):
            with self.subTest(host=host):
                status, _, body = self.request("GET", "/api/inventory", headers={"Host": host})
                self.assert_json_error(status, body, 403)
        for headers in (b"", f"Host: {self.authority}\r\nHost: {self.authority}\r\n".encode()):
            status, body = self.raw_request(b"GET /api/inventory HTTP/1.1\r\n" + headers + b"\r\n")
            self.assert_json_error(status, body, 403)

    def test_wrong_methods_and_execution_routes_are_denied(self) -> None:
        for method in ("PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT", "EXECUTE"):
            with self.subTest(method=method):
                status, _, body = self.request(method, "/api/inventory")
                self.assert_json_error(status, body, 405)
        self.assertEqual(self.request("HEAD", "/api/inventory")[0], 405)
        self.assertEqual(self.request("GET", "/api/plans/migration")[0], 405)
        self.assertEqual(self.post("/api/inventory", {})[0], 405)
        self.assertEqual(self.post("/api/execute", {"command": "anything"})[0], 404)

    def test_body_type_length_and_json_boundaries(self) -> None:
        for content_type in ("text/plain", "application/x-www-form-urlencoded", "application/json; charset=latin1"):
            with self.subTest(content_type=content_type):
                status, _, body = self.request("POST", "/api/observations/local", b"{}", {"Content-Type": content_type})
                self.assert_json_error(status, body, 415)
        status, _, body = self.request("POST", "/api/observations/local", b"{}")
        self.assert_json_error(status, body, 415)
        status, _, body = self.request("POST", "/api/observations/local", b"x" * (MAX_BODY_BYTES + 1), {"Content-Type": "application/json"})
        self.assert_json_error(status, body, 413)
        for content in (b"", b"[1]", b"null", b"{", b"{\"a\": NaN}", b"{\"a\": 1, \"a\": 2}", b"\xff", b"[" * 1200):
            with self.subTest(content=content[:30]):
                status, _, body = self.request("POST", "/api/observations/local", content, {"Content-Type": "application/json"})
                self.assert_json_error(status, body, 400)
        status, _, body = self.post("/api/observations/local", {}, **{"Content-Type": "application/json; charset=utf-8"})
        self.assertEqual(status, 200)

    def test_framing_headers_denied_before_reading_body(self) -> None:
        prefix = f"POST /api/observations/local HTTP/1.1\r\nHost: {self.authority}\r\nContent-Type: application/json\r\n".encode()
        cases = [
            (b"", 411),
            (b"Content-Length: -1\r\n", 400),
            (b"Content-Length: 2\r\nContent-Length: 2\r\n", 400),
            (b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n", 400),
            (b"Content-Length: 2\r\nExpect: 100-continue\r\n", 417),
        ]
        for headers, expected in cases:
            with self.subTest(headers=headers):
                status, body = self.raw_request(prefix + headers + b"\r\n")
                self.assert_json_error(status, body, expected)
        status, _, body = self.request("GET", "/api/inventory", b"{}")
        self.assert_json_error(status, body, 400)

    def test_proposals_accept_only_known_ids_and_exact_fields(self) -> None:
        invalid = [
            {}, {"workload_id": "missing", "target_id": "destination"},
            {"workload_id": "observed-example", "target_id": "destination"},
            {"workload_id": "foobar", "target_id": "missing"},
            {"workload_id": ["foobar"], "target_id": "destination"},
            {"workload_id": "foobar", "target_id": "destination", "command": "no"},
            {"workload_id": "foobar", "target_id": "destination", "catalog": "/tmp/other"},
        ]
        for data in invalid:
            with self.subTest(data=data):
                status, _, body = self.post("/api/plans/migration", data)
                self.assert_json_error(status, body, 400)
        self.assertEqual(self.post("/api/observations/local", {"host": "target"})[0], 400)

    def test_operations_unconfigured_never_gain_authority_from_requests(self) -> None:
        with patch("switchyard.core.collect_host") as collect:
            self.assertEqual(json.loads(self.request("GET", "/api/operations")[2]), [])
            for path, payload in (
                ("/api/operations/inspect", {"workload_id": "foobar", "request_id": "inspection"}),
                ("/api/operations/plan", {"action": "deploy", "workload_id": "foobar", "target_id": "source"}),
                ("/api/operations/execute", {"plan_id": "unused", "approved": True, "request_id": "explicit"}),
                ("/api/operations/shell", {"host_id": "source", "script": "printf unrestricted", "request_id": "shell"}),
            ):
                self.assertEqual(self.request("GET", path)[0], 405)
                status, _, body = self.post(path, payload)
                self.assert_json_error(status, body, 400)
            self.assertEqual(self.request("GET", "/api/operations/missing")[0], 404)
            self.request("GET", "/")
            self.request("GET", "/api/fleet")
            collect.assert_not_called()

    def test_operation_posts_require_exact_typed_arguments_and_same_origin(self) -> None:
        cases = [
            ("/api/operations/inspect", {"workload_id": "foobar"}),
            ("/api/operations/inspect", {"workload_id": [], "request_id": "inspection"}),
            ("/api/operations/inspect", {"workload_id": "foobar", "request_id": "inspection", "host_id": "other"}),
            ("/api/operations/plan", {"action": ["deploy"], "workload_id": "foobar"}),
            ("/api/operations/plan", {"action": "deploy", "workload_id": "foobar", "target_id": 1}),
            ("/api/operations/plan", {"action": "deploy", "workload_id": "foobar", "config": "/tmp/other"}),
            ("/api/operations/execute", {"plan_id": "plan", "approved": "true", "request_id": "request"}),
            ("/api/operations/execute", {"plan_id": "plan", "approved": 1, "request_id": "request"}),
            ("/api/operations/execute", {"plan_id": "plan", "approved": True}),
            ("/api/operations/execute", {"plan_id": "plan", "approved": True, "request_id": "request", "force": True}),
        ]
        shell = {"host_id": "source", "script": "printf x", "request_id": "request"}
        cases.extend(("/api/operations/shell", {**shell, **extra}) for extra in (
            {"timeout_seconds": True}, {"timeout_seconds": 0}, {"timeout_seconds": 301},
            {"timeout_seconds": "30"}, {"extra_host_ids": "destination"}, {"extra_host_ids": [1]},
            {"script": "é" * 8193}, {"script": ""}, {"script": []}, {"host_id": []},
            {"ssh_target": "user@other"}, {"operations_path": "/tmp/other"},
        ))
        with patch.object(self.server.service, "plan_operation") as plan, patch.object(
            self.server.service, "execute_operation"
        ) as execute, patch.object(self.server.service, "run_shell") as run:
            for path, payload in cases:
                with self.subTest(path=path, payload=payload):
                    status, _, body = self.post(path, payload)
                    self.assert_json_error(status, body, 400)
            for path in ("/api/operations/inspect", "/api/operations/plan", "/api/operations/execute", "/api/operations/shell"):
                self.assertEqual(self.post(path, shell, Origin="https://evil.example")[0], 403)
            plan.assert_not_called()
            execute.assert_not_called()
            run.assert_not_called()

    def test_structured_operations_are_separate_explicit_plan_and_approved_execution(self) -> None:
        plan = {"id": "exact-plan", "action": "migrate", "workload_id": "foobar", "target_id": "destination",
                "source_id": "source", "steps": ["Stop owned source"], "warnings": ["Downtime"],
                "expires_at": "2099-01-01T00:00:00+00:00", "approval_required": True}
        receipt = {"id": "operation", "kind": "managed", "status": "needs-inspection", "events": []}
        with patch.object(self.server.service, "plan_operation", return_value=plan) as prepare, patch.object(
            self.server.service, "execute_operation", return_value={"receipt": receipt}
        ) as execute:
            response = self.post("/api/operations/plan", {"action": "migrate", "workload_id": "foobar", "target_id": "destination"})
            self.assertEqual(response[0], 200)
            self.assertEqual(json.loads(response[2]), plan)
            prepare.assert_called_once_with("migrate", "foobar", "destination")
            execute.assert_not_called()
            response = self.post("/api/operations/execute", {"plan_id": "exact-plan", "approved": True, "request_id": "one-intent"})
            self.assertEqual(response[0], 200)
            self.assertEqual(json.loads(response[2])["receipt"]["status"], "needs-inspection")
            execute.assert_called_once_with("exact-plan", approved=True, request_id="one-intent")

    def test_shell_forwards_unrestricted_script_and_declared_leases_without_rewriting(self) -> None:
        script = "for word in one two; do printf '%s\\n' \"$word\"; done\n# <script>not HTML</script>\n"
        result = {"receipt": {"id": "shell", "status": "succeeded"}, "stdout": "<script>alert(1)</script>", "stderr": ""}
        with patch.object(self.server.service, "run_shell", return_value=result) as run:
            response = self.post("/api/operations/shell", {
                "host_id": "source", "script": script, "request_id": "unrestricted",
                "timeout_seconds": 90, "extra_host_ids": ["destination"],
            })
            self.assertEqual(response[0], 200)
            self.assertEqual(json.loads(response[2]), result)
            run.assert_called_once_with("source", script, timeout_seconds=90,
                                        request_id="unrestricted", extra_host_ids=["destination"])
        # Six-byte JSON escapes still fit the request envelope at the byte limit.
        script = "\x01" * 16384
        with patch.object(self.server.service, "run_shell", return_value=result) as run:
            self.assertEqual(self.post("/api/operations/shell", {
                "host_id": "source", "script": script, "request_id": "bounded",
            })[0], 200)
            run.assert_called_once_with("source", script, timeout_seconds=30, request_id="bounded", extra_host_ids=[])

    def test_receipt_inspection_is_read_only_and_execution_capacity_leaves_reads_available(self) -> None:
        receipt = {"id": "known", "kind": "shell", "status": "unknown", "events": []}
        with patch.object(self.server.service, "operation_receipts", return_value=[receipt]), patch.object(
            self.server.service, "operation_receipt", return_value=receipt
        ) as inspect, patch.object(self.server.service, "run_shell") as run:
            self.assertEqual(json.loads(self.request("GET", "/api/operations")[2]), [receipt])
            self.assertEqual(json.loads(self.request("GET", "/api/operations/known")[2]), receipt)
            inspect.assert_called_once_with("known")
            self.assertTrue(self.server.mutation_slots.acquire(blocking=False))
            self.assertTrue(self.server.mutation_slots.acquire(blocking=False))
            try:
                self.assertEqual(self.post("/api/operations/shell", {
                    "host_id": "source", "script": "anything", "request_id": "busy",
                })[0], 503)
                self.assertEqual(self.request("GET", "/api/fleet")[0], 200)
                self.assertEqual(self.request("GET", "/api/operations")[0], 200)
                run.assert_not_called()
            finally:
                self.server.mutation_slots.release()
                self.server.mutation_slots.release()

    def test_shell_execution_has_separate_deadline_and_is_not_retried(self) -> None:
        def slow_shell(*args, **kwargs):
            time.sleep(0.3)
            return {"receipt": {"id": "slow", "status": "unknown"}}

        with patch("switchyard.web.CONNECTION_TIMEOUT_SECONDS", 0.1), patch(
            "switchyard.web.OPERATION_TIMEOUT_SECONDS", 2
        ), patch.object(self.server.service, "run_shell", side_effect=slow_shell) as run:
            response = self.post("/api/operations/shell", {"host_id": "source", "script": "sleep 1", "request_id": "slow"})
            self.assertEqual(response[0], 200)
            self.assertEqual(json.loads(response[2])["receipt"]["status"], "unknown")
            run.assert_called_once()

    def open_events(self) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        self.addCleanup(connection.close)
        connection.request("GET", "/api/events", headers={"Origin": self.origin})
        return connection, connection.getresponse()

    def test_stream_initial_cache_and_revision_driven_updates_never_collect(self) -> None:
        revision = ["first"]
        with patch("switchyard.web.SSE_POLL_SECONDS", 0.01), patch(
            "switchyard.web.SSE_HEARTBEAT_SECONDS", 0.05
        ), patch.object(self.server.service, "fleet_revision", side_effect=lambda: revision[0]), patch.object(
            self.server.service, "fleet", wraps=self.server.service.fleet
        ) as cached, patch("switchyard.core.collect_host") as collect:
            connection, response = self.open_events()
            self.assertEqual(response.status, 200)
            self.assertTrue(response.getheader("Content-Type").startswith("text/event-stream"))
            self.assertEqual(read_fleet_event(response)["workloads"][0]["id"], "foobar")
            self.assertEqual(response.readline(), b"\n")
            self.assertEqual(response.readline(), b": cached fleet heartbeat\n")
            self.assertEqual(cached.call_count, 1)
            revision[0] = "second"
            self.assertEqual(read_fleet_event(response)["mode"], "observe-and-propose")
            self.assertEqual(cached.call_count, 2)
            collect.assert_not_called()
            connection.close()

    def test_stream_slots_leave_capacity_for_regular_requests(self) -> None:
        from switchyard.web import MAX_SSE_CONNECTIONS
        streams = []
        for _ in range(MAX_SSE_CONNECTIONS):
            connection, response = self.open_events()
            read_fleet_event(response)
            streams.append(connection)
        self.assertEqual(self.request("GET", "/api/events")[0], 503)
        self.assertEqual(self.request("GET", "/api/fleet")[0], 200)
        for connection in streams:
            connection.close()

    def test_http_capacity_has_no_unbounded_pending_worker_queue(self) -> None:
        from switchyard.web import MAX_HTTP_WORKERS
        for _ in range(MAX_HTTP_WORKERS):
            self.assertTrue(self.server._workers.acquire(blocking=False))
        try:
            self.assertEqual(self.request("GET", "/api/fleet")[0], 503)
        finally:
            for _ in range(MAX_HTTP_WORKERS):
                self.server._workers.release()
        self.assertEqual(self.request("GET", "/api/fleet")[0], 200)

    def test_stream_origin_and_methods_rejected_before_stream_mode(self) -> None:
        with patch("switchyard.web._Handler._allow_stream", side_effect=AssertionError("unsafe stream")):
            for headers in ({"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"},
                            {"Host": "evil.example"}, {"Origin": f"http://localhost:{self.port}"}):
                self.assertEqual(self.request("GET", "/api/events", headers=headers)[0], 403)
            self.assertEqual(self.post("/api/events", {})[0], 405)
        self.assertEqual(self.request("GET", "/api/fleet")[0], 200)

    def test_stream_has_finite_lifetime_and_shutdown_closes_active_stream(self) -> None:
        with patch("switchyard.web.SSE_LIFETIME_SECONDS", 0.15), patch(
            "switchyard.web.SSE_POLL_SECONDS", 0.01
        ):
            connection, response = self.open_events()
            read_fleet_event(response)
            self.assertEqual(response.read(), b"\n")
            connection.close()
        connection, response = self.open_events()
        read_fleet_event(response)
        self.server.shutdown()
        self.assertEqual(response.read(), b"\n")
        connection.close()

    def test_curated_page_discloses_discovery_and_uses_one_cached_event_source(self) -> None:
        page = self.request("GET", "/")[2].decode()
        script = self.request("GET", "/app.js")[2].decode()
        self.assertIn('id="tab-workloads" role="tab" aria-controls="panel-workloads" aria-selected="true"', page)
        self.assertIn('<details id="discovery-section"', page)
        self.assertNotIn("Catalog candidates", page)
        self.assertIn('new EventSource("/api/events")', script)
        self.assertIn('source.addEventListener("fleet"', script)
        self.assertNotIn("fleet.candidates", script)
        self.assertIn('<details id="fleet-keys-panel"', page)
        self.assertIn("Definition only — no restart/deployment permission", page)
        self.assertIn("ssh -F ~/.ssh/switchyard/config", page)
        self.assertNotIn("innerHTML", script)

    def test_enrollment_reads_are_cached_and_key_actions_are_explicit(self) -> None:
        status = {"enabled": False, "allowed_hosts": [], "members": [], "hosts": [], "connections": [], "revision": "r1"}
        with patch.object(self.server.service, "fleet_keys", return_value=status), patch.object(
            self.server.service, "inspect_fleet_keys", return_value={"receipt": {"id": "inspect", "status": "partial"}}
        ) as inspect, patch.object(
            self.server.service, "plan_fleet_keys", return_value={"id": "key-plan", "warnings": ["Offline peer"]}
        ) as plan, patch.object(
            self.server.service, "execute_fleet_keys", return_value={"receipt": {"id": "key-apply", "status": "partial"}}
        ) as execute, patch("switchyard.core.collect_host") as collect:
            self.assertEqual(json.loads(self.request("GET", "/api/fleet-keys")[2]), status)
            self.assertEqual(self.request("GET", "/api/definitions")[0], 200)
            self.request("GET", "/")
            inspect.assert_not_called()
            plan.assert_not_called()
            execute.assert_not_called()
            collect.assert_not_called()
            self.assertEqual(self.post("/api/fleet-keys/inspect", {"host_ids": ["source"], "request_id": "inspect-intent"})[0], 200)
            inspect.assert_called_once_with(["source"], request_id="inspect-intent")
            self.assertEqual(self.post("/api/fleet-keys/plan", {"action": "reconcile", "host_ids": []})[0], 200)
            plan.assert_called_once_with("reconcile", [])
            execute.assert_not_called()
            response = self.post("/api/fleet-keys/execute", {"plan_id": "key-plan", "approved": True, "request_id": "apply-intent"})
            self.assertEqual(json.loads(response[2])["receipt"]["status"], "partial")
            execute.assert_called_once_with("key-plan", approved=True, request_id="apply-intent")

    def test_enrollment_rejects_ambiguous_arguments_and_does_not_retry(self) -> None:
        cases = [
            ("/api/fleet-keys/inspect", {"host_ids": "source", "request_id": "intent"}),
            ("/api/fleet-keys/inspect", {"host_ids": ["source", "source"], "request_id": "intent"}),
            ("/api/fleet-keys/inspect", {"host_ids": [1], "request_id": "intent"}),
            ("/api/fleet-keys/plan", {"action": "enroll", "host_ids": [], "force": True}),
            ("/api/fleet-keys/plan", {"action": ["enroll"], "host_ids": []}),
            ("/api/fleet-keys/execute", {"plan_id": "plan", "approved": "true", "request_id": "intent"}),
            ("/api/fleet-keys/execute", {"plan_id": "plan", "approved": 1, "request_id": "intent"}),
            ("/api/definitions/propose", {"resource_id": "x", "workload_id": "x", "name": "X", "purpose": "Purpose", "adopt": True}),
            ("/api/definitions/propose", {"resource_id": "x", "workload_id": "x", "name": "X", "purpose": "Purpose", "supporting_resource_ids": "x"}),
            ("/api/definitions/save", {"definition": [], "expected_revision": "r"}),
            ("/api/definitions/update", {"definition": {}, "expected_revision": "r"}),
            ("/api/definitions/save", {"definition": {}, "expected_revision": "r", "operations_path": "/tmp/authority"}),
        ]
        with patch.object(self.server.service, "inspect_fleet_keys") as inspect, patch.object(
            self.server.service, "plan_fleet_keys"
        ) as plan, patch.object(self.server.service, "execute_fleet_keys") as execute, patch.object(
            self.server.service, "save_workload_definition"
        ) as save, patch.object(self.server.service, "propose_workload_definition") as propose:
            for route, payload in cases:
                with self.subTest(route=route, payload=payload):
                    self.assert_json_error(*self._status_body(self.post(route, payload)), 400)
                    self.assertEqual(self.request("GET", route)[0], 405)
                    self.assertEqual(self.post(route, payload, Origin="https://evil.example")[0], 403)
            for method in (inspect, plan, execute, save, propose):
                method.assert_not_called()
        with patch.object(self.server.service, "execute_fleet_keys", side_effect=ValueError("conflict")) as execute:
            self.assertEqual(self.post("/api/fleet-keys/execute", {"plan_id": "plan", "approved": True, "request_id": "intent"})[0], 400)
            execute.assert_called_once()

    @staticmethod
    def _status_body(response: tuple) -> tuple:
        return response[0], response[2]

    def test_definition_promotion_and_update_share_canonical_state_and_reject_stale_writes(self) -> None:
        with patch("switchyard.core.collect_host", return_value=snapshot()):
            fleet = json.loads(self.post("/api/observations/host", {"host_id": "source"})[2])
        resource = fleet["resources"][0]
        initial = json.loads(self.request("GET", "/api/definitions")[2])
        before_policy = self.server.service.operation_policy()
        mcp = create_mcp(self.catalog, state_dir=self.state_dir, collectors_path=self.collectors)
        response = self.post("/api/definitions/propose", {
            "resource_id": resource["id"], "workload_id": "observed-service",
            "name": "Useful service", "purpose": "Runs a useful native service", "supporting_resource_ids": [],
        })
        self.assertEqual(response[0], 200, response[2])
        proposal = json.loads(response[2])
        self.assertEqual(proposal["revision"], initial["revision"])
        self.assertEqual(self.request("GET", "/api/definitions")[2], json.dumps(initial).encode())
        saved_response = self.post("/api/definitions/save", {"definition": proposal["definition"], "expected_revision": proposal["revision"]})
        self.assertEqual(saved_response[0], 200, saved_response[2])
        saved = json.loads(saved_response[2])
        self.assertNotEqual(saved["revision"], proposal["revision"])
        # Long-lived consumers see the same canonical catalog without restarting.
        self.assertIn("observed-service", [item["id"] for item in mcp._service.definition_inventory()["workloads"]])
        edited = {**saved["definition"], "name": "<script>Plain text name</script>", "purpose": "Updated description"}
        updated = self.post("/api/definitions/update", {
            "workload_id": "observed-service", "definition": edited, "expected_revision": saved["revision"],
        })
        self.assertEqual(updated[0], 200, updated[2])
        stale = self.post("/api/definitions/update", {
            "workload_id": "observed-service", "definition": saved["definition"], "expected_revision": saved["revision"],
        })
        self.assertEqual(stale[0], 400)
        self.assertTrue(json.loads(stale[2])["error"])
        current = json.loads(self.request("GET", "/api/definitions")[2])
        self.assertEqual(next(item for item in current["workloads"] if item["id"] == "observed-service")["name"], edited["name"])
        self.assertEqual(self.server.service.operation_policy(), before_policy)

    def test_definition_save_preserves_revision_failure_and_releases_request_capacity(self) -> None:
        with patch.object(self.server.service, "save_workload_definition", side_effect=ValueError("Catalog revision changed; review again")) as save:
            response = self.post("/api/definitions/save", {"definition": {}, "expected_revision": "stale"})
            self.assertEqual(response[0], 400)
            self.assertIn("revision changed", json.loads(response[2])["error"])
            save.assert_called_once_with({}, expected_revision="stale")
        acquired = []
        try:
            for _ in range(2):
                self.assertTrue(self.server.mutation_slots.acquire(blocking=False))
                acquired.append(True)
            with patch.object(self.server.service, "inspect_fleet_keys") as inspect:
                self.assertEqual(self.post("/api/fleet-keys/inspect", {"host_ids": ["source"], "request_id": "busy"})[0], 503)
                inspect.assert_not_called()
                self.assertEqual(self.request("GET", "/api/definitions")[0], 200)
        finally:
            for _ in acquired:
                self.server.mutation_slots.release()


    def test_static_allowlist_and_bounded_headers(self) -> None:
        for path in ("/", "/index.html", "/app.js", "/style.css", "/big-shoulders.woff2", "/source-sans-3.woff2"):
            with self.subTest(path=path):
                status, _, body = self.request("GET", path)
                self.assertEqual(status, 200)
                self.assertTrue(body)
        for path in ("/../pyproject.toml", "/%2e%2e/pyproject.toml", "/core.py", "/api/inventory?catalog=/tmp/other"):
            with self.subTest(path=path):
                self.assertEqual(self.request("GET", path)[0], 404)
        request = f"GET /api/inventory HTTP/1.1\r\nHost: {self.authority}\r\nX-Padding: ".encode() + b"x" * MAX_HEADER_BYTES + b"\r\n\r\n"
        status, body = self.raw_request(request)
        self.assert_json_error(status, body, 431)

    def test_non_loopback_listener_rejected(self) -> None:
        for host in ("0.0.0.0", "::", "192.0.2.1", "example.com"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                create_server(self.catalog, host, 0, state_dir=self.state_dir)

    def test_lan_view_binding_rules(self) -> None:
        for host, clients in (("127.0.0.1", "127.0.0.0/8"), ("0.0.0.0", "192.168.50.0/24"), ("8.8.8.8", "8.8.8.0/24"),
                              ("192.168.50.5", "192.168.60.0/24"), ("192.168.50.3", "192.0.0.0/8"), ("192.168.50.5", "example")):
            with self.subTest(host=host, clients=clients), self.assertRaises(ValueError):
                create_server(self.catalog, host, 0, state_dir=self.state_dir, lan_read_only=True, allowed_clients=clients)

    def test_lan_view_is_get_only_and_drops_clients_outside_its_network(self) -> None:
        import ipaddress
        # The LAN listener itself needs a private non-loopback address; its policy is exercised on this server.
        self.assertNotIn("read_only_view", json.loads(self.request("GET", "/api/fleet")[2]))
        self.server.read_only = True
        self.server.allowed_clients = ipaddress.ip_network("127.0.0.0/8")
        status, _, body = self.request("GET", "/api/fleet")
        self.assertEqual(status, 200)
        self.assertIs(json.loads(body)["read_only_view"], True)
        status, _, body = self.post("/api/observations/host", {"host_id": "alpha"})
        self.assertEqual(status, 403)
        self.assertIn("Read-only LAN view", json.loads(body)["error"])
        self.server.allowed_clients = ipaddress.ip_network("192.168.50.0/24")
        with self.assertRaises((ConnectionError, http.client.RemoteDisconnected, OSError)):
            self.request("GET", "/api/fleet")

class FakeLeases:
    """Stands in for Service.agent_leases(): records calls, never starts a systemd holder."""

    def __init__(self):
        self.calls, self.busy = [], False

    def list(self):
        return {"ledgers": []}

    def hold(self, device, **kwargs):
        self.calls.append(("hold", device, kwargs))
        if self.busy:
            from switchyard.leases import LeaseBusy
            raise LeaseBusy("SOURCE is held by someone else (scope: fixture)")
        return {"lease_id": f"{len(self.calls):032x}", "device": device.upper(), "expires_at": "later",
                "holder_unit": "unit", "env": {}}

    def renew(self, lease_id, *, ttl):
        self.calls.append(("renew", lease_id, ttl))
        return {"lease_id": lease_id, "device": "SOURCE", "expires_at": "renewed", "holder_unit": "unit"}

    def release(self, lease_id):
        self.calls.append(("release", lease_id))
        return {"lease_id": lease_id, "device": "SOURCE", "status": "released", "reason": "released"}


class AccessHTTPTests(unittest.TestCase):
    """Login, CSRF, identities against every authority level, enrollment and keys, on loopback and HTTPS."""

    def setUp(self) -> None:
        from switchyard import tls
        try:
            tls.find_openssl()
        except ValueError:
            self.skipTest("openssl CLI not available")
        from switchyard.web import enable_https
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.catalog = write_catalog(self.temp.name)
        self.state_dir = Path(self.temp.name) / "state"
        collectors = write_collectors(self.temp.name)
        self.local = create_server(self.catalog, port=0, state_dir=self.state_dir, collectors_path=collectors)
        self.lan = create_server(self.catalog, port=0, state_dir=self.state_dir, collectors_path=collectors)
        tls.TLSStore(self.state_dir).init()
        enable_https(self.lan, self.state_dir)  # The LAN listener's policy, served on loopback for the test.
        for server in (self.local, self.lan):
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            thread.start()
            self.addCleanup(lambda server=server, thread=thread: (server.shutdown(), thread.join(7), server.server_close()))
        self.local_port, self.lan_port = self.local.server_address[1], self.lan.server_address[1]
        self.leases = FakeLeases()
        patcher = patch.object(self.lan.service, "agent_leases", return_value=self.leases)
        patcher.start()
        self.addCleanup(patcher.stop)

    # ---- transport helpers ----

    def call(self, method, path, data=None, headers=None, *, secure=False, raw=None):
        import ssl
        port = self.lan_port if secure else self.local_port
        if secure:
            context = ssl.create_default_context(cafile=str(self.state_dir / "tls/ca.pem"))
            connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=7, context=context)
        else:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=7)
        body = raw if raw is not None else (None if data is None else json.dumps(data).encode())
        base = {"Content-Type": "application/json"} if body is not None else {}
        try:
            connection.request(method, path, body=body, headers={**base, **(headers or {})})
            self.peer_der = connection.sock.getpeercert(binary_form=True) if secure else None
            response = connection.getresponse()
            content = response.read()
            value = json.loads(content) if content and response.getheader("Content-Type", "").startswith("application/json") else content
            return response.status, dict(response.getheaders()), value
        finally:
            connection.close()

    def operator(self, *, secure=False):
        if not self.local.auth.operator_configured():
            self.local.auth.set_password("operator", OPERATOR_PASSWORD, scrypt_n=2 ** 10)
        status, headers, body = self.call("POST", "/api/auth/login", {"username": "operator", "password": OPERATOR_PASSWORD},
                                          secure=secure)
        self.assertEqual(status, 200, body)
        return {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "X-Switchyard-CSRF": body["csrf_token"]}

    def new_bearer(self):
        import base64
        import os
        return "sy1_" + base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")

    def request_access(self, scope="read", hosts=None, bearer=None):
        import hashlib
        bearer = bearer or self.new_bearer()
        body = {"name": "host-b agent", "user": "operator", "host_id": "source", "agent_id": "agent-1",
                "scope": scope, "key_sha256": hashlib.sha256(bearer.encode()).hexdigest(), "client": "test"}
        if hosts is not None:
            body["hosts"] = hosts
        status, _, result = self.call("POST", "/api/enroll", body, secure=True)
        self.assertEqual(status, 201, result)
        return bearer, result

    def key(self, scope="read", hosts=None, **grant):
        bearer, request = self.request_access(scope, hosts)
        status, _, key = self.call("POST", f"/api/enrollments/{request['id']}/approve", grant, self.operator())
        self.assertEqual(status, 200, key)
        return bearer, key

    @staticmethod
    def bearer(token):
        return {"Authorization": f"Bearer {token}"}

    # ---- tests ----

    def test_every_route_has_one_table_entry_and_every_handler_is_routed(self) -> None:
        from switchyard.web import AUTHORITIES, ROUTES, _Handler
        handlers = {name for name in dir(_Handler) if name.startswith(("_r_", "_hosts_"))}
        routed = {route.handler for route in ROUTES} | {route.hosts for route in ROUTES if route.hosts}
        self.assertEqual(handlers, routed, "a handler exists without a route table entry (or vice versa)")
        self.assertTrue(all(route.authority in AUTHORITIES for route in ROUTES))
        self.assertTrue(all(route.hosts is None or route.authority == "operate" for route in ROUTES))
        self.assertEqual(len({(route.method, route.path) for route in ROUTES}), len(ROUTES))
        self.assertEqual(match_route("GET", "/api/nothing"), (None, 404))
        self.assertEqual(match_route("GET", "/api/operations/plan"), (None, 405))
        self.assertEqual(match_route("POST", "/api/keys/self/revoke")[0].authority, "self")

    def test_lan_url_mutations_require_an_operator_session_and_csrf(self) -> None:
        body = {"action": "delete", "current_hostname": "test.example", "expected_revision": 1}
        self.assertFalse(self.call("GET", "/api/lan-urls")[2]["configured"])
        self.assertEqual(self.call("GET", "/api/lan-urls", secure=True)[0], 401)
        self.assertEqual(self.call("POST", "/api/lan-urls/plan", body)[0], 403)
        token, _ = self.key("operate", hosts=["source"])
        self.assertEqual(self.call("POST", "/api/lan-urls/plan", body, self.bearer(token), secure=True)[0], 403)
        operator = self.operator(secure=True)
        self.assertEqual(self.call("POST", "/api/lan-urls/plan", body, {"Cookie": operator["Cookie"]}, secure=True)[0], 403)
        self.assertEqual(self.call("POST", "/api/lan-urls/plan", body, operator, secure=True)[0], 404)
        self.assertEqual(self.call("POST", "/api/lan-urls/apply", {
            "plan_id": "plan-a", "request_id": "request-a", "approved": False,
        }, operator, secure=True)[0], 400)

    def test_lan_listener_requires_authentication_except_public_routes(self) -> None:
        for path in ("/api/fleet", "/api/inventory", "/api/operations", "/api/enrollments", "/api/keys", "/api/leases"):
            with self.subTest(path=path):
                status, headers, _ = self.call("GET", path, secure=True)
                self.assertEqual(status, 401)
                self.assertIn("Bearer", headers["WWW-Authenticate"])
        self.assertEqual(self.call("GET", "/", secure=True)[0], 200)
        self.assertEqual(self.call("GET", "/app.js", secure=True)[0], 200)
        status, _, session = self.call("GET", "/api/auth/session", secure=True)
        self.assertEqual((status, session["authenticated"], session["login_required"], session["kind"]), (200, False, True, None))
        self.assertFalse(session["operator_configured"])
        status, headers, pem = self.call("GET", "/api/tls/ca", secure=True)
        self.assertEqual((status, headers["Content-Type"]), (200, "application/x-pem-file"))
        from switchyard.tls import der_sha256
        self.assertEqual(der_sha256(pem.decode()), session["tls"]["ca_fingerprint_sha256"])
        # The HTTPS listener expects https origins.
        self.assertEqual(self.call("GET", "/api/auth/session", headers={"Origin": f"http://127.0.0.1:{self.lan_port}"},
                                   secure=True)[0], 403)
        self.assertEqual(self.call("GET", "/api/auth/session", headers={"Origin": f"https://127.0.0.1:{self.lan_port}"},
                                   secure=True)[0], 200)

    def test_login_cookie_csrf_rotation_and_logout(self) -> None:
        self.local.auth.set_password("operator", OPERATOR_PASSWORD, scrypt_n=2 ** 10)
        wrong = self.call("POST", "/api/auth/login", {"username": "operator", "password": "x" * 12}, secure=True)
        unknown = self.call("POST", "/api/auth/login", {"username": "nobody", "password": OPERATOR_PASSWORD}, secure=True)
        self.assertEqual((wrong[0], unknown[0]), (401, 401))
        self.assertEqual(wrong[2], unknown[2])  # One generic message.
        status, headers, body = self.call("POST", "/api/auth/login", {"username": "operator", "password": OPERATOR_PASSWORD},
                                          secure=True)
        self.assertEqual(status, 200)
        cookie = headers["Set-Cookie"]
        self.assertTrue(cookie.startswith("__Host-switchyard-session="))
        for attribute in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(attribute, cookie)
        self.assertNotIn(OPERATOR_PASSWORD, json.dumps(body))
        session = {"Cookie": cookie.split(";", 1)[0]}
        status, _, view = self.call("GET", "/api/auth/session", headers=session, secure=True)
        self.assertEqual((view["kind"], view["username"], view["csrf_token"]), ("operator", "operator", body["csrf_token"]))
        self.assertEqual(self.call("GET", "/api/fleet", headers=session, secure=True)[0], 200)
        # State changes need the CSRF token; a key plus a cookie is refused.
        self.assertEqual(self.call("POST", "/api/keys/0123456789abcdef/revoke", {}, session, secure=True)[0], 403)
        self.assertEqual(self.call("POST", "/api/keys/0123456789abcdef/revoke", {},
                                   {**session, "X-Switchyard-CSRF": "wrong"}, secure=True)[0], 403)
        self.assertEqual(self.call("POST", "/api/keys/0123456789abcdef/revoke", {},
                                   {**session, "X-Switchyard-CSRF": body["csrf_token"]}, secure=True)[0], 404)
        self.assertEqual(self.call("GET", "/api/fleet", headers={**session, **self.bearer(self.new_bearer())}, secure=True)[0], 400)
        # Logging in again rotates: the old token stops working.
        status, headers, _ = self.call("POST", "/api/auth/login", {"username": "operator", "password": OPERATOR_PASSWORD},
                                       session, secure=True)
        self.assertEqual(self.call("GET", "/api/fleet", headers=session, secure=True)[0], 401)
        rotated = {"Cookie": headers["Set-Cookie"].split(";", 1)[0]}
        csrf = self.call("GET", "/api/auth/session", headers=rotated, secure=True)[2]["csrf_token"]
        status, headers, _ = self.call("POST", "/api/auth/logout", raw=b"", headers={**rotated, "X-Switchyard-CSRF": csrf,
                                                                                      "Content-Length": "0"}, secure=True)
        self.assertEqual(status, 204)
        self.assertIn("Max-Age=0", headers["Set-Cookie"])
        self.assertEqual(self.call("GET", "/api/fleet", headers=rotated, secure=True)[0], 401)
        # A session is bound to its listener; loopback uses a non-__Host- cookie without Secure.
        status, headers, _ = self.call("POST", "/api/auth/login", {"username": "operator", "password": OPERATOR_PASSWORD})
        self.assertTrue(headers["Set-Cookie"].startswith("switchyard-session="))
        self.assertNotIn("Secure", headers["Set-Cookie"])

    def test_login_throttle_per_address(self) -> None:
        self.local.auth.set_password("operator", OPERATOR_PASSWORD, scrypt_n=2 ** 10)
        for _ in range(5):
            self.assertEqual(self.call("POST", "/api/auth/login", {"username": "operator", "password": "wrong password"})[0], 401)
        status, headers, _ = self.call("POST", "/api/auth/login", {"username": "operator", "password": OPERATOR_PASSWORD})
        self.assertEqual(status, 429)
        self.assertLessEqual(int(headers["Retry-After"]), 900)
        audit = self.local.auth.store.audit_tail(10)
        self.assertNotIn(OPERATOR_PASSWORD, json.dumps(audit))
        self.assertEqual(audit[0]["outcome"], "throttled")

    def test_local_identity_keeps_the_desk_but_not_operator_actions(self) -> None:
        self.assertEqual(self.call("GET", "/api/fleet")[0], 200)
        session = self.call("GET", "/api/auth/session")[2]
        self.assertEqual((session["kind"], session["login_required"], session["authenticated"]), ("local", False, False))
        self.assertEqual(self.call("GET", "/api/enrollments")[0], 200)
        self.assertEqual(self.call("GET", "/api/keys")[0], 200)
        self.assertEqual(self.call("POST", "/api/observations/local", {})[0], 200)  # desk
        for path, data in (("/api/hosts/update", {}), ("/api/definitions/save", {}), ("/api/fleet-keys/plan", {}),
                           ("/api/enrollments/" + "0" * 32 + "/deny", {}), ("/api/keys/0123456789abcdef/revoke", {})):
            with self.subTest(path=path):
                status, _, body = self.call("POST", path, data)
                self.assertEqual(status, 403)
                self.assertIn("operator", body["error"])
        self.assertEqual(self.call("GET", "/api/leases")[0], 403)
        self.assertEqual(self.call("POST", "/api/enroll", {"name": "x"})[0], 404)  # HTTPS listener only.

    def test_enrollment_code_poll_proof_and_approval(self) -> None:
        import hashlib
        from switchyard.auth import enrollment_code
        bearer, request = self.request_access("operate", ["source"])
        leaf = hashlib.sha256(self.peer_der).hexdigest()
        self.assertEqual(request["code"], enrollment_code(leaf, hashlib.sha256(bearer.encode()).hexdigest(), request["id"]))
        self.assertEqual(request["approve_url"], f"https://127.0.0.1:{self.lan_port}/#access/{request['id']}")
        self.assertEqual(request["poll_after_seconds"], 3)
        poll = f"/api/enroll/{request['id']}"
        self.assertEqual(self.call("GET", poll, headers=self.bearer(self.new_bearer()), secure=True)[0], 404)
        self.assertEqual(self.call("GET", poll, secure=True)[0], 404)
        self.assertEqual(self.call("GET", poll, headers=self.bearer(bearer), secure=True)[2], {"status": "pending"})
        pending = self.call("GET", "/api/enrollments")[2]["pending"]
        self.assertEqual([(item["id"], item["code"], item["source_address"], item["requested_scope"]) for item in pending],
                         [(request["id"], request["code"], "127.0.0.1", "operate")])
        self.assertNotIn("key_sha256", json.dumps(pending))
        approve = f"/api/enrollments/{request['id']}/approve"
        # `local` may approve read only; lease/operate need the operator.
        self.assertEqual(self.call("POST", approve, {})[0], 403)
        self.assertEqual(self.call("POST", approve, {"scope": "lease"})[0], 403)
        operator = self.operator()
        self.assertEqual(self.call("POST", approve, {"scope": "operate", "hosts": []}, operator)[0], 400)
        self.assertEqual(self.call("POST", approve, {"scope": "operate", "hosts": ["elsewhere"]}, operator)[0], 400)
        self.assertEqual(self.call("POST", approve, {"expires_in_days": 366}, operator)[0], 400)
        status, _, key = self.call("POST", approve, {"scope": "lease", "hosts": ["source"], "expires_in_days": 7,
                                                     "label": "pop agent"}, operator)
        self.assertEqual(status, 200, key)
        self.assertEqual((key["scope"], key["hosts"], key["label"], key["user"], key["agent_id"]),
                         ("lease", ["source"], "pop agent", "operator", "agent-1"))
        self.assertEqual(self.call("POST", approve, {}, operator)[0], 409)
        status, _, result = self.call("GET", poll, headers=self.bearer(bearer), secure=True)
        self.assertEqual((result["status"], result["key"]["id"], result["key"]["scope"]), ("approved", key["id"], "lease"))
        status, _, session = self.call("GET", "/api/auth/session", headers=self.bearer(bearer), secure=True)
        self.assertEqual((session["kind"], session["key"]["hosts"]), ("key", ["source"]))

    def test_scope_never_widens_and_read_keys_have_no_hosts(self) -> None:
        bearer, request = self.request_access("read")
        approve = f"/api/enrollments/{request['id']}/approve"
        self.assertEqual(self.call("POST", approve, {"scope": "lease", "hosts": ["source"]}, self.operator())[0], 400)
        self.assertEqual(self.call("POST", approve, {"hosts": ["source"]})[0], 400)
        status, _, key = self.call("POST", approve, {})  # `local` approves read.
        self.assertEqual((status, key["scope"], key["hosts"]), (200, "read", []))
        # Lease request without hosts is accepted; the approver must choose them.
        _, request = self.request_access("lease")
        approve = f"/api/enrollments/{request['id']}/approve"
        self.assertEqual(self.call("POST", approve, {}, self.operator())[0], 400)
        self.assertEqual(self.call("POST", approve, {"hosts": ["destination"]}, self.operator())[2]["hosts"], ["destination"])
        self.assertEqual(self.call("POST", "/api/enroll", {"name": "x", "user": "u", "scope": "read",
                                                          "key_sha256": "0" * 64, "hosts": ["source"]}, secure=True)[0], 400)

    def test_enrollment_caps_body_bound_and_expiry(self) -> None:
        self.assertEqual(self.call("POST", "/api/enroll", raw=b"{" + b" " * 4096 + b"}", secure=True)[0], 413)
        import hashlib
        requests = [self.request_access()]
        # Reusing a submitted key is refused.
        reused = {"name": "x", "user": "u", "scope": "read", "key_sha256": hashlib.sha256(requests[0][0].encode()).hexdigest()}
        self.assertEqual(self.call("POST", "/api/enroll", reused, secure=True)[0], 400)
        requests += [self.request_access() for _ in range(15)]
        overflow = {"name": "x", "user": "u", "scope": "read",
                    "key_sha256": hashlib.sha256(self.new_bearer().encode()).hexdigest()}
        self.assertEqual(self.call("POST", "/api/enroll", overflow, secure=True)[0], 429)
        later = time.time() + 15 * 60 + 1
        self.lan.auth.store.clock = self.lan.auth.clock = self.local.auth.store.clock = self.local.auth.clock = lambda: later
        bearer, request = requests[0]
        self.assertEqual(self.call("GET", f"/api/enroll/{request['id']}", headers=self.bearer(bearer), secure=True)[2],
                         {"status": "expired"})
        self.assertEqual(self.call("POST", f"/api/enrollments/{request['id']}/approve", {})[0], 409)
        self.assertEqual(self.call("GET", "/api/enrollments")[2]["pending"], [])
        self.assertEqual(self.call("POST", "/api/enroll", overflow, secure=True)[0], 201)

    def test_read_key_reads_with_redaction_and_nothing_else(self) -> None:
        bearer, key = self.key("read")
        receipt = {"id": "op1", "kind": "shell", "status": "succeeded", "script_preview": "rm -rf /tmp/x"}
        with patch.object(self.lan.service, "operation_receipts", return_value=[receipt]), \
                patch.object(self.lan.service, "operation_receipt", return_value={**receipt, "script": "secret"}):
            listed = self.call("GET", "/api/operations", headers=self.bearer(bearer), secure=True)[2]
            single = self.call("GET", "/api/operations/op1", headers=self.bearer(bearer), secure=True)[2]
            operator = self.operator(secure=True)
            unredacted = self.call("GET", "/api/operations", headers=operator, secure=True)[2]
        self.assertEqual(listed, [{"id": "op1", "kind": "shell", "status": "succeeded", "script_redacted": True}])
        self.assertNotIn("script", single)
        self.assertEqual(unredacted[0]["script_preview"], "rm -rf /tmp/x")
        for path in ("/api/fleet", "/api/hosts", "/api/locks", "/api/definitions"):
            self.assertEqual(self.call("GET", path, headers=self.bearer(bearer), secure=True)[0], 200)
        for method, path, data in (("GET", "/api/leases", None), ("GET", "/api/keys", None), ("GET", "/api/enrollments", None),
                                   ("POST", "/api/leases", {"device": "source", "scope": "x"}),
                                   ("POST", "/api/observations/host", {"host_id": "source"}),
                                   ("POST", "/api/observations/local", {}), ("POST", "/api/hosts/update", {}),
                                   ("POST", f"/api/enrollments/{'0' * 32}/approve", {})):
            with self.subTest(path=path):
                self.assertEqual(self.call(method, path, data, self.bearer(bearer), secure=True)[0], 403)
        self.assertEqual(self.leases.calls, [])

    def test_operate_key_only_on_its_hosts_and_never_desk_routes(self) -> None:
        bearer, key = self.key("operate", ["source"])
        shell = {"host_id": "source", "script": "true", "request_id": "r1"}
        with patch.object(self.lan.service, "run_shell", return_value={"receipt": {"status": "succeeded"}}) as run:
            outside = self.call("POST", "/api/operations/shell", {**shell, "extra_host_ids": ["destination"]},
                                self.bearer(bearer), secure=True)
            self.assertEqual(outside[0], 403)
            self.assertIn("destination", outside[2]["error"])
            run.assert_not_called()
            self.assertEqual(self.call("POST", "/api/operations/shell", shell, self.bearer(bearer), secure=True)[0], 200)
            run.assert_called_once()
        self.assertEqual(self.call("POST", "/api/observations/host", {"host_id": "destination"}, self.bearer(bearer),
                                   secure=True)[0], 403)
        for path in ("/api/operations/execute", "/api/operations/plan", "/api/plans/migration"):
            self.assertEqual(self.call("POST", path, {}, self.bearer(bearer), secure=True)[0], 403)

    def test_lease_keys_lease_only_their_hosts_and_only_their_leases(self) -> None:
        bearer, key = self.key("lease", ["source"])
        other, _ = self.key("lease", ["destination"])
        # Amendment 1: outside the key's hosts is 403 before any lock is attempted.
        status, _, body = self.call("POST", "/api/leases", {"device": "destination", "scope": "work"}, self.bearer(bearer), secure=True)
        self.assertEqual(status, 403)
        self.assertEqual(self.call("POST", "/api/leases", {"device": "nowhere", "scope": "work"}, self.bearer(bearer), secure=True)[0], 403)
        self.assertEqual(self.leases.calls, [])
        status, _, lease = self.call("POST", "/api/leases", {"device": "source", "scope": "deploy test", "ttl_minutes": 30},
                                     self.bearer(bearer), secure=True)
        self.assertEqual(status, 200, lease)
        _, device, kwargs = self.leases.calls[0]
        self.assertEqual((device, kwargs["ttl"], kwargs["detached"], kwargs["origin_host"], kwargs["agent_id"]),
                         ("source", 1800, True, "source", "agent-1"))
        self.assertIn(key["id"][:8], kwargs["owner"])
        self.assertIn("operator", kwargs["owner"])
        self.assertEqual(set(lease), {"lease_id", "device", "expires_at"})
        renew, release = f"/api/leases/{lease['lease_id']}/renew", f"/api/leases/{lease['lease_id']}/release"
        self.assertEqual(self.call("POST", renew, {}, self.bearer(other), secure=True)[0], 403)
        self.assertEqual(self.call("POST", release, {}, self.bearer(other), secure=True)[0], 403)
        self.assertEqual(self.call("POST", renew, {"ttl_minutes": 121}, self.bearer(bearer), secure=True)[0], 400)
        self.assertEqual(self.call("POST", renew, {"ttl_minutes": 10}, self.bearer(bearer), secure=True)[0], 200)
        self.assertEqual(self.call("POST", release, {}, self.bearer(bearer), secure=True)[0], 200)
        self.assertEqual([call[0] for call in self.leases.calls], ["hold", "renew", "release"])
        self.leases.busy = True
        status, _, body = self.call("POST", "/api/leases", {"device": "source", "scope": "x"}, self.bearer(bearer), secure=True)
        self.assertEqual(status, 409)
        self.assertIn("held by", body["error"])
        self.assertEqual(self.call("POST", "/api/operations/shell", {"host_id": "source", "script": "true", "request_id": "r"},
                                   self.bearer(bearer), secure=True)[0], 403)

    def test_key_revocation_expiry_and_last_used(self) -> None:
        bearer, key = self.key("read")
        self.assertEqual(self.call("GET", "/api/fleet", headers=self.bearer(bearer), secure=True)[0], 200)
        listed = {item["id"]: item for item in self.call("GET", "/api/keys")[2]}
        first_use = listed[key["id"]]["last_used_at"]
        self.assertEqual(listed[key["id"]]["last_used_from"], "127.0.0.1")
        self.assertIsNotNone(first_use)
        self.call("GET", "/api/fleet", headers=self.bearer(bearer), secure=True)
        self.assertEqual({item["id"]: item for item in self.call("GET", "/api/keys")[2]}[key["id"]]["last_used_at"], first_use)
        self.assertEqual(self.call("GET", "/api/fleet", headers=self.bearer("sy1_" + "x" * 43), secure=True)[0], 401)
        self.assertEqual(self.call("POST", "/api/keys/self/revoke", {}, self.operator())[0], 403)
        self.assertEqual(self.call("POST", "/api/keys/self/revoke", raw=b"", headers={**self.bearer(bearer), "Content-Length": "0"},
                                   secure=True)[0], 204)
        self.assertEqual(self.call("GET", "/api/fleet", headers=self.bearer(bearer), secure=True)[0], 401)
        self.assertIsNotNone({item["id"]: item for item in self.call("GET", "/api/keys")[2]}[key["id"]]["revoked_at"])
        second, key2 = self.key("read")
        self.assertEqual(self.call("POST", f"/api/keys/{key2['id']}/revoke", {}, self.operator())[0], 204)
        self.assertEqual(self.call("GET", "/api/fleet", headers=self.bearer(second), secure=True)[0], 401)
        third, _ = self.key("read", expires_in_days=1)
        later = time.time() + 86400 + 1
        self.lan.auth.store.clock = self.lan.auth.clock = lambda: later
        status, _, body = self.call("GET", "/api/fleet", headers=self.bearer(third), secure=True)
        self.assertEqual(status, 401)
        self.assertIn("expired", body["error"])



class MCPInterfaceTests(unittest.IsolatedAsyncioTestCase):
    async def test_sdk_stdio_initialize_list_and_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            catalog = write_catalog(directory)
            parameters = StdioServerParameters(
                command=sys.executable,
                args=["-m", "switchyard.mcp_server", "--catalog", str(catalog),
                      "--state-dir", str(Path(directory) / "state"),
                      "--collectors", str(write_collectors(directory))],
                cwd=Path(__file__).resolve().parents[1],
            )
            with anyio.fail_after(20):
                async with stdio_client(parameters) as (read, write):
                    async with ClientSession(read, write) as session:
                        initialized = await session.initialize()
                        self.assertEqual(initialized.serverInfo.name, "Switchyard")
                        tools = {tool.name: tool for tool in (await session.list_tools()).tools}
                        self.assertEqual(set(tools), TOOL_NAMES)
                        for name, tool in tools.items():
                            self.assertIs(tool.annotations.readOnlyHint, name not in {
                                "collect_host", "inspect_workload", "plan_operation", "execute_operation", "shell", "inspect_fleet_keys",
                                "plan_fleet_keys", "execute_fleet_keys", "save_workload_definition", "update_workload_definition",
                                "update_host_description", "lease_hold", "lease_release", "lease_renew",
                                "deploy_plan", "deploy_apply", "deploy_action", "deploy_verify", "undeploy_plan", "undeploy_apply",
                                "deploy_refresh_plan", "deploy_refresh_apply", "deploy_switch_plan", "deploy_switch_apply",
                                "deploy_upgrade_plan",
                                "deploy_pull_start", "deploy_pull_status",
                                "register_application", "token_verify", "token_issue", "token_revoke", "enrollment_approve",
                            })
                            self.assertIs(tool.annotations.openWorldHint, name in {
                                "collect_host", "inspect_workload", "execute_operation", "shell", "inspect_fleet_keys", "execute_fleet_keys",
                                "deploy_plan", "deploy_apply", "deploy_action", "deploy_verify", "undeploy_plan", "undeploy_apply",
                                "deploy_refresh_plan", "deploy_refresh_apply", "deploy_switch_plan", "deploy_switch_apply",
                                "deploy_upgrade_plan",
                                "deploy_pull_start", "deploy_pull_status",
                                "token_verify", "token_issue", "token_revoke"})
                            self.assertIs(tool.inputSchema["additionalProperties"], False)
                            self.assertIs(tool.annotations.destructiveHint, name in {
                                "execute_operation", "shell", "execute_fleet_keys", "deploy_apply", "deploy_action", "undeploy_apply",
                                "deploy_refresh_apply", "deploy_switch_apply",
                                "token_issue", "token_revoke"})
                        self.assertIs(tools["collect_host"].annotations.idempotentHint, False)
                        self.assertEqual(tools["collect_host"].inputSchema["properties"]["host_id"]["enum"], ["source"])
                        self.assertEqual(set(tools["collect_host"].inputSchema["properties"]), {"host_id"})
                        self.assertIn("never workloads", tools["collect_host"].description)
                        properties = tools["plan_migration"].inputSchema["properties"]
                        self.assertEqual(properties["workload_id"]["enum"], ["foobar", "notes-sync"])
                        self.assertEqual(properties["target_id"]["enum"], ["source", "destination"])
                        inventory = await session.call_tool("inventory", {})
                        self.assertFalse(inventory.isError)
                        self.assertEqual(inventory.structuredContent["mode"], "proposal-only")
                        cached = await session.call_tool("fleet", {})
                        self.assertFalse(cached.isError)
                        self.assertIsNone(cached.structuredContent["hosts"][0]["observation"]["snapshot"])
                        for name, arguments in (
                            ("fleet", {"force": True}), ("inventory", {"path": "/tmp/no"}),
                            ("observe_local", {"command": "no"}),
                            ("collect_host", {"host_id": "source", "command": "no"}),
                            ("collect_host", {"host_id": "destination"}),
                            ("collect_host", {"host_id": "source", "force": True}),
                            ("plan_migration", {"workload_id": "foobar", "target_id": "destination", "path": "/tmp/no"}),
                        ):
                            rejected = await session.call_tool(name, arguments)
                            self.assertTrue(rejected.isError)
                        proposal = await session.call_tool("plan_migration", {"workload_id": "foobar", "target_id": "destination"})
                        self.assertFalse(proposal.isError)
                        self.assertIs(proposal.structuredContent["executable"], False)
                        self.assertEqual(proposal.structuredContent["target_id"], "destination")
                        rejected = await session.call_tool("plan_migration", {"workload_id": "unknown", "target_id": "destination"})
                        self.assertTrue(rejected.isError)
                        observation = await session.call_tool("observe_local", {})
                        self.assertFalse(observation.isError)
                        self.assertEqual(observation.structuredContent["scope"], "control-plane host only")
                        after = await session.call_tool("inventory", {})
                        self.assertEqual(inventory.structuredContent, after.structuredContent)
                        rejected = await session.call_tool("execute", {"command": "not accepted"})
                        self.assertTrue(rejected.isError)

    async def test_factory_uses_official_sdk_without_starting_transport(self) -> None:
        from mcp.server.fastmcp import FastMCP

        with tempfile.TemporaryDirectory() as directory:
            mcp = create_mcp(write_catalog(directory), state_dir=Path(directory) / "state")
            self.assertIsInstance(mcp, FastMCP)
            tools = {tool.name: tool for tool in await mcp.list_tools()}
            self.assertEqual(set(tools), TOOL_NAMES)
            self.assertEqual(tools["collect_host"].inputSchema["properties"]["host_id"]["enum"], [])

    async def test_mcp_collection_is_explicit_and_preserves_cached_failure(self) -> None:
        clock = [time.time()]
        with tempfile.TemporaryDirectory() as directory, patch(
            "switchyard.core.ObservationCache",
            side_effect=lambda *args, **kwargs: ObservationCache(*args, **kwargs, clock=lambda: clock[0]),
        ):
            with patch("switchyard.core.collect_host", return_value=snapshot()) as collect:
                mcp = create_mcp(write_catalog(directory), state_dir=Path(directory) / "state",
                                 collectors_path=write_collectors(directory))
                await mcp.list_tools()
                await mcp.call_tool("inventory", {})
                cached = await mcp.call_tool("fleet", {})
                self.assertIsNone(cached[1]["hosts"][0]["observation"]["snapshot"])
                collect.assert_not_called()
                result = await mcp.call_tool("collect_host", {"host_id": "source"})
                self.assertEqual(result[1]["hosts"][0]["observation"]["last_attempt"]["status"], "success")
                collect.assert_called_once()
                tools = {tool.name: tool for tool in await mcp.list_tools()}
                self.assertEqual(tools["plan_migration"].inputSchema["properties"]["workload_id"]["enum"],
                                 ["foobar", "notes-sync"])
                await mcp.call_tool("fleet", {})
                await mcp.call_tool("collect_host", {"host_id": "source"})
                collect.assert_called_once()
            clock[0] += 61
            with patch("switchyard.core.collect_host", side_effect=RuntimeError("private failure")):
                failed = (await mcp.call_tool("collect_host", {"host_id": "source"}))[1]
            observation = failed["hosts"][0]["observation"]
            self.assertEqual(observation["snapshot"], result[1]["hosts"][0]["observation"]["snapshot"])
            self.assertEqual(observation["last_attempt"]["status"], "error")
            self.assertNotIn("private failure", json.dumps(failed))
            for arguments in ({"host_id": "source", "force": True}, {"host_id": "source", "path": "/tmp/no"}):
                with self.assertRaises(ValueError):
                    await mcp.call_tool("collect_host", arguments)


    async def test_mcp_operation_defaults_strict_types_and_disabled_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            mcp = create_mcp(write_catalog(directory), state_dir=Path(directory) / "state")
            policy = (await mcp.call_tool("operation_policy", {}))[1]
            self.assertEqual(policy, {"enabled": False, "shell_hosts": [], "workloads": [], "fleet_key_hosts": []})
            self.assertEqual((await mcp.call_tool("operation_receipts", {}))[1]["result"], [])
            tools = {tool.name: tool for tool in await mcp.list_tools()}
            self.assertEqual(set(tools["shell"].inputSchema["required"]), {"host_id", "script", "request_id"})
            self.assertNotIn("target_id", tools["plan_operation"].inputSchema.get("required", []))
            for name in ("execute_operation", "shell"):
                self.assertIs(tools[name].annotations.readOnlyHint, False)
                self.assertIs(tools[name].annotations.destructiveHint, True)
            for name, payload in (
                ("plan_operation", {"action": "deploy", "workload_id": "foobar"}),
                ("shell", {"host_id": "source", "script": "echo anything", "request_id": "disabled"}),
                ("execute_operation", {"plan_id": "missing", "approved": True, "request_id": "disabled"}),
                ("execute_operation", {"plan_id": "missing", "approved": "true", "request_id": "typed"}),
                ("shell", {"host_id": "source", "script": "x", "request_id": "typed", "timeout_seconds": True}),
                ("shell", {"host_id": "source", "script": "é" * 8193, "request_id": "bytes"}),
                ("shell", {"host_id": "source", "script": "x", "request_id": "extra", "ssh_target": "other"}),
            ):
                with self.subTest(name=name, payload=payload):
                    with self.assertRaises((ValueError, ToolError)):
                        await mcp.call_tool(name, payload)

    async def test_mcp_shell_preserves_unrestricted_input_and_optional_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            mcp = create_mcp(write_catalog(directory), state_dir=Path(directory) / "state")
            script = "printf '%s\\n' unrestricted; for x in a b; do echo \"$x\"; done"
            receipt = {"id": "replayed", "kind": "shell", "status": "succeeded", "events": []}
            with patch.object(mcp._service, "run_shell", return_value={"receipt": receipt, "replayed": True}) as run:
                result = await mcp.call_tool("shell", {"host_id": "source", "script": script, "request_id": "same-intent"})
                run.assert_called_once_with("source", script, timeout_seconds=30, request_id="same-intent", extra_host_ids=None)
                self.assertEqual(result[1], {"receipt": receipt, "replayed": True})
                self.assertNotIn("stdout", result[1])
                self.assertNotIn("stderr", result[1])
            with patch.object(mcp._service, "plan_operation", return_value={"id": "plan"}) as plan:
                await mcp.call_tool("plan_operation", {"action": "stop", "workload_id": "foobar"})
                plan.assert_called_once_with("stop", "foobar", None)

    async def test_mcp_enrollment_strict_arguments_and_explicit_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            mcp = create_mcp(write_catalog(directory), state_dir=Path(directory) / "state")
            state = (await mcp.call_tool("fleet_keys", {}))[1]
            self.assertFalse(state["enabled"])
            for name, payload in (
                ("inspect_fleet_keys", {"host_ids": ["source"], "request_id": "inspect", "force": True}),
                ("inspect_fleet_keys", {"host_ids": "source", "request_id": "inspect"}),
                ("execute_fleet_keys", {"plan_id": "plan", "approved": "true", "request_id": "intent"}),
                ("execute_fleet_keys", {"plan_id": "plan", "approved": True}),
                ("save_workload_definition", {"definition": {}, "expected_revision": "r", "adopt": True}),
                ("propose_workload_definition", {"resource_id": "r", "workload_id": "w", "name": "Name", "purpose": "Purpose", "supporting_resource_ids": "r"}),
            ):
                with self.subTest(name=name), self.assertRaises((ValueError, ToolError)):
                    await mcp.call_tool(name, payload)
            with patch.object(mcp._service, "inspect_fleet_keys", return_value={"receipt": {"status": "partial"}}) as inspect:
                result = await mcp.call_tool("inspect_fleet_keys", {"host_ids": ["source"], "request_id": "inspect"})
                self.assertEqual(result[1]["receipt"]["status"], "partial")
                inspect.assert_called_once_with(["source"], request_id="inspect")
            with patch.object(mcp._service, "execute_fleet_keys", return_value={"receipt": {"status": "needs-inspection"}}) as execute:
                result = await mcp.call_tool("execute_fleet_keys", {"plan_id": "plan", "approved": True, "request_id": "intent"})
                self.assertEqual(result[1]["receipt"]["status"], "needs-inspection")
                execute.assert_called_once_with("plan", approved=True, request_id="intent")
            with patch.object(mcp._service, "propose_workload_definition", return_value={"definition": {}, "revision": "r"}) as propose:
                await mcp.call_tool("propose_workload_definition", {"resource_id": "resource", "workload_id": "w", "name": "Name", "purpose": "Purpose"})
                propose.assert_called_once_with("resource", workload_id="w", name="Name", purpose="Purpose", supporting_resource_ids=None)
            with patch.object(mcp._service, "save_workload_definition", side_effect=ValueError("stale revision")) as save:
                with self.assertRaises(ToolError):
                    await mcp.call_tool("save_workload_definition", {"definition": {"id": "w"}, "expected_revision": "old"})
                save.assert_called_once_with({"id": "w"}, expected_revision="old")

class CLIInterfaceTests(unittest.TestCase):
    def test_monitor_uses_service_context_and_optional_cycles(self) -> None:
        from switchyard.cli import main
        for cycles, expected in (([], None), (["--cycles", "2"], 2)):
            with self.subTest(cycles=cycles), patch("switchyard.cli.Service") as service, patch(
                "switchyard.monitoring.Monitor"
            ) as monitor, patch.object(sys, "argv", ["switchyard", "--catalog", "unused", "monitor", *cycles]):
                cache = object()
                configs = {"source": {"monitor": {"fast_seconds": 10}}}
                service.return_value.monitor_context.return_value = (cache, configs)
                main()
                monitor.assert_called_once_with(cache, configs)
                monitor.return_value.run.assert_called_once_with(max_cycles=expected)
                service.return_value.collect_host.assert_not_called()

    def test_monitor_rejects_nonpositive_cycles(self) -> None:
        from switchyard.cli import main
        with patch.object(sys, "argv", ["switchyard", "--catalog", "unused", "monitor", "--cycles", "0"]), patch(
            "switchyard.cli.Service"
        ) as service, self.assertRaises(SystemExit) as raised:
            main()
        self.assertEqual(raised.exception.code, 2)
        service.assert_not_called()

    def test_cli_plan_execute_and_receipts_require_explicit_commands(self) -> None:
        from switchyard.cli import main
        for command, method, args, kwargs in (
            (["plan-operation", "migrate", "foobar", "--target", "destination"],
             "plan_operation", ("migrate", "foobar", "destination"), {}),
            (["execute-operation", "exact", "--approve", "--request-id", "intent"],
             "execute_operation", ("exact",), {"approved": True, "request_id": "intent"}),
            (["operations"], "operation_receipts", (), {}),
            (["operations", "--id", "receipt"], "operation_receipt", ("receipt",), {}),
        ):
            with self.subTest(command=command), patch("switchyard.cli.Service") as service, patch.object(
                sys, "argv", ["switchyard", "--catalog", "catalog", "--operations", "operations", *command]
            ), redirect_stdout(io.StringIO()) as stdout:
                getattr(service.return_value, method).return_value = {"result": "factual"}
                main()
                service.assert_called_once_with("catalog", state_dir=None, collectors_path=None, operations_path="operations")
                getattr(service.return_value, method).assert_called_once_with(*args, **kwargs)
                self.assertEqual(json.loads(stdout.getvalue()), {"result": "factual"})
                service.return_value.collect_host.assert_not_called()

    def test_cli_execute_without_approval_is_not_an_execution(self) -> None:
        from switchyard.cli import main
        with patch("switchyard.cli.Service") as service, patch.object(
            sys, "argv", ["switchyard", "--catalog", "unused", "execute-operation", "plan", "--request-id", "intent"]
        ), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main()
        self.assertEqual(raised.exception.code, 2)
        service.assert_not_called()

    def test_cli_shell_reads_bounded_utf8_file_or_stdin_and_declares_extra_hosts(self) -> None:
        from switchyard.cli import main
        script = "for x in 1 2; do printf '%s\\n' \"$x\"; done\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "script.sh"
            path.write_text(script, encoding="utf-8")
            for source in (str(path), "-"):
                with self.subTest(source=source), patch("switchyard.cli.Service") as service, patch.object(
                    sys, "argv", ["switchyard", "--catalog", "catalog", "--operations", "ops", "shell", "source",
                                  "--script-file", source, "--request-id", "shell-intent", "--timeout", "90",
                                  "--also-host", "destination", "--also-host", "other"]
                ), patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(script.encode()), encoding="utf-8")), redirect_stdout(io.StringIO()):
                    service.return_value.run_shell.return_value = {"receipt": {"id": "shell", "status": "succeeded"}}
                    main()
                    service.return_value.run_shell.assert_called_once_with(
                        "source", script, timeout_seconds=90, request_id="shell-intent",
                        extra_host_ids=["destination", "other"],
                    )
            path.write_bytes(b"x" * 16385)
            with patch("switchyard.cli.Service") as service, patch.object(
                sys, "argv", ["switchyard", "--catalog", "catalog", "shell", "source",
                              "--script-file", str(path), "--request-id", "oversized"]
            ), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                main()
            self.assertEqual(raised.exception.code, 2)
            service.return_value.run_shell.assert_not_called()

    def test_cli_web_passes_operations_only_from_startup(self) -> None:
        from switchyard.cli import main
        with patch("switchyard.web.serve") as serve, patch.object(
            sys, "argv", ["switchyard", "--catalog", "catalog", "--operations", "operations", "web", "--port", "0"]
        ):
            main()
        serve.assert_called_once_with("catalog", host="127.0.0.1", port=0, state_dir=None, collectors_path=None,
                                     operations_path="operations", lan_read_only=False, allowed_clients=None)

    def test_cli_enrollment_and_promotion_commands_preserve_explicit_intent(self) -> None:
        from switchyard.cli import main
        for command, method, args, kwargs in (
            (["fleet-keys"], "fleet_keys", (), {}),
            (["inspect-fleet-keys", "source", "destination", "--request-id", "inspect-intent"],
             "inspect_fleet_keys", (["source", "destination"],), {"request_id": "inspect-intent"}),
            (["plan-fleet-keys", "reconcile"], "plan_fleet_keys", ("reconcile", []), {}),
            (["plan-fleet-keys", "rotate", "source"], "plan_fleet_keys", ("rotate", ["source"]), {}),
            (["execute-fleet-keys", "exact", "--approve", "--request-id", "apply-intent"],
             "execute_fleet_keys", ("exact",), {"approved": True, "request_id": "apply-intent"}),
            (["definitions"], "definition_inventory", (), {}),
            (["propose-workload-definition", "resource", "--workload-id", "service", "--name", "Service",
              "--purpose", "Useful service", "--supporting-resource", "support"],
             "propose_workload_definition", ("resource",), {
                 "workload_id": "service", "name": "Service", "purpose": "Useful service", "supporting_resource_ids": ["support"],
             }),
        ):
            with self.subTest(command=command), patch("switchyard.cli.Service") as service, patch.object(
                sys, "argv", ["switchyard", "--catalog", "catalog", *command]
            ), redirect_stdout(io.StringIO()) as stdout:
                getattr(service.return_value, method).return_value = {"status": "factual"}
                main()
                getattr(service.return_value, method).assert_called_once_with(*args, **kwargs)
                self.assertEqual(json.loads(stdout.getvalue()), {"status": "factual"})
                service.return_value.collect_host.assert_not_called()

    def test_cli_key_execution_without_approval_never_reaches_service(self) -> None:
        from switchyard.cli import main
        with patch("switchyard.cli.Service") as service, patch.object(
            sys, "argv", ["switchyard", "--catalog", "unused", "execute-fleet-keys", "plan", "--request-id", "intent"]
        ), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main()
        self.assertEqual(raised.exception.code, 2)
        service.assert_not_called()

    def test_cli_definition_file_and_stdin_are_bounded_objects_with_exact_revision(self) -> None:
        from switchyard.cli import main
        definition = {"id": "service", "name": "Service", "purpose": "Useful"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "definition.json"
            path.write_text(json.dumps(definition), encoding="utf-8")
            for command, method, positional in (
                ("save-workload-definition", "save_workload_definition", []),
                ("update-workload-definition", "update_workload_definition", ["service"]),
            ):
                for source in (str(path), "-"):
                    with self.subTest(command=command, source=source), patch("switchyard.cli.Service") as service, patch.object(
                        sys, "argv", ["switchyard", "--catalog", "catalog", command, *positional,
                                      "--definition-file", source, "--expected-revision", "exact-revision"]
                    ), patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(definition).encode()), encoding="utf-8")), redirect_stdout(io.StringIO()):
                        getattr(service.return_value, method).return_value = {"definition": definition, "revision": "new"}
                        main()
                        args = ("service", definition) if positional else (definition,)
                        getattr(service.return_value, method).assert_called_once_with(*args, expected_revision="exact-revision")
            for content in ("[]", "{not-json", "x" * 102401):
                path.write_text(content, encoding="utf-8")
                with self.subTest(content=content[:20]), patch("switchyard.cli.Service") as service, patch.object(
                    sys, "argv", ["switchyard", "--catalog", "catalog", "save-workload-definition",
                                  "--definition-file", str(path), "--expected-revision", "r"]
                ), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                    main()
                self.assertEqual(raised.exception.code, 2)
                service.return_value.save_workload_definition.assert_not_called()



if __name__ == "__main__":
    unittest.main()
