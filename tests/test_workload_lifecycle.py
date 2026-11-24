"""The desk's generic lifecycle routes against the real deployment worker on a fixture host."""
import http.client
import json
import threading
from unittest.mock import patch

from switchyard.web import create_server
from test_deploy import DeployFixture, ROOT


class WorkloadLifecycleTests(DeployFixture):
    def setUp(self):
        super().setUp()
        catalog = json.loads((ROOT / "catalogs/example.json").read_text())
        for device, host_id in zip(catalog["devices"], self.hosts, strict=True):
            device["id"] = host_id
        catalog["workloads"] = []
        catalog_path = self.root / "catalog.json"
        catalog_path.write_text(json.dumps(catalog))
        collectors = self.root / "collectors.json"
        collectors.write_text(json.dumps({"schema_version": 1, "hosts": list(self.hosts.values())}))
        self.server = create_server(catalog_path, port=0, state_dir=self.root / "desk-state",
                                    collectors_path=collectors, operations_path=self.config_path)
        self.addCleanup(self.server.server_close)
        self.broker = self.server.service._broker
        self.hosts = self.broker.hosts
        self.manager = self.server.service.deployments()
        patch.object(self.broker, "_dispatch", side_effect=self.dispatch).start()
        self.save_template()
        self.assertEqual(self.deploy()[1]["receipt"]["status"], "succeeded")
        self.port = self.server.server_port
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.server.shutdown)

    def request(self, path, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=8)
        try:
            connection.request("GET" if body is None else "POST", path,
                               None if body is None else json.dumps(body),
                               {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{self.port}"})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_generic_plan_approval_and_receipt_for_deployed_workload(self):
        status, fleet = self.request("/api/fleet")
        self.assertEqual(status, 200)
        policy, = fleet["operation_policy"]["workloads"]
        self.assertEqual((policy["id"], policy["actions"]), ("garden", ["start", "stop", "restart"]))
        row, = fleet["workloads"]
        self.assertTrue(row["authority"]["execute"])
        self.assertIn("restart", row["supported_operations"])
        before = list(self.remote_actions)
        status, plan = self.request("/api/operations/plan", {"action": "restart", "workload_id": "garden"})
        self.assertEqual(status, 200, plan)
        self.assertEqual((plan["workload_id"], plan["action"], plan["approval_required"]), ("garden", "restart", True))
        request = {"plan_id": plan["id"], "request_id": "generic-restart", "approved": False}
        self.assertGreaterEqual(self.request("/api/operations/execute", request)[0], 400)
        self.assertEqual(self.remote_actions, before)
        request["approved"] = True
        status, result = self.request("/api/operations/execute", request)
        self.assertEqual(status, 200, result)
        receipt = result["receipt"]
        self.assertEqual((receipt["status"], receipt["workload_id"], receipt["action"]), ("succeeded", "garden", "restart"))
        self.assertEqual(self.state()["state"], "active")
        self.assertEqual(self.request("/api/operations/" + receipt["id"]), (200, receipt))

    def test_revoked_deploy_host_removes_controls_but_not_workload(self):
        self.config["deploy_hosts"] = []
        self.write_config()
        status, fleet = self.request("/api/fleet")
        self.assertEqual(status, 200)
        self.assertEqual(fleet["operation_policy"]["workloads"], [])
        row, = fleet["workloads"]
        self.assertEqual(row["id"], "garden")
        self.assertFalse(row["authority"]["execute"])
        self.assertNotIn("stop", row["supported_operations"])
        before = list(self.remote_actions)
        status, response = self.request("/api/operations/plan", {"action": "stop", "workload_id": "garden"})
        self.assertEqual(status, 400, response)
        self.assertEqual(self.remote_actions, before)
