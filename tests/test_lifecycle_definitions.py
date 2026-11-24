"""Adopted lifecycle resources must match the operator's workload definition."""
from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from switchyard.core import Service
from switchyard import operation_worker
from switchyard.operation_store import encode


class LifecycleDefinitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.catalog = json.loads((Path(__file__).resolve().parents[1] / "catalogs/example.json").read_text())
        self.catalog_path = self.root / "catalog.json"
        self.operations_path = self.root / "operations.json"
        self.collectors_path = self.root / "collectors.json"
        self.ledger = self.root / "source.ledger"
        self.host = {"host_id": "source", "transport": "ssh", "target": "fixture@source.invalid",
                     "expected_hostname": "source", "ledger": str(self.ledger), "user_units": [], "system_units": []}
        self.collectors_path.write_text(json.dumps({"schema_version": 1, "hosts": [self.host]}))
        self.remote_actions = []

    def resource(self, name, native_id, backend="podman", scope="user:1000"):
        return {"backend": backend, "scope": scope, "name": name, "native_id": native_id}

    def prepare(self, resources, bindings, backend="compose"):
        # The store record (seeded from this catalog) describes the workload; the policy only grants it.
        runtime = {"kind": "compose", "provider": "podman-compose", "project_name": "fixture",
                   "project_directory": "/srv/fixture", "files": ["/srv/fixture/compose.yaml"],
                   "services": ["web", "db"]} if backend == "compose" else None
        definition = deepcopy(self.catalog["workloads"][0])
        definition.update(id="adopted", name="Adopted fixture", device_id="source", backend=bindings[0]["backend"],
                          bindings=bindings, kind="service", recipe=None, runtime=runtime)
        self.catalog["workloads"] = [definition]
        self.catalog_path.write_text(json.dumps(self.catalog))
        self.operations_path.write_text(json.dumps({"schema_version": 2, "shell_hosts": [], "workloads": {
            "adopted": {"actions": ["start", "stop", "restart"], "hosts": ["source"]}}}))
        self.service = Service(self.catalog_path, state_dir=self.root / "state", collectors_path=self.collectors_path,
                               operations_path=self.operations_path)
        self.inspection = {"backend": backend, "identity": {"fixture": "exact native identity"},
                           "state": {"lifecycle": "running"}, "lifecycle": "running", "health": "unknown",
                           "resources": resources, "warnings": ["Native state is not application health"],
                           "supported_actions": ["start", "stop", "restart"]}
        remote = patch("switchyard.lifecycle_ops.run_remote", side_effect=self.remote)
        dispatch = patch.object(self.service._broker, "_dispatch", side_effect=self.dispatch)
        remote.start()
        dispatch.start()
        self.addCleanup(remote.stop)
        self.addCleanup(dispatch.stop)
        result = self.service.inspect_workload("adopted", request_id="inspect-fixture")
        self.assertEqual(result["receipt"]["status"], "succeeded", result)

    def remote(self, host, source, request, **kwargs):
        self.remote_actions.append(request["action"])
        if request["action"] != "inspect":
            raise AssertionError("Definition validation must precede lifecycle dispatch")
        return {"status": "succeeded", "inspection": deepcopy(self.inspection)}

    def dispatch(self, receipt, payload):
        payload = {**payload, "operation_id": receipt["id"], "state_dir": str(self.service._broker.store.directory),
                   "lease_state_dir": str(self.service._broker.lease_state_dir),
                   "hosts": {"source": self.host}}
        with patch.object(operation_worker.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(encode(payload).encode()))), \
                patch.object(operation_worker.signal, "signal"), redirect_stdout(io.StringIO()):
            operation_worker.main()
        return {"receipt": self.service._broker.receipt(receipt["id"])}

    def binding(self, value, role="primary", backend="podman", scope="user:1000", selector="name"):
        return {"backend": backend, "scope": scope, "selector": {selector: value}, "role": role}

    def test_partial_project_definition_cannot_control_unlisted_database(self):
        self.prepare([self.resource("web", "a" * 64), self.resource("db", "b" * 64)], [self.binding("web")])
        with self.assertRaisesRegex(ValueError, "complete adopted"):
            self.service.plan_operation("stop", "adopted")
        self.assertEqual(self.remote_actions, ["inspect"])

    def test_replaced_container_does_not_match_promoted_native_id(self):
        self.prepare([self.resource("web", "b" * 64)], [self.binding("a" * 64, selector="native_id")])
        with self.assertRaisesRegex(ValueError, "uniquely match"):
            self.service.plan_operation("restart", "adopted")
        self.assertEqual(self.remote_actions, ["inspect"])

    def test_complete_project_is_lifecycle_only_and_health_stays_unknown(self):
        self.prepare([self.resource("web", "a" * 64), self.resource("db", "b" * 64)],
                     [self.binding("web"), self.binding("db", "supporting")])
        plan = self.service.plan_operation("restart", "adopted")
        self.assertEqual((plan["backend"], plan["source_id"], plan["target_id"]), ("compose", "source", "source"))
        fleet = self.service.fleet()
        workload = fleet["workloads"][0]
        self.assertEqual((workload["lifecycle"], workload["health"]), ("running", "unknown"))
        self.assertEqual(workload["state_evidence"]["kind"], "lifecycle-inspection")
        self.assertEqual(fleet["operation_policy"]["workloads"][0]["actions"], ["start", "stop", "restart"])
        self.assertNotIn("podman-static-web", [item["id"] for item in fleet["backends"]])
        with self.assertRaises(ValueError):
            self.service.plan_operation("migrate", "adopted", "destination")
        self.assertEqual(self.remote_actions, ["inspect"])

    def test_same_named_unit_in_another_account_is_not_adopted(self):
        self.prepare([self.resource("fixture.service", "fixture.service", "systemd", "user:1001")],
                     [self.binding("fixture.service", backend="systemd", selector="native_id")], "systemd")
        with self.assertRaisesRegex(ValueError, "uniquely match"):
            self.service.plan_operation("start", "adopted")
        self.assertEqual(self.remote_actions, ["inspect"])


if __name__ == "__main__":
    unittest.main()
