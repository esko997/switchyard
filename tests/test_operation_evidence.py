from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from switchyard.core import Service
from test_observations import snapshot


ROOT = Path(__file__).resolve().parents[1]


def at(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


class OperationEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.now = 2000
        self.catalog = json.loads((ROOT / "catalogs/example.json").read_text())
        definition = self.catalog["workloads"][0]
        definition.update(backend="podman", recipe=None, requirements=["linux", "podman"])
        definition["bindings"] = [{"backend": "podman", "scope": "user:1000",
                                   "selector": {"name": "switchyard-foobar"}, "role": "primary"}]
        self.catalog_path = self.root / "catalog.json"
        broker_patch = patch("switchyard.core.Broker")
        self.broker = broker_patch.start().return_value
        self.addCleanup(broker_patch.stop)
        self.broker.policy.return_value = {"enabled": False, "shell_hosts": [], "workloads": []}
        self.broker.receipts.return_value = []
        self.broker.placements.return_value = {}
        self.broker.lifecycle_inspections.return_value = {}
        self.broker.revision.return_value = "0"
        # The fleet also reads the deploy journal, which sits in the broker's state directory.
        self.broker.store.directory = self.root / "state" / "operations" / "fixture"

    def service(self):
        self.catalog_path.write_text(json.dumps(self.catalog))
        # Evidence only exists under a host's collector authority, so destination gets a real one.
        collectors = self.root / "collectors.json"
        collectors.write_text(json.dumps({"schema_version": 1, "hosts": [
            {"host_id": "destination", "transport": "local", "expected_hostname": "destination",
             "user_units": [], "system_units": [], "container_engines": ["podman"]}]}))
        service = Service(self.catalog_path, state_dir=self.root / "state", collectors_path=collectors)
        service._cache.clock = lambda: self.now
        return service

    def placement(self, **changes):
        value = {"workload_id": "foobar", "host_id": "destination", "native_id": "a" * 64,
                 "scope": "user:1000", "lifecycle": "running", "verified_at": at(1990),
                 "uncertain": False, "ownership_id": "11111111-1111-4111-8111-111111111111"}
        value.update(changes)
        self.broker.placements.return_value = {"foobar": value}

    def observe_destination(self, service, *, native_id="a" * 64, lifecycle="running", observed=1995):
        reading = snapshot(observed, workloads=False)
        reading["host_id"] = "destination"
        reading["host"]["hostname"] = "destination"
        reading["coverage"] = [{"scope": "podman:user:1000", "status": "complete", "message": "Measured"}]
        reading["workloads"] = [{"id": "destination-container", "host_id": "destination",
                                 "backend": "podman", "scope": "user:1000", "native_id": native_id,
                                 "name": "switchyard-foobar", "kind": "service", "lifecycle": lifecycle,
                                 "health": "unknown", "management": "discovered", "observed_at": at(observed),
                                 "extensions": {"container.v1": {}}}]
        service._cache.refresh("destination", service._collectors["destination"], lambda _: reading)

    def workload(self, service):
        with patch("time.time", return_value=self.now):
            return service.fleet()["workloads"][0]

    def test_disabling_operations_keeps_verified_destination_without_regranting_authority(self):
        self.placement()
        workload = self.workload(self.service())
        self.assertEqual(workload["device_id"], "destination")
        self.assertEqual(workload["declared_device_id"], "source")
        self.assertEqual(workload["lifecycle"], "running")
        self.assertEqual(workload["observed_at"], at(1990))
        self.assertEqual(workload["state_evidence"]["kind"], "operation-receipt")
        self.assertEqual(workload["health"], "unknown")
        self.assertFalse(workload["authority"]["execute"])

    def test_same_name_replacement_is_not_treated_as_owned_container(self):
        self.placement(verified_at=at(1000))
        service = self.service()
        self.observe_destination(service, native_id="b" * 64)
        workload = self.workload(service)
        self.assertEqual(workload["lifecycle"], "unknown")
        self.assertEqual(workload["resource_ids"], [])
        self.assertEqual(workload["bindings_evidence"][0]["status"], "missing")

    def test_newer_native_stop_overrides_older_successful_start_receipt(self):
        self.placement()
        service = self.service()
        self.observe_destination(service, lifecycle="stopped")
        workload = self.workload(service)
        self.assertEqual(workload["lifecycle"], "stopped")
        self.assertEqual(workload["observed_at"], at(1995))

    def test_uncertain_or_running_operation_does_not_show_old_healthy_state(self):
        for uncertain, receipts, expected in (
            (True, [], "uncertain-operation"),
            (False, [{"id": "operation-one", "workload_id": "foobar", "status": "running"}], "operation-in-progress"),
        ):
            with self.subTest(expected=expected):
                self.placement(uncertain=uncertain)
                self.broker.receipts.return_value = receipts
                service = self.service()
                self.observe_destination(service)
                workload = self.workload(service)
                self.assertEqual(workload["lifecycle"], "unknown")
                self.assertEqual(workload["health"], "unknown")
                self.assertEqual(workload["state_evidence"]["kind"], expected)


if __name__ == "__main__":
    unittest.main()
