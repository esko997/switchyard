from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from switchyard.core import Service
from test_observations import snapshot


ROOT = Path(__file__).resolve().parents[1]


class CadenceDefinitionTests(unittest.TestCase):
    def test_slow_inventory_freshness_does_not_relax_migration_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog = json.loads((ROOT / "catalogs/example.json").read_text())
            definition = deepcopy(catalog["workloads"][0])
            definition.update(id="test-container", name="Test container", device_id="source",
                              backend="docker", recipe=None, dependencies=[])
            definition["bindings"] = [{"backend": "docker", "scope": "system",
                                       "selector": {"name": "test-container"}, "role": "primary"}]
            catalog["workloads"] = [definition]
            catalog_path = root / "catalog.json"
            catalog_path.write_text(json.dumps(catalog))
            config = {"host_id": "source", "transport": "local", "expected_hostname": "source",
                      "user_units": ["notes.service"], "system_units": [],
                      "monitor": {"fast_seconds": 10, "storage_seconds": 60, "inventory_seconds": 300}}
            config_path = root / "collectors.json"
            config_path.write_text(json.dumps({"schema_version": 1, "hosts": [config]}))
            service = Service(catalog_path, state_dir=root / "state", collectors_path=config_path)
            service._cache.clock = lambda: 2000.0
            full = snapshot(1790)
            full["coverage"] += [{"scope": scope, "status": "complete", "message": "Measured"}
                                 for scope in ("cpu", "memory", "gpus", "storage", "docker:system")]
            container = {**deepcopy(full["workloads"][0]), "id": "native-container", "backend": "docker",
                         "scope": "system", "native_id": "a" * 64, "name": "test-container",
                         "extensions": {"container.v1": {}}}
            full["workloads"].append(container)
            service._cache.refresh("source", config, lambda _: full, lane="inventory")
            fast = snapshot(1985)
            fast["coverage"] += [{"scope": scope, "status": "complete", "message": "Measured"}
                                 for scope in ("cpu", "memory")]
            service._cache.refresh("source", config, lambda _: fast, lane="fast")
            monitor = {"state": "running", "heartbeat_at": datetime.fromtimestamp(2000, timezone.utc).isoformat(),
                       "hosts": [{"host_id": "source", **config["monitor"]}], "message": "Automatic read-only observation"}
            with patch("time.time", return_value=2000.0), patch.object(service._cache, "read_monitor", return_value=monitor):
                fleet = service.fleet()
                host = next(host for host in fleet["hosts"] if host["id"] == "source")
                self.assertEqual(host["resource_status"]["cpu"]["freshness"], "fresh")
                self.assertEqual(host["resource_status"]["gpus"]["freshness"], "fresh")
                self.assertEqual(host["resource_status"]["storage"]["freshness"], "stale")
                self.assertEqual(fleet["workloads"][0]["lifecycle"], "running")
                self.assertEqual(fleet["workloads"][0]["age_seconds"], 210)
                self.assertEqual(fleet["workloads"][0]["freshness_ttl_seconds"], 900)
                plan = service.plan_migration("test-container", "destination")
                self.assertIn("Selected workload observation is stale for migration assessment.", plan["blockers"])
                self.assertFalse(plan["executable"])
                with self.assertRaises(ValueError):
                    service.plan_migration("native-container", "destination")


    def test_cadence_change_preserves_evidence_but_allowlist_change_does_not(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog_path = root / "catalog.json"
            catalog_path.write_bytes((ROOT / "catalogs/example.json").read_bytes())
            config_path = root / "collectors.json"
            config = {"host_id": "source", "transport": "local", "expected_hostname": "source",
                      "user_units": ["notes.service"], "system_units": []}
            config_path.write_text(json.dumps({"schema_version": 1, "hosts": [config]}))
            service = Service(catalog_path, state_dir=root / "state", collectors_path=config_path)
            reading = snapshot(datetime.now(timezone.utc).timestamp())
            service._cache.refresh("source", service._collectors["source"], lambda _: reading)
            revision = service.hosts()["revision"]
            # Live registry edits, not seed-file rewrites: the registry is authoritative after seeding.
            revision = service.update_host("source", {"monitor": {"fast_seconds": 10, "storage_seconds": 60, "inventory_seconds": 300}},
                                           expected_revision=revision, connection=True, allowlists=True)["revision"]
            self.assertEqual(service.fleet()["resources"][0]["observed_at"], reading["observed_at"])
            reopened = Service(catalog_path, state_dir=root / "state", collectors_path=config_path)
            self.assertEqual(reopened.fleet()["resources"][0]["observed_at"], reading["observed_at"])
            service.update_host("source", {"user_units": ["different.service"]},
                                expected_revision=revision, connection=True, allowlists=True)
            self.assertEqual(service.fleet()["resources"], [])
            self.assertEqual(reopened.fleet()["resources"], [])


class DeployedWorkloadFleetTests(unittest.TestCase):
    def test_deployed_workloads_stay_in_the_fleet_when_operations_are_not_configured(self):
        # Turning control off (or starting a desk without --operations) must not hide what was deployed:
        # reading the deploy journal needs no execution authority.
        from switchyard.deploy import DeployManager
        deployment = {"instance_id": "lan-dns", "template_ref": {"id": "coredns-lan", "revision": 1}, "host_id": "source",
                      "generation": 3, "state": "fenced", "token": "revoked", "runtime": "stopped", "uncertain": False,
                      "service": "switchyard-lan-dns-dns.service", "claims": ["udp/192.168.50.233:53"],
                      "last_verified": None, "updated_at": datetime.now(timezone.utc).isoformat()}
        definition = {"id": "lan-dns", "name": "LAN DNS", "purpose": "names", "device_id": "source", "backend": "podman",
                      "management": "deployed", "kind": "service", "requirements": [], "architectures": [], "recipe": None,
                      "health_check": None, "data_locations": [], "dependencies": [], "notes": None,
                      "supported_operations": ["observe"],
                      "bindings": [{"backend": "podman", "scope": "user:1000",
                                    "selector": {"name": "switchyard-lan-dns-dns-coredns"}, "role": "primary"}]}
        with tempfile.TemporaryDirectory() as directory:
            service = Service(ROOT / "catalogs/example.json", state_dir=Path(directory) / "state")
            self.assertFalse(service.operation_policy()["enabled"])
            self.assertEqual(service.deployments().workload_definitions(), [])  # The journal is readable without authority.
            with patch.object(DeployManager, "workload_definitions", return_value=[{"definition": definition, "deployment": deployment}]):
                workload = next(item for item in service.fleet()["workloads"] if item["id"] == "lan-dns")
            self.assertEqual((workload["management"], workload["device_id"], workload["deployment"]["state"]),
                             ("deployed", "source", "fenced"))
            # A fenced instance has no container to observe: the journal is the evidence, not "unknown".
            self.assertEqual((workload["lifecycle"], workload["state_evidence"]["kind"]), ("stopped", "deploy-journal"))
            self.assertEqual(workload["authority"], {"execute": False, "approval": "deploy-plan-required"})


if __name__ == "__main__":
    unittest.main()
