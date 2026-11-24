"""Registry, identity and live-monitor regressions; no real transport is opened."""
import base64
from concurrent.futures import Future
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch

from switchyard.core import Service
from switchyard.host_registry import authority
from switchyard.host_keys import fingerprint
from switchyard.monitoring import Monitor
from switchyard.observations import merge_snapshot


def key(byte=1):
    kind = b"ssh-ed25519"
    wire = struct.pack(">I", len(kind)) + kind + struct.pack(">I", 32) + bytes([byte]) * 32
    return "ssh-ed25519 " + base64.b64encode(wire).decode()


def snapshot(config, at):
    host = config["host_id"]
    return {"schema_version": 1, "host_id": host, "collector": "linux-v1", "observed_at": at,
            "host": {"hostname": config["expected_hostname"], "os": "Linux", "distribution": None, "architecture": "x86_64"},
            "cpu": {"model": None, "logical_count": 2, "utilization_percent": None, "sample_seconds": None, "load_1m": None},
            "memory": dict.fromkeys(("total_bytes", "available_bytes", "swap_total_bytes", "swap_free_bytes")),
            "gpus": [], "storage": {"devices": [], "filesystems": []}, "workloads": [],
            "coverage": [{"scope": "host", "status": "complete", "message": ""}], "warnings": []}


class ImmediateExecutor:
    def __init__(self, **kwargs):
        pass

    def submit(self, function, *args):
        future = Future()
        try:
            future.set_result(function(*args))
        except BaseException as error:
            future.set_exception(error)
        return future

    def shutdown(self, **kwargs):
        pass


class HostRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.catalog = self.root / "catalog.json"
        self.collectors = self.root / "collectors.json"
        self.ledger = self.root / "ledger.md"
        self.document = {"schema_version": 1, "provenance": "isolated test", "workloads": [],
                         "devices": [{"id": host, "name": host, "platform": "linux", "architecture": "x86_64",
                                      "capabilities": ["linux"], "notes": "isolated test", "provenance": "test",
                                      "access": "declared-only", "observed_at": None} for host in ("alpha", "beta")]}
        self.configs = {host: {"host_id": host, "transport": "ssh", "target": "tester@" + host + ".invalid",
                              "ledger": str(self.ledger), "expected_hostname": host,
                              "user_units": [], "system_units": []} for host in ("alpha", "beta")}
        self.write_seeds()
        self.bootstrap = patch("switchyard.host_registry.host_keys.bootstrap", return_value=[key()])
        self.bootstrap.start()
        self.addCleanup(self.bootstrap.stop)
        self.now = 2000.0

    def write_seeds(self):
        self.catalog.write_text(json.dumps(self.document))
        self.collectors.write_text(json.dumps({"schema_version": 1, "hosts": list(self.configs.values())}))

    def service(self):
        service = Service(self.catalog, collectors_path=self.collectors, state_dir=self.root / "state")
        service._cache.clock = lambda: self.now
        service._registry.clock = lambda: self.now
        return service

    def observe(self, service, host):
        at = datetime.fromtimestamp(self.now, timezone.utc).isoformat()
        with patch("switchyard.core.collect_host", side_effect=lambda config, **_: snapshot(config, at)):
            return service.collect_host(host)

    def test_symlinked_state_root_seeds_pins(self):
        # A symlinked home/state root must still produce a canonical pin file.
        real = self.root / "real-state"
        real.mkdir(mode=0o700)
        link = self.root / "linked-state"
        link.symlink_to(real)
        service = Service(self.catalog, collectors_path=self.collectors, state_dir=link)
        self.assertEqual([len(host["pins"]) for host in service.hosts()["hosts"]], [1, 1])
        self.assertEqual(service._registry.pins_path.parent.resolve(), service._registry.pins_path.parent)
        self.assertTrue(service._registry.pins_path.is_file())

    def test_seed_once_and_private_catalog_scoped_storage(self):
        service = self.service()
        original = service.hosts()
        self.document["devices"][0]["name"] = "seed changed"
        self.configs["alpha"]["target"] = "tester@different.invalid"
        self.write_seeds()
        other = self.service()
        self.assertEqual(other.hosts(), original)
        expected = hashlib.sha256(str(self.catalog.resolve()).encode()).hexdigest() + ".sqlite3"
        self.assertEqual(other._registry.path.name, expected)
        self.assertEqual(stat.S_IMODE(other._registry.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(other._registry.directory.stat().st_mode), 0o700)
        # A populated registry does not even need the collectors seed to remain valid.
        self.collectors.write_text("not JSON")
        self.assertEqual(self.service().hosts(), original)
        self.assertEqual(other.inventory()["devices"][0]["access"], "declared-only")

    def test_cas_and_descriptive_edits_do_not_change_connection_revision(self):
        service, other = self.service(), self.service()
        revision = service.hosts()["revision"]
        changed = service.update_host("alpha", {"name": "Edited"}, expected_revision=revision, connection=False)
        self.assertEqual(changed["host"]["connection_revision"], 1)
        with self.assertRaisesRegex(ValueError, "revision changed"):
            other.update_host("beta", {"notes": "stale"}, expected_revision=revision, connection=False)
        self.assertEqual(other.hosts()["hosts"][0]["name"], "Edited")
        with self.assertRaisesRegex(ValueError, "immutable"):
            service.update_host("alpha", {"id": "renamed"}, expected_revision=changed["revision"], connection=True)

    def test_address_edit_invalidates_only_its_host_and_verification_is_not_cas(self):
        service = self.service()
        revision = service.hosts()["revision"]
        self.observe(service, "alpha")
        self.observe(service, "beta")
        self.assertEqual(service.hosts()["revision"], revision)
        self.assertEqual(service.hosts()["hosts"][0]["verification"]["state"], "verified")
        beta = service._cache.read("beta")
        changed = service.update_host("alpha", {"target": "tester@new.invalid"}, expected_revision=revision, connection=True)
        self.assertEqual(changed["host"]["connection_revision"], 2)
        self.assertEqual(changed["host"]["verification"]["state"], "unverified")
        absent = service._cache.read("alpha")
        self.assertIsNone(absent["snapshot"])
        self.assertIsNone(absent["last_attempt"])
        self.assertEqual(absent["freshness"], "never")
        self.assertEqual(absent["retry_after_seconds"], 0)
        self.assertEqual(service._cache.read("beta"), beta)
        self.observe(service, "alpha")
        host = service.hosts()["hosts"][0]
        self.assertEqual(host["verified_revision"], 2)
        self.assertEqual(host["verification"]["state"], "verified")
        self.assertEqual(service.hosts()["revision"], changed["revision"])
        self.assertEqual(service._broker.hosts["alpha"]["target"], "tester@new.invalid")
        self.assertIn("known_hosts", service._broker.hosts["alpha"])
        self.assertEqual(self.service()._cache.namespace, service._cache.namespace)

    def test_stale_inflight_authority_cannot_verify_new_connection(self):
        service = self.service()
        old = deepcopy(service._collectors["alpha"])
        old_authority = authority(service.hosts()["hosts"][0])
        service.update_host("alpha", {"target": "tester@new.invalid"}, expected_revision=service.hosts()["revision"], connection=True)
        self.assertNotEqual(service._collection_authority(old), service._cache.authorities["alpha"])
        service._registry.verify("alpha", old_authority)
        self.assertEqual(service.hosts()["hosts"][0]["verification"]["state"], "unverified")

    def test_scan_exact_confirmation_expiry_and_connection_binding(self):
        service = self.service()
        revision = service.hosts()["revision"]
        with patch("switchyard.collector.scan_host_key", return_value={"keys": [key(2)], "fingerprints": [fingerprint(key(2))]}) as scan:
            result = service.scan_host_key("alpha", request_id="scan-1")
            scan.assert_called_once()
            self.assertEqual(service.hosts()["revision"], revision)
            for values in ([], [fingerprint(key())], result["fingerprints"] * 2):
                with self.assertRaisesRegex(ValueError, "exactly"):
                    service.pin_host_key("alpha", scan_id=result["scan_id"], fingerprints=values, expected_revision=revision)
            pinned = service.pin_host_key("alpha", scan_id=result["scan_id"], fingerprints=result["fingerprints"], expected_revision=revision)
            self.assertEqual(pinned["host"]["host_keys"], [key(2)])
            self.assertEqual(pinned["host"]["connection_revision"], 2)
            self.assertEqual(pinned["host"]["verification"]["state"], "unverified")
            result = service.scan_host_key("alpha", request_id="scan-2")
            self.now += 600
            with self.assertRaisesRegex(ValueError, "expired"):
                service.pin_host_key("alpha", scan_id=result["scan_id"], fingerprints=result["fingerprints"], expected_revision=pinned["revision"])
            result = service.scan_host_key("alpha", request_id="scan-3")
            changed = service.update_host("alpha", {"port": 2222}, expected_revision=pinned["revision"], connection=True)
            with self.assertRaisesRegex(ValueError, "connection changed"):
                service.pin_host_key("alpha", scan_id=result["scan_id"], fingerprints=result["fingerprints"], expected_revision=changed["revision"])

    def test_unpinned_address_and_local_connection_changes_refused(self):
        self.bootstrap.stop()
        self.bootstrap = patch("switchyard.host_registry.host_keys.bootstrap", return_value=[])
        self.bootstrap.start()
        self.addCleanup(self.bootstrap.stop)
        self.configs["beta"] = {"host_id": "beta", "transport": "local", "expected_hostname": "beta", "user_units": [], "system_units": []}
        self.write_seeds()
        service = self.service()
        revision = service.hosts()["revision"]
        with self.assertRaisesRegex(ValueError, "Pin this host's key first"):
            service.update_host("alpha", {"target": "tester@new.invalid"}, expected_revision=revision, connection=True)
        with self.assertRaisesRegex(ValueError, "local and ADB connections cannot be edited"):
            service.update_host("beta", {"expected_hostname": "new"}, expected_revision=revision, connection=True)
        self.observe(service, "alpha")
        self.assertEqual(service.hosts()["hosts"][0]["verification"]["state"], "unpinned")

    def test_explicit_import_replaces_seed_only_on_current_revision(self):
        service = self.service()
        old = service.hosts()["revision"]
        changed = service.update_host("alpha", {"name": "Edited"}, expected_revision=old, connection=False)
        with self.assertRaisesRegex(ValueError, "revision changed"):
            service.import_hosts(replace=True, expected_revision=old)
        result = service.import_hosts(replace=True, expected_revision=changed["revision"])
        self.assertEqual(result["hosts"][0]["name"], "alpha")
        self.assertEqual(service.export_hosts()["hosts"][0]["collector"]["target"], "tester@alpha.invalid")
        self.assertNotIn("verification", service.export_hosts()["hosts"][0])

    def test_allowlists_are_cli_only_and_cadence_preserves_evidence(self):
        service = self.service()
        self.observe(service, "alpha")
        original = service._cache.read("alpha")["snapshot"]
        changes = {"monitor": {"fast_seconds": 20, "storage_seconds": 60, "inventory_seconds": 300}}
        revision = service.hosts()["revision"]
        with self.assertRaises(ValueError):
            service.update_host("alpha", changes, expected_revision=revision, connection=True)
        result = service.update_host("alpha", changes, expected_revision=revision, connection=True, allowlists=True)
        self.assertEqual(result["host"]["connection_revision"], 1)
        self.assertEqual(service._cache.read("alpha")["snapshot"], original)
        self.assertEqual(service.monitoring_configs()["alpha"]["monitor"]["fast_seconds"], 20)

    def test_monitor_reloads_registry_cadence_and_allowlist_without_restart(self):
        self.configs["alpha"]["monitor"] = {"fast_seconds": 10, "storage_seconds": 60, "inventory_seconds": 300}
        self.write_seeds()
        service = self.service()
        monitor = Monitor(*service.monitor_context())
        calls = []
        edited = False
        def collect(config, **kwargs):
            calls.append((self.now, deepcopy(config)))
            return snapshot(config, datetime.fromtimestamp(self.now, timezone.utc).isoformat())
        def wait(wake, stop, seconds):
            nonlocal edited
            if not edited:
                edited = True
                service.update_host("alpha", {"monitor": {"fast_seconds": 20, "storage_seconds": 60, "inventory_seconds": 300},
                                              "user_units": ["new.service"]}, expected_revision=service.hosts()["revision"],
                                    connection=True, allowlists=True)
            self.now += seconds
            wake.clear()
        with patch("switchyard.monitoring.ThreadPoolExecutor", ImmediateExecutor), \
             patch("switchyard.monitoring.time.monotonic", side_effect=lambda: self.now), \
             patch("switchyard.monitoring.collector.collect_host", side_effect=collect), \
             patch.object(monitor, "_wait", side_effect=wait):
            monitor.run(max_cycles=2)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][1]["user_units"], ["new.service"])
        self.assertEqual(calls[1][1]["monitor"]["fast_seconds"], 20)
        self.assertGreaterEqual(calls[1][0] - calls[0][0], 20)
        self.assertEqual(service._cache.read_monitor()["hosts"][0]["fast_seconds"], 20)

    def test_paseo_scope_retains_omitted_evidence_and_replaces_complete(self):
        config = self.configs["alpha"]
        previous = snapshot(config, datetime.fromtimestamp(self.now, timezone.utc).isoformat())
        previous["paseo"] = {"daemon": {"version": "1.0", "server_id": "server", "hostname": "alpha", "listen": "127.0.0.1:6767",
                                          "state": "running", "started_at": None, "providers": [], "relay_enabled": None},
                             "agents": None, "configured": True, "cli_candidates": []}
        previous["coverage"].append({"scope": "paseo", "status": "partial", "message": "No CLI"})
        retained = merge_snapshot(previous, snapshot(config, previous["observed_at"]))
        self.assertEqual(retained["paseo"], previous["paseo"])
        current = snapshot(config, previous["observed_at"])
        current["paseo"] = deepcopy(previous["paseo"])
        current["paseo"]["daemon"]["state"] = "stopped"
        current["coverage"].append({"scope": "paseo", "status": "complete", "message": ""})
        self.assertEqual(merge_snapshot(previous, current)["paseo"]["daemon"]["state"], "stopped")

    def test_legacy_seed_wrapper_is_ignored_and_does_not_fix_endpoint(self):
        self.configs["alpha"]["lease_wrapper"] = "/test-only/retired-wrapper"
        self.write_seeds()
        service = self.service()
        self.assertNotIn("lease_wrapper", service._collectors["alpha"])
        service.update_host("alpha", {"target": "tester@other.invalid"},
                            expected_revision=service.hosts()["revision"], connection=True)
        self.assertEqual(service._collectors["alpha"]["target"], "tester@other.invalid")

    def test_removal_refuses_definition_and_operation_references(self):
        self.document["workloads"] = [{
            "id": "defined", "name": "Defined", "purpose": "Test definition", "device_id": "alpha",
            "backend": "systemd", "management": "defined", "kind": "service",
            "bindings": [{"backend": "systemd", "scope": "user:1000", "selector": {"native_id": "test.service"}, "role": "primary"}],
            "requirements": [], "architectures": [], "recipe": None, "notes": "Test",
            "health_check": None, "data_locations": [], "dependencies": [],
            "supported_operations": ["observe", "plan-migration"]}]
        self.write_seeds()
        service = self.service()
        revision = service.hosts()["revision"]
        with self.assertRaisesRegex(ValueError, "unknown source device"):
            service.remove_host("alpha", expected_revision=revision)
        self.assertEqual(service.hosts()["revision"], revision)
        # A fresh state directory: after seeding, the catalog's workloads no longer change a store.
        self.document["workloads"] = []
        self.write_seeds()
        operations = self.root / "operations.json"
        operations.write_text(json.dumps({"schema_version": 2, "shell_hosts": ["alpha"], "workloads": {}}))
        service = Service(self.catalog, collectors_path=self.collectors, state_dir=self.root / "state-without-workloads",
                          operations_path=operations)
        revision = service.hosts()["revision"]
        with self.assertRaisesRegex(ValueError, "enrolled SSH host"):
            service.remove_host("alpha", expected_revision=revision)
        self.assertEqual(service.hosts()["revision"], revision)

    def test_add_remove_are_cas_safe_and_removed_registry_does_not_reseed(self):
        service = self.service()
        record = {key: value for key, value in service.export_hosts()["hosts"][0].items()}
        record.update(id="gamma", name="Gamma", collector=None, host_keys=[], connection_revision=1, verified_revision=None)
        result = service.add_host(record, expected_revision=service.hosts()["revision"])
        self.assertEqual(result["host"]["verification"]["state"], "no-collector")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            service.add_host(record, expected_revision=result["revision"])
        for host in ("alpha", "beta", "gamma"):
            service.remove_host(host, expected_revision=service.hosts()["revision"])
        self.assertEqual(self.service().hosts()["hosts"], [])


if __name__ == "__main__":
    unittest.main()
