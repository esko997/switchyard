from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from pydantic import ValidationError

from switchyard.core import Service
from switchyard.leases import LeaseBusy
from switchyard.models import Snapshot
from switchyard.observations import ObservationCache

ROOT = Path(__file__).resolve().parents[1]


def snapshot(at=1000, *, scope_status="complete", workloads=True):
    observed = datetime.fromtimestamp(at, timezone.utc).isoformat()
    return {
        "schema_version": 1, "host_id": "source", "collector": "linux-v1", "observed_at": observed,
        "host": {"hostname": "source", "os": "Linux", "distribution": None, "architecture": "x86_64"},
        "cpu": {"model": None, "logical_count": 4, "utilization_percent": None, "sample_seconds": None, "load_1m": None},
        "memory": {"total_bytes": 4096, "available_bytes": 2048, "swap_total_bytes": None, "swap_free_bytes": None},
        "gpus": [], "storage": {"devices": [], "filesystems": []},
        "workloads": [{"id": "source-service", "host_id": "source", "backend": "systemd", "scope": "user:1000", "native_id": "notes.service", "name": "Notes", "kind": "service", "lifecycle": "running", "health": "unknown", "management": "discovered", "observed_at": observed, "extensions": {"systemd.v1": {"active_state": "active", "sub_state": "running"}}}] if workloads else [],
        "coverage": [{"scope": "systemd:user:1000", "status": scope_status, "message": "Exact allowlist only"}], "warnings": [],
    }


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = 1000.0
        self.cache = ObservationCache(self.temp.name, "test", clock=lambda: self.now)
        self.config = {"host_id": "source", "expected_hostname": "source"}

    def test_cooldown_and_storage_shared_between_instances(self):
        self.cache.refresh("source", self.config, lambda config: snapshot())
        other = ObservationCache(self.temp.name, "test", clock=lambda: self.now)
        collector = Mock(side_effect=AssertionError("cache must prevent repeat collection"))
        result = other.refresh("source", self.config, collector)
        collector.assert_not_called()
        self.assertEqual(result["snapshot"]["host"]["hostname"], "source")
        self.assertEqual(result["retry_after_seconds"], 60)
        self.now += 121
        self.assertEqual(other.read("source")["freshness"], "stale")

    def test_failure_retains_old_evidence_and_timestamp(self):
        good = self.cache.refresh("source", self.config, lambda config: snapshot())["snapshot"]
        self.now += 61
        def failed(config):
            raise RuntimeError("secret token must never reach API")
        result = self.cache.refresh("source", self.config, failed)
        self.assertEqual(result["snapshot"], good)
        self.assertEqual(result["last_attempt"]["status"], "error")
        self.assertNotIn("secret", result["last_attempt"]["message"])
        self.assertEqual(result["age_seconds"], 61)

    def test_partial_scope_retains_old_workloads_with_old_age(self):
        self.cache.refresh("source", self.config, lambda config: snapshot())
        self.now += 121
        result = self.cache.refresh("source", self.config, lambda config: snapshot(1121, scope_status="unavailable", workloads=False))
        self.assertEqual(result["freshness"], "fresh")
        self.assertEqual(result["last_attempt"]["status"], "partial")
        self.assertEqual(result["snapshot"]["workloads"][0]["observed_at"], snapshot()["observed_at"])
        self.now += 61
        result = self.cache.refresh("source", self.config, lambda config: snapshot(1182, workloads=False))
        self.assertEqual(result["snapshot"]["workloads"], [])

    def test_wrong_identity_and_future_timestamp_never_replace_snapshot(self):
        good = self.cache.refresh("source", self.config, lambda config: snapshot())["snapshot"]
        for change in (lambda s: s.update(host_id="another"), lambda s: s["host"].update(hostname="other"), lambda s: s.update(observed_at="2999-01-01T00:00:00+00:00")):
            self.now += 61
            bad = snapshot(self.now)
            change(bad)
            result = self.cache.refresh("source", self.config, lambda config: bad)
            self.assertEqual(result["snapshot"], good)
            self.assertEqual(result["last_attempt"]["status"], "error")

    def test_device_busy_does_not_destroy_snapshot(self):
        good = self.cache.refresh("source", self.config, lambda config: snapshot())["snapshot"]
        self.now += 61
        def busy(config):
            raise LeaseBusy("busy")
        result = self.cache.refresh("source", self.config, busy)
        self.assertEqual(result["snapshot"], good)
        self.assertEqual(result["last_attempt"]["status"], "busy")

    def test_single_flight_excludes_another_cache_client(self):
        entered, release = threading.Event(), threading.Event()
        other = ObservationCache(self.temp.name, "test", clock=lambda: self.now)
        def slow(config):
            entered.set()
            if not release.wait(3):
                raise RuntimeError("test coordination timed out")
            return snapshot()
        with ThreadPoolExecutor(max_workers=1) as executor:
            first = executor.submit(self.cache.refresh, "source", self.config, slow)
            try:
                self.assertTrue(entered.wait(2))
                second = other.refresh("source", self.config, lambda config: self.fail("duplicate collection"))
                self.assertEqual(second["last_attempt"]["status"], "busy")
                self.assertIsNone(second["snapshot"])
            finally:
                release.set()
            self.assertEqual(first.result(timeout=3)["last_attempt"]["status"], "success")

    def test_namespaces_do_not_share_authority(self):
        self.cache.refresh("source", self.config, lambda config: snapshot())
        changed = ObservationCache(self.temp.name, "changed-config", clock=lambda: self.now)
        self.assertIsNone(changed.read("source")["snapshot"])

    def test_failed_resource_keeps_its_age_while_other_scopes_advance(self):
        first = snapshot()
        first["cpu"].update(utilization_percent=25, sample_seconds=0.1)
        first["coverage"] += [{"scope": scope, "status": "complete", "message": ""} for scope in ("cpu", "memory")]
        self.cache.refresh("source", self.config, lambda config: first)
        self.now = 1121
        second = snapshot(1121, workloads=False)
        second["coverage"] = [{"scope": "cpu", "status": "unavailable", "message": "Unavailable"},
                              {"scope": "memory", "status": "complete", "message": ""},
                              {"scope": "podman:user:1000", "status": "complete", "message": ""}]
        second["memory"]["available_bytes"] = 3000
        result = self.cache.refresh("source", self.config, lambda config: second)
        saved = result["snapshot"]
        self.assertEqual(result["freshness"], "fresh")
        self.assertEqual(saved["cpu"]["utilization_percent"], 25)
        self.assertEqual(saved["resource_observed_at"]["cpu"], first["observed_at"])
        self.assertEqual(saved["resource_observed_at"]["memory"], second["observed_at"])
        self.assertEqual(saved["memory"]["available_bytes"], 3000)
        self.assertEqual(saved["workloads"][0]["observed_at"], first["observed_at"])
        systemd = next(c for c in saved["coverage"] if c["scope"] == "systemd:user:1000")
        self.assertEqual(systemd["observed_at"], first["observed_at"])
        self.assertEqual(result["last_attempt"]["status"], "partial")

    def test_artifact_removal_requires_its_own_complete_scope(self):
        first = snapshot(workloads=False)
        first["artifacts"] = [{"id": "installed-app", "host_id": "source", "backend": "android-package",
                               "scope": "user:0", "native_id": "example.app", "name": "Example",
                               "kind": "package", "observed_at": first["observed_at"], "extensions": {"android.v1": {}}}]
        first["coverage"] = [{"scope": "android-package:user:0", "status": "complete", "message": ""}]
        self.cache.refresh("source", self.config, lambda config: first)
        for offset, scope, status, count in ((61, "android:user:0", "complete", 1),
                                           (122, "android-package:user:0", "unavailable", 1),
                                           (183, "android-package:user:0", "complete", 0)):
            self.now = 1000 + offset
            current = snapshot(self.now, workloads=False)
            current["coverage"] = [{"scope": scope, "status": status, "message": ""}]
            saved = self.cache.refresh("source", self.config, lambda config: current)["snapshot"]
            self.assertEqual(len(saved["artifacts"]), count)
            self.assertEqual(saved["workloads"], [])
            if count:
                self.assertEqual(saved["artifacts"][0]["observed_at"], first["observed_at"])

    def test_invalid_readings_and_unversioned_extensions_refused(self):
        for mutate in (lambda s: s["cpu"].update(utilization_percent=101),
                       lambda s: s["cpu"].update(utilization_percent=5, sample_seconds=None),
                       lambda s: s["memory"].update(available_bytes=-1),
                       lambda s: s["workloads"][0].update(extensions={"systemd": {}})):
            value = snapshot()
            mutate(value)
            with self.assertRaises(ValidationError):
                Snapshot.model_validate(value)

    def test_automatic_lanes_never_starve_manual_or_each_other(self):
        for lane in ("fast", "storage", "inventory"):
            self.cache.refresh("source", self.config, lambda config: snapshot(), lane=lane)
        self.assertEqual(self.cache.read("source")["retry_after_seconds"], 0)
        manual = Mock(return_value=snapshot())
        self.cache.refresh("source", self.config, manual)
        manual.assert_called_once()
        self.now += 10
        fast = Mock(return_value=snapshot(self.now))
        self.cache.refresh("source", self.config, fast, lane="fast")
        fast.assert_called_once()
        self.assertEqual(self.cache.read("source")["retry_after_seconds"], 50)

    def test_automatic_only_cache_reopen_does_not_create_manual_cooldown(self):
        self.cache.refresh("source", self.config, lambda config: snapshot(), lane="fast")
        reopened = ObservationCache(self.temp.name, "test", clock=lambda: self.now)
        self.assertEqual(reopened.read("source")["retry_after_seconds"], 0)

    def test_all_lanes_and_namespaces_share_host_single_flight(self):
        entered, release = threading.Event(), threading.Event()
        other = ObservationCache(self.temp.name, "other", clock=lambda: self.now)
        def slow(config):
            entered.set()
            if not release.wait(3):
                raise RuntimeError("coordination timed out")
            return snapshot()
        with ThreadPoolExecutor(max_workers=1) as executor:
            first = executor.submit(self.cache.refresh, "source", self.config, slow, lane="inventory")
            try:
                self.assertTrue(entered.wait(2))
                for lane in ("manual", "fast", "storage", "inventory"):
                    result = other.refresh("source", self.config, Mock(side_effect=AssertionError("overlap")), lane=lane)
                    self.assertEqual(result["last_attempt"]["status"], "busy")
            finally:
                release.set()
            first.result(timeout=3)

    def test_fast_and_storage_preserve_omitted_scope_evidence_and_timestamps(self):
        initial = snapshot()
        initial["coverage"] += [{"scope": scope, "status": "complete", "message": ""}
                                for scope in ("cpu", "memory", "gpus", "storage")]
        initial["storage"]["filesystems"] = []
        initial["artifacts"] = [{"id": "image", "host_id": "source", "backend": "docker",
                                  "scope": "system", "native_id": "sha256:fixture", "name": "fixture",
                                  "kind": "image", "observed_at": initial["observed_at"],
                                  "extensions": {"container.v1": {}}}]
        initial["coverage"].append({"scope": "docker:system", "status": "complete", "message": ""})
        self.cache.refresh("source", self.config, lambda config: initial)
        self.now += 10
        fast = snapshot(self.now)
        fast["coverage"] = [{"scope": "cpu", "status": "partial", "message": "counters"}]
        saved = self.cache.refresh("source", self.config, lambda config: fast, lane="fast")["snapshot"]
        for resource in ("memory", "gpus", "storage"):
            self.assertEqual(saved["resource_observed_at"][resource], initial["observed_at"])
        self.assertEqual(saved["artifacts"][0]["observed_at"], initial["observed_at"])
        self.now += 60
        storage = snapshot(self.now, workloads=False)
        storage["coverage"] = [{"scope": "storage", "status": "complete", "message": ""}]
        saved = self.cache.refresh("source", self.config, lambda config: storage, lane="storage")["snapshot"]
        self.assertEqual(saved["resource_observed_at"]["cpu"], fast["observed_at"])
        self.assertEqual(saved["resource_observed_at"]["storage"], storage["observed_at"])
        self.assertEqual(saved["artifacts"][0]["observed_at"], initial["observed_at"])
        self.assertEqual(saved["workloads"][0]["observed_at"], fast["observed_at"])

    def test_revision_changes_on_writes_not_ordinary_age(self):
        revision = self.cache.revision()
        self.now += 20
        self.cache.read("source")
        self.assertEqual(self.cache.revision(), revision)
        self.cache.refresh("source", self.config, lambda config: snapshot(self.now))
        self.assertNotEqual(self.cache.revision(), revision)
        revision = self.cache.revision()
        self.now += 200
        self.assertEqual(self.cache.revision(), revision)

    def test_automatic_failure_retry_is_owned_by_scheduler_not_inventory_cooldown(self):
        failed = Mock(side_effect=RuntimeError("transport unavailable"))
        self.assertEqual(self.cache.refresh("source", self.config, failed, lane="inventory")["last_attempt"]["status"], "error")
        self.now += 10
        recovered = Mock(return_value=snapshot(self.now))
        self.cache.refresh("source", self.config, recovered, lane="inventory")
        recovered.assert_called_once()
        self.assertEqual(self.cache.read("source")["retry_after_seconds"], 0)


class FleetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.catalog = self.root / "catalog.json"
        catalog = json.loads((ROOT / "catalogs/example.json").read_text())
        definition = catalog["workloads"][0]
        definition.update(id="notes", name="Test service", purpose="An explicitly defined test service.",
                          backend="systemd", requirements=["linux", "systemd"], recipe=None,
                          data_locations=[], dependencies=[], health_check=None)
        definition["bindings"] = [{"backend": "systemd", "scope": "user:1000",
                                   "selector": {"native_id": "notes.service"}, "role": "primary"}]
        self.catalog.write_text(json.dumps(catalog))
        self.config = self.root / "collectors.json"
        self.config.write_text(json.dumps({"schema_version": 1, "hosts": [{"host_id": "source", "transport": "local", "expected_hostname": "source", "user_units": ["notes.service"], "system_units": []}]}))

    def service(self):
        return Service(self.catalog, state_dir=self.root / "state", collectors_path=self.config)

    def test_fleet_reads_do_not_collect_and_new_instance_uses_cache(self):
        service = self.service()
        with patch("switchyard.core.collect_host") as collector:
            service.fleet()
            service.inventory()
            collector.assert_not_called()
            collector.return_value = snapshot(datetime.now(timezone.utc).timestamp())
            collected = service.collect_host("source")
            collector.assert_called_once()
            self.assertEqual(collected["workloads"][0]["health"], "unknown")
            self.service().fleet()
            service.collect_host("source")
            collector.assert_called_once()

    def test_defined_workload_plan_remains_blocked_and_evidence_bound(self):
        service = self.service()
        with patch("switchyard.core.collect_host", return_value=snapshot(datetime.now(timezone.utc).timestamp())):
            service.collect_host("source")
        with self.assertRaises(ValueError):
            service.plan_migration("source-service", "destination")
        plan = service.plan_migration("notes", "destination")
        self.assertFalse(plan["executable"])
        self.assertEqual(plan["backend_resource"]["native_id"], "notes.service")
        self.assertTrue(any("No service-specific" in item for item in plan["blockers"]))
        self.assertEqual(plan["evidence"]["source"]["freshness"], "fresh")
        self.assertEqual(plan["evidence"]["destination"]["freshness"], "never")

    def test_installed_artifact_is_not_an_active_workload_or_migration_candidate(self):
        service = self.service()
        value = snapshot(datetime.now(timezone.utc).timestamp(), workloads=False)
        value["artifacts"] = [{"id": "installed-app", "host_id": "source", "backend": "android-package",
                              "scope": "user:0", "native_id": "example.app", "name": "Example",
                              "kind": "package", "observed_at": value["observed_at"], "extensions": {"android.v1": {}}}]
        value["coverage"] = [{"scope": "android-package:user:0", "status": "complete", "message": ""}]
        with patch("switchyard.core.collect_host", return_value=value):
            result = service.collect_host("source")
        self.assertEqual(result["resources"], [])
        self.assertEqual(result["workloads"][0]["lifecycle"], "unknown")
        self.assertEqual(result["workloads"][0]["resource_ids"], [])
        self.assertEqual(result["artifacts"][0]["native_id"], "example.app")
        source = next(host for host in result["hosts"] if host["id"] == "source")
        self.assertFalse(source["capabilities"]["execute"])
        self.assertEqual(source["capabilities"]["approval"], "not-granted")
        with self.assertRaises(ValueError):
            service.plan_migration("installed-app", "destination")

    def test_unknown_or_disabled_host_cannot_reach_collector(self):
        with patch("switchyard.core.collect_host") as collector:
            for host in ("destination", "unlisted", [], "source;whoami"):
                with self.assertRaises(ValueError):
                    self.service().collect_host(host)
            collector.assert_not_called()


if __name__ == "__main__":
    unittest.main()
