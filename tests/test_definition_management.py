"""Observed-workload enrollment into the workload store, with local cached observations only."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from switchyard import lan_route_config
from switchyard.core import Service
from test_observations import snapshot


ROOT = Path(__file__).resolve().parents[1]


class DefinitionManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.catalog = json.loads((ROOT / "catalogs/example.json").read_text())
        self.catalog["workloads"] = []
        self.catalog["unrelated-extension"] = {"retain": [1, "operator-owned"]}
        self.catalog["application_groups"] = [{
            "id": "notes-group", "name": "Operator grouping", "host_id": "source",
            "backend": "systemd", "scope": "user:1000", "native_ids": ["notes.service"],
            "provenance": "Manually maintained",
        }]
        self.path = self.root / "catalog.json"
        self.path.write_text(json.dumps(self.catalog))
        self.path.chmod(0o640)
        self.config = {"host_id": "source", "transport": "local", "expected_hostname": "source",
                       "user_units": ["notes.service"], "system_units": [], "container_engines": ["podman"]}
        self.collectors = self.root / "collectors.json"
        self.collectors.write_text(json.dumps({"schema_version": 1, "hosts": [self.config]}))
        self.service = self.new_service()
        self.now = datetime.now(timezone.utc).timestamp()
        self.reading = snapshot(self.now)
        self.reading["coverage"].append({"scope": "podman:user:1000", "status": "complete", "message": "Fixture"})
        self.reading["workloads"].append({
            **deepcopy(self.reading["workloads"][0]), "id": "container-resource", "backend": "podman",
            "native_id": "a" * 64, "name": "switchyard-foobar", "extensions": {"container.v1": {}},
        })
        self.publish()

    def new_service(self):
        return Service(self.path, state_dir=self.root / "state", collectors_path=self.collectors)

    def publish(self):
        self.service._cache.clock = lambda: self.now
        self.service._cache.refresh("source", self.config, lambda _: deepcopy(self.reading))

    def proposal(self, *, resource_id="source-service", workload_id="notes", **kwargs):
        return self.service.propose_workload_definition(resource_id, workload_id=workload_id,
                                                        name="Notes", purpose="Named hosted service", **kwargs)

    def save(self, proposal=None):
        proposal = self.proposal() if proposal is None else proposal
        return self.service.save_workload_definition(proposal["definition"], expected_revision=proposal["revision"])

    def test_promotion_is_cache_only_and_never_infers_permission_or_unknown_facts(self):
        with patch("switchyard.core.collect_host", side_effect=AssertionError("No host I/O")), \
             patch("switchyard.broker.run_bounded", side_effect=AssertionError("No SSH")):
            proposal = self.proposal()
            saved = self.save(proposal)
            fleet = self.service.fleet()
        definition = saved["definition"]
        self.assertEqual(definition["bindings"][0]["selector"], {"native_id": "notes.service"})
        self.assertIsNone(definition["recipe"])
        self.assertIsNone(definition["health_check"])
        for field in ("requirements", "architectures", "data_locations", "dependencies"):
            self.assertEqual(definition[field], [])
        self.assertEqual(definition["supported_operations"], ["observe", "plan-migration"])
        self.assertFalse(fleet["workloads"][0]["authority"]["execute"])
        self.assertEqual(proposal["source_evidence"][0]["observed_at"], self.reading["observed_at"])
        self.assertNotEqual(saved["revision"], proposal["revision"])
        self.assertEqual(fleet["definition_revision"], saved["revision"])
        self.assertIn("integration", fleet["hosts"][0])

    def test_saves_into_the_store_never_the_catalog_file(self):
        before = self.path.read_bytes()
        saved = self.save()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(list(self.root.glob("*.definitions.lock")) + list(self.root.glob(".switchyard-*")))
        with self.service._store.transaction() as db:
            record = self.service._store.record(db, "notes")
        self.assertEqual((record["relation"], record["revision"]), ("observed", 1))
        self.assertEqual(record["data"]["placements"][0]["components"][0]["native_identities"][0]["native_id"], "notes.service")
        provenance = record["meta"]["definition_provenance"]
        self.assertEqual(provenance["method"], "cached-discovery")
        self.assertEqual(provenance["source_evidence"][0]["native_id"], "notes.service")
        self.assertEqual(self.service.definition_inventory()["workloads"], [saved["definition"]])

    def test_reviewed_web_endpoint_becomes_a_route_candidate_without_publishing(self):
        saved = self.save()
        endpoint = {"id": "desk", "address": "192.168.50.104", "port": 8710, "scheme": "http"}
        definition = {**saved["definition"], "endpoints": [endpoint]}
        updated = self.service.update_workload_definition("notes", definition, expected_revision=saved["revision"])
        other = self.new_service()
        self.assertEqual(other.definition_inventory()["workloads"][0]["endpoints"], [endpoint])
        config = lan_route_config.normalize({"gateway_id": "lan-web", "dns_id": "lan-dns",
                                              "zone": "example.test", "ca_sha256": "a" * 64})
        hosts = [{"id": "source", "collector": {"transport": "ssh", "target": "fixture@192.168.50.104"},
                  "verification": {"state": "verified"}}]
        rows = lan_route_config.endpoint_candidates(other._store, config, hosts=hosts)
        plan = lan_route_config.route(config, rows, "notes-desk", "notes", "desk")
        self.assertEqual((plan["address"], plan["port"], plan["scheme"]), ("192.168.50.104", 8710, "http"))
        other.update_workload_definition("notes", {**updated["definition"], "endpoints": []},
                                         expected_revision=updated["revision"])
        self.assertEqual(lan_route_config.endpoint_candidates(other._store, config, hosts=hosts), [])

    def test_endpoint_metadata_rejects_false_port_urls_and_duplicate_ids(self):
        proposal = self.proposal()
        endpoint = {"id": "web", "address": "192.168.50.104", "port": 8080, "scheme": "http"}
        for entries in ([{**endpoint, "port": True}], [{**endpoint, "address": "http://192.168.50.104"}],
                        [endpoint, {**endpoint, "port": 8081}]):
            with self.subTest(entries=entries), self.assertRaisesRegex(ValueError, "[Ee]ndpoint"):
                self.service.save_workload_definition({**proposal["definition"], "endpoints": entries},
                                                      expected_revision=proposal["revision"])
        self.assertEqual(self.service.definition_inventory()["workloads"], [])

    def test_other_live_service_refreshes_all_views_and_retains_cache_namespace(self):
        other = self.new_service()
        before = other.fleet_revision()
        saved = self.save()
        self.assertEqual(other.definition_inventory(), {"revision": saved["revision"], "workloads": [saved["definition"]]})
        self.assertEqual(other.inventory()["definition_revision"], saved["revision"])
        self.assertEqual(other.fleet()["workloads"][0]["id"], "notes")
        self.assertNotEqual(before, other.fleet_revision())
        self.assertEqual(other.fleet()["resources"][0]["observed_at"], self.reading["observed_at"])
        edited = deepcopy(saved["definition"])
        edited["name"] = "Reviewed name"
        self.service.update_workload_definition("notes", edited, expected_revision=saved["revision"])
        self.assertEqual(other.definition_inventory()["workloads"][0]["name"], "Reviewed name")

    def test_stale_revision_never_overwrites_another_client(self):
        first = self.proposal()
        second = self.proposal(resource_id="container-resource", workload_id="other")
        self.save(first)
        before = self.service.definition_inventory()
        with self.assertRaisesRegex(ValueError, "revision"):
            self.save(second)
        self.assertEqual(self.service.definition_inventory(), before)

    def test_catalog_edits_are_ignored_but_store_changes_invalidate_proposal(self):
        proposal = self.proposal()
        external = json.loads(self.path.read_text())
        external["workloads"] = deepcopy(json.loads((ROOT / "catalogs/example.json").read_text())["workloads"])
        self.path.write_text(json.dumps(external))
        self.assertEqual(self.service.definition_inventory()["revision"], proposal["revision"])
        self.assertEqual(self.new_service().definition_inventory()["workloads"], [])
        self.new_service().save_workload_definition(
            self.proposal(resource_id="container-resource", workload_id="other")["definition"], expected_revision=proposal["revision"])
        with self.assertRaisesRegex(ValueError, "revision"):
            self.save(proposal)
        self.assertNotEqual(self.service.definition_inventory()["revision"], proposal["revision"])

    def test_concurrent_clients_only_one_wins_same_revision(self):
        other = self.new_service()
        proposal = self.proposal()
        second = self.proposal(resource_id="container-resource", workload_id="other")
        gate = threading.Barrier(2)

        def save(service, candidate):
            gate.wait(timeout=5)
            try:
                return service.save_workload_definition(candidate["definition"], expected_revision=candidate["revision"])
            except ValueError as error:
                return error

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(save, service, candidate)
                       for service, candidate in ((self.service, proposal), (other, second))]
            results = [future.result(timeout=5) for future in futures]
        self.assertEqual(sum(isinstance(result, dict) for result in results), 1)
        self.assertEqual(sum(isinstance(result, ValueError) for result in results), 1)
        self.assertEqual(len(self.new_service().definition_inventory()["workloads"]), 1)

    def test_duplicate_id_and_alias_binding_rejected(self):
        proposal = self.proposal(resource_id="container-resource", workload_id="container")
        proposal["definition"]["bindings"][0]["selector"] = {"name": "switchyard-foobar"}
        saved = self.save(proposal)
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.service.save_workload_definition(saved["definition"], expected_revision=saved["revision"])
        with self.assertRaisesRegex(ValueError, "already belongs"):
            self.proposal(resource_id="container-resource", workload_id="alias")

    def test_duplicate_aliases_within_one_definition_rejected(self):
        proposal = self.proposal(resource_id="container-resource")
        duplicate = deepcopy(proposal["definition"]["bindings"][0])
        duplicate.update(role="supporting", selector={"name": "switchyard-foobar"})
        proposal["definition"]["bindings"].append(duplicate)
        with self.assertRaisesRegex(ValueError, "same resource"):
            self.save(proposal)

    def test_supporting_resources_are_explicit_and_same_host(self):
        proposal = self.proposal(supporting_resource_ids=["container-resource"])
        self.assertEqual([binding["role"] for binding in proposal["definition"]["bindings"]], ["primary", "supporting"])
        self.assertEqual(len(proposal["source_evidence"]), 2)
        for supporting in (["source-service"], ["container-resource", "container-resource"], ["missing"], "container-resource"):
            with self.subTest(supporting=supporting), self.assertRaises(ValueError):
                self.proposal(supporting_resource_ids=supporting)

    def test_environment_cannot_be_promoted_or_smuggled_in_crafted_save(self):
        proposal = self.proposal(resource_id="container-resource")
        self.now += 61
        self.reading["observed_at"] = datetime.fromtimestamp(self.now, timezone.utc).isoformat()
        for resource in self.reading["workloads"]:
            resource["observed_at"] = self.reading["observed_at"]
        self.reading["workloads"][1].update(kind="environment", extensions={"container.v1": {"environment": "distrobox"}})
        self.publish()
        with self.assertRaisesRegex(ValueError, "environment"):
            self.proposal(resource_id="container-resource")
        with self.assertRaisesRegex(ValueError, "Environments"):
            self.save(proposal)

    def test_disappeared_resource_blocks_save_even_with_current_catalog_revision(self):
        proposal = self.proposal()
        self.now += 61
        self.reading["observed_at"] = datetime.fromtimestamp(self.now, timezone.utc).isoformat()
        self.reading["workloads"] = []
        self.publish()
        with self.assertRaisesRegex(ValueError, "exactly one cached"):
            self.save(proposal)

    def test_lifecycle_authority_fields_and_operations_are_rejected(self):
        for field, value in (("lifecycle", "running"), ("authority", {"execute": True}),
                             ("supported_operations", ["observe", "restart"]), ("management", "managed")):
            proposal = self.proposal()
            proposal["definition"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.save(proposal)
        self.assertEqual(self.service.definition_inventory()["workloads"], [])

    def test_edit_preserves_id_and_does_not_require_old_manual_binding_to_be_observed(self):
        saved = self.save()
        self.now += 61
        self.reading["observed_at"] = datetime.fromtimestamp(self.now, timezone.utc).isoformat()
        self.reading["workloads"] = []
        self.publish()
        edited = deepcopy(saved["definition"])
        edited.update(name="Useful description", purpose="Operator-authored purpose")
        result = self.service.update_workload_definition("notes", edited, expected_revision=saved["revision"])
        self.assertEqual(result["definition"]["name"], edited["name"])
        edited["id"] = "renamed"
        with self.assertRaisesRegex(ValueError, "immutable"):
            self.service.update_workload_definition("notes", edited, expected_revision=result["revision"])

    def test_ambiguous_native_selector_is_not_a_definition_candidate(self):
        self.now += 61
        self.reading["observed_at"] = datetime.fromtimestamp(self.now, timezone.utc).isoformat()
        duplicate = deepcopy(self.reading["workloads"][0])
        duplicate.update(id="same-native-alias", observed_at=self.reading["observed_at"])
        self.reading["workloads"].append(duplicate)
        self.publish()
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            self.proposal()
        self.assertEqual(self.service.definition_inventory()["workloads"], [])

    def test_supporting_resource_cannot_already_belong_to_another_definition(self):
        self.save(self.proposal(resource_id="container-resource", workload_id="container"))
        with self.assertRaisesRegex(ValueError, "already belongs"):
            self.proposal(supporting_resource_ids=["container-resource"])

    def test_adopted_native_placement_cannot_be_redefined_under_another_id(self):
        proposal = self.proposal(resource_id="container-resource", workload_id="container")
        proposal["definition"]["bindings"][0]["selector"] = {"name": "switchyard-foobar"}
        self.save(proposal)
        # After a migration/replacement the owned incarnation may have a new name,
        # while the canonical name still describes its original deployment.
        self.now += 61
        self.reading["observed_at"] = datetime.fromtimestamp(self.now, timezone.utc).isoformat()
        self.reading["workloads"][1].update(name="replacement-name", observed_at=self.reading["observed_at"])
        self.publish()
        with patch.object(self.service._broker, "placements", return_value={
            "container": {"host_id": "source", "native_id": "a" * 64, "scope": "user:1000"}
        }):
            with self.assertRaisesRegex(ValueError, "already belongs"):
                self.proposal(resource_id="container-resource", workload_id="replacement")

    def test_managed_and_adopted_binding_changes_are_refused_but_descriptions_work(self):
        proposal = self.proposal(resource_id="container-resource", workload_id="foobar")
        proposal["definition"]["bindings"][0]["selector"] = {"name": "switchyard-foobar"}
        saved = self.save(proposal)
        policy = {"enabled": True, "shell_hosts": [], "workloads": [{
            "id": "foobar", "backend": "podman", "allowed_hosts": ["source"], "container_name": "switchyard-foobar",
        }]}
        for configured in (True, False):
            with self.subTest(configured=configured), \
                 patch.object(self.service._broker, "policy", return_value=policy if configured else {"enabled": False, "shell_hosts": [], "workloads": []}), \
                 patch.object(self.service._broker, "placements", return_value={"foobar": {"host_id": "source"}}):
                edited = deepcopy(saved["definition"])
                edited["name"] = "Description only"
                saved = self.service.update_workload_definition("foobar", edited, expected_revision=saved["revision"])
                edited["recipe"] = deepcopy(json.loads((ROOT / "catalogs/example.json").read_text())["workloads"][0]["recipe"])
                edited["recipe"]["source"]["backend"] = "podman"
                edited["recipe"]["source"]["scope"] = "user:1000"
                with self.assertRaises(ValueError):
                    self.service.update_workload_definition("foobar", edited, expected_revision=saved["revision"])
                edited = deepcopy(saved["definition"])
                edited["bindings"].append({"backend": "systemd", "scope": "user:1000",
                                            "selector": {"native_id": "notes.service"}, "role": "supporting"})
                with self.assertRaisesRegex(ValueError, "Managed/adopted"):
                    self.service.update_workload_definition("foobar", edited, expected_revision=saved["revision"])

    def test_recipe_binding_mismatch_rejected_before_write(self):
        proposal = self.proposal()
        proposal["definition"]["recipe"] = deepcopy(json.loads((ROOT / "catalogs/example.json").read_text())["workloads"][0]["recipe"])
        before = self.service.definition_inventory()
        with self.assertRaisesRegex(ValueError, "Migration recipe"):
            self.save(proposal)
        self.assertEqual(before, self.service.definition_inventory())

    def test_seeded_catalog_definitions_work_without_discovery(self):
        catalog = deepcopy(self.catalog)
        catalog["workloads"] = deepcopy(json.loads((ROOT / "catalogs/example.json").read_text())["workloads"])
        self.path.write_text(json.dumps(catalog))
        seeded = Service(self.path, state_dir=self.root / "fresh-state", collectors_path=self.collectors)
        self.assertEqual(seeded.definition_inventory()["workloads"][0]["id"], "foobar")
        self.assertEqual(seeded.definition_inventory()["workloads"][0]["management"], "observed")

    def test_cached_fleet_remains_readable_during_remote_operation(self):
        entered, release = threading.Event(), threading.Event()

        def remote(*args, **kwargs):
            entered.set()
            release.wait(5)
            return {"receipt": {"status": "succeeded"}}

        with patch.object(self.service._broker, "shell", side_effect=remote), ThreadPoolExecutor(max_workers=2) as pool:
            operation = pool.submit(self.service.run_shell, "source", "true", request_id="concurrent-read")
            try:
                self.assertTrue(entered.wait(2))
                view = pool.submit(self.service.fleet).result(timeout=2)
                self.assertEqual({host["id"] for host in view["hosts"]}, {"source", "destination"})
                self.assertFalse(operation.done())
            finally:
                release.set()
            self.assertEqual(operation.result(timeout=2)["receipt"]["status"], "succeeded")


if __name__ == "__main__":
    unittest.main()
