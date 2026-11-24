import copy
import json
from pathlib import Path
import tempfile
import unittest

from switchyard.core import Service

ROOT = Path(__file__).resolve().parents[1]


class PlanningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "catalog.json"
        self.catalog = json.loads((ROOT / "catalogs/example.json").read_text())

    def service(self):
        self.path.write_text(json.dumps(self.catalog))
        return Service(self.path, state_dir=Path(self.temp.name) / "state")

    def test_plan_orders_cold_migration_without_adopting_or_observing(self):
        service = self.service()
        original = service.inventory()
        before = self.path.read_bytes()
        plan = service.plan_migration("foobar", "destination")
        self.assertFalse(plan["executable"])
        self.assertEqual([step["action"] for step in plan["steps"]], [
            "preflight", "stop", "confirm-stopped", "transfer", "start", "verify", "cutover", "recovery"])
        self.assertTrue(any("no lifecycle authority" in b for b in plan["blockers"]))
        self.assertIsNone(plan["backend_resource"])
        checks = {check["id"]: check for check in plan["checks"]}
        for identity in ("artifact-digest", "source-binding", "destination-storage", "content-digest",
                         "dedicated-port", "http-body-verification", "recovery-before-cutover"):
            self.assertEqual(checks[identity]["status"], "blocked", identity)
        self.assertEqual(original, service.inventory())
        self.assertEqual(before, self.path.read_bytes())
        self.assertEqual(plan, service.plan_migration("foobar", "destination"))

    def edit_foobar(self, service, change):
        """After seeding the store is the authority: edit the definition there, as the editor does."""
        inventory = service.definition_inventory()
        definition = copy.deepcopy(next(item for item in inventory["workloads"] if item["id"] == "foobar"))
        change(definition)
        service.update_workload_definition("foobar", definition, expected_revision=inventory["revision"])

    def test_recipe_and_architecture_changes_invalidate_proposal(self):
        service = self.service()
        old = service.plan_migration("foobar", "destination")
        # Host declarations are edited in the registry; the catalog only seeds them.
        service.update_host("destination", {"architecture": "sparc64"}, expected_revision=service.hosts()["revision"])
        new = service.plan_migration("foobar", "destination")
        self.assertNotEqual(old["id"], new["id"])
        self.assertTrue(any("incompatible" in b for b in new["blockers"]))
        self.edit_foobar(service, lambda definition: definition["recipe"].update(transfer="A changed transfer requirement"))
        self.assertNotEqual(new["id"], self.service().plan_migration("foobar", "destination")["id"])

    def test_nested_recipe_evidence_changes_invalidate_proposal(self):
        service = self.service()
        old = service.plan_migration("foobar", "destination")
        self.edit_foobar(service, lambda definition: definition["recipe"]["site"].update(upper_bound_bytes=4096))
        new = self.service().plan_migration("foobar", "destination")
        self.assertNotEqual(old["id"], new["id"])
        self.assertFalse(new["executable"])

    def test_catalog_edits_after_seeding_are_ignored(self):
        before = self.service().plan_migration("foobar", "destination")
        self.catalog["workloads"][0]["recipe"]["site"]["upper_bound_bytes"] = 4096
        self.catalog["workloads"].append({**copy.deepcopy(self.catalog["workloads"][0]), "id": "smuggled"})
        service = self.service()
        self.assertEqual(before["id"], service.plan_migration("foobar", "destination")["id"])
        self.assertEqual([item["id"] for item in service.fleet()["workloads"]], ["foobar", "notes-sync"])  # not "smuggled"

    def test_recipe_contract_rejects_legacy_and_unverified_claims(self):
        original = copy.deepcopy(self.catalog["workloads"][0]["recipe"])
        invalid = [
            {key: original[key] for key in ("stop", "transfer", "start", "verify", "recovery")},
            {**original, "command": "not an executor"},
            {**original, "verification": {**original["verification"], "baseline": "verified"}},
            {**original, "artifact": {**original["artifact"], "password": "not allowed"}},
        ]
        for recipe in invalid:
            with self.subTest(recipe=recipe):
                self.catalog["workloads"][0]["recipe"] = recipe
                with self.assertRaises(ValueError):
                    self.service()

    def test_missing_recipe_and_unknown_architecture_are_blockers(self):
        self.catalog["workloads"][0]["recipe"] = None
        self.catalog["workloads"][0]["architectures"] = []
        plan = self.service().plan_migration("foobar", "destination")
        self.assertEqual(plan["steps"], [])
        self.assertTrue(any("compatibility is unknown" in b for b in plan["blockers"]))
        self.assertTrue(any("No service-specific" in b for b in plan["blockers"]))

    def test_cannot_smuggle_management_or_unknown_references(self):
        original = copy.deepcopy(self.catalog)
        mutations = [
            lambda c: c["workloads"][0].update(management="managed"),
            lambda c: c["workloads"][0].update(device_id="missing"),
            lambda c: c["devices"].append(copy.deepcopy(c["devices"][0])),
            lambda c: c["devices"][0].update(observed_at="2026-11-22"),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.catalog = copy.deepcopy(original)
                mutate(self.catalog)
                with self.assertRaises(ValueError):
                    self.service()

    def test_same_host_and_missing_capabilities_block(self):
        self.catalog["workloads"][0]["requirements"].append("cuda")
        plan = self.service().plan_migration("foobar", "source")
        self.assertTrue(any("same device" in b for b in plan["blockers"]))
        self.assertTrue(any("cuda" in b for b in plan["blockers"]))

    def test_unknown_ids_are_errors(self):
        service = self.service()
        for workload, target in [("missing", "destination"), ("foobar", "missing"), ([], "destination")]:
            with self.assertRaises(ValueError):
                service.plan_migration(workload, target)

    def test_local_observation_does_not_assign_identity_to_declared_device(self):
        service = self.service()
        snapshot = service.inventory()
        observed = service.observe_local()
        self.assertEqual(observed["scope"], "control-plane host only")
        self.assertEqual(service.inventory(), snapshot)
        self.assertNotIn("device_id", observed)


if __name__ == "__main__":
    unittest.main()
