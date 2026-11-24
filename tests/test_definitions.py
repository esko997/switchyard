from copy import deepcopy
from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from switchyard.definitions import resolve_definitions, validate_definitions
from switchyard.models import Workload
from switchyard.observations import TTL_SECONDS


NOW = datetime(2026, 11, 22, 12, tzinfo=timezone.utc).timestamp()


def binding(native="app.service", *, backend="systemd", scope="user:1000", role="primary", name=None):
    return {"backend": backend, "scope": scope,
            "selector": {"native_id": native} if name is None else {"name": name}, "role": role}


def definition(identity="app", **changes):
    return {"id": identity, "name": "Deliberate application", "purpose": "Serve the operator's application",
            "device_id": "one", "backend": "systemd", "management": "observed", "kind": "service",
            "bindings": [binding()], "requirements": ["linux"], "architectures": ["x86_64"],
            "recipe": None, "notes": "Observation and proposals only", "health_check": None,
            "data_locations": [], "dependencies": [], "supported_operations": ["observe", "plan-migration"],
            "runtime": None, **changes}


def resource(native="app.service", *, host="one", backend="systemd", scope="user:1000",
             name=None, lifecycle="running", kind="service", seconds=1):
    at = datetime.fromtimestamp(NOW - seconds, timezone.utc).isoformat()
    value = Workload.model_validate({
        "id": ":".join((host, backend, scope, native)), "host_id": host, "backend": backend,
        "scope": scope, "native_id": native, "name": name or native, "kind": kind,
        "lifecycle": lifecycle, "health": "unknown", "management": "discovered",
        "observed_at": at, "extensions": {},
    }).model_dump()
    return {**value, "age_seconds": seconds, "freshness": "fresh" if seconds < TTL_SECONDS else "stale"}


class DefinitionValidationTests(unittest.TestCase):
    def validate(self, records):
        return validate_definitions(records, {"one", "two"})

    def test_sanitizes_without_mutating_or_sharing_nested_configuration(self):
        # Recipes are validated here too now (planning.validate_recipe); test_core covers their contract.
        source = definition(health_check="GET / must contain expected content (description only)",
                            data_locations=["/srv/app"])
        before = deepcopy(source)
        result = self.validate([source])[0]
        self.assertEqual(result, source)
        self.assertEqual(source, before)
        result["bindings"][0]["selector"]["native_id"] = "changed.service"
        result["data_locations"].append("changed")
        result["requirements"].append("changed")
        self.assertEqual(source, before)

    def test_runtime_is_optional_validated_and_matches_the_backend(self):
        older = definition()
        del older["runtime"]
        self.assertIsNone(self.validate([older])[0]["runtime"])
        compose = {"kind": "compose", "provider": "podman-compose", "project_name": "app", "project_directory": "/srv/app",
                   "files": ["/srv/app/compose.yaml"], "services": ["web"]}
        container = definition(backend="podman", bindings=[binding(backend="podman", name="app-web")], runtime=compose)
        self.assertEqual(self.validate([container])[0]["runtime"], compose)
        for label, value in (("compose on a systemd unit", definition(runtime=compose)),
                             ("docker provider on podman", definition(backend="podman", bindings=[binding(backend="podman", name="app-web")],
                                                                      runtime={**compose, "provider": "docker-compose-v2"})),
                             ("timer with a runtime", definition(kind="scheduled-job", runtime={"kind": "quadlet"})),
                             ("unknown field", definition(runtime={"kind": "quadlet", "unit": "app.service"})),
                             ("relative manifest", definition(backend="podman", bindings=[binding(backend="podman", name="app-web")],
                                                              runtime={**compose, "files": ["compose.yaml"]}))):
            with self.subTest(case=label), self.assertRaisesRegex(ValueError, "runtime"):
                self.validate([value])

    def test_requires_exact_definition_fields_and_known_host(self):
        missing = definition()
        del missing["purpose"]
        for value in (missing, definition(extra="secret"), definition(device_id="missing"),
                      definition(id="App"), definition(id="a" * 65), definition(management="discovered"),
                      definition(kind="environment"), definition(backend="docker")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validate([value])

    def test_exact_selectors_reject_patterns_unknown_keys_and_systemd_name(self):
        invalid = [
            {**binding(), "selector": {}},
            {**binding(), "selector": {"native_id": "app.service", "name": "app"}},
            {**binding(), "selector": {"label": "app"}},
            binding("app*.service"), binding("app?.service"), binding(" app.service"),
            binding("app.service\n"), binding(""), binding(name="app.service"),
            binding(backend="docker", name="app*"), binding(backend="podman", name="app/name"),
            {**binding(), "extra": True}, {**binding(), "role": "helper"},
            {**binding(), "scope": "user:1000\n"},
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validate([definition(bindings=[value])])
        for backend in ("docker", "podman"):
            result = self.validate([definition(backend=backend, bindings=[binding(backend=backend, name="exact-app")])])
            self.assertEqual(result[0]["bindings"][0]["selector"], {"name": "exact-app"})

    def test_requires_one_primary_and_rejects_duplicate_bindings(self):
        for bindings in ([], [binding(role="supporting")],
                         [binding(), binding("other.service")], [binding(), binding()],
                         [binding(), binding(role="supporting")]):
            with self.subTest(bindings=bindings), self.assertRaises(ValueError):
                self.validate([definition(bindings=bindings)])
        result = self.validate([definition(bindings=[binding(), binding("app.timer", role="supporting")])])
        self.assertEqual(len(result[0]["bindings"]), 2)

    def test_duplicate_definitions_or_primary_targets_are_rejected(self):
        for second in (definition(), definition("alias")):
            with self.subTest(second=second), self.assertRaises(ValueError):
                self.validate([definition(), second])
        # Exact targets on different hosts or scopes are not ambiguous declarations.
        self.assertEqual(len(self.validate([definition(), definition("other", device_id="two")])), 2)
        self.assertEqual(len(self.validate([definition(), definition("other", bindings=[binding(scope="system")])])), 2)

    def test_only_public_observation_and_proposal_operations(self):
        for operations in ([], ["observe"], ["observe", "stop"], ["observe", "observe"],
                           ["observe", "plan-migration", "start"]):
            with self.subTest(operations=operations), self.assertRaises(ValueError):
                self.validate([definition(supported_operations=operations)])

    def test_bounds_strings_collections_and_recipe_without_executing_descriptions(self):
        for changes in ({"name": "x" * 4097}, {"purpose": "x" * 8193}, {"notes": ""},
                        {"health_check": "x" * 8193}, {"requirements": ["x" * 4097]},
                        {"data_locations": [str(i) for i in range(129)]},
                        {"architectures": [str(i) for i in range(65)]},
                        {"bindings": [binding(str(i)) for i in range(129)]},
                        {"requirements": ["linux", "linux"]}, {"recipe": []},
                        {"recipe": {"large": "x" * 65536}}, {"recipe": {"bad": float("nan")}}):
            with self.subTest(fields=list(changes)), self.assertRaises(ValueError):
                self.validate([definition(**changes)])
        with self.assertRaises(ValueError):
            self.validate([definition(str(i)) for i in range(129)])
        result = self.validate([definition(health_check="curl http://example.invalid/; never execute")])
        self.assertIn("never execute", result[0]["health_check"])

    def test_dependencies_must_exist_and_be_acyclic(self):
        other = definition("helper", bindings=[binding("helper.service")])
        result = self.validate([definition(dependencies=["helper"]), other])
        self.assertEqual(result[0]["dependencies"], ["helper"])
        invalid = [
            [definition(dependencies=["absent"])],
            [definition(dependencies=["app"])],
            [definition(dependencies=["helper", "helper"]), other],
            [definition(dependencies=["helper"]), {**other, "dependencies": ["app"]}],
        ]
        third = definition("third", bindings=[binding("third.service")], dependencies=["app"])
        invalid.append([definition(dependencies=["helper"]), {**other, "dependencies": ["third"]}, third])
        for records in invalid:
            with self.subTest(records=records), self.assertRaises(ValueError):
                self.validate(records)


class DefinitionResolutionTests(unittest.TestCase):
    def resolve(self, value, resources):
        definitions = validate_definitions([value], {"one", "two"})
        with patch("switchyard.definitions.time.time", return_value=NOW):
            return resolve_definitions(definitions, resources)[0]

    def test_exact_native_binding_excludes_wrong_host_backend_scope_and_similar_name(self):
        correct = resource()
        others = [resource(host="two"), resource(backend="docker"), resource(scope="system"),
                  resource("app-helper.service"), resource("other.service", name="app.service")]
        result = self.resolve(definition(), [*others, correct])
        self.assertEqual(result["resource_ids"], [correct["id"]])
        self.assertEqual(result["bindings_evidence"], [
            {"binding": binding(), "matches": [correct["id"]], "status": "matched"}])
        self.assertEqual(result["lifecycle"], "running")
        self.assertEqual(result["health"], "unknown")
        self.assertEqual(result["authority"], {"execute": False, "approval": "not-granted"})
        self.assertEqual(result["freshness_ttl_seconds"], TTL_SECONDS)
        for field, value in definition().items():
            self.assertEqual(result[field], value)

    def test_wrong_scope_never_satisfies_a_primary(self):
        result = self.resolve(definition(), [resource(scope="system"), resource(scope="user:1001")])
        self.assertEqual(result["bindings_evidence"][0]["status"], "missing")
        self.assertEqual(result["resource_ids"], [])
        self.assertEqual(result["freshness_ttl_seconds"], TTL_SECONDS)
        self.assertEqual((result["lifecycle"], result["freshness"], result["observed_at"], result["age_seconds"]),
                         ("unknown", "never", None, None))

    def test_name_binding_resolves_full_observed_identity_but_does_not_pin_incarnation(self):
        value = definition(backend="docker", bindings=[binding(backend="docker", scope="system", name="exact-app")])
        old = resource("a" * 64, backend="docker", scope="system", name="exact-app")
        replacement = resource("b" * 64, backend="docker", scope="system", name="exact-app")
        for observed in (old, replacement):
            result = self.resolve(value, [observed])
            self.assertEqual(result["resource_ids"], [observed["id"]])
            self.assertEqual(result["bindings"][0]["selector"], {"name": "exact-app"})
        pinned = {**value, "bindings": [binding("a" * 64, backend="docker", scope="system")]}
        self.assertEqual(self.resolve(pinned, [replacement])["bindings_evidence"][0]["status"], "missing")

    def test_ambiguous_primary_is_evidence_not_an_arbitrary_running_selection(self):
        value = definition(backend="podman", bindings=[binding(backend="podman", name="app")])
        resources = [resource("a" * 64, backend="podman", name="app"), resource("b" * 64, backend="podman", name="app")]
        result = self.resolve(value, resources)
        self.assertEqual(result["bindings_evidence"][0]["status"], "ambiguous")
        self.assertEqual(result["bindings_evidence"][0]["matches"], [r["id"] for r in resources])
        self.assertEqual(result["resource_ids"], [])
        self.assertEqual((result["lifecycle"], result["freshness"]), ("unknown", "never"))

    def test_fresh_helper_cannot_fill_missing_or_stale_primary_evidence(self):
        value = definition(bindings=[binding(), binding("helper.service", role="supporting")])
        helper = resource("helper.service", seconds=0)
        missing = self.resolve(value, [helper])
        self.assertEqual(missing["resource_ids"], [helper["id"]])
        self.assertEqual((missing["lifecycle"], missing["freshness"], missing["observed_at"]), ("unknown", "never", None))
        primary = resource(seconds=TTL_SECONDS)
        stale = self.resolve(value, [primary, helper])
        self.assertEqual(stale["freshness"], "stale")
        self.assertEqual(stale["lifecycle"], "unknown")
        self.assertEqual(stale["observed_at"], primary["observed_at"])
        self.assertEqual(stale["age_seconds"], TTL_SECONDS)
        self.assertEqual(stale["health"], "unknown")

    def test_failed_support_is_linked_without_inventing_primary_health(self):
        helper = resource("helper.service", lifecycle="failed", seconds=0)
        primary = resource(seconds=30)
        value = definition(bindings=[binding(), binding("helper.service", role="supporting")])
        result = self.resolve(value, [primary, helper])
        self.assertEqual(result["bindings_evidence"][1]["matches"], [helper["id"]])
        self.assertIn(helper["id"], result["resource_ids"])
        self.assertEqual(result["lifecycle"], "running")
        self.assertEqual(result["health"], "unknown")
        self.assertEqual(result["observed_at"], primary["observed_at"])
        self.assertEqual(result["age_seconds"], 30)

    def test_idle_timer_does_not_make_a_scheduled_job_stopped(self):
        timer = resource("app.timer", lifecycle="idle", kind="scheduled-job")
        helper = resource(lifecycle="stopped")
        value = definition(kind="scheduled-job", bindings=[binding("app.timer"), binding(role="supporting")])
        result = self.resolve(value, [timer, helper])
        self.assertEqual(result["lifecycle"], "idle")
        self.assertEqual(result["health"], "unknown")
        self.assertEqual(result["freshness"], "fresh")

    def test_matching_environment_is_not_promoted_into_a_service(self):
        value = definition(backend="podman", bindings=[binding(backend="podman", name="ubuntu")])
        environment = resource("e" * 64, backend="podman", name="ubuntu", kind="environment")
        result = self.resolve(value, [environment])
        self.assertEqual(result["bindings_evidence"][0]["status"], "mismatch")
        self.assertEqual(result["bindings_evidence"][0]["matches"], [environment["id"]])
        self.assertEqual(result["resource_ids"], [])
        self.assertEqual((result["lifecycle"], result["freshness"], result["observed_at"]), ("unknown", "never", None))

    def test_raw_resource_timing_uses_existing_ttl_and_never_fabricates_missing_time(self):
        primary = resource(seconds=TTL_SECONDS + 1)
        del primary["freshness"]
        del primary["age_seconds"]
        result = self.resolve(definition(), [primary])
        self.assertEqual((result["freshness"], result["age_seconds"], result["lifecycle"]),
                         ("stale", TTL_SECONDS + 1, "unknown"))
        primary["observed_at"] = None
        result = self.resolve(definition(), [primary])
        self.assertEqual((result["freshness"], result["age_seconds"], result["lifecycle"]), ("never", None, "unknown"))

    def test_cadence_ttl_comes_from_primary_not_a_fresher_helper(self):
        primary = {**resource(seconds=180), "freshness": "fresh", "freshness_ttl_seconds": 600}
        helper = {**resource("helper.service", seconds=0), "freshness_ttl_seconds": 20}
        value = definition(bindings=[binding(), binding("helper.service", role="supporting")])
        result = self.resolve(value, [primary, helper])
        self.assertEqual(result["freshness_ttl_seconds"], 600)
        self.assertEqual((result["freshness"], result["lifecycle"]), ("fresh", "running"))
        self.assertEqual(result["age_seconds"], 180)
        primary["freshness"] = "stale"
        self.assertEqual(self.resolve(value, [primary, helper])["freshness"], "stale")

    def test_ambiguous_primary_does_not_adopt_a_candidate_ttl(self):
        value = definition(backend="podman", bindings=[binding(backend="podman", name="app")])
        resources = [
            {**resource("a" * 64, backend="podman", name="app"), "freshness_ttl_seconds": 600},
            {**resource("b" * 64, backend="podman", name="app"), "freshness_ttl_seconds": 900},
        ]
        result = self.resolve(value, resources)
        self.assertEqual(result["freshness_ttl_seconds"], TTL_SECONDS)
        self.assertEqual(result["freshness"], "never")

    def test_legacy_distrobox_metadata_cannot_claim_a_running_service(self):
        value = definition(backend="podman", bindings=[binding(backend="podman", name="ubuntu")])
        environment = resource("e" * 64, backend="podman", name="ubuntu", kind="service")
        environment["extensions"] = {"container.v1": {"environment": "distrobox"}}
        result = self.resolve(value, [environment])
        self.assertEqual(result["bindings_evidence"][0]["status"], "mismatch")
        self.assertEqual(result["bindings_evidence"][0]["matches"], [environment["id"]])
        self.assertEqual(result["resource_ids"], [])
        self.assertEqual((result["lifecycle"], result["freshness"]), ("unknown", "never"))

    def test_resolution_does_not_mutate_inputs_or_share_output_bindings(self):
        source, observed = definition(), resource()
        before = deepcopy((source, observed))
        result = self.resolve(source, [observed])
        result["bindings"][0]["selector"]["native_id"] = "changed"
        result["bindings_evidence"][0]["binding"]["selector"]["native_id"] = "also-changed"
        self.assertEqual((source, observed), before)


if __name__ == "__main__":
    unittest.main()
