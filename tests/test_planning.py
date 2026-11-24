"""Synthetic offline evidence only; no container or HTTP rehearsal is run."""
import copy
import hashlib
import json
from pathlib import Path
import unittest

from switchyard.planning import assess_recipe, validate_recipe


ROOT = Path(__file__).resolve().parents[1]
AT = "2026-11-22T12:00:00+00:00"
OLD = "2026-11-22T11:50:00+00:00"
CONTAINER_ID = "1" * 64
IMAGE_ID = "sha256:" + "a" * 64  # Synthetic fixture, never a deployed image claim.


def observed_workload(host="source"):
    return {
        "id": host + ":fixture", "host_id": host, "backend": "docker", "scope": "system",
        "native_id": CONTAINER_ID, "name": "switchyard-foobar", "lifecycle": "stopped",
        "health": "unknown", "observed_at": AT,
        "extensions": {"container.v1": {
            "image_id": IMAGE_ID, "image_reference": "nginxinc/nginx-unprivileged:1.28.0-alpine",
            "mounts": [{"source": "/srv/switchyard-foobar/index.html",
                        "destination": "/usr/share/nginx/html/index.html", "type": "bind", "read_only": True}],
        }},
    }


def observation(host):
    return {
        "snapshot": {
            "host_id": host, "observed_at": AT, "host": {"architecture": "x86_64"},
            "resource_observed_at": {key: AT for key in ("host", "cpu", "memory", "storage")},
            "cpu": {"logical_count": 4}, "memory": {"available_bytes": 1024**3},
            "storage": {"filesystems": [{
                "id": "fictional-foobar-pool", "mounts": ["/srv"], "available_bytes": 1024**3,
                "kind": "persistent", "read_only": False,
            }]},
            "coverage": [{"scope": scope, "status": "complete", "observed_at": AT}
                         for scope in ("cpu", "memory", "storage", "docker:system")],
            "workloads": [], "artifacts": [],
        },
        "freshness": "fresh", "age_seconds": 1, "last_attempt": {"status": "success"},
    }


class RecipeTests(unittest.TestCase):
    def setUp(self):
        catalog = json.loads((ROOT / "catalogs/example.json").read_text())
        self.workload, self.target = catalog["workloads"][0], catalog["devices"][1]
        self.recipe = self.workload["recipe"]
        self.observations = {host: observation(host) for host in ("source", "destination")}
        self.observations["source"]["snapshot"]["workloads"] = [observed_workload()]

    def assess(self):
        return assess_recipe(self.recipe, self.workload, self.target, self.observations)

    def checks(self):
        return {check["id"]: check for check in self.assess()["checks"]}

    def test_example_is_detached_and_asset_hash_is_not_deployment_evidence(self):
        sanitized = validate_recipe(self.recipe)
        self.assertEqual(self.recipe, sanitized)
        sanitized["source"]["selector"]["name"] = "different"
        self.assertEqual(self.recipe["source"]["selector"]["name"], "switchyard-foobar")
        self.assertIsNone(self.recipe["artifact"]["digest"])
        self.assertEqual(self.recipe["artifact"]["reference_status"], "unverified")
        page = (ROOT / "examples/foobar/index.html").read_bytes()
        self.assertEqual("sha256:" + hashlib.sha256(page).hexdigest(), self.recipe["site"]["content_sha256"])
        self.assertLessEqual(len(page), self.recipe["site"]["upper_bound_bytes"])
        self.assertEqual(self.checks()["content-digest"]["status"], "blocked")
        self.assertEqual(self.recipe["verification"]["baseline"], "unobserved")

    def test_rejects_legacy_unknown_fields_credentials_and_unbounded_values(self):
        mutations = [
            lambda r: r.update(command="do something"),
            lambda r: r.update(data_sets=[]),
            lambda r: r.update(backup={}),
            lambda r: r["artifact"].update(password="not-allowed"),
            lambda r: r.update(stop="password=not-allowed"),
            lambda r: r["artifact"].update(reference="https://user:password@example.invalid/image"),
            lambda r: r["artifact"].update(reference="nginx:latest"),
            lambda r: r["artifact"].update(digest="sha256:invented"),
            lambda r: r["artifact"].update(architectures=["x86_64"] * 17),
            lambda r: r["artifact"].update(architectures=["x86_64", "x86_64"]),
            lambda r: r["verification"].update(baseline="verified"),
            lambda r: r["resources"].update(memory_bytes=True),
            lambda r: r["resources"].update(memory_bytes=-1),
            lambda r: r["resources"].update(memory_bytes=2**64),
            lambda r: r["site"].update(read_only=1),
            lambda r: r["network"].update(host_port=18080.0),
            lambda r: r.update(schema_version=True),
            lambda r: r.update(stop="x" * 2049),
            lambda r: r.update(stop="text\x00hidden"),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                recipe = copy.deepcopy(self.recipe)
                mutate(recipe)
                with self.assertRaises(ValueError):
                    validate_recipe(recipe)
        with self.assertRaises(ValueError):
            validate_recipe({step: "legacy prose" for step in ("stop", "transfer", "start", "verify", "recovery")})

    def test_rejects_escaping_paths_ambiguous_selectors_and_unsafe_policy(self):
        mutations = [
            lambda r: r["site"].update(destination_path="/outside/index.html"),
            lambda r: r["site"].update(source_path="/srv/../index.html"),
            lambda r: r["site"].update(source_path="/srv//index.html"),
            lambda r: r["site"].update(source_path="/srv/index.html/"),
            lambda r: r["site"].update(source_path="relative/index.html"),
            lambda r: r["source"].update(selector={}),
            lambda r: r["source"].update(selector={"name": "switchyard-foobar", "native_id": CONTAINER_ID}),
            lambda r: r["source"].update(selector={"native_id": "short"}),
            lambda r: r["source"].update(scope="user:1000"),
            lambda r: r["destination"].update(definition_id="different"),
            lambda r: r["network"].update(bind_address="0.0.0.0"),
            lambda r: r["network"].update(host_port=80),
            lambda r: r.update(restart_policy="always"),
            lambda r: r["site"].update(read_only=False),
            lambda r: r["verification"].update(follow_redirects=True),
            lambda r: r["recovery_conditions"].update(automatic_restart=True),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                recipe = copy.deepcopy(self.recipe)
                mutate(recipe)
                with self.assertRaises(ValueError):
                    validate_recipe(recipe)

    def test_supported_capacity_never_means_ready_or_authorized(self):
        before = copy.deepcopy((self.recipe, self.workload, self.target, self.observations))
        checks = self.checks()
        for identity in ("source-binding", "destination-binding", "source-host-identity", "destination-host-identity",
                         "source-runtime", "destination-runtime", "source-architecture", "artifact-architecture",
                         "destination-cpu", "destination-memory", "destination-storage", "source-stopped",
                         "source-readonly-content"):
            self.assertEqual(checks[identity]["status"], "supported", identity)
        for identity in ("execution-authority", "artifact-digest", "source-artifact-digest",
                         "dedicated-port", "destination-name-available", "restart-inhibited",
                         "content-digest", "http-body-verification", "recovery-before-cutover"):
            self.assertEqual(checks[identity]["status"], "blocked", identity)
        self.assertEqual(before, (self.recipe, self.workload, self.target, self.observations))
        self.assertEqual(self.assess(), self.assess())

    def test_source_requires_unique_fresh_exact_definition_binding_and_full_id(self):
        source = self.observations["source"]["snapshot"]
        original = observed_workload()
        for records in ([], [original, copy.deepcopy(original)],
                        [{**original, "name": "other"}], [{**original, "native_id": "short"}],
                        [{**original, "backend": "podman"}], [{**original, "scope": "user:1000"}],
                        [{**original, "host_id": "destination"}], [{**original, "observed_at": OLD}]):
            with self.subTest(records=records):
                source["workloads"] = records
                self.assertEqual(self.checks()["source-binding"]["status"], "blocked")
        source["workloads"] = [original]
        self.workload["bindings"][0]["selector"]["name"] = "other"
        self.assertEqual(self.checks()["source-binding"]["status"], "blocked")
        self.workload["bindings"][0]["selector"] = {"name": "switchyard-foobar"}
        self.recipe["source"]["definition_id"] = self.recipe["destination"]["definition_id"] = "other"
        self.assertEqual(self.checks()["source-binding"]["status"], "blocked")

    def test_exact_native_selector_resolves_without_name_fallback(self):
        selector = {"native_id": CONTAINER_ID}
        self.recipe["source"]["selector"] = dict(selector)
        self.workload["bindings"][0]["selector"] = dict(selector)
        self.assertEqual(self.checks()["source-binding"]["status"], "supported")
        self.observations["source"]["snapshot"]["workloads"][0]["native_id"] = "2" * 64
        self.assertEqual(self.checks()["source-binding"]["status"], "blocked")

    def test_target_identity_and_same_host_cannot_rebind_recipe(self):
        self.target["id"] = "other"
        self.assertEqual(self.checks()["destination-binding"]["status"], "blocked")
        self.target["id"] = "source"
        self.assertEqual(self.checks()["source-binding"]["status"], "blocked")
        self.assertEqual(self.checks()["destination-binding"]["status"], "blocked")

    def test_retained_resources_and_scope_times_are_not_freshened(self):
        snapshot = self.observations["destination"]["snapshot"]
        snapshot["resource_observed_at"]["storage"] = OLD
        snapshot["resource_observed_at"]["memory"] = OLD
        snapshot["coverage"][-1]["observed_at"] = OLD
        for identity in ("destination-storage", "destination-memory", "destination-runtime"):
            self.assertEqual(self.checks()[identity]["status"], "blocked")
        self.assertEqual(self.checks()["destination-cpu"]["status"], "supported")

    def test_partial_capacity_coverage_does_not_imply_runtime_completeness(self):
        wrapper = self.observations["destination"]
        wrapper["last_attempt"]["status"] = "partial"
        for entry in wrapper["snapshot"]["coverage"]:
            entry["status"] = "partial"
        self.assertEqual(self.checks()["destination-memory"]["status"], "supported")
        self.assertEqual(self.checks()["destination-storage"]["status"], "supported")
        self.assertEqual(self.checks()["destination-runtime"]["status"], "blocked")

    def test_wrapper_identity_age_and_missing_timestamps_block(self):
        for change in ({"freshness": "stale"}, {"age_seconds": 120}, {"age_seconds": None},
                       {"age_seconds": True}, {"age_seconds": float("nan")}):
            with self.subTest(change=change):
                self.observations["source"] = observation("source")
                self.observations["source"]["snapshot"]["workloads"] = [observed_workload()]
                self.observations["source"].update(change)
                self.assertEqual(self.checks()["source-binding"]["status"], "blocked")
        self.observations["source"] = observation("source")
        self.observations["source"]["snapshot"]["host_id"] = "destination"
        self.assertEqual(self.checks()["source-host-identity"]["status"], "blocked")
        self.observations["destination"]["snapshot"]["resource_observed_at"].pop("host")
        self.assertEqual(self.checks()["artifact-architecture"]["status"], "blocked")

    def test_selected_pool_covers_paths_without_borrowing_child_capacity(self):
        snapshot = self.observations["destination"]["snapshot"]
        original = copy.deepcopy(snapshot["storage"]["filesystems"])
        for mutate in (
            lambda pools: pools[0].update(id="different-pool"),
            lambda pools: pools[0].update(mounts=["/unrelated"]),
            lambda pools: pools[0].update(available_bytes=1),
            lambda pools: pools[0].update(read_only=True),
            lambda pools: pools[0].update(kind="volatile"),
            lambda pools: pools.append({"id": "child", "mounts": ["/srv/switchyard-foobar"], "available_bytes": 1}),
        ):
            with self.subTest(mutation=mutate):
                snapshot["storage"]["filesystems"] = copy.deepcopy(original)
                mutate(snapshot["storage"]["filesystems"])
                self.assertEqual(self.checks()["destination-storage"]["status"], "blocked")
        snapshot["storage"]["filesystems"] = original
        self.recipe["site"]["upper_bound_bytes"] = None
        self.assertEqual(self.checks()["destination-storage"]["status"], "blocked")

    def test_observed_capacity_and_architecture_override_optimistic_catalog(self):
        snapshot = self.observations["destination"]["snapshot"]
        snapshot["host"]["architecture"] = "aarch64"
        snapshot["cpu"]["logical_count"] = 0
        snapshot["memory"]["available_bytes"] = None
        for identity in ("artifact-architecture", "destination-cpu", "destination-memory"):
            self.assertEqual(self.checks()[identity]["status"], "blocked")

    def test_source_stop_and_readonly_mount_are_independent(self):
        record = self.observations["source"]["snapshot"]["workloads"][0]
        record["lifecycle"] = "running"
        self.assertEqual(self.checks()["source-stopped"]["status"], "blocked")
        self.assertEqual(self.checks()["source-readonly-content"]["status"], "supported")
        record["extensions"]["container.v1"]["mounts"][0]["read_only"] = False
        self.assertEqual(self.checks()["source-readonly-content"]["status"], "blocked")

    def test_image_digest_requires_exact_fresh_same_scope_evidence(self):
        self.recipe["artifact"]["digest"] = IMAGE_ID
        artifact = {"id": "fixture-image", "host_id": "destination", "backend": "docker", "scope": "system",
                    "kind": "image", "native_id": IMAGE_ID, "observed_at": AT}
        self.observations["destination"]["snapshot"]["artifacts"] = [artifact]
        self.assertEqual(self.checks()["artifact-digest"]["status"], "supported")
        self.assertEqual(self.checks()["source-artifact-digest"]["status"], "supported")
        for field, value in (("native_id", "sha256:" + "b" * 64), ("scope", "user:1000"),
                             ("backend", "podman"), ("host_id", "source"), ("observed_at", OLD)):
            with self.subTest(field=field):
                original = artifact[field]
                artifact[field] = value
                self.assertEqual(self.checks()["artifact-digest"]["status"], "blocked")
                artifact[field] = original
        self.observations["source"]["snapshot"]["workloads"][0]["extensions"]["container.v1"]["image_reference"] = "nginx:other"
        self.assertEqual(self.checks()["source-artifact-digest"]["status"], "blocked")
        self.assertEqual(self.checks()["http-body-verification"]["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
