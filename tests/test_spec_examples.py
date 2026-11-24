"""Validate the v2 declaration examples and reject the reviewed unsafe shapes."""
from copy import deepcopy
import inspect
import json
from pathlib import Path
import re
import unittest

from pydantic import ValidationError

from switchyard import spec


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "docs" / "spec" / "examples"


def example(name):
    return json.loads((EXAMPLES / name).read_text())


def residents():
    """Frozen residents-shaped test input. The published example 03 is the bundle as its owner registered it
    and changes with the residents; rule tests must not depend on its layout."""
    return json.loads((ROOT / "tests" / "fixtures" / "residents.json").read_text())


def static_web():
    return example("02-static-web.json")


def gates_of(app, component_id):
    return [g["id"] for c in app["components"] if c["id"] == component_id for g in c.get("gates", [])]


def fenced(placement, app, state="active"):
    """Synthetic validation input, never runtime evidence or a host operation."""
    placement["state"] = state
    revoked = state != "active"
    placement["fence"] = {
        "journal_generation": placement["generation"],
        "host_generation": placement["generation"],
        "tokens": [{
            "application_id": app["id"], "component": component["component"],
            "generation": placement["generation"], "issued_at": "2026-11-22T00:00:00Z",
            "token_path": f"/validation-only/{component['component']}.token",
            "gates": [{"gate": gate, "evidence": "validation-only gate"} for gate in gates_of(app, component["component"])],
            "state": "revoked" if revoked else "valid",
            **({"revoked_at": "2026-11-22T00:01:00Z"} if revoked else {}),
        } for component in placement["components"]],
        "activators": ["validation-only native start path"],
        "previous_policy": "validation-only", "evidence": ["synthetic test input"],
        "verified_at": "2026-11-22T00:02:00Z",
    }
    return placement


def residents_active(drop_station_test_client=True):
    """Both residents placements active, with the test identity held on at most one host."""
    value = residents()
    app = value["applications"][0]
    for placement in value["placements"]:
        if drop_station_test_client:
            placement["components"] = [c for c in placement["components"] if c["component"] != "station-test-client"]
        for item in placement["components"]:
            if not gates_of(app, item["component"]):
                item["ungated_reason"] = "test client started by hand; validation-only"
        fenced(placement, app)
    return value


# A stored-format switchyard/v1alpha2 record (adopted Quadlet, contained TLS secret, single-gate token).
V1ALPHA2_BUNDLE = {
    "apiVersion": "switchyard/v1alpha2", "kind": "Bundle",
    "applications": [{
        "apiVersion": "switchyard/v1alpha2", "kind": "Application", "id": "legacy", "revision": 1,
        "name": "Legacy", "purpose": "v1alpha2 fixture",
        "components": [{"id": "web", "native": {"kind": "quadlet", "source": "container-file", "unit": "legacy.service"}}],
        "datasets": [{"id": "data", "snapshot": "files-quiesced", "verify": "sha256-manifest", "writers": ["web"],
                      "contains_secrets": ["tls"]}],
        "secrets": [
            {"id": "tls", "kind": "credential", "consumers": ["web"], "transfer": "copy", "rotates_on_use": False},
            {"id": "env", "kind": "environment-file", "consumers": ["web"], "transfer": "copy", "rotates_on_use": "unknown"},
        ],
        "provenance": {"submitted_by": "fixture", "source": "test"},
    }],
    "placements": [{
        "apiVersion": "switchyard/v1alpha2", "kind": "Placement", "id": "legacy-pop", "application_id": "legacy",
        "revision": 1, "host_id": "host-b", "generation": 1, "state": "active", "ownership": "adopted",
        "components": [{"component": "web", "native_identities": [{"native_id": "legacy.service", "scope": "user:1000"}],
                        "source_paths": {"container-file": "/home/user/.config/containers/systemd/legacy.container"}}],
        "datasets": [{"dataset": "data", "path": "/srv/legacy", "access": "write"}],
        "secrets": [{"secret": "tls", "within_dataset": "data", "relative_path": "tls/key.pem"},
                    {"secret": "env", "path": "/home/user/.config/legacy.env"}],
        "fence": {"journal_generation": 1, "host_generation": 1,
                  "tokens": [{"application_id": "legacy", "component": "web", "generation": 1,
                              "issued_at": "2026-11-22T00:00:00Z", "token_path": "/home/user/.local/state/legacy.token",
                              "gate": "exec-start-pre", "gate_ref": "drop-in checks the token", "state": "valid"}],
                  "activators": ["systemctl --user start legacy.service"], "previous_policy": "fixture",
                  "evidence": ["fixture"], "verified_at": "2026-11-22T00:01:00Z"},
    }],
}


class SpecExamplesTests(unittest.TestCase):
    def test_all_examples(self):
        paths = sorted(EXAMPLES.glob("*.json"))
        self.assertEqual(len(paths), 8)
        for path in paths:
            with self.subTest(example=path.name):
                value = spec.SpecBundle.model_validate_json(path.read_text())
                self.assertEqual(value, spec.SpecBundle.model_validate(value.model_dump()))

    def test_explicit_endpoint_scheme_is_tcp_only_and_agrees_with_http_check(self):
        data = static_web()["applications"][0]
        legacy = spec.Application.model_validate(data)
        self.assertNotIn("scheme", legacy.model_dump()["endpoints"][0])
        data["endpoints"][0]["scheme"] = "http"
        model = spec.Application.model_validate(data)
        self.assertEqual(model.endpoints[0].scheme, "http")
        self.assertNotEqual(model.content_sha256(), legacy.content_sha256())
        data["health_checks"][0]["scheme"] = "https"
        with self.assertRaisesRegex(ValidationError, "check scheme does not match"):
            spec.Application.model_validate(data)
        with self.assertRaisesRegex(ValidationError, "requires TCP"):
            spec.Endpoint.model_validate({"id": "web", "component": "web", "protocol": "udp",
                                          "target_port": 8443, "scheme": "https"})

    def test_observed_components_are_only_watched(self):
        base = example("06-observed-job.json")
        cases = [
            ("gated", lambda v: v["applications"][0]["components"][0].update(
                gates=[{"id": "g", "kind": "script", "target": "x", "covers": "x"}])),
            ("deployed", lambda v: v["placements"][0].update(ownership="deployed", ownership_id="owned")),
            ("staged", lambda v: v["placements"][0].update(state="staged")),
            ("two primaries", lambda v: v["placements"][0]["components"][0]["native_identities"][1].update(role="primary")),
            ("no selector", lambda v: v["placements"][0]["components"][0]["native_identities"][0].update(native_id=None)),
            ("name on systemd", lambda v: v["placements"][0]["components"][0]["native_identities"][0].update(
                native_id=None, name="test-sync-job")),
        ]
        for label, change in cases:
            value = deepcopy(base)
            change(value)
            with self.subTest(case=label), self.assertRaises(ValidationError):
                spec.SpecBundle.model_validate(value)
        container = deepcopy(base)
        container["placements"][0]["components"][0]["native_identities"][0].update(native_id=None, name="sabnzbd", backend="podman")
        spec.SpecBundle.model_validate(container)

    def test_observed_runtime_is_additive_and_hash_neutral_while_unset(self):
        # A record stored before `runtime` existed normalizes to the very same bytes, hence the same hash.
        stored = example("06-observed-job.json")
        normalized = spec.SpecBundle.model_validate(stored).model_dump(mode="json")
        self.assertEqual(json.dumps(normalized, sort_keys=True), json.dumps(stored, sort_keys=True))
        self.assertNotIn("runtime", normalized["applications"][0]["components"][0]["native"])
        described = example("07-observed-runtime.json")
        native = described["applications"][0]["components"][0]["native"]
        self.assertEqual(spec.SpecBundle.model_validate(described).model_dump(mode="json"), described)
        cases = [
            ("engine of the other provider", {**native, "runtime": {**native["runtime"], "provider": "docker-compose-v2"}}),
            ("scheduled job", {**native, "resource_kind": "scheduled-job"}),
            ("quadlet on a container", {**native, "runtime": {"kind": "quadlet"}}),
            ("static-web on systemd", {**native, "backend": "systemd", "runtime": {"kind": "static-web", "image": "x", "port": 1, "site_file": "/p"}}),
            ("duplicate service", {**native, "runtime": {**native["runtime"], "services": ["web", "web"]}}),
            ("unknown field", {**native, "runtime": {**native["runtime"], "unit": "x.service"}}),
        ]
        for label, value in cases:
            broken = deepcopy(described)
            broken["applications"][0]["components"][0]["native"] = value
            with self.subTest(case=label), self.assertRaises(ValidationError):
                spec.SpecBundle.model_validate(broken)

    def test_document_field_inventory_matches_models(self):
        text = (ROOT / "docs" / "spec" / "workload.md").read_text()
        rows = dict(re.findall(r"^\| `([A-Z][A-Za-z]+)` \| ([^|]*) \|$", text, re.MULTILINE))
        models = {name: cls for name, cls in inspect.getmembers(spec, inspect.isclass)
                  if issubclass(cls, spec.Model) and cls is not spec.Model}
        self.assertEqual(set(rows), set(models))
        for name, cls in models.items():
            with self.subTest(model=name):
                self.assertEqual(re.findall(r"`([^`]+)`", rows[name]), list(cls.model_fields))

    def test_content_hash_is_normalized_and_placement_free(self):
        value = static_web()
        app = spec.Application.model_validate(value["applications"][1])
        digest = app.content_sha256()
        self.assertRegex(digest, r"^[a-f0-9]{64}$")
        reordered = dict(reversed(list(value["applications"][1].items())))
        self.assertEqual(digest, spec.Application.model_validate(reordered).content_sha256())
        value["placements"][0]["host_id"] = "other-host"
        bundle = spec.SpecBundle.model_validate(value)
        self.assertEqual(digest, bundle.applications[1].content_sha256())
        changed = app.model_dump()
        changed["revision"] = 2
        self.assertNotEqual(digest, spec.Application.model_validate(changed).content_sha256())

    def test_instance_identity_allows_multiple_hosts(self):
        value = static_web()
        other = deepcopy(value["applications"][1])
        other["id"] = "static-web-second"
        value["applications"].append(other)
        placement = deepcopy(value["placements"][0])
        placement.update(id="second-placement", application_id=other["id"], host_id="host-b")
        value["placements"].append(placement)
        spec.SpecBundle.model_validate(value)

    def test_strict_unknown_fields_and_old_version(self):
        for location, field, value in [
            ("application", "single_active", True),
            ("application", "host_id", "host-b"),
            ("application", "apiVersion", "switchyard/v1alpha1"),
            ("application", "apiVersion", "switchyard/v1alpha2"),
            ("dataset", "contains_secrets", ["hub-dashboard-token"]),
            ("secret", "locations", []),
            ("application", "revision", "1"),
            ("component", "bindings", []),
            ("component", "deadline_epoch", 123),
            ("dataset", "class", "sqlite"),
            ("dataset", "locations", []),
            ("dataset", "include_sidecars", True),
            ("secret", "path", "/secret"),
            ("secret", "value", "not-allowed"),
            ("endpoint", "host_port", 8080),
        ]:
            with self.subTest(location=location, field=field):
                bundle = residents()
                app = bundle["applications"][0]
                selected = {"application": app, "component": app["components"][0],
                            "dataset": app["datasets"][0], "secret": app["secrets"][0],
                            "endpoint": app["endpoints"][0]}[location]
                selected[field] = value
                with self.assertRaises(ValidationError):
                    spec.SpecBundle.model_validate(bundle)

    def test_rejected_kube_kinds_and_fields(self):
        for location, field, value in [
            ("manifest", "kind", "Deployment"),
            ("manifest", "kind", "PersistentVolumeClaim"),
            ("pod", "volumeMode", "Filesystem"),
            ("pod", "initContainers", []),
            ("container", "readinessProbe", {"tcpSocket": {"port": 8080}}),
            ("container", "startupProbe", {"tcpSocket": {"port": 8080}}),
            ("security", "runAsNonRoot", True),
            ("pod-security", "fsGroup", 101),
            ("volume", "persistentVolumeClaim", {"claimName": "site"}),
            ("volume", "secret", {"secretName": "secret"}),
            ("port", "hostPort", 18081),
            ("port", "hostIP", "127.0.0.1"),
        ]:
            with self.subTest(location=location, field=field):
                bundle = static_web()
                manifest = bundle["applications"][1]["components"][0]["native"]["manifest"]
                pod = manifest["spec"]
                container = pod["containers"][0]
                pod["securityContext"] = {}
                selected = {"manifest": manifest, "pod": pod, "container": container,
                            "security": container["securityContext"], "pod-security": pod["securityContext"],
                            "volume": pod["volumes"][0], "port": container["ports"][0]}[location]
                selected[field] = value
                with self.assertRaises(ValidationError):
                    spec.SpecBundle.model_validate(bundle)

    def test_kube_compatibility_and_host_network_reviews(self):
        native = static_web()["applications"][1]["components"][0]["native"]
        volume = native["manifest"]["spec"]["volumes"][0]
        volume.pop("hostPath")
        volume["configMap"] = {"name": "site-config"}
        with self.assertRaises(ValidationError):
            spec.KubeNative.model_validate(native)
        native["compatibility_gates"] = ["configmap-volume-unverified"]
        spec.KubeNative.model_validate(native)
        native["manifest"]["spec"]["hostNetwork"] = True
        with self.assertRaises(ValidationError):
            spec.KubeNative.model_validate(native)
        native["reviews"] = ["host-network"]
        spec.KubeNative.model_validate(native)

    def test_private_whole_secret_conversion_required(self):
        value = static_web()
        app = value["applications"][1]
        app["secrets"] = [{"id": "api-key", "kind": "file", "consumers": ["web"], "transfer": "copy", "rotates_on_use": "unknown",
                           "locations": [{"id": "file", "form": "value", "role": "holder", "component": "web"}]}]
        app["components"][0]["native"]["manifest"]["spec"]["containers"][0]["env"] = [{"name": "API_KEY", "valueFrom": {"secretKeyRef": {"name": "api-key", "key": "value"}}}]
        value["placements"][0]["secrets"] = [{"secret": "api-key", "location": "file", "path": "/private/key"}]
        with self.assertRaises(ValidationError):
            spec.SpecBundle.model_validate(value)
        value["placements"][0]["secrets"][0]["conversion"] = "podman-kube-secret"
        spec.SpecBundle.model_validate(value)

    def test_active_placement_requires_generation_gate(self):
        value = static_web()
        placement = value["placements"][0]
        placement["state"] = "active"
        with self.assertRaises(ValidationError):
            spec.SpecBundle.model_validate(value)
        fenced(placement, value["applications"][1])
        spec.SpecBundle.model_validate(value)
        for field in ("host_generation", "journal_generation"):
            bad = deepcopy(value)
            bad["placements"][0]["fence"][field] = 2
            with self.subTest(field=field), self.assertRaises(ValidationError):
                spec.SpecBundle.model_validate(bad)

    def test_fenced_generation_cannot_keep_valid_token(self):
        value = static_web()
        placement = fenced(value["placements"][0], value["applications"][1], "fenced")
        spec.SpecBundle.model_validate(value)
        placement["fence"]["tokens"][0].update(state="valid", revoked_at=None)
        with self.assertRaises(ValidationError):
            spec.SpecBundle.model_validate(value)

    def test_takeover_requires_attestation_and_generation_bump(self):
        value = static_web()
        placement = fenced(value["placements"][0], value["applications"][1])
        placement["fence"]["takeover"] = {
            "who": "operator", "why": "source unavailable", "evidence": ["verified-source-snapshot"],
            "attested_at": "2026-11-22T00:00:00Z", "source_generation": 1,
            "snapshot_ref": "latest-verified-snapshot",
        }
        with self.assertRaises(ValidationError):
            spec.SpecBundle.model_validate(value)
        placement["generation"] = 2
        placement["fence"].update(journal_generation=2, host_generation=2)
        placement["fence"]["tokens"][0]["generation"] = 2
        spec.SpecBundle.model_validate(value)
        placement["fence"]["takeover"]["evidence"] = []
        with self.assertRaises(ValidationError):
            spec.SpecBundle.model_validate(value)

    def test_single_active_is_per_component_not_application(self):
        value = residents_active()
        spec.SpecBundle.model_validate(value)
        duplicate = deepcopy(value["placements"][0])
        duplicate.update(id="duplicate-hub", host_id="other-host", generation=2)
        duplicate["fence"].update(journal_generation=2, host_generation=2)
        for token in duplicate["fence"]["tokens"]:
            token["generation"] = 2
        value["placements"].append(duplicate)
        with self.assertRaisesRegex(ValidationError, "single-active"):
            spec.SpecBundle.model_validate(value)

    def test_dataset_has_one_writer_placement_even_for_distinct_components(self):
        value = static_web()
        app = value["applications"][1]
        second = deepcopy(app["components"][0])
        second["id"] = "other-web"
        second["native"]["manifest"]["spec"]["containers"][0]["ports"] = []
        app["components"].append(second)
        app["datasets"][0]["writers"].append("other-web")
        app["datasets"][0]["readers"].append("other-web")
        first = fenced(value["placements"][0], app)
        other = deepcopy(first)
        other.update(id="second-writer", host_id="other-host")
        other["components"][0]["component"] = "other-web"
        other["endpoints"] = []
        other["fence"]["tokens"][0]["component"] = "other-web"
        value["placements"].append(other)
        with self.assertRaisesRegex(ValidationError, "writer placement"):
            spec.SpecBundle.model_validate(value)

    def test_secret_locations_bind_once_in_their_dataset(self):
        value = residents()
        binding = value["placements"][0]["secrets"][0]
        self.assertEqual((binding["secret"], binding["location"]), ("hub-dashboard-token", "hub-state"))
        binding["path"] = "/private/duplicate-token"
        with self.assertRaisesRegex(ValidationError, "exactly one of path or relative_path"):
            spec.SpecBundle.model_validate(value)
        binding.pop("relative_path")
        with self.assertRaisesRegex(ValidationError, "binds relative_path, never a second copy path"):
            spec.SpecBundle.model_validate(value)

    def test_freshness_files_must_be_stale_on_restore(self):
        value = residents()
        value["applications"][0]["datasets"][4]["health_files"][0]["stale_on_restore"] = False
        with self.assertRaises(ValidationError):
            spec.SpecBundle.model_validate(value)

    def test_adopted_hashes_only_at_plan_time(self):
        value = example("04-learning-box.json")
        component = value["applications"][0]["components"][0]
        component["sources"] = [{"id": "container-file", "sha256": "a" * 64}]
        with self.assertRaisesRegex(ValidationError, "PLAN time"):
            spec.SpecBundle.model_validate(value)
        value["placements"][0].update(ownership="deployed", ownership_id="validation-only-owned-resource")
        spec.SpecBundle.model_validate(value)
        component["sources"] = []
        with self.assertRaisesRegex(ValidationError, "source hash pins"):
            spec.SpecBundle.model_validate(value)

    def test_native_source_hash_is_not_a_binding_field(self):
        value = example("04-learning-box.json")
        value["placements"][0]["components"][0]["native_identities"][0]["sha256"] = "a" * 64
        with self.assertRaises(ValidationError):
            spec.SpecBundle.model_validate(value)

    def test_external_writers_require_quiescence_check(self):
        value = residents()
        actor = value["applications"][0]["datasets"][0]["external_actors"][0]
        actor["access"] = "write"
        with self.assertRaisesRegex(ValidationError, "quiesce check"):
            spec.SpecBundle.model_validate(value)

    # ---------------------------------------------------------------- gates
    def test_several_gates_per_component_all_bound_when_active(self):
        value = residents_active()
        spec.SpecBundle.model_validate(value)
        test_alice = next(t for t in value["placements"][0]["fence"]["tokens"] if t["component"] == "test-alice")
        self.assertEqual([g["gate"] for g in test_alice["gates"]], ["g1-launcher", "g2-session", "g3-body"])
        test_alice["gates"].pop()  # the body template drop-in has no evidence
        with self.assertRaisesRegex(ValidationError, "every declared gate"):
            spec.SpecBundle.model_validate(value)
        test_alice["gates"].append({"gate": "g9-unknown", "evidence": "validation-only"})
        with self.assertRaisesRegex(ValidationError, "unknown gate evidence"):
            spec.SpecBundle.model_validate(value)

    def test_ungated_components_need_a_recorded_decision_and_never_when_deployed(self):
        value = residents_active()
        client = next(c for c in value["placements"][0]["components"] if c["component"] == "hub-test-client")
        client.pop("ungated_reason")
        with self.assertRaisesRegex(ValidationError, "explicit ungated_reason"):
            spec.SpecBundle.model_validate(value)
        test_alice = next(c for c in value["placements"][0]["components"] if c["component"] == "test-alice")
        client["ungated_reason"] = test_alice["ungated_reason"] = "contradiction"
        with self.assertRaisesRegex(ValidationError, "contradicts declared gates"):
            spec.SpecBundle.model_validate(value)
        web = static_web()
        web["applications"][1]["components"][0].pop("gates")
        placement = fenced(web["placements"][0], web["applications"][1])
        placement["components"][0]["ungated_reason"] = "deployed workloads cannot opt out"
        with self.assertRaisesRegex(ValidationError, "active deployed component requires declared gates"):
            spec.SpecBundle.model_validate(web)

    def test_transient_gates_need_the_launcher_and_gate_related_units(self):
        component = deepcopy(residents()["applications"][0]["components"][3])
        self.assertEqual(component["id"], "test-alice")
        spec.Component.model_validate(component)
        without_launcher = deepcopy(component)
        without_launcher["gates"] = [g for g in component["gates"] if g["kind"] != "launcher"]
        with self.assertRaisesRegex(ValidationError, "require a launcher gate"):
            spec.Component.model_validate(without_launcher)
        own_unit = deepcopy(component)
        own_unit["gates"][2]["target"] = "test-alice-run.service"
        with self.assertRaisesRegex(ValidationError, "transient unit cannot carry an ExecStartPre gate"):
            spec.Component.model_validate(own_unit)
        duplicate = deepcopy(component)
        duplicate["gates"][1]["id"] = "g1-launcher"
        with self.assertRaisesRegex(ValidationError, "duplicate gate IDs"):
            spec.Component.model_validate(duplicate)

    # ---------------------------------------------------------------- identities
    def test_exclusive_identity_active_on_one_holder_only(self):
        spec.SpecBundle.model_validate(residents_active())
        both = residents_active(drop_station_test_client=False)
        station = both["placements"][1]
        station["endpoints"].append({"endpoint": "station-test-test-bridge", "address": "127.0.0.1", "host_port": 25620})
        with self.assertRaisesRegex(ValidationError, "exclusive identity minecraft-user/TEST_CLIENT"):
            spec.SpecBundle.model_validate(both)
        # The same holder set is fine while only one placement is active.
        both["placements"][0]["state"] = "declared"
        both["placements"][0].pop("fence")
        spec.SpecBundle.model_validate(both)

    def test_identity_references_and_uniqueness(self):
        for mutate, message in [
            (lambda app: app["identities"][0]["holders"].append("nobody"), "unknown identity holder"),
            (lambda app: app["identities"][1].update(name="TEST_ALICE"), "duplicate identity kind/name pairs"),
            (lambda app: app["identities"][0]["holders"].append("test-alice"), "duplicate identity holders"),
        ]:
            value = residents()
            mutate(value["applications"][0])
            with self.subTest(message=message), self.assertRaisesRegex(ValidationError, message):
                spec.SpecBundle.model_validate(value)
        value = residents()
        value["applications"][0]["identities"][6]["name"] = "PLACEHOLDER-test-alice-thread-id"  # placeholders never collide
        spec.SpecBundle.model_validate(value)

    # ---------------------------------------------------------------- credentials in several places
    def test_reissue_inventory_enumerates_every_location_across_hosts(self):
        bundle = spec.SpecBundle.model_validate(residents())
        station = bundle.secret_locations("test-agent-cluster", "station-dashboard-token")
        self.assertEqual(station["transfer"], "copy")
        self.assertEqual([(l["id"], l["form"], l["role"], [b["host_id"] for b in l["bindings"]]) for l in station["locations"]],
                         [("station-state", "value", "holder", ["host-a"]), ("hub-stations-file", "embedded", "copy", ["host-c"])])
        observer = bundle.secret_locations("test-agent-cluster", "hub-observer-token")
        self.assertEqual(observer["transfer"], "reissue")  # lives in a dataset, yet reissued
        self.assertEqual(observer["locations"][1]["external_dependency"], "server-bridge")
        self.assertEqual(observer["locations"][1]["bindings"], [])

    def test_secret_location_rules(self):
        def secret(app, secret_id):
            return next(s for s in app["secrets"] if s["id"] == secret_id)
        for mutate, message in [
            (lambda app: secret(app, "test-alice-api-token")["locations"].pop(0), "at least one holder location"),
            (lambda app: secret(app, "test-alice-api-token")["locations"][0].update(form="hash"), "usable value, not a hash"),
            (lambda app: secret(app, "test-alice-api-token")["locations"][1].update(component="video"), "accesses that dataset"),
            (lambda app: secret(app, "test-alice-api-token")["locations"][0].update(component="test-bob"), "declared consumer"),
            (lambda app: secret(app, "hub-observer-token")["locations"][1].update(dataset="hub-state"), "outside this application's datasets"),
            (lambda app: secret(app, "hub-observer-token")["locations"][1].update(component="hub"), "exactly one component or external"),
            (lambda app: secret(app, "hub-dashboard-token")["locations"].append(
                {"id": "loose-copy", "form": "value", "role": "copy", "component": "hub"}), "travels only with that dataset"),
            (lambda app: secret(app, "test-alice-api-token")["locations"][1].update(id="token-file"), "duplicate secret location IDs"),
        ]:
            value = residents()
            mutate(value["applications"][0])
            with self.subTest(message=message), self.assertRaisesRegex(ValidationError, message):
                spec.SpecBundle.model_validate(value)

    def test_placement_binds_each_location_of_its_components(self):
        value = residents_active()
        spec.SpecBundle.model_validate(value)
        hub = value["placements"][0]
        hub["secrets"] = [b for b in hub["secrets"] if (b["secret"], b["location"]) != ("test-carol-api-token", "hub-credentials")]
        with self.assertRaisesRegex(ValidationError, "required secret location binding: test-carol-api-token/hub-credentials"):
            spec.SpecBundle.model_validate(value)
        hub["secrets"].append({"secret": "test-carol-api-token", "location": "token-file", "path": "/home/operator/resident-client/test-hub-tokens/TEST_CAROL"})
        with self.assertRaisesRegex(ValidationError, "not on this placement"):
            spec.SpecBundle.model_validate(value)
        hub["secrets"][-1]["location"] = "missing"
        with self.assertRaisesRegex(ValidationError, "unknown secret location"):
            spec.SpecBundle.model_validate(value)

    # ---------------------------------------------------------------- v1alpha2 compatibility
    def test_v1alpha2_bundles_upgrade_in_memory(self):
        old = deepcopy(V1ALPHA2_BUNDLE)
        with self.assertRaises(ValidationError):
            spec.SpecBundle.model_validate(old)
        upgraded, source = spec.upgrade(old)
        self.assertEqual(source, "switchyard/v1alpha2")
        self.assertEqual(old, V1ALPHA2_BUNDLE)  # input untouched
        bundle = spec.SpecBundle.model_validate(upgraded)
        app = bundle.applications[0]
        tls = next(s for s in app.secrets if s.id == "tls")
        self.assertEqual([(l.id, l.dataset, l.component) for l in tls.locations], [("data", "data", "web")])
        self.assertEqual(app.components[0].gates[0].id, "legacy-exec-start-pre")
        token = bundle.placements[0].fence.tokens[0]
        self.assertEqual([(g.gate, g.evidence) for g in token.gates], [("legacy-exec-start-pre", "drop-in checks the token")])
        self.assertEqual(spec.upgrade(upgraded), (upgraded, None))
        mapped, _ = spec.upgrade(deepcopy(V1ALPHA2_BUNDLE["placements"][0]), gate_ids={"exec-start-pre": "generation-gate"})
        self.assertEqual(mapped["fence"]["tokens"][0]["gates"][0]["gate"], "generation-gate")

    def test_only_three_human_checkpoints(self):
        step = {"id": "copy", "action": "transfer", "target": {"kind": "dataset", "id": "data"}, "idempotent": True, "checks": ["verified"]}
        for checkpoint in ("none", "downtime", "writer-switch", "destructive"):
            spec.RecipeStep.model_validate({**step, "checkpoint": checkpoint})
        with self.assertRaises(ValidationError):
            spec.RecipeStep.model_validate({**step, "checkpoint": "publish-approval"})
        with self.assertRaises(ValidationError):
            spec.RecipeStep.model_validate({**step, "checks": []})
        with self.assertRaises(ValidationError):
            spec.RecipeStep.model_validate({**step, "action": "script"})

    def test_plan_claims_reject_overlapping_wildcard_and_specific_bind(self):
        value = static_web()
        app = value["applications"][1]
        app["endpoints"].append({"id": "other-http", "component": "web", "protocol": "tcp", "target_port": 8081})
        value["placements"][0]["endpoints"].append({"endpoint": "other-http", "address": "0.0.0.0", "host_port": 18081})
        with self.assertRaisesRegex(ValidationError, "overlapping"):
            spec.SpecBundle.model_validate(value)

    def test_bad_references_traversal_and_capacity(self):
        mutations = [
            lambda v: v["applications"][1]["components"][0]["depends_on"].append("missing"),
            lambda v: v["placements"][0]["datasets"][0].update(path="/safe/../escape"),
            lambda v: v["applications"][1]["requires"][2]["capacity"].update(memory_mib=-1),
            lambda v: v["applications"][1]["template_ref"].update(id="static-web-garden"),
            lambda v: v["placements"][0].update(application_id="static-web-template"),
            lambda v: v["placements"][0]["endpoints"][0].update(address="localhost"),
            lambda v: v["applications"][1]["endpoints"][0].update(target_port=9090),
        ]
        for index, mutate in enumerate(mutations):
            value = spec.SpecBundle.model_validate(static_web()).model_dump()
            mutate(value)
            with self.subTest(index=index), self.assertRaises(ValidationError):
                spec.SpecBundle.model_validate(value)

    def test_reviewed_read_only_paths_cannot_render_writable_mounts(self):
        value = static_web()
        native = value["applications"][1]["components"][0]["native"]
        native["manifest"]["spec"]["volumes"][0]["hostPath"]["path"] = "reviewed://checkout"
        native["manifest"]["spec"]["containers"][0]["volumeMounts"][0]["readOnly"] = False
        value["placements"][0]["reviewed_paths"] = [{
            "id": "checkout", "path": "/reviewed/source", "access": "read",
            "review_ref": "read-only source checkout",
        }]
        with self.assertRaisesRegex(ValidationError, "read-only reviewed path"):
            spec.SpecBundle.model_validate(value)


if __name__ == "__main__":
    unittest.main()
