"""Container fixtures only: never invoke an engine or inspect this machine."""
import copy
import json
import unittest
from unittest.mock import MagicMock, patch

from switchyard import collector, container_probe as containers, probe

AT = "2026-11-22T00:00:00+00:00"
CID = "a" * 64
IID = "sha256:" + "b" * 64


def config():
    return {"host_id": "fixture", "transport": "local", "expected_hostname": "fixture",
            "user_units": [], "system_units": [], "container_engines": ["podman"]}


def selected(**changes):
    return {"id": CID, "name": "/notes", "state": "running", "image_reference": "localhost/notes:latest",
            "image_id": IID, "project": "notes", "service": "web", "podman_project": None,
            "podman_service": None, "compose_directory": "/srv/notes", "compose_files": "/srv/notes/compose.yaml,/srv/notes/override.yaml",
            "systemd_unit": "podman-compose@notes.service", "distrobox": False,
            "mounts": [{"source": "/srv/notes", "destination": "/data", "type": "bind", "read_only": False}],
            **changes}


def image_output():
    return json.dumps({"id": IID, "repository": "localhost/notes", "tag": "latest"}) + "\n"


def observed():
    return {"schema_version": 1, "host_id": "fixture", "observed_at": AT, "collector": "linux-v1",
            "host": {"hostname": "fixture", "os": "Linux", "distribution": None, "architecture": "x86_64"},
            "cpu": dict.fromkeys(("model", "logical_count", "utilization_percent", "sample_seconds", "load_1m")),
            "memory": dict.fromkeys(("total_bytes", "available_bytes", "swap_total_bytes", "swap_free_bytes")),
            "gpus": [], "storage": {"devices": [], "filesystems": []},
            "workloads": containers.parse_containers(json.dumps(selected()), [CID], "fixture", "podman", "user:1000", AT),
            "artifacts": containers.parse_images(image_output(), "fixture", "podman", "user:1000", AT),
            "coverage": [{"scope": scope, "status": "complete", "message": "fixture"} for scope in
                         ("cpu", "memory", "gpus", "storage", "systemd:user:1000", "systemd:system", "podman:user:1000")],
            "warnings": []}


class SelectedMetadataTests(unittest.TestCase):
    def test_full_identity_is_stable_bounded_and_backend_scope_distinct(self):
        fields = observed()["workloads"][0]["extensions"]["container.v1"]
        base = containers.workload("h" * 64, "podman", "user:1000", CID, "notes", fields, AT)
        later = containers.workload("h" * 64, "podman", "user:1000", CID, "renamed", fields, "2026-11-23T00:00:00Z")
        self.assertEqual(base["id"], later["id"])
        self.assertLessEqual(len(base["id"]), 128)
        self.assertEqual(base["native_id"], CID)
        for host, backend, scope in (("other", "podman", "user:1000"), ("h" * 64, "docker", "system"), ("h" * 64, "podman", "user:1001")):
            self.assertNotEqual(base["id"], containers.workload(host, backend, scope, CID, "notes", fields, AT)["id"])
        with self.assertRaises(ValueError):
            containers.workload("fixture", "podman", "user:1000", CID[:12], "notes", fields, AT)

    def test_health_is_unknown_and_environment_requires_explicit_evidence(self):
        for state, lifecycle in (("running", "running"), ("exited", "stopped"), ("created", "stopped"), ("paused", "idle"), ("mystery", "unknown")):
            row = selected(name="ubuntu", state=state)
            work = containers.parse_containers(json.dumps(row), [CID], "fixture", "podman", "user:1000", AT)[0]
            self.assertEqual(work["lifecycle"], lifecycle)
            self.assertEqual(work["health"], "unknown")
            self.assertEqual(work["kind"], "service")
        work = containers.parse_containers(json.dumps(selected(distrobox=True)), [CID], "fixture", "podman", "user:1000", AT)[0]
        self.assertEqual(work["kind"], "environment")
        self.assertEqual(work["extensions"]["container.v1"]["environment"], "distrobox")

    def test_mounts_and_nullable_compose_hints_are_selected_only(self):
        row = selected(project=None, service=None, mounts=[{"source": "", "destination": "/tmp", "type": "tmpfs", "read_only": True}])
        work = containers.parse_containers(json.dumps(row), [CID], "fixture", "podman", "user:1000", AT)[0]
        fields = work["extensions"]["container.v1"]
        self.assertIsNone(fields["project"])
        self.assertIsNone(fields["service"])
        self.assertEqual(set(fields), containers.WORKLOAD_FIELDS)
        self.assertEqual(set(fields["mounts"][0]), {"source", "destination", "type", "read_only"})
        row = selected(project=None, podman_project="notes")
        self.assertEqual(containers.parse_containers(json.dumps(row), [CID], "fixture", "podman", "user:1000", AT)[0]["extensions"]["container.v1"]["project"], "notes")
        with self.assertRaises(ValueError):
            containers.parse_containers(json.dumps(selected(podman_project="other")), [CID], "fixture", "podman", "user:1000", AT)

    def test_origin_labels_are_split_and_absent_labels_are_null(self):
        fields = containers.parse_containers(json.dumps(selected()), [CID], "fixture", "podman", "user:1000", AT)[0]["extensions"]["container.v1"]
        self.assertEqual((fields["compose_directory"], fields["compose_files"], fields["systemd_unit"]),
                         ("/srv/notes", ["/srv/notes/compose.yaml", "/srv/notes/override.yaml"], "podman-compose@notes.service"))
        # Go templates render missing labels as empty strings: no origin is invented.
        bare = selected(project="", service="", compose_directory="", compose_files="", systemd_unit="")
        fields = containers.parse_containers(json.dumps(bare), [CID], "fixture", "podman", "user:1000", AT)[0]["extensions"]["container.v1"]
        self.assertEqual((fields["project"], fields["compose_directory"], fields["compose_files"], fields["systemd_unit"]), (None, None, [], None))
        for bad in (selected(compose_files=",".join(f"/f{i}" for i in range(containers.MAX_COMPOSE_FILES + 1))),
                    selected(compose_files="/a,/a"), selected(systemd_unit="bad\nunit"), selected(compose_files=["/a"])):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                containers.parse_containers(json.dumps(bad), [CID], "fixture", "podman", "user:1000", AT)

    def test_development_environment_mounts_fit_without_losing_metadata(self):
        mounts = [{"source": f"/host/{i}", "destination": f"/guest/{i}", "type": "bind", "read_only": False}
                  for i in range(18)]
        value = containers.parse_containers(json.dumps(selected(distrobox=True, mounts=mounts)),
                                            [CID], "fixture", "podman", "user:1000", AT)[0]
        self.assertEqual(value["kind"], "environment")
        self.assertEqual(value["extensions"]["container.v1"]["mounts"], mounts)
        with self.assertRaises(ValueError):
            containers.parse_containers(json.dumps(selected(mounts=mounts[:1] * (containers.MAX_MOUNTS + 1))),
                                        [CID], "fixture", "podman", "user:1000", AT)

    def test_secret_bearing_payload_fields_are_rejected(self):
        for secret_key in ("environment", "command", "labels", "healthcheck", "logs"):
            with self.subTest(key=secret_key), self.assertRaises(ValueError):
                containers.parse_containers(json.dumps(selected(**{secret_key: "SECRET_CANARY"})), [CID], "fixture", "podman", "user:1000", AT)
        with self.assertRaises(ValueError):
            containers.parse_containers(json.dumps(selected(mounts=[{"source": "/data", "destination": "/data", "type": "bind", "read_only": False, "secret": "SECRET_CANARY"}])), [CID], "fixture", "podman", "user:1000", AT)

    def test_image_inventory_deduplicates_full_content_ids_not_tags(self):
        extra = json.dumps({"id": IID.removeprefix("sha256:"), "repository": "localhost/notes", "tag": "stable"})
        images = containers.parse_images(image_output() + extra, "fixture", "podman", "user:1000", AT)
        self.assertEqual(len(images), 1)
        self.assertEqual(images[0]["native_id"], IID)
        self.assertEqual(images[0]["extensions"]["container.v1"]["references"], ["localhost/notes:latest", "localhost/notes:stable"])
        dangling = json.dumps({"id": IID, "repository": "<none>", "tag": "<none>"})
        self.assertEqual(containers.parse_images(dangling, "fixture", "podman", "user:1000", AT)[0]["name"], IID)
        for value in ("[]", json.dumps({"id": "b" * 12, "repository": "x", "tag": "y"}), image_output().replace('"tag":', '"Env":"SECRET_CANARY","tag":')):
            with self.assertRaises(ValueError):
                containers.parse_images(value, "fixture", "podman", "user:1000", AT)

    def test_duplicate_and_unlisted_inspect_identities_are_rejected(self):
        for value in (json.dumps(selected()) + "\n" + json.dumps(selected()), json.dumps(selected(id="c" * 64)), '{"id":"x","id":"y"}'):
            with self.assertRaises(ValueError):
                containers.parse_containers(value, [CID], "fixture", "podman", "user:1000", AT)


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.uid = patch.object(containers.os, "getuid", return_value=1000)
        self.euid = patch.object(containers.os, "geteuid", return_value=1000)
        self.uid.start()
        self.euid.start()
        self.addCleanup(self.uid.stop)
        self.addCleanup(self.euid.stop)

    def test_opt_in_only_and_fixed_local_endpoints(self):
        with patch.object(containers, "run", side_effect=AssertionError("Not opted in")):
            self.assertEqual(containers.observe_containers("fixture", [], AT), ([], [], []))
        self.assertEqual(containers.command("podman", ["ps"]), ["/usr/bin/podman", "--remote=false", "ps"])
        self.assertEqual(containers.command("docker", ["ps"]), ["/usr/bin/docker", "--host=unix:///var/run/docker.sock", "ps"])

    def test_one_batch_includes_all_selected_metadata(self):
        outputs = [(CID + "\n", 0), (json.dumps(selected()), 0), (image_output(), 0)]
        with patch.object(containers, "run", side_effect=outputs) as run:
            works, images, coverage = containers.observe_containers("fixture", ["podman"], AT)
        self.assertEqual(len(works), 1)
        self.assertEqual(len(images), 1)
        self.assertEqual(coverage[0]["status"], "complete")
        self.assertEqual(run.call_args_list[1].args[1], ["container", "inspect", "--format", containers.INSPECT_FORMAT.replace("json .Id", "json .ID"), CID])
        self.assertEqual(len({call.args[2] for call in run.call_args_list}), 1)

    def test_unavailable_engine_does_not_discard_other_engine(self):
        def fake(engine, arguments, deadline):
            if engine == "podman":
                raise OSError("SECRET_CANARY")
            return (image_output(), 0) if arguments[0] == "images" else ("", 0)
        with patch.object(containers, "run", side_effect=fake) as run, patch.object(containers, "docker_socket_safe", return_value=True), patch.object(containers.time, "monotonic", return_value=10):
            works, images, coverage = containers.observe_containers("fixture", ["podman", "docker"], AT)
        self.assertEqual([c["status"] for c in coverage], ["unavailable", "complete"])
        self.assertEqual(images[0]["backend"], "docker")
        self.assertEqual(works, [])
        self.assertNotIn("SECRET_CANARY", json.dumps(coverage))
        self.assertEqual({call.args[2] for call in run.call_args_list}, {11.5, 13.0})

    def test_inspect_and_image_failures_preserve_other_selected_evidence(self):
        cases = [([(CID + "\n", 0), OSError("SECRET_CANARY"), (image_output(), 0)], 0, 1),
                 ([(CID + "\n", 0), (json.dumps(selected()), 1), OSError("SECRET_CANARY")], 1, 0)]
        for outputs, work_count, image_count in cases:
            with patch.object(containers, "run", side_effect=outputs):
                works, images, coverage = containers.observe_containers("fixture", ["podman"], AT)
            self.assertEqual(len(works), work_count)
            self.assertEqual(len(images), image_count)
            self.assertEqual(coverage[0]["status"], "partial")
            self.assertNotIn("SECRET_CANARY", json.dumps([works, images, coverage]))

    def test_socket_activation_is_refused_without_contacting_docker(self):
        with patch.object(containers, "docker_socket_safe", return_value=False), patch.object(containers, "run", side_effect=AssertionError("No socket connection")):
            works, images, coverage = containers.observe_containers("fixture", ["docker"], AT)
        self.assertEqual((works, images, coverage[0]["status"]), ([], [], "unavailable"))
        for state, expected in (("active", False), ("activating", False), ("inactive", True)):
            with patch.object(containers, "_run_command", return_value=("LoadState=loaded\nActiveState=" + state + "\n", 0)):
                self.assertEqual(containers.docker_socket_safe(10), expected)

    def test_exhausted_batch_budget_never_starts_a_command(self):
        with patch.object(containers.time, "monotonic", return_value=20), \
             patch.object(containers.subprocess, "Popen", side_effect=AssertionError("Expired budget")):
            works, images, coverage = containers.observe_containers("fixture", ["podman", "docker"], AT, deadline=19)
        self.assertEqual((works, images), ([], []))
        self.assertEqual([c["status"] for c in coverage], ["unavailable", "unavailable"])

    def test_runner_discards_context_environment_and_reaps_on_interrupt(self):
        child = MagicMock()
        child.poll.return_value = None
        selector = MagicMock()
        selector.__enter__.return_value = selector
        selector.get_map.return_value = {1: True}
        selector.select.side_effect = KeyboardInterrupt
        with patch.object(containers.subprocess, "Popen", return_value=child) as popen, patch.object(containers.selectors, "DefaultSelector", return_value=selector), patch.object(containers.time, "monotonic", return_value=0), patch.dict(containers.os.environ, {"CONTAINER_HOST": "ssh://secret", "DOCKER_HOST": "tcp://secret", "DOCKER_CONTEXT": "secret"}):
            with self.assertRaises(KeyboardInterrupt):
                containers.run("podman", ["ps"], 1)
        self.assertEqual(set(popen.call_args.kwargs["env"]), {"PATH", "HOME", "LANG", "XDG_RUNTIME_DIR"})
        self.assertEqual(popen.call_args.kwargs["env"]["XDG_RUNTIME_DIR"], "/run/user/1000")
        child.kill.assert_called_once()
        child.wait.assert_called_once()
        child.stdout.close.assert_called_once()

    def test_probe_preserves_systemd_when_container_scope_fails(self):
        record = {**config(), "user_units": ["notes.service"]}
        properties = {"Id": "notes.service", "LoadState": "loaded", "ActiveState": "active", "SubState": "running"}
        with patch.object(probe.platform, "system", return_value="Linux"), patch.object(probe.platform, "node", return_value="fixture"), patch.object(probe, "text", side_effect=OSError), patch.object(probe, "cpu", side_effect=OSError), patch.object(probe, "memory", side_effect=OSError), patch.object(probe, "gpus", return_value=[]), patch.object(probe, "storage", return_value=({"devices": [], "filesystems": []}, False)), patch.object(probe, "systemctl", return_value=({"notes.service": properties}, 0)), patch.object(containers, "run", side_effect=OSError("SECRET_CANARY")):
            value = probe.observe(record)
        self.assertEqual(value["workloads"][0]["backend"], "systemd")
        self.assertEqual(value["workloads"][0]["lifecycle"], "running")
        self.assertEqual({c["scope"]: c["status"] for c in value["coverage"]}["podman:user:1000"], "unavailable")
        collector._validate_snapshot(json.dumps(value), record)


class TransportValidationTests(unittest.TestCase):
    def test_valid_selected_metadata_and_sanitized_rejection(self):
        self.assertEqual(collector._validate_snapshot(json.dumps(observed()), config())["artifacts"][0]["native_id"], IID)
        mutations = [lambda s: s["workloads"][0].update(scope="user:1001"),
                     lambda s: s["workloads"][0].update(native_id=CID[:12]),
                     lambda s: s["workloads"][0].update(id="forged"),
                     lambda s: s["workloads"][0].update(backend="docker"),
                     lambda s: s["workloads"][0]["extensions"]["container.v1"].update(environment="guessed"),
                     lambda s: s["workloads"][0]["extensions"]["container.v1"].update(env="SECRET_CANARY"),
                     lambda s: s["workloads"][0]["extensions"]["container.v1"]["mounts"][0].update(read_only="false"),
                     lambda s: s["artifacts"][0].update(scope="system"),
                     lambda s: s["artifacts"][0].update(id="forged"),
                     lambda s: s["artifacts"][0]["extensions"]["container.v1"].update(labels="SECRET_CANARY"),
                     lambda s: s["coverage"][-1].update(scope="podman:user:1001"),
                     lambda s: s["coverage"][-1].update(status="unavailable"),
                     lambda s: s["workloads"].append(copy.deepcopy(s["workloads"][0]))]
        for mutate in mutations:
            value = observed()
            mutate(value)
            with self.assertRaises(collector.CollectionError) as error:
                collector._validate_snapshot(json.dumps(value), config())
            self.assertNotIn("SECRET_CANARY", str(error.exception))
        with self.assertRaises(collector.CollectionError):
            collector._validate_snapshot(json.dumps(observed()), {**config(), "container_engines": []})

    def test_complete_systemd_scope_is_not_satisfied_by_container_scope(self):
        value = observed()
        with self.assertRaises(collector.CollectionError):
            collector._validate_snapshot(json.dumps(value), {**config(), "user_units": ["notes.service"]})


if __name__ == "__main__":
    unittest.main()
