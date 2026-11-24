"""Isolated consumer-visible Compose lifecycle tests; no container engine access."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from switchyard import compose_remote as remote


class ComposeFixture:
    def __init__(self, root):
        self.root = root
        self.manifest = root / "compose.yaml"
        self.manifest.write_text("services:\n  web:\n    image: example/web\n  db:\n    image: example/db\n")
        self.plugin = root / "docker-compose"
        self.plugin.write_bytes(b"fixture-compose-plugin")
        self.config = {"backend": "compose", "name": "Test application", "host_id": "test",
                       "provider": "podman-compose", "project_name": "example",
                       "project_directory": str(root), "files": [str(self.manifest)],
                       "services": ["web", "db"]}
        self.services = ["web", "db"]
        self.rendered = "services:\n  db: {image: example/db}\n  web: {image: example/web, environment: {TOKEN: SECRET}}\n"
        self.model = {"services": {"web": {"image": "example/web", "environment": {"TOKEN": "SECRET"}},
                                   "db": {"image": "example/db"}}}
        self.targets = {"web": ["custom-web"], "db": ["example_db_1"]}
        self.version = "1.0.6"
        self.docker_version = "2.32.4"
        self.graphroot = str(root / "storage")
        self.daemon_id = "fixture-daemon"
        self.socket_active = False
        self.daemon_active = True
        self.owner_loaded = False
        self.calls = []
        self.mutations = []
        self.records = [self.record("web", "a" * 64, "custom-web"),
                        self.record("db", "b" * 64, "example_db_1")]
        self.mutation_error = None
        self.spawn_error = False
        self.no_transition = False
        self.definition_drift_after_mutation = False
        self.render_drift = False
        self.render_count = 0
        self.extra_plan = ""
        self.engine_hash = "e" * 64
        self.real_file_hash = remote.file_hash

    def record(self, service, native, name, number="1"):
        return {"id": native, "name": name, "status": "running", "running": True, "paused": False,
                "started": "2026-11-22T12:00:00Z", "finished": "0001-01-01T00:00:00Z", "exit_code": 0,
                "labels": {"project": "example", "service": service, "directory": str(self.root),
                           "files": str(self.manifest), "number": number, "oneoff": None,
                           "docker_hash": None, "podman_hash": "c" * 64, "podman_project": "example",
                           # Actual 1.0.6 does not emit io.podman.compose.service.
                           "podman_service": None, "systemd_unit": "podman-compose@example.service"}}

    def docker(self):
        self.config["provider"] = "docker-compose-v2"
        for record in self.records:
            labels = record["labels"]
            labels.update({"podman_hash": None, "podman_project": None, "podman_service": None,
                           "systemd_unit": None, "docker_hash": "c" * 64, "oneoff": "False"})

    def hash_file(self, path, maximum=4 * remote.LIMIT):
        if str(path).startswith("/usr/bin/"):
            return self.engine_hash
        return self.real_file_hash(path, maximum)

    def command(self, runtime, args, *, mutation=False, diagnostics=False, allow_failure=False):
        self.calls.append(list(args))
        out, errors, code = "", "PRIVATE diagnostic SECRET", 0
        if mutation:
            if self.spawn_error:
                raise OSError("SECRET executable detail")
            runtime.mutation_issued = True
            self.mutations.append(list(args))
            if self.mutation_error:
                raise self.mutation_error
            action = next(a for a in remote.ACTIONS if a in args)
            if not self.no_transition:
                for record in self.records:
                    record["running"] = action != "stop"
                    record["status"] = "running" if action != "stop" else "exited"
                    if action == "stop":
                        record["finished"] = "2026-11-22T12:01:00Z"
                    elif action == "restart" or record["started"] != "2026-11-22T12:00:00Z":
                        record["started"] = "2026-11-22T12:02:00Z"
            if self.definition_drift_after_mutation:
                self.rendered += "# changed effective model\n"
            return ""
        if args[0] == "/usr/bin/systemctl":
            unit = args[-1]
            if unit == "docker.socket":
                active = "active" if self.socket_active else "inactive"
                out = "LoadState=loaded\nActiveState=" + active + "\n"
            elif unit == "docker.service":
                active = "active" if self.daemon_active else "inactive"
                out = "LoadState=loaded\nActiveState=" + active + "\n"
            else:
                out = "LoadState=loaded\nActiveState=inactive\n" if self.owner_loaded else "LoadState=not-found\nActiveState=inactive\n"
                code = 0 if self.owner_loaded else 4
        elif args == ["/usr/bin/podman-compose", "--version"]:
            out = "podman version 4.9.3\npodman-compose version " + self.version + "\n"
        elif "compose" in args and "version" in args:
            out = self.docker_version + "\n"
        elif args[0] == "/usr/bin/podman-compose" or "compose" in args:
            if "--dry-run" in args:
                service = args[-1]
                launcher = args[args.index("--podman-path") + 1]
                prefix = ("" if self.version == "1.0.6" else "INFO:podman_compose:") + launcher + " start "
                errors += "\n" + "\n".join(prefix + name for name in self.targets[service]) + self.extra_plan.replace("{launcher}", launcher)
            elif "--services" in args:
                out = "\n".join(self.services) + "\n"
            elif "config" in args:
                self.render_count += 1
                out = json.dumps(self.model) if "--format" in args else self.rendered
                if self.render_drift and self.render_count % 2 == 0:
                    out += "# changed\n"
            else:
                raise AssertionError("Unexpected provider command: " + repr(args))
        elif "info" in args:
            if args[0] == "/usr/bin/podman":
                out = json.dumps({"graph": self.graphroot, "run": str(self.root / "run"),
                                  "rootless": True, "version": "4.9.3"})
            else:
                out = json.dumps({"id": self.daemon_id,
                                  "plugins": [{"Name": "compose", "Path": str(self.plugin)}]})
        elif "ps" in args:
            label = args[args.index("--filter") + 1]
            key = "podman_project" if "io.podman" in label else "project"
            out = "\n".join(r["id"] for r in self.records if r["labels"].get(key) == "example")
        elif "inspect" in args:
            ids = args[args.index("--format") + 2:]
            out = "\n".join(json.dumps(r) for r in self.records if r["id"] in ids)
        else:
            raise AssertionError("Unexpected engine command: " + repr(args))
        if not allow_failure and code:
            raise remote.Refusal("Compose command failed or capability unsupported")
        return (out, errors, code) if diagnostics else out


class ComposeRemoteTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.fixture = ComposeFixture(self.root)
        self.real_stat = Path.stat
        fixture = self.fixture

        def fake_stat(path, *args, **kwargs):
            if str(path) == "/var/run/docker.sock":
                return SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_dev=1, st_ino=123, st_uid=0)
            return self.real_stat(path, *args, **kwargs)

        def command(runtime, args, **kwargs):
            return fixture.command(runtime, args, **kwargs)

        for patcher in (patch.object(remote.Runtime, "command", new=command),
                        patch.object(remote, "file_hash", side_effect=fixture.hash_file),
                        patch.object(remote.Path, "home", return_value=self.root),
                        patch.object(remote.Path, "stat", new=fake_stat),
                        patch.object(remote.os, "getuid", return_value=1000),
                        patch.object(remote.os, "geteuid", return_value=1000)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def request(self, action="inspect", expected=None, config=None):
        return remote.run({"action": action, "config": config or self.fixture.config, "expected": expected})

    def inspection(self):
        result = self.request()
        self.assertEqual(result["status"], "succeeded", result)
        return result["inspection"]

    def test_inspect_pins_complete_native_project_without_secret_disclosure(self):
        result = self.inspection()
        self.assertEqual(result["supported_actions"], ["start", "stop", "restart"])
        self.assertEqual(result["lifecycle"], "running")
        self.assertEqual(result["health"], "unknown")
        self.assertIn("not verified", result["warnings"][0])
        self.assertEqual(result["identity"]["rendered_sha256"], hashlib.sha256(self.fixture.rendered.encode()).hexdigest())
        self.assertEqual(result["resources"], [
            {"backend": "podman", "scope": "user:1000", "native_id": "a" * 64, "name": "custom-web"},
            {"backend": "podman", "scope": "user:1000", "native_id": "b" * 64, "name": "example_db_1"}])
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertNotIn("environment", result["state"])
        self.assertEqual(self.fixture.mutations, [])
        self.assertEqual(self.inspection(), result)
        for call in self.fixture.calls:
            if "ps" in call:
                self.assertIn("--filter", call)
            self.assertFalse(any(x in call for x in ("up", "down", "pull", "create", "run")))

    def test_stop_start_restart_use_compose_not_engine_lifecycle(self):
        before = self.inspection()
        stopped = self.request("stop", before)
        self.assertEqual(stopped["status"], "succeeded", stopped)
        self.assertEqual(stopped["inspection"]["lifecycle"], "stopped")
        started = self.request("start", stopped["inspection"])
        self.assertEqual(started["status"], "succeeded", started)
        restarted = self.request("restart", started["inspection"])
        self.assertEqual(restarted["status"], "succeeded", restarted)
        self.assertEqual(len(self.fixture.mutations), 3)
        for action, call in zip(("stop", "start", "restart"), self.fixture.mutations):
            self.assertEqual(call[0], "/usr/bin/podman-compose")
            self.assertEqual(call[-3:], [action, "db", "web"])

    def test_all_stale_preconditions_fail_before_first_mutation(self):
        for kind in ("id", "state", "manifest", "rendered", "runtime", "provider_hash"):
            with self.subTest(kind=kind):
                before = self.inspection()
                original = copy.deepcopy(self.fixture.records)
                original_render = self.fixture.rendered
                original_bytes = self.fixture.manifest.read_bytes()
                if kind == "id":
                    self.fixture.records[0]["id"] = "d" * 64
                elif kind == "state":
                    self.fixture.records[0]["started"] = "2026-11-22T12:05:00Z"
                elif kind == "manifest":
                    self.fixture.manifest.write_bytes(original_bytes + b"# changed\n")
                elif kind == "rendered":
                    self.fixture.rendered += "# interpolated value changed\n"
                elif kind == "runtime":
                    self.fixture.graphroot += "-different"
                else:
                    self.fixture.engine_hash = "f" * 64
                result = self.request("stop", before)
                self.assertEqual(result["status"], "failed", result)
                self.assertIn("Stale", result["error"])
                self.assertEqual(self.fixture.mutations, [])
                self.fixture.records = original
                self.fixture.rendered = original_render
                self.fixture.manifest.write_bytes(original_bytes)

    def test_explicit_inspection_is_required_for_every_mutation(self):
        result = self.request("restart")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(self.fixture.mutations, [])

    def test_incomplete_project_or_extra_orphan_or_foreign_container_refused(self):
        for kind in ("missing-service", "unconfigured-service", "orphan", "foreign-files", "foreign-project",
                     "oneoff", "duplicate-replica", "custom-name-collision", "foreign-provider"):
            with self.subTest(kind=kind):
                records, services = copy.deepcopy(self.fixture.records), list(self.fixture.services)
                if kind == "missing-service":
                    self.fixture.records.pop()
                elif kind == "unconfigured-service":
                    self.fixture.services.append("unadopted")
                elif kind == "orphan":
                    self.fixture.records.append(self.fixture.record("other", "d" * 64, "orphan"))
                elif kind == "foreign-files":
                    self.fixture.records[0]["labels"]["files"] = "/different/compose.yaml"
                elif kind == "foreign-project":
                    self.fixture.records[0]["labels"]["project"] = "somebody-else"
                elif kind == "oneoff":
                    self.fixture.records[0]["labels"]["oneoff"] = "True"
                elif kind == "duplicate-replica":
                    self.fixture.records.append(self.fixture.record("web", "d" * 64, "extra-web"))
                elif kind == "custom-name-collision":
                    self.fixture.targets["web"] = ["unowned-personal-container"]
                else:
                    self.fixture.records[0]["labels"]["podman_service"] = "other"
                result = self.request()
                self.assertEqual(result["status"], "failed", result)
                self.assertEqual(self.fixture.mutations, [])
                self.fixture.records, self.fixture.services = records, services
                self.fixture.targets["web"] = ["custom-web"]

    def test_native_podman_replicas_must_exactly_match_provider_targets(self):
        self.fixture.targets["web"].append("example_web_2")
        self.fixture.records.append(self.fixture.record("web", "d" * 64, "example_web_2", "2"))
        self.assertEqual(len(self.inspection()["resources"]), 3)
        self.fixture.records.pop()
        self.assertEqual(self.request()["status"], "failed")

    def test_external_systemd_and_quadlet_owners_are_not_adopted(self):
        for kind in ("loaded-unit", "registration", "other-unit", "quadlet", "autoupdate", "manager"):
            with self.subTest(kind=kind):
                labels = self.fixture.records[0]["labels"]
                original = labels.copy()
                registration = self.root / ".config/containers/compose/projects/example.env"
                if kind == "loaded-unit":
                    self.fixture.owner_loaded = True
                elif kind == "registration":
                    registration.parent.mkdir(parents=True, exist_ok=True)
                    registration.write_text("not-disclosed")
                elif kind == "other-unit":
                    labels["systemd_unit"] = "protected.service"
                else:
                    labels[kind] = "owner"
                result = self.request()
                self.assertEqual(result["status"], "failed", result)
                self.assertIn("owner", result["error"])
                self.assertEqual(self.fixture.mutations, [])
                labels.clear()
                labels.update(original)
                self.fixture.owner_loaded = False
                registration.unlink(missing_ok=True)

    def test_dotenv_application_values_are_private_pinned_inputs(self):
        dotenv = self.root / ".env"
        dotenv.write_text("TOKEN=APPLICATION_SECRET\n")
        before = self.inspection()
        self.assertEqual(before["identity"]["environment_input"]["sha256"], hashlib.sha256(dotenv.read_bytes()).hexdigest())
        self.assertNotIn("APPLICATION_SECRET", json.dumps(before))
        for call in self.fixture.calls:
            if "--env-file" in call:
                path = Path(call[call.index("--env-file") + 1])
                self.assertNotEqual(path, dotenv)
                self.assertFalse(path.exists(), "private environment snapshot must be cleaned up")
        dotenv.write_text("TOKEN=DIFFERENT_SECRET\n")
        self.assertEqual(self.request("stop", before)["status"], "failed")
        self.assertEqual(self.fixture.mutations, [])

    def test_dotenv_cannot_redirect_engine_context_or_provider(self):
        for value in ("DOCKER_HOST=tcp://elsewhere", "export 'CONTAINER_HOST'=ssh://elsewhere",
                      "PODMAN_COMPOSE_PROVIDER=evil", "COMPOSE_FILE=/different.yaml"):
            with self.subTest(value=value):
                (self.root / ".env").write_text(value + "\n")
                self.fixture.calls.clear()
                result = self.request()
                self.assertEqual(result["status"], "failed")
                self.assertIn("provider-control", result["error"])
                self.assertEqual(self.fixture.calls, [])
                self.assertNotIn(value, json.dumps(result))

    def test_unknown_provider_version_or_dry_run_capability_fails_closed(self):
        self.fixture.version = "9.9.9"
        self.assertIn("Unsupported", self.request()["error"])
        self.fixture.version = "1.0.6"
        self.fixture.extra_plan = "\n{launcher} start foreign-container\n"
        self.assertEqual(self.request()["status"], "failed")
        self.assertEqual(self.fixture.mutations, [])

    def test_current_supported_podman_logging_and_service_labels(self):
        self.fixture.version = "1.6.0"
        for record in self.fixture.records:
            record["labels"]["podman_service"] = record["labels"]["service"]
        result = self.inspection()
        self.assertEqual(result["identity"]["runtime"]["provider_version"], "1.6.0")
        plans = [c for c in self.fixture.calls if "--dry-run" in c]
        self.assertTrue(all("--verbose" in c for c in plans))

    def test_changed_effective_config_during_inspection_is_not_evidence(self):
        self.fixture.render_drift = True
        result = self.request()
        self.assertEqual(result["status"], "failed")
        self.assertIn("changed during inspection", result["error"])

    def test_failure_after_mutation_is_needs_inspection_without_retry_or_diagnostics(self):
        before = self.inspection()
        for error in (subprocess.TimeoutExpired("SECRET command", 30),
                      remote.Refusal("Compose command failed or capability unsupported"),
                      OSError("SECRET transport diagnostics")):
            with self.subTest(error=type(error).__name__):
                self.fixture.mutation_error = error
                self.fixture.mutations.clear()
                result = self.request("stop", before)
                self.assertEqual(result["status"], "needs-inspection", result)
                self.assertEqual(len(self.fixture.mutations), 1)
                self.assertNotIn("SECRET", json.dumps(result))
                self.assertNotIn("inspection", result)

    def test_spawn_failure_is_pre_mutation_failure(self):
        before = self.inspection()
        self.fixture.spawn_error = True
        self.assertEqual(self.request("stop", before)["status"], "failed")
        self.assertEqual(self.fixture.mutations, [])

    def test_native_postcondition_and_restart_incarnation_are_required(self):
        before = self.inspection()
        self.fixture.no_transition = True
        for action in ("stop", "restart"):
            result = self.request(action, before)
            self.assertEqual(result["status"], "needs-inspection", result)
            self.assertNotIn("inspection", result)

    def test_definition_change_after_action_is_uncertain_not_success(self):
        before = self.inspection()
        self.fixture.definition_drift_after_mutation = True
        result = self.request("stop", before)
        self.assertEqual(result["status"], "needs-inspection")
        self.assertEqual(len(self.fixture.mutations), 1)

    def test_paused_or_transitional_state_is_not_claimed_healthy(self):
        for key, value in (("paused", True), ("status", "restarting"), ("status", "dead")):
            original = self.fixture.records[0].copy()
            self.fixture.records[0][key] = value
            result = self.request()
            self.assertEqual(result["status"], "failed")
            self.fixture.records[0] = original

    def test_configuration_cannot_inject_flags_paths_or_unapproved_actions(self):
        for change in ({"services": ["--all"]}, {"project_name": "--other"},
                       {"files": ["relative.yaml"]}, {"provider": "docker-compose"},
                       {"project_directory": "/missing/fixture"}):
            config = {**self.fixture.config, **change}
            self.assertEqual(self.request(config=config)["status"], "failed")
        for action in ("up", "down", "pull", "migrate", "enable"):
            self.assertEqual(self.request(action)["status"], "failed")
        self.assertEqual(self.fixture.mutations, [])

    def test_imported_models_and_unpinnable_podman_env_files_are_explicitly_unsupported(self):
        for source, reason in (
            ('include: [https://unapproved.invalid/compose.yaml]\n', "imported"),
            ('services:\n  web:\n    extends: {file: /personal/compose.yaml, service: secret}\n', "imported"),
            ('services:\n  web:\n    env_file: /personal/secret.env\n', "env_file"),
            ('"incl\\u0075de": ["https://unapproved.invalid/model"]\n', "escaped"),
        ):
            with self.subTest(reason=reason):
                self.fixture.manifest.write_text(source)
                self.fixture.calls.clear()
                result = self.request()
                self.assertEqual(result["status"], "failed", result)
                self.assertIn(reason, result["error"])
                self.assertFalse(any("config" in call for call in self.fixture.calls))
                self.assertEqual(self.fixture.mutations, [])

    def test_symlinked_dotenv_is_not_silently_followed(self):
        target = self.root / "personal.env"
        target.write_text("TOKEN=PRIVATE\n")
        (self.root / ".env").symlink_to(target)
        result = self.request()
        self.assertEqual(result["status"], "failed")
        self.assertIn(".env", result["error"])
        self.assertEqual(self.fixture.calls, [])

    def test_docker_socket_activation_blocks_before_any_docker_contact(self):
        self.fixture.docker()
        self.fixture.socket_active = True
        result = self.request()
        self.assertEqual(result["status"], "failed")
        self.assertIn("socket activation", result["error"])
        self.assertTrue(all(c[0] == "/usr/bin/systemctl" for c in self.fixture.calls))
        self.assertEqual(self.fixture.mutations, [])

    def test_docker_daemon_must_already_be_running(self):
        self.fixture.docker()
        self.fixture.daemon_active = False
        self.assertEqual(self.request()["status"], "failed")
        self.assertTrue(all(c[0] == "/usr/bin/systemctl" for c in self.fixture.calls))

    def test_docker_is_bound_to_local_socket_plugin_and_daemon_identity(self):
        self.fixture.docker()
        before = self.inspection()
        self.assertEqual(before["resources"][0]["backend"], "docker")
        self.assertEqual(before["resources"][0]["scope"], "system")
        self.assertEqual(before["identity"]["runtime"]["daemon_id"], "fixture-daemon")
        for call in self.fixture.calls:
            if call[0] == "/usr/bin/docker":
                self.assertEqual(call[:3], ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"])
        self.fixture.daemon_id = "replacement-daemon"
        self.assertEqual(self.request("stop", before)["status"], "failed")
        self.assertEqual(self.fixture.mutations, [])

    def test_docker_requires_v2_and_rejects_external_hooks_and_extra_replicas(self):
        self.fixture.docker()
        self.fixture.docker_version = "1.29.2"
        self.assertEqual(self.request()["status"], "failed")
        self.fixture.docker_version = "2.32.4"
        self.fixture.model["services"]["web"]["post_start"] = [{"command": "SECRET external hook"}]
        self.assertEqual(self.request()["status"], "failed")
        del self.fixture.model["services"]["web"]["post_start"]
        extra = copy.deepcopy(self.fixture.records[0])
        extra.update({"id": "d" * 64, "name": "extra-web"})
        extra["labels"]["number"] = "2"
        self.fixture.records.append(extra)
        result = self.request()
        self.assertEqual(result["status"], "failed")
        self.assertIn("replicas", result["error"])
        self.fixture.model["services"]["web"]["deploy"] = {"replicas": 2}
        self.assertEqual(len(self.inspection()["resources"]), 3)


class CommandIsolationTests(unittest.TestCase):
    """Only launches local throwaway Python children, never engine/systemctl."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.config = {"provider": "podman-compose", "project_name": "fixture", "files": [],
                       "project_directory": temporary.name}

    def test_environment_stdin_and_deadline_are_enforced_at_process_boundary(self):
        runtime = remote.Runtime(self.config)
        self.addCleanup(runtime.close)
        code = "import json, os, sys; print(json.dumps(dict(os.environ))); print(repr(sys.stdin.read()))"
        with patch.dict(os.environ, {"DOCKER_CONTEXT": "personal-remote", "DOCKER_HOST": "tcp://remote",
                                     "CONTAINER_HOST": "ssh://remote", "PODMAN_COMPOSE_PROVIDER": "evil",
                                     "COMPOSE_FILE": "personal.yaml", "SECRET": "PRIVATE"}):
            result = runtime.command([sys.executable, "-c", code])
        environment = json.loads(result.splitlines()[0])
        for key in ("DOCKER_CONTEXT", "DOCKER_HOST", "CONTAINER_HOST", "PODMAN_COMPOSE_PROVIDER", "COMPOSE_FILE", "SECRET"):
            self.assertNotIn(key, environment)
        self.assertEqual(result.splitlines()[1], "''")
        runtime.deadline = 0
        with patch.object(remote.subprocess, "Popen") as spawn:
            with self.assertRaises(remote.Refusal):
                runtime.command([sys.executable, "-c", "pass"])
            spawn.assert_not_called()

    def test_local_launcher_keeps_endpoint_flag_before_provider_subcommand(self):
        runtime = remote.Runtime(self.config)
        self.addCleanup(runtime.close)
        engine = Path(self.config["project_directory"]) / "engine.py"
        engine.write_text("import json,sys; print(json.dumps(sys.argv[1:]))")
        runtime.engine = [sys.executable, str(engine), "--remote=false"]
        runtime.environment_input()
        launcher = Path(runtime.compose[runtime.compose.index("--podman-path") + 1])
        self.assertTrue(launcher.is_relative_to(runtime.scratch.name))
        self.assertEqual(launcher.stat().st_mode & 0o777, 0o700)
        output = runtime.command([str(launcher), "start", "owned-container"])
        self.assertEqual(json.loads(output), ["--remote=false", "start", "owned-container"])
        runtime.close()
        self.assertFalse(launcher.exists())

    def test_output_is_bounded_and_mutation_bookkeeping_survives_overflow(self):
        runtime = remote.Runtime(self.config)
        self.addCleanup(runtime.close)
        with self.assertRaisesRegex(remote.Refusal, "output exceeds limit"):
            runtime.command([sys.executable, "-c", "import sys; sys.stderr.write('SECRET' * 200000)"], mutation=True)
        self.assertTrue(runtime.mutation_issued)

    def test_timeout_terminates_process_group_and_does_not_return_diagnostics(self):
        runtime = remote.Runtime(self.config)
        self.addCleanup(runtime.close)
        runtime.deadline = remote.time.monotonic() + 0.1
        with patch.object(remote.os, "killpg", wraps=os.killpg) as kill:
            with self.assertRaisesRegex(remote.Refusal, "deadline"):
                runtime.command([sys.executable, "-c", "import time; time.sleep(10)"], mutation=True)
        kill.assert_called_once()
        self.assertTrue(runtime.mutation_issued)

    def test_environment_snapshot_is_private_and_refuses_concurrent_source_drift(self):
        directory = Path(self.config["project_directory"])
        dotenv = directory / ".env"
        dotenv.write_text("TOKEN=PRIVATE\n")
        runtime = remote.Runtime(self.config)
        self.addCleanup(runtime.close)
        evidence = runtime.environment_input()
        path = Path(runtime.compose[runtime.compose.index("--env-file") + 1])
        self.assertEqual(path.read_text(), "TOKEN=PRIVATE\n")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        self.assertNotIn("PRIVATE", json.dumps(evidence))
        dotenv.write_text("DOCKER_HOST=ssh://unapproved\n")
        self.assertEqual(path.read_text(), "TOKEN=PRIVATE\n")
        with self.assertRaisesRegex(remote.Refusal, "changed"):
            runtime.environment_input()
        runtime.close()
        self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
