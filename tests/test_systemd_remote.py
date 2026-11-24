"""Consumer-facing offline regression cases; never contact a real manager."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from switchyard import lifecycle_ops, systemd_remote as remote


class NativeManager:
    def __init__(self, fragment):
        self.calls = []
        self.units = {}
        self.manager = {"Version": "249.11", "SystemState": "running", "NJobs": "0"}
        self.effect = None
        self.add("fixture.service", fragment)

    def add(self, name, fragment, **overrides):
        unit = {key: "" for key in remote.COMMON + remote.SERVICE}
        unit.update({"Id": name, "Names": name, "LoadState": "loaded", "ActiveState": "active",
                     "SubState": "running", "FragmentPath": str(fragment), "NeedDaemonReload": "no",
                     "Transient": "no", "Job": "", "StopWhenUnneeded": "no",
                     "RefuseManualStart": "no", "RefuseManualStop": "no", "Type": "simple",
                     "RemainAfterExit": "no", "Result": "success", "InvocationID": "a" * 32,
                     "ExecMainCode": "0", "ExecMainStatus": "0", "CanStart": "yes", "CanStop": "yes",
                     "Restart": "no", "NRestarts": "0", "SuccessAction": "none",
                     "FailureAction": "none", "StartLimitAction": "none"})
        unit.update(overrides)
        self.units[name] = unit
        return unit

    @property
    def mutations(self):
        return [args for scope, args, deadline in self.calls if "--job-mode=fail" in args]

    def __call__(self, scope, args, deadline):
        self.calls.append((scope, args, deadline))
        if args[0] == "show":
            source = self.units[args[-1]] if "--" in args else self.manager
            names = args[2].split("=", 1)[1].split(",")
            return "\n".join(name + "=" + source[name] for name in names if name in source) + "\n"
        action, name = args[1], args[-1]
        unit = self.units[name]
        if self.effect:
            self.effect(action, unit)
        elif action == "stop":
            unit.update(ActiveState="inactive", SubState="dead")
        else:
            unit.update(ActiveState="active", SubState="running", Result="success", InvocationID="b" * 32)
        return ""


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.fragment = self.root / "fixture.service"
        self.fragment.write_text("[Service]\nType=simple\nExecStart=/bin/sleep infinity\nEnvironment=SECRET=private-value\n")
        self.fragment.chmod(0o600)
        self.native = NativeManager(self.fragment)
        command_patch = patch.object(remote, "command", side_effect=self.native)
        command_patch.start()
        self.addCleanup(command_patch.stop)
        boot_patch = patch.object(remote, "boot_id", return_value="01234567-89ab-cdef-0123-456789abcdef")
        boot_patch.start()
        self.addCleanup(boot_patch.stop)
        self.config = {"backend": "systemd", "name": "Fixture", "host_id": "host",
                       "scope": "user", "unit": "fixture.service"}

    @property
    def unit(self):
        return self.native.units["fixture.service"]

    def request(self, action="inspect", expected=None):
        return remote.run({"action": action, "config": self.config, "expected": expected})

    def inspection(self):
        result = self.request()
        self.assertEqual(result["status"], "succeeded", result)
        return result["inspection"]

    def assert_no_mutation(self, result):
        self.assertEqual(result["status"], "failed", result)
        self.assertEqual(self.native.mutations, [])

    def test_inspection_is_sanitized_and_explicitly_not_health(self):
        first = self.inspection()
        self.assertEqual(first, self.inspection())
        self.assertEqual(first["supported_actions"], ["start", "stop", "restart"])
        self.assertEqual(first["lifecycle"], "running")
        self.assertEqual(first["health"], "unknown")
        self.assertIn("not application health", first["warnings"][0])
        self.assertEqual(first["identity"]["fragment"]["sha256"], hashlib.sha256(self.fragment.read_bytes()).hexdigest())
        self.assertEqual(first["resources"], [{"backend": "systemd", "scope": "user:" + str(os.getuid()),
                                               "native_id": "fixture.service", "name": "fixture.service"}])
        self.assertNotIn("private-value", json.dumps(first))
        self.assertNotIn("ExecStart", json.dumps(first))

    def test_start_stop_restart_use_only_exact_native_lifecycle(self):
        for action in ("stop", "start", "restart"):
            expected = self.inspection()
            if action == "restart":
                self.unit["InvocationID"] = "c" * 32
                expected = self.inspection()
            result = self.request(action, expected)
            self.assertEqual(result["status"], "succeeded", result)
            self.assertEqual(self.native.mutations[-1], ["--job-mode=fail", action, "--", "fixture.service"])
            self.assertEqual(result["inspection"]["lifecycle"], "stopped" if action == "stop" else "running")
        self.assertTrue(all(scope == "user" for scope, _, _ in self.native.calls))
        self.assertEqual(len({deadline for _, _, deadline in self.native.calls[-4:]}), 1)

    def test_system_scope_does_not_substitute_user_scope(self):
        self.config["scope"] = "system"
        expected = self.inspection()
        self.assertEqual(expected["resources"][0]["scope"], "system")
        result = self.request("stop", expected)
        self.assertEqual(result["status"], "succeeded", result)
        self.assertTrue(all(scope == "system" for scope, _, _ in self.native.calls))

    def test_missing_or_changed_approved_snapshot_cannot_mutate(self):
        self.assert_no_mutation(self.request("stop"))
        expected = self.inspection()
        self.unit["InvocationID"] = "c" * 32
        self.assert_no_mutation(self.request("stop", expected))
        expected = self.inspection()
        self.unit.update(ActiveState="inactive", SubState="dead")
        self.assert_no_mutation(self.request("start", expected))

    def test_fragment_and_dropin_bytes_bind_approval(self):
        dropin = self.root / "override.conf"
        dropin.write_text("[Service]\nRestart=no\n")
        self.unit["DropInPaths"] = str(dropin)
        expected = self.inspection()
        dropin.write_text("[Service]\nRestart=always\n")
        self.assert_no_mutation(self.request("restart", expected))
        expected = self.inspection()
        self.fragment.write_text("[Service]\nExecStart=/another/program\n")
        self.assert_no_mutation(self.request("stop", expected))

    def test_alias_template_glob_missing_and_reload_definitions_refused(self):
        for name in ("alias.service", "fixture@.service", "fixture@one.service", "*.service", "-fixture.service", "fixture.socket"):
            with self.subTest(name=name):
                self.config["unit"] = name
                self.assert_no_mutation(self.request())
        self.config["unit"] = "fixture.service"
        for field, value in (("Id", "another.service"), ("Names", "fixture.service alias.service"),
                             ("LoadState", "not-found"), ("LoadState", "masked"),
                             ("Transient", "yes"), ("NeedDaemonReload", "yes"),
                             ("Job", "123"), ("ActiveState", "activating")):
            with self.subTest(field=field, value=value):
                original = self.unit[field]
                self.unit[field] = value
                self.assert_no_mutation(self.request())
                self.unit[field] = original

    def test_unknown_manager_capabilities_and_busy_manager_refused(self):
        del self.unit["UpheldBy"]
        self.assert_no_mutation(self.request())
        self.unit["UpheldBy"] = ""
        self.native.manager["NJobs"] = "1"
        self.assert_no_mutation(self.request())

    def test_nonpersistent_and_manager_side_effect_shapes_are_inspectable_but_not_actionable(self):
        for field, value in (("Type", "oneshot"), ("RemainAfterExit", "yes"),
                             ("StopWhenUnneeded", "yes"), ("SuccessAction", "reboot"),
                             ("FailureAction", "exit"), ("StartLimitAction", "poweroff")):
            with self.subTest(field=field):
                original = self.unit[field]
                self.unit[field] = value
                expected = self.inspection()
                self.assertEqual(expected["supported_actions"], [])
                self.assert_no_mutation(self.request("start", expected))
                self.unit[field] = original

    def test_activators_and_reverse_stop_propagation_never_spill(self):
        for relation in remote.PROPAGATION:
            with self.subTest(relation=relation):
                self.unit[relation] = "outside.service"
                expected = self.inspection()
                self.assertEqual(expected["supported_actions"], [])
                self.assertTrue(any(relation in value for value in expected["warnings"]))
                self.assert_no_mutation(self.request("stop", expected))
                self.unit[relation] = ""

    def test_inactive_dependency_or_active_conflict_is_not_started_or_stopped(self):
        self.native.add("outside.service", self.root / "outside.service", ActiveState="inactive", SubState="dead")
        for relation, active in (("Requires", "inactive"), ("Wants", "inactive"), ("Conflicts", "active")):
            with self.subTest(relation=relation):
                self.native.units["outside.service"]["ActiveState"] = active
                self.unit[relation] = "outside.service"
                expected = self.inspection()
                self.assertEqual(expected["supported_actions"], [])
                self.assert_no_mutation(self.request("restart", expected))
                self.unit[relation] = ""

    def test_active_prerequisite_prunes_inactive_descendant_start_jobs(self):
        self.unit["Requires"] = "basic.target"
        self.native.add("basic.target", "", Wants="outside.service", SubState="active")
        self.native.add("outside.service", self.root / "outside.service", ActiveState="inactive", SubState="dead")
        expected = self.inspection()
        self.assertEqual(expected["supported_actions"], list(remote.ACTIONS))
        self.assertEqual(self.request("start", expected)["status"], "succeeded")

    def test_absent_transitive_want_is_pruned_but_absent_direct_prerequisite_blocks(self):
        self.unit["Requires"] = "app.slice"
        self.native.add("app.slice", "", SubState="active", Wants="systemd-oomd.service")
        absent = self.native.add("systemd-oomd.service", "", LoadState="not-found", ActiveState="inactive", SubState="dead")
        expected = self.inspection()
        self.assertEqual(expected["supported_actions"], list(remote.ACTIONS))
        self.assertEqual(self.request("start", expected)["status"], "succeeded")
        # The missing unit appearing is drift: the approval no longer describes the transaction.
        expected = self.inspection()
        absent.update(LoadState="loaded")
        mutations = len(self.native.mutations)
        self.assertEqual(self.request("stop", expected)["status"], "failed")
        self.assertEqual(len(self.native.mutations), mutations)
        self.unit["Requires"] = "systemd-oomd.service"
        absent.update(LoadState="not-found")
        self.assertEqual(self.inspection()["supported_actions"], [])

    def test_active_prerequisite_and_inactive_shutdown_conflict_can_be_preserved(self):
        self.unit.update(Requires="basic.target", Conflicts="shutdown.target")
        self.native.add("basic.target", "", SubState="active")
        self.native.add("shutdown.target", "", ActiveState="inactive", SubState="dead", Conflicts="fixture.service")
        expected = self.inspection()
        self.assertEqual(expected["supported_actions"], list(remote.ACTIONS))
        self.assertEqual(self.request("stop", expected)["status"], "succeeded")

    def test_quoted_escaped_desktop_relations_preserve_native_names(self):
        names = [r"app-dbus\x2d:1.1-" + str(i) + ".scope" for i in range(150)]
        self.unit["After"] = " ".join(json.dumps(name) for name in names)
        expected = self.inspection()
        self.assertEqual(expected["identity"]["properties"]["After"], sorted(names))
        self.assertEqual(self.request("stop", expected)["status"], "succeeded")
        self.assertEqual(len(self.native.mutations), 1)

    def test_absent_conflict_is_safe_but_becoming_active_invalidates_approval(self):
        self.unit["Conflicts"] = "unavailable.socket"
        for load in ("not-found", "masked"):
            other = self.native.add("unavailable.socket", "", LoadState=load,
                                    ActiveState="inactive", SubState="dead")
            expected = self.inspection()
            self.assertEqual(expected["supported_actions"], list(remote.ACTIONS))
            other.update(LoadState="loaded", ActiveState="active")
            self.assert_no_mutation(self.request("start", expected))

    def test_wide_desktop_dependencies_fit_broker_evidence_without_losing_drift_checks(self):
        targets = ["one.target", "two.target", "three.target", "four.target"]
        self.unit["Requires"] = " ".join(targets)
        relations = " ".join("app-" + str(i) + ".scope" for i in range(300))
        for target in targets:
            self.native.add(target, "", SubState="active", Before=relations, After=relations)
        expected = self.inspection()
        self.assertEqual(lifecycle_ops._inspection(expected, self.config["backend"]), expected)
        self.native.units["one.target"]["After"] += " newly-opened.scope"
        self.assert_no_mutation(self.request("start", expected))

    def test_own_start_stop_reverse_edges_are_not_unrelated_definition_drift(self):
        self.unit.update(Requires="basic.target", Conflicts="shutdown.target",
                         ActiveState="inactive", SubState="dead", InvocationID="")
        parent = self.native.add("basic.target", "", SubState="active")
        shutdown = self.native.add("shutdown.target", "", ActiveState="inactive", SubState="dead")

        def transition(action, unit):
            running = action != "stop"
            unit.update(ActiveState="active" if running else "inactive",
                        SubState="running" if running else "dead", InvocationID="b" * 32)
            edge = "fixture.service" if running else ""
            parent.update(RequiredBy=edge, Before=edge)
            shutdown.update(ConflictedBy=edge, After=edge)

        self.native.effect = transition
        for action in ("start", "stop"):
            result = self.request(action, self.inspection())
            self.assertEqual(result["status"], "succeeded", result)

    def test_native_dependency_invocation_drift_invalidates_approval(self):
        self.unit["Wants"] = "outside.service"
        dependency = self.native.add("outside.service", self.root / "outside.service")
        expected = self.inspection()
        dependency["InvocationID"] = "c" * 32
        self.assert_no_mutation(self.request("start", expected))

    def test_manual_refusal_removes_only_relevant_actions(self):
        self.unit["RefuseManualStart"] = "yes"
        self.assertEqual(self.inspection()["supported_actions"], ["stop"])
        self.unit.update(RefuseManualStart="no", RefuseManualStop="yes")
        self.assertEqual(self.inspection()["supported_actions"], ["start"])

    def test_mutation_failure_and_unproven_postcondition_need_inspection_without_retry(self):
        def fail(action, unit):
            raise subprocess.TimeoutExpired("systemctl private-value", 1)
        self.native.effect = fail
        expected = self.inspection()
        result = self.request("stop", expected)
        self.assertEqual(result["status"], "needs-inspection")
        self.assertNotIn("private-value", json.dumps(result))
        self.assertEqual(len(self.native.mutations), 1)
        self.native.effect = lambda action, unit: unit.update(ActiveState="failed", SubState="failed", Result="exit-code")
        result = self.request("restart", expected)
        self.assertEqual(result["status"], "needs-inspection")
        self.assertEqual(len(self.native.mutations), 2)

    def test_exited_oneshot_or_same_invocation_cannot_fake_restart_success(self):
        expected = self.inspection()
        self.native.effect = lambda action, unit: None
        self.assertEqual(self.request("restart", expected)["status"], "needs-inspection")
        self.native.effect = lambda action, unit: unit.update(SubState="exited", InvocationID="b" * 32)
        self.assertEqual(self.request("start", expected)["status"], "needs-inspection")

    def test_changed_post_operation_definition_and_dependency_are_uncertain(self):
        expected = self.inspection()
        def rewrite(action, unit):
            self.fragment.write_text("[Service]\nExecStart=/changed\n")
            unit.update(ActiveState="inactive", SubState="dead")
        self.native.effect = rewrite
        self.assertEqual(self.request("stop", expected)["status"], "needs-inspection")

    def test_preflight_errors_do_not_expose_paths_or_command_diagnostics(self):
        with patch.object(remote, "file_record", side_effect=OSError("secret-password private-path")):
            result = self.request()
        self.assert_no_mutation(result)
        self.assertNotIn("secret-password", json.dumps(result))


    def test_inverse_conflict_declared_by_another_unit_is_not_ignored(self):
        self.unit["ConflictedBy"] = "outside.service"
        self.native.add("outside.service", self.root / "outside.service")
        expected = self.inspection()
        self.assertEqual(expected["supported_actions"], [])
        self.assert_no_mutation(self.request("start", expected))

    def test_dbus_name_and_upholding_units_are_explicitly_unsupported(self):
        self.unit["BusName"] = "org.example.Fixture"
        self.assertEqual(self.inspection()["supported_actions"], [])
        self.unit["BusName"] = ""
        self.unit["Upholds"] = "outside.service"
        self.native.add("outside.service", self.root / "outside.service")
        expected = self.inspection()
        self.assertEqual(expected["supported_actions"], [])
        self.assert_no_mutation(self.request("restart", expected))

    def test_boot_identity_drift_invalidates_cached_approval(self):
        expected = self.inspection()
        with patch.object(remote, "boot_id", return_value="11234567-89ab-cdef-0123-456789abcdef"):
            self.assert_no_mutation(self.request("stop", expected))

    def test_config_and_action_cannot_inject_additional_targets_or_commands(self):
        for action in ("daemon-reload", "enable", "reload", "start; reboot"):
            with self.subTest(action=action):
                self.assert_no_mutation(self.request(action))
        self.config["extra_arguments"] = ["outside.service"]
        self.assert_no_mutation(self.request())

    def test_dependency_change_after_mutation_cannot_be_reported_as_success(self):
        self.unit["Requires"] = "outside.service"
        dependency = self.native.add("outside.service", self.root / "outside.service")
        expected = self.inspection()
        def effect(action, unit):
            unit.update(ActiveState="inactive", SubState="dead")
            dependency["InvocationID"] = "c" * 32
        self.native.effect = effect
        self.assertEqual(self.request("stop", expected)["status"], "needs-inspection")


class QuadletTests(LifecycleTests):
    def setUp(self):
        super().setUp()
        self.config["backend"] = "quadlet"
        self.source_root = self.root / "containers/systemd"
        self.source_root.mkdir(parents=True)
        self.source = self.source_root / "fixture.container"
        self.source.write_text("[Container]\nImage=local-fixture:fixed\nEnvironment=SECRET=private-value\n")
        self.generator = self.root / "generator-binary"
        self.generator.write_bytes(b"fixed generator identity")
        self.native_path = "/run/user/" + str(os.getuid()) + "/systemd/generator/fixture.service"
        self.fragment.write_text("# Automatically generated by " + str(self.generator) + "\n[Unit]\nSourcePath="
                                 + str(self.source) + "\n[X-Container]\nImage=local-fixture:fixed\nEnvironment=SECRET=private-value\n"
                                 + "[Service]\nExecStart=/usr/bin/podman run local-fixture:fixed\n")
        self.unit.update(FragmentPath=self.native_path, SourcePath=str(self.source))
        self.real_file_record = remote.file_record
        def files(path, *, executable=False):
            # Real bounded temp-file reads, with virtual native generator output
            # paths and a fixture generator instead of a host-owned executable.
            if path == self.native_path:
                record, body, mtime = self.real_file_record(str(self.fragment))
                record["path"] = path
                return record, body, mtime
            if path == str(self.generator):
                self.assertTrue(executable)
                return self.real_file_record(path)
            return self.real_file_record(path, executable=executable)
        for patcher in (patch.object(remote, "file_record", side_effect=files),
                        patch.object(remote, "GENERATORS", (str(self.generator),)),
                        patch.object(remote, "quadlet_roots", return_value=[self.source_root])):
            patcher.start()
            self.addCleanup(patcher.stop)

    # Quadlet-specific fixtures inherit the behavior cases that apply unchanged.
    def test_inspection_is_sanitized_and_explicitly_not_health(self):
        first = self.inspection()
        self.assertEqual(first["backend"], "quadlet")
        self.assertEqual(first["resources"][0]["backend"], "systemd")
        self.assertEqual(first["identity"]["quadlet"]["source"]["sha256"], hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertNotIn("private-value", json.dumps(first))
        self.assertNotIn("podman run", json.dumps(first))

    def test_system_scope_does_not_substitute_user_scope(self):
        # The fixture is explicitly a user-generated fragment, never a system
        # fragment merely because the caller changes scope.
        self.config["scope"] = "system"
        self.assert_no_mutation(self.request())

    def test_fragment_and_dropin_bytes_bind_approval(self):
        expected = self.inspection()
        dropin = self.root / "override.conf"
        dropin.write_text("[Service]\nRestart=no\n")
        self.unit["DropInPaths"] = str(dropin)
        self.assert_no_mutation(self.request("stop", expected))
        expected = self.inspection()
        dropin.write_text("[Service]\nRestart=always\n")
        self.assert_no_mutation(self.request("stop", expected))

    def test_quadlet_source_drift_and_source_dropins_require_operator_attention(self):
        expected = self.inspection()
        self.source.write_text("[Container]\nImage=another-image\n")
        self.assert_no_mutation(self.request("stop", expected))
        self.source.write_text("[Container]\nImage=local-fixture:fixed\nEnvironment=SECRET=private-value\n")
        os.utime(self.source, ns=(1, 1))
        for dirname in ("fixture.container.d", "container.d"):
            with self.subTest(dirname=dirname):
                directory = self.source_root / dirname
                directory.mkdir()
                self.assert_no_mutation(self.request())
                directory.rmdir()

    def test_name_is_not_quadlet_provenance(self):
        original = self.fragment.read_text()
        for change in (lambda: self.unit.update(SourcePath=""),
                       lambda: self.fragment.write_text("[Unit]\nSourcePath=" + str(self.source) + "\n"),
                       lambda: self.fragment.write_text(original.replace(str(self.generator), "/tmp/untrusted-generator"))):
            with self.subTest(change=change):
                self.unit["SourcePath"] = str(self.source)
                self.fragment.write_text(original)
                change()
                self.assert_no_mutation(self.request())

    def test_generated_container_section_must_match_actual_source(self):
        body = self.fragment.read_text()
        self.fragment.write_text(body.replace("Image=local-fixture:fixed", "Image=wrong-image"))
        self.assert_no_mutation(self.request())

    def test_shadowed_or_nested_quadlet_inputs_are_not_guessed(self):
        other = self.root / "other-search-root"
        other.mkdir()
        (other / "fixture.container").write_bytes(self.source.read_bytes())
        with patch.object(remote, "quadlet_roots", return_value=[self.source_root, other]):
            self.assert_no_mutation(self.request())
        nested = self.source_root / "nested"
        nested.mkdir()
        nested_source = nested / "fixture.container"
        nested_source.write_bytes(self.source.read_bytes())
        self.unit["SourcePath"] = str(nested_source)
        self.assert_no_mutation(self.request())

    def test_systemd_adoption_cannot_disguise_quadlet(self):
        self.config["backend"] = "systemd"
        self.assert_no_mutation(self.request())


class CommandBoundariesTests(unittest.TestCase):
    def test_cli_environment_cannot_redirect_manager_or_prompt_for_privilege(self):
        process = MagicMock()
        process.stdout.fileno.return_value = 1
        process.stderr.fileno.return_value = 2
        process.wait.return_value = 0
        process.poll.return_value = 0
        with patch.dict(os.environ, {"DBUS_SESSION_BUS_ADDRESS": "tcp:host=evil", "SYSTEMD_HOST": "evil",
                                     "LD_PRELOAD": "/evil.so", "PATH": "/evil", "XDG_RUNTIME_DIR": "/evil"}), \
                patch.object(remote.subprocess, "Popen", return_value=process) as popen, \
                patch.object(remote.select, "select", side_effect=lambda streams, *_: (list(streams), [], [])), \
                patch.object(remote.os, "read", return_value=b""):
            self.assertEqual(remote.command("system", ["stop", "--", "fixture.service"], remote.time.monotonic() + 5), "")
        argv = popen.call_args.args[0]
        options = popen.call_args.kwargs
        self.assertEqual(argv, ["/usr/bin/systemctl", "--system", "--no-ask-password", "--no-pager", "stop", "--", "fixture.service"])
        self.assertEqual(options["stdin"], subprocess.DEVNULL)
        self.assertNotIn("LD_PRELOAD", options["env"])
        self.assertNotIn("SYSTEMD_HOST", options["env"])
        self.assertNotIn("evil", json.dumps(options["env"]))
        self.assertTrue(options["start_new_session"])

    def test_output_overflow_is_bounded_and_only_our_cli_is_killed(self):
        process = MagicMock(pid=12345)
        process.stdout.fileno.return_value = 1
        process.stderr.fileno.return_value = 2
        process.poll.return_value = None
        with patch.object(remote.subprocess, "Popen", return_value=process), \
                patch.object(remote.select, "select", side_effect=lambda streams, *_: (list(streams), [], [])), \
                patch.object(remote.os, "read", return_value=b"x" * 16384), \
                patch.object(remote.os, "killpg") as kill:
            with self.assertRaisesRegex(remote.Refusal, "bound"):
                remote.command("user", ["show"], remote.time.monotonic() + 5)
        kill.assert_called_once_with(12345, remote.signal.SIGKILL)
        process.stdout.close.assert_called_once()
        process.stderr.close.assert_called_once()

    def test_deadline_before_spawn_does_not_issue_a_command(self):
        with patch.object(remote.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(remote.Refusal, "deadline"):
                remote.command("user", ["show"], remote.time.monotonic() - 1)
        popen.assert_not_called()


class DefinitionFilesTests(unittest.TestCase):
    def test_unsafe_mode_fifo_and_oversized_files_are_rejected_without_disclosure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "fixture.service"
            path.write_bytes(b"secret unit content")
            path.chmod(0o666)
            with self.assertRaisesRegex(remote.Refusal, "Unsafe"):
                remote.file_record(str(path))
            path.chmod(0o600)
            path.write_bytes(b"x" * (remote.LIMIT + 1))
            with self.assertRaisesRegex(remote.Refusal, "oversized"):
                remote.file_record(str(path))
            fifo = root / "pipe.service"
            os.mkfifo(fifo, 0o600)
            with self.assertRaisesRegex(remote.Refusal, "Unsafe"):
                remote.file_record(str(fifo))


if __name__ == "__main__":
    unittest.main()
