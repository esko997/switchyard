"""Integrated execution fixtures: no systemd manager, hardware or network probes."""
from contextlib import ExitStack
import os
from pathlib import Path
import platform
import pwd
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from switchyard import collector, host_context, remote
from switchyard.lease_db import LeaseStore
from switchyard.leases import LedgerBroker


class HostContextTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {"SWITCHYARD_CONTAINER_HOST": "1"})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.cancel_unit = host_context._cancel
        self.cancellation = patch.object(host_context, "_cancel", return_value=True)
        self.cancellation.start()
        self.addCleanup(self.cancellation.stop)

    def test_native_mode_is_the_existing_interpreter_and_source(self):
        with patch.dict(os.environ, {"SWITCHYARD_CONTAINER_HOST": "0"}), host_context.execution(b"print('{}')", timeout=2) as (argv, source):
            self.assertEqual(argv, [sys.executable, "-I", "-S", "-"])
            self.assertEqual(source, b"print('{}')")
        with patch.dict(os.environ, {"SWITCHYARD_CONTAINER_HOST": "yes"}), self.assertRaisesRegex(ValueError, "must be 0 or 1"):
            with host_context.execution(b"", timeout=2):
                self.fail("Invalid opt-in accepted")

    def test_source_is_independently_compiled(self):
        with host_context.execution(b"from __future__ import annotations\nprint('future')", timeout=2) as (_, source):
            status, output = remote.run_bounded([sys.executable, "-I", "-S", "-"], source, timeout=3)
            self.assertEqual((status, output), (0, b"future\n"))
        with self.assertRaisesRegex(ValueError, "must be bytes"):
            with host_context.execution("not bytes", timeout=2):
                self.fail("Text source accepted")

    def test_normal_transport_return_also_confirms_stop_before_release(self):
        with tempfile.TemporaryDirectory() as root:
            store = LeaseStore(Path(root) / "leases")
            with LedgerBroker({"fixture": Path(root) / "metadata"}, state_dir=root).hold(
                    "fixture", owner="fixture", scope="test", worktree=root):
                with host_context.execution(b"print('done')", timeout=2) as (_, source):
                    status, output = remote.run_bounded([sys.executable, "-I", "-S", "-"], source, timeout=3)
                    self.assertEqual((status, output), (0, b"done\n"))
                host_context._cancel.assert_called_once()
                self.assertIsNotNone(store.current("FIXTURE"))
            self.assertIsNone(store.current("FIXTURE"))

    def test_fixed_payload_uses_host_python_foreground_unit(self):
        with host_context.execution(b"print('ready')", timeout=2.1) as (argv, source):
            for flag in ("--user", "--pipe", "--wait", "--collect", "--quiet", "--property=RuntimeMaxSec=3",
                         "--property=KillMode=control-group", "--property=TimeoutStopSec=5"):
                self.assertIn(flag, argv)
            self.assertEqual(argv[-7:], ["--", "/usr/bin/env", "--", "/usr/bin/python3", "-I", "-S", "-"])
            status, output = remote.run_bounded([sys.executable, "-I", "-S", "-"], source, timeout=3)
            self.assertEqual((status, output), (0, b"ready\n"))

    def test_local_operation_keeps_identity_checks_and_does_not_use_ssh(self):
        host = {"transport": "ssh", "target": pwd.getpwuid(os.getuid()).pw_name + "@fixture.invalid",
                "expected_hostname": platform.node()}
        bounded = remote.run_bounded
        calls = []

        def fixed(argv, source, **kwargs):
            calls.append(argv)
            return bounded([sys.executable, "-I", "-S", "-"], source, **kwargs)

        with patch.object(remote, "run_bounded", side_effect=fixed), patch.object(remote, "_ssh_command") as ssh:
            self.assertEqual(remote.run_remote(host, "print(json.dumps(PAYLOAD))", {"value": "data"}, local=True), {"value": "data"})
            with self.assertRaises(remote.RemoteError):
                remote.run_remote({**host, "expected_hostname": "not-the-fixture"}, "raise AssertionError('action must not execute')", {}, local=True)
        ssh.assert_not_called()
        self.assertTrue(all(argv[0] == "systemd-run" for argv in calls))

    def test_local_fixed_probe_routes_through_host_without_changing_config(self):
        config = {"host_id": "fixture", "transport": "local", "expected_hostname": "fixture",
                  "user_units": [], "system_units": []}
        value = {"observed_at": "2026-01-01T00:00:00Z", "coverage": "full"}
        run = collector._run
        calls = []

        def fixed(argv, source, deadline):
            calls.append(argv)
            return run([sys.executable, "-I", "-S", "-"], source, deadline)

        with patch.object(collector, "_probe_source", return_value=b"print('{\"fixture\": true}')"), \
                patch.object(collector, "_validate_snapshot", return_value=value), \
                patch.object(collector, "_run", side_effect=fixed):
            self.assertEqual(collector.collect_host(config), value)
        self.assertEqual(calls[0][0], "systemd-run")
        self.assertEqual(config["transport"], "local")

    def test_unconfirmed_unit_exit_keeps_the_durable_reservation(self):
        with tempfile.TemporaryDirectory() as root:
            paths = {name: Path(root) / name for name in ("one", "two")}
            store = LeaseStore(Path(root) / "leases")
            with patch.object(host_context, "_cancel", return_value=False), ExitStack() as leases:
                for name, path in paths.items():
                    leases.enter_context(LedgerBroker({name: path}, state_dir=root).hold(
                        name, owner="fixture", scope="test", worktree=root))
                with host_context.execution(b"print('complete')", timeout=2) as (_, source):
                    status, output = remote.run_bounded([sys.executable, "-I", "-S", "-"], source, timeout=3)
                    self.assertEqual((status, output), (0, b"complete\n"))
            for name in paths:
                self.assertEqual(store.current(name.upper())["suspect_cause"], "host unit termination unconfirmed")

    def test_cancel_requires_sync_stop_or_confirmed_unloaded_unit(self):
        success = subprocess.CompletedProcess([], 0, b"")
        failure = subprocess.CompletedProcess([], 1, b"")
        unloaded = subprocess.CompletedProcess([], 0, b"not-found\n")
        active = subprocess.CompletedProcess([], 0, b"loaded\n")
        for results, expected in (([success], True), ([failure, unloaded], True), ([failure, active], False)):
            with patch.object(host_context.subprocess, "run", side_effect=results) as run:
                self.assertEqual(self.cancel_unit("fixture.service"), expected)
                self.assertEqual(run.call_args_list[0].args[0], ["systemctl", "--user", "stop", "fixture.service"])
        with patch.object(host_context.subprocess, "run", side_effect=subprocess.TimeoutExpired("systemctl", 10)):
            self.assertFalse(self.cancel_unit("fixture.service"))
