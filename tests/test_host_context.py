"""Integrated execution fixtures: no systemd manager, hardware or network probes."""
from contextlib import ExitStack
import fcntl
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

    def test_source_is_independently_compiled_and_fd_count_is_bounded(self):
        with host_context.execution(b"from __future__ import annotations\nprint('future')", timeout=2) as (_, source):
            status, output = remote.run_bounded([sys.executable, "-I", "-S", "-"], source, timeout=3)
            self.assertEqual((status, output), (0, b"future\n"))
        with self.assertRaisesRegex(ValueError, "must be bytes"):
            with host_context.execution("not bytes", timeout=2):
                self.fail("Text source accepted")
        with patch.object(host_context, "held_ledgers", return_value=({},) * 254), self.assertRaisesRegex(ValueError, "Too many"):
            with host_context.execution(b"", timeout=2):
                self.fail("Too many descriptors accepted")

    def test_normal_transport_return_also_confirms_stop_before_release(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "ledger"
            path.write_text("baseline\n")
            with LedgerBroker({"fixture": path}).hold("fixture", owner="fixture", scope="test", worktree=root):
                with host_context.execution(b"print('done')", timeout=2) as (_, source):
                    status, output = remote.run_bounded([sys.executable, "-I", "-S", "-"], source, timeout=3)
                    self.assertEqual((status, output), (0, b"done\n"))
                host_context._cancel.assert_called_once()
                self.assertNotIn('"event": "RELEASE"', path.read_text())
            self.assertIn('"event": "RELEASE"', path.read_text())

    def test_fixed_payload_uses_host_python_foreground_unit_and_fd_handshake(self):
        with host_context.execution(b"print('ready')", timeout=2.1) as (argv, source):
            for flag in ("--user", "--pipe", "--wait", "--collect", "--quiet", "--property=RuntimeMaxSec=3",
                         "--property=KillMode=control-group", "--property=TimeoutStopSec=5"):
                self.assertIn(flag, argv)
            self.assertEqual(argv[-5:], ["--", "/usr/bin/python3", "-I", "-S", "-"])
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

    def test_unconfirmed_cancellation_keeps_all_same_inode_flocks_on_host(self):
        with tempfile.TemporaryDirectory() as root:
            paths = [Path(root) / name for name in ("one", "two")]
            for path in paths:
                path.write_text("baseline\n")
            child = None
            try:
                with patch.object(host_context, "_cancel", return_value=False) as cancel:
                    with self.assertRaises(InterruptedError), ExitStack() as leases:
                        for path in paths:
                            leases.enter_context(LedgerBroker({path.name: path}).hold(path.name, owner="fixture", scope="test", worktree=root))
                        with host_context.execution(b"import time\nprint('ready', flush=True)\ntime.sleep(30)", timeout=2) as (_, source):
                            child = subprocess.Popen([sys.executable, "-I", "-S", "-"], stdin=subprocess.PIPE,
                                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            child.stdin.write(source)
                            child.stdin.close()
                            self.assertEqual(child.stdout.readline(), b"ready\n")
                            raise InterruptedError("fixture cancellation")
                    cancel.assert_called_once()
                for path in paths:
                    with path.open("a") as contender:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self.assertNotIn('"event": "RELEASE"', path.read_text())
            finally:
                if child is not None:
                    child.terminate()
                    child.wait(timeout=5)
                    child.stdout.close()
                    child.stderr.close()
            for path in paths:
                with path.open("a") as contender:
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_confirmed_cancellation_precedes_ledger_release(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "ledger"
            path.write_text("baseline\n")

            def stop(unit):
                self.assertNotIn('"event": "RELEASE"', path.read_text())
                with path.open("a") as contender:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True

            with patch.object(host_context, "_cancel", side_effect=stop) as cancel:
                with self.assertRaises(InterruptedError), LedgerBroker({"fixture": path}).hold("fixture", owner="fixture", scope="test", worktree=root):
                    with host_context.execution(b"", timeout=2):
                        raise InterruptedError("fixture cancellation")
            cancel.assert_called_once()
            self.assertIn('"event": "RELEASE"', path.read_text())

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
