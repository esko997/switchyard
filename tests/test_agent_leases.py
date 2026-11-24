"""Agent leases: temporary ledgers only; never execute systemd or contact devices."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

import anyio
from mcp.server.fastmcp.exceptions import ToolError

from switchyard import cli, locks
from switchyard.agent_leases import (
    AgentLeases, LeaseStates, busy_message, caller_identity, enrich_locks,
    process_alive, systemd_argv, ttl_seconds,
)
from switchyard.leases import LedgerBroker, LeaseBusy
from switchyard.mcp_server import create_mcp


@contextmanager
def raw_holder(path):
    script = "import fcntl,sys; f=open(sys.argv[1], 'a'); fcntl.flock(f, fcntl.LOCK_EX); print('locked', flush=True); sys.stdin.read()"
    child = subprocess.Popen([sys.executable, "-c", script, str(path)], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        if child.stdout.readline().strip() != "locked":
            raise AssertionError(child.stderr.read())
        yield child
    finally:
        child.communicate(input="", timeout=5)


class Clock:
    def __init__(self):
        self.now = 2_000_000_000.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class AgentLeaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.ledgers = self.root / "ledgers"
        self.ledgers.mkdir()
        self.ledger = self.ledgers / "DEVICE_ACCESS_TESTHANDHELD.md"
        self.ledger.write_text("baseline\n")
        self.clock = Clock()
        self.runner = MagicMock()
        self.collectors = {"test-handheld": {"transport": "adb", "serial": "fake-serial",
                                        "ledger": str(self.ledger), "private_field": "not-exported"}}
        self.manager = AgentLeases(collectors=self.collectors, state_dir=self.root / "state",
                                   ledger_dir=self.ledgers, clock=self.clock,
                                   monotonic=self.clock, sleep=self.clock.sleep,
                                   owner_alive=lambda pid, started: True, runner=self.runner)

    def events(self):
        return [json.loads(line) for line in self.ledger.read_text().splitlines() if line.startswith("{")]

    def state(self, **updates):
        value = self.manager._new("test-handheld", "inspect temporary fixture", "test agent", str(self.root), "hold", 60)
        value.update(updates)
        self.manager.states.update(value["lease_id"], lambda current: current.update(value), create=True)
        return value

    def held_row(self, pid=None):
        return {"device": "TESTHANDHELD", "path": str(self.ledger), "state": "held",
                "holders": [{"pid": pid or os.getpid(), "comm": "omp", "paseo_agent_name": "FixtureAgent"}],
                "last_entries": [{"event": "CLAIM", "scope": "fixture inspection", "at": "2033-05-18T03:33:20+00:00"}]}

    @contextmanager
    def claimed(self):
        state = self.state(status="claimed", pid=os.getpid(),
                           pid_started=locks._process_stat(Path("/proc") / str(os.getpid()))[1])
        self.manager.observer = lambda: {"ledgers": [self.held_row()]}
        with LedgerBroker({"TESTHANDHELD": self.ledger}).hold("TESTHANDHELD", owner="fixture", scope="fixture", worktree=str(self.root),
                                                    lease_id=state["lease_id"]) as receipt:
            yield state, receipt

    def test_device_resolution_unknown_missing_and_symlinks(self):
        for alias in ("TESTHANDHELD", "tEsThAnDhElD", "TEST-HANDHELD"):
            self.assertEqual(self.manager.resolve(alias)[:2], ("TESTHANDHELD", self.ledger))
        with self.assertRaisesRegex(ValueError, "not a Switchyard registry host"):
            self.manager.resolve("unknown-tv")
        self.collectors["television"] = {"ledger": str(self.ledgers / "DEVICE_ACCESS_TESTTV.md")}
        with self.assertRaisesRegex(ValueError, "no existing ledger"):
            self.manager.resolve("television")
        for value in ("missing", "TESTHANDHELDB", "../TESTHANDHELD"):
            with self.assertRaises(ValueError):
                self.manager.resolve(value)
        target = self.root / "real.md"
        self.ledger.rename(target)
        self.ledger.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            self.manager.resolve("TESTHANDHELD")
        self.assertFalse((self.ledgers / "DEVICE_ACCESS_TESTHANDHELDB.md").exists())

    def test_same_inode_exclusion_with_other_process_and_busy_cli_75(self):
        inode = self.ledger.stat().st_ino
        with raw_holder(self.ledger) as child:
            self.manager.observer = lambda: {"ledgers": [self.held_row(child.pid)]}
            with self.assertRaisesRegex(LeaseBusy, "FixtureAgent.*fixture inspection"):
                self.manager.run("test-handheld", [sys.executable, "-c", "raise AssertionError('must not run')"], scope="test")
            stderr = io.StringIO()
            with patch.object(cli, "Service") as service, patch.object(sys, "argv", [
                "switchyard", "--catalog", "fixture", "lease", "run", "test-handheld", "--scope", "test", "--", "never-run",
            ]), redirect_stderr(stderr):
                service.return_value.agent_leases.return_value = self.manager
                with self.assertRaises(SystemExit) as exit_error:
                    cli.main()
            self.assertEqual(exit_error.exception.code, 75)
            self.assertIn("FixtureAgent", stderr.getvalue())
            self.assertIn("fixture inspection", stderr.getvalue())
            self.assertEqual(len(stderr.getvalue().splitlines()), 1)
        self.assertEqual(inode, self.ledger.stat().st_ino)
        self.assertEqual(self.events(), [])
        with LedgerBroker({"TESTHANDHELD": self.ledger}).hold("TESTHANDHELD", owner="fixture", scope="after raw holder", worktree=str(self.root)):
            pass
        self.assertEqual(inode, self.ledger.stat().st_ino)

    def test_bounded_wait_polls_no_faster_than_once_per_second(self):
        self.manager.observer = lambda: {"ledgers": [self.held_row()]}
        with raw_holder(self.ledger):
            with self.assertRaises(LeaseBusy):
                self.manager.run("test-handheld", ["never-run"], scope="test", wait=2.5)
        self.assertEqual(self.clock.sleeps, [1, 1, 0.5])
        for wait in (-1, 601, float("inf"), float("nan"), True):
            with self.assertRaises(ValueError):
                self.manager.run("test-handheld", ["never-run"], scope="test", wait=wait)

    def test_run_propagates_exit_and_only_connection_hints_are_exported(self):
        output = self.root / "environment.json"
        source = "import json,os,sys; json.dump(dict(os.environ),open(sys.argv[1],'w')); sys.exit(7)"
        with patch.dict(os.environ, {"SWITCHYARD_SSH_TARGET": "stale", "SWITCHYARD_SSH_PORT": "999", "ANDROID_SERIAL": "old"}):
            code = self.manager.run("test-handheld", [sys.executable, "-c", source, str(output)],
                                    scope="inspect fixture", owner="Explicit", worktree=str(self.root))
        self.assertEqual(code, 7)
        environment = json.loads(output.read_text())
        self.assertEqual(environment["ANDROID_SERIAL"], "fake-serial")
        self.assertEqual(environment["SWITCHYARD_DEVICE"], "TESTHANDHELD")
        self.assertNotIn("SWITCHYARD_SSH_TARGET", environment)
        self.assertNotIn("SWITCHYARD_SSH_PORT", environment)
        self.assertNotIn("private_field", environment)
        self.assertNotIn("DEVICE_LOCK_FD", environment)
        events = self.events()
        self.assertEqual([event["event"] for event in events], ["CLAIM", "RELEASE"])
        self.assertEqual(events[-1]["exit_code"], 7)
        self.assertEqual(events[-1]["reason"], "completed")
        self.assertEqual(events[0]["via"], "switchyard lease run")
        self.assertEqual(events[0]["pid"], os.getpid())
        self.assertEqual(events[0]["owner"], "Explicit")
        self.assertEqual(events[0]["lease_id"], environment["SWITCHYARD_LEASE_ID"])
        self.assertIn("caveat", events[-1])
        state = self.manager.states.read(events[0]["lease_id"])
        self.assertEqual(set(state["env"]), {"SWITCHYARD_LEASE_ID", "SWITCHYARD_DEVICE", "ANDROID_SERIAL"})
        self.assertEqual(state["status"], "released")

    def test_pass_lock_fd_satisfies_inherited_descriptor_scripts(self):
        # An inherited descriptor must still resolve to the canonical ledger.
        # `flock -n` on it must succeed (shared lock), and the device must stay held for everyone else.
        output = self.root / "fd-check.json"
        source = (
            "import fcntl,json,os,sys\n"
            "fd=int(os.environ['DEVICE_LOCK_FD']); ledger=sys.argv[2]\n"
            "same=os.path.realpath(f'/proc/self/fd/{fd}')==os.path.realpath(ledger)\n"
            "fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)\n"
            "other=os.open(ledger, os.O_RDONLY)\n"
            "try:\n"
            "    fcntl.flock(other, fcntl.LOCK_EX|fcntl.LOCK_NB); outsider=False\n"
            "except BlockingIOError:\n"
            "    outsider=True\n"
            "json.dump({'same': same, 'outsider_blocked': outsider}, open(sys.argv[1],'w'))\n")
        code = self.manager.run("test-handheld", [sys.executable, "-c", source, str(output), str(self.ledger)],
                                scope="fd fixture", pass_lock_fd=True)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.read_text()), {"same": True, "outsider_blocked": True})
        self.assertEqual([event["event"] for event in self.events()], ["CLAIM", "RELEASE"])

    def test_ssh_exports_target_and_port_only(self):
        self.collectors["test-handheld"] = {"transport": "ssh", "target": "test@192.0.2.1", "port": 2200, "ledger": str(self.ledger)}
        state = self.manager._new("test-handheld", "test", None, None, "hold", 60)
        self.assertEqual(set(state["env"]), {"SWITCHYARD_LEASE_ID", "SWITCHYARD_DEVICE", "SWITCHYARD_SSH_TARGET", "SWITCHYARD_SSH_PORT"})
        self.assertEqual(state["env"]["SWITCHYARD_SSH_PORT"], "2200")

    def test_run_sigterm_is_forwarded_and_releases(self):
        self._assert_run_signal(signal.SIGTERM)

    def test_run_sigint_is_forwarded_and_releases(self):
        self._assert_run_signal(signal.SIGINT)

    def test_every_registry_host_is_leaseable_and_others_are_refused(self):
        (self.ledgers / "DEVICE_ACCESS_TESTUNIX.md").write_text("")
        (self.ledgers / "DEVICE_ACCESS_ROGUE.md").write_text("")
        (self.ledgers / "DEVICE_ACCESS_TESTTV.md").write_text("")
        manager = AgentLeases(collectors=self.collectors, hosts=("test-unix", "test-tv", "test-printer"),
                              state_dir=self.root / "state", ledger_dir=self.ledgers)
        # A registry host without a collector leases DEVICE_ACCESS_<ID>.md by ID or label.
        self.assertEqual(manager.resolve("test-unix")[0], "TESTUNIX")
        self.assertEqual(manager.resolve("TESTUNIX")[0], "TESTUNIX")
        # A stray ledger file does not make an arbitrary device leaseable.
        with self.assertRaisesRegex(ValueError, "not a Switchyard registry host"):
            manager.resolve("rogue")
        # A registry host whose ledger does not exist yet is refused, never created.
        with self.assertRaisesRegex(ValueError, "no existing ledger"):
            manager.resolve("test-printer")
        self.assertFalse((self.ledgers / "DEVICE_ACCESS_TESTPRINTER.md").exists())
        self.assertEqual(manager.resolve("test-tv")[0], "TESTTV")

    def test_ensure_ledger_creates_once_and_never_touches_existing(self):
        from switchyard.agent_leases import ensure_ledger
        path, created = ensure_ledger("new-host", self.ledgers)
        self.assertEqual((path.name, created), ("DEVICE_ACCESS_NEWHOST.md", True))
        inode, content = path.stat().st_ino, path.read_text()
        self.assertEqual(ensure_ledger("new-host", self.ledgers), (path, False))
        self.assertEqual((path.stat().st_ino, path.read_text()), (inode, content))
        # The fresh ledger is immediately leaseable for that registry host.
        manager = AgentLeases(hosts=("new-host",), state_dir=self.root / "state", ledger_dir=self.ledgers)
        self.assertEqual(manager.resolve("new-host")[1], path)

    def _assert_run_signal(self, signum):
        ready = self.root / "ready"
        command = "import pathlib,signal,sys,time; signal.signal(signal.SIGTERM,lambda *_: sys.exit(23)); signal.signal(signal.SIGINT,lambda *_: sys.exit(23)); pathlib.Path(sys.argv[1]).touch(); time.sleep(30)"
        harness = "from switchyard.agent_leases import AgentLeases; import sys; m=AgentLeases(ledger_dir=sys.argv[1],state_dir=sys.argv[2],hosts=('test-handheld',)); sys.exit(m.run('TESTHANDHELD',sys.argv[3:],scope='signal fixture'))"
        child = subprocess.Popen([sys.executable, "-c", harness, str(self.ledgers), str(self.root / "signal-state"),
                                  sys.executable, "-c", command, str(ready)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(ready.exists(), "child did not become ready")
            child.send_signal(signum)
            _, stderr = child.communicate(timeout=5)
            self.assertEqual(child.returncode, 23, stderr.decode())
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)
        self.assertEqual([event["event"] for event in self.events()], ["CLAIM", "RELEASE"])
        self.assertEqual(self.events()[-1]["reason"], "signal")
        self.assertEqual(self.events()[-1]["exit_code"], 23)
        with LedgerBroker({"TESTHANDHELD": self.ledger}).hold("TESTHANDHELD", owner="fixture", scope="after signal", worktree=str(self.root)):
            pass

    def test_holder_expiry_owner_exit_release_signal_and_error_once(self):
        for reason in ("expired", "owner-exited", "released", "signal", "error"):
            with self.subTest(reason=reason):
                self.ledger.write_text("baseline\n")
                state = self.state()
                self.manager.owner_alive = lambda pid, started: reason != "owner-exited"
                def step(seconds):
                    if reason == "released":
                        self.manager.states.update(state["lease_id"], lambda value: value.update(release_requested=True))
                    elif reason == "signal":
                        os.kill(os.getpid(), signal.SIGTERM)
                    elif reason == "error":
                        raise RuntimeError("fixture failure")
                    else:
                        self.clock.now += 60
                self.manager.sleep = step
                if reason == "error":
                    with self.assertRaisesRegex(RuntimeError, "fixture failure"):
                        self.manager.holder(state["lease_id"])
                else:
                    self.manager.holder(state["lease_id"])
                events = self.events()
                self.assertEqual([event["event"] for event in events], ["CLAIM", "RELEASE"])
                self.assertEqual(events[-1]["reason"], reason)
                self.assertEqual(events[0]["via"], "switchyard lease hold")
                self.assertIn("expires_at", events[0])
                self.assertIn("caveat", events[-1])

    def test_holder_refuses_duplicate_execution_and_cancel_before_claim(self):
        state = self.state(release_requested=True)
        self.manager.holder(state["lease_id"])
        self.assertEqual(self.events(), [])
        with self.assertRaisesRegex(ValueError, "awaiting a holder"):
            self.manager.holder(state["lease_id"])

    def test_holder_cancellation_interrupts_lock_wait_without_claim(self):
        state = self.state(wait_seconds=600)
        def cancel(seconds):
            self.manager.states.update(state["lease_id"], lambda value: value.update(release_requested=True))
        self.manager.sleep = cancel
        with raw_holder(self.ledger):
            self.manager.holder(state["lease_id"])
        self.assertEqual(self.events(), [])
        self.assertEqual(self.manager.states.read(state["lease_id"])["reason"], "released")

    def test_hold_builds_systemd_argv_and_waits_for_claim(self):
        retained = []
        def start(argv, **kwargs):
            self.assertEqual(argv[0], "systemd-run")
            state = self.manager.states.read(argv[-1])
            context = self.manager._acquire(state, 0)
            receipt = context.__enter__()
            retained.append((context, receipt))
            self.manager.states.update(state["lease_id"], lambda value: value.update(status="claimed", pid=os.getpid()))
        self.runner.side_effect = start
        try:
            result = self.manager.hold("TESTHANDHELD", scope="fixture", ttl=60)
            state = self.manager.states.read(result["lease_id"])
            self.assertEqual(state["status"], "claimed")
            self.assertEqual(self.events()[0]["event"], "CLAIM")
            argv = self.runner.call_args.args[0]
            self.assertIn("--property=RuntimeMaxSec=120", argv)
            self.assertIn(f"--unit={result['holder_unit']}", argv)
            self.assertIn("--collect", argv)
            self.assertEqual(argv[-3:-1], ["lease", "_holder"])
            self.assertEqual(set(result), {"lease_id", "device", "expires_at", "holder_unit", "env"})
            info = (self.manager.states.directory / f"{result['lease_id']}.json").stat()
            self.assertEqual(info.st_mode & 0o777, 0o600)
            self.assertEqual(self.manager.states.directory.stat().st_mode & 0o777, 0o700)
        finally:
            for context, receipt in retained:
                receipt["release"]["reason"] = "released"
                context.__exit__(None, None, None)
        state = self.state(paseo_agent_id="fake-agent")
        argv = systemd_argv(state, ["switchyard", "lease", "_holder", state["lease_id"]])
        self.assertIn("--setenv=PASEO_AGENT_ID=fake-agent", argv)
        self.assertEqual(argv[-5], "--")

    def test_hold_timeout_stops_unit_and_persists_cancel(self):
        self.runner.return_value = subprocess.CompletedProcess([], 0)
        with self.assertRaisesRegex(LeaseBusy, "TESTHANDHELD busy"):
            self.manager.hold("TESTHANDHELD", scope="fixture", wait=2)
        self.assertLessEqual(sum(self.clock.sleeps), 12.1)
        self.assertGreaterEqual(sum(self.clock.sleeps), 12)
        self.assertIn("--property=RuntimeMaxSec=3662", self.runner.call_args_list[0].args[0])
        self.assertEqual(self.runner.call_args.args[0][:3], ["systemctl", "--user", "stop"])
        state = self.manager.states.records()[0]
        self.assertTrue(state["release_requested"])
        self.manager.holder(state["lease_id"])
        self.assertEqual(self.events(), [])

    def test_release_refuses_raw_flock_with_holder_attribution(self):
        with raw_holder(self.ledger) as child:
            self.manager.observer = lambda: {"ledgers": [self.held_row(child.pid)]}
            with self.assertRaisesRegex(ValueError, "No unique Switchyard holder.*FixtureAgent"):
                self.manager.release("TESTHANDHELD")
            with self.assertRaises(LeaseBusy):
                with LedgerBroker({"TESTHANDHELD": self.ledger}).hold("TESTHANDHELD", owner="fixture", scope="test", worktree=str(self.root)):
                    self.fail("raw holder was released")
        self.runner.assert_not_called()

    def test_release_requests_and_confirms_only_switchyard_holder(self):
        with self.claimed() as (state, receipt):
            def acknowledge(seconds):
                current = self.manager.states.read(state["lease_id"])
                self.assertTrue(current["release_requested"])
                self.manager.states.update(state["lease_id"], lambda value: value.update(status="released", reason="released"))
            self.manager.sleep = acknowledge
            result = self.manager.release("test-handheld")
            self.assertEqual(result["reason"], "released")
            receipt["release"]["reason"] = "released"
        self.assertEqual([event["event"] for event in self.events()], ["CLAIM", "RELEASE"])

    def test_renew_extends_unit_and_state_without_ledger_event(self):
        with self.claimed() as (state, receipt):
            old = state["expires_at"]
            self.clock.now += 20
            result = self.manager.renew(state["lease_id"], ttl=120)
            self.assertGreater(result["expires_at"], old)
            self.assertEqual(self.runner.call_args.args[0], ["systemctl", "--user", "set-property", "--runtime", state["holder_unit"], "RuntimeMaxSec=200"])
            self.assertEqual([event["event"] for event in self.events()], ["CLAIM"])
            self.manager.states.update(state["lease_id"], lambda value: value.update(release_requested=True))
            with self.assertRaisesRegex(ValueError, "releasing"):
                self.manager.renew(state["lease_id"], ttl=60)
        self.assertEqual([event["event"] for event in self.events()], ["CLAIM", "RELEASE"])

    def test_holder_reads_renewed_expiry(self):
        state = self.state()
        calls = []
        def step(seconds):
            calls.append(seconds)
            if len(calls) == 1:
                self.manager.states.update(state["lease_id"], lambda value: value.update(expires_at="2033-05-18T03:35:20+00:00"))
                self.clock.now += 60
            else:
                self.clock.now += 60
        self.manager.sleep = step
        self.manager.holder(state["lease_id"])
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.events()[-1]["reason"], "expired")

    def test_enrichment_requires_real_matching_process_identity_and_held_row(self):
        with self.claimed() as (state, receipt):
            rows = {"ledgers": [self.held_row()]}
            enriched = enrich_locks(rows, self.manager.states.directory)["ledgers"][0]
            self.assertEqual(enriched["switchyard_lease"]["lease_id"], state["lease_id"])
            self.assertEqual(set(enriched["switchyard_lease"]), {"lease_id", "owner", "scope", "expires_at", "holder_unit"})
            row = self.held_row()
            row["state"] = "free"
            self.assertNotIn("switchyard_lease", enrich_locks({"ledgers": [row]}, self.manager.states.directory)["ledgers"][0])
            self.manager.states.update(state["lease_id"], lambda value: value.update(pid_started=-1))
            self.assertNotIn("switchyard_lease", enrich_locks({"ledgers": [self.held_row()]}, self.manager.states.directory)["ledgers"][0])

    def test_ttl_and_scope_bounds(self):
        self.assertEqual(ttl_seconds("60m"), 3600)
        self.assertEqual(ttl_seconds("2h"), 7200)
        for ttl in ("0m", "3h", "59s", "nan", "-1m"):
            with self.assertRaises(ValueError):
                ttl_seconds(ttl)
        for scope in ("", " ", "x" * 513, "line\nbreak"):
            with self.assertRaises(ValueError):
                self.manager.hold("TESTHANDHELD", scope=scope)
        self.runner.assert_not_called()

    def test_default_worktree_is_callers_cwd_and_run_is_not_releasable(self):
        state = self.manager._new("TESTHANDHELD", "fixture", "Explicit", None, "run")
        self.assertEqual(state["worktree"], str(Path.cwd()))
        self.manager.states.update(state["lease_id"], lambda value: value.update(state), create=True)
        with self.assertRaisesRegex(ValueError, "Only Switchyard hold"):
            self.manager.release(state["lease_id"])

    def test_cli_env_catalog_only_for_lease_and_status_exit_codes(self):
        environment = {"SWITCHYARD_CATALOG": "catalog-from-env", "SWITCHYARD_COLLECTORS": "collectors-from-env"}
        for state, code in (("free", 0), ("held", 1), ("unknown", 2)):
            with self.subTest(state=state), patch.dict(os.environ, environment), patch.object(cli, "Service") as service, \
                    patch.object(sys, "argv", ["switchyard", "lease", "status", "TESTHANDHELD"]), redirect_stdout(io.StringIO()):
                service.return_value.agent_leases.return_value.status.return_value = {"state": state}
                with self.assertRaises(SystemExit) as error:
                    cli.main()
                self.assertEqual(error.exception.code, code)
                self.assertEqual(service.call_args.args, ("catalog-from-env",))
                self.assertEqual(service.call_args.kwargs["collectors_path"], "collectors-from-env")
        with patch.dict(os.environ, environment), patch.object(sys, "argv", ["switchyard", "inventory"]), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                cli.main()
            self.assertEqual(error.exception.code, 2)


ATTACH_HARNESS = (
    "from switchyard.agent_leases import AgentLeases; import sys; "
    "m=AgentLeases(ledger_dir=sys.argv[1], state_dir=sys.argv[2], hosts=('test-handheld', 'host-b')); "
    "beat=float(sys.argv[3]) if len(sys.argv) > 3 else None; "
    "sys.exit(m.attach('TESTHANDHELD', scope='attach fixture', origin_host='host-b', origin_user='tester', heartbeat=beat))")


class RemoteCallerTests(unittest.TestCase):
    """`lease attach` (lease bound to the caller's connection) and `hold --detached` for remote agents."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.ledgers = self.root / "ledgers"
        self.ledgers.mkdir()
        self.ledger = self.ledgers / "DEVICE_ACCESS_TESTHANDHELD.md"
        self.ledger.write_text("baseline\n")
        self.clock = Clock()
        self.runner = MagicMock()
        self.agents = {"test-agent-b-0001": {"name": "TestAgentB", "host_id": "host-b"},
                       "test-agent-controller-0001": {"name": "ControllerAgent", "host_id": "controller"}}
        self.manager = AgentLeases(collectors={"test-handheld": {"transport": "adb", "serial": "fake-serial", "ledger": str(self.ledger)}},
                                   hosts=("test-handheld", "host-b", "controller"), paseo_agents=self.agents,
                                   state_dir=self.root / "state", ledger_dir=self.ledgers, clock=self.clock,
                                   monotonic=self.clock, sleep=self.clock.sleep,
                                   owner_alive=lambda pid, started: True, runner=self.runner)

    def events(self):
        return [json.loads(line) for line in self.ledger.read_text().splitlines() if line.startswith("{")]

    def spawn_attach(self, heartbeat=None):
        extra = [] if heartbeat is None else [str(heartbeat)]
        child = subprocess.Popen([sys.executable, "-c", ATTACH_HARNESS, str(self.ledgers), str(self.root / "attach-state"), *extra],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()
        self.addCleanup(cleanup)
        claim = json.loads(child.stdout.readline())
        return child, claim

    def test_attach_prints_claim_then_releases_once_on_eof(self):
        child, claim = self.spawn_attach()
        self.assertEqual(claim["status"], "claimed")
        self.assertEqual(claim["device"], "TESTHANDHELD")
        self.assertEqual(set(claim["env"]), {"SWITCHYARD_LEASE_ID", "SWITCHYARD_DEVICE"})
        self.assertEqual(claim["env"]["SWITCHYARD_LEASE_ID"], claim["lease_id"])
        # Held while the connection (stdin) stays open: a contender is refused.
        with self.assertRaises(LeaseBusy):
            with LedgerBroker({"TESTHANDHELD": self.ledger}).hold("TESTHANDHELD", owner="contender", scope="test", worktree=str(self.root)):
                pass
        self.assertEqual([event["event"] for event in self.events()], ["CLAIM"])
        stdout, stderr = child.communicate(input="", timeout=10)
        self.assertEqual(child.returncode, 0, stderr)
        released = [json.loads(line) for line in stdout.splitlines()]
        self.assertEqual(released, [{"status": "released", "lease_id": claim["lease_id"], "device": "TESTHANDHELD", "reason": "released"}])
        events = self.events()
        self.assertEqual([event["event"] for event in events], ["CLAIM", "RELEASE"])
        self.assertEqual(events[0]["owner"], "tester@host-b")
        self.assertEqual(events[0]["via"], "switchyard lease attach from host-b")
        self.assertIn("expires_at", events[0])
        self.assertEqual(events[1]["reason"], "released")
        with LedgerBroker({"TESTHANDHELD": self.ledger}).hold("TESTHANDHELD", owner="after", scope="test", worktree=str(self.root)):
            pass

    def test_attach_releases_on_sigterm_and_sighup(self):
        for signum in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=signum):
                self.ledger.write_text("baseline\n")
                child, claim = self.spawn_attach()
                child.send_signal(signum)
                child.wait(timeout=10)  # Keep stdin open: the signal, not EOF, must end the lease.
                stdout, stderr = child.communicate(timeout=10)
                self.assertEqual(child.returncode, 0, stderr)
                self.assertEqual(json.loads(stdout)["reason"], "signal")
                self.assertEqual([(event["event"], event.get("reason")) for event in self.events()],
                                 [("CLAIM", None), ("RELEASE", "signal")])

    def test_attach_busy_exits_75_without_claim_line(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with raw_holder(self.ledger) as holder:
            self.manager.observer = lambda: {"ledgers": [{"device": "TESTHANDHELD", "state": "held", "holders": [
                {"pid": holder.pid, "comm": "omp", "paseo_agent_name": "FixtureAgent"}], "last_entries": [
                {"event": "CLAIM", "scope": "fixture inspection", "at": "2033-05-18T03:33:20+00:00"}]}]}
            with patch.object(cli, "Service") as service, patch.object(sys, "argv", [
                "switchyard", "--catalog", "fixture", "lease", "attach", "test-handheld", "--scope", "remote",
                "--origin-host", "host-b"]), redirect_stdout(stdout), redirect_stderr(stderr):
                service.return_value.agent_leases.return_value = self.manager
                with self.assertRaises(SystemExit) as error:
                    cli.main()
        self.assertEqual(error.exception.code, 75)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("FixtureAgent", stderr.getvalue())
        self.assertEqual(self.events(), [])
        self.assertEqual(self.manager.states.records(), [])

    def test_attach_hard_cap_expires_after_two_hours(self):
        read_end, write_end = os.pipe()
        self.addCleanup(os.close, read_end)
        self.addCleanup(os.close, write_end)
        def jumping():
            self.clock.now += 3000
            return self.clock.now
        self.manager.clock = jumping
        output = io.StringIO()
        self.assertEqual(self.manager.attach("test-handheld", scope="cap fixture", input_fd=read_end, output=output), 0)
        claim, released = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(claim["status"], "claimed")
        self.assertEqual(released["reason"], "expired")
        self.assertEqual([(event["event"], event.get("reason")) for event in self.events()],
                         [("CLAIM", None), ("RELEASE", "expired")])
        state = self.manager.states.read(claim["lease_id"])
        self.assertEqual((state["status"], state["ttl_seconds"], state["mode"]), ("released", 7200, "attach"))

    def test_attach_cancelled_by_eof_while_waiting_never_claims(self):
        read_end, write_end = os.pipe()
        self.addCleanup(os.close, read_end)
        os.close(write_end)
        with raw_holder(self.ledger), redirect_stderr(io.StringIO()):
            self.assertEqual(self.manager.attach("test-handheld", scope="wait fixture", wait=600, input_fd=read_end, output=io.StringIO()), 1)
        self.assertEqual(self.events(), [])

    def test_attach_is_releasable_but_not_renewable(self):
        child, claim = self.spawn_attach()
        manager = AgentLeases(hosts=("test-handheld",), state_dir=self.root / "attach-state", ledger_dir=self.ledgers)
        manager.observer = lambda: {"ledgers": [{"device": "TESTHANDHELD", "state": "held", "holders": [{"pid": child.pid}]}]}
        with self.assertRaisesRegex(ValueError, "cannot be renewed"):
            manager.renew(claim["lease_id"], ttl=600)
        self.assertEqual(manager.release(claim["lease_id"])["reason"], "released")
        stdout, stderr = child.communicate(timeout=10)
        self.assertEqual(child.returncode, 0, stderr)
        self.assertEqual([event["event"] for event in self.events()], ["CLAIM", "RELEASE"])

    def test_remote_owner_resolution_and_validation(self):
        cases = [({"agent_id": "test-agent-b-0001"}, "TestAgentB (paseo:test-age)@host-b"),
                 # Cached under another host: never borrow that name.
                 ({"agent_id": "test-agent-controller-0001"}, "paseo:test-age@host-b"),
                 ({"agent_id": "unknown-agent-id"}, "paseo:unknown-@host-b"),
                 ({"origin_user": "alice"}, "alice@host-b"),
                 ({"owner": "Explicit", "agent_id": "test-agent-b-0001"}, "Explicit@host-b")]
        for kwargs, owner in cases:
            with self.subTest(kwargs=kwargs):
                origin = self.manager._origin(kwargs.get("owner"), kwargs.get("agent_id"), "HOST-B", kwargs.get("origin_user"))
                self.assertEqual(origin["owner"], owner)
                self.assertEqual(origin["origin_host"], "host-b")
                self.assertIsNone(origin["owner_pid"])
        with patch("switchyard.agent_leases.getpass.getuser", return_value="controller-user"):
            self.assertEqual(self.manager._origin(None, None, "host-b", None)["owner"], "controller-user@host-b")
        self.assertIsNone(self.manager._origin(None, None, None, None))
        for args, message in (((None, None, "elsewhere", None), "Unknown origin host"),
                              ((None, "bad id!", "host-b", None), "Invalid Paseo agent ID"),
                              ((None, None, "host-b", "bad user"), "Invalid origin user"),
                              ((None, "test-agent-b-0001", None, None), "require --origin-host")):
            with self.assertRaisesRegex(ValueError, message):
                self.manager._origin(*args)

    def test_detached_hold_skips_owner_watch_but_honours_ttl_and_release(self):
        with self.assertRaisesRegex(ValueError, "requires --detached"):
            self.manager.hold("test-handheld", scope="remote", origin_host="host-b")
        self.runner.assert_not_called()
        for ending in ("expired", "released"):
            with self.subTest(ending=ending):
                self.ledger.write_text("baseline\n")
                self.runner.reset_mock()
                self.runner.return_value = subprocess.CompletedProcess([], 0)
                with self.assertRaises(LeaseBusy):
                    # The fake runner never starts the unit; drive the persisted request's holder directly.
                    self.manager.hold("test-handheld", scope="remote fixture", ttl=120, detached=True,
                                      agent_id="test-agent-b-0001", origin_host="host-b")
                argv = self.runner.call_args_list[0].args[0]
                self.assertIn("--setenv=PASEO_AGENT_ID=test-agent-b-0001", argv)
                state = next(value for value in self.manager.states.records() if value["status"] == "starting")
                self.assertTrue(state["detached"])
                self.assertEqual(state["owner"], "TestAgentB (paseo:test-age)@host-b")
                self.manager.states.update(state["lease_id"], lambda value: value.pop("release_requested"))
                self.manager.owner_alive = lambda pid, started: False
                steps = []
                def step(seconds, lease_id=state["lease_id"]):
                    steps.append(seconds)
                    if ending == "released" and len(steps) == 3:
                        self.manager.states.update(lease_id, lambda value: value.update(release_requested=True))
                    self.clock.now += 30
                self.manager.sleep = step
                self.manager.holder(state["lease_id"])
                self.manager.sleep = self.clock.sleep
                events = self.events()
                self.assertEqual([(event["event"], event.get("reason")) for event in events], [("CLAIM", None), ("RELEASE", ending)])
                self.assertEqual(events[0]["via"], "switchyard lease hold --detached from host-b")
                self.assertGreaterEqual(len(steps), 3)

    def test_busy_message_prefers_the_matched_switchyard_owner(self):
        row = {"device": "TESTHANDHELD", "holders": [{"pid": 1, "comm": "python3"}], "last_entries": [],
               "switchyard_lease": {"owner": "TestAgentB (paseo:test-age)@host-b"}}
        self.assertTrue(busy_message(row).startswith("TESTHANDHELD busy: TestAgentB (paseo:test-age)@host-b;"))
        del row["switchyard_lease"]
        self.assertTrue(busy_message(row).startswith("TESTHANDHELD busy: python3:1;"))
        row["switchyard_lease"] = {"owner": "TestAgentB@host-b", "lease_id": "a" * 32, "suspect": True,
                                   "suspect_cause": "disconnected", "suspect_since": "2000-01-01T00:00:00+00:00"}
        message = busy_message(row)
        self.assertRegex(message, r"connection lost \d+ min ago \(disconnected\), command state unknown")
        self.assertIn(f"switchyard lease release {'a' * 32}", message)

    def wait_for(self, predicate, timeout=10):
        deadline = time.monotonic() + timeout
        while not predicate():
            if time.monotonic() > deadline:
                self.fail("condition not reached")
            time.sleep(0.05)

    def attach_state(self, lease_id):
        return LeaseStates(self.root / "attach-state" / "leases").read(lease_id)

    def test_heartbeat_attach_releases_only_on_done(self):
        child, claim = self.spawn_attach(heartbeat=5)
        child.stdin.write("\n\ndone\n")
        child.stdin.flush()
        child.wait(timeout=10)
        stdout, stderr = child.communicate(timeout=10)
        self.assertEqual(child.returncode, 0, stderr)
        self.assertEqual(json.loads(stdout)["reason"], "released")
        events = self.events()
        self.assertEqual([(event["event"], event.get("reason")) for event in events], [("CLAIM", None), ("RELEASE", "released")])
        self.assertNotIn("suspect_cause", events[1])

    def test_heartbeat_eof_without_done_is_suspect_until_explicit_release(self):
        child, claim = self.spawn_attach(heartbeat=30)
        child.send_signal(signal.SIGHUP)  # SSH session teardown: ignored once a heartbeat lease is held.
        child.stdin.close()
        self.wait_for(lambda: self.attach_state(claim["lease_id"]).get("suspect"))
        state = self.attach_state(claim["lease_id"])
        self.assertEqual((state["suspect_cause"], state["status"]), ("disconnected", "claimed"))
        time.sleep(0.5)
        self.assertIsNone(child.poll())
        self.assertEqual([event["event"] for event in self.events()], ["CLAIM"])
        with self.assertRaises(LeaseBusy):
            with LedgerBroker({"TESTHANDHELD": self.ledger}).hold("TESTHANDHELD", owner="contender", scope="test", worktree=str(self.root)):
                pass
        # Visible in the lock view and the busy message.
        row = {"device": "TESTHANDHELD", "state": "held", "path": str(self.ledger), "holders": [{"pid": child.pid}], "last_entries": []}
        lease = enrich_locks({"ledgers": [row]}, self.root / "attach-state" / "leases")["ledgers"][0]["switchyard_lease"]
        self.assertEqual((lease["suspect"], lease["suspect_cause"]), (True, "disconnected"))
        self.assertIn("command state unknown", busy_message(row))
        manager = AgentLeases(hosts=("test-handheld",), state_dir=self.root / "attach-state", ledger_dir=self.ledgers)
        manager.observer = lambda: {"ledgers": [dict(row)]}
        self.assertEqual(manager.release(claim["lease_id"])["reason"], "released")
        child.wait(timeout=10)
        self.assertEqual(child.returncode, 0, child.stderr.read())
        events = self.events()
        self.assertEqual([event["event"] for event in events], ["CLAIM", "RELEASE"])
        self.assertEqual((events[1]["reason"], events[1]["released_after_loss"], events[1]["suspect_cause"]),
                         ("released", True, "disconnected"))

    def test_heartbeats_keep_the_lease_and_silence_marks_it_suspect(self):
        child, claim = self.spawn_attach(heartbeat=1)
        for _ in range(8):  # 2.4 s of heartbeats: more than twice the window.
            child.stdin.write("\n")
            child.stdin.flush()
            time.sleep(0.3)
        self.assertFalse(self.attach_state(claim["lease_id"]).get("suspect"))
        self.wait_for(lambda: self.attach_state(claim["lease_id"]).get("suspect"), timeout=5)
        self.assertEqual(self.attach_state(claim["lease_id"])["suspect_cause"], "silent")
        self.assertEqual([event["event"] for event in self.events()], ["CLAIM"])
        child.send_signal(signal.SIGTERM)  # An operator signal on the control host still ends it.
        child.wait(timeout=10)
        self.assertEqual([(event["event"], event.get("reason"), event.get("suspect_cause")) for event in self.events()],
                         [("CLAIM", None, None), ("RELEASE", "signal", "silent")])

    def test_hard_cap_expires_a_suspect_lease(self):
        read_end, write_end = os.pipe()
        self.addCleanup(os.close, read_end)
        self.addCleanup(os.close, write_end)
        ticks = []
        def monotonic():
            ticks.append(None)
            return len(ticks) * 10.0
        def clock():
            # The wall clock races ahead only once silence (on `monotonic`) has made the lease suspect.
            self.clock.now += 3000 if len(ticks) >= 3 else 0
            return self.clock.now
        self.manager.monotonic, self.manager.clock = monotonic, clock
        output = io.StringIO()
        self.assertEqual(self.manager.attach("test-handheld", scope="cap fixture", heartbeat=5, input_fd=read_end, output=output), 0)
        claim, released = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(released["reason"], "expired")
        events = self.events()
        self.assertEqual([(event["event"], event.get("reason"), event.get("suspect_cause")) for event in events],
                         [("CLAIM", None, None), ("RELEASE", "expired", "silent")])
        self.assertNotIn("released_after_loss", events[1])


class IdentityTests(unittest.TestCase):
    def test_ancestor_agent_and_pid_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def process(pid, parent, comm, started, agent_id=""):
                path = root / str(pid)
                path.mkdir(exist_ok=True)
                fields = ["S", str(parent), *(["0"] * 17), str(started)]
                (path / "stat").write_text(f"{pid} ({comm}) " + " ".join(fields))
                (path / "comm").write_text(comm + "\n")
                (path / "environ").write_bytes(f"PASEO_AGENT_ID={agent_id}\0UNRELATED_SECRET=never-read\0".encode())
            process(100, 200, "sh", 10, "agent-123456789")
            process(200, 0, "omp", 20, "agent-123456789")
            with patch.object(locks, "PROC_ROOT", root):
                identity = caller_identity({"agent-123456789": {"name": "TestAgent"}}, environment={"PASEO_AGENT_ID": "agent-123456789"}, pid=100)
                self.assertEqual(identity["owner"], "TestAgent (paseo:agent-12)")
                self.assertEqual(identity["owner_pid"], 200)
                self.assertEqual(identity["owner_started"], 20)
                self.assertTrue(process_alive(200, 20))
                process(200, 0, "omp", 21)
                self.assertFalse(process_alive(200, 20))
                identity = caller_identity(environment={}, pid=200)
                self.assertEqual(identity["owner"], "omp:200")

    def test_without_agent_owner_is_the_durable_caller_not_launcher_plumbing(self):
        # An operator's terminal: bash -> uv -> python (this CLI). uv exits as soon as `hold`
        # returns, so owning the lease by it would release the hold immediately.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for pid, parent, comm, started in ((300, 301, "uv", 30), (301, 302, "bash", 31), (302, 0, "konsole", 32)):
                path = root / str(pid)
                path.mkdir()
                (path / "stat").write_text(f"{pid} ({comm}) S {parent} " + "0 " * 17 + str(started))
                (path / "comm").write_text(comm + "\n")
                (path / "environ").write_bytes(b"")
            with patch.object(locks, "PROC_ROOT", root):
                identity = caller_identity(environment={}, pid=300)
            self.assertEqual((identity["owner_pid"], identity["owner_started"]), (301, 31))


class MCPLeaseTests(unittest.TestCase):
    def test_signatures_defaults_bounds_and_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / "catalog.json"
            catalog.write_text((Path(__file__).resolve().parents[1] / "catalogs/example.json").read_text())
            server = create_mcp(catalog, state_dir=Path(directory) / "state")
            manager = MagicMock()
            manager.hold.return_value = {"lease_id": "fixture"}
            manager.release.return_value = {"status": "released"}
            manager.renew.return_value = {"expires_at": "fixture"}
            async def exercise():
                tools = {item.name: item for item in await server.list_tools()}
                schema = tools["lease_hold"].inputSchema
                self.assertEqual(schema["required"], ["device", "scope"])
                self.assertEqual(schema["properties"]["ttl_minutes"]["default"], 60)
                self.assertEqual(schema["properties"]["ttl_minutes"]["maximum"], 120)
                self.assertNotIn("lease_run", tools)
                await server.call_tool("lease_hold", {"device": "TESTHANDHELD", "scope": "fixture"})
                await server.call_tool("lease_release", {"lease_id": "fixture"})
                await server.call_tool("lease_renew", {"lease_id": "fixture", "ttl_minutes": 2})
                with self.assertRaises(ToolError):
                    await server.call_tool("lease_hold", {"device": "TESTHANDHELD", "scope": "fixture", "ttl_minutes": 121})
            with patch.object(server._service, "agent_leases", return_value=manager):
                anyio.run(exercise)
            manager.hold.assert_called_once_with("TESTHANDHELD", scope="fixture", ttl=3600, owner=None)
            manager.release.assert_called_once_with("fixture")
            manager.renew.assert_called_once_with("fixture", ttl=120)


if __name__ == "__main__":
    unittest.main()
