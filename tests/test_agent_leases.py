"""Durable lease clients; fixtures never contact devices or execute systemd."""
from contextlib import redirect_stderr, redirect_stdout
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
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import anyio
from mcp.server.fastmcp.exceptions import ToolError

from switchyard import cli, locks
from switchyard.agent_leases import (
    AgentLeases, busy_message, caller_identity, holder_main,
    process_alive, systemd_argv, ttl_seconds,
)
from switchyard.leases import LeaseBusy
from switchyard.mcp_server import create_mcp
from switchyard.auth import AuthError
from switchyard.web import _Handler


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
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.ledgers = self.root / "metadata-only"
        self.ledger = self.ledgers / "DEVICE_ACCESS_TESTHANDHELD.md"
        self.clock, self.runner = Clock(), MagicMock()
        self.collectors = {
            "test-handheld": {"transport": "adb", "serial": "fake-serial", "ledger": str(self.ledger)},
            "handheld-alias": {"transport": "adb", "serial": "fake-serial", "ledger": str(self.ledger)},
        }
        self.manager = AgentLeases(collectors=self.collectors, hosts=("test-handheld", "host-b"),
                                   state_dir=self.root / "state", ledger_dir=self.ledgers,
                                   clock=self.clock, monotonic=self.clock, sleep=self.clock.sleep,
                                   owner_alive=lambda pid, started: True, runner=self.runner)

    def claim(self, mode="hold", **updates):
        state = self.manager._new("test-handheld", "fixture inspection", "FixtureAgent", str(self.root), mode, 60)
        state.update(updates)
        return self.manager._claim(state)

    def test_aliases_share_one_database_reservation_without_ledger_files(self):
        for alias in ("TESTHANDHELD", "tEsThAnDhElD", "test-handheld", "handheld-alias"):
            self.assertEqual(self.manager.resolve(alias)[:2], ("TESTHANDHELD", self.ledger))
        current = self.claim()
        for alias in ("TESTHANDHELD", "test-handheld", "handheld-alias"):
            with self.subTest(alias=alias), self.assertRaisesRegex(LeaseBusy, "FixtureAgent"):
                self.manager.run(alias, ["never-run"], scope="contender")
        self.assertEqual(self.manager.status("handheld-alias")["current"]["lease_id"], current["lease_id"])
        self.assertEqual(len(self.manager.list()["ledgers"]), 2)
        self.assertFalse(self.ledgers.exists())
        self.assertTrue(self.manager.states.path.exists())
        self.assertEqual(self.manager.states.path.stat().st_mode & 0o777, 0o600)

    def test_registry_without_existing_ledger(self):
        manager = AgentLeases(hosts=("new-host",), state_dir=self.root / "other-state", ledger_dir=self.ledgers)
        self.assertEqual(manager.resolve("new-host")[1], self.ledgers / "DEVICE_ACCESS_NEWHOST.md")
        self.assertFalse(self.ledgers.exists())
        for device in ("rogue", "../TESTHANDHELD", "TESTHANDHELDB"):
            with self.assertRaises(ValueError):
                self.manager.resolve(device)

    def test_configured_legacy_label_does_not_create_an_independent_derived_label(self):
        alternate = self.ledgers / "DEVICE_ACCESS_ALTERNATE.md"
        collectors = {"test-handheld": {"ledger": str(alternate)}, "handheld-alias": {"ledger": str(alternate)}}
        manager = AgentLeases(collectors=collectors, hosts=("test-handheld", "handheld-alias"),
                               state_dir=self.root / "alternate-state", ledger_dir=self.ledgers)
        for alias in ("test-handheld", "handheld-alias", "ALTERNATE"):
            self.assertEqual(manager.resolve(alias)[0], "ALTERNATE")
        with self.assertRaises(ValueError):
            manager.resolve("TESTHANDHELD")
        self.assertEqual([row["device"] for row in manager.list()["ledgers"]], ["ALTERNATE"])

    def test_nonstandard_configured_metadata_path_is_leaseable_and_guarded(self):
        path = self.root / "custom-metadata" / "host.lock"
        manager = AgentLeases(collectors={"host-b": {"ledger": str(path)}}, hosts=("host-b",),
                               state_dir=self.root / "custom-state", ledger_dir=self.ledgers)
        self.assertEqual(manager.resolve("host-b")[:2], ("HOSTB", path))
        self.assertEqual(manager.resolve("HOSTB")[:2], ("HOSTB", path))
        self.assertEqual(manager.list()["ledgers"][0]["path"], str(path))
        self.assertFalse(path.exists())
        path.parent.mkdir()
        legacy = path
        legacy.write_text("legacy history\n")
        with self.assertRaisesRegex(ValueError, "migration"):
            AgentLeases(collectors={"host-b": {"ledger": str(path)}}, hosts=("host-b",),
                         state_dir=self.root / "guard-state", ledger_dir=self.ledgers)

    def test_external_exclusions_cover_every_alias(self):
        for excluded in ("test-handheld", "TESTHANDHELD", "handheld-alias"):
            with patch.dict(os.environ, {"SWITCHYARD_EXTERNAL_LEASE_HOSTS": excluded}):
                for alias in ("test-handheld", "TESTHANDHELD", "handheld-alias"):
                    with self.subTest(excluded=excluded, alias=alias), self.assertRaisesRegex(ValueError, "external lease coordinator"):
                        self.manager.resolve(alias)
        with patch.dict(os.environ, {"SWITCHYARD_EXTERNAL_LEASE_HOSTS": "../bad"}), self.assertRaises(ValueError):
            self.manager.resolve("test-handheld")

    def test_bounded_wait_and_validation_never_dispatch_busy_command(self):
        self.claim()
        with patch("switchyard.agent_leases.subprocess.Popen") as spawn, self.assertRaises(LeaseBusy):
            self.manager.run("test-handheld", ["never-run"], scope="contender", wait=2.5)
        spawn.assert_not_called()
        self.assertEqual(self.clock.sleeps, [1, 1, 0.5])
        for wait in (-1, 601, float("inf"), float("nan"), True):
            with self.assertRaises(ValueError):
                self.manager.run("test-handheld", ["never-run"], scope="test", wait=wait)

    def test_run_preserves_exit_environment_cwd_and_no_lock_fd(self):
        output = self.root / "environment.json"
        source = "import json,os,sys; json.dump({'env':dict(os.environ),'cwd':os.getcwd()},open(sys.argv[1],'w')); sys.exit(7)"
        with patch.dict(os.environ, {"SWITCHYARD_SSH_TARGET": "stale", "SWITCHYARD_SSH_PORT": "999",
                                    "ANDROID_SERIAL": "old", "DEVICE_LOCK_FD": "8", "CALLER_VAR": "preserved"}):
            code = self.manager.run("test-handheld", [sys.executable, "-c", source, str(output)], scope="inspect")
        self.assertEqual(code, 7)
        result = json.loads(output.read_text())
        environment = result["env"]
        self.assertEqual(result["cwd"], os.getcwd())
        self.assertEqual(environment["CALLER_VAR"], "preserved")
        self.assertEqual(environment["ANDROID_SERIAL"], "fake-serial")
        for name in ("SWITCHYARD_SSH_TARGET", "SWITCHYARD_SSH_PORT", "DEVICE_LOCK_FD"):
            self.assertNotIn(name, environment)
        state = self.manager.states.read(environment["SWITCHYARD_LEASE_ID"])
        self.assertEqual((state["status"], state["reason"], state["outcome"]), ("released", "completed", "completed"))
        self.assertEqual(self.manager.status("test-handheld")["state"], "free")

    def test_pass_lock_fd_fails_before_claim_or_dispatch(self):
        with patch("switchyard.agent_leases.subprocess.Popen") as spawn, self.assertRaisesRegex(ValueError, "unsupported"):
            self.manager.run("test-handheld", ["never-run"], scope="legacy", pass_lock_fd=True)
        spawn.assert_not_called()
        self.assertEqual(self.manager.states.records(), [])

    def test_spawn_failure_is_proven_not_dispatched(self):
        with self.assertRaises(FileNotFoundError):
            self.manager.run("test-handheld", [str(self.root / "absent")], scope="fixture")
        self.assertEqual(self.manager.status("test-handheld")["state"], "free")
        self.assertEqual(self.manager.states.records()[0]["reason"], "not-dispatched")

    def test_transport_failure_and_child_signal_leave_suspect(self):
        for source in ("raise SystemExit(255)", "import os,signal; os.kill(os.getpid(),signal.SIGTERM)"):
            with self.subTest(source=source):
                self.manager.run("test-handheld", [sys.executable, "-c", source], scope="uncertain remote work")
                current = self.manager.states.current("TESTHANDHELD")
                self.assertEqual(current["status"], "suspect")
                with self.assertRaises(LeaseBusy):
                    self.manager.run("test-handheld", ["never-run"], scope="must defer")
                self.manager.states.break_device("TESTHANDHELD", operator="tester", reason="fixture cleanup",
                                                 attest_stopped="fixture child reaped", expected_id=current["lease_id"])

    def test_expiry_restart_and_owner_death_retain_reservation(self):
        state = self.claim()
        self.clock.now += 61
        restarted = AgentLeases(collectors=self.collectors, state_dir=self.manager.root, ledger_dir=self.ledgers,
                                clock=self.clock)
        current = restarted.states.current("TESTHANDHELD")
        self.assertEqual((current["lease_id"], current["status"]), (state["lease_id"], "suspect"))
        with self.assertRaisesRegex(ValueError, "matching lease ID"):
            restarted.release("test-handheld")
        self.assertEqual(restarted.release(state["lease_id"])["status"], "released")
        dead = self.claim(pid=999999999, pid_started=1)
        self.manager.states.update(dead["lease_id"], lambda value: value.update(pid=999999999, pid_started=1))
        self.assertTrue(self.manager.states.current("TESTHANDHELD")["suspect"])

    def test_detached_hold_return_renew_release_and_stale_completion(self):
        result = self.manager.hold("test-handheld", scope="HTTP fixture", detached=True, ttl=60,
                                   origin_host="host-b", origin_user="tester")
        self.assertEqual(set(result), {"lease_id", "device", "expires_at", "holder_unit", "env"})
        self.assertEqual(self.manager.states.read(result["lease_id"])["owner"], "tester@host-b")
        old = result["expires_at"]
        renewed = self.manager.renew(result["lease_id"], ttl=120)
        self.assertEqual(set(renewed), {"lease_id", "device", "expires_at", "holder_unit"})
        self.assertGreater(renewed["expires_at"], old)
        released = self.manager.release(result["lease_id"])
        self.assertEqual(set(released), {"lease_id", "device", "status", "reason"})
        self.assertEqual((released["status"], released["reason"]), ("released", "released"))
        next_lease = self.manager.hold("test-handheld", scope="next generation", detached=True)
        with self.assertRaisesRegex(ValueError, "no longer active"):
            self.manager.release(result["lease_id"])
        self.assertEqual(self.manager.states.current("TESTHANDHELD")["lease_id"], next_lease["lease_id"])
        self.runner.assert_not_called()

    def test_detached_expiry_cannot_be_renewed_or_released_by_alias(self):
        result = self.manager.hold("test-handheld", scope="fixture", detached=True, ttl=60)
        self.clock.now += 61
        with self.assertRaisesRegex(ValueError, "suspect"):
            self.manager.renew(result["lease_id"], ttl=60)
        with self.assertRaisesRegex(ValueError, "matching lease ID"):
            self.manager.release("test-handheld")
        self.assertEqual(self.manager.release(result["lease_id"])["status"], "released")

    def test_holder_owner_exit_and_signal_do_not_free(self):
        for reason in ("owner-exited", "expired", "signal", "holder-error"):
            with self.subTest(reason=reason):
                state = self.manager._new("test-handheld", "watch owner", None, None, "hold", 60)
                self.manager.states.update(state["lease_id"], lambda value: value.update(state), create=True)
                self.manager.owner_alive = lambda pid, started: reason != "owner-exited"
                def step(seconds):
                    if reason == "signal":
                        os.kill(os.getpid(), signal.SIGTERM)
                    elif reason == "holder-error":
                        raise RuntimeError("watcher failed")
                    else:
                        self.clock.now += 60
                self.manager.sleep = step
                if reason == "holder-error":
                    with self.assertRaisesRegex(RuntimeError, "watcher failed"):
                        self.manager.holder(state["lease_id"])
                else:
                    self.manager.holder(state["lease_id"])
                self.assertEqual(self.manager.states.current("TESTHANDHELD")["status"], "suspect")
                self.manager.release(state["lease_id"])

    def test_unconfirmed_holder_startup_reserves_and_delayed_holder_cannot_claim(self):
        with self.assertRaisesRegex(LeaseBusy, "startup unconfirmed"):
            self.manager.hold("test-handheld", scope="watch fixture", ttl=60)
        state = self.manager.states.records()[0]
        self.assertEqual(state["status"], "suspect")
        with self.assertRaisesRegex(ValueError, "awaiting a holder"):
            self.manager.holder(state["lease_id"])
        with self.assertRaises(LeaseBusy):
            self.manager.run("test-handheld", ["never-run"], scope="contender")

    def test_integrated_holder_command_and_mapping(self):
        for executable in ("", "relative", "/host/../unsafe", "/host/helper\n"):
            with patch.dict(os.environ, {"SWITCHYARD_CONTAINER_HOST": "1", "SWITCHYARD_HOST_HOLDER": executable}):
                with self.assertRaisesRegex(ValueError, "absolute trusted"):
                    self.manager.hold("test-handheld", scope="fixture")
        self.assertEqual(self.manager.states.records(), [])
        def start(argv, **kwargs):
            state = self.manager.states.read(argv[-1])
            self.assertEqual(argv[argv.index("--") + 1:],
                             ["/usr/bin/env", "--", "/host/helper", "--state-dir", str(self.manager.root.resolve()),
                              "lease", "_holder", state["lease_id"]])
            self.manager._claim(state)
        self.runner.side_effect = start
        with patch.dict(os.environ, {"SWITCHYARD_CONTAINER_HOST": "1", "SWITCHYARD_HOST_HOLDER": "/host/helper"}):
            result = self.manager.hold("test-handheld", scope="fixture")
        self.assertEqual(self.manager.states.read(result["lease_id"])["status"], "claimed")
        state = self.manager.states.read(result["lease_id"])
        state["paseo_agent_id"] = "fixture-agent"
        self.assertIn("--setenv=PASEO_AGENT_ID=fixture-agent", systemd_argv(state, ["fixture"]))
        self.manager.states.update(result["lease_id"], lambda value: value.update(ledger="relative/unsafe"))
        with self.assertRaisesRegex(ValueError, "ledger changed"):
            holder_main(self.manager.root, result["lease_id"])

    def test_metadata_bounds_and_remote_attribution(self):
        self.assertEqual(ttl_seconds("60m"), 3600)
        self.assertEqual(ttl_seconds("2h"), 7200)
        for ttl in ("0m", "3h", "59s", "nan", "-1m"):
            with self.assertRaises(ValueError):
                ttl_seconds(ttl)
        for scope in ("", " ", "x" * 513, "line\nbreak"):
            with self.assertRaises(ValueError):
                self.manager.hold("test-handheld", scope=scope)
        for values in ((None, "bad id!", "host-b", None), (None, None, "unknown", None),
                       (None, None, "host-b", "bad user"), (None, "fixture", None, None)):
            with self.assertRaises(ValueError):
                self.manager._origin(*values)
        self.manager.paseo_agents = {"fixture-agent": {"name": "Remote", "host_id": "host-b"}}
        origin = self.manager._origin(None, "fixture-agent", "HOST-B", "tester")
        self.assertEqual(origin["owner"], "Remote (paseo:fixture-)@host-b")


ATTACH_HARNESS = (
    "from switchyard.agent_leases import AgentLeases; import sys; "
    "m=AgentLeases(ledger_dir=sys.argv[1],state_dir=sys.argv[2],hosts=('test-handheld','host-b')); "
    "beat=float(sys.argv[3]) if len(sys.argv)>3 else None; "
    "sys.exit(m.attach('test-handheld',scope='remote fixture',origin_host='host-b',origin_user='tester',heartbeat=beat,completion_proof=True))")


class RemoteCallerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.manager = AgentLeases(hosts=("test-handheld", "host-b"), state_dir=self.root / "state",
                                   ledger_dir=self.root / "metadata")

    def spawn_attach(self, heartbeat=None):
        child = subprocess.Popen([sys.executable, "-c", ATTACH_HARNESS, str(self.manager.ledger_dir),
                                  str(self.manager.root), *([] if heartbeat is None else [str(heartbeat)])],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()
        self.addCleanup(cleanup)
        return child, json.loads(child.stdout.readline())

    def test_old_remote_client_is_refused_before_claim(self):
        with self.assertRaisesRegex(ValueError, "completion-proof client"):
            self.manager.attach("test-handheld", scope="old client", origin_host="host-b", output=io.StringIO())
        self.assertEqual(self.manager.states.records(), [])

    def test_done_is_the_only_normal_attach_completion(self):
        child, claim = self.spawn_attach(heartbeat=5)
        self.assertEqual(set(claim), {"status", "lease_id", "device", "expires_at", "env"})
        self.assertEqual(claim["env"]["SWITCHYARD_LEASE_ID"], claim["lease_id"])
        stdout, stderr = child.communicate("\n\ndone\n", timeout=10)
        self.assertEqual(child.returncode, 0, stderr)
        self.assertEqual(json.loads(stdout), {"status": "released", "lease_id": claim["lease_id"],
                                            "device": "TESTHANDHELD", "reason": "released"})
        self.assertEqual(self.manager.status("test-handheld")["state"], "free")

    def test_eof_with_or_without_heartbeat_retains_after_process_exit_and_restart(self):
        for heartbeat in (None, 30):
            with self.subTest(heartbeat=heartbeat):
                child, claim = self.spawn_attach(heartbeat)
                stdout, stderr = child.communicate("", timeout=10)
                self.assertNotEqual(child.returncode, 0, stderr)
                self.assertEqual(stdout, "")
                restarted = AgentLeases(hosts=("test-handheld",), state_dir=self.manager.root,
                                         ledger_dir=self.manager.ledger_dir)
                row = restarted.status("test-handheld")
                self.assertEqual((row["state"], row["status"]), ("held", "suspect"))
                self.assertTrue(row["switchyard_lease"]["suspect"])
                self.assertIn("command state unknown", busy_message(row))
                for reference in ("test-handheld", claim["lease_id"]):
                    with self.assertRaisesRegex(ValueError, "attach requires"):
                        restarted.release(reference)
                with self.assertRaises(LeaseBusy):
                    restarted.run("test-handheld", ["never-run"], scope="must defer")
                restarted.states.break_device("TESTHANDHELD", operator="tester", reason="cleanup fixture",
                                               attest_stopped="fixture command never dispatched", expected_id=claim["lease_id"])

    def test_signal_and_killed_attach_never_release(self):
        for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGKILL):
            child, claim = self.spawn_attach(heartbeat=30)
            child.send_signal(signum)
            child.wait(timeout=10)
            current = self.manager.states.current("TESTHANDHELD")
            self.assertEqual((current["lease_id"], current["status"]), (claim["lease_id"], "suspect"))
            self.manager.states.break_device("TESTHANDHELD", operator="tester", reason="fixture cleanup",
                                             attest_stopped="no command dispatched", expected_id=claim["lease_id"])

    def test_silence_retains_while_late_matching_done_can_complete(self):
        child, claim = self.spawn_attach(heartbeat=1)
        deadline = time.monotonic() + 5
        while not self.manager.states.read(claim["lease_id"]).get("suspect") and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(self.manager.states.read(claim["lease_id"])["suspect"])
        stdout, stderr = child.communicate("done\n", timeout=10)
        self.assertEqual(child.returncode, 0, stderr)
        self.assertEqual(json.loads(stdout)["status"], "released")

    def test_deadline_and_output_failure_are_not_completion(self):
        for failure in ("deadline", "output"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                clock = Clock()
                manager = AgentLeases(hosts=("fixture",), state_dir=Path(directory) / "state",
                                       ledger_dir=Path(directory) / "metadata", clock=clock)
                output = io.StringIO()
                if failure == "output":
                    output.close()
                def reader(fd, timeout):
                    clock.now += 7201
                    return False, b""
                with patch("switchyard.agent_leases._read_input", side_effect=reader):
                    self.assertNotEqual(manager.attach("fixture", scope="fixture", output=output), 0)
                current = manager.states.current("FIXTURE")
                self.assertEqual(current["status"], "suspect")

    def test_stale_done_cannot_complete_a_replacement_generation(self):
        child, claim = self.spawn_attach(heartbeat=30)
        self.manager.states.break_device("TESTHANDHELD", operator="tester", reason="fixture fence",
                                         attest_stopped="fixture has no dispatched remote command",
                                         expected_id=claim["lease_id"])
        replacement = self.manager.hold("test-handheld", scope="new generation", detached=True)
        child.communicate("done\n", timeout=10)
        self.assertNotEqual(child.returncode, 0)
        self.assertEqual(self.manager.states.current("TESTHANDHELD")["lease_id"], replacement["lease_id"])


class HTTPLeaseTests(unittest.TestCase):
    """Exercise the real route handlers with no socket or device access."""
    def test_return_shapes_key_ownership_and_scoped_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manager = AgentLeases(hosts=("test-handheld", "host-b"), state_dir=root / "state",
                                   ledger_dir=root / "metadata")
            service = MagicMock()
            service.agent_leases.return_value = manager
            service.hosts.return_value = {"hosts": [{"id": "test-handheld"}, {"id": "host-b"}]}
            store = MagicMock()
            owners = {}
            store.record_lease.side_effect = lambda lease_id, key_id: owners.update({lease_id: key_id})
            store.lease_owner.side_effect = owners.get
            handler = _Handler.__new__(_Handler)
            handler.server = SimpleNamespace(service=service, auth=SimpleNamespace(store=store))
            handler._allow_deadline = MagicMock()
            handler._json = MagicMock()
            key = {"id": "a" * 32, "name": "Fixture", "user": "tester", "host_id": "host-b",
                   "agent_id": None, "hosts": ["test-handheld"]}
            handler.identity = SimpleNamespace(kind="key", key=key)
            handler._r_lease_hold((), {"device": "test-handheld", "scope": "HTTP fixture", "ttl_minutes": 1})
            status, held = handler._json.call_args.args
            self.assertEqual(status, 200)
            self.assertEqual(set(held), {"lease_id", "device", "expires_at"})
            lease_id = held["lease_id"]
            self.assertEqual(owners[lease_id], key["id"])
            handler._r_lease_renew((lease_id,), {"ttl_minutes": 2})
            self.assertEqual(set(handler._json.call_args.args[1]), {"lease_id", "device", "expires_at"})
            handler.identity = SimpleNamespace(kind="key", key={**key, "id": "b" * 32})
            for method in (handler._r_lease_renew, handler._r_lease_release):
                with self.assertRaises(AuthError) as error:
                    method((lease_id,), {})
                self.assertEqual(error.exception.status, 403)
            self.assertEqual(manager.status("test-handheld")["state"], "held")
            handler.identity = SimpleNamespace(kind="key", key={**key, "hosts": ["host-b"]})
            with self.assertRaises(AuthError) as error:
                handler._r_lease_hold((), {"device": "test-handheld", "scope": "not authorized"})
            self.assertEqual(error.exception.status, 403)
            handler.identity = SimpleNamespace(kind="key", key=key)
            handler._r_lease_release((lease_id,), {})
            released = handler._json.call_args.args[1]
            self.assertEqual(set(released), {"lease_id", "device", "status", "reason"})
            self.assertEqual(released["status"], "released")
            self.assertEqual(manager.status("test-handheld")["state"], "free")


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
