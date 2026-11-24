"""`switchyard lease break` / `lease clear`: temporary ledgers and the test's own child processes only."""
from contextlib import redirect_stderr, redirect_stdout
import importlib.machinery
import importlib.util
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

from switchyard import cli, locks
from switchyard.agent_leases import (
    AgentLeases, BREAK_REFUSED, agent_ancestry, block_path, flock_holders, read_block,
)
from switchyard.leases import LedgerBroker, LeaseBusy

OPERATOR = {"user": "tester", "agent": None}
ROOT = Path(__file__).resolve().parents[1]

# A raw-flock holder the test owns. Modes: "agent" renames itself `omp` (an agent session), "ignore"
# ignores SIGTERM, "inherit" hands the locked descriptor to a child and exits (the kernel then reports a
# dead PID while the child holds the lock). Writes the holding PID to the report file.
RAW_HOLDER = r"""
import ctypes, fcntl, os, signal, sys, time
path, mode, report = sys.argv[1:4]
if "agent" in mode:
    ctypes.CDLL(None).prctl(15, b"omp", 0, 0, 0)
if "ignore" in mode:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
fd = os.open(path, os.O_RDWR | os.O_APPEND)
fcntl.flock(fd, fcntl.LOCK_EX)
if "inherit" in mode and os.fork():
    os._exit(0)
with open(report + ".tmp", "w") as stream:
    stream.write(str(os.getpid()))
os.rename(report + ".tmp", report)
time.sleep(60)
"""

HOLDER = "import sys; from switchyard.agent_leases import holder_main; holder_main(sys.argv[1], sys.argv[2])"
ATTACH = ("import sys; from switchyard.agent_leases import AgentLeases; "
          "m=AgentLeases(ledger_dir=sys.argv[1], state_dir=sys.argv[2], hosts=('test-handheld', 'host-b')); "
          "sys.exit(m.attach('TESTHANDHELD', scope='remote fixture', origin_host='host-b', origin_user='tester', heartbeat=30))")


def running(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


class LeaseBreakTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.ledgers = self.root / "ledgers"
        self.ledgers.mkdir()
        self.ledger = self.ledgers / "DEVICE_ACCESS_TESTHANDHELD.md"
        self.ledger.write_text("baseline\n")
        self.state = self.root / "state"
        self.runner = MagicMock()
        self.manager = AgentLeases(hosts=("test-handheld", "host-b"), state_dir=self.state, ledger_dir=self.ledgers, runner=self.runner)
        self.output = io.StringIO()

    def events(self):
        return [json.loads(line) for line in self.ledger.read_text().splitlines() if line.startswith("{")]

    def wait_for(self, predicate, timeout=10):
        deadline = time.monotonic() + timeout
        while not predicate():
            if time.monotonic() > deadline:
                self.fail("condition not reached")
            time.sleep(0.05)

    def raw_holder(self, mode=""):
        report = self.root / f"holder-{len(list(self.root.glob('holder-*')))}"
        child = subprocess.Popen([sys.executable, "-c", RAW_HOLDER, str(self.ledger), mode, str(report)])
        self.wait_for(report.exists)
        pid = int(report.read_text())

        def cleanup():
            for target in {pid, child.pid}:
                try:
                    os.kill(target, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            child.wait(timeout=5)
        self.addCleanup(cleanup)
        if "inherit" in mode:
            child.wait(timeout=5)  # The locker is gone; only the inheritor holds the lock now.
        return pid

    def break_(self, **kwargs):
        kwargs.setdefault("confirm", lambda label: label == "TESTHANDHELD")
        kwargs.setdefault("identity", OPERATOR)
        kwargs.setdefault("verify_seconds", 2)
        kwargs.setdefault("signal_grace", 2)
        return self.manager.break_lease("test-handheld", reason=kwargs.pop("reason", "stuck fixture"), output=self.output, **kwargs)

    def start_hold(self):
        state = self.manager._new("test-handheld", "hold fixture", "Holder", str(self.root), "hold", 600)
        state.update(detached=True)
        self.manager.states.update(state["lease_id"], lambda value: value.update(state), create=True)
        child = subprocess.Popen([sys.executable, "-c", HOLDER, str(self.state), state["lease_id"]],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: child.poll() is None and (child.kill(), child.wait(timeout=5)))
        self.wait_for(lambda: self.manager.states.read(state["lease_id"])["status"] == "claimed")
        return state["lease_id"], child

    # ---- human-only gate ------------------------------------------------------------------------------

    def test_refused_for_agents_and_without_terminal_confirmation(self):
        with self.assertRaisesRegex(ValueError, BREAK_REFUSED):
            self.break_(identity={"user": "tester", "agent": "ancestor omp:1 is an agent session"})
        self.assertIsNotNone(agent_ancestry(environment={"PASEO_AGENT_ID": "abc"}))
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            for pid, parent, comm in ((10, 11, "uv"), (11, 12, "bash"), (12, 13, "xcompmgr"), (13, 0, "konsole")):
                (proc / str(pid)).mkdir()
                (proc / str(pid) / "stat").write_text(f"{pid} ({comm}) S {parent} " + "0 " * 17 + "5")
                (proc / str(pid) / "comm").write_text(comm + "\n")
                (proc / str(pid) / "environ").write_bytes(b"")
            with patch.object(locks, "PROC_ROOT", proc):
                self.assertIsNone(agent_ancestry(environment={}, pid=10))
                (proc / "13" / "comm").write_text("omp\n")
                self.assertIn("omp:13 is an agent session", agent_ancestry(environment={}, pid=10))
        # CLI: refused under agent ancestry before anything is shown; without a TTY needs --yes-device.
        self.raw_holder()  # Held, so a wrong --yes-device reaches the confirmation step.
        for environment, human, argv, message in (
                ({"PASEO_AGENT_ID": "agent-1"}, False, [], BREAK_REFUSED),
                ({}, True, [], "needs a terminal"),
                ({}, True, ["--yes-device", "TESTHANDHELDB"], "Not confirmed")):
            with self.subTest(argv=argv), patch.dict(os.environ, environment), \
                    patch("switchyard.agent_leases.agent_ancestry",
                          side_effect=None if human else agent_ancestry, return_value=None), \
                    patch.object(cli, "Service") as service, redirect_stderr(io.StringIO()) as stderr, \
                    redirect_stdout(io.StringIO()), patch.object(sys, "stdin", io.StringIO()), \
                    patch.object(sys, "argv", ["switchyard", "--catalog", "fixture", "lease", "break", "test-handheld",
                                               "--reason", "fixture", *argv]):
                service.return_value.agent_leases.return_value = self.manager
                with self.assertRaises(SystemExit) as error:
                    cli.main()
                self.assertEqual(error.exception.code, 2)
                self.assertIn(message, stderr.getvalue())
        self.assertEqual(self.events(), [])

    # ---- Switchyard leases ----------------------------------------------------------------------------

    def test_switchyard_hold_is_released_broken_then_blocked_until_clear(self):
        lease_id, child = self.start_hold()
        result = self.break_()
        self.assertEqual(result["status"], "broken")
        self.assertTrue(result["blocked"])
        self.assertEqual(child.wait(timeout=10), 0)
        self.assertIn(f"Switchyard lease {lease_id} mode hold owner Holder", self.output.getvalue())
        events = self.events()
        self.assertEqual([(event["event"], event.get("reason")) for event in events],
                         [("CLAIM", None), ("RELEASE", "broken"), ("BREAK", "stuck fixture")])
        brk = events[-1]
        self.assertEqual((brk["operator"], brk["lease_id"], brk["revoked"][0]["owner"], brk["blocked"], brk["attested_stopped"]),
                         ("tester", lease_id, "Holder", True, False))
        self.runner.assert_not_called()  # Ended through its own state path; no unit stop was needed.
        block = read_block(self.manager.states.directory, "TESTHANDHELD")
        self.assertEqual((block["operator"], block["reason"]), ("tester", "stuck fixture"))
        self.assertEqual(block_path(self.manager.states.directory, "TESTHANDHELD").stat().st_mode & 0o777, 0o600)
        # Every Switchyard lease request is refused while blocked (exit 75 from the CLI).
        for request in (lambda: self.manager.run("test-handheld", ["true"], scope="after break"),
                        lambda: self.manager.hold("test-handheld", scope="after break"),
                        lambda: self.manager.attach("test-handheld", scope="after break", output=io.StringIO())):
            with self.assertRaisesRegex(LeaseBusy, r"TESTHANDHELD blocked: lease broken by tester .*lease clear testhandheld --attest-stopped"):
                request()
        self.runner.assert_not_called()
        stderr = io.StringIO()
        with patch.object(cli, "Service") as service, redirect_stderr(stderr), patch.object(sys, "argv", [
                "switchyard", "--catalog", "fixture", "lease", "run", "test-handheld", "--scope", "s", "--", "true"]):
            service.return_value.agent_leases.return_value = self.manager
            with self.assertRaises(SystemExit) as error:
                cli.main()
        self.assertEqual(error.exception.code, 75)
        self.assertIn("blocked", stderr.getvalue())
        # Visible in the locks view (no false anomaly) and status.
        row = locks.device_locks(self.ledgers, lease_state_dir=self.manager.states.directory)["ledgers"][0]
        self.assertEqual((row["state"], row["anomaly"], row["blocked"]["operator"]), ("free", None, "tester"))
        self.assertEqual(row["last_entries"][-1]["event"], "BREAK")
        self.assertEqual(self.manager.status("test-handheld")["blocked"]["reason"], "stuck fixture")
        # A second break has nothing to act on.
        self.assertEqual(self.break_()["status"], "not-applicable")
        # Clear: attested, recorded while holding the lock, block removed, leases work again.
        result = self.manager.clear_block("test-handheld", attest_stopped="holder unit gone; device idle",
                                          confirm=lambda label: True, identity=OPERATOR, output=self.output)
        self.assertEqual(result["status"], "cleared")
        clear = self.events()[-1]
        self.assertEqual((clear["event"], clear["attestation"], clear["break_reason"]),
                         ("CLEAR", "holder unit gone; device idle", "stuck fixture"))
        self.assertIsNone(read_block(self.manager.states.directory, "TESTHANDHELD"))
        self.assertEqual(self.manager.run("test-handheld", ["true"], scope="after clear"), 0)
        self.assertIsNone(locks.device_locks(self.ledgers)["ledgers"][0]["anomaly"])
        self.assertEqual(self.manager.clear_block("test-handheld", attest_stopped="x", confirm=lambda label: True,
                                                  identity=OPERATOR, output=self.output)["status"], "not-applicable")

    def test_suspect_attach_lease_is_broken_with_one_release(self):
        child = subprocess.Popen([sys.executable, "-c", ATTACH, str(self.ledgers), str(self.state)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: child.poll() is None and (child.kill(), child.communicate(timeout=5)))
        claim = json.loads(child.stdout.readline())
        child.stdin.close()  # EOF without `done`: suspect, still held.
        self.wait_for(lambda: self.manager.states.read(claim["lease_id"]).get("suspect"))
        result = self.break_(attest_stopped="remote client and its command confirmed dead on host-b")
        self.assertEqual((result["status"], result["blocked"]), ("broken", False))
        self.assertEqual(child.wait(timeout=10), 0)
        child.stdout.close()
        child.stderr.close()
        self.assertIn("SUSPECT since", self.output.getvalue())
        events = self.events()
        self.assertEqual([event["event"] for event in events], ["CLAIM", "RELEASE", "BREAK"])
        self.assertEqual((events[1]["reason"], events[1]["released_after_loss"], events[1]["suspect_cause"]),
                         ("broken", True, "disconnected"))
        self.assertEqual((events[2]["revoked"][0]["suspect"], events[2]["attested_stopped"], events[2]["blocked"]),
                         (True, True, False))
        self.assertIsNone(read_block(self.manager.states.directory, "TESTHANDHELD"))
        self.assertEqual(self.manager.run("test-handheld", ["true"], scope="attested"), 0)

    def test_local_run_lease_is_broken_through_its_signal_path(self):
        harness = ("import sys; from switchyard.agent_leases import AgentLeases; "
                   "m=AgentLeases(ledger_dir=sys.argv[1], state_dir=sys.argv[2], hosts=('test-handheld',)); "
                   "sys.exit(m.run('TESTHANDHELD', ['sleep', '30'], scope='run fixture'))")
        child = subprocess.Popen([sys.executable, "-c", harness, str(self.ledgers), str(self.state)])
        self.addCleanup(lambda: child.poll() is None and (child.kill(), child.wait(timeout=5)))
        self.wait_for(lambda: any(value.get("status") == "claimed" for value in self.manager.states.records()))
        result = self.break_()
        self.assertEqual((result["status"], result["revoked"][0]["mode"], result["revoked"][0]["ended"]), ("broken", "run", True))
        self.assertEqual(child.wait(timeout=10), 128 + signal.SIGTERM)  # Its command got the forwarded SIGTERM.
        self.assertEqual([(event["event"], event.get("reason")) for event in self.events()],
                         [("CLAIM", None), ("RELEASE", "broken"), ("BREAK", "stuck fixture")])

    def test_contender_in_the_revoke_window_never_runs(self):
        # Deterministic: a contender acquires exactly between the revoke and the verifying flock.
        lease_id, child = self.start_hold()
        marker = self.root / "contender-ran"
        contender = AgentLeases(hosts=("test-handheld",), state_dir=self.state, ledger_dir=self.ledgers)
        revoke, outcomes = self.manager._revoke, []

        def revoke_then_contend(lease, operator):
            result = revoke(lease, operator)
            try:
                contender.run("test-handheld", ["touch", str(marker)], scope="queued contender")
                outcomes.append("ran")
            except LeaseBusy as error:
                outcomes.append(str(error))
            return result
        self.manager._revoke = revoke_then_contend
        result = self.break_()
        self.assertEqual(result["status"], "broken")
        self.assertEqual(len(outcomes), 1)
        self.assertIn("TESTHANDHELD blocked: lease break in progress by tester", outcomes[0])
        self.assertFalse(marker.exists())
        self.assertEqual(child.wait(timeout=10), 0)
        self.assertEqual([event["event"] for event in self.events()], ["CLAIM", "RELEASE", "BREAK"])
        self.assertFalse(read_block(self.manager.states.directory, "TESTHANDHELD").get("pending"))

    def test_contender_queued_before_break_backs_out_whatever_wins_the_flock(self):
        lease_id, holder = self.start_hold()
        marker = self.root / "queued-ran"
        harness = ("import sys; from switchyard.agent_leases import AgentLeases; from switchyard.leases import LeaseBusy\n"
                   "m=AgentLeases(ledger_dir=sys.argv[1], state_dir=sys.argv[2], hosts=('test-handheld',))\n"
                   "try:\n    sys.exit(m.run('TESTHANDHELD', ['touch', sys.argv[3]], scope='queued contender', wait=30))\n"
                   "except LeaseBusy as error:\n    print(error, file=sys.stderr); sys.exit(75)\n")
        queued = subprocess.Popen([sys.executable, "-c", harness, str(self.ledgers), str(self.state), str(marker)],
                                  stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: queued.poll() is None and (queued.kill(), queued.communicate(timeout=5)))
        time.sleep(0.5)  # Queued: polling the busy ledger.
        self.assertIsNone(queued.poll())
        self.assertEqual(self.break_()["status"], "broken")
        _, stderr = queued.communicate(timeout=20)
        self.assertEqual(queued.returncode, 75, stderr)
        self.assertIn("TESTHANDHELD blocked", stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(holder.wait(timeout=10), 0)
        self.assertNotIn("completed", [event.get("reason") for event in self.events()])

    def test_still_held_restores_the_previous_block_state(self):
        self.manager._write_block("TESTHANDHELD", {"device": "TESTHANDHELD", "operator": "earlier", "reason": "older break"})
        self.raw_holder()
        self.assertEqual(self.break_(verify_seconds=0.3)["status"], "still-held")
        self.assertEqual(read_block(self.manager.states.directory, "TESTHANDHELD")["reason"], "older break")

    def test_block_appearing_after_the_first_check_still_refuses_before_any_command(self):
        state = self.manager._new("test-handheld", "racing request", None, None, "run")
        self.manager._write_block("TESTHANDHELD", {"device": "TESTHANDHELD", "operator": "tester", "reason": "race"})
        with self.assertRaisesRegex(LeaseBusy, "TESTHANDHELD blocked"):
            with self.manager._acquire(state, 0):
                self.fail("must not run")
        self.assertEqual([(event["event"], event.get("reason")) for event in self.events()],
                         [("CLAIM", None), ("RELEASE", "blocked")])

    # ---- foreign holders -----------------------------------------------------------------------------

    def test_foreign_holder_is_never_signalled_without_the_flag(self):
        pid = self.raw_holder()
        self.manager.kill = MagicMock()
        result = self.break_(verify_seconds=0.5)
        self.assertEqual(result["status"], "still-held")
        self.assertEqual([item["pid"] for item in result["holders"]], [pid])
        self.manager.kill.assert_not_called()
        self.assertTrue(running(pid))
        self.assertIn("lock NOT gone; no BREAK recorded", self.output.getvalue())
        self.assertEqual(self.events(), [])
        self.assertIsNone(read_block(self.manager.states.directory, "TESTHANDHELD"))

    def test_signal_holders_terminates_an_inherited_descriptor_holder_and_verifies(self):
        pid = self.raw_holder("inherit")
        # The kernel still names the exited locker; the descriptor scan finds the real holder.
        self.assertEqual(flock_holders(self.ledger), {pid})
        result = self.break_(signal_holders=True)
        self.assertEqual((result["status"], result["signalled"], result["killed"], result["blocked"]), ("broken", [pid], [], True))
        self.wait_for(lambda: not running(pid))
        brk = self.events()[-1]
        self.assertEqual((brk["event"], brk["signalled"], brk["holders"][0]["pid"]), ("BREAK", [pid], pid))
        with LedgerBroker({"TESTHANDHELD": self.ledger}).hold("TESTHANDHELD", owner="raw", scope="s", worktree="w"):
            pass  # The kernel lock is really gone: a raw caller can lock again...
        with self.assertRaisesRegex(LeaseBusy, "TESTHANDHELD blocked"):  # ...while Switchyard leases stay blocked.
            self.manager.run("test-handheld", ["true"], scope="blocked")

    def test_kill_only_with_the_flag_for_holders_ignoring_sigterm(self):
        pid = self.raw_holder("ignore")
        self.assertEqual(self.break_(signal_holders=True, signal_grace=0.5, verify_seconds=0.5)["status"], "still-held")
        self.assertTrue(running(pid))
        result = self.break_(signal_holders=True, kill=True, signal_grace=0.5)
        self.assertEqual((result["status"], result["killed"]), ("broken", [pid]))
        with self.assertRaisesRegex(ValueError, "--kill requires --signal-holders"):
            self.break_(kill=True)

    def test_agent_session_holder_is_never_signalled(self):
        pid = self.raw_holder("agent")
        self.manager.kill = MagicMock()
        result = self.break_(signal_holders=True, kill=True)
        self.assertEqual((result["status"], result["refused_holders"]), ("still-held", [pid]))
        self.manager.kill.assert_not_called()
        self.assertIn(f"held inside agent process omp:{pid}; ask that agent to exit the command or restart it", self.output.getvalue())
        self.assertIn("AGENT SESSION: never signalled", self.output.getvalue())
        self.assertEqual(self.events(), [])

    def test_free_device_is_not_applicable(self):
        self.assertEqual(self.break_()["status"], "not-applicable")
        self.assertEqual(self.events(), [])


class LedgerParsingTests(unittest.TestCase):
    def test_break_and_clear_are_ledger_events_without_false_anomalies(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "DEVICE_ACCESS_TESTHANDHELD.md"
            old = "2020-01-01T00:00:00+00:00"
            lines = [{"at": old, "event": "CLAIM", "owner": "gone", "scope": "crashed"},
                     {"at": old, "event": "BREAK", "owner": "operator tester", "scope": "stuck"}]
            ledger.write_text("".join(json.dumps(line) + "\n" for line in lines))
            row = locks.device_locks(directory)["ledgers"][0]
            self.assertEqual((row["state"], row["anomaly"]), ("free", None))
            self.assertEqual([entry["event"] for entry in row["last_entries"]], ["CLAIM", "BREAK"])
            # Held after a CLEAR with no new CLAIM: a raw holder took it without recording one.
            with ledger.open("a") as stream:
                stream.write(json.dumps({"at": old, "event": "CLEAR", "owner": "operator tester", "scope": "ok"}) + "\n")
            fd = os.open(ledger, os.O_RDONLY)
            try:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
                row = locks.device_locks(directory)["ledgers"][0]
            finally:
                os.close(fd)
            self.assertEqual((row["state"], row["anomaly"], row["last_entries"][-1]["event"]), ("held", "held-after-release", "CLEAR"))


class RemoteRefusalTests(unittest.TestCase):
    def test_remote_client_refuses_break_and_clear_without_contacting_the_control_host(self):
        loader = importlib.machinery.SourceFileLoader("switchyard_remote_break", str(ROOT / "tools/switchyard-remote"))
        client = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
        loader.exec_module(client)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "remote.json"
            config.write_text(json.dumps({"control": "u@control.invalid", "switchyard": "/x/switchyard",
                                          "mcp": "/x/mcp", "host_id": "host-b"}))
            with patch.dict(os.environ, {"SWITCHYARD_REMOTE_CONFIG": str(config)}), \
                    patch.object(client.subprocess, "run") as run, patch.object(client.subprocess, "Popen") as popen:
                for argv in (["lease", "break", "test-handheld", "--reason", "x"], ["lease", "clear", "test-handheld", "--attest-stopped", "x"]):
                    with self.subTest(argv=argv), redirect_stderr(io.StringIO()) as stderr:
                        self.assertEqual(client.main(argv), 2)
                        self.assertIn("operator's breakglass", stderr.getvalue())
                run.assert_not_called()
                popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
