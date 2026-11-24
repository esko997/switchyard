"""Operator fencing and attested clearing against isolated durable authorities."""
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
import unittest
from unittest.mock import MagicMock, patch

from switchyard import cli
from switchyard.agent_leases import AgentLeases, BREAK_REFUSED, agent_ancestry
from switchyard.leases import LeaseBusy

OPERATOR = {"user": "tester", "agent": None}
ROOT = Path(__file__).resolve().parents[1]


class LeaseBreakTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.manager = AgentLeases(hosts=("test-handheld", "host-b"), state_dir=self.root / "state",
                                   ledger_dir=self.root / "metadata", runner=MagicMock())
        self.output = io.StringIO()

    def claim(self, mode="hold"):
        return self.manager._claim(self.manager._new("test-handheld", "fixture operation", "Fixture", None, mode, 600))

    def break_(self, **kwargs):
        kwargs.setdefault("identity", OPERATOR)
        kwargs.setdefault("confirm", lambda label: label == "TESTHANDHELD")
        return self.manager.break_lease("test-handheld", reason="stuck fixture", output=self.output, **kwargs)

    def clear(self, **kwargs):
        kwargs.setdefault("identity", OPERATOR)
        kwargs.setdefault("confirm", lambda label: label == "TESTHANDHELD")
        return self.manager.clear_block("test-handheld", attest_stopped="confirmed fixture idle",
                                        output=self.output, **kwargs)

    def test_operator_and_exact_confirmation_gate(self):
        self.claim()
        with self.assertRaisesRegex(ValueError, BREAK_REFUSED):
            self.break_(identity={"user": "tester", "agent": "ancestor omp:1"})
        self.assertIsNotNone(agent_ancestry(environment={"PASEO_AGENT_ID": "fixture"}))
        with self.assertRaisesRegex(ValueError, "Not confirmed"):
            self.break_(confirm=lambda label: False)
        self.assertIsNone(self.manager.states.block("TESTHANDHELD"))
        for argv, message in (([], "needs a terminal"), (["--yes-device", "WRONG"], "Not confirmed")):
            with patch("switchyard.agent_leases.agent_ancestry", return_value=None), \
                    patch.object(cli, "Service") as service, patch.object(sys, "stdin", io.StringIO()), \
                    patch.object(sys, "argv", ["switchyard", "--catalog", "fixture", "lease", "break", "test-handheld",
                                               "--reason", "fixture", *argv]), \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as stderr:
                service.return_value.agent_leases.return_value = self.manager
                with self.assertRaises(SystemExit) as error:
                    cli.main()
                self.assertEqual(error.exception.code, 2)
                self.assertIn(message, stderr.getvalue())

    def test_break_without_attestation_durably_blocks_even_after_old_completion(self):
        state = self.claim()
        result = self.break_()
        self.assertEqual((result["device"], result["status"], result["blocked"]), ("TESTHANDHELD", "broken", True))
        self.assertEqual(result["revoked"][0]["lease_id"], state["lease_id"])
        self.assertEqual(result["signalled"], [])
        self.assertEqual(result["killed"], [])
        self.assertEqual(result["break"]["event"], "BREAK")
        self.assertEqual(result["break"]["operator"], "tester")
        self.assertFalse(self.manager.states.finish(state["lease_id"], reason="late completion"))
        restarted = AgentLeases(hosts=("test-handheld",), state_dir=self.manager.root, ledger_dir=self.manager.ledger_dir)
        self.assertTrue(restarted.status("test-handheld")["blocked"])
        for dispatch in (lambda: restarted.run("test-handheld", ["never-run"], scope="blocked"),
                         lambda: restarted.hold("test-handheld", scope="blocked", detached=True),
                         lambda: restarted.attach("test-handheld", scope="blocked", output=io.StringIO())):
            with self.assertRaisesRegex(LeaseBusy, "blocked"):
                dispatch()
        self.assertFalse(self.manager.ledger_dir.exists())
        self.assertEqual(list(self.manager.states.directory.glob("blocked-*.json")), [])

    def test_attested_break_fences_old_generation_without_block(self):
        old = self.claim("attach")
        self.manager.states.suspect(old["lease_id"], "disconnected")
        result = self.break_(attest_stopped="remote group inspected and stopped")
        self.assertEqual((result["status"], result["blocked"]), ("broken", False))
        self.assertTrue(result["break"]["attested_stopped"])
        current = self.claim()
        self.assertFalse(self.manager.states.finish(old["lease_id"], reason="stale done"))
        self.assertEqual(self.manager.states.current("TESTHANDHELD")["lease_id"], current["lease_id"])
        with self.assertRaisesRegex(ValueError, "no longer active"):
            self.manager.release(old["lease_id"])

    def test_clear_requires_operator_attestation_and_exact_current_block(self):
        self.claim()
        self.break_()
        with self.assertRaisesRegex(ValueError, BREAK_REFUSED):
            self.clear(identity={"user": "tester", "agent": "agent caller"})
        with self.assertRaisesRegex(ValueError, "Not confirmed"):
            self.clear(confirm=lambda label: False)
        self.assertIsNotNone(self.manager.states.block("TESTHANDHELD"))
        result = self.clear()
        self.assertEqual((result["status"], result["clear"]["event"]), ("cleared", "CLEAR"))
        self.assertEqual(result["clear"]["attestation"], "confirmed fixture idle")
        self.assertIsNone(self.manager.states.block("TESTHANDHELD"))
        self.assertEqual(self.manager.run("test-handheld", ["true"], scope="after attestation"), 0)
        self.assertEqual(self.clear()["status"], "not-applicable")

    def test_clear_direct_suspect_attach_fences_without_separate_break(self):
        state = self.claim("attach")
        self.manager.states.suspect(state["lease_id"], "disconnected")
        with self.assertRaisesRegex(ValueError, "Not confirmed"):
            self.clear(confirm=lambda label: False)
        result = self.clear()
        self.assertEqual((result["device"], result["status"]), ("TESTHANDHELD", "cleared"))
        self.assertEqual(result["clear"]["attestation"], "confirmed fixture idle")
        replacement = self.claim()
        self.assertFalse(self.manager.states.finish(state["lease_id"], reason="stale done"))
        self.assertEqual(self.manager.states.current("TESTHANDHELD")["lease_id"], replacement["lease_id"])

    def test_clear_direct_suspect_is_generation_scoped_and_preserves_racing_block(self):
        state = self.claim("attach")
        self.manager.states.suspect(state["lease_id"], "disconnected")
        def confirm(label):
            self.manager.states.break_device(label, operator="tester", reason="concurrent block")
            return True
        with self.assertRaises(LeaseBusy):
            self.clear(confirm=confirm)
        self.assertEqual(self.manager.states.block("TESTHANDHELD")["reason"], "concurrent block")

    def test_clear_does_not_silently_fence_an_active_lease(self):
        state = self.claim()
        with self.assertRaisesRegex(ValueError, "still active"):
            self.clear()
        self.assertEqual(self.manager.states.current("TESTHANDHELD")["lease_id"], state["lease_id"])

    def test_break_confirmation_race_cannot_fence_a_new_generation(self):
        old = self.claim()
        created = []
        def confirm(label):
            self.manager.release(old["lease_id"])
            created.append(self.claim())
            return True
        with self.assertRaisesRegex(LeaseBusy, "changed"):
            self.break_(confirm=confirm)
        self.assertEqual(self.manager.states.current("TESTHANDHELD")["lease_id"], created[0]["lease_id"])
        self.assertIsNone(self.manager.states.block("TESTHANDHELD"))

    def test_clear_confirmation_race_cannot_clear_replaced_block(self):
        self.claim()
        self.break_()
        def confirm(label):
            self.manager.states.break_device(label, operator="tester", reason="new evidence")
            return True
        with self.assertRaisesRegex(LeaseBusy, "block changed"):
            self.clear(confirm=confirm)
        self.assertEqual(self.manager.states.block("TESTHANDHELD")["reason"], "new evidence")

    def test_dead_holder_and_restart_do_not_implicitly_attest_stop(self):
        state = self.claim()
        self.manager.states.update(state["lease_id"], lambda value: value.update(pid=999999999, pid_started=1))
        self.assertEqual(self.manager.states.current("TESTHANDHELD")["status"], "suspect")
        result = self.break_()
        self.assertTrue(result["blocked"])
        self.assertFalse(result["revoked"][0]["ended"])
        self.assertEqual(self.break_()["status"], "not-applicable")
        self.assertIsNotNone(self.manager.states.block("TESTHANDHELD"))

    def test_deprecated_signalling_flags_refuse_without_touching_any_process(self):
        state = self.claim()
        for flags in ({"signal_holders": True}, {"kill": True}, {"signal_holders": True, "kill": True}):
            with self.subTest(flags=flags), self.assertRaisesRegex(ValueError, "unsupported by durable leases"):
                self.break_(**flags)
        self.manager.runner.assert_not_called()
        self.assertEqual(self.manager.states.current("TESTHANDHELD")["lease_id"], state["lease_id"])
        self.assertIsNone(self.manager.states.block("TESTHANDHELD"))


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
