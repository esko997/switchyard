"""Durable broker behavior using local fixture transport only, never a real host."""
import fcntl
import json
import os
from pathlib import Path
import platform
import pwd
import tempfile
import unittest
from unittest.mock import patch

from switchyard.broker import Broker
from switchyard.operation_store import encode
from operations_fixture import write_policy


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.config_path = self.root / "operations.json"
        self.site = self.root / "index.html"
        self.site.write_text("<h1>fixture</h1>")
        self.hosts = {}
        for name in ("alpha", "beta"):
            ledger = self.root / (name + ".ledger")
            ledger.write_text("fixture baseline\n")
            self.hosts[name] = {"host_id": name, "transport": "ssh", "target": pwd.getpwuid(os.getuid()).pw_name + "@fixture.invalid",
                                "expected_hostname": platform.node(), "ledger": str(ledger), "user_units": [], "system_units": []}
        self.config = {"schema_version": 1, "shell_hosts": ["alpha", "beta"], "workloads": {"foobar": {
            "name": "Foobar", "allowed_hosts": ["alpha", "beta"], "initial_host": "alpha",
            "container_name": "switchyard-foobar", "image": "docker.io/nginxinc/nginx-unprivileged:1.28.0-alpine",
            "site_file": str(self.site), "port": 18080}}}
        write_policy(self.config_path, self.config, self.state)
        # This fixture executable replaces SSH on PATH, runs stdin in an isolated
        # local interpreter, and can never contact a network device.
        binary = self.root / "bin"
        binary.mkdir()
        ssh = binary / "ssh"
        import sys
        ssh.write_text("#!" + sys.executable + "\nimport os,sys\nos.execv(sys.executable,[sys.executable,'-I','-S','-'])\n")
        ssh.chmod(0o700)
        self.path_patch = patch.dict(os.environ, {"PATH": str(binary) + os.pathsep + os.environ["PATH"]})
        self.path_patch.start()
        self.addCleanup(self.path_patch.stop)
        self.broker = Broker(self.config_path, hosts=self.hosts, state_dir=self.state)

    def test_shell_is_unrestricted_and_replay_is_durable_with_the_script_but_without_output(self):
        marker = self.root / "marker"
        # The output tokens are assembled at run time so they never appear in the script text itself.
        script = "printf 'entry\\n' >> '" + str(marker) + "'; printf 'private-%s-token' output; printf 'private-%s-token' error >&2"
        first = self.broker.shell("alpha", script, request_id="shell-1")
        self.assertEqual(first["receipt"]["status"], "succeeded")
        self.assertEqual(first["stdout"], "private-output-token")
        self.assertEqual(first["stderr"], "private-error-token")
        restarted = Broker(self.config_path, hosts=self.hosts, state_dir=self.state)
        second = restarted.shell("alpha", script, request_id="shell-1")
        self.assertTrue(second["replayed"])
        self.assertNotIn("stdout", second)
        self.assertEqual(second["receipt"]["id"], first["receipt"]["id"])
        self.assertEqual(marker.read_text(), "entry\n")
        # The audit entry records exactly what ran; what it printed is never stored.
        stored_receipt = restarted.receipt(first["receipt"]["id"])
        self.assertEqual((stored_receipt["script"], stored_receipt["timeout_seconds"]), (script, 30))
        stored = (self.state / "operations.sqlite3").read_bytes()
        for private in (b"private-output-token", b"private-error-token"):
            self.assertNotIn(private, stored)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.state / "operations.sqlite3").stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(ValueError, "different intent"):
            restarted.shell("alpha", "true", request_id="shell-1")

    def test_receipt_views_preview_in_lists_full_script_singly_and_redact_for_other_machines(self):
        from types import SimpleNamespace
        from switchyard.core import Service
        receipt = {"id": "r", "kind": "shell", "script": "\n  # a comment\nset -eu\necho secret-ish " + "x" * 300 + "\n"}
        local = SimpleNamespace(redact_commands=False)
        listed = Service._public_receipt(local, receipt, full=False)
        self.assertNotIn("script", listed)
        # The list preview is the first real command, bounded, and marked as truncated.
        self.assertEqual(listed["script_preview"], ("echo secret-ish " + "x" * 300)[:160] + "…")
        self.assertEqual(Service._public_receipt(local, receipt, full=True)["script"], receipt["script"])
        for full in (False, True):
            remote = Service._public_receipt(SimpleNamespace(redact_commands=True), receipt, full=full)
            self.assertEqual({key for key in remote if key.startswith("script")}, {"script_redacted"})
        other = {"id": "o", "kind": "lifecycle"}
        self.assertIs(Service._public_receipt(local, other, full=True), other)
        self.assertIn("script", receipt)  # The stored receipt is never mutated.

    @patch.dict(os.environ, {"SWITCHYARD_OPERATION_LEASE_WAIT": "0"})
    def test_all_leases_are_acquired_before_any_remote_execution(self):
        marker = self.root / "must-not-exist"
        with Path(self.hosts["beta"]["ledger"]).open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.broker.shell("alpha", "touch '" + str(marker) + "'", request_id="multi-host", extra_host_ids=["beta"])
        self.assertEqual(result["receipt"]["status"], "busy")
        self.assertFalse(marker.exists())
        self.assertEqual(result["receipt"]["host_ids"], ["alpha", "beta"])
        ledger = Path(self.hosts["alpha"]["ledger"]).read_text()
        self.assertIn('"event": "CLAIM"', ledger)
        self.assertIn('"event": "RELEASE"', ledger)

    def test_plan_requires_real_approval_and_binds_content_and_configuration(self):
        plan = self.broker.plan("deploy", "foobar")
        for approved in (False, 1, "true", None):
            with self.subTest(approved=approved), self.assertRaises(ValueError):
                self.broker.execute(plan["id"], approved=approved, request_id="no-approval")
        self.site.write_text("changed")
        with self.assertRaisesRegex(ValueError, "changed"):
            self.broker.execute(plan["id"], approved=True, request_id="changed-content")
        self.assertEqual(self.broker.receipts(), [])
        plan = self.broker.plan("deploy", "foobar")
        self.config["shell_hosts"] = ["alpha"]
        write_policy(self.config_path, self.config)
        with self.assertRaisesRegex(ValueError, "changed"):
            self.broker.execute(plan["id"], approved=True, request_id="changed-config")

    def test_plan_expiry_and_single_consumption(self):
        plan = self.broker.plan("deploy", "foobar")
        with self.broker.store.transaction() as db:
            plan["expires_at"] = "2000-01-01T00:00:00+00:00"
            db.execute("UPDATE plans SET data=? WHERE id=?", (encode(plan), plan["id"]))
        with self.assertRaisesRegex(ValueError, "expired"):
            self.broker.execute(plan["id"], approved=True, request_id="expired")
        plan = self.broker.plan("deploy", "foobar")
        def finish(receipt, payload):
            with self.broker.store.transaction() as db:
                value = self.broker.store.finish(db, receipt["id"], {"status": "failed", "error": "fixture preflight refusal"})
            return {"receipt": value}
        with patch.object(self.broker, "_dispatch", side_effect=finish) as dispatch:
            first = self.broker.execute(plan["id"], approved=True, request_id="once")
            replay = self.broker.execute(plan["id"], approved=True, request_id="once")
            self.assertTrue(replay["replayed"])
            self.assertEqual(first["receipt"]["id"], replay["receipt"]["id"])
            self.assertEqual(dispatch.call_count, 1)
            with self.assertRaisesRegex(ValueError, "already executed"):
                self.broker.execute(plan["id"], approved=True, request_id="another-key")

    def test_disabled_configuration_retains_history_and_unknown_placement(self):
        with self.broker.store.transaction() as db:
            self.broker.store.ownership(db, "foobar")
            begun = self.broker._begin(db, request_id="interrupted", intent={"action": "migrate"}, kind="managed", host_ids=["alpha", "beta"], workload_id="foobar")
            placement = {"workload_id": "foobar", "host_id": "alpha", "native_id": "fixture-id", "lifecycle": "running",
                         "recovery": {"source": {"host_id": "alpha"}, "target_id": "beta"}}
            self.broker.store.record_placement(db, "foobar", placement)
            db.execute("UPDATE operations SET pid=-1,birth='dead' WHERE id=?", (begun["receipt"]["id"],))
        disabled = Broker(None, hosts={}, state_dir=self.state)
        self.assertFalse(disabled.policy()["enabled"])
        self.assertEqual(disabled.receipts()[0]["status"], "needs-inspection")
        state = disabled.placements()["foobar"]
        self.assertTrue(state["uncertain"])
        self.assertEqual(state["lifecycle"], "unknown")
        self.assertEqual(state["recovery"]["target_id"], "beta")
        with self.assertRaises(ValueError):
            disabled.shell("alpha", "true", request_id="disabled")
        with self.assertRaises(ValueError):
            disabled.plan("deploy", "foobar")
        with self.assertRaises(ValueError):
            disabled.execute("anything", approved=True, request_id="disabled")

    def test_global_two_job_bound_returns_durable_busy_and_does_not_dispatch(self):
        with self.broker.store.transaction() as db:
            for key in ("running-1", "running-2"):
                self.broker._begin(db, request_id=key, intent={"key": key}, kind="shell", host_ids=["alpha"])
        with patch.object(self.broker, "_dispatch", side_effect=AssertionError("Must not spawn a third worker")):
            result = self.broker.shell("alpha", "true", request_id="third")
        self.assertEqual(result["receipt"]["status"], "busy")
        self.assertEqual(self.broker.receipt(result["receipt"]["id"])["status"], "busy")

    def test_same_key_across_processes_executes_exactly_once(self):
        import subprocess
        import sys
        marker = self.root / "cross-process"
        script = "sleep 0.2; printf x >> '" + str(marker) + "'"
        program = ("import json,sys; from pathlib import Path; from switchyard.broker import Broker; "
                   "b=Broker(sys.argv[1],hosts=json.loads(sys.argv[2]),state_dir=Path(sys.argv[3])); "
                   "print(json.dumps(b.shell('alpha',sys.argv[4],request_id='cross-process')))")
        args = [sys.executable, "-c", program, str(self.config_path), json.dumps(self.hosts), str(self.state), script]
        children = [subprocess.Popen(args, cwd=Path(__file__).resolve().parents[1],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        results = []
        try:
            for child in children:
                output, errors = child.communicate(timeout=10)
                self.assertEqual(child.returncode, 0, errors.decode())
                results.append(json.loads(output))
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait()
        self.assertEqual(results[0]["receipt"]["id"], results[1]["receipt"]["id"])
        self.assertEqual(sum(bool(result.get("replayed")) for result in results), 1)
        self.assertEqual(marker.read_text(), "x")

    def test_extra_hosts_and_timeout_are_strict(self):
        for extra in (["unknown"], ["alpha", "alpha"], "beta", [True]):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                self.broker.shell("alpha", "true", request_id="invalid", extra_host_ids=extra)
        for seconds in (True, 0, 241, 1.5):
            with self.subTest(seconds=seconds), self.assertRaises(ValueError):
                self.broker.shell("alpha", "true", request_id="invalid", timeout_seconds=seconds)
        for script in ("", "\0", "x" * 16385):
            with self.subTest(length=len(script)), self.assertRaises(ValueError):
                self.broker.shell("alpha", script, request_id="invalid")


if __name__ == "__main__":
    unittest.main()
