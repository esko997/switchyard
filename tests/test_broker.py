"""Durable broker behavior using local fixture transport only, never a real host."""
import json
import os
from pathlib import Path
import platform
import pwd
import tempfile
import unittest
from unittest.mock import patch

from switchyard.broker import Broker
from switchyard.lease_db import LeaseStore
from switchyard.leases import LedgerBroker
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
            ledger = self.root / ("DEVICE_ACCESS_" + name.upper() + ".md")
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
        self.leases = LeaseStore(self.state / "leases")

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

    def test_confirmed_shell_failure_releases_the_device(self):
        result = self.broker.shell("alpha", "exit 7", request_id="confirmed-failure")
        self.assertEqual(result["receipt"]["status"], "failed")
        self.assertEqual(result["receipt"]["exit_code"], 7)
        self.assertIsNone(self.leases.current("ALPHA"))
        self.assertEqual([event["event"] for event in reversed(self.leases.history())], ["CLAIM", "RELEASE"])
        self.assertFalse(Path(self.hosts["alpha"]["ledger"]).exists())

    @patch.dict(os.environ, {"SWITCHYARD_OPERATION_LEASE_WAIT": "0"})
    def test_transport_loss_retains_suspect_until_operator_clear(self):
        marker = self.root / "transport-marker"
        script = "touch '" + str(marker) + "'"
        ssh = self.root / "bin/ssh"
        transport = ssh.read_text()
        ssh.write_text(transport.split("\n", 1)[0] + "\nimport sys\nsys.exit(255)\n")
        first = self.broker.shell("alpha", script, request_id="lost-transport")
        self.assertEqual(first["receipt"]["status"], "needs-inspection")
        held = self.leases.current("ALPHA")
        self.assertEqual(held["status"], "suspect")
        self.assertTrue(held["suspect_cause"])
        self.assertFalse(any(event["event"] == "RELEASE" for event in self.leases.history()))
        ssh.write_text(transport)
        restarted = Broker(self.config_path, hosts=self.hosts, state_dir=self.state)
        replay = restarted.shell("alpha", script, request_id="lost-transport")
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["receipt"]["id"], first["receipt"]["id"])
        blocked = restarted.shell("alpha", script, request_id="still-suspect")
        self.assertEqual(blocked["receipt"]["status"], "busy")
        self.assertEqual(self.leases.current("ALPHA")["lease_id"], held["lease_id"])
        self.assertFalse(marker.exists())
        self.leases.break_device("ALPHA", reason="fixture transport inspected", operator="tester",
                                 expected_id=held["lease_id"])
        self.leases.clear("ALPHA", operator="tester", attest_stopped="fixture has no remote process",
                          expected_block=self.leases.block("ALPHA"))
        recovered = restarted.shell("alpha", script, request_id="after-operator-clear")
        self.assertEqual(recovered["receipt"]["status"], "succeeded")
        self.assertTrue(marker.exists())
        self.assertIsNone(self.leases.current("ALPHA"))

    @patch.dict(os.environ, {"SWITCHYARD_OPERATION_LEASE_WAIT": "0"})
    def test_shell_timeout_retains_suspect_and_blocks_the_next_request(self):
        first = self.broker.shell("alpha", "sleep 30", timeout_seconds=1, request_id="shell-timeout")
        self.assertEqual(first["receipt"]["status"], "needs-inspection")
        held = self.leases.current("ALPHA")
        self.assertEqual(held["status"], "suspect")
        second = self.broker.shell("alpha", "true", request_id="after-timeout")
        self.assertEqual(second["receipt"]["status"], "busy")
        self.assertEqual(self.leases.current("ALPHA")["lease_id"], held["lease_id"])

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
        with LedgerBroker({"beta": Path(self.hosts["beta"]["ledger"])}, state_dir=self.state).hold(
                "beta", owner="other-agent", scope="fixture contention", worktree=str(self.root)):
            result = self.broker.shell("alpha", "touch '" + str(marker) + "'", request_id="multi-host", extra_host_ids=["beta"])
            self.assertEqual(self.leases.current("BETA")["owner"], "other-agent")
            self.assertIsNone(self.leases.current("ALPHA"))
        self.assertEqual(result["receipt"]["status"], "busy")
        self.assertFalse(marker.exists())
        self.assertEqual(result["receipt"]["host_ids"], ["alpha", "beta"])
        alpha_events = [event["event"] for event in reversed(self.leases.history()) if event["device"] == "ALPHA"]
        self.assertEqual(alpha_events, ["CLAIM", "RELEASE"])
        self.assertIsNone(self.leases.current("BETA"))

    @patch.dict(os.environ, {"SWITCHYARD_OPERATION_LEASE_WAIT": "0"})
    def test_device_alias_cannot_bypass_an_existing_lease(self):
        hosts = {**self.hosts, "alias": {**self.hosts["alpha"], "host_id": "alias"}}
        self.config["shell_hosts"].append("alias")
        write_policy(self.config_path, self.config)
        broker = Broker(self.config_path, hosts=hosts, state_dir=self.state)
        marker = self.root / "alias-marker"
        with LedgerBroker({"alpha": Path(self.hosts["alpha"]["ledger"])}, state_dir=self.state).hold(
                "alpha", owner="other-agent", scope="same physical device", worktree=str(self.root)):
            result = broker.shell("alias", "touch '" + str(marker) + "'", request_id="alias-contention")
            self.assertEqual(result["receipt"]["status"], "busy")
            self.assertEqual(self.leases.current("ALPHA")["owner"], "other-agent")
        self.assertFalse(marker.exists())

    @patch.dict(os.environ, {"SWITCHYARD_OPERATION_LEASE_WAIT": "0"})
    def test_service_operations_use_common_lease_root_not_the_operation_journal_directory(self):
        from switchyard.core import Service
        catalog = self.root / "catalog.json"
        catalog.write_text(json.dumps({
            "schema_version": 1, "provenance": "offline fixture", "workloads": [], "groups": [],
            "devices": [{"id": name, "name": name, "platform": "linux", "architecture": "x86_64",
                         "capabilities": [], "access": "declared-only", "observed_at": None,
                         "provenance": "offline fixture", "notes": "No network transport"}
                        for name in self.hosts]}))
        collectors = self.root / "collectors.json"
        collectors.write_text(json.dumps({"schema_version": 1, "hosts": list(self.hosts.values())}))
        policy = self.root / "service-operations.json"
        write_policy(policy, {"shell_hosts": ["alpha"], "workloads": {}})
        service = Service(catalog, state_dir=self.state, collectors_path=collectors, operations_path=policy)
        self.leases.break_device("ALPHA", reason="fixture operator block", operator="tester")
        marker = self.root / "service-marker"
        blocked = service.run_shell("alpha", "touch '" + str(marker) + "'", request_id="service-blocked")
        self.assertEqual(blocked["receipt"]["status"], "busy")
        self.assertFalse(marker.exists())
        self.leases.clear("ALPHA", operator="tester", attest_stopped="fixture is stopped",
                          expected_block=self.leases.block("ALPHA"))
        succeeded = service.run_shell("alpha", "touch '" + str(marker) + "'", request_id="service-cleared")
        self.assertEqual(succeeded["receipt"]["status"], "succeeded")
        self.assertTrue(marker.exists())
        events = [event["event"] for event in reversed(self.leases.history())]
        self.assertEqual(events, ["BREAK", "CLEAR", "CLAIM", "RELEASE"])
        self.assertEqual(len(list((self.state / "operations").rglob("operations.sqlite3"))), 1)
        self.assertEqual(list((self.state / "operations").rglob("leases.sqlite3")), [])

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
        self.assertEqual(self.leases.history(), [])

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
