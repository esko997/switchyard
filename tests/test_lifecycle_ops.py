"""Scoped lifecycle authority and durable evidence, using only fixture transports."""
from contextlib import closing, redirect_stdout
from datetime import datetime, timedelta, timezone
import copy
import fcntl
import io
import json
import os
from pathlib import Path
import platform
import pwd
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from switchyard.broker import Broker
from switchyard import lifecycle_ops, operation_worker
from switchyard.operation_store import encode
from switchyard.remote import RemoteError
from operations_fixture import write_policy


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ledger = self.root / "alpha.ledger"
        self.ledger.write_text("fixture baseline\n")
        self.hosts = {"alpha": {"host_id": "alpha", "transport": "ssh",
            "target": pwd.getpwuid(os.getuid()).pw_name + "@fixture.invalid",
            "expected_hostname": platform.node(), "ledger": str(self.ledger),
            "user_units": [], "system_units": []}}
        self.config = {"schema_version": 1, "shell_hosts": [], "workloads": {
            "service": {"backend": "systemd", "name": "Example", "host_id": "alpha", "scope": "user", "unit": "example.service"},
            "quad": {"backend": "quadlet", "name": "Quadlet", "host_id": "alpha", "scope": "system", "unit": "quad.service"},
            "project": {"backend": "compose", "name": "Project", "host_id": "alpha", "provider": "docker-compose-v2",
                        "project_name": "example", "project_directory": "/srv/example", "files": ["/srv/example/compose.yaml"], "services": ["web", "db"]}}}
        self.config_path = self.root / "operations.json"
        self.write_config()
        self.broker = Broker(self.config_path, hosts=self.hosts, state_dir=self.root / "state")
        self.current = {"backend": "systemd", "identity": {"unit": "example.service", "fragment_sha256": "a" * 64},
                        "state": {"active": "inactive", "invocation_id": ""}, "warnings": ["Native state is not health"],
                        "supported_actions": ["start", "stop", "restart"]}
        self.calls = []
        self.locals = []
        self.remote = patch.object(lifecycle_ops, "run_remote", side_effect=self.fake_remote).start()
        self.addCleanup(patch.stopall)
        patch.object(self.broker, "_dispatch", side_effect=self.dispatch).start()

    def write_config(self):
        # Grants go to the policy file; descriptions (unit, scope, project, ...) to the workload store records.
        write_policy(self.config_path, self.config, self.root / "state")

    def fake_remote(self, host, source, request, *, timeout, local=False):
        self.locals.append(local)
        # The fixture action must hold the canonical inode, but never a SQLite lock.
        with self.ledger.open("a") as ledger:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(ledger, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with closing(sqlite3.connect(self.broker.store.path, timeout=0)) as db:
            db.execute("BEGIN IMMEDIATE")
            db.rollback()
        self.assertEqual(host["host_id"], "alpha")
        self.assertEqual(timeout, 240)
        self.assertEqual(set(request), {"action", "config", "expected"})
        self.calls.append(copy.deepcopy(request))
        inspection = copy.deepcopy(self.current)
        inspection["backend"] = request["config"]["backend"]
        if request["action"] != "inspect":
            if request["expected"] != inspection:
                return {"status": "failed", "inspection": inspection, "error": "Native preconditions changed"}
            inspection["state"]["active"] = "inactive" if request["action"] == "stop" else "active"
            self.current = copy.deepcopy(inspection)
        return {"status": "succeeded", "inspection": inspection}

    def dispatch(self, receipt, payload):
        payload = {**payload, "operation_id": receipt["id"], "state_dir": str(self.broker.store.directory),
                   "hosts": {key: self.hosts[key] for key in receipt["host_ids"]}}
        output = io.StringIO()
        with patch.object(operation_worker.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(encode(payload).encode()))), \
                patch.object(operation_worker.signal, "signal"), redirect_stdout(output):
            operation_worker.main()
        self.assertEqual(json.loads(output.getvalue())["operation_id"], receipt["id"])
        return {"receipt": self.broker.receipt(receipt["id"])}

    def inspect(self, request_id="inspect-1", workload_id="service"):
        receipt = self.broker.inspect_workload(workload_id, request_id=request_id)["receipt"]
        self.assertEqual(receipt["status"], "succeeded", receipt)
        return receipt

    def age_cache(self):
        old = (datetime.now(timezone.utc) - timedelta(seconds=121)).isoformat()
        with self.broker.store.transaction() as db:
            db.execute("UPDATE lifecycle_inspections SET inspected_at=?", (old,))

    def test_local_collector_target_runs_lifecycle_locally_under_its_ledger(self):
        ssh = self.hosts["alpha"]
        self.broker.hosts["alpha"] = {"host_id": "alpha", "transport": "local", "expected_hostname": ssh["expected_hostname"],
                                      "user_units": [], "system_units": []}
        self.config["local_targets"] = {"alpha": {"target": ssh["target"], "ledger": ssh["ledger"]}}
        self.write_config()
        self.inspect()
        proposal = self.broker.plan("start", "service")
        receipt = self.broker.execute(proposal["id"], approved=True, request_id="local-start")["receipt"]
        self.assertEqual(receipt["status"], "succeeded", receipt)
        # fake_remote also asserts the canonical ledger was held throughout.
        self.assertEqual(self.locals, [True, True])
        del self.config["local_targets"]
        self.write_config()
        with self.assertRaisesRegex(ValueError, "SSH host"):
            self.broker.policy()

    def test_local_target_revoked_or_changed_after_dispatch_refuses_execution(self):
        ssh = self.hosts["alpha"]
        self.broker.hosts["alpha"] = {"host_id": "alpha", "transport": "local", "expected_hostname": ssh["expected_hostname"],
                                      "user_units": [], "system_units": []}
        other_ledger = self.root / "other.ledger"
        other_ledger.write_text("other baseline\n")
        for mode in ("revoked", "account", "ledger"):
            with self.subTest(mode=mode):
                self.config["local_targets"] = {"alpha": {"target": ssh["target"], "ledger": ssh["ledger"]}}
                self.write_config()
                self.inspect("inspect-local-" + mode)
                proposal = self.broker.plan("start", "service")
                original_dispatch = self.dispatch

                def delayed(receipt, payload):
                    # The worker still carries the dispatched host snapshot; only the live file changes.
                    if mode == "revoked":
                        del self.config["local_targets"]
                    elif mode == "account":
                        self.config["local_targets"]["alpha"]["target"] = "someone-else@fixture.invalid"
                    else:
                        self.config["local_targets"]["alpha"]["ledger"] = str(other_ledger)
                    self.write_config()
                    return original_dispatch(receipt, payload)

                before = len(self.calls)
                with patch.object(self.broker, "_dispatch", side_effect=delayed):
                    receipt = self.broker.execute(proposal["id"], approved=True, request_id="local-" + mode)["receipt"]
                self.assertEqual(receipt["status"], "failed", receipt)
                self.assertEqual(len(self.calls), before)

    def test_exact_config_and_normalized_policy_for_all_backends(self):
        entries = {entry["id"]: entry for entry in self.broker.policy()["workloads"]}
        for entry in entries.values():
            self.assertEqual(entry["allowed_hosts"], ["alpha"])
            self.assertEqual(entry["actions"], ["start", "stop", "restart"])
            self.assertTrue(entry["inspection_required"])
        self.assertEqual(entries["service"]["unit"], "example.service")
        self.assertEqual(entries["quad"]["scope"], "system")
        self.assertEqual(entries["project"]["services"], ["web", "db"])
        self.assertEqual(entries["project"]["provider"], "docker-compose-v2")
        original = self.config["workloads"]["service"]
        for changes in ({"backend": "podman"}, {"backend": []}, {"scope": []}, {"unit": "x@instance.service"},
                        {"unit": "*.service"}, {"unit": "x.timer"}, {"unit": "--bad.service"},
                        {"host_id": "missing"}, {"host_id": []}, {"command": "systemctl"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                lifecycle_ops.validate_workload("service", {**original, **changes}, self.hosts)
        compose = self.config["workloads"]["project"]
        for changes in ({"provider": []}, {"provider": "compose"}, {"files": []}, {"files": ["relative"]},
                        {"files": ["/a", "/a"]}, {"project_directory": "/a/../b"},
                        {"services": []}, {"services": ["web", "web"]}, {"services": ["--all"]},
                        {"project_name": "UPPER"}, {"extra": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                lifecycle_ops.validate_workload("project", {**compose, **changes}, self.hosts)
        with self.assertRaises(ValueError):
            lifecycle_ops.validate_workload("foobar", original, self.hosts)
        self.assertEqual(self.calls, [])

    def test_inspection_is_leased_durable_bounded_and_cache_only_reads(self):
        self.assertEqual(self.broker.lifecycle_inspections(), {})
        receipt = self.inspect()
        self.assertEqual(receipt["kind"], "lifecycle")
        self.assertEqual(receipt["action"], "inspect")
        self.assertEqual(receipt["inspection"], self.current)
        cached = self.broker.lifecycle_inspections()["service"]
        self.assertEqual(set(cached), {"backend", "host_id", "authority_fingerprint", "inspection_fingerprint", "inspected_at", "fresh", "inspection"})
        self.assertTrue(cached["fresh"])
        self.assertEqual(cached["inspection_fingerprint"], receipt["inspection_fingerprint"])
        restarted = Broker(self.config_path, hosts=self.hosts, state_dir=self.root / "state")
        self.assertEqual(restarted.lifecycle_inspections(), {"service": cached})
        observer = Broker(None, hosts=self.hosts, state_dir=self.root / "state")
        self.assertEqual(observer.lifecycle_inspections(), {})
        self.assertEqual(self.broker.lifecycle_inspections(), {"service": cached})
        replay = self.broker.inspect_workload("service", request_id="inspect-1")
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["receipt"], receipt)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.broker.placements(), {})
        self.assertIn('"event": "RELEASE"', self.ledger.read_text())

    def test_plan_requires_fresh_evidence_and_never_contacts_remote(self):
        with self.assertRaisesRegex(ValueError, "inspection required"):
            self.broker.plan("start", "service")
        self.inspect()
        proposal = self.broker.plan("restart", "service")
        self.assertEqual(proposal["backend"], "systemd")
        self.assertEqual(proposal["kind"], "lifecycle")
        self.assertEqual(proposal["source_id"], proposal["target_id"])
        self.assertEqual(proposal["inspection"], self.current)
        self.assertEqual(len(self.calls), 1)
        for action in ("deploy", "migrate", "recover", "up"):
            with self.assertRaises(ValueError):
                self.broker.plan(action, "service")
        with self.assertRaises(ValueError):
            self.broker.plan("start", "service", "other")
        self.age_cache()
        self.assertFalse(self.broker.lifecycle_inspections()["service"]["fresh"])
        with self.assertRaises(ValueError):
            self.broker.plan("start", "service")
        with self.assertRaises(ValueError):
            self.broker.execute(proposal["id"], approved=True, request_id="expired-evidence")
        self.assertEqual(len(self.calls), 1)

    def test_execution_approval_revision_binding_postcondition_and_replay(self):
        self.inspect()
        proposal = self.broker.plan("start", "service")
        for approval in (False, 1, "true", None):
            with self.assertRaises(ValueError):
                self.broker.execute(proposal["id"], approved=approval, request_id="start")
        with self.assertRaises(ValueError):
            self.broker.execute(proposal["id"], approved=True, request_id="bad request")
        receipt = self.broker.execute(proposal["id"], approved=True, request_id="start")["receipt"]
        self.assertEqual(receipt["status"], "succeeded", receipt)
        self.assertEqual(receipt["inspection"]["state"]["active"], "active")
        self.assertNotEqual(receipt["inspection_fingerprint"], proposal["inspection_fingerprint"])
        self.assertEqual(self.calls[-1]["expected"], proposal["inspection"])
        self.assertEqual(self.broker.lifecycle_inspections()["service"]["inspection"], receipt["inspection"])
        with self.assertRaises(ValueError):
            self.broker.execute(proposal["id"], approved=True, request_id="another")
        self.age_cache()
        replay = self.broker.execute(proposal["id"], approved=True, request_id="start")
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["receipt"], receipt)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.broker.placements(), {})

    def test_repeat_inspection_invalidates_even_identical_observation_plan(self):
        self.inspect()
        proposal = self.broker.plan("stop", "service")
        self.inspect("inspect-2")
        with self.assertRaisesRegex(ValueError, "inspection changed"):
            self.broker.execute(proposal["id"], approved=True, request_id="old-plan")
        self.assertEqual(len(self.calls), 2)

    def test_authority_changes_invalidate_cache_and_plans(self):
        self.inspect()
        proposal = self.broker.plan("start", "service")
        self.config["workloads"]["service"]["unit"] = "different.service"
        self.write_config()
        with self.assertRaisesRegex(ValueError, "authority changed"):
            self.broker.execute(proposal["id"], approved=True, request_id="old-authority")
        self.assertEqual(self.broker.lifecycle_inspections(), {})
        self.assertEqual(len(self.calls), 1)

    def test_changed_evidence_or_authority_while_waiting_for_lease_refuses_dispatch(self):
        for mode in ("age", "revision", "authority"):
            with self.subTest(mode=mode):
                self.inspect("inspect-" + mode)
                proposal = self.broker.plan("start", "service")
                original_dispatch = self.dispatch

                def delayed(receipt, payload):
                    if mode == "age":
                        self.age_cache()
                    elif mode == "revision":
                        with self.broker.store.transaction() as db:
                            db.execute("UPDATE lifecycle_inspections SET revision='new-revision'")
                    else:
                        self.config["workloads"]["service"]["unit"] = "changed.service"
                        self.write_config()
                    return original_dispatch(receipt, payload)

                before = len(self.calls)
                with patch.object(self.broker, "_dispatch", side_effect=delayed):
                    receipt = self.broker.execute(proposal["id"], approved=True, request_id="delayed-" + mode)["receipt"]
                self.assertEqual(receipt["status"], "failed", receipt)
                self.assertEqual(len(self.calls), before)

    def test_native_preconditions_changed_refuses_mutation_and_invalidates_evidence(self):
        self.inspect()
        proposal = self.broker.plan("start", "service")
        self.current["identity"]["fragment_sha256"] = "b" * 64
        receipt = self.broker.execute(proposal["id"], approved=True, request_id="native-changed")["receipt"]
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(self.current["state"]["active"], "inactive")
        self.assertEqual(self.broker.lifecycle_inspections(), {})

    def test_transport_uncertainty_has_no_retry_and_invalidates_cache(self):
        self.inspect()
        proposal = self.broker.plan("restart", "service")
        with patch.object(lifecycle_ops, "run_remote", side_effect=RemoteError("private transport detail")) as remote:
            receipt = self.broker.execute(proposal["id"], approved=True, request_id="uncertain")["receipt"]
            self.assertEqual(remote.call_count, 1)
        self.assertEqual(receipt["status"], "needs-inspection")
        self.assertNotIn("private transport detail", encode(receipt))
        self.assertEqual(self.broker.lifecycle_inspections(), {})

    def test_unsupported_inspection_is_visible_but_not_plannable(self):
        self.current["supported_actions"] = []
        self.current["warnings"] = ["Unsupported activation dependency"]
        self.inspect()
        self.assertEqual(self.broker.lifecycle_inspections()["service"]["inspection"]["supported_actions"], [])
        with self.assertRaisesRegex(ValueError, "unsupported"):
            self.broker.plan("restart", "service")
        self.assertEqual(len(self.calls), 1)

    def test_cross_kind_plans_never_dispatch(self):
        self.inspect()
        proposal = self.broker.plan("start", "service")
        for kind in (None, "fleet-keys", "managed"):
            changed = {**proposal}
            if kind is None:
                changed.pop("kind")
            else:
                changed["kind"] = kind
            with self.broker.store.transaction() as db:
                db.execute("UPDATE plans SET data=? WHERE id=?", (encode(changed), proposal["id"]))
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.broker.execute(proposal["id"], approved=True, request_id="wrong-kind")
        self.assertEqual(len(self.calls), 1)

    @patch.dict(os.environ, {"SWITCHYARD_OPERATION_LEASE_WAIT": "0"})
    def test_lease_busy_does_not_inspect_or_mutate(self):
        with self.ledger.open("a") as ledger:
            fcntl.flock(ledger, fcntl.LOCK_EX)
            receipt = self.broker.inspect_workload("service", request_id="busy")["receipt"]
        self.assertEqual(receipt["status"], "busy")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.broker.lifecycle_inspections(), {})

    def test_receipts_reject_unbounded_or_secret_bearing_adapter_evidence(self):
        for invalid in ({"env": {"TOKEN": "private-value"}}, {"huge": "x" * 4097}, {"number": float("nan")}):
            with self.subTest(invalid=list(invalid)):
                inspection = {**self.current, "identity": invalid}
                with patch.object(lifecycle_ops, "run_remote", return_value={"status": "succeeded", "inspection": inspection}):
                    receipt = self.broker.inspect_workload("service", request_id="invalid-" + next(iter(invalid)))["receipt"]
                self.assertEqual(receipt["status"], "needs-inspection")
                self.assertNotIn("inspection", receipt)
                self.assertNotIn("private-value", encode(receipt))
        self.assertEqual(self.broker.lifecycle_inspections(), {})

    def test_compose_and_quadlet_dispatch_fixed_modules_without_migration(self):
        for workload_id in ("quad", "project"):
            receipt = self.inspect("inspect-" + workload_id, workload_id)
            proposal = self.broker.plan("stop", workload_id)
            self.assertEqual(proposal["backend"], receipt["inspection"]["backend"])
            self.assertEqual(self.calls[-1]["config"], self.config["workloads"][workload_id])
            self.assertEqual(proposal["source_id"], "alpha")
            with self.assertRaises(ValueError):
                self.broker.plan("migrate", workload_id)

    def test_foobar_recipe_remains_available_alongside_scoped_workloads(self):
        site = self.root / "index.html"
        site.write_text("<h1>fixture</h1>")
        self.config["workloads"]["foobar"] = {
            "name": "Foobar", "allowed_hosts": ["alpha"], "initial_host": "alpha",
            "container_name": "switchyard-foobar", "image": "docker.io/nginxinc/nginx-unprivileged:1.28.0-alpine",
            "site_file": str(site), "port": 18080}
        self.write_config()
        policy = {entry["id"]: entry for entry in self.broker.policy()["workloads"]}
        self.assertEqual(policy["foobar"]["backend"], "podman")
        self.assertEqual(policy["foobar"]["actions"], ["deploy", "start", "stop", "migrate", "recover"])
        proposal = self.broker.plan("deploy", "foobar")
        self.assertEqual(proposal["target_id"], "alpha")
        self.assertNotIn("kind", proposal)
        with self.assertRaises(ValueError):
            self.broker.inspect_workload("foobar", request_id="not-scoped")
        self.assertEqual(self.calls, [])

    def test_optional_sanitized_native_resources_and_state_summary_survive(self):
        self.current.update(lifecycle="stopped", health="unknown", resources=[
            {"backend": "systemd", "scope": "user:1000", "native_id": "example.service", "name": "example.service"}])
        self.inspect()
        cached = self.broker.lifecycle_inspections()["service"]["inspection"]
        self.assertEqual(cached["resources"], self.current["resources"])
        self.assertEqual(cached["lifecycle"], "stopped")
        self.assertEqual(cached["health"], "unknown")

    def test_plan_expiry_and_fleet_key_cross_kind_are_rejected_without_remote_work(self):
        self.inspect()
        proposal = self.broker.plan("restart", "service")
        with self.assertRaisesRegex(ValueError, "not a fleet key plan"):
            self.broker.execute_fleet_keys(proposal["id"], approved=True, request_id="wrong-interface")
        proposal["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        with self.broker.store.transaction() as db:
            db.execute("UPDATE plans SET data=? WHERE id=?", (encode(proposal), proposal["id"]))
        with self.assertRaisesRegex(ValueError, "expired"):
            self.broker.execute(proposal["id"], approved=True, request_id="expired-plan")
        self.assertEqual(len(self.calls), 1)

    def test_authority_changed_during_remote_action_requires_new_inspection(self):
        self.inspect()
        proposal = self.broker.plan("start", "service")

        def changed(host, source, request, *, timeout, local=False):
            result = self.fake_remote(host, source, request, timeout=timeout, local=local)
            self.config["workloads"]["service"]["unit"] = "other.service"
            self.write_config()
            return result

        with patch.object(lifecycle_ops, "run_remote", side_effect=changed):
            receipt = self.broker.execute(proposal["id"], approved=True, request_id="authority-race")["receipt"]
        self.assertEqual(receipt["status"], "needs-inspection")
        self.assertNotIn("inspection", receipt)
        self.assertEqual(self.broker.lifecycle_inspections(), {})



if __name__ == "__main__":
    unittest.main()
