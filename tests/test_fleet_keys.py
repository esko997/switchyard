"""Fleet mesh failure cases using isolated public-data fixtures, never real SSH."""
import base64
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

from switchyard.broker import Broker
from switchyard import fleet_keys, operation_worker
from switchyard.lease_db import resource_label
from switchyard.leases import LedgerBroker
from switchyard.operation_store import digest, encode
from switchyard.remote import RemoteError


def key(seed):
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + hashlib.sha256(seed.encode()).digest()
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


class Network:
    def __init__(self, lease_store):
        self.lease_store = lease_store
        self.records = {name: {"keys": {}, "grants": [], "peers": [], "generation": None, "serial": 0}
                        for name in ("alpha", "beta", "gamma")}
        self.offline = set()
        self.manual = {name: set() for name in self.records}
        self.trace = []
        self.interrupt_after_write = None
        self.interrupt_after_retirement = None
        self.active_hosts = {}

    def snapshot(self, name):
        record = self.records[name]
        return {"ok": True, "supported": True, "revision": digest(record), "keys": dict(record["keys"]),
                "server_key": key("server-" + name), "detail": "Fixture public metadata"}

    def call(self, host, source, request, **kwargs):
        name = host["host_id"]
        # Every source/destination reservation survives direct peer verification.
        for host_id, enrolled in self.active_hosts.items():
            current = self.lease_store.current(resource_label(host_id, enrolled["ledger"]))
            if current is None or current["status"] not in {"claimed", "suspect"}:
                raise AssertionError("A whole-operation durable lease was released")
            if current["owner"] != "switchyard":
                raise AssertionError("The operation does not own its device reservation")
        self.trace.append((name, request.copy()))
        if name in self.offline:
            raise RemoteError("Fixture offline")
        record = self.records[name]
        if request["action"] == "inspect":
            return self.snapshot(name)
        if request["action"] == "verify":
            target = request["peer"]["host_id"]
            if target in self.offline:
                return {"ok": True, "status": "pending", "detail": "Offline peer"}
            public = record["keys"].get(request["generation"])
            accepted = public in self.records[target]["grants"] or public in self.manual[target]
            return {"ok": True, "status": "verified" if accepted else "revoked", "detail": "Fixture pinned listener"}
        if request["expected_revision"] != self.snapshot(name)["revision"]:
            return {"ok": False, "status": "conflict", "detail": "Concurrent change"}
        if request["action"] == "identity":
            record["keys"].setdefault(request["generation"], key(name + request["generation"]))
        elif request["action"] == "configure":
            record.update(grants=request["grants"], peers=request["peers"], generation=request["generation"])
        if (self.interrupt_after_retirement and request["action"] == "configure"
                and self.interrupt_after_retirement[0] == name
                and self.interrupt_after_retirement[1] not in request["grants"]):
            self.interrupt_after_retirement = None
            raise RemoteError("Fixture interrupted after old grants withdrawn")
        if self.interrupt_after_write == (name, request["action"]):
            self.interrupt_after_write = None
            raise RemoteError("Fixture interrupted response after remote write")
        return {**self.snapshot(name), "residual_access": [fleet_keys.fleet_keys_remote.fingerprint(public)
                for public in request.get("revoked_keys", []) if public in self.manual[name]]}


class FleetKeyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.hosts = {}
        for name in ("alpha", "beta", "gamma"):
            ledger = self.root / name
            self.hosts[name] = {"host_id": name, "transport": "ssh", "target": "fixture@" + name,
                                "expected_hostname": name, "ledger": str(ledger), "user_units": [], "system_units": []}
        self.config_path = self.root / "operations.json"
        self.config = {"schema_version": 2, "shell_hosts": [], "workloads": {}, "fleet_key_hosts": list(self.hosts)}
        self.config_path.write_text(json.dumps(self.config))
        self.broker = Broker(self.config_path, hosts=self.hosts, state_dir=self.root / "state")
        self.leases = LedgerBroker({name: Path(host["ledger"]) for name, host in self.hosts.items()},
                                   state_dir=self.broker.lease_state_dir)
        self.lease_store = self.leases.store
        self.network = Network(self.lease_store)
        self.sequence = 0
        for number in (signal.SIGTERM, signal.SIGINT):
            self.addCleanup(signal.signal, number, signal.getsignal(number))
        self.dispatch_patch = patch.object(self.broker, "_dispatch", side_effect=self.dispatch)
        self.dispatch_patch.start()
        self.addCleanup(self.dispatch_patch.stop)

    def dispatch(self, receipt, payload):
        hosts = payload.pop("operation_hosts", self.hosts)
        payload.update(hosts={name: hosts[name] for name in receipt["host_ids"]},
                       operation_id=receipt["id"], state_dir=str(self.broker.store.directory),
                       lease_state_dir=str(self.broker.lease_state_dir))
        self.network.active_hosts = payload["hosts"]
        stdin = type("Input", (), {"buffer": io.BytesIO(encode(payload).encode())})()
        output = io.StringIO()
        with patch("sys.stdin", stdin), patch("sys.stdout", output), patch("switchyard.fleet_keys.run_remote", self.network.call):
            operation_worker.main()
        self.assertEqual(json.loads(output.getvalue())["operation_id"], receipt["id"])
        return {"receipt": self.broker.receipt(receipt["id"])}

    def inspect(self, hosts=None):
        self.sequence += 1
        return self.broker.inspect_fleet_keys(hosts or ["alpha", "beta"], request_id="inspect-" + str(self.sequence))

    def apply(self, action, hosts):
        self.sequence += 1
        proposal = self.broker.plan_fleet_keys(action, hosts)
        return self.broker.execute_fleet_keys(proposal["id"], approved=True, request_id="apply-" + str(self.sequence))

    def state(self):
        with self.broker.store.transaction() as db:
            return fleet_keys.load(db)

    def attest_uncertain_leases(self, *host_ids):
        # Offline fixture only: emulate inspection and an operator's stopped-work attestation.
        for host_id in host_ids:
            host = self.hosts[host_id]
            current = self.lease_store.current(resource_label(host_id, host["ledger"]))
            self.assertIsNotNone(current)
            self.assertEqual(current["status"], "suspect")
        for host_id, host in self.hosts.items():
            label = resource_label(host_id, host["ledger"])
            current = self.lease_store.current(label)
            if current is None:
                continue
            self.assertEqual(current["status"], "suspect")
            block = self.lease_store.break_device(
                label, reason="Inspected isolated fixture effects", operator="fixture operator",
                expected_id=current["lease_id"])
            self.lease_store.clear(
                label, operator="fixture operator", expected_block=block,
                attest_stopped="Inspected fixture transport and remote state; no work remains")
            self.assertIsNone(self.lease_store.current(label))

    def enroll(self):
        self.inspect()
        result = self.apply("enroll", ["alpha", "beta"])
        self.assertEqual(result["receipt"]["status"], "succeeded")
        return result

    def test_inspection_and_status_never_create_identities_and_read_only_retains_state(self):
        self.assertEqual(self.broker.fleet_keys()["members"], [])
        with self.assertRaises(ValueError):
            self.broker.plan_fleet_keys("enroll", ["alpha"])
        self.inspect()
        self.assertTrue(all(request["action"] == "inspect" for _, request in self.network.trace))
        self.assertTrue(all(not record["keys"] for record in self.network.records.values()))
        self.assertTrue(all(not Path(host["ledger"]).exists() for host in self.hosts.values()))
        self.assertTrue(all(self.lease_store.current(resource_label(name, host["ledger"])) is None
                            for name, host in self.hosts.items()))
        disabled = Broker(None, hosts=self.hosts, state_dir=self.root / "state")
        self.assertFalse(disabled.fleet_keys()["enabled"])
        self.assertEqual(len(disabled.fleet_keys()["hosts"]), 2)
        self.assertEqual(disabled.policy()["fleet_key_hosts"], [])
        with self.assertRaises(ValueError):
            disabled.inspect_fleet_keys(["alpha"], request_id="no-authority")

    def test_enroll_and_remove_verifies_both_directions_without_losing_manual_grants(self):
        self.enroll()
        manual_key = key("manual-bootstrap")
        self.network.manual["alpha"].add(manual_key)
        self.network.manual["beta"].add(manual_key)
        self.assertEqual(len(self.broker.fleet_keys()["connections"]), 2)
        result = self.apply("remove", ["alpha"])
        self.assertEqual(result["receipt"]["status"], "succeeded")
        self.assertEqual(self.broker.fleet_keys()["members"], ["beta"])
        self.assertTrue(all(not record["grants"] for record in self.network.records.values()))
        self.assertIn(manual_key, self.network.manual["alpha"])
        self.assertTrue(all(item["status"] == "verified" and not item["desired"] for item in self.broker.fleet_keys()["connections"]))
        self.assertEqual(self.apply("enroll", ["alpha"])["receipt"]["status"], "succeeded")

    def test_offline_removal_persists_desire_and_does_not_claim_revocation(self):
        self.enroll()
        self.network.offline.add("beta")
        result = self.apply("remove", ["alpha"])
        self.assertEqual(result["receipt"]["status"], "needs-inspection")
        self.assertEqual(self.state()["members"], ["beta"])
        self.assertTrue(all(item["status"] != "verified" for item in self.broker.fleet_keys()["connections"]))
        restarted = Broker(None, hosts=self.hosts, state_dir=self.root / "state")
        self.assertEqual(restarted.fleet_keys()["members"], ["beta"])
        self.network.offline.clear()
        self.attest_uncertain_leases("beta")
        self.assertEqual(self.apply("reconcile", [])["receipt"]["status"], "succeeded")

    def test_rotation_keeps_old_grants_until_new_full_mesh_verifies(self):
        self.enroll()
        old_generation = self.state()["hosts"]["alpha"]["generation"]
        old_key = self.network.records["alpha"]["keys"][old_generation]
        self.network.offline.add("beta")
        self.assertEqual(self.apply("rotate", ["alpha"])["receipt"]["status"], "needs-inspection")
        self.assertIn(old_generation, self.state()["hosts"]["alpha"]["retiring"])
        self.assertIn(old_key, self.network.records["beta"]["grants"])
        with self.assertRaises(ValueError):
            self.broker.plan_fleet_keys("rotate", ["alpha"])
        self.network.offline.clear()
        self.attest_uncertain_leases("beta")
        self.assertEqual(self.apply("reconcile", [])["receipt"]["status"], "succeeded")
        self.assertNotIn("retiring", self.state()["hosts"]["alpha"])
        self.assertNotIn(old_key, self.network.records["beta"]["grants"])
        self.assertIn(old_generation, self.network.records["alpha"]["keys"])

    def test_removal_detects_manual_regrant_of_previously_retired_identity(self):
        self.enroll()
        old_generation = self.state()["hosts"]["alpha"]["generation"]
        old_key = self.network.records["alpha"]["keys"][old_generation]
        self.assertEqual(self.apply("rotate", ["alpha"])["receipt"]["status"], "succeeded")
        self.assertNotIn("retiring", self.state()["hosts"]["alpha"])
        self.network.manual["beta"].add(old_key)
        result = self.apply("remove", ["alpha"])
        self.assertEqual(result["receipt"]["status"], "needs-inspection")
        self.assertEqual(self.state()["hosts"]["beta"]["status"], "conflict")
        self.assertIn(old_key, self.network.manual["beta"])
        self.assertTrue(any(item["source_id"] == "alpha" and item["target_id"] == "beta"
                            and item["status"] == "conflict" for item in self.broker.fleet_keys()["connections"]))

    def test_interrupted_retirement_never_regrants_the_withdrawn_old_key(self):
        self.enroll()
        generation = self.state()["hosts"]["alpha"]["generation"]
        old_key = self.network.records["alpha"]["keys"][generation]
        self.network.interrupt_after_retirement = ("beta", old_key)
        self.assertEqual(self.apply("rotate", ["alpha"])["receipt"]["status"], "needs-inspection")
        self.assertTrue(self.state()["retirement_started"])
        self.assertNotIn(old_key, self.network.records["beta"]["grants"])
        self.attest_uncertain_leases("beta")
        self.inspect()
        self.network.trace.clear()
        self.assertEqual(self.apply("reconcile", [])["receipt"]["status"], "succeeded")
        self.assertTrue(all(old_key not in request["grants"] for name, request in self.network.trace
                            if name == "beta" and request["action"] == "configure"))
        self.assertNotIn("retirement_started", self.state())

    def test_duplicate_unmanaged_credential_prevents_complete_removal(self):
        self.enroll()
        current = self.state()["hosts"]["alpha"]["generation"]
        self.network.manual["beta"].add(self.network.records["alpha"]["keys"][current])
        result = self.apply("remove", ["alpha"])
        self.assertEqual(result["receipt"]["status"], "needs-inspection")
        self.assertTrue(any(item["status"] == "conflict" for item in self.broker.fleet_keys()["hosts"]))
        self.assertIn("conflict", [item["status"] for item in self.broker.fleet_keys()["connections"]])

    def test_unissued_offline_joiner_does_not_block_other_peer_revocation(self):
        self.enroll()
        self.inspect(["gamma"])
        self.network.offline.add("gamma")
        self.assertEqual(self.apply("enroll", ["gamma"])["receipt"]["status"], "needs-inspection")
        generation = self.state()["hosts"]["alpha"]["generation"]
        old_key = self.network.records["alpha"]["keys"][generation]
        self.assertIn(old_key, self.network.records["beta"]["grants"])
        self.attest_uncertain_leases("gamma")
        self.assertEqual(self.apply("remove", ["alpha"])["receipt"]["status"], "needs-inspection")
        self.assertNotIn(old_key, self.network.records["beta"]["grants"])
        self.assertEqual(self.state()["members"], ["beta", "gamma"])

    def test_unsupported_hosts_stay_explicit_without_creating_or_weakening_keys(self):
        snapshot = self.network.snapshot
        with patch.object(self.network, "snapshot", side_effect=lambda name: {
                **snapshot(name), "supported": False, "server_key": None, "detail": "No supported Ed25519 server identity"}):
            self.assertEqual(self.inspect()["receipt"]["status"], "needs-inspection")
            proposal = self.broker.plan_fleet_keys("enroll", ["alpha", "beta"])
            self.assertTrue(any("No supported" in warning for warning in proposal["warnings"]))
            result = self.broker.execute_fleet_keys(proposal["id"], approved=True, request_id="unsupported")
        self.assertEqual(result["receipt"]["status"], "needs-inspection")
        self.assertTrue(all(record["status"] == "unsupported" for record in self.broker.fleet_keys()["hosts"][:2]))
        self.assertTrue(all(request["action"] == "inspect" for _, request in self.network.trace))

    def test_changed_remote_files_fail_before_membership_or_identity_mutation(self):
        self.inspect()
        proposal = self.broker.plan_fleet_keys("enroll", ["alpha", "beta"])
        self.network.records["beta"]["serial"] += 1
        result = self.broker.execute_fleet_keys(proposal["id"], approved=True, request_id="stale")
        self.assertEqual(result["receipt"]["status"], "failed")
        self.assertEqual(self.state()["members"], [])
        self.assertTrue(all(not record["keys"] for record in self.network.records.values()))
        self.assertTrue(all(request["action"] == "inspect" for _, request in self.network.trace))

    @patch.dict(os.environ, {"SWITCHYARD_OPERATION_LEASE_WAIT": "0"})
    def test_uncertain_identity_creation_is_durable_and_requires_explicit_reinspection(self):
        self.inspect()
        self.network.interrupt_after_write = ("alpha", "identity")
        result = self.apply("enroll", ["alpha", "beta"])
        self.assertEqual(result["receipt"]["status"], "needs-inspection")
        generation = self.state()["hosts"]["alpha"]["generation"]
        self.assertIn(generation, self.network.records["alpha"]["keys"])
        self.assertEqual(self.state()["members"], ["alpha", "beta"])
        before = len(self.network.trace)
        self.assertEqual(self.apply("reconcile", [])["receipt"]["status"], "busy")
        self.assertEqual(len(self.network.trace), before)
        self.attest_uncertain_leases("alpha")
        self.assertEqual(self.apply("reconcile", [])["receipt"]["status"], "failed")
        self.inspect()
        self.assertEqual(self.apply("reconcile", [])["receipt"]["status"], "succeeded")
        self.assertEqual(self.state()["hosts"]["alpha"]["generation"], generation)

    def test_plan_kind_expiry_authority_and_keyed_replay(self):
        self.inspect()
        revision = self.broker.fleet_keys()["revision"]
        proposal = self.broker.plan_fleet_keys("enroll", ["alpha", "beta"])
        self.assertEqual(self.broker.fleet_keys()["revision"], revision)
        with self.assertRaises(ValueError):
            self.broker.execute(proposal["id"], approved=True, request_id="wrong-api")
        with self.assertRaises(ValueError):
            self.broker.execute_fleet_keys(proposal["id"], approved=1, request_id="not-literal")
        result = self.broker.execute_fleet_keys(proposal["id"], approved=True, request_id="once")
        count = len(self.network.trace)
        replay = self.broker.execute_fleet_keys(proposal["id"], approved=True, request_id="once")
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["receipt"]["id"], result["receipt"]["id"])
        self.assertEqual(len(self.network.trace), count)
        with self.assertRaises(ValueError):
            self.broker.inspect_fleet_keys(["alpha"], request_id="once")
        proposal = self.broker.plan_fleet_keys("rotate", ["alpha"])
        self.config["fleet_key_hosts"] = ["alpha", "beta"]
        self.config_path.write_text(json.dumps(self.config))
        with self.assertRaises(ValueError):
            self.broker.execute_fleet_keys(proposal["id"], approved=True, request_id="changed-authority")
        self.config["fleet_key_hosts"] = list(self.hosts)
        self.config_path.write_text(json.dumps(self.config))
        with self.broker.store.transaction() as db:
            proposal["expires_at"] = "2000-01-01T00:00:00+00:00"
            db.execute("UPDATE plans SET data=? WHERE id=?", (encode(proposal), proposal["id"]))
        with self.assertRaises(ValueError):
            self.broker.execute_fleet_keys(proposal["id"], approved=True, request_id="expired")
        with self.broker.store.transaction() as db:
            db.execute("INSERT INTO plans(id,data,fingerprint) VALUES(?,?,?)", ("workload-plan", encode({"action": "deploy"}), "unused"))
        with self.assertRaises(ValueError):
            self.broker.execute_fleet_keys("workload-plan", approved=True, request_id="wrong-key-api")

    @patch.dict(os.environ, {"SWITCHYARD_OPERATION_LEASE_WAIT": "0"})
    def test_busy_canonical_lease_prevents_every_remote_command(self):
        with self.leases.hold("beta", owner="fixture blocker", scope="busy device test",
                              worktree=str(self.root)):
            result = self.inspect()
        self.assertEqual(result["receipt"]["status"], "busy")
        self.assertEqual(self.network.trace, [])
        self.assertIsNone(self.lease_store.current(resource_label("alpha", self.hosts["alpha"]["ledger"])))
        self.assertIsNone(self.lease_store.current(resource_label("beta", self.hosts["beta"]["ledger"])))

    def test_state_lease_prevents_disjoint_inspection_lost_updates(self):
        with open(self.broker.store.directory / "fleet-keys.lock", "a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.inspect(["gamma"])
        self.assertEqual(result["receipt"]["status"], "busy")
        self.assertEqual(self.network.trace, [])

    def test_local_target_override_uses_fixed_local_subprocess_not_self_ssh(self):
        local = {"host_id": "alpha", "transport": "local", "expected_hostname": "alpha", "user_units": [], "system_units": []}
        self.broker.hosts["alpha"] = local
        self.config["local_targets"] = {"alpha": {"target": "fixture@192.0.2.68", "ledger": self.hosts["alpha"]["ledger"]}}
        self.config_path.write_text(json.dumps(self.config))
        calls = []
        original = self.network.call

        def recording(host, source, request, **kwargs):
            calls.append((host["host_id"], host["target"], kwargs.get("local")))
            return original(host, source, request, **kwargs)

        self.network.call = recording
        result = self.inspect(["alpha"])
        self.assertEqual(result["receipt"]["status"], "succeeded")
        # The local collector gains its declared account/ledger and runs locally, never via self-SSH.
        self.assertEqual(calls, [("alpha", "fixture@192.0.2.68", True)])
        self.assertEqual(self.broker.hosts["alpha"]["transport"], "local")
        self.config["local_targets"]["beta"] = {"target": "fixture@beta", "ledger": self.hosts["beta"]["ledger"]}
        self.config_path.write_text(json.dumps(self.config))
        with self.assertRaises(ValueError):
            self.broker.policy()


if __name__ == "__main__":
    unittest.main()
