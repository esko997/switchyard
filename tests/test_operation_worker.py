"""Worker/store boundaries with durable leases."""
import io
import json
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

from switchyard import operation_worker, podman_ops
from switchyard.broker import Broker
from switchyard.lease_db import LeaseStore
from switchyard.operation_store import encode


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.broker = Broker(None, hosts={}, state_dir=self.root / "state")
        self.leases = LeaseStore(self.broker.lease_state_dir / "leases")
        self.hosts = {}
        for name in ("alpha", "beta"):
            ledger = self.root / name
            self.hosts[name] = {"host_id": name, "ledger": str(ledger)}
        for signum in (signal.SIGTERM, signal.SIGINT):
            handler = signal.getsignal(signum)
            self.addCleanup(signal.signal, signum, handler)

    def begin(self, placement=None):
        with self.broker.store.transaction() as db:
            self.broker.store.ownership(db, "foobar")
            self.broker.store.record_placement(db, "foobar", placement)
            result = self.broker._begin(db, request_id="worker", intent={"action": "deploy"}, kind="managed",
                                        host_ids=list(self.hosts), workload_id="foobar")
        return result["receipt"]

    def run_worker(self, receipt, placement, execute):
        payload = {"kind": "managed", "state_dir": str(self.broker.store.directory), "operation_id": receipt["id"],
                   "lease_state_dir": str(self.broker.lease_state_dir),
                   "hosts": self.hosts, "request": {"workload_id": "foobar", "placement": placement}}
        stream = io.TextIOWrapper(io.BytesIO(encode(payload).encode()))
        with patch.object(operation_worker.sys, "stdin", stream), patch.object(operation_worker.sys, "stdout", io.StringIO()) as output, \
             patch.object(operation_worker, "_validate_config", side_effect=lambda host: host), \
             patch.object(podman_ops, "execute_managed", side_effect=execute):
            operation_worker.main()
        return json.loads(output.getvalue())

    def test_every_lease_remains_held_during_action_and_failed_placement_is_factual(self):
        original = {"workload_id": "foobar", "host_id": "alpha", "native_id": "source", "lifecycle": "running"}
        receipt = self.begin(original)
        recovery = {"source": original, "target_id": "beta"}
        def execute(request, hosts, emit):
            for host in hosts.values():
                self.assertIsNotNone(self.leases.current(host["host_id"].upper()))
            emit("recovery-intent", recovery)
            return {"status": "failed", "error": "verified stopped source; destination refused",
                    "placement": {**original, "lifecycle": "stopped", "recovery": recovery}}
        self.run_worker(receipt, original, execute)
        placement = self.broker.placements()["foobar"]
        self.assertEqual(placement["lifecycle"], "stopped")
        self.assertEqual(placement["recovery"], recovery)
        self.assertEqual(self.broker.receipt(receipt["id"])["status"], "failed")
        self.assertTrue(all(self.leases.current(host.upper()) is None for host in self.hosts))

    def test_interrupted_deployment_retains_identity_and_can_plan_recovery(self):
        receipt = self.begin()
        intended = {"workload_id": "foobar", "host_id": "alpha", "native_id": None,
                    "image_id": "sha256:fixture", "image_digest": "fixture@sha256:digest", "ownership_id": "fixture-owner"}
        def execute(request, hosts, emit):
            emit("deployment-intent", intended)
            raise InterruptedError("fixture cancellation")
        self.run_worker(receipt, None, execute)
        placement = self.broker.placements()["foobar"]
        self.assertEqual(placement["ownership_id"], "fixture-owner")
        self.assertIsNone(placement["native_id"])
        self.assertTrue(placement["uncertain"])
        self.assertEqual(placement["lifecycle"], "unknown")
        self.assertEqual(self.broker.receipt(receipt["id"])["status"], "needs-inspection")
        self.assertTrue(all(self.leases.current(host.upper())["suspect"] for host in self.hosts))

    def test_admin_block_in_shared_state_prevents_any_dispatch(self):
        self.leases.break_device("BETA", reason="operator fixture", operator="operator")
        receipt = self.begin()
        self.run_worker(receipt, None, lambda *args: self.fail("Sent work to a blocked device"))
        result = self.broker.receipt(receipt["id"])
        self.assertEqual(result["status"], "busy")
        self.assertIn("blocked", result["error"])
        self.assertIsNone(self.leases.current("ALPHA"))
        self.assertIsNotNone(self.leases.block("BETA"))

    def test_changed_placement_refuses_action_even_if_parent_planned_earlier(self):
        original = {"host_id": "alpha", "lifecycle": "running"}
        receipt = self.begin({"host_id": "beta", "lifecycle": "running"})
        self.run_worker(receipt, original, lambda *args: self.fail("No action after stale placement"))
        self.assertEqual(self.broker.receipt(receipt["id"])["status"], "failed")
        self.assertEqual(self.broker.placements()["foobar"]["host_id"], "beta")

    def test_lifecycle_diagnostics_return_to_caller_but_are_not_persisted(self):
        receipt = self.begin()
        result = self.run_worker(receipt, None, lambda *args: {
            "status": "needs-inspection", "error": "Container command failed",
            "stderr": "private-runtime-diagnostic",
        })
        self.assertEqual(result["stderr"], "private-runtime-diagnostic")
        persisted = self.broker.receipt(receipt["id"])
        self.assertEqual(persisted["status"], "needs-inspection")
        self.assertNotIn("private-runtime-diagnostic", json.dumps(persisted))
        self.assertNotIn(b"private-runtime-diagnostic", self.broker.store.path.read_bytes())


if __name__ == "__main__":
    unittest.main()
