"""Direct durable device leases and legacy registry normalization, using isolated state."""
import base64
from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from switchyard import collector, operation_worker
from switchyard.broker import Broker
from switchyard.core import Service
from switchyard.host_registry import HostRegistry, authority, encode
from switchyard.leases import LedgerBroker, LeaseBusy


def public_key():
    kind = b"ssh-ed25519"
    return "ssh-ed25519 " + base64.b64encode(struct.pack(">I", len(kind)) + kind + struct.pack(">I", 32) + b"x" * 32).decode()


class DirectLeaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.state = self.root / "state"
        self.hosts = {}
        self.ledgers = {}
        for host_id, device, target in (("host-c", "HOSTC", "operator@192.168.50.69"),
                                        ("host-b", "HOSTB", "operator@192.168.50.233")):
            ledger = self.root / ("DEVICE_ACCESS_" + device + ".md")
            self.ledgers[host_id] = ledger
            self.hosts[host_id] = {"host_id": host_id, "transport": "ssh", "target": target,
                                   "ledger": str(ledger), "expected_hostname": host_id,
                                   "user_units": [], "system_units": []}
        self.catalog = self.root / "catalog.json"
        self.devices = [{"id": host_id, "name": host_id, "platform": "linux", "architecture": "x86_64",
                         "capabilities": ["linux"], "notes": "fixture", "provenance": "fixture",
                         "access": "declared-only", "observed_at": None} for host_id in self.hosts]
        self.catalog.write_text(json.dumps({"schema_version": 1, "provenance": "fixture",
                                             "devices": self.devices, "workloads": []}))
        bootstrap = patch("switchyard.host_registry.host_keys.bootstrap", return_value=[public_key()])
        bootstrap.start()
        self.addCleanup(bootstrap.stop)
        self.lease_broker = LedgerBroker(self.ledgers, state_dir=self.state)

    def assert_held(self, host_ids):
        for host_id in host_ids:
            label = self.lease_broker.keys[host_id]
            self.assertEqual(self.lease_broker.store.current(label)["status"], "claimed")
            with self.assertRaises(LeaseBusy):
                with self.lease_broker.hold(host_id, owner="other", scope="exclusion fixture", worktree=str(self.root)):
                    pass

    def assert_released(self, host_ids):
        events = list(reversed(self.lease_broker.store.history()))
        for host_id in host_ids:
            label = self.lease_broker.keys[host_id]
            self.assertIsNone(self.lease_broker.store.current(label))
            entries = [entry for entry in events if entry["device"] == label]
            self.assertEqual(entries[0]["event"], "CLAIM")
            self.assertEqual(entries[-1]["event"], "RELEASE")

    def test_wrapper_api_removed_and_runtime_schema_refuses_retired_field(self):
        for name in ("_wrapped_input", "LEGACY_WRAPPER", "WRAPPER_SHA256"):
            self.assertFalse(hasattr(collector, name), name)
        for config in self.hosts.values():
            legacy = {**config, "lease_wrapper": "/nonexistent/retired-wrapper"}
            with self.assertRaisesRegex(ValueError, "fields"):
                collector._validate_config(legacy)
            with patch.object(collector, "_run", side_effect=AssertionError("No transport")):
                with self.assertRaises(collector.CollectionError):
                    collector.collect_host(legacy, state_dir=self.state)
                with self.assertRaises(collector.CollectionError):
                    collector.scan_host_key(legacy, address=config["target"].split("@")[1], port=22, state_dir=self.state)

    def test_collections_hold_durable_claim_with_direct_ssh_and_receipts(self):
        for host_id, config in self.hosts.items():
            def run(command, source, deadline):
                self.assert_held([host_id])
                self.assertEqual(command[0], "ssh")
                self.assertEqual(command[-2], config["target"])
                return 0, b"fixture output"
            evidence = {"observed_at": "2026-11-22T00:00:00+00:00", "coverage": []}
            with self.subTest(host_id=host_id), patch.object(collector, "_run", side_effect=run), \
                    patch.object(collector, "_validate_snapshot", return_value=evidence):
                self.assertEqual(collector.collect_host(config, state_dir=self.state), evidence)
            self.assertFalse(self.ledgers[host_id].exists())
        self.assert_released(self.hosts)

    def test_scans_hold_durable_claim_and_invoke_keyscan_directly(self):
        for host_id, config in self.hosts.items():
            def run(command, source, deadline):
                self.assert_held([host_id])
                self.assertEqual(command[0], "ssh-keyscan")
                self.assertEqual(source, b"")
                return 0, ("fixture " + public_key()).encode()
            with self.subTest(host_id=host_id), patch.object(collector, "_run", side_effect=run):
                scanned = collector.scan_host_key(config, address=config["target"].split("@")[1], port=22, state_dir=self.state)
                self.assertEqual(scanned["keys"], [public_key()])
        self.assert_released(self.hosts)

    def test_busy_direct_lease_prevents_collection_and_scan(self):
        for host_id, config in self.hosts.items():
            with self.subTest(host_id=host_id), self.lease_broker.hold(
                    host_id, owner="test", scope="busy fixture", worktree=str(self.root)):
                with patch.object(collector, "_run", side_effect=AssertionError("No transport while busy")):
                    with self.assertRaises(LeaseBusy):
                        collector.collect_host(config, state_dir=self.state)
                    with self.assertRaises(LeaseBusy):
                        collector.scan_host_key(config, address=config["target"].split("@")[1], port=22, state_dir=self.state)

    def broker(self):
        path = self.root / "operations.json"
        path.write_text(json.dumps({"schema_version": 2, "shell_hosts": list(self.hosts), "workloads": {}}))
        return Broker(path, hosts=self.hosts, state_dir=self.state / "operations", lease_state_dir=self.state)

    def dispatch_worker(self, command, source, **kwargs):
        self.assertEqual(command[0], sys.executable)
        self.assertIn("switchyard.operation_worker", command[-1])
        output = io.StringIO()
        with patch.object(operation_worker.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(source))), \
                patch.object(operation_worker.signal, "signal"), redirect_stdout(output):
            operation_worker.main()
        return 0, output.getvalue().encode()

    def test_operations_acquire_both_durable_claims_before_remote_execution(self):
        broker = self.broker()
        def remote(host, source, request, **kwargs):
            self.assert_held(self.hosts)
            self.assertEqual(host["host_id"], "host-c")
            return {"status": "succeeded", "exit_code": 0, "stdout": "fixture", "stderr": ""}
        with patch("switchyard.broker.run_bounded", side_effect=self.dispatch_worker), \
                patch.object(operation_worker, "run_remote", side_effect=remote) as run:
            result = broker.shell("host-c", "true", extra_host_ids=["host-b"], request_id="direct-operation")
        self.assertEqual(result["receipt"]["status"], "succeeded")
        run.assert_called_once()
        self.assertTrue(all(not ledger.exists() for ledger in self.ledgers.values()))
        self.assert_released(self.hosts)

    @patch.dict("os.environ", {"SWITCHYARD_OPERATION_LEASE_WAIT": "0"})
    def test_busy_operation_lease_prevents_every_remote_command(self):
        broker = self.broker()
        with self.lease_broker.hold("host-b", owner="test", scope="busy fixture", worktree=str(self.root)):
            with patch("switchyard.broker.run_bounded", side_effect=self.dispatch_worker), \
                    patch.object(operation_worker, "run_remote", side_effect=AssertionError("No remote execution")):
                result = broker.shell("host-c", "true", extra_host_ids=["host-b"], request_id="busy-direct")
        self.assertEqual(result["receipt"]["status"], "busy")

    def test_device_blocked_after_lease_break_refuses_operations(self):
        # `switchyard lease break` without an attestation blocks the device; brokered operations must honour
        # that, not only agent-facing leases.
        broker = self.broker()
        block = self.lease_broker.store.break_device("HOSTB", operator="tester", reason="fixture")
        with patch("switchyard.broker.run_bounded", side_effect=self.dispatch_worker), \
                patch.object(operation_worker, "run_remote", side_effect=AssertionError("No remote execution")):
            result = broker.shell("host-c", "true", extra_host_ids=["host-b"], request_id="blocked-direct")
        self.assertEqual(result["receipt"]["status"], "busy")
        self.assertIn("HOSTB", result["receipt"]["error"])
        self.assertIn("blocked", result["receipt"]["error"])
        self.lease_broker.store.clear("HOSTB", operator="tester", attest_stopped="fixture confirmed stopped", expected_block=block)
        with patch("switchyard.broker.run_bounded", side_effect=self.dispatch_worker), \
                patch.object(operation_worker, "run_remote", return_value={"status": "succeeded", "exit_code": 0, "stdout": "", "stderr": ""}):
            self.assertEqual(broker.shell("host-c", "true", extra_host_ids=["host-b"], request_id="unblocked-direct")["receipt"]["status"], "succeeded")

    def test_ssh_connection_rejects_symlink_to_a_device_ledger(self):
        alias = self.root / "noncanonical.md"
        alias.symlink_to(self.ledgers["host-b"])
        for host_id, config in self.hosts.items():
            changed = {**config, "target": "observer@new.invalid", "port": 2222, "expected_hostname": "renamed"}
            with self.subTest(host_id=host_id):
                self.assertEqual(collector._validate_config(changed), changed)
                with self.assertRaisesRegex(ValueError, "canonical"):
                    collector._validate_config({**changed, "ledger": str(alias)})

    def test_pinned_host_c_endpoint_edit_preserves_keys_and_becomes_unverified(self):
        path = self.root / "collectors.json"
        path.write_text(json.dumps({"schema_version": 1, "hosts": list(self.hosts.values())}))
        service = Service(self.catalog, collectors_path=path, state_dir=self.root / "service")
        before = service.hosts()
        host = next(host for host in before["hosts"] if host["id"] == "host-c")
        service._registry.verify("host-c", authority(host))
        before = service.hosts()
        self.assertEqual(next(host for host in before["hosts"] if host["id"] == "host-c")["verification"]["state"], "verified")
        service.update_host("host-c", {"target": "operator@new.invalid", "port": 2222},
                            expected_revision=before["revision"], connection=True)
        host = next(host for host in service.hosts()["hosts"] if host["id"] == "host-c")
        self.assertEqual(host["collector"]["target"], "operator@new.invalid")
        self.assertEqual(host["collector"]["ledger"], str(self.ledgers["host-c"]))
        self.assertEqual(host["host_keys"], [public_key()])
        self.assertEqual(host["connection_revision"], 2)
        self.assertEqual(host["verification"]["state"], "unverified")

    def test_seed_files_ignore_retired_wrapper_without_executing_it(self):
        configs = {host: {**config, "lease_wrapper": "/missing/retired"} for host, config in self.hosts.items()}
        path = self.root / "collectors.json"
        path.write_text(json.dumps({"schema_version": 1, "hosts": list(configs.values())}))
        self.assertEqual(collector.load_config(path), self.hosts)
        records = HostRegistry.seed_records(self.devices, configs)
        self.assertTrue(all("lease_wrapper" not in record["collector"] for record in records))
        self.assertTrue(all(record["connection_revision"] == 1 for record in records))
        self.assertTrue(all("lease_wrapper" in config for config in configs.values()))

    def test_legacy_registry_rows_normalize_once_invalidate_verification_and_scans(self):
        registry = HostRegistry(self.root / "registry-state", self.catalog)
        records = HostRegistry.seed_records(self.devices, self.hosts)
        registry.seed(records)
        for record in records:
            registry.verify(record["id"], authority(record))
            registry.save_scan(record["id"], authority(record), {"keys": [public_key()], "fingerprints": []})
        legacy = deepcopy(records[0])
        legacy["collector"]["lease_wrapper"] = "/missing/retired"
        with registry.transaction() as db:
            db.execute("UPDATE hosts SET data=? WHERE id=?", (encode(legacy), legacy["id"]))
            metadata_revision = db.execute("SELECT revision FROM metadata").fetchone()[0]
        before_authority = authority(legacy)
        migrated = registry.read()
        changed, unchanged = migrated["hosts"]
        self.assertNotIn("lease_wrapper", changed["collector"])
        self.assertEqual(changed["connection_revision"], 2)
        self.assertEqual(changed["verification"]["state"], "unverified")
        self.assertIsNone(changed["verified_revision"])
        self.assertEqual(unchanged["connection_revision"], 1)
        self.assertEqual(unchanged["verification"]["state"], "verified")
        registry.verify(changed["id"], before_authority)
        self.assertEqual(registry.read(), migrated)
        reopened = HostRegistry(self.root / "registry-state", self.catalog)
        self.assertEqual(reopened.read(), migrated)
        with registry.transaction() as db:
            self.assertEqual(db.execute("SELECT revision FROM metadata").fetchone()[0], metadata_revision + 1)
            self.assertEqual(db.execute("SELECT host_id FROM scans").fetchall(), [(unchanged["id"],)])
            self.assertEqual(db.execute("SELECT host_id FROM verification").fetchall(), [(unchanged["id"],)])


class BoundedLeaseWaitTests(unittest.TestCase):
    def test_operation_lease_waits_for_a_brief_holder_but_not_forever(self):
        import threading
        import time
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory).resolve() / "DEVICE_ACCESS_FIXTURE.md"
            broker = LedgerBroker({"fixture": ledger}, state_dir=Path(directory) / "state")
            meta = dict(owner="test", scope="wait fixture", worktree=directory)
            def holder(ready, release, errors):
                try:
                    with broker.hold("fixture", **meta):
                        ready.set()
                        if not release.wait(5):
                            raise AssertionError("holder release timed out")
                except BaseException as error:
                    errors.append(error)
                    ready.set()
            for brief in (True, False):
                ready, release = threading.Event(), threading.Event()
                errors = []
                thread = threading.Thread(target=holder, args=(ready, release, errors))
                thread.start()
                timer = None
                try:
                    self.assertTrue(ready.wait(2))
                    self.assertFalse(errors)
                    if brief:
                        timer = threading.Timer(0.6, release.set)
                        timer.start()
                        started = time.monotonic()
                        with broker.hold("fixture", wait=5, **meta):
                            self.assertGreater(time.monotonic() - started, 0.2)
                    else:
                        events = broker.store.history()
                        with self.assertRaises(LeaseBusy):
                            with broker.hold("fixture", wait=0.5, **meta):
                                pass
                        self.assertEqual(broker.store.history(), events)
                finally:
                    release.set()
                    if timer is not None:
                        timer.join(2)
                    thread.join(2)
                self.assertFalse(thread.is_alive())
                self.assertFalse(errors)
            with self.assertRaises(ValueError):
                with broker.hold("fixture", wait=601, **meta):
                    pass
