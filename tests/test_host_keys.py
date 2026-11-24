"""Isolated SSH identity/lease regressions; never contacts an endpoint."""
import base64
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from switchyard import collector, host_keys
from switchyard.lease_db import LeaseStore
from switchyard.leases import LedgerBroker, LeaseBusy


def public_key():
    kind = b"ssh-ed25519"
    return "ssh-ed25519 " + base64.b64encode(struct.pack(">I", len(kind)) + kind + struct.pack(">I", 32) + b"x" * 32).decode()


class HostKeysTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.state = self.root / "state"
        self.ledger = self.root / "ledger"
        self.config = {"host_id": "fixture", "transport": "ssh", "target": "observer@fixture.test",
                       "ledger": str(self.ledger), "expected_hostname": "fixture",
                       "user_units": [], "system_units": []}

    def test_alias_only_for_registry_pins_and_nondefault_port(self):
        plain = collector._ssh_command(self.config)
        self.assertNotIn("-p", plain)
        self.assertFalse(any("HostKeyAlias=" in arg or "KnownHostsFile=" in arg for arg in plain))
        pinned = collector._ssh_command({**self.config, "known_hosts": "/private/pins", "port": 2222})
        for option in ("UserKnownHostsFile=/private/pins", "GlobalKnownHostsFile=/dev/null",
                       "HostKeyAlias=switchyard-fixture", "StrictHostKeyChecking=yes"):
            self.assertIn(option, pinned)
        self.assertEqual(pinned[pinned.index("-p") + 1], "2222")
        self.assertIn("-p", collector._ssh_command({**self.config, "port": 2222}))

    def test_port_validation_and_local_restrictions(self):
        for port in (0, 65536, True, "22"):
            with self.subTest(port=port), self.assertRaises(ValueError):
                collector._validate_config({**self.config, "port": port})
        local = {key: value for key, value in self.config.items() if key not in {"target", "ledger"}}
        local["transport"] = "local"
        for extra in ({"port": 22}, {"known_hosts": "/private/pins"}):
            with self.assertRaises(ValueError):
                collector._validate_config({**local, **extra})

    def test_address_change_does_not_remove_canonical_ledger(self):
        for host_id in ("host-a", "host-d", "controller", "test-portable", "host-c", "host-b"):
            with self.subTest(host_id=host_id), self.assertRaises(ValueError):
                collector._validate_config({**self.config, "host_id": host_id, "target": "observer@new-address.test", "ledger": None})

    def test_host_c_endpoint_and_port_can_change_under_canonical_lease(self):
        cfg = {**self.config, "host_id": "host-c", "expected_hostname": "host-c",
               "target": "operator@new.test", "port": 2222}
        self.assertEqual(collector._validate_config(cfg), cfg)
        with patch.object(collector, "_run", return_value=(0, ("fixture " + public_key()).encode())) as run:
            collector.scan_host_key(cfg, address="new.test", port=2222, state_dir=self.state)
            args, source, _ = run.call_args.args
            self.assertEqual(args[0], "ssh-keyscan")
            self.assertEqual(source, b"")

    def test_bootstrap_hashed_and_port_entries_use_keygen_lookup(self):
        known = self.root / "known_hosts"
        known.touch()
        key = public_key()
        for port, host in ((22, "|1|hash|value"), (2222, "[fixture.test]:2222")):
            output = f"# Host fixture found: line 4\n{host} {key} comment\n{host} {key}\n@revoked {host} {key}\n".encode()
            result = subprocess.CompletedProcess([], 0, output, b"")
            with self.subTest(port=port), patch.object(host_keys.subprocess, "run", return_value=result) as run:
                self.assertEqual(host_keys.bootstrap("fixture.test", port, known), [key])
                args = run.call_args.args[0]
                self.assertEqual(args, ["ssh-keygen", "-F", "fixture.test" if port == 22 else "[fixture.test]:2222", "-f", str(known)])
        blob = base64.b64decode(key.split()[1])
        expected = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        self.assertEqual(host_keys.fingerprint(key), expected)

    def test_atomic_private_pin_replacement_and_ownership_checks(self):
        path = self.root / "pins"
        host_keys.write_pins(path, {"fixture": [public_key(), public_key()]})
        original = path.read_bytes()
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(original.decode(), "switchyard-fixture " + public_key() + "\n")
        with patch.object(host_keys.os, "replace", side_effect=OSError("fixture failure")), self.assertRaises(OSError):
            host_keys.write_pins(path, {})
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["pins"])
        host_keys.write_pins(path, {})
        self.assertEqual(path.read_bytes(), b"")
        with patch.object(host_keys.os, "getuid", return_value=os.getuid() + 1), self.assertRaisesRegex(ValueError, "owned"):
            host_keys.write_pins(path, {})
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "private"):
            host_keys.write_pins(path, {})
        path.unlink()
        path.symlink_to(self.ledger)
        with self.assertRaises(ValueError):
            host_keys.write_pins(path, {})

    def test_scan_holds_durable_lease_through_output_and_releases(self):
        broker = LedgerBroker({"fixture": self.ledger}, state_dir=self.state)
        def run(command, source, deadline):
            self.assertEqual(command, ["ssh-keyscan", "-T", "5", "-p", "22", "-t", "ed25519,ecdsa,rsa", "fixture.test"])
            self.assertEqual(broker.store.current("FIXTURE")["status"], "claimed")
            with self.assertRaises(LeaseBusy):
                with broker.hold("fixture", owner="other", scope="exclusion check", worktree=str(self.root)):
                    pass
            self.assertEqual([entry["event"] for entry in broker.store.history()], ["CLAIM"])
            return 0, ("fixture.test " + public_key()).encode()
        with patch.object(collector, "_run", side_effect=run):
            result = collector.scan_host_key(self.config, address="fixture.test", port=22, state_dir=self.state)
        self.assertEqual(result, {"keys": [public_key()], "fingerprints": [host_keys.fingerprint(public_key())]})
        self.assertIsNone(LeaseStore(self.state / "leases").current("FIXTURE"))
        self.assertEqual([entry["event"] for entry in broker.store.history()], ["RELEASE", "CLAIM"])

    def test_unexpected_scan_interruptions_keep_durable_reservation_suspect(self):
        for index, failure in enumerate((KeyboardInterrupt(), OSError("private scan diagnostic"))):
            state = self.state / str(index)
            expected = KeyboardInterrupt if isinstance(failure, KeyboardInterrupt) else collector.CollectionError
            with self.subTest(failure=type(failure).__name__), \
                 patch.object(collector, "_run", side_effect=failure), self.assertRaises(expected):
                collector.scan_host_key(self.config, address="fixture.test", port=22, state_dir=state)
            store = LeaseStore(state / "leases")
            self.assertEqual(store.current("FIXTURE")["status"], "suspect")
            self.assertNotIn("RELEASE", [entry["event"] for entry in store.history()])
            self.assertNotIn("private scan diagnostic", str(store.history()))

    def test_completed_scan_without_usable_key_releases_reservation(self):
        with patch.object(collector, "_run", return_value=(0, b"not a usable identity")), \
             self.assertRaisesRegex(collector.CollectionError, "no usable identity"):
            collector.scan_host_key(self.config, address="fixture.test", port=22, state_dir=self.state)
        store = LeaseStore(self.state / "leases")
        self.assertIsNone(store.current("FIXTURE"))
        self.assertEqual([entry["event"] for entry in store.history()], ["RELEASE", "CLAIM"])

    def test_scan_refuses_nonssh_and_different_target_without_execution(self):
        with patch.object(collector, "_run", side_effect=AssertionError("No transport")):
            for cfg in ({"transport": "local"}, {"transport": "adb"}):
                with patch.object(collector, "_validate_config", return_value=cfg), self.assertRaises(collector.CollectionError):
                    collector.scan_host_key(cfg, address="fixture.test", port=22, state_dir=self.state)
            with self.assertRaises(collector.CollectionError):
                collector.scan_host_key(self.config, address="other.test", port=22, state_dir=self.state)
