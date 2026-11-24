"""Exercise the offline import with legacy files and the public CLI."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from switchyard.lease_db import LeaseBusy, LeaseStore
from switchyard.lease_migration import migrate


class LeaseMigrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name) / "state"
        self.directory = self.state / "leases"
        self.directory.mkdir(parents=True, mode=0o700)
        self.ledgers = Path(temporary.name) / "ledgers"
        self.ledgers.mkdir()

    def write_state(self, filename, record):
        path = self.directory / filename
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
            json.dump(record, stream)

    def preview(self):
        env = {**os.environ, "SWITCHYARD_LEDGER_DIR": str(self.ledgers)}
        return subprocess.run([sys.executable, "-m", "switchyard.cli", "--state-dir", str(self.state),
                               "lease", "migrate", "--dry-run"], env=env, capture_output=True, text=True, timeout=10)

    def test_cli_dry_run_and_import_preserve_source_and_uncertain_completion(self):
        claim = {"at": "2026-09-20T11:00:00Z", "event": "CLAIM", "lease_id": "a" * 32,
                 "owner": "fixture agent", "scope": "test", "device": "HOSTA"}
        source = self.ledgers / "DEVICE_ACCESS_HOSTA.md"
        content = "# Legacy audit\n" + json.dumps(claim) + "\n" + json.dumps({**claim, "event": "RELEASE", "reason": "expired"}) + "\n"
        source.write_text(content)
        self.write_state(claim["lease_id"] + ".json", {**claim, "status": "released", "reason": "expired"})
        self.write_state("blocked-HOSTB.json", {"device": "HOSTB", "reason": "operator investigation"})
        planned = self.preview()
        self.assertEqual(planned.returncode, 0, planned.stderr)
        self.assertFalse((self.directory / "leases.sqlite3").exists())
        self.assertEqual(json.loads(planned.stdout)["unresolved_devices"], ["HOSTA"])
        applied = migrate(self.state, ledger_dir=self.ledgers, dry_run=False)
        self.assertEqual(applied["blocked_devices"], ["HOSTB"])
        self.assertEqual(source.read_text(), content)
        authority = LeaseStore(self.directory, legacy_dir=self.ledgers)
        self.assertEqual(authority.current("HOSTA")["lease_id"], claim["lease_id"])
        self.assertTrue(authority.current("HOSTA")["suspect"])
        self.assertEqual(authority.block("HOSTB")["reason"], "operator investigation")
        self.assertIn("# Legacy audit", [event.get("text") for event in authority.history()])
        for label in ("HOSTA", "HOSTB"):
            with self.assertRaises(LeaseBusy):
                authority.claim({"lease_id": "b" * 32, "device": label})
        self.assertEqual(migrate(self.state, ledger_dir=self.ledgers, dry_run=False), applied)

    def test_import_refuses_a_still_held_legacy_ledger(self):
        source = self.ledgers / "DEVICE_ACCESS_HOSTA.md"
        with source.open("w") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, "drain not verified.*HOSTA"):
                migrate(self.state, ledger_dir=self.ledgers, dry_run=False)
        self.assertFalse((self.directory / "leases.sqlite3").exists())

    def test_unmatched_text_claim_blocks_without_inventing_a_lease_id(self):
        (self.ledgers / "DEVICE_ACCESS_HOSTA.md").write_text(
            "- 2026-09-20T11:00:00Z CLAIM owner=fixture scope=read-only\n")
        report = migrate(self.state, ledger_dir=self.ledgers, dry_run=False)
        self.assertEqual(report["blocked_devices"], ["HOSTA"])
        authority = LeaseStore(self.directory)
        self.assertIsNone(authority.current("HOSTA"))
        self.assertEqual(authority.block("HOSTA")["reason"], "unmatched legacy text claim")

    def test_explicit_nonstandard_ledger_uses_its_declared_label(self):
        source = self.state.parent / "old-reservations.txt"
        source.write_text("2026-09-20T11:00:00Z CLAIM owner=fixture scope=test\n")
        with self.assertRaisesRegex(ValueError, "explicit migration"):
            LeaseStore(self.directory, legacy_paths=[source])
        options = [f"HOSTA={source.resolve()}"]
        with source.open() as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            with self.assertRaisesRegex(ValueError, "drain not verified.*HOSTA"):
                migrate(self.state, ledger_dir=self.ledgers, legacy_ledgers=options, dry_run=True)
        result = migrate(self.state, ledger_dir=self.ledgers, legacy_ledgers=options, dry_run=False)
        self.assertEqual(result["blocked_devices"], ["HOSTA"])
        self.assertIsNotNone(LeaseStore(self.directory, legacy_paths=[source]).block("HOSTA"))


if __name__ == "__main__":
    unittest.main()
