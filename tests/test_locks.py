"""Read-only lock observation against temporary ledgers and synthetic proc trees."""
import datetime
import fcntl
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from switchyard import locks


class DeviceLocksTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.ledgers = self.root / "ledgers"
        self.proc = self.root / "proc"
        self.ledgers.mkdir()
        self.proc.mkdir()
        (self.proc / "locks").write_text("")
        (self.proc / "stat").write_text("cpu 1 2 3 4\nbtime 1700000000\n")
        proc_patch = patch.object(locks, "PROC_ROOT", self.proc)
        proc_patch.start()
        self.addCleanup(proc_patch.stop)

    def ledger(self, name="TESTHANDHELD", content=""):
        path = self.ledgers / ("DEVICE_ACCESS_" + name + ".md")
        path.write_text(content)
        return path

    def hold(self, path, pid=123):
        info = path.stat()
        key = f"{os.major(info.st_dev):02x}:{os.minor(info.st_dev):02x}:{info.st_ino}"
        (self.proc / "locks").write_text(
            f"1: POSIX ADVISORY WRITE 456 {key} 0 EOF\n"
            f"2: FLOCK ADVISORY WRITE {pid} {key} 0 EOF\n"
            f"2: -> FLOCK ADVISORY WRITE 999 {key} 0 EOF\n")

    def process(self, pid, parent=1, environment=b"", command=b"/opt/bin/omp\0--fixture\0"):
        path = self.proc / str(pid)
        path.mkdir()
        (path / "comm").write_text("omp\n")
        (path / "cmdline").write_bytes(command)
        # stat fields 3 onward: state, ppid, then field 22 (start ticks).
        (path / "stat").write_text(f"{pid} (odd (process) name) S {parent} " + "0 " * 17 + "200\n")
        (path / "environ").write_bytes(environment)
        (path / "cwd").symlink_to(self.root)
        return path

    def observe(self):
        return locks.device_locks(self.ledgers, {"agent-1": {"name": "TestAgent", "host_id": "fixture"}})

    def test_device_inode_holder_ancestor_and_environment_allowlist_without_flocking(self):
        path = self.ledger(content='2026-11-22T00:00:00Z RELEASE owner=test scope=fixture\n')
        before = (path.stat().st_ino, path.read_bytes())
        self.hold(path)
        self.process(123, parent=122, environment=b"SECRET=do-not-export\0TOKEN=never-export\0")
        self.process(122, environment=b"PASEO_AGENT_ID=agent-1\0PASEO_AGENT_CWD=/work\0OTHER=hidden-value\0")
        with patch.object(fcntl, "flock", side_effect=AssertionError("Must not acquire locks")):
            result = self.observe()
        row = result["ledgers"][0]
        self.assertEqual(row["state"], "held")
        self.assertEqual(row["device"], "TESTHANDHELD")
        self.assertEqual(row["anomaly"], "held-after-release")
        self.assertEqual(len(row["holders"]), 1)
        holder = row["holders"][0]
        self.assertEqual(holder["pid"], 123)
        self.assertEqual(holder["comm"], "omp")
        self.assertEqual(holder["cmdline"], "omp --fixture")
        self.assertEqual(holder["cwd"], str(self.root))
        self.assertEqual(holder["paseo_agent_id"], "agent-1")
        self.assertEqual(holder["paseo_agent_name"], "TestAgent")
        self.assertIsNotNone(holder["started_at"])
        self.assertEqual((path.stat().st_ino, path.read_bytes()), before)
        for secret in ("do-not-export", "never-export", "hidden-value", "SECRET", "TOKEN", "OTHER"):
            self.assertNotIn(secret, json.dumps(result))

    def test_both_ledger_formats_bounded_tail_and_last_five_entries(self):
        lines = ["x" * 17000, '{"at":"2000-01-01T00:00:00Z","event":"CLAIM","owner":"old"}']
        for index in range(6):
            lines.append(json.dumps({"at": f"2000-01-01T00:0{index}:00Z", "event": "CLAIM",
                                     "owner": str(index), "scope": "json scope", "token": "discard-me"}))
        lines.append('2000-01-01T00:09:00+00:00 RELEASE owner=worker worktree=/tmp/fixture scope=two words')
        self.ledger(content="\n".join(lines))
        row = self.observe()["ledgers"][0]
        self.assertEqual(len(row["last_entries"]), 5)
        self.assertEqual(row["last_entries"][0]["owner"], "2")
        self.assertEqual(row["last_entries"][-1], {"at": "2000-01-01T00:09:00+00:00", "event": "RELEASE",
                                                    "owner": "worker", "scope": "two words"})
        self.assertNotIn("discard-me", json.dumps(row))
        self.assertIsNone(row["anomaly"])

    def test_old_claim_without_holder_only_when_evidence_is_free(self):
        path = self.ledger(content="2000-01-01T00:00:00Z CLAIM owner=fixture scope=crashed\n")
        self.assertEqual(self.observe()["ledgers"][0]["anomaly"], "claim-without-holder")
        path.write_text(datetime.datetime.now(datetime.timezone.utc).isoformat() + " CLAIM owner=recent\n")
        self.assertIsNone(self.observe()["ledgers"][0]["anomaly"])
        path.write_text("2000-01-01T00:00:00Z CLAIM owner=fixture\n")
        (self.proc / "locks").unlink()
        row = self.observe()["ledgers"][0]
        self.assertEqual(row["state"], "unknown")
        self.assertIsNone(row["anomaly"])

    def test_unreadable_or_exited_process_metadata_is_null(self):
        path = self.ledger()
        self.hold(path)
        row = self.observe()["ledgers"][0]
        self.assertEqual(row["state"], "held")
        self.assertEqual(row["holders"][0], {"pid": 123, "comm": None, "cmdline": None, "cwd": None, "started_at": None,
                                              "paseo_agent_id": None, "paseo_agent_name": None, "inferred": False})
        process = self.process(123)
        with patch.object(locks, "_read", side_effect=PermissionError):
            self.assertTrue(all(v is None for k, v in locks._holder(123, None, None, {}).items()
                                if k not in {"pid", "cwd"}))
        with patch.object(locks, "_own_process", return_value=False), \
             patch.object(locks, "_read", side_effect=AssertionError("Other user's proc must not be read")):
            self.assertIsNone(locks._holder(123, None, None, {})["comm"])
        self.assertTrue(process.is_dir())

    def test_six_ancestor_limit_and_cmdline_bound(self):
        path = self.ledger()
        self.hold(path, pid=10)
        for pid in range(10, 18):
            self.process(pid, parent=pid + 1, environment=b"PASEO_AGENT_ID=agent-1\0" if pid == 17 else b"",
                         command=b"/opt/omp\0" + b"x" * 2000)
        holder = self.observe()["ledgers"][0]["holders"][0]
        self.assertIsNone(holder["paseo_agent_id"])
        self.assertEqual(len(holder["cmdline"]), 512)
        (self.proc / "16/environ").write_bytes(b"PASEO_AGENT_ID=agent-1\0")
        self.assertEqual(self.observe()["ledgers"][0]["holders"][0]["paseo_agent_id"], "agent-1")

    def test_regular_files_only_at_most_sixty_four_and_malformed_entries_ignored(self):
        outside = self.root / "outside"
        outside.write_text("2000-01-01T00:00:00Z CLAIM owner=must-not-read\n")
        (self.ledgers / "DEVICE_ACCESS_LINK.md").symlink_to(outside)
        (self.ledgers / "DEVICE_ACCESS_DIRECTORY.md").mkdir()
        for index in range(70):
            self.ledger(str(index), '{"at":"now","event":[]}\nnot an event\n')
        rows = self.observe()["ledgers"]
        self.assertEqual(len(rows), 64)
        self.assertTrue(all(row["last_entries"] == [] for row in rows))
        self.assertNotIn("must-not-read", json.dumps(rows))

    def test_btrfs_superblock_device_needs_descriptor_proof(self):
        # /proc/locks reports the filesystem's superblock device; btrfs st_dev is a per-subvolume
        # anonymous device and inode numbers repeat across subvolumes, so a superblock match counts
        # only when the holder's descriptor table has this exact file open.
        path = self.ledger()
        info = path.stat()
        superblock = (0, 0xFE) if (os.major(info.st_dev), os.minor(info.st_dev)) != (0, 0xFE) else (0, 0xFD)
        (self.proc / "self").mkdir()
        (self.proc / "self" / "mountinfo").write_text(
            f"1 0 {superblock[0]}:{superblock[1]} / {self.root} rw - btrfs /dev/fixture rw\n")
        key = f"{superblock[0]:02x}:{superblock[1]:02x}:{info.st_ino}"
        (self.proc / "locks").write_text(f"1: FLOCK ADVISORY WRITE 123 {key} 0 EOF\n")
        holder = self.process(123)
        (holder / "fd").mkdir()
        (holder / "fd" / "9").symlink_to(path)
        row = self.observe()["ledgers"][0]
        self.assertEqual((row["state"], row["holders"][0]["pid"]), ("held", 123))
        # Same inode number in another subvolume: the holder has a different file open.
        (holder / "fd" / "9").unlink()
        other = self.root / "other-subvolume-file"
        other.write_text("")
        (holder / "fd" / "9").symlink_to(other)
        self.assertEqual(self.observe()["ledgers"][0]["state"], "free")
        # Descriptor table unreadable or holder gone: never report free.
        (holder / "fd" / "9").unlink()
        (holder / "fd").rmdir()
        self.assertEqual(self.observe()["ledgers"][0]["state"], "unknown")

    def test_inherited_descriptor_holder_when_locking_pid_has_exited(self):
        # Seen live with test-agent-cluster with-popos.sh: a subshell took the flock and exited, while the
        # wrapper and its child kept the inherited descriptor. The kernel still reports the dead PID.
        path = self.ledger()
        self.hold(path, pid=500)  # No /proc/500: the locker exited.
        heir = self.process(501, environment=b"PASEO_AGENT_ID=agent-1\0")
        (heir / "fd").mkdir()
        (heir / "fd" / "9").symlink_to(path)
        bystander = self.process(502)
        (bystander / "fd").mkdir()
        (bystander / "fd" / "3").symlink_to(self.root / "proc" / "stat")
        row = self.observe()["ledgers"][0]
        self.assertEqual(row["state"], "held")
        self.assertEqual([(h["pid"], h["inferred"], h["paseo_agent_name"]) for h in row["holders"]], [(501, True, "TestAgent")])
        # Nobody readable still holds it: the exact-device entry keeps it held, attributed only to the kernel PID.
        (heir / "fd" / "9").unlink()
        row = self.observe()["ledgers"][0]
        self.assertEqual((row["state"], [h["pid"] for h in row["holders"]]), ("held", [500]))
