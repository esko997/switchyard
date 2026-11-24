"""SQLite lease authority: process isolation, durable uncertainty and explicit migration."""
from contextlib import closing
from datetime import datetime, timezone
import json
import multiprocessing
import os
from pathlib import Path
import signal
import sqlite3
import tempfile
import unittest
import uuid
from unittest.mock import patch

from switchyard.lease_db import LeaseBusy, LeaseStore, boot_id, process_started
from switchyard.leases import LedgerBroker, held_leases, mark_uncertain


def state(label="HOSTA", **extra):
    return {"lease_id": uuid.uuid4().hex, "device": label, "status": "claimed",
            "owner": "fixture operator", "scope": "isolated lease test", "pid": os.getpid(),
            "pid_started": process_started(os.getpid()), "boot_id": boot_id(), "expires_at": None, **extra}


def contender(root, start, done, connection):
    """A truly independent SQLite connection and OS process, not a thread fixture."""
    try:
        store = LeaseStore(root)
        start.wait(10)
        value = state()
        try:
            store.claim(value)
        except LeaseBusy:
            connection.send(("busy", value["lease_id"]))
        else:
            connection.send(("claimed", value["lease_id"]))
            done.wait(15)
            store.finish(value["lease_id"], reason="fixture command completed")
    except BaseException as error:
        connection.send(("error", repr(error)))
    finally:
        connection.close()


class LeaseDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = LeaseStore(self.root / "leases")

    def broker(self, resources=None):
        return LedgerBroker(resources or {"host-a": self.root / "DEVICE_ACCESS_HOSTA.md"}, state_dir=self.root)

    def process(self, start, done):
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=False)
        process = context.Process(target=contender, args=(self.store.directory, start, done, child))
        process.start()
        child.close()
        self.addCleanup(parent.close)
        def stop():
            if process.is_alive():
                process.kill()
            process.join(5)
        self.addCleanup(stop)
        return process, parent

    def test_concurrent_independent_processes_grant_exactly_one(self):
        context = multiprocessing.get_context("spawn")
        start, done = context.Event(), context.Event()
        children = [self.process(start, done) for _ in range(2)]
        start.set()
        answers = []
        for _, pipe in children:
            self.assertTrue(pipe.poll(10), "contender did not report acquisition")
            answers.append(pipe.recv())
        self.assertEqual(sorted(answer[0] for answer in answers), ["busy", "claimed"])
        self.assertEqual(len([event for event in self.store.history() if event["event"] == "CLAIM"]), 1)
        done.set()
        for process, _ in children:
            process.join(10)
            self.assertEqual(process.exitcode, 0)
        self.assertIsNone(self.store.current("HOSTA"))

    def test_sigkill_leaves_reservation_and_restart_marks_suspect(self):
        context = multiprocessing.get_context("spawn")
        start, done = context.Event(), context.Event()
        process, pipe = self.process(start, done)
        start.set()
        self.assertTrue(pipe.poll(10))
        result, token = pipe.recv()
        self.assertEqual(result, "claimed")
        os.kill(process.pid, signal.SIGKILL)
        process.join(5)
        restarted = LeaseStore(self.store.directory)
        current = restarted.current("HOSTA")
        self.assertEqual(current["lease_id"], token)
        self.assertEqual(current["status"], "suspect")
        self.assertIn("process", current["suspect_cause"])
        with self.assertRaises(LeaseBusy):
            restarted.claim(state())
        self.assertFalse(any(event["event"] == "RELEASE" for event in restarted.history()))

    def test_process_start_alone_cannot_survive_boot_change(self):
        value = state()
        self.store.claim(value)
        with patch("switchyard.lease_db.boot_id", return_value="different-boot"):
            restarted = LeaseStore(self.store.directory)
            self.assertIn("boot", restarted.current("HOSTA")["suspect_cause"])
        self.assertEqual(self.store.current("HOSTA")["status"], "suspect")

    def test_expiry_quarantines_and_never_grants(self):
        now = [100.0]
        store = LeaseStore(self.root / "expiry", clock=lambda: now[0])
        value = state(expires_at=datetime.fromtimestamp(101, timezone.utc).isoformat())
        store.claim(value)
        now[0] = 102.0
        self.assertEqual(store.current("HOSTA")["status"], "suspect")
        with self.assertRaises(LeaseBusy):
            store.claim(state())
        self.assertTrue(store.finish(value["lease_id"], reason="operator verified command ended"))
        store.claim(state())

    def test_mutable_status_does_not_release_reservation(self):
        value = state()
        self.store.claim(value)
        self.store.update(value["lease_id"], lambda row: row.update(status="released", release_requested=True))
        with self.assertRaises(LeaseBusy):
            self.store.claim(state())
        self.assertEqual(self.store.current("HOSTA")["lease_id"], value["lease_id"])
        self.assertTrue(self.store.finish(value["lease_id"], reason="command exit confirmed"))

    def test_stale_completion_and_break_cannot_release_new_grant(self):
        first = state()
        self.store.claim(first)
        self.store.break_device("HOSTA", reason="old operation stopped", operator="operator", attest_stopped="observed its exit", expected_id=first["lease_id"])
        second = state()
        self.store.claim(second)
        self.assertFalse(self.store.finish(first["lease_id"], reason="late callback"))
        self.store.suspect(first["lease_id"], "late uncertainty")
        with self.assertRaises(LeaseBusy):
            self.store.break_device("HOSTA", reason="stale dialog", operator="operator", expected_id=first["lease_id"])
        self.assertEqual(self.store.current("HOSTA")["lease_id"], second["lease_id"])
        self.assertIsNone(self.store.block("HOSTA"))

    def test_block_clear_cas_persists_and_journals(self):
        value = state()
        self.store.claim(value)
        record = self.store.break_device("HOSTA", reason="remote connection lost", operator="operator", expected_id=value["lease_id"])
        self.assertTrue(record["blocked"])
        self.assertIsNone(self.store.current("HOSTA"))
        self.assertEqual(self.store.read(value["lease_id"])["status"], "broken")
        restarted = LeaseStore(self.store.directory)
        self.assertEqual(restarted.block("HOSTA"), record)
        self.assertFalse(restarted.finish(value["lease_id"], reason="late exit"))
        with self.assertRaises(LeaseBusy):
            restarted.claim(state())
        newer = restarted.break_device("HOSTA", reason="updated investigation", operator="operator")
        with self.assertRaises(LeaseBusy):
            restarted.clear("HOSTA", operator="operator", attest_stopped="observed remote stopped", expected_block=record)
        clear = restarted.clear("HOSTA", operator="operator", attest_stopped="observed remote stopped", expected_block=newer)
        self.assertEqual(clear["event"], "CLEAR")
        restarted.claim(state())
        history = restarted.history()
        self.assertEqual(len([event for event in history if event["event"] == "BREAK"]), 2)
        self.assertEqual(len([event for event in history if event["event"] == "CLEAR"]), 1)

    def test_suspect_repeat_remains_reserved(self):
        value = state()
        self.store.claim(value)
        first = self.store.suspect(value["lease_id"], "SSH disconnected")
        second = self.store.suspect(value["lease_id"], "client vanished")
        self.assertEqual(first["suspect_since"], second["suspect_since"])
        self.assertEqual(second["suspect_cause"], "client vanished")
        self.assertEqual(len([event for event in self.store.history() if event["event"] == "SUSPECT"]), 2)
        with self.assertRaises(LeaseBusy):
            self.store.claim(state())

    def test_launch_uncertainty_reserves_preclaim_and_refuses_delayed_holder(self):
        value = state(status="starting", mode="hold")
        self.store.update(value["lease_id"], lambda row: row.update(value), create=True)
        self.store.suspect(value["lease_id"], "systemd launch reply lost")
        self.assertEqual(self.store.current("HOSTA")["status"], "suspect")
        with self.assertRaises((LeaseBusy, ValueError)):
            self.store.claim(value)
        self.assertTrue(self.store.finish(value["lease_id"], reason="holder proven absent"))

    def test_mutable_callbacks_are_atomic_and_identity_is_fixed(self):
        value = state(status="starting")
        self.store.update(value["lease_id"], lambda row: row.update(value), create=True)
        def failing(row):
            row["scope"] = "must roll back"
            raise RuntimeError("callback failed")
        with self.assertRaises(RuntimeError):
            self.store.update(value["lease_id"], failing)
        self.assertEqual(self.store.read(value["lease_id"])["scope"], value["scope"])
        with self.assertRaises(ValueError):
            self.store.update(value["lease_id"], lambda row: row.update(device="HOSTB"))
        self.store.claim({**value, "status": "claimed"})
        with self.assertRaises(FileNotFoundError):
            self.store.read("0" * 32)

    def test_detached_hold_has_no_process_watcher_but_still_has_boot_and_ttl(self):
        now = [100.0]
        store = LeaseStore(self.root / "detached", clock=lambda: now[0])
        value = state(mode="hold", detached=True, pid=None, pid_started=None,
                      expires_at=datetime.fromtimestamp(101, timezone.utc).isoformat())
        store.claim(value)
        self.assertEqual(store.current("HOSTA")["status"], "claimed")
        now[0] = 102.0
        self.assertEqual(store.current("HOSTA")["status"], "suspect")
        other = state("HOSTB", mode="hold", detached=True, pid=None, pid_started=None)
        store.claim(other)
        with patch("switchyard.lease_db.boot_id", return_value="different-boot"):
            self.assertIn("boot", store.current("HOSTB")["suspect_cause"])

    def test_launch_failure_details_remain_compatible_without_changing_identity(self):
        value = state(status="starting")
        self.store.update(value["lease_id"], lambda row: row.update(value), create=True)
        self.assertFalse(self.store.finish(value["lease_id"], reason="not dispatched", outcome="failed",
                                           details={"error": "fixture launch failure", "busy": True,
                                                    "lease_id": "must-not-overwrite"}))
        result = self.store.read(value["lease_id"])
        self.assertEqual(result["lease_id"], value["lease_id"])
        self.assertEqual(result["error"], "fixture launch failure")
        self.assertTrue(result["busy"])
        self.assertEqual(result["status"], "released")

    def test_rows_expose_only_sanitized_public_attribution(self):
        value = state(private_value="PRIVATE_STATE_MARKER")
        self.store.claim(value)
        public = self.store.rows({"HOSTA": None})["ledgers"][0]
        self.assertNotIn("PRIVATE_STATE_MARKER", json.dumps(public))
        self.assertNotIn("pid", public["switchyard_lease"])
        self.assertNotIn("boot_id", public["current"])
        self.assertEqual(set(public["last_entries"][0]), {"at", "event", "owner", "scope"})
        self.store.break_device("HOSTA", reason="fixture break", operator="operator")
        public = self.store.rows({"HOSTA": None})["ledgers"][0]
        self.assertNotIn("PRIVATE_STATE_MARKER", json.dumps(public))
        store = LeaseStore(self.root / "private-history", allow_legacy=True)
        store.import_legacy([], {}, [{"device": "HOSTA", "event": "LEGACY", "text": "PRIVATE_LEGACY_BYTES",
                                     "owner": "owner" + chr(10) + "with control", "at": "2026-11-24T00:00:00+00:00"}])
        self.assertIn("PRIVATE_LEGACY_BYTES", json.dumps(store.history()))
        public = store.rows({"HOSTA": None})
        self.assertNotIn("PRIVATE_LEGACY_BYTES", json.dumps(public))
        self.assertEqual(public["ledgers"][0]["last_entries"][0]["owner"], "owner with control")

    def test_rows_keep_old_shape_and_suspect_is_held(self):
        value = state()
        self.store.claim(value)
        self.store.suspect(value["lease_id"], "uncertain remote outcome")
        self.store.break_device("HOSTB", reason="untracked old operation", operator="operator")
        result = self.store.rows({"HOSTA": "/historical/a", "HOSTB": None})
        held, blocked = result["ledgers"]
        self.assertEqual(held["state"], "held")
        self.assertEqual(held["status"], "suspect")
        self.assertTrue(held["switchyard_lease"]["suspect"])
        self.assertEqual(held["current"]["lease_id"], value["lease_id"])
        self.assertEqual(held["holders"][0]["pid"], os.getpid())
        self.assertTrue(held["last_entries"])
        self.assertEqual(blocked["state"], "free")
        self.assertTrue(blocked["blocked"])

    def test_history_limit_is_per_resource_and_events_are_append_only(self):
        for label in ("HOSTA", "HOSTB"):
            value = state(label)
            self.store.claim(value)
            self.store.finish(value["lease_id"], reason="completed")
        history = self.store.history(limit=1)
        self.assertEqual({event["device"] for event in history}, {"HOSTA", "HOSTB"})
        self.assertTrue(all(event["event"] == "RELEASE" for event in history))
        with closing(sqlite3.connect(self.store.path)) as db:
            for statement in ("UPDATE events SET state='{}'", "DELETE FROM events"):
                with self.assertRaises(sqlite3.IntegrityError):
                    db.execute(statement)

    def test_legacy_files_require_explicit_atomic_import_and_retry_is_idempotent(self):
        source = self.root / "source"
        source.mkdir(mode=0o700)
        directory = self.root / "legacy"
        directory.mkdir(mode=0o700)
        value = state()
        (directory / f"{value['lease_id']}.json").write_text(json.dumps(value))
        (source / "DEVICE_ACCESS_HOSTA.md").write_text("human legacy handoff\n")
        with self.assertRaisesRegex(ValueError, "migration"):
            LeaseStore(directory, legacy_dir=source)
        store = LeaseStore(directory, legacy_dir=source, allow_legacy=True)
        with self.assertRaisesRegex(ValueError, "migration"):
            store.claim(state())
        block = {"device": "HOSTB", "at": "2026-11-24T12:00:00+00:00", "reason": "old break", "operator": "operator"}
        events = [{"device": "HOSTA", "event": "LEGACY", "at": "2026-11-24T11:00:00+00:00", "text": "human legacy handoff"}]
        self.assertTrue(store.import_legacy([value], [block], events))
        self.assertFalse(store.import_legacy([value], [block], events))
        restarted = LeaseStore(directory, legacy_dir=source)
        self.assertEqual(restarted.current("HOSTA")["status"], "suspect")
        self.assertEqual(restarted.block("HOSTB")["reason"], "old break")
        self.assertTrue(any(event.get("text") == "human legacy handoff" for event in restarted.history()))
        with self.assertRaisesRegex(ValueError, "different input"):
            restarted.import_legacy([], [], [])
        for label in ("HOSTA", "HOSTB"):
            with self.assertRaises(LeaseBusy):
                restarted.claim(state(label))

    def test_history_alone_prevents_silent_fresh_start(self):
        source = self.root / "ledgers"
        source.mkdir()
        (source / "DEVICE_ACCESS_HOSTA.md").write_text("historic CLAIM with unknown completion\n")
        with self.assertRaisesRegex(ValueError, "migration"):
            LeaseStore(self.root / "history-only", legacy_dir=source)
        with self.assertRaisesRegex(ValueError, "migration"):
            LedgerBroker({"host-a": source / "DEVICE_ACCESS_HOSTA.md"}, state_dir=self.root / "broker")

    def test_failed_import_rolls_back_all_rows_and_history(self):
        store = LeaseStore(self.root / "import", allow_legacy=True)
        good = state()
        with self.assertRaises(ValueError):
            store.import_legacy([good, {**state(), "device": "invalid label"}], [], [])
        self.assertEqual(store.records(), [])
        self.assertEqual(store.history(), [])
        self.assertTrue(store.import_legacy([good], [], []))

    def test_multiple_unmatched_legacy_ids_quarantine_label(self):
        store = LeaseStore(self.root / "ambiguous", allow_legacy=True)
        values = [state(), state()]
        store.import_legacy(values, {}, [])
        self.assertIsNone(store.current("HOSTA"))
        block = store.block("HOSTA")
        self.assertEqual(set(block["lease_ids"]), {value["lease_id"] for value in values})
        self.assertEqual(len(store.records()), 2)
        with self.assertRaises(LeaseBusy):
            store.claim(state())

    def test_database_and_directory_privacy(self):
        self.assertEqual(self.store.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o600)
        self.store.path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "private"):
            self.store.records()
        self.store.path.chmod(0o600)
        self.store.directory.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "private"):
            LeaseStore(self.store.directory)
        self.store.directory.chmod(0o700)

    def test_symlink_and_hardlinked_databases_are_refused(self):
        link = self.root / "linked"
        link.symlink_to(self.store.directory, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            LeaseStore(link)
        directory = self.root / "hardlink"
        directory.mkdir(mode=0o700)
        os.link(self.store.path, directory / "leases.sqlite3")
        with self.assertRaisesRegex(ValueError, "links"):
            LeaseStore(directory)

    def test_broker_shared_alias_identity_and_receipt_without_fd(self):
        ledger = self.root / "DEVICE_ACCESS_HOSTA.md"
        broker = self.broker({"host-a": ledger, "alias-a": ledger})
        with broker.hold("host-a", owner="operator", scope="fixture", worktree="fixture") as receipt:
            self.assertEqual(set(receipt), {"resource", "lease_id", "release"})
            self.assertEqual(held_leases()[0]["store"].directory, self.root / "leases")
            self.assertIsNone(held_leases()[0]["uncertainty"])
            with self.assertRaises(LeaseBusy):
                with broker.hold("alias-a", owner="operator", scope="fixture", worktree="fixture"):
                    self.fail("alias acquired the same device")
        self.assertEqual(held_leases(), ())
        self.assertIsNone(self.store.current("HOSTA"))
        self.assertFalse(ledger.exists(), "runtime must not recreate flock ledgers")

    def test_broker_exception_is_suspect_unless_completion_is_explicit(self):
        broker = self.broker()
        with self.assertRaisesRegex(RuntimeError, "unknown result"):
            with broker.hold("host-a", owner="operator", scope="fixture", worktree="fixture"):
                raise RuntimeError("unknown result")
        current = self.store.current("HOSTA")
        self.assertEqual(current["status"], "suspect")
        self.store.finish(current["lease_id"], reason="test confirms no work dispatched")
        with self.assertRaisesRegex(RuntimeError, "local validation"):
            with broker.hold("host-a", owner="operator", scope="fixture", worktree="fixture") as receipt:
                receipt["release"].update(outcome="completed", reason="remote command returned")
                raise RuntimeError("local validation")
        self.assertIsNone(self.store.current("HOSTA"))

    def test_swallowed_uncertainty_is_resource_specific_and_stays_suspect(self):
        broker = self.broker({"host-a": self.root / "a", "host-b": self.root / "b"})
        with broker.hold("host-a", owner="operator", scope="fixture", worktree="fixture"):
            with broker.hold("host-b", owner="operator", scope="fixture", worktree="fixture"):
                mark_uncertain("remote reply lost", resource="host-a")
        self.assertEqual(self.store.current("HOSTA")["status"], "suspect")
        self.assertIsNone(self.store.current("HOSTB"))


if __name__ == "__main__":
    unittest.main()
