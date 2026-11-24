"""Deterministic scheduling/cache tests; never collect a host or open a transport."""
from concurrent.futures import Future
from datetime import datetime, timezone
import signal
import tempfile
import threading
import unittest
from unittest.mock import patch

from switchyard.leases import LeaseBusy
from switchyard.monitoring import Monitor, _stop_signals
from switchyard.observations import ObservationCache


def configs(count=1):
    return {f"host-{i}": {"host_id": f"host-{i}", "transport": "local", "expected_hostname": f"host-{i}",
                         "monitor": {"fast_seconds": 10, "storage_seconds": 60, "inventory_seconds": 300}}
            for i in range(count)}


class ImmediateExecutor:
    """No background timing: a scheduler test explicitly advances its clock."""
    def __init__(self, *, max_workers, **kwargs):
        if max_workers != 2:
            raise AssertionError("worker bound changed")

    def submit(self, function, *args):
        future = Future()
        try:
            future.set_result(function(*args))
        except Exception as error:
            future.set_exception(error)
        return future

    def shutdown(self, **kwargs):
        pass


class MonitoringTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = 1000.0
        self.cache = ObservationCache(self.temp.name, "test", clock=lambda: self.now)

    def run_clocked(self, monitor, sample, cycles):
        def wait(wake, stop, seconds):
            self.now += seconds
            wake.clear()
        with patch("switchyard.monitoring.ThreadPoolExecutor", ImmediateExecutor), \
             patch("switchyard.monitoring.time.monotonic", side_effect=lambda: self.now), \
             patch.object(monitor, "_sample", side_effect=sample), patch.object(monitor, "_wait", side_effect=wait):
            monitor.run(max_cycles=cycles)

    def test_constructor_and_configuration_never_claim_running(self):
        monitor = Monitor(self.cache, configs())
        self.assertEqual(self.cache.read_monitor()["state"], "disabled")
        self.cache.configure_monitor(configs())
        self.assertEqual(self.cache.read_monitor()["state"], "stopped")
        self.assertEqual(self.cache.read_monitor()["hosts"][0]["fast_seconds"], 10)
        revision = self.cache.revision()
        self.cache.configure_monitor(configs())
        self.assertEqual(self.cache.revision(), revision)
        with patch.object(monitor, "_sample", side_effect=AssertionError("zero cycles collected")):
            monitor.run(max_cycles=0)
        self.assertEqual(self.cache.read_monitor()["state"], "stopped")

    def test_sample_uses_cache_lane_and_passes_previous_without_transport(self):
        record = configs()["host-0"]
        at = datetime.fromtimestamp(self.now, timezone.utc).isoformat()
        value = {"schema_version": 1, "host_id": "host-0", "collector": "linux-v1", "observed_at": at,
                 "host": {"hostname": "host-0", "os": "Linux", "distribution": None, "architecture": "x86_64"},
                 "cpu": {"model": None, "logical_count": 2, "utilization_percent": None,
                         "sample_seconds": None, "load_1m": None},
                 "memory": dict.fromkeys(("total_bytes", "available_bytes", "swap_total_bytes", "swap_free_bytes")),
                 "gpus": [], "storage": {"devices": [], "filesystems": []}, "workloads": [],
                 "coverage": [{"scope": "cpu", "status": "partial", "message": ""}], "warnings": []}
        monitor = Monitor(self.cache, configs())
        with patch("switchyard.monitoring.collector.collect_host", return_value=value) as collect:
            self.assertEqual(monitor._sample("host-0", "fast")[0], "partial")
            collect.assert_called_once_with(record, mode="fast", previous=None, state_dir=self.cache.directory)
            saved = self.cache.read("host-0")["snapshot"]
            self.now += 10
            self.assertEqual(monitor._sample("host-0", "fast")[0], "partial")
            self.assertEqual(collect.call_args.kwargs["previous"], saved)
            self.assertEqual(collect.call_args.kwargs["state_dir"], self.cache.directory)
        self.assertEqual(self.cache.read("host-0")["retry_after_seconds"], 0)

    def test_missed_deadlines_are_skipped_instead_of_caught_up(self):
        calls = []
        def sample(host_id, lane):
            calls.append((self.now, lane))
            self.now += 120
            return "success", 120, None
        self.run_clocked(Monitor(self.cache, configs()), sample, 5)
        for lane, interval in (("fast", 10), ("storage", 60), ("inventory", 300)):
            times = [at for at, sampled in calls if sampled == lane]
            self.assertTrue(all(b - a >= 120 + interval for a, b in zip(times, times[1:])))

    def test_inventory_subsumes_and_storage_does_not_starve_fast(self):
        calls = []
        def sample(host_id, lane):
            calls.append((self.now, lane))
            return "partial", 0.2, None
        self.run_clocked(Monitor(self.cache, configs()), sample, 10)
        self.assertEqual(calls[0][1], "inventory")
        self.assertEqual(calls[1][1], "fast")
        storage = next(i for i, (_, lane) in enumerate(calls) if lane == "storage")
        self.assertEqual(calls[storage + 1][1], "fast")
        self.assertLessEqual(calls[storage + 1][0] - calls[storage][0], 15)
        status = self.cache.read_monitor()
        self.assertEqual(status["state"], "stopped")
        self.assertEqual(status["hosts"][0]["last_status"], "partial")
        self.assertIsNone(status["hosts"][0]["next_due_at"])

    def test_error_backoff_caps_and_partial_resets_transport_failure_count(self):
        calls = []
        outcomes = iter(["error"] * 8 + ["partial", "error", "success"])
        def sample(host_id, lane):
            calls.append(self.now)
            return next(outcomes), 0.1, None
        self.run_clocked(Monitor(self.cache, configs()), sample, 11)
        gaps = [b - a for a, b in zip(calls, calls[1:])]
        for actual, minimum in zip(gaps[:8], (10, 20, 40, 80, 160, 300, 300, 300)):
            self.assertGreaterEqual(actual, minimum)
            self.assertLessEqual(actual, minimum + 5.01)
        # Successful partial inventory resets backoff, then the next failure
        # restarts at 10 rather than continuing the capped error sequence.
        self.assertLess(gaps[8], 20)
        self.assertLess(gaps[9], 20)

    def test_busy_host_has_bounded_retry_not_error_backoff(self):
        calls = []
        def sample(host_id, lane):
            calls.append(self.now)
            return "busy", 0.1, None
        self.run_clocked(Monitor(self.cache, configs()), sample, 3)
        self.assertTrue(all(5 <= b - a <= 10.01 for a, b in zip(calls, calls[1:])))

    def test_cooldown_resumes_when_persisted_cooldown_expires(self):
        # A restarted monitor finds inventory cooling down from the previous process's
        # attempt; it must retry when that cooldown ends, not a full interval later.
        calls = []
        def sample(host_id, lane):
            calls.append((self.now, lane))
            return ("cooldown", 0.1, 30.0) if len(calls) == 1 else ("success", 0.1, None)
        self.run_clocked(Monitor(self.cache, configs()), sample, 6)
        inventory = [at for at, lane in calls if lane == "inventory"]
        self.assertGreaterEqual(len(inventory), 2)
        # The clocked harness observes completion after one 5 s heartbeat wait; the
        # regression being guarded is a full 300 s interval.
        self.assertLessEqual(inventory[1] - inventory[0], 35.01)

    def test_one_leader_and_config_reads_do_not_replace_live_status(self):
        self.cache.configure_monitor(configs())
        status = self.cache.read_monitor()
        status.update(state="running", heartbeat_at=datetime.fromtimestamp(self.now, timezone.utc).isoformat())
        self.cache.save_monitor(status)
        other = ObservationCache(self.temp.name, "test", clock=lambda: self.now)
        with self.cache.monitor_leader():
            revision = self.cache.revision()
            with self.assertRaises(LeaseBusy):
                Monitor(other, configs()).run(max_cycles=1)
            other.configure_monitor(configs(2))
            self.assertEqual(other.revision(), revision)
        self.assertEqual(self.cache.read_monitor()["state"], "running")
        self.cache.configure_monitor(configs())
        self.assertEqual(self.cache.read_monitor()["state"], "running")
        self.assertEqual(self.cache.revision(), revision)

    def test_expired_heartbeat_changes_revision_but_ordinary_age_does_not(self):
        status = {"state": "running", "heartbeat_at": datetime.fromtimestamp(self.now, timezone.utc).isoformat(),
                  "hosts": [], "message": "fixture"}
        self.cache.save_monitor(status)
        revision = self.cache.revision()
        self.now += 10
        self.assertEqual(self.cache.revision(), revision)
        self.now += 21
        expired = self.cache.revision()
        self.assertNotEqual(expired, revision)
        self.assertEqual(self.cache.read_monitor()["state"], "unavailable")
        self.now += 100
        self.assertEqual(self.cache.revision(), expired)

    def test_two_workers_no_backlog_shutdown_waits_and_releases_leader(self):
        entered = [threading.Event(), threading.Event()]
        release = threading.Event()
        stop = threading.Event()
        calls = []
        errors = []
        mutex = threading.Lock()
        monitor = Monitor(self.cache, configs(4))
        def sample(host_id, lane):
            with mutex:
                index = len(calls)
                calls.append(host_id)
                if index >= 2:
                    raise AssertionError("queued work dispatched")
            entered[index].set()
            if not release.wait(3):
                raise AssertionError("shutdown coordination timed out")
            return "success", 0.2, None
        def run():
            try:
                monitor.run(stop_event=stop)
            except BaseException as error:
                errors.append(error)
        with patch.object(monitor, "_sample", side_effect=sample):
            thread = threading.Thread(target=run)
            thread.start()
            try:
                self.assertTrue(all(event.wait(2) for event in entered))
                stop.set()
                self.assertTrue(thread.is_alive())
                with self.assertRaises(LeaseBusy):
                    with self.cache.monitor_leader():
                        pass
            finally:
                stop.set()
                release.set()
                thread.join(3)
            self.assertFalse(thread.is_alive())
        self.assertFalse(errors)
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.cache.read_monitor()["state"], "stopped")
        with self.cache.monitor_leader():
            pass

    def test_supervisor_signals_request_shutdown_and_restore_handlers(self):
        stop = threading.Event()
        original = {signal.SIGINT: object(), signal.SIGTERM: object()}
        installed = dict(original)
        with patch("switchyard.monitoring.signal.getsignal", side_effect=lambda number: installed[number]), \
             patch("switchyard.monitoring.signal.signal", side_effect=lambda number, handler: installed.__setitem__(number, handler)):
            with _stop_signals(stop):
                installed[signal.SIGTERM](signal.SIGTERM, None)
                self.assertTrue(stop.is_set())
            self.assertEqual(installed, original)

    def test_invalid_intervals_and_cycles_fail_before_collection(self):
        for value in (True, 0, 9, 86401):
            records = configs()
            records["host-0"]["monitor"]["fast_seconds"] = value
            with self.assertRaises(ValueError):
                Monitor(self.cache, records)
        monitor = Monitor(self.cache, configs())
        for cycles in (True, -1, 1.5):
            with self.assertRaises(ValueError):
                monitor.run(max_cycles=cycles)


if __name__ == "__main__":
    unittest.main()
