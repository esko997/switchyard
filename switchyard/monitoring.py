"""Explicit, bounded read-only monitoring. Importing or reading never starts it."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import signal
import threading
import time

from . import collector

INTERVALS = {"fast": 10, "storage": 60, "inventory": 300}
HEARTBEAT_SECONDS = 5


@contextmanager
def _stop_signals(stop):
    """A supervised CLI SIGTERM must unwind collectors, not orphan transports."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = {}
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, lambda number, frame: stop.set())
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


class Monitor:
    def __init__(self, cache, configs):
        self.cache = cache
        self._config_source = configs if callable(configs) else lambda: configs
        self.configs = self._load_configs()

    def _load_configs(self):
        configs = deepcopy(self._config_source())
        for host_id, config in configs.items():
            intervals = config.get("monitor")
            if config.get("transport") == "adb" or config.get("host_id") != host_id:
                raise ValueError("Monitoring requires configured Linux hosts")
            if not isinstance(intervals, dict) or set(intervals) != {lane + "_seconds" for lane in INTERVALS}:
                raise ValueError("Monitoring requires explicit intervals")
            if any(type(intervals[lane + "_seconds"]) is not int or
                   not minimum <= intervals[lane + "_seconds"] <= 86400
                   for lane, minimum in INTERVALS.items()):
                raise ValueError("Invalid monitoring interval")
        return configs

    def _sample(self, host_id, lane):
        started = time.monotonic()
        config = self.configs[host_id]
        mode = "full" if lane == "inventory" else lane
        result = self.cache.refresh(host_id, config, lambda record: collector.collect_host(
            record, mode=mode, previous=self.cache.read(host_id)["snapshot"], state_dir=self.cache.directory), lane=lane)
        attempt = result["last_attempt"]
        remaining = None
        if attempt["status"] == "cooldown":
            # Resume when the persisted cooldown expires, not a full interval from now:
            # a restart must not delay inventory by up to two intervals.
            elapsed = self.cache.clock() - datetime.fromisoformat(attempt["at"]).timestamp()
            remaining = min(config["monitor"][lane + "_seconds"], max(1.0, config["monitor"][lane + "_seconds"] - elapsed))
        return attempt["status"], max(0.0, time.monotonic() - started), remaining

    @staticmethod
    def _wait(wake, stop, seconds):
        # Completion callbacks wake immediately; the bounded wait also notices an
        # externally supplied Event without a detached watcher thread.
        if not stop.is_set():
            wake.wait(min(max(seconds, 0.001), 0.5))
        wake.clear()

    def run(self, *, stop_event=None, max_cycles=None):
        """Run until stopped; max_cycles bounds dispatch batches, not host count.

        Each batch submits only currently free worker slots. Missed deadlines are
        skipped, never queued for catch-up. Shutdown joins all bounded collectors.
        A second leader raises LeaseBusy without touching the first one's status.
        """
        if max_cycles is not None and (type(max_cycles) is not int or max_cycles < 0):
            raise ValueError("max_cycles must be a nonnegative integer")
        stop = stop_event if stop_event is not None else threading.Event()
        wake = threading.Event()
        with self.cache.monitor_leader(), _stop_signals(stop):
            now = time.monotonic()
            states = {host_id: {"due": {lane: now for lane in INTERVALS}, "retry": now,
                               "failures": 0, "duration": None, "status": None}
                      for host_id in self.configs}
            active = {}
            cycles = 0
            heartbeat = now
            running = False

            def publish(state, message):
                monotonic = time.monotonic()
                wall = self.cache.clock()
                hosts = []
                for host_id, config in sorted(self.configs.items()):
                    item = states[host_id]
                    due = max(item["retry"], min(item["due"].values()))
                    hosts.append({"host_id": host_id, **config["monitor"],
                                  "next_due_at": None if state != "running" or host_id in active else
                                  datetime.fromtimestamp(wall + max(0, due - monotonic), timezone.utc).isoformat(),
                                  "last_duration_seconds": item["duration"], "last_status": item["status"]})
                self.cache.save_monitor({"state": state,
                    "heartbeat_at": datetime.fromtimestamp(wall, timezone.utc).isoformat() if running else None,
                    "hosts": hosts, "message": message})

            def finish(host_id, future, lane):
                item = states[host_id]
                completed = time.monotonic()
                remaining = None
                try:
                    status, duration, remaining = future.result()
                except Exception:
                    status, duration = "error", None
                item.update(status=status, duration=duration)
                if status in {"success", "partial"}:
                    item.update(failures=0, retry=completed)
                    lanes = INTERVALS if lane == "inventory" else (lane,)
                    for sampled in lanes:
                        item["due"][sampled] = completed + self.configs[host_id]["monitor"][sampled + "_seconds"]
                elif status == "error":
                    item["failures"] += 1
                    item["retry"] = completed + min(300, 10 * 2 ** min(item["failures"] - 1, 5))
                elif status == "cooldown":
                    item["due"][lane] = completed + (remaining if remaining is not None else self.configs[host_id]["monitor"][lane + "_seconds"])
                else:
                    item["retry"] = completed + 5

            publish("stopped" if states else "disabled", "Monitor starting; no observation has been dispatched.")
            executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="switchyard-observe")
            try:
                while not stop.is_set() and (max_cycles is None or cycles < max_cycles):
                    changed = False
                    for host_id, (future, lane) in list(active.items()):
                        if future.done():
                            del active[host_id]
                            finish(host_id, future, lane)
                            changed = True
                    latest = self._load_configs()
                    now = time.monotonic()
                    for host_id in set(states) - set(latest) - set(active):
                        del states[host_id]
                        self.configs.pop(host_id, None)
                        changed = True
                    for host_id, config in latest.items():
                        old = self.configs.get(host_id)
                        if host_id not in states:
                            states[host_id] = {"due": {lane: now for lane in INTERVALS}, "retry": now,
                                               "failures": 0, "duration": None, "status": None}
                        elif old and old["monitor"] != config["monitor"]:
                            # Rebase outstanding deadlines, preserving the last sample
                            # rather than clearing cache/cooldowns on cadence edits.
                            for lane in INTERVALS:
                                states[host_id]["due"][lane] += config["monitor"][lane + "_seconds"] - old["monitor"][lane + "_seconds"]
                        if old != config:
                            changed = True
                        self.configs[host_id] = config
                    now = time.monotonic()
                    submitted = False
                    candidates = sorted(set(states) & set(latest), key=lambda host: max(states[host]["retry"], min(states[host]["due"].values())))
                    for host_id in candidates:
                        if len(active) >= 2:
                            break
                        item = states[host_id]
                        if host_id in active or item["retry"] > now:
                            continue
                        lane = next((lane for lane in ("inventory", "storage", "fast") if item["due"][lane] <= now), None)
                        if lane is None:
                            continue
                        future = executor.submit(self._sample, host_id, lane)
                        active[host_id] = (future, lane)
                        future.add_done_callback(lambda finished: wake.set())
                        submitted = running = True
                    if submitted:
                        cycles += 1
                    if changed or submitted or now >= heartbeat:
                        publish("running" if running and states else "stopped" if states else "disabled", "Bounded read-only monitoring; retained scopes keep their original timestamps.")
                        heartbeat = now + HEARTBEAT_SECONDS
                    if max_cycles is not None and cycles >= max_cycles:
                        break
                    deadlines = [heartbeat]
                    deadlines.extend(max(item["retry"], min(item["due"].values()))
                                     for host_id, item in states.items() if host_id not in active)
                    self._wait(wake, stop, max(0.001, min(deadlines) - time.monotonic()))
            finally:
                # No queued work exists: at most two submitted futures, one/host.
                # The collector owns transport termination/reaping and leases.
                executor.shutdown(wait=True, cancel_futures=True)
                for host_id, (future, lane) in active.items():
                    finish(host_id, future, lane)
                active.clear()
                publish("stopped" if states else "disabled", "Automatic monitoring stopped; cached evidence retained.")
