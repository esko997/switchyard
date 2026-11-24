"""Process-shared observation cache. Reads never collect; refresh is explicit."""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
from typing import Callable

from .leases import LeaseBusy
from .models import Snapshot, timestamp

TTL_SECONDS = 120
COOLDOWN_SECONDS = 60
LANE_MINIMUMS = {"manual": 60, "fast": 10, "storage": 60, "inventory": 300}
MONITOR_EXPIRY_SECONDS = 30


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def age(value: str, now: float) -> float:
    return max(0.0, now - timestamp(value).timestamp())


def merge_snapshot(previous: dict | None, current: dict) -> dict:
    """A batch owns its reported scopes, not every cached resource on the host."""
    previous = previous or {}
    old_at = previous.get("observed_at")
    at = current["observed_at"]
    incoming = {entry["scope"]: entry for entry in current["coverage"]}
    complete = {scope for scope, entry in incoming.items() if entry["status"] == "complete"}
    merged = dict(current)
    for family in ("workloads", "artifacts"):
        records = {record["id"]: record for record in previous.get(family, [])
                   if ("paseo" if record["backend"] == "paseo" else f"{record['backend']}:{record['scope']}") not in complete}
        records.update({record["id"]: record for record in current.get(family, [])})
        merged[family] = list(records.values())
    coverage = {entry["scope"]: {**entry, "observed_at": entry.get("observed_at") or old_at}
                for entry in previous.get("coverage", [])}
    coverage.update({scope: {**entry, "observed_at": entry.get("observed_at") or at}
                     for scope, entry in incoming.items()})
    merged["coverage"] = list(coverage.values())
    resource_times = {}
    previous_scopes = {entry["scope"]: entry for entry in previous.get("coverage", [])}
    for resource in ("host", "cpu", "memory", "gpus", "storage", "paseo"):
        owned = resource == "host" or resource in incoming and incoming[resource]["status"] != "unavailable"
        if owned:
            resource_times[resource] = current.get("resource_observed_at", {}).get(resource, at)
        elif resource in previous:
            merged[resource] = previous[resource]
            old_time = previous.get("resource_observed_at", {}).get(resource)
            if old_time is None and previous_scopes.get(resource, {}).get("status") in {"complete", "partial"}:
                old_time = old_at
            if old_time is not None:
                resource_times[resource] = old_time
    merged["resource_observed_at"] = resource_times
    return Snapshot.model_validate(merged).model_dump()


class ObservationCache:
    def __init__(self, directory: str | Path, namespace: str, *, clock: Callable[[], float] = time.time):
        self.directory = Path(directory).expanduser()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("Observation state directory must be owned by you and mode 0700")
        self.directory = self.directory.resolve()
        self.path = self.directory / "observations.sqlite3"
        if self.path.is_symlink():
            raise ValueError("Observation database cannot be a symlink")
        self.namespace = namespace
        self.clock = clock
        self.authorities = {}
        self.on_success = None
        self.authority_for_config = None
        with self.connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("""CREATE TABLE IF NOT EXISTS observations (
                namespace TEXT NOT NULL, host_id TEXT NOT NULL,
                snapshot TEXT, attempt TEXT, attempted_at REAL,
                PRIMARY KEY(namespace, host_id))""")
            legacy = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='collection_lanes'").fetchone() is None
            connection.execute("""CREATE TABLE IF NOT EXISTS collection_lanes (
                namespace TEXT NOT NULL, host_id TEXT NOT NULL, lane TEXT NOT NULL,
                attempted_at REAL NOT NULL, PRIMARY KEY(namespace,host_id,lane))""")
            connection.execute("""CREATE TABLE IF NOT EXISTS cache_state (
                namespace TEXT PRIMARY KEY, revision INTEGER NOT NULL DEFAULT 0,
                monitor TEXT)""")
            connection.execute("INSERT OR IGNORE INTO cache_state(namespace) VALUES(?)", (self.namespace,))
            # Preserve the pre-lane manual cooldown when opening an existing cache.
            if legacy:
                connection.execute("""INSERT OR IGNORE INTO collection_lanes
                    SELECT namespace,host_id,'manual',attempted_at FROM observations
                    WHERE attempted_at IS NOT NULL""")
            for table in ("observations", "collection_lanes"):
                if "authority" not in {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}:
                    connection.execute(f"ALTER TABLE {table} ADD COLUMN authority TEXT")

    def configure_authorities(self, authorities):
        self.authorities = dict(authorities)

    @contextmanager
    def connection(self):
        connection = sqlite3.connect(self.path, timeout=1)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def read(self, host_id: str) -> dict:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT snapshot,attempt,attempted_at,authority FROM observations WHERE namespace=? AND host_id=?",
                (self.namespace, host_id)).fetchone()
            manual = connection.execute(
                "SELECT attempted_at,authority FROM collection_lanes WHERE namespace=? AND host_id=? AND lane='manual'",
                (self.namespace, host_id)).fetchone()
        current_authority = self.authorities.get(host_id)
        if row and row[3] != current_authority:
            row = None
        if manual and manual[1] != current_authority:
            manual = None
        now = self.clock()
        snapshot = json.loads(row[0]) if row and row[0] else None
        attempt = json.loads(row[1]) if row and row[1] else None
        # A crashed collector must not look permanently in progress.
        if attempt and attempt["status"] == "collecting" and now - row[2] > 30:
            attempt = {**attempt, "status": "error", "message": "Collector interrupted; previous evidence retained."}
        seconds = age(snapshot["observed_at"], now) if snapshot else None
        return {
            "snapshot": snapshot,
            "freshness": "never" if seconds is None else "fresh" if seconds < TTL_SECONDS else "stale",
            "age_seconds": seconds,
            "last_attempt": attempt,
            "retry_after_seconds": max(0, COOLDOWN_SECONDS - (now - manual[0])) if manual else 0,
        }

    def _save(self, host_id: str, *, status: str, message: str, snapshot: dict | None = None, lane="manual", authority=None):
        now = self.clock()
        attempt = json.dumps({"status": status, "message": message, "lane": lane,
                              "at": datetime.fromtimestamp(now, timezone.utc).isoformat()})
        authority = self.authorities.get(host_id) if authority is None else authority
        with self.connection() as connection:
            connection.execute("""INSERT INTO observations(namespace,host_id,snapshot,attempt,attempted_at,authority)
                VALUES(?,?,?,?,?,?) ON CONFLICT(namespace,host_id) DO UPDATE SET
                snapshot=CASE WHEN observations.authority IS excluded.authority THEN COALESCE(excluded.snapshot,observations.snapshot) ELSE excluded.snapshot END,
                attempt=excluded.attempt,attempted_at=excluded.attempted_at,authority=excluded.authority""",
                (self.namespace, host_id, json.dumps(snapshot, allow_nan=False) if snapshot is not None else None, attempt, now, authority))
            if lane != "manual" and status in {"error", "busy"}:
                connection.execute("DELETE FROM collection_lanes WHERE namespace=? AND host_id=? AND lane=?",
                                   (self.namespace, host_id, lane))
            else:
                connection.execute("""INSERT INTO collection_lanes(namespace,host_id,lane,attempted_at,authority) VALUES(?,?,?,?,?)
                    ON CONFLICT(namespace,host_id,lane) DO UPDATE SET attempted_at=excluded.attempted_at,authority=excluded.authority""",
                    (self.namespace, host_id, lane, now, authority))
            connection.execute("UPDATE cache_state SET revision=revision+1 WHERE namespace=?", (self.namespace,))

    def refresh(self, host_id: str, config: dict, collector: Callable[[dict], dict], *, lane="manual") -> dict:
        # The local lock is shared across web, CLI and MCP, and held across cache
        # lookup, device lease acquisition, transport teardown and result commit.
        if lane not in LANE_MINIMUMS:
            raise ValueError("Unknown internal collection lane")
        authority = self.authority_for_config(config) if self.authority_for_config else self.authorities.get(host_id)
        key = hashlib.sha256(host_id.encode()).hexdigest()
        path = self.directory / f"collect-{key}.lock"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        locked = False
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                result = self.read(host_id)
                # Do not overwrite the active collector's persisted outcome.
                result["last_attempt"] = {"status": "busy", "at": now_iso(),
                                          "message": "A collection is already in progress; cached evidence returned."}
                return result
            locked = True
            before = self.read(host_id)
            with self.connection() as connection:
                last = connection.execute(
                    "SELECT attempted_at,authority FROM collection_lanes WHERE namespace=? AND host_id=? AND lane=?",
                    (self.namespace, host_id, lane)).fetchone()
            interval = LANE_MINIMUMS[lane]
            if lane != "manual":
                interval = max(interval, config.get("monitor", {}).get(lane + "_seconds", interval))
            if last and last[1] == authority and self.clock() - last[0] < interval:
                return {**before, "last_attempt": {"status": "cooldown", "lane": lane,
                        "at": datetime.fromtimestamp(last[0], timezone.utc).isoformat(),
                        "message": "This collection lane is cooling down; cached evidence returned."}}
            self._save(host_id, status="collecting", lane=lane, authority=authority, message="Bounded read-only collection in progress.")
            try:
                snapshot = Snapshot.model_validate(collector(config)).model_dump()
                if snapshot["host_id"] != host_id:
                    raise ValueError("Collector returned a different host identity")
                if snapshot["host"]["hostname"] != config["expected_hostname"]:
                    raise ValueError("Collector hostname mismatch")
                if timestamp(snapshot["observed_at"]).timestamp() > self.clock() + 30:
                    raise ValueError("Collector timestamp is in the future")
                merged = merge_snapshot(before["snapshot"], snapshot)
                partial = any(c["status"] != "complete" for c in snapshot["coverage"])
                self._save(host_id, status="partial" if partial else "success",
                           message="Read-only observation saved; inspect scope coverage.", snapshot=merged, lane=lane, authority=authority)
                if self.on_success is not None:
                    self.on_success(host_id, authority)
            except LeaseBusy:
                self._save(host_id, status="busy", lane=lane, authority=authority, message="Device lease is busy; no observation performed.")
            except Exception as error:
                # Do not echo remote stderr, host paths, authentication material or
                # arbitrary exceptions into the browser/model interface.
                self._save(host_id, status="error", lane=lane, authority=authority, message=f"Collection failed ({type(error).__name__}); previous evidence retained. Check collector configuration and host access.")
            return self.read(host_id)
        finally:
            if locked:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    @contextmanager
    def monitor_leader(self):
        key = hashlib.sha256(self.namespace.encode()).hexdigest()
        path = self.directory / f"monitor-{key}.lock"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise LeaseBusy("A monitor already owns this cache namespace") from error
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def save_monitor(self, status: dict):
        encoded = json.dumps(status, allow_nan=False, sort_keys=True)
        with self.connection() as connection:
            connection.execute("""UPDATE cache_state SET monitor=?,revision=revision+1
                WHERE namespace=? AND (monitor IS NULL OR monitor!=?)""", (encoded, self.namespace, encoded))

    def configure_monitor(self, configs: dict):
        """Advertise opt-in intervals without starting or impersonating a monitor."""
        try:
            with self.monitor_leader():
                status = self.read_monitor()
                hosts = [{"host_id": host_id, **config["monitor"], "next_due_at": None,
                          "last_duration_seconds": None, "last_status": None}
                         for host_id, config in sorted(configs.items()) if "monitor" in config]
                old = {host["host_id"]: host for host in status["hosts"]}
                fields = ("host_id", "fast_seconds", "storage_seconds", "inventory_seconds")
                if [{key: host[key] for key in fields} for host in status["hosts"]] == [
                        {key: host[key] for key in fields} for host in hosts]:
                    return
                for host in hosts:
                    for field in ("last_duration_seconds", "last_status"):
                        host[field] = old.get(host["host_id"], {}).get(field)
                state = status["state"]
                if not hosts:
                    state = "disabled"
                elif state == "disabled":
                    state = "stopped"
                self.save_monitor({**status, "hosts": hosts, "state": state})
        except LeaseBusy:
            pass  # A live leader exclusively owns status, including intervals.

    def read_monitor(self) -> dict:
        with self.connection() as connection:
            row = connection.execute("SELECT monitor FROM cache_state WHERE namespace=?", (self.namespace,)).fetchone()
        if not row or not row[0]:
            return {"state": "disabled", "heartbeat_at": None, "hosts": [],
                    "message": "Automatic monitoring has not been started."}
        status = json.loads(row[0])
        if status["state"] == "running" and (
                not status["heartbeat_at"] or age(status["heartbeat_at"], self.clock()) > MONITOR_EXPIRY_SECONDS):
            status.update(state="unavailable", message="Monitor heartbeat expired; cached evidence is retained.")
        return status

    def revision(self) -> str:
        with self.connection() as connection:
            row = connection.execute("SELECT revision FROM cache_state WHERE namespace=?", (self.namespace,)).fetchone()
        # Expiration is a lifecycle transition, unlike ordinary sample aging.
        return f"{row[0]}:{self.read_monitor()['state']}"
