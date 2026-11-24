"""Shared policy boundary for observation, proposals and explicitly configured operations."""
from copy import deepcopy
import hashlib
from functools import wraps
import json
import os
from pathlib import Path
import re
import threading
import time
from typing import Any

from .backends import BackendRegistry, LocalHostBackend, StoreBackend
from .collector import collect_host, load_config
from .observations import ObservationCache, TTL_SECONDS, age, now_iso
from .grouping import build_groups, load_groups
from .definitions import resolve_definitions, validate_definitions
from .coverage import host_integration
from .planning import assess_recipe
from .broker import Broker
from .workload_store import WorkloadStore
from .workloads import (apply_import, bundle_definition, catalog_workloads, document_sha256, dry_run, export_document,
                        import_plan, links, observed_record, public_import, read_catalog, registered_declaration,
                        registered_rows, seed)

from . import collector, host_registry, locks
from .agent_leases import AgentLeases

IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")


def state_root(state_dir=None) -> Path:
    """Private Switchyard state root (default `$XDG_STATE_HOME/switchyard`)."""
    if state_dir is not None:
        return Path(state_dir)
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "switchyard"


def namespace(catalog_path) -> str:
    """State namespace of one catalog path: registry, observation cache, operations and workload store."""
    return hashlib.sha256(str(Path(catalog_path).resolve()).encode()).hexdigest()


def seed_dry_run(catalog_path, *, state_dir=None):
    """What seeding the workload store would create, read without creating or changing any state file.
    Returns `{"seeded": True, ...}` for a store that is already seeded."""
    import sqlite3
    root = state_root(state_dir)
    space = namespace(catalog_path)
    catalog, catalog_sha256 = read_catalog(catalog_path)
    Service._validate_devices(catalog)
    host_ids = [device["id"] for device in catalog["devices"]]
    registry = root / "registry" / (space + ".sqlite3")
    if registry.exists():
        db = sqlite3.connect(registry.resolve().as_uri() + "?mode=ro", uri=True, timeout=3)
        try:
            if db.execute("SELECT seeded FROM metadata").fetchone()[0]:
                host_ids = [json.loads(row[0])["id"] for row in db.execute("SELECT data FROM hosts ORDER BY rowid")]
        finally:
            db.close()
    return dry_run(root / "operations" / space / "deploy.sqlite3", catalog=catalog, catalog_sha256=catalog_sha256,
                   catalog_path=catalog_path, host_ids=host_ids)


def _text(record: dict, key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > 8192:
        raise ValueError(f"{key} must be nonempty text (at most 8192 characters)")
    return value


def _strings(record: dict, key: str) -> list[str]:
    value = record.get(key)
    if not isinstance(value, list) or any(not isinstance(v, str) or not v.strip() for v in value):
        raise ValueError(f"{key} must be a list of nonempty strings")
    return value


def _records(catalog: dict, key: str) -> list[dict]:
    records = catalog.get(key)
    if not isinstance(records, list) or any(not isinstance(r, dict) for r in records):
        raise ValueError(f"{key} must be a list of objects")
    seen = set()
    for record in records:
        identity = _text(record, "id")
        if not IDENTIFIER.fullmatch(identity) or identity in seen:
            raise ValueError(f"Invalid or duplicate {key} ID: {identity}")
        seen.add(identity)
    return records


def _snapshot_view(method):
    """Keep each public read/operation on one validated workload-store and host-registry snapshot."""
    @wraps(method)
    def call(self, *args, **kwargs):
        with self._snapshot_lock:
            if not self._snapshot_depth:
                self._refresh()
            self._snapshot_depth += 1
            try:
                return method(self, *args, **kwargs)
            finally:
                self._snapshot_depth -= 1
    return call


def _snapshot_preflight(method):
    """Validate the current snapshot before remote I/O without starving cached readers."""
    @wraps(method)
    def call(self, *args, **kwargs):
        with self._snapshot_lock:
            self._refresh()
        return method(self, *args, **kwargs)
    return call


class Service:
    def __init__(self, catalog_path: str | Path, *, state_dir=None, collectors_path=None, operations_path=None):
        self._snapshot_lock = threading.RLock()
        self._snapshot_depth = 0
        self._catalog_path = Path(catalog_path)
        self._collectors_path = collectors_path
        root = state_root(state_dir)
        self._state_dir = root
        self._registry = host_registry.HostRegistry(root, catalog_path)
        # The catalog is a one-time seed: its devices for the host registry, its workloads and groups for the
        # workload store. Validate the seed declarations even when both are authoritative.
        catalog, catalog_sha256 = read_catalog(catalog_path)
        self._validate_devices(catalog)
        if not self._registry.initialized():
            self._registry.seed(self._registry.seed_records(catalog["devices"], load_config(collectors_path)))
        self._registry_state = self._registry.read()
        self._collectors = self._registry_collectors(self._registry_state["hosts"])
        space = namespace(catalog_path)
        # The workload store sits beside the operation journal so the leased workers can journal into it. It is
        # seeded before the operations policy is read: the policy's grants are resolved from its records.
        self._store = WorkloadStore(root / "operations" / space)
        self.backends = BackendRegistry(StoreBackend(self._store), LocalHostBackend())
        if not self._store.seeded():
            seed(self._store, catalog=catalog, catalog_sha256=catalog_sha256, catalog_path=catalog_path,
                 host_ids=[record["id"] for record in self._registry_state["hosts"]])
        self._broker = Broker(operations_path, hosts=self._collectors, state_dir=root / "operations" / space,
                              lease_state_dir=root)
        snapshot = self._read_store()
        self._install_store(self._prepare_store(snapshot), snapshot["revision"])
        self._cache = ObservationCache(root, space)
        self._cache.on_success = self._registry.verify
        self._cache.authority_for_config = self._collection_authority
        self._cache.configure_authorities({record["id"]: host_registry.authority(record) for record in self._registry_state["hosts"]})
        self._cache.configure_monitor({identity: config for identity, config in self._collectors.items() if "monitor" in config})

    @staticmethod
    def _validate_devices(catalog):
        if catalog.get("schema_version") != 1:
            raise ValueError("Expected catalog schema_version 1")
        _text(catalog, "provenance")
        devices = _records(catalog, "devices")
        for device in devices:
            for field in ("name", "platform", "architecture", "provenance", "notes"):
                _text(device, field)
            _strings(device, "capabilities")
            if device.get("access") != "declared-only" or device.get("observed_at") is not None:
                raise ValueError("Declared devices must have declared-only access and null observed_at")

    def _registry_collectors(self, records):
        configs = {}
        for record in records:
            config = record["collector"]
            if config:
                config = deepcopy(config)
                if record["host_keys"]:
                    config["known_hosts"] = str(self._registry.pins_path)
                configs[record["id"]] = collector._validate_config(config)
        return configs

    def _collection_authority(self, config):
        with self._snapshot_lock:
            record = deepcopy(self._host_record(config["host_id"]))
        record["collector"] = {key: value for key, value in config.items() if key != "known_hosts"}
        return host_registry.authority(record)

    def _read_store(self):
        """One consistent read of the workload store: its revision, observed workloads (editor form) and groups."""
        with self._store.transaction() as db:
            return {"revision": self._store.revision(db),
                    "definitions": [bundle_definition(record["data"]) for record in self._store.records(db, "observed")],
                    "groups": self._store.groups(db), "seed": self._store.meta(db, "seed")}

    def _host_ids(self, registry_records=None):
        records = self._registry_state["hosts"] if registry_records is None else registry_records
        return {record["id"] for record in records}

    def _prepare_store(self, snapshot, registry_records=None):
        records = self._registry_state["hosts"] if registry_records is None else registry_records
        devices = [{**{key: record[key] for key in ("id", "name", "platform", "architecture", "capabilities", "provenance", "notes")},
                    "access": "declared-only", "observed_at": None} for record in records]
        ids = {device["id"] for device in devices}
        workloads = validate_definitions(snapshot["definitions"], ids)
        seeded = snapshot["seed"]
        provenance = f"Workload store {self._store.path}" + (
            f", seeded {seeded['seeded_at']} from {seeded['catalog']['path']}" if seeded else "")
        inventory = {"mode": "proposal-only", "provenance": provenance, "devices": devices,
                     "workloads": workloads, "backends": self.backends.describe()}
        return inventory, load_groups({"application_groups": snapshot["groups"]}, ids)

    def _install_store(self, prepared, revision):
        self._inventory, self._groups = prepared
        self._devices = {device["id"]: device for device in self._inventory["devices"]}
        self._workloads = {workload["id"]: workload for workload in self._inventory["workloads"]}
        self._definition_revision = revision

    def _validate_authority(self):
        """The operations policy still resolves: every grant against its workload store record and current hosts."""
        self._broker.policy()

    def _validate_lifecycle_bindings(self, workload_id=None):
        """Adopt only the exact inspected resources named by this definition."""
        inspections = self._broker.lifecycle_inspections()
        definitions = {item["id"]: item for item in self._inventory["workloads"]}
        for operation in self._broker.policy()["workloads"]:
            identity = operation["id"]
            if not operation.get("inspection_required") or (workload_id is not None and identity != workload_id):
                continue
            record = inspections.get(identity)
            if record is None:
                continue  # The broker refuses a plan/execute without current inspection.
            resources = record["inspection"].get("resources", [])
            bindings = definitions[identity]["bindings"]
            if operation["backend"] != "compose":
                bindings = [binding for binding in bindings if binding["role"] == "primary"]
            matched = set()
            for binding in bindings:
                selector = binding["selector"]
                candidates = [resource for resource in resources
                              if resource.get("backend") == binding["backend"]
                              and resource.get("scope") == binding["scope"]
                              and all(resource.get(key) == value for key, value in selector.items())]
                if len(candidates) != 1:
                    raise ValueError("Lifecycle inspection does not uniquely match the defined resource bindings")
                matched.add(candidates[0]["native_id"])
            if not resources or len(matched) != len(resources):
                raise ValueError("Definition must cover the complete adopted lifecycle resource set")

    def _check_protected_changes(self, workloads):
        protected = {workload["id"] for workload in self._broker.policy()["workloads"]}
        protected.update(self._broker.placements())
        definitions = {workload["id"]: workload for workload in workloads}
        for identity in protected & self._workloads.keys():
            previous, current = self._workloads[identity], definitions.get(identity)
            if current is None or any(previous[key] != current[key] for key in
                                      ("device_id", "backend", "kind", "bindings", "recipe", "runtime")):
                raise ValueError("Managed/adopted workload bindings, recipe and runtime cannot change; lifecycle authority is separate")

    def _refresh(self):
        revision = self._store.current_revision()
        state = self._registry.read()
        if revision == self._definition_revision and state["revision"] == self._registry_state["revision"]:
            # Verification is separate from the operator revision.
            self._registry_state = state
            return
        snapshot = self._read_store()
        prepared = self._prepare_store(snapshot, state["hosts"])
        configs = self._registry_collectors(state["hosts"])
        previous = self._broker.hosts
        self._broker.hosts = configs
        try:
            self._validate_authority()
            self._check_protected_changes(prepared[0]["workloads"])
        except BaseException:
            self._broker.hosts = previous
            raise
        self._registry_state, self._collectors = state, configs
        self._install_store(prepared, snapshot["revision"])
        self._cache.configure_authorities({record["id"]: host_registry.authority(record) for record in state["hosts"]})
        self._cache.configure_monitor({identity: config for identity, config in configs.items() if "monitor" in config})

    @_snapshot_view
    def monitoring_configs(self) -> dict:
        """Return live explicit Linux monitoring opt-ins, never start a scheduler."""
        return deepcopy({identity: config for identity, config in self._collectors.items() if "monitor" in config})

    def monitor_context(self):
        return self._cache, self.monitoring_configs

    @property
    def state_dir(self) -> Path:
        """Private Switchyard state root, for backends that keep their own stores beneath it."""
        return self._state_dir

    def ssh_pins_path(self) -> Path:
        """The per-host-ID pinned known_hosts file (`HostKeyAlias=switchyard-<id>`)."""
        return self._registry.pins_path

    def paseo_agent_names(self) -> dict:
        """Cached Paseo agent ID -> {name, host_id}, for lease attribution."""
        return self._paseo_agent_names()

    def _host_record(self, host_id):
        record = next((record for record in self._registry_state["hosts"] if record["id"] == host_id), None)
        if record is None:
            raise ValueError("Unknown registry host ID")
        return record

    @_snapshot_view
    def hosts(self):
        return deepcopy(self._registry_state)

    def _validate_registry(self, records):
        self._prepare_store(self._read_store(), records)  # every workload still names a registry host
        previous = self._broker.hosts
        self._broker.hosts = self._registry_collectors(records)
        try:
            self._validate_authority()
        finally:
            self._broker.hosts = previous

    def _mutate_hosts(self, expected_revision, change, host_id=None):
        self._registry.mutate(expected_revision, change, validate_hosts=self._validate_registry)
        self._refresh()
        result = {"revision": self._registry_state["revision"]}
        if host_id is not None:
            result["host"] = deepcopy(self._host_record(host_id))
        return result

    @_snapshot_view
    def update_host(self, host_id, changes, *, expected_revision, connection=False, allowlists=False):
        if type(connection) is not bool or type(allowlists) is not bool or allowlists and not connection:
            raise ValueError("Allowlists require explicit CLI connection authority")
        allowed = host_registry.DESCRIPTION | (host_registry.CONNECTION if connection else set()) | (host_registry.ALLOWLISTS if allowlists else set())
        if not isinstance(changes, dict) or not changes or set(changes) - allowed:
            raise ValueError("Invalid host changes; host IDs are immutable and connection/allowlist edits need explicit authority")

        def change(records, db):
            record = next((r for r in records if r["id"] == host_id), None)
            if record is None:
                raise ValueError("Unknown registry host ID")
            config = record["collector"]
            edits = set(changes) & host_registry.CONNECTION
            if edits and (not config or config["transport"] != "ssh"):
                raise ValueError("Connection edits require an SSH host; local and ADB connections cannot be edited")
            if config and not record["host_keys"] and any(key in changes and changes[key] != config.get(key, 22 if key == "port" else None) for key in ("target", "port")):
                raise ValueError("Pin this host's key first: Check host key → Pin")
            collector_edits = set(changes) - host_registry.DESCRIPTION
            if collector_edits and config is None:
                raise ValueError("Host has no collector")
            before = {key: config.get(key, 22 if key == "port" and config.get("transport") == "ssh" else None)
                      for key in host_registry.CONNECTION_FIELDS} if config else None
            for key, value in changes.items():
                if key in host_registry.DESCRIPTION:
                    record[key] = deepcopy(value)
                else:
                    config[key] = deepcopy(value)
            after = {key: config.get(key, 22 if key == "port" and config.get("transport") == "ssh" else None)
                     for key in host_registry.CONNECTION_FIELDS} if config else None
            if before != after:
                record["connection_revision"] += 1
        return self._mutate_hosts(expected_revision, change, host_id)

    def _paseo_snapshot(self, host_id):
        snapshot = self._cache.read(host_id)["snapshot"]
        return snapshot.get("paseo") if snapshot else None

    def _paseo_agent_names(self):
        names = {}
        for record in self._registry_state["hosts"]:
            for agent in ((self._paseo_snapshot(record["id"]) or {}).get("agents") or []):
                names[agent["id"]] = {"name": agent.get("name"), "host_id": record["id"]}
        return names

    def _ledger_configs(self):
        """Collector identity hints plus local operation targets."""
        policy = self._broker._configuration()
        return {**self._collectors, **(self._broker.operation_hosts(policy) if policy else {})}

    @_snapshot_view
    def device_locks(self) -> dict:
        """Read the shared reservation state without acquiring a device lease."""
        return self.agent_leases().list()

    @_snapshot_view
    def agent_leases(self):
        """Agent-facing operations on the same authority as the workers."""
        return AgentLeases(collectors=self._ledger_configs(), state_dir=self._state_dir,
                           hosts=[record["id"] for record in self._registry_state["hosts"]],
                           paseo_agents=self._paseo_agent_names())

    def deployments(self):
        """Deploy manager for Switchyard-created workloads (templates, instances, placements, port claims)."""
        from .deploy import DeployManager
        return DeployManager(self._broker, registry_hosts=lambda: self.hosts()["hosts"])

    def lan_routes(self):
        """The operator may opt this catalog into managing one LAN gateway and DNS zone."""
        from .lan_route_config import load
        from .lan_routes import LanRoutes

        path = self._catalog_path.with_suffix(".lan-routes.json")
        try:
            config = load(path)
        except FileNotFoundError:
            return None
        return LanRoutes(self, config)

    def _deployed_workloads(self) -> list[dict]:
        """Deployed records of the workload store, each with its current deploy journal placement.

        Reading the journal needs no execution authority: a desk started without an operations configuration
        still shows what was deployed."""
        return self.deployments().workload_definitions()

    def _registered(self):
        """Registered records of the workload store, with the start-token states recorded for each."""
        with self._store.transaction() as db:
            records = self._store.records(db, "registered")
            tokens = {record["id"]: [{key: row[key] for key in ("component", "host_id", "generation", "state", "updated_at")}
                                     for row in self._store.token_rows(db, record["id"])] for record in records}
        return records, tokens

    def tokens(self):
        """Start tokens for registered (adopted) applications: one small file per component (docs/tokens.md)."""
        from .tokens import TokenManager
        return TokenManager(self._broker)

    def _hostname(self, host_id: str, snapshot) -> str:
        """What the machine calls itself, for display: the observed `hostname`; else the one its collector
        expects (SSH and local hosts only: an ADB collector's expectation is a serial number); else the
        registry ID, which is the nearest thing for a device that cannot be asked."""
        observed = ((snapshot or {}).get("host") or {}).get("hostname")
        if isinstance(observed, str) and observed:
            return observed
        config = self._collectors.get(host_id) or {}
        if config.get("transport") in {"local", "ssh"} and config.get("expected_hostname"):
            return config["expected_hostname"]
        return host_id

    @_snapshot_view
    def agents(self) -> dict:
        """Paseo evidence for Linux collector hosts; freshness is judged against that host's inventory cadence."""
        hosts = []
        now = self._cache.clock()
        for record in self._registry_state["hosts"]:
            config = self._collectors.get(record["id"])
            if not config or config["transport"] not in {"local", "ssh"}:
                continue
            snapshot = self._cache.read(record["id"])["snapshot"]
            observed_at = ((snapshot or {}).get("resource_observed_at") or {}).get("paseo")
            limit = 2 * config["monitor"]["inventory_seconds"] if "monitor" in config else TTL_SECONDS
            freshness = "never" if observed_at is None else "fresh" if age(observed_at, now) < limit else "stale"
            hosts.append({"host_id": record["id"], "host_name": record["name"],
                          "hostname": self._hostname(record["id"], snapshot),
                          "paseo": deepcopy(snapshot.get("paseo")) if snapshot else None,
                          "freshness": freshness, "observed_at": observed_at})
        return {"hosts": hosts, "locks": self.device_locks()["ledgers"]}

    @_snapshot_view
    def configure_paseo(self, host_id, *, enabled, listen="127.0.0.1:6767", cli=None, expected_revision):
        """The only collector-allowlist edit the web may make: opt a host in/out of Paseo observation."""
        if type(enabled) is not bool:
            raise ValueError("enabled must be true or false")
        current = (self._host_record(host_id)["collector"] or {}).get("paseo")
        discovered = (self._paseo_snapshot(host_id) or {}).get("cli_candidates") or []
        if enabled and cli is not None and cli not in discovered and cli != (current or {}).get("cli"):
            raise ValueError("Choose a Paseo CLI path discovered on this host, or none for HTTP-only status")

        def change(records, db):
            record = next((r for r in records if r["id"] == host_id), None)
            if record is None or not record["collector"] or record["collector"]["transport"] not in {"local", "ssh"}:
                raise ValueError("Paseo observation needs a Linux collector on this host")
            if enabled:
                record["collector"]["paseo"] = {"listen": listen, "cli": cli}
            else:
                record["collector"].pop("paseo", None)
        return self._mutate_hosts(expected_revision, change, host_id)

    @_snapshot_view
    def add_host(self, record, *, expected_revision):
        record = host_registry.validate(record)
        if record["connection_revision"] != 1 or record["host_keys"]:
            raise ValueError("New hosts start at connection revision 1 without pins; scan and confirm their keys explicitly")
        def change(records, db):
            if any(r["id"] == record["id"] for r in records):
                raise ValueError("Duplicate registry host ID")
            records.append(record)
        return self._mutate_hosts(expected_revision, change, record["id"])

    @_snapshot_view
    def remove_host(self, host_id, *, expected_revision):
        self._host_record(host_id)
        def change(records, db):
            records[:] = [record for record in records if record["id"] != host_id]
        return self._mutate_hosts(expected_revision, change)

    @_snapshot_preflight
    def scan_host_key(self, host_id, *, request_id):
        if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", request_id):
            raise ValueError("Invalid host-key scan request ID")
        with self._snapshot_lock:
            record = deepcopy(self._host_record(host_id))
            config = deepcopy(self._collectors.get(host_id))
        if not config or config["transport"] != "ssh":
            raise ValueError("Host-key scans require an SSH collector")
        data = collector.scan_host_key(config, address=config["target"].split("@", 1)[1],
                                       port=config.get("port", 22), state_dir=self._state_dir)
        keys = data.get("keys")
        if not isinstance(keys, list) or not keys:
            raise ValueError("Host-key scan returned no keys")
        from . import host_keys
        data = {"keys": sorted(set(keys)), "fingerprints": sorted({host_keys.fingerprint(key) for key in keys})}
        return self._registry.save_scan(host_id, host_registry.authority(record), data)

    @_snapshot_view
    def pin_host_key(self, host_id, *, scan_id, fingerprints, expected_revision):
        def change(records, db):
            record = next((r for r in records if r["id"] == host_id), None)
            if record is None:
                raise ValueError("Unknown registry host ID")
            keys = self._registry.scanned_keys(db, host_id, record, scan_id, fingerprints)
            if record["host_keys"] != keys:
                record["host_keys"] = keys
                record["connection_revision"] += 1
        return self._mutate_hosts(expected_revision, change, host_id)

    @_snapshot_view
    def import_hosts(self, *, expected_revision, replace):
        if replace is not True:
            raise ValueError("Host import requires --replace")
        catalog, _ = read_catalog(self._catalog_path)
        self._validate_devices(catalog)
        seeds = self._registry.seed_records(catalog["devices"], load_config(self._collectors_path))
        def change(records, db):
            previous = {record["id"]: record for record in records}
            for seed in seeds:
                old = previous.get(seed["id"])
                if old:
                    before = {key: old["collector"].get(key, 22 if key == "port" and old["collector"]["transport"] == "ssh" else None) for key in host_registry.CONNECTION_FIELDS} if old["collector"] else None
                    after = {key: seed["collector"].get(key, 22 if key == "port" and seed["collector"]["transport"] == "ssh" else None) for key in host_registry.CONNECTION_FIELDS} if seed["collector"] else None
                    seed["connection_revision"] = old["connection_revision"] + (before != after or old["host_keys"] != seed["host_keys"])
            records[:] = seeds
        result = self._mutate_hosts(expected_revision, change)
        return {**result, "hosts": self.hosts()["hosts"]}

    @_snapshot_view
    def export_hosts(self):
        return {"revision": self._registry_state["revision"],
                "hosts": [{key: deepcopy(record[key]) for key in host_registry.FIELDS} for record in self._registry_state["hosts"]]}

    @_snapshot_view
    def fleet_revision(self) -> str:
        """Stable definition/observation/journal revision; aging is not new evidence."""
        from .ansible_ops import audit_revision
        return (f"{self._definition_revision}:{self._registry_state['revision']}:{self._cache.revision()}:"
                f"{self._broker.revision()}:{audit_revision(self._state_dir)}")

    @_snapshot_view
    def fleet(self) -> dict[str, Any]:
        """Read shared cached evidence only. Never calls a collector."""
        import time
        hosts, resources, artifacts = [], [], []
        monitoring = self._cache.read_monitor()
        active_cadences = {host["host_id"]: host for host in monitoring["hosts"]}
        now = time.time()
        deployed = self._deployed_workloads()
        operation_policy = self._operation_policy(deployed)
        key_state = self.fleet_keys()
        receipts = self.operation_receipts()
        placements = self._broker.placements()
        managed = {workload["id"]: workload for workload in operation_policy["workloads"]}
        executable_hosts = set(operation_policy["shell_hosts"])
        for workload in managed.values():
            executable_hosts.update(workload["allowed_hosts"])

        def timed(record, ttl=TTL_SECONDS):
            at = record.get("observed_at")
            seconds = age(at, now) if at else None
            return {**record, "age_seconds": seconds, "freshness_ttl_seconds": ttl,
                    "freshness": "never" if seconds is None else "fresh" if seconds < ttl else "stale"}

        for host in self._devices.values():
            cadence = active_cadences.get(host["id"], {})
            automatic = bool(cadence) and monitoring["state"] == "running"

            def interval(scope):
                if not automatic:
                    return None
                if scope in {"host", "cpu", "memory"} or scope.startswith("systemd:"):
                    return cadence["fast_seconds"]
                if scope == "storage":
                    return cadence["storage_seconds"]
                return cadence["inventory_seconds"]

            def scope_ttl(scope):
                seconds = interval(scope)
                return max(30, 3 * seconds) if seconds is not None else TTL_SECONDS

            observation = self._cache.read(host["id"])
            at = observation["snapshot"]["observed_at"] if observation["snapshot"] else None
            observation.update({key: value for key, value in timed({"observed_at": at}, scope_ttl("host")).items()
                                if key != "observed_at"})
            snapshot = observation["snapshot"]
            coverage = [timed(record, scope_ttl(record["scope"])) for record in snapshot["coverage"]] if snapshot else []
            resource_status = {
                resource: {**timed({"observed_at": at}, scope_ttl(resource)),
                           "expected_interval_seconds": interval(resource)}
                for resource, at in (snapshot.get("resource_observed_at", {}) if snapshot else {}).items()
            }
            attention = []
            if observation["freshness"] != "fresh":
                attention.append("No fresh host observation")
            if observation["last_attempt"] and (
                observation["last_attempt"]["status"] in {"error", "busy"}
                or observation["last_attempt"]["status"] == "collecting" and observation["freshness"] != "fresh"
            ):
                attention.append("Latest collection: " + observation["last_attempt"]["status"])
            for scope in coverage:
                if scope["status"] != "complete" or scope["freshness"] != "fresh":
                    attention.append(f"{scope['scope']}: {scope['status']} / {scope['freshness']}")
            enabled = host["id"] in self._collectors
            hosts.append({**deepcopy(host), "hostname": self._hostname(host["id"], snapshot),
                          "collection_enabled": enabled, "observation": observation,
                          "verification": self._host_record(host["id"])["verification"],
                          "pins": self._host_record(host["id"])["pins"],
                          "paseo": snapshot.get("paseo") if snapshot else None,
                          "declared_capabilities": list(host["capabilities"]),
                          "capabilities": {"observe": enabled, "execute": host["id"] in executable_hosts,
                                           "approval": "explicit-operation-required" if host["id"] in executable_hosts else "not-granted"},
                          "coverage": coverage, "resource_status": resource_status, "attention": attention})
            if snapshot:
                resources.extend(timed(record, scope_ttl(f"{record['backend']}:{record['scope']}"))
                                 for record in snapshot["workloads"])
                artifacts.extend(timed(record, scope_ttl(f"{record['backend']}:{record['scope']}"))
                                 for record in snapshot.get("artifacts", []))
        for host in hosts:
            host["integration"] = host_integration(
                host, self._collectors.get(host["id"]), shell_hosts=operation_policy["shell_hosts"],
                managed_workloads=operation_policy["workloads"], key_state=key_state)
        observers = []
        if any(c["transport"] != "adb" for c in self._collectors.values()):
            observers.append({"id": "linux-v1", "name": "Bounded Linux observer", "status": "available",
                              "capabilities": ["explicit-host-observation", "systemd-allowlist", "resource-snapshot"]})
        if any(c["transport"] == "adb" for c in self._collectors.values()):
            observers.append({"id": "android-v1", "name": "Bounded Android observer", "status": "available",
                              "capabilities": ["explicit-host-observation", "package-allowlist", "resource-snapshot"]})
        for engine in sorted({engine for c in self._collectors.values() for engine in c.get("container_engines", [])}):
            observers.append({"id": engine, "name": f"{engine.title()} scoped observer", "status": "available",
                              "capabilities": ["container-observation", "filtered-image-and-mount-metadata"]})
        definitions = deepcopy(self._inventory["workloads"])
        for definition in definitions:
            placement = placements.get(definition["id"])
            if placement and placement.get("host_id") in self._devices:
                definition["device_id"] = placement["host_id"]
                if placement.get("native_id"):
                    for binding in definition["bindings"]:
                        if binding["role"] == "primary":
                            binding["selector"] = {"native_id": placement["native_id"]}
                            if placement.get("scope"):
                                binding["scope"] = placement["scope"]
        workloads = resolve_definitions(definitions, resources)
        lifecycle_inspections = self._broker.lifecycle_inspections()
        active_operations = {receipt.get("workload_id") for receipt in receipts
                             if receipt["status"] in {"queued", "running"}}
        for workload in workloads:
            placement = placements.get(workload["id"])
            workload["declared_device_id"] = self._workloads[workload["id"]]["device_id"]
            if workload["id"] in managed:
                workload["authority"] = {"execute": True, "approval": "explicit-operation-required"}
                workload["supported_operations"] += managed[workload["id"]]["actions"]
            inspection = lifecycle_inspections.get(workload["id"])
            if inspection:
                workload["lifecycle_inspection"] = deepcopy(inspection)
                observed = inspection["inspected_at"]
                if (inspection["fresh"] and
                        (not workload["observed_at"] or age(observed, now) < age(workload["observed_at"], now))):
                    workload.update(timed({"observed_at": observed}))
                    workload["lifecycle"] = inspection["inspection"].get("lifecycle", "unknown")
                    workload["health"] = "unknown"
                    workload["state_evidence"] = {"kind": "lifecycle-inspection", "observed_at": observed}
            if placement:
                workload["managed_placement"] = deepcopy(placement)
                verified = placement.get("verified_at")
                evidence = timed({"observed_at": verified})
                if (verified and evidence["freshness"] == "fresh"
                        and (not workload["observed_at"] or age(verified, now) < age(workload["observed_at"], now))):
                    workload.update(evidence)
                    workload["lifecycle"] = placement.get("lifecycle", "unknown")
                    workload["state_evidence"] = {"kind": "operation-receipt", "observed_at": verified}
                if placement.get("uncertain"):
                    workload["lifecycle"] = "unknown"
                    workload["health"] = "unknown"
                    workload["state_evidence"] = {"kind": "uncertain-operation", "observed_at": None}
            if workload["id"] in active_operations:
                workload["lifecycle"] = "unknown"
                workload["health"] = "unknown"
                workload["state_evidence"] = {"kind": "operation-in-progress", "observed_at": None}
        # Every workload comes from the workload store and joins host observations the same way: observed ones
        # through their declared bindings (above), deployed ones through bindings derived from the deploy journal,
        # registered ones through their placements' declared native identities.
        for item in deployed:
            definition, deployment = item["definition"], item["deployment"]
            workload = resolve_definitions([definition], resources)[0]
            workload.update(declared_device_id=definition["device_id"], deployment=deployment,
                            authority={"execute": False, "approval": "deploy-plan-required"})
            if control := managed.get(workload["id"]):
                workload["authority"] = {"execute": True, "approval": "explicit-operation-required"}
                workload["supported_operations"] += control["actions"]
            verified = deployment.get("last_verified")
            if verified:
                workload["health"] = "consistent with the deploy journal" if verified["consistent"] \
                    else "drift: " + ", ".join(verified["drift"] or ["host not observed"])
            if deployment["uncertain"]:
                workload.update(lifecycle="unknown", state_evidence={"kind": "uncertain-operation", "observed_at": None})
            elif deployment["state"] != "active" and workload["freshness"] != "fresh":
                # Staged and fenced instances have no container to observe: the journal is the evidence.
                workload.update(timed({"observed_at": (verified or {}).get("verified_at") or deployment["updated_at"]}, 86400),
                                lifecycle="stopped",
                                state_evidence={"kind": "deploy-journal", "observed_at": deployment["updated_at"]})
            if workload["id"] in active_operations:
                workload.update(lifecycle="unknown", health="unknown",
                                state_evidence={"kind": "operation-in-progress", "observed_at": None})
            workloads.append(workload)
        registered, tokens = self._registered()
        # An observed workload whose primary resource is a registered application's component on the same host is
        # shown as part of that application, never as an unrelated second workload.
        linked, _ = links(definitions, registered)
        for workload in workloads:
            if workload["id"] in linked:
                workload["part_of"] = linked[workload["id"]]
        workloads.extend(registered_rows(registered, resources, linked=linked, tokens=tokens))
        if any(item["backend"] == "podman" for item in managed.values()):
            observers.append({"id": "podman-static-web", "name": "Managed Podman static web",
                              "status": "available", "capabilities": ["scoped-deployment", "cold-migration", "explicit-recovery"]})
        for backend in sorted({item["backend"] for item in managed.values() if item.get("inspection_required")}):
            observers.append({"id": backend + "-lifecycle", "name": backend.title() + " scoped lifecycle",
                              "status": "available", "capabilities": ["explicit-inspection", "start", "stop", "restart"],
                              "notes": "Existing adopted resources only; no deployment or migration."})
        if operation_policy["shell_hosts"]:
            observers.append({"id": "ssh-shell", "name": "Brokered SSH shell", "status": "available",
                              "capabilities": ["unrestricted-user-shell", "canonical-host-leases", "durable-receipts"]})
        mode = "scoped-operations" if operation_policy["enabled"] else "observe-and-propose"
        operations = ["observe-host", "plan-migration"]
        if operation_policy["enabled"]:
            operations += ["inspect-workload", "plan-operation", "execute-operation", "shell"]
        relations = {relation: sum(workload["management"] == relation for workload in workloads)
                     for relation in ("observed", "registered", "deployed")}
        try:
            routes = self.lan_routes()
            published = routes.published() if routes else []
        except ValueError:
            # Invalid optional gateway configuration must not break other fleet controls.
            published = []
        return {"mode": mode, "generated_at": now_iso(), "hosts": hosts,
                "definition_revision": self._definition_revision, "registry_revision": self._registry_state["revision"], "fleet_keys": key_state,
                "store": {"revision": self._definition_revision, "path": str(self._store.path), "relations": relations},
                "workloads": workloads, "resources": resources,
                "lan_urls": published,
                "environments": [record for record in resources if record["kind"] == "environment"],
                "artifacts": artifacts, "monitoring": monitoring,
                "groups": build_groups(self._groups, resources),
                "operation_policy": operation_policy, "operations": receipts,
                "policy": {"mode": mode, "execution_enabled": operation_policy["enabled"],
                           "authentication": "loopback-only", "operations": operations},
                "backends": self.backends.describe() + observers}

    @_snapshot_preflight
    def collect_host(self, host_id: str) -> dict[str, Any]:
        if not isinstance(host_id, str) or host_id not in self._collectors:
            raise ValueError("Host is not configured for collection")
        observation = self._cache.refresh(host_id, self._collectors[host_id],
                                          lambda config: collect_host(config, state_dir=self._state_dir))
        result = self.fleet()
        for host in result["hosts"]:
            if host["id"] == host_id:
                if observation["last_attempt"] and observation["last_attempt"]["status"] == "busy":
                    # Busy is a transient result; never replace newer cached evidence
                    # or cadence-derived freshness with the pre-contention snapshot.
                    host["observation"]["last_attempt"] = observation["last_attempt"]
                    host["attention"] = list(dict.fromkeys(host["attention"] + ["Latest collection: busy"]))
        return result

    @_snapshot_view
    def inventory(self) -> dict[str, Any]:
        # Declarations only: verification and pins are observations and belong to fleet()/hosts(). Workloads are the
        # store's records of all three relations; observed ones in the definition form the editor uses.
        registry = {"revision": self._registry_state["revision"],
                    "hosts": [{key: deepcopy(record[key]) for key in host_registry.FIELDS - {"verified_revision"}}
                              for record in self._registry_state["hosts"]]}
        inventory = deepcopy(self._inventory)
        inventory["workloads"] += [item["definition"] for item in self._deployed_workloads()]
        inventory["workloads"] += [registered_declaration(record) for record in self._registered()[0]]
        return {**inventory, "definition_revision": self._definition_revision, "registry": registry}

    @_snapshot_view
    def definition_inventory(self) -> dict:
        return {"revision": self._definition_revision, "workloads": deepcopy(self._inventory["workloads"])}

    def _definition_resources(self):
        resources = []
        for host_id in self._devices:
            snapshot = self._cache.read(host_id)["snapshot"]
            if snapshot:
                resources.extend(snapshot["workloads"])
        return resources

    @staticmethod
    def _resource_eligible(resource):
        return (resource["kind"] in {"service", "scheduled-job"}
                and resource.get("extensions", {}).get("container.v1", {}).get("environment") != "distrobox")

    @staticmethod
    def _binding_matches(definition, binding, resources):
        selector, value = next(iter(binding["selector"].items()))
        return [resource for resource in resources
                if (resource["host_id"], resource["backend"], resource["scope"], resource.get(selector))
                == (definition["device_id"], binding["backend"], binding["scope"], value)]

    @staticmethod
    def _source_evidence(resources):
        return [{key: resource.get(key) for key in
                 ("id", "host_id", "backend", "scope", "native_id", "kind", "observed_at")}
                for resource in resources]

    def _validate_definition_change(self, records, definition, *, taken, workload_id=None):
        """Validate one created or edited observed workload against all current ones (definition form).
        `taken`: IDs of registered and deployed records, which an observed workload cannot reuse."""
        if not isinstance(definition, dict):
            raise ValueError("definition must be an object")
        definition = deepcopy(definition)
        records = deepcopy(records)
        if workload_id is None:
            if any(record["id"] == definition.get("id") for record in records):
                raise ValueError("Duplicate workload definition ID; use update for an existing definition")
            if definition.get("id") in taken:
                raise ValueError("ID " + str(definition.get("id")) + " already belongs to a " + taken[definition["id"]]
                                 + " workload in the store")
            records.append(definition)
            previous = None
        else:
            previous = next((record for record in records if record["id"] == workload_id), None)
            if previous is None:
                raise ValueError("Unknown defined workload ID")
            if definition.get("id") != workload_id:
                raise ValueError("Workload definition ID is immutable")
            records[records.index(previous)] = definition
        prepared = self._prepare_store({"definitions": records, "groups": [], "seed": None})
        candidate = next(record for record in prepared[0]["workloads"] if record["id"] == definition["id"])
        self._check_protected_changes(prepared[0]["workloads"])
        resources = self._definition_resources()
        bindings_changed = previous is None or any(previous[key] != candidate[key] for key in
                                                  ("device_id", "backend", "kind", "bindings"))
        selected, candidate_keys = {}, set()
        for binding in candidate["bindings"]:
            selector, value = next(iter(binding["selector"].items()))
            candidate_keys.add((candidate["device_id"], binding["backend"], binding["scope"], selector, value))
            matches = self._binding_matches(candidate, binding, resources)
            if len(matches) > 1:
                raise ValueError("Workload binding is ambiguous in cached discovery")
            if bindings_changed and len(matches) != 1:
                raise ValueError("Promotion requires each binding to match exactly one cached resource")
            for resource in matches:
                if not self._resource_eligible(resource):
                    raise ValueError("Environments and unsupported resource kinds cannot become workload definitions")
                if binding["role"] == "primary" and candidate["kind"] != resource["kind"]:
                    raise ValueError("Workload kind must match the discovered primary resource")
                if resource["id"] in selected:
                    raise ValueError("Duplicate workload bindings resolve to the same resource")
                selected[resource["id"]] = resource
        placements = self._broker.placements()
        for other in prepared[0]["workloads"]:
            if other["id"] == candidate["id"]:
                continue
            variants = [other]
            placement = placements.get(other["id"])
            if placement and placement.get("host_id") and placement.get("native_id"):
                effective = deepcopy(other)
                effective["device_id"] = placement["host_id"]
                for binding in effective["bindings"]:
                    if binding["role"] == "primary":
                        binding["selector"] = {"native_id": placement["native_id"]}
                        binding["scope"] = placement.get("scope") or binding["scope"]
                variants.append(effective)
            for variant in variants:
                for binding in variant["bindings"]:
                    selector, value = next(iter(binding["selector"].items()))
                    key = (variant["device_id"], binding["backend"], binding["scope"], selector, value)
                    matches = self._binding_matches(variant, binding, resources)
                    if key in candidate_keys or any(resource["id"] in selected for resource in matches):
                        raise ValueError("Resource binding already belongs to another workload definition")
        return candidate, self._source_evidence(selected.values()), bindings_changed

    @_snapshot_view
    def propose_workload_definition(self, resource_id: str, *, workload_id: str, name: str,
                                    purpose: str, supporting_resource_ids: list[str] | None = None) -> dict:
        if not isinstance(resource_id, str) or not resource_id:
            raise ValueError("resource_id must be nonempty text")
        supporting = [] if supporting_resource_ids is None else supporting_resource_ids
        if (not isinstance(supporting, list) or len(supporting) > 127
                or any(not isinstance(identity, str) or not identity for identity in supporting)
                or len(set([resource_id, *supporting])) != len(supporting) + 1):
            raise ValueError("Supporting resource IDs must be a bounded list of distinct resources")
        resources = self._definition_resources()
        selected = []
        for identity in [resource_id, *supporting]:
            matches = [resource for resource in resources if resource["id"] == identity]
            if len(matches) != 1 or not self._resource_eligible(matches[0]):
                raise ValueError("Choose one cached service or scheduled-job resource, not an environment")
            selected.append(matches[0])
        primary = selected[0]
        if any(resource["host_id"] != primary["host_id"] for resource in selected):
            raise ValueError("Workload bindings must belong to one host")
        definition = {
            "id": workload_id, "name": name, "purpose": purpose,
            "device_id": primary["host_id"], "backend": primary["backend"],
            "management": "observed", "kind": primary["kind"],
            "bindings": [{"backend": resource["backend"], "scope": resource["scope"],
                          "selector": {"native_id": resource["native_id"]},
                          "role": "primary" if index == 0 else "supporting"}
                         for index, resource in enumerate(selected)],
            "requirements": [], "architectures": [], "recipe": None,
            "notes": "Defined from cached discovery. Health checks, data, dependencies and portability remain unknown. Definition only — no restart/deployment permission.",
            "health_check": None, "data_locations": [], "dependencies": [],
            "supported_operations": ["observe", "plan-migration"], "runtime": None,
        }
        with self._store.transaction() as db:
            taken = {record["id"]: record["relation"] for record in self._store.records(db) if record["relation"] != "observed"}
        definition, evidence, _ = self._validate_definition_change(self._inventory["workloads"], definition, taken=taken)
        warnings = ["Definition only — no restart/deployment permission.",
                    "Health checks, requirements, architecture compatibility, data and dependencies are not inferred."]
        if any(not resource.get("observed_at") or age(resource["observed_at"], time.time()) >= TTL_SECONDS for resource in selected):
            warnings.append("Discovery evidence is stale; this definition does not establish current runtime state.")
        return {"definition": deepcopy(definition), "revision": self._definition_revision,
                "warnings": warnings, "source_evidence": evidence}

    def _save_definition(self, definition, *, expected_revision, workload_id=None):
        if not isinstance(expected_revision, str) or not expected_revision:
            raise ValueError("expected_revision is required")
        # Serialize definition saves with host removals across processes. Both
        # validate the other source while holding the registry write lock.
        with self._registry.transaction() as registry_db:
            _, registry_revision = self._registry._read(registry_db)
            if registry_revision != self._registry_state["revision"]:
                raise ValueError("Host registry revision changed; review current hosts before saving the definition")
            with self._store.transaction() as db:
                if self._store.revision(db) != expected_revision:
                    raise ValueError("Definition revision changed; review the current workloads before saving")
                records = self._store.records(db)
                current = {record["id"]: record for record in records if record["relation"] == "observed"}
                taken = {record["id"]: record["relation"] for record in records if record["relation"] != "observed"}
                candidate, evidence, bindings_changed = self._validate_definition_change(
                    [bundle_definition(record["data"]) for record in current.values()], definition,
                    taken=taken, workload_id=workload_id)
                previous = current.get(candidate["id"])
                meta = deepcopy(previous["meta"]) if previous else {"origin": "definition-editor"}
                entry = {**(meta.get("definition_provenance") or {}), "updated_at": now_iso(), "previous_revision": expected_revision,
                         "method": "cached-discovery" if bindings_changed
                         else (meta.get("definition_provenance") or {}).get("method", "operator-edit")}
                if bindings_changed:
                    entry["source_evidence"] = evidence
                meta["definition_provenance"] = entry
                revision = (previous["revision"] if previous else 0) + 1
                bundle, digest = observed_record(candidate, revision=revision, provenance={
                    "submitted_by": "definition editor", "source": entry["method"]})
                self._store.put_record(db, workload_id=candidate["id"], relation="observed", expected_revision=revision - 1,
                                       revision=revision, content_sha256=digest, data=bundle, meta=meta)
                store_revision = self._store.revision(db)
        self._refresh()
        return {"definition": deepcopy(candidate), "revision": store_revision}

    @_snapshot_view
    def save_workload_definition(self, definition: dict, *, expected_revision: str) -> dict:
        return self._save_definition(definition, expected_revision=expected_revision)

    @_snapshot_view
    def update_workload_definition(self, workload_id: str, definition: dict, *, expected_revision: str) -> dict:
        if not isinstance(workload_id, str) or not IDENTIFIER.fullmatch(workload_id):
            raise ValueError("Invalid workload definition ID")
        return self._save_definition(definition, expected_revision=expected_revision, workload_id=workload_id)

    @_snapshot_view
    def store_status(self) -> dict:
        """What the workload store holds, where each record came from, and whether the catalog file still differs.
        Reads only; never contacts a host."""
        with self._store.transaction() as db:
            records = self._store.records(db)
            seeded = self._store.meta(db, "seed")
            groups = self._store.groups(db)
            legacy = self._store.legacy_summary(db)
        observed = {record["id"]: bundle_definition(record["data"]) for record in records if record["relation"] == "observed"}
        registered = [record for record in records if record["relation"] == "registered"]
        catalog = {"path": str(self._catalog_path.resolve()),
                   "role": "Seed only: after seeding its workloads and application_groups are ignored; hosts come from the "
                           "host registry. Edit workloads with the definition editor, `spec register` or `deploy`; "
                           "write the store out with `switchyard export`."}
        try:
            raw, catalog_sha256 = read_catalog(self._catalog_path)
            catalog["sha256"] = catalog_sha256
            catalog["changed_since_seed"] = bool(seeded) and catalog_sha256 != seeded["catalog"]["sha256"]
            in_catalog = {item["id"]: item for item in catalog_workloads(raw, self._host_ids())}
            differences = []
            for identity in sorted(set(in_catalog) | set(observed)):
                if identity not in observed:
                    differences.append({"id": identity, "difference": "only in the catalog file (ignored)"})
                elif identity not in in_catalog:
                    differences.append({"id": identity, "difference": "only in the store"})
                elif in_catalog[identity] != validate_definitions([observed[identity]], self._host_ids())[0]:
                    fields = sorted(key for key in in_catalog[identity] if in_catalog[identity][key] != observed[identity].get(key))
                    differences.append({"id": identity, "difference": "store revision differs from the catalog file",
                                        "fields": fields})
            catalog["workload_differences"] = differences
            catalog["groups_differ"] = load_groups(raw, self._host_ids()) != groups
        except ValueError as error:
            catalog["error"] = str(error)
        linked, overlaps = links(list(observed.values()), registered)
        components = []
        for row in registered_rows(registered, [], linked=linked, tokens={}):
            for item in row["registered_components"]:
                components.append({"application_id": row["id"], "component": item["component"], "host_id": item["host_id"],
                                   "placement_id": item["placement_id"], "linked_workloads": item["linked_workloads"]})
        placements = self._broker.placements()
        return {
            "store": str(self._store.path), "revision": self._definition_revision,
            "seed": seeded,
            "workloads": [{"id": record["id"], "relation": record["relation"], "revision": record["revision"],
                           "content_sha256": record["content_sha256"], "updated_at": record["updated_at"],
                           "origin": record["meta"].get("origin")
                           or ("deploy" if record["relation"] == "deployed" else "spec register" if record["relation"] == "registered" else None),
                           **({"host_id": observed[record["id"]]["device_id"]} if record["id"] in observed else {})}
                          for record in records],
            "relations": {relation: sum(record["relation"] == relation for record in records)
                          for relation in ("observed", "registered", "deployed")},
            "groups": [group["id"] for group in groups],
            "catalog": catalog,
            "links": [{"workload_id": identity, **link} for identity, link in sorted(linked.items())],
            "registered_components": components,
            "unmatched_overlaps": overlaps,
            # The operations journal still records where its legacy executor placed a workload (Foobar).
            "operations_journal_placements": {identity: {key: placement.get(key) for key in ("host_id", "lifecycle", "uncertain")}
                                              for identity, placement in placements.items()},
            "legacy_tables": legacy["tables"],
        }

    @_snapshot_view
    def export_store(self) -> dict:
        """Hosts, workloads (all three relations), templates and groups as one deterministic, secret-free document."""
        hosts = [{key: value for key, value in host.items() if key != "verified_revision"} for host in self.export_hosts()["hosts"]]
        return export_document(self._store, hosts)

    @_snapshot_view
    def import_store(self, document: dict, *, source_sha256: str, expected_revision: str | None = None) -> dict:
        """Plan (without `expected_revision`) or apply an export into an empty or matching store. Creates only what is
        absent; any record that differs is a blocker, never overwritten."""
        hosts = [{key: value for key, value in host.items() if key != "verified_revision"} for host in self.export_hosts()["hosts"]]

        def validate(definitions):
            self._prepare_store({"definitions": definitions, "groups": [], "seed": None})

        with self._store.transaction() as db:
            plan = import_plan(db, self._store, document, registry_hosts=hosts, validate_observed=validate)
            if expected_revision is None:
                return {**public_import(plan), "applied": False}
            if plan["revision"] != expected_revision:
                raise ValueError("Workload store revision changed; plan the import again")
            if plan["blockers"]:
                raise ValueError("Import refused: " + "; ".join(plan["blockers"]))
            apply_import(db, self._store, plan, source_sha256=source_sha256)
            revision = self._store.revision(db)
        self._refresh()
        return {**public_import(plan), "applied": True, "revision": revision}

    @_snapshot_view
    def fleet_keys(self) -> dict:
        return self._broker.fleet_keys()

    @_snapshot_preflight
    def inspect_fleet_keys(self, host_ids: list[str], *, request_id: str) -> dict:
        return self._broker.inspect_fleet_keys(host_ids, request_id=request_id)

    @_snapshot_view
    def plan_fleet_keys(self, action: str, host_ids: list[str]) -> dict:
        return self._broker.plan_fleet_keys(action, host_ids)

    @_snapshot_preflight
    def execute_fleet_keys(self, plan_id: str, *, approved: bool, request_id: str) -> dict:
        return self._broker.execute_fleet_keys(plan_id, approved=approved, request_id=request_id)

    def observe_local(self) -> dict[str, Any]:
        return self.backends.observe("local-host")

    @_snapshot_view
    def operation_policy(self) -> dict:
        return self._operation_policy(self._deployed_workloads())

    def _operation_policy(self, deployed) -> dict:
        from .deploy import LIFECYCLE_ACTIONS

        policy = self._broker.policy()
        if policy["enabled"]:
            deploy_hosts = set(self.deployments().policy()["deploy_hosts"])
            for item in deployed:
                definition = item["definition"]
                host_id = definition["device_id"]
                if host_id in deploy_hosts:
                    policy["workloads"].append({"id": definition["id"], "name": definition["name"],
                                                "backend": "quadlet", "allowed_hosts": [host_id],
                                                "actions": list(LIFECYCLE_ACTIONS), "inspection_required": False})
        return policy

    @_snapshot_preflight
    def inspect_workload(self, workload_id: str, *, request_id: str) -> dict:
        self._validate_authority()
        return self._broker.inspect_workload(workload_id, request_id=request_id)

    @_snapshot_view
    def plan_operation(self, action: str, workload_id: str, target_id: str | None = None) -> dict:
        self._validate_authority()
        if not isinstance(workload_id, str):
            raise ValueError("Unsupported workload operation")
        with self._store.reading() as db:
            deployed = self._store.relation_of(db, workload_id) == "deployed"
        if deployed:
            if target_id is not None:
                raise ValueError("Lifecycle actions apply to the current placement; omit target_id")
            return self.deployments().lifecycle_plan(action, workload_id)
        self._validate_lifecycle_bindings(workload_id)
        return self._broker.plan(action, workload_id, target_id)

    @_snapshot_preflight
    def execute_operation(self, plan_id: str, *, approved: bool, request_id: str) -> dict:
        self._validate_authority()
        if self._broker.plan_kind(plan_id) == "deploy-lifecycle":
            return self.deployments().lifecycle_apply(plan_id, approved=approved, request_id=request_id)
        self._validate_lifecycle_bindings()
        return self._broker.execute(plan_id, approved=approved, request_id=request_id)

    @_snapshot_preflight
    def run_shell(self, host_id: str, script: str, *, timeout_seconds: int = 30,
                  request_id: str, extra_host_ids: list[str] | None = None) -> dict:
        return self._broker.shell(host_id, script, timeout_seconds=timeout_seconds,
                                  request_id=request_id, extra_host_ids=extra_host_ids)

    # Shell receipts record the script that ran. Lists carry a one-line preview (they travel in every fleet
    # event); one receipt carries the whole script. Views served to other machines set `redact_commands`.
    redact_commands = False

    def _public_receipt(self, receipt: dict, *, full: bool) -> dict:
        if "script" not in receipt:
            return receipt
        receipt = dict(receipt)
        script = receipt.pop("script")
        if self.redact_commands:
            receipt["script_redacted"] = True
        elif full:
            receipt["script"] = script
        else:
            lines = [line.strip() for line in script.splitlines() if line.strip()]
            # Prefer the first real command over comments and shell options.
            first = next((line for line in lines if not line.startswith("#") and not line.startswith("set ")), lines[0] if lines else "")
            receipt["script_preview"] = first[:160] + ("…" if len(first) > 160 or len(lines) > 1 else "")
        return receipt

    def operation_receipts(self) -> list[dict]:
        """Brokered operation receipts and Ansible apply receipts, newest first (the Audit log)."""
        from .ansible_ops import audit_receipts
        receipts = [self._public_receipt(receipt, full=False) for receipt in self._broker.receipts()]
        receipts += audit_receipts(self._state_dir)
        return sorted(receipts, key=lambda item: str(item.get("started_at") or ""), reverse=True)[:200]

    def operation_receipt(self, operation_id: str) -> dict:
        try:
            return self._public_receipt(self._broker.receipt(operation_id), full=True)
        except ValueError:
            from .ansible_ops import PLAN_ID, audit_receipt
            if isinstance(operation_id, str) and PLAN_ID.fullmatch(operation_id):
                return audit_receipt(self._state_dir, operation_id)
            raise

    @_snapshot_view
    def plan_migration(self, workload_id: str, target_id: str) -> dict[str, Any]:
        if not isinstance(workload_id, str) or workload_id not in self._workloads:
            raise ValueError("Unknown defined workload ID")
        if not isinstance(target_id, str) or target_id not in self._devices:
            raise ValueError("Unknown target device ID")
        fleet = self.fleet()
        workload = deepcopy(self._workloads[workload_id])
        resolved = next(w for w in fleet["workloads"] if w["id"] == workload_id)
        workload["device_id"] = resolved["device_id"]
        primary = next(binding for binding in resolved["bindings_evidence"]
                       if binding["binding"]["role"] == "primary")
        native = next((resource for resource in fleet["resources"]
                       if primary["status"] == "matched" and resource["id"] in primary["matches"]), None)
        target = self._devices[target_id]
        evidence = {h["id"]: h["observation"] for h in fleet["hosts"]
                    if h["id"] in {workload["device_id"], target_id}}
        blockers = [
            ("Execution is disabled for this cache-only proposal; use a separately approved operation plan."
             if fleet["operation_policy"]["enabled"] else "Execution is disabled; this is a proposal, not an approved job."),
            "Defining a workload grants no lifecycle authority; operation approval has not been granted.",
            "Observations do not verify source stop, destination runtime compatibility or content portability.",
        ]
        for role, identity in (("Source", workload["device_id"]), ("Destination", target_id)):
            observation = evidence[identity]
            if observation["freshness"] != "fresh":
                blockers.append(f"{role} has no fresh host observation.")
            if observation["last_attempt"] and observation["last_attempt"]["status"] in {"error", "busy", "collecting"}:
                blockers.append(f"{role} collection did not complete; inspect coverage and last-known evidence.")
        if native is None:
            blockers.append("Defined primary resource is not uniquely observed in its exact host/backend/scope.")
        elif native["age_seconds"] is None or native["age_seconds"] >= TTL_SECONDS:
            blockers.append("Selected workload observation is stale for migration assessment.")
        if native and native["backend"] == "android":
            blockers.append("Android application sessions are device/profile-bound; cold migration is not supported.")
        if workload["device_id"] == target_id:
            blockers.append("Source and destination are the same device.")
        architectures = workload["architectures"]
        if not architectures or target["architecture"] == "unknown":
            blockers.append("Architecture compatibility is unknown.")
        elif target["architecture"] not in architectures:
            blockers.append(f"Declared destination architecture {target['architecture']} is incompatible with this workload.")
        missing = sorted(set(workload["requirements"]) - set(target["capabilities"]))
        if missing:
            blockers.append("Destination lacks declared capabilities: " + ", ".join(missing))
        recipe = workload["recipe"]
        steps = []
        if recipe is None:
            blockers.append("No service-specific migration recipe has been supplied.")
        else:
            steps = [
                {"action": "preflight", "detail": "Validate host identities, runtime/image, site content checksum, free space, dedicated port and HTTP baseline. Reserve source and destination access."},
                {"action": "stop", "detail": recipe["stop"]},
                {"action": "confirm-stopped", "detail": "Verify the source has stopped and its restart policy cannot reactivate it. Unreachable is not stopped; abort rather than start a second copy."},
                {"action": "transfer", "detail": recipe["transfer"]},
                {"action": "start", "detail": recipe["start"]},
                {"action": "verify", "detail": recipe["verify"]},
                {"action": "cutover", "detail": "Change endpoints only after verifying the expected HTTP body. Keep the source stopped and retain its verified static content/configuration."},
                {"action": "recovery", "detail": recipe["recovery"]},
            ]
        assessment = assess_recipe(recipe, workload, target, evidence) if recipe is not None else {"blockers": [], "checks": []}
        blockers = list(dict.fromkeys(blockers + assessment["blockers"]))
        plan = {
            "kind": "cold-migration", "status": "proposal", "executable": False,
            "workload_id": workload_id, "source_id": workload["device_id"], "target_id": target_id,
            "blockers": blockers,
            "checks": assessment["checks"],
            "warnings": ["Downtime includes stop, transfer, startup and verification.",
                         "This rehearsal covers immutable static content, not databases, live migration or automatic traffic routing."
                         if recipe else "No migration recipe defines this workload's data, verification or recovery."],
            "steps": steps,
            "requirements": ["Explicit operation approval", "Fresh evidence with expiry",
                             "Canonical source and destination leases for the whole operation",
                             "Verified artifacts, configuration and data", "Service-specific recovery and health verification"],
            "evidence": {identity: {"observed_at": item["snapshot"]["observed_at"] if item["snapshot"] else None,
                                   "freshness": item["freshness"], "last_attempt": item["last_attempt"]}
                         for identity, item in evidence.items()},
            "backend_resource": {key: native[key] for key in ("backend", "scope", "native_id", "observed_at")} if native else None,
        }
        # Include the complete declarations so capability/recipe changes invalidate plan identity.
        digest = hashlib.sha256(json.dumps({"plan": plan, "inventory": self._inventory, "snapshots": {key: value["snapshot"] for key, value in evidence.items()}}, sort_keys=True).encode()).hexdigest()[:20]
        return {"id": "proposal-" + digest, **plan}
