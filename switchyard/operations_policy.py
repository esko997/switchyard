"""The operations policy file: which workloads Switchyard may act on, which actions, and on which hosts.

Schema 2 (2026-11-23) states authority only:

    {"schema_version": 2, "shell_hosts": [...], "workloads": {"<id>": {"actions": [...], "hosts": [...]}},
     optional "fleet_key_hosts", "deploy_hosts", "deploy_devices", "token_hosts", "local_targets"}

`deploy_devices` ({"<deploy host>": ["/dev/..."]}) lists the host devices a Switchyard deployment may be given.

Everything that describes a granted workload (host, backend, unit and scope, Compose project, container, image,
port, page) is read from that ID's record in the workload store: its primary binding and its `runtime`
(`spec.Runtime`). A grant whose record is missing or cannot support it is refused when the file is loaded.
Schema 1 files (descriptions inline) are refused with the command that converts them, `migrate-operations`,
which also moves the operation journal's old placement table into the workload store (`migrate`).
"""
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3

from .collector import _json
from .definitions import _runtime
from .operation_store import MIGRATION_KEY, digest, encode, now
from .workload_store import WorkloadStore
from .workloads import bundle_definition, observed_record

SCHEMA_VERSION = 2
MAX_BYTES = 65536
KEYS = ("schema_version", "shell_hosts", "workloads", "fleet_key_hosts", "local_targets", "deploy_hosts", "deploy_devices",
        "token_hosts")
SCOPED_ACTIONS = ("start", "stop", "restart")
MANAGED_ACTIONS = ("deploy", "start", "stop", "migrate", "recover")
STATIC_WEB_ID = "foobar"  # the one disposable workload the static-web recipe (podman_ops) may act on
COMPOSE_FIELDS = ("provider", "project_name", "project_directory", "files", "services")
CONVERT = "switchyard --catalog CATALOG migrate-operations {path} --output NEW_FILE"


def read(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Operations configuration exceeds limit")
    return _json(raw)


def parse(config, path):
    """The validated shape of a schema-2 policy. Schema 1 is refused, naming the command that converts it."""
    if isinstance(config, dict) and config.get("schema_version") == 1:
        raise ValueError(
            f"{path} is an operations policy in the old format (schema_version 1, workload descriptions inline). "
            "Descriptions now live in the workload store and the policy states authority only. Convert it once with "
            f"`{CONVERT.format(path=path)}` (add --dry-run to preview the new file and what moves into the store)")
    if (not isinstance(config, dict) or not {"schema_version", "shell_hosts", "workloads"} <= set(config)
            or set(config) - set(KEYS) or type(config["schema_version"]) is not int
            or config["schema_version"] != SCHEMA_VERSION):
        raise ValueError("Invalid operations configuration")
    workloads = config["workloads"]
    if not isinstance(workloads, dict) or len(workloads) > 64:
        raise ValueError("Invalid operations workload map")
    for workload_id, grant in workloads.items():
        if not isinstance(grant, dict) or set(grant) != {"actions", "hosts"}:
            raise ValueError(f"Operations grant {workload_id} must have exactly `actions` and `hosts`; "
                             "what the workload is comes from its workload store record")
        for key in ("actions", "hosts"):
            value = grant[key]
            if (not isinstance(value, list) or not 1 <= len(value) <= 32 or any(not isinstance(item, str) for item in value)
                    or len(set(value)) != len(value)):
                raise ValueError(f"Operations grant {workload_id}: `{key}` must be a nonempty list of distinct names")
    return config


def resolve(workload_id, grant, record):
    """`(description, grant)` for one grant: the description in the broker's internal form (built only from the
    store record) and the grant with its actions in canonical order. ValueError names what does not fit."""
    where = "Operations policy grants " + workload_id
    if record is None:
        raise ValueError(f"{where}, which is not in the workload store; define it (definition editor or "
                         "`switchyard import`) or remove the grant")
    if record["relation"] != "observed":
        raise ValueError(f"{where}, a {record['relation']} workload; lifecycle grants cover observed workloads only "
                         "(deployed workloads: deploy_hosts; registered applications: token_hosts)")
    definition = bundle_definition(record["data"])
    runtime, host_id = definition["runtime"], definition["device_id"]
    primary = next(binding for binding in definition["bindings"] if binding["role"] == "primary")
    if definition["kind"] != "service":
        raise ValueError(f"{where}, whose store record is a {definition['kind']}; lifecycle actions need a service")
    kind = runtime["kind"] if runtime else "systemd" if primary["backend"] == "systemd" else None
    if kind is None:
        raise ValueError(f"{where}, but its store record has no primary binding of a supported backend: a systemd "
                         "unit, or a `runtime` (quadlet, compose or static-web) saying how to start and stop it")
    supported = MANAGED_ACTIONS if kind == "static-web" else SCOPED_ACTIONS
    unsupported = [action for action in grant["actions"] if action not in supported]
    if unsupported:
        raise ValueError(f"{where} {', '.join(unsupported)}, which its {kind} backend does not support "
                         f"(supported: {', '.join(supported)})")
    grant = {"actions": [action for action in supported if action in grant["actions"]], "hosts": list(grant["hosts"])}
    if kind == "static-web":
        if workload_id != STATIC_WEB_ID:
            raise ValueError(f"{where}: the static-web recipe exists only for the disposable {STATIC_WEB_ID} workload")
        if primary["backend"] != "podman" or not primary["scope"].startswith("user:") or "name" not in primary["selector"]:
            raise ValueError(f"{where}: the static-web recipe needs a rootless Podman container named by the primary binding")
        if host_id not in grant["hosts"]:
            raise ValueError(f"{where} on {', '.join(grant['hosts'])}, which does not include {host_id}, where its store "
                             "record places it first")
        return {"name": definition["name"], "allowed_hosts": grant["hosts"], "initial_host": host_id,
                "container_name": primary["selector"]["name"], "image": runtime["image"],
                "site_file": runtime["site_file"], "port": runtime["port"]}, grant
    if grant["hosts"] != [host_id]:
        raise ValueError(f"{where} on {', '.join(grant['hosts'])}, but scoped lifecycle acts only where its store "
                         f"record places it: hosts must be [\"{host_id}\"]")
    if kind == "compose":
        engine = "podman" if runtime["provider"] == "podman-compose" else "docker"
        if any(binding["backend"] != engine for binding in definition["bindings"]):
            raise ValueError(f"{where}: Compose authority requires a definition of the project's native {engine} containers")
        return {"backend": "compose", "name": definition["name"], "host_id": host_id,
                **{key: deepcopy(runtime[key]) for key in COMPOSE_FIELDS}}, grant
    scope = "system" if primary["scope"] == "system" else "user" if primary["scope"].startswith("user:") else None
    if primary["backend"] != "systemd" or scope is None or "native_id" not in primary["selector"]:
        raise ValueError(f"{where}: unit authority needs a primary systemd unit in the system or a user scope")
    return {"backend": kind, "name": definition["name"], "host_id": host_id, "scope": scope,
            "unit": primary["selector"]["native_id"]}, grant


# ------------------------------------------------------------------------- schema 1 -> 2 (one-time migration)

def convert(old, records):
    """A schema-1 policy as `(schema-2 policy, {workload_id: runtime the store record gains})`.

    `records`: `{workload_id: store record or None}`. Refuses when a description in the old file is not exactly
    what the converted file and the store would describe together, so nothing is lost or silently changed."""
    if not isinstance(old, dict) or old.get("schema_version") != 1 or not isinstance(old.get("workloads"), dict):
        raise ValueError("Expected an operations policy in the old format (schema_version 1)")
    grants, runtimes = {}, {}
    for workload_id, entry in old["workloads"].items():
        record = records.get(workload_id)
        if not isinstance(entry, dict):
            raise ValueError(f"{workload_id}: invalid old policy entry")
        if record is None or record["relation"] != "observed":
            raise ValueError(f"{workload_id}: the old policy describes it, but the workload store has no observed record "
                             "of it; define it first (definition editor), then convert")
        backend = entry.get("backend")
        if backend is None:
            runtime = {"kind": "static-web", **{key: entry.get(key) for key in ("image", "port", "site_file")}}
            grant = {"actions": list(MANAGED_ACTIONS), "hosts": deepcopy(entry.get("allowed_hosts"))}
        elif backend in {"systemd", "quadlet", "compose"}:
            runtime = None if backend == "systemd" else {"kind": "quadlet"} if backend == "quadlet" else \
                {"kind": "compose", **{key: deepcopy(entry.get(key)) for key in COMPOSE_FIELDS}}
            grant = {"actions": list(SCOPED_ACTIONS), "hosts": [entry.get("host_id")]}
        else:
            raise ValueError(f"{workload_id}: unknown backend {backend!r} in the old policy")
        definition = bundle_definition(record["data"])
        runtime = _runtime(runtime, definition["backend"], definition["kind"])
        if definition["runtime"] is not None and definition["runtime"] != runtime:
            raise ValueError(f"{workload_id}: the store record already describes a different runtime "
                             f"({definition['runtime']}) than the old policy ({runtime})")
        candidate = {"relation": "observed", "data": observed_record({**definition, "runtime": runtime},
                     revision=record["revision"], provenance=record["data"]["applications"][0]["provenance"])[0]}
        described, grant = resolve(workload_id, grant, candidate)
        if described != entry:
            differences = [f"{key} (policy {entry.get(key)!r}, store {described.get(key)!r})"
                           for key in sorted(set(entry) | set(described)) if entry.get(key) != described.get(key)]
            raise ValueError(f"{workload_id}: the old policy and the workload store disagree on {'; '.join(differences)}. "
                             "Make them agree (edit the policy file or the record), then convert")
        grants[workload_id] = grant
        if definition["runtime"] != runtime:
            runtimes[workload_id] = runtime
    new = {key: SCHEMA_VERSION if key == "schema_version" else grants if key == "workloads" else deepcopy(value)
           for key, value in old.items()}
    return new, runtimes


def policy_bytes(policy):
    return (json.dumps(policy, indent=2) + "\n").encode()


def _read_only(path):
    db = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=3)
    db.row_factory = sqlite3.Row
    return db


def _tables(db, schema="main"):
    return {row[0] for row in db.execute(f"SELECT name FROM {schema}.sqlite_master WHERE type='table'")}


def _state(db, workload_ids, journal="journal"):
    """Store records of `workload_ids`, the journal's old placement rows, the moved rows and the migration marker."""
    tables = _tables(db)
    records = {identity: WorkloadStore.record(db, identity) if "workloads" in tables else None for identity in workload_ids}
    legacy = []
    if journal in {row[1] for row in db.execute("PRAGMA database_list")}:
        if "workloads" in _tables(db, journal):
            legacy = [[row[0], row[1], row[2]] for row in
                      db.execute(f"SELECT id, ownership_id, placement FROM {journal}.workloads ORDER BY id")]
    moved = WorkloadStore.managed_placement_rows(db) if "managed_placements" in tables else {}
    marker = WorkloadStore.meta(db, MIGRATION_KEY) if "store_meta" in tables else None
    return records, legacy, moved, marker


def _placement_plan(legacy, moved):
    rows = []
    for workload_id, ownership_id, placement in legacy:
        value = json.loads(placement) if placement else None
        present = moved.get(workload_id)
        if present is not None and (present["ownership_id"], present["placement"]) != (ownership_id, value):
            if present["sequence"] == 0:
                raise ValueError(f"{workload_id}: the workload store already holds a different managed placement")
            state = "changed since by operations"  # moved earlier; receipts have changed it since
        else:
            state = "already in the store" if present is not None else "moves into the store"
        rows.append({"workload_id": workload_id, "ownership_id": ownership_id, "placement": value, "state": state})
    return rows


def migrate(source, target, operations_dir, *, apply=False):
    """Convert schema-1 policy `source` into schema-2 `target` and move the journal's placement rows and the
    descriptions the old file held into the workload store. Dry run unless `apply`: reads only, writes nothing.
    Applying is one store transaction (journal attached, both locked), then the policy file (atomic rename);
    running it again changes nothing."""
    source, target, directory = Path(source), Path(target), Path(operations_dir)
    old = read(source)
    if not isinstance(old, dict) or not isinstance(old.get("workloads"), dict):
        raise ValueError("Invalid operations configuration")
    store_path, journal_path = directory / "deploy.sqlite3", directory / "operations.sqlite3"
    if not store_path.exists():
        raise ValueError(f"No workload store at {store_path}; check --catalog/--state-dir (state is namespaced by catalog path)")
    db = _read_only(store_path)
    try:
        if journal_path.exists():
            db.execute("ATTACH DATABASE ? AS journal", (journal_path.resolve().as_uri() + "?mode=ro",))
        records, legacy, moved, marker = _state(db, list(old["workloads"]))
    finally:
        db.close()
    policy, runtimes = convert(old, records)
    encoded = policy_bytes(policy)
    existing = target.read_bytes() if target.exists() else None
    if existing is not None and existing != encoded:
        raise ValueError(f"{target} already exists and differs from the converted policy; move it away first")
    plan = {"source": str(source), "policy_path": str(target),
            "policy_file": "identical, already written" if existing == encoded else "to write",
            "policy": policy,
            "store": {
                "records": [{"id": key, "revision": records[key]["revision"], "new_revision": records[key]["revision"] + 1,
                             "adds": {"runtime": value}} for key, value in runtimes.items()],
                "unchanged_records": sorted(set(old["workloads"]) - set(runtimes)),
                "placements": _placement_plan(legacy, moved),
                "marker": marker},
            "applied": False}
    if not apply:
        return plan
    changes = bool(runtimes) or marker is None or any(row["state"] == "moves into the store" for row in plan["store"]["placements"])
    if changes:
        store = WorkloadStore(directory)  # its schema (managed_placements) exists before the transaction
        connection = sqlite3.connect(store.path, timeout=3, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            if journal_path.exists():
                connection.execute("ATTACH DATABASE ? AS journal", (str(journal_path),))
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")  # locks the store and the attached journal: one consistent snapshot
            current, legacy_now, moved_now, marker_now = _state(connection, list(old["workloads"]))
            if (legacy_now != legacy or marker_now != marker
                    or any(current[key]["revision"] != records[key]["revision"] for key in runtimes)):
                raise ValueError("The workload store or operation journal changed since planning; run the migration again")
            backups = [str(store.backup("pre-operations-migration"))]
            if journal_path.exists():
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
                copy = directory / f"operations.sqlite3.pre-operations-migration-{stamp}.bak"
                os.close(os.open(copy, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600))
                source_db, copy_db = sqlite3.connect(journal_path, timeout=3), sqlite3.connect(copy)
                try:
                    source_db.backup(copy_db)
                finally:
                    copy_db.close()
                    source_db.close()
                backups.append(str(copy))
            revision = WorkloadStore.revision(connection)
            for workload_id, runtime in runtimes.items():
                record = current[workload_id]
                definition = {**bundle_definition(record["data"]), "runtime": runtime}
                bundle, content = observed_record(definition, revision=record["revision"] + 1, provenance={
                    "submitted_by": "operations policy migration", "source": f"{source} (schema_version 1)",
                    "evidence": ["runtime moved from the operations policy file into the workload store"]})
                meta = deepcopy(record["meta"])
                meta["definition_provenance"] = {**(meta.get("definition_provenance") or {}), "updated_at": now(),
                                                 "previous_revision": revision, "method": "operations-policy-migration"}
                WorkloadStore.put_record(connection, workload_id=workload_id, relation="observed",
                                         expected_revision=record["revision"], revision=record["revision"] + 1,
                                         content_sha256=content, data=bundle, meta=meta)
            for row in plan["store"]["placements"]:
                if row["state"] == "moves into the store":
                    connection.execute("INSERT INTO managed_placements VALUES(?,?,?,0,?)",
                                       (row["workload_id"], row["ownership_id"],
                                        None if row["placement"] is None else encode(row["placement"]), now()))
            if marker is None:
                WorkloadStore.set_meta(connection, MIGRATION_KEY, {
                    "migrated_at": now(), "legacy_sha256": digest(legacy), "rows": [row[0] for row in legacy],
                    "policy_source": str(source), "policy_target": str(target), "backups": backups})
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        plan["backups"] = backups
    if existing is None:
        temporary = target.with_name("." + target.name + ".migrating")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,
                     source.stat().st_mode & 0o777)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(target)
    plan["applied"] = True
    return plan
