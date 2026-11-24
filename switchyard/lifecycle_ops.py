"""Explicit adoption, cached plans and fixed-source scoped native lifecycle actions."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path, PurePosixPath
import re
import uuid

from .collector import _validate_config
from .operation_store import digest, encode, now
from .remote import RemoteError, run_remote

BACKENDS = {"systemd", "quadlet", "compose"}
ACTIONS = ("start", "stop", "restart")
INSPECTION_TTL = 120
MAX_INSPECTION = 65536
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,239}\.service\Z")
_SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


def _path(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 4096
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or not PurePosixPath(value).is_absolute() or ".." in PurePosixPath(value).parts):
        raise ValueError("Lifecycle paths must be explicit absolute POSIX paths")
    return value


def validate_workload(workload_id, config, hosts):
    """Validate a scoped lifecycle description (built from the workload store record the policy grants)."""
    if not isinstance(workload_id, str) or not _IDENTIFIER.fullmatch(workload_id) or workload_id == "foobar":
        raise ValueError("Invalid scoped lifecycle workload ID")
    if not isinstance(config, dict) or not isinstance(config.get("backend"), str) or config["backend"] not in BACKENDS:
        raise ValueError("Unsupported lifecycle backend")
    fields = {"backend", "name", "host_id"}
    if config["backend"] in {"systemd", "quadlet"}:
        fields |= {"scope", "unit"}
    else:
        fields |= {"provider", "project_name", "project_directory", "files", "services"}
    if set(config) != fields:
        raise ValueError("Invalid scoped lifecycle configuration fields")
    name = config["name"]
    if not isinstance(name, str) or not 1 <= len(name) <= 128 or any(ord(char) < 32 for char in name):
        raise ValueError("Invalid workload name")
    host_id = config["host_id"]
    if not isinstance(host_id, str) or host_id not in hosts or hosts[host_id].get("transport") != "ssh":
        raise ValueError("Lifecycle requires an enrolled SSH host")
    _validate_config(hosts[host_id])
    if config["backend"] in {"systemd", "quadlet"}:
        if not isinstance(config["scope"], str) or config["scope"] not in {"user", "system"} or not isinstance(config["unit"], str) or not _UNIT.fullmatch(config["unit"]):
            raise ValueError("Lifecycle requires an exact non-template .service and scope")
    else:
        if not isinstance(config["provider"], str) or config["provider"] not in {"docker-compose-v2", "podman-compose"}:
            raise ValueError("Unsupported explicit Compose provider")
        if not isinstance(config["project_name"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", config["project_name"]):
            raise ValueError("Invalid Compose project name")
        _path(config["project_directory"])
        files, services = config["files"], config["services"]
        if not isinstance(files, list) or not 1 <= len(files) <= 16 or any(not isinstance(item, str) for item in files) or len(set(files)) != len(files):
            raise ValueError("Compose requires an explicit unique manifest list")
        for item in files:
            _path(item)
        if (not isinstance(services, list) or not 1 <= len(services) <= 64
                or any(not isinstance(item, str) or not _SERVICE.fullmatch(item) for item in services)
                or len(set(services)) != len(services)):
            raise ValueError("Compose requires an exact complete service set")
    return json.loads(encode(config))


def policy_entry(workload_id, config, actions):
    return {"id": workload_id, **config, "allowed_hosts": [config["host_id"]],
            "actions": list(actions), "inspection_required": True}


def authority(config, host):
    return digest({"workload": config, "host": _validate_config(host)})


def _fresh(observed_at):
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(observed_at)).total_seconds()
        return 0 <= age <= INSPECTION_TTL
    except (ValueError, TypeError):
        return False


def _inspection(value, backend):
    """Bound trusted adapter evidence, rejecting raw/secret-bearing diagnostic fields."""
    if (not isinstance(value, dict) or not {"backend", "identity", "state", "warnings", "supported_actions"} <= set(value)
            or set(value) - {"backend", "identity", "state", "warnings", "supported_actions", "resources", "lifecycle", "health"}
            or value["backend"] != backend or not isinstance(value["identity"], dict)
            or not value["identity"] or not isinstance(value["state"], dict) or not value["state"]):
        raise RemoteError("Invalid lifecycle inspection shape")
    for field in ("warnings", "supported_actions"):
        items = value[field]
        if not isinstance(items, list) or len(items) > 32 or any(not isinstance(item, str) or len(item) > 512 for item in items):
            raise RemoteError("Invalid bounded lifecycle inspection metadata")
    if len(set(value["supported_actions"])) != len(value["supported_actions"]) or not set(value["supported_actions"]) <= set(ACTIONS):
        raise RemoteError("Invalid lifecycle supported actions")
    if "lifecycle" in value and value["lifecycle"] not in ("running", "stopped", "failed", "unknown"):
        raise RemoteError("Invalid native lifecycle summary")
    if "health" in value and value["health"] != "unknown":
        raise RemoteError("Lifecycle adapter cannot establish application health")
    if "resources" in value:
        resources = value["resources"]
        if (not isinstance(resources, list) or len(resources) > 128
                or any(not isinstance(item, dict) or set(item) != {"backend", "scope", "native_id", "name"}
                       or any(not isinstance(field, str) for field in item.values()) for item in resources)):
            raise RemoteError("Invalid bounded native resource selectors")
    forbidden = {"environment", "env", "command", "commandline", "cmdline", "logs", "stdout", "stderr", "unit_text", "raw_config", "config_text"}
    remaining = 2048

    def bounded(item, depth=0):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 12:
            raise RemoteError("Lifecycle inspection exceeds structural bounds")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > 128 or key.lower() in forbidden:
                    raise RemoteError("Unsafe lifecycle inspection field")
                bounded(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                bounded(child, depth + 1)
        elif isinstance(item, str):
            if len(item) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in item):
                raise RemoteError("Invalid lifecycle inspection text")
        elif item is not None and type(item) not in {bool, int, float}:
            raise RemoteError("Invalid lifecycle inspection value")
    bounded(value)
    try:
        encoded = encode(value)
    except (ValueError, TypeError) as error:
        raise RemoteError("Invalid lifecycle inspection encoding") from error
    if len(encoded.encode()) > MAX_INSPECTION:
        raise RemoteError("Lifecycle inspection exceeds evidence bounds")
    return json.loads(encoded)


def _cached(db, workload_id, fingerprint):
    row = db.execute("SELECT * FROM lifecycle_inspections WHERE workload_id=?", (workload_id,)).fetchone()
    if row and row["authority_fingerprint"] == fingerprint:
        return {"inspection": json.loads(row["inspection"]), "inspected_at": row["inspected_at"],
                "inspection_fingerprint": row["revision"]}
    return None


def _require_cache(db, workload_id, fingerprint, revision=None):
    cached = _cached(db, workload_id, fingerprint)
    if not cached or not _fresh(cached["inspected_at"]):
        raise ValueError("Fresh explicit workload inspection required (120 second TTL)")
    if revision is not None and cached["inspection_fingerprint"] != revision:
        raise ValueError("Cached workload inspection changed; plan again")
    return cached


def inspections(broker):
    config = broker._configuration()
    workloads = config["workloads"] if config else {}
    result = {}
    with broker.store.transaction() as db:
        for row in db.execute("SELECT * FROM lifecycle_inspections").fetchall():
            workload = workloads.get(row["workload_id"])
            current = (workload is not None and workload.get("backend") in BACKENDS
                       and row["authority_fingerprint"] == authority(workload, broker.operation_hosts(config)[workload["host_id"]]))
            if not current:
                continue
            inspection = json.loads(row["inspection"])
            result[row["workload_id"]] = {"backend": workload["backend"], "host_id": workload["host_id"],
                "authority_fingerprint": row["authority_fingerprint"],
                "inspection_fingerprint": row["revision"], "inspected_at": row["inspected_at"],
                "fresh": _fresh(row["inspected_at"]),
                "inspection": inspection}
    return result


def inspect(broker, workload_id, request_id):
    config = broker._enabled()
    workload = config["workloads"].get(workload_id) if isinstance(workload_id, str) else None
    if not workload or workload.get("backend") not in BACKENDS:
        raise ValueError("Explicit inspection requires a scoped lifecycle workload")
    hosts = broker.operation_hosts(config)
    fingerprint = authority(workload, hosts[workload["host_id"]])
    intent = {"action": "inspect", "workload_id": workload_id, "authority_fingerprint": fingerprint}
    with broker.store.transaction() as db:
        result = broker._begin(db, request_id=request_id, intent=intent, kind="lifecycle",
                               host_ids=[workload["host_id"]], workload_id=workload_id)
    if result["receipt"]["status"] != "running" or result.get("replayed"):
        return result
    return broker._dispatch(result["receipt"], {"kind": "lifecycle", "operation_hosts": hosts,
                                                "request": _request(broker, config, workload_id, workload, fingerprint, "inspect")})


def _request(broker, config, workload_id, workload, fingerprint, action):
    # A collector-local host runs the same fixed adapter locally under its device reservation.
    return {"action": action, "workload_id": workload_id, "config": workload,
            "authority_fingerprint": fingerprint, "config_path": str(broker.config_path.resolve()),
            "local": workload["host_id"] in broker.local_host_ids(config)}


def plan(broker, config, action, workload_id, target_id):
    workload = config["workloads"][workload_id]
    if action not in ACTIONS:
        raise ValueError("Scoped lifecycle supports only start, stop and restart")
    broker._granted(config, action, workload_id)
    if target_id is not None and target_id != workload["host_id"]:
        raise ValueError("Scoped lifecycle cannot change hosts")
    fingerprint = authority(workload, broker.operation_hosts(config)[workload["host_id"]])
    with broker.store.transaction() as db:
        broker.store.reconcile(db)
        cached = _require_cache(db, workload_id, fingerprint)
        inspection = cached["inspection"]
        if action not in inspection["supported_actions"]:
            raise ValueError("Native inspection reports this action unsupported; inspect blockers")
        proposal = {"id": uuid.uuid4().hex, "kind": "lifecycle", "backend": workload["backend"],
            "action": action, "workload_id": workload_id, "source_id": workload["host_id"], "target_id": workload["host_id"],
            "inspection_fingerprint": cached["inspection_fingerprint"], "inspection": inspection,
            "inspected_at": cached["inspected_at"], "approval_required": True,
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
            "steps": ["Acquire canonical host lease", "Reinspect native identity and state; refuse changed preconditions",
                      action.capitalize() + " only the explicitly adopted native workload", "Verify native runtime postcondition"],
            "warnings": ["Native runtime state is not application health.",
                         "Transport loss can leave uncertain effects; no automatic retry.", *inspection["warnings"]]}
        db.execute("DELETE FROM plans WHERE consumed=0 AND json_extract(data,'$.expires_at') < ?", (now(),))
        if db.execute("SELECT count(*) FROM plans WHERE consumed=0").fetchone()[0] >= 256:
            raise ValueError("Too many outstanding plans")
        db.execute("INSERT INTO plans(id,data,fingerprint) VALUES(?,?,?)", (proposal["id"], encode(proposal), fingerprint))
        broker.store.bump(db)
    return proposal


def execute(broker, config, db, row, proposal, request_id):
    """Prepare durable execution inside broker transaction; remote work is dispatched later."""
    workload = config["workloads"].get(proposal["workload_id"])
    if (not workload or workload.get("backend") not in BACKENDS or proposal.get("backend") != workload["backend"]
            or proposal.get("kind") != "lifecycle" or proposal.get("action") not in ACTIONS
            or proposal.get("source_id") != workload["host_id"] or proposal.get("target_id") != workload["host_id"]):
        raise ValueError("Lifecycle plan authority or kind changed; plan again")
    fingerprint = authority(workload, broker.operation_hosts(config)[workload["host_id"]])
    if row["fingerprint"] != fingerprint or datetime.fromisoformat(proposal["expires_at"]) <= datetime.now(timezone.utc):
        raise ValueError("Lifecycle plan expired or operator authority changed; plan again")
    cached = _require_cache(db, proposal["workload_id"], fingerprint, proposal["inspection_fingerprint"])
    if cached["inspection"] != proposal["inspection"] or proposal["action"] not in cached["inspection"]["supported_actions"]:
        raise ValueError("Lifecycle inspection preconditions changed; plan again")
    intent = {"plan_id": proposal["id"], "action": proposal["action"], "target_id": proposal["target_id"]}
    result = broker._begin(db, request_id=request_id, intent=intent, kind="lifecycle",
                          host_ids=[workload["host_id"]], workload_id=proposal["workload_id"], plan_id=proposal["id"])
    request = _request(broker, config, proposal["workload_id"], workload, fingerprint, proposal["action"])
    request.update(expected=cached["inspection"], inspection_fingerprint=cached["inspection_fingerprint"])
    return result, request


def _current_authority(request, hosts, store):
    try:
        from . import operations_policy
        from .workload_store import WorkloadStore
        config = operations_policy.parse(operations_policy.read(request["config_path"]), request["config_path"])
        with store.workloads.reading() as db:
            record = WorkloadStore.record(db, request["workload_id"])
        workload, grant = operations_policy.resolve(request["workload_id"], config["workloads"][request["workload_id"]], record)
        workload = validate_workload(request["workload_id"], workload, hosts)
        if request["action"] != "inspect" and request["action"] not in grant["actions"]:
            return False
        host = hosts[workload["host_id"]]
        # The dispatched host map is a snapshot. Local execution identity lives in the live operations
        # file, so revoking or changing a local target must also stop a dispatched-but-unstarted action.
        targets = config.get("local_targets", {})
        if not isinstance(targets, dict):
            return False
        local = workload["host_id"] in targets
        if local != (request.get("local") is True):
            return False
        if local and targets[workload["host_id"]] != {"target": host["target"], "ledger": host["ledger"]}:
            return False
        return workload == request["config"] and authority(workload, host) == request["authority_fingerprint"]
    except (OSError, ValueError, TypeError, KeyError):
        return False


def execute_worker(request, hosts, store, operation_id):
    """Caller holds canonical leases. No SQLite transaction spans an SSH call."""
    workload = request["config"]
    backend = workload["backend"]
    if backend not in BACKENDS or request["action"] not in {"inspect", *ACTIONS}:
        return {"status": "failed", "error": "Invalid scoped lifecycle request; no remote command executed"}
    if not _current_authority(request, hosts, store):
        return {"status": "failed", "error": "Workload authority changed before dispatch; no remote command executed"}
    if request["action"] != "inspect":
        try:
            with store.transaction() as db:
                cached = _require_cache(db, request["workload_id"], request["authority_fingerprint"], request["inspection_fingerprint"])
                if cached["inspection"] != request["expected"]:
                    raise ValueError("Inspection changed")
        except ValueError:
            return {"status": "failed", "error": "Workload inspection changed or expired while acquiring lease; no remote command executed"}
    store.event(operation_id, "lifecycle-dispatched", {"backend": backend, "action": request["action"], "host_id": workload["host_id"]})
    filename = "compose_remote.py" if backend == "compose" else "systemd_remote.py"
    source = Path(__file__).with_name(filename).read_text() + "\nprint(json.dumps(run(PAYLOAD)))\n"
    result = run_remote(hosts[workload["host_id"]], source,
                        {"action": request["action"], "config": workload, "expected": request.get("expected")},
                        timeout=240, local=request["local"] is True)
    if not isinstance(result, dict) or result.get("status") not in {"succeeded", "failed", "needs-inspection"}:
        raise RemoteError("Invalid scoped lifecycle result; effects need inspection")
    clean = {"status": result["status"]}
    if result.get("error") is not None:
        if not isinstance(result["error"], str) or len(result["error"]) > 1024 or any(ord(char) < 32 for char in result["error"]):
            raise RemoteError("Invalid scoped lifecycle error metadata")
        clean["error"] = result["error"]
    if "inspection" in result:
        try:
            clean["inspection"] = _inspection(result["inspection"], backend)
        except RemoteError as error:
            # These validator messages are constant-authored, never remote
            # diagnostics. Keep the actual boundary failure visible to operators.
            return {"status": "needs-inspection", "error": str(error)}
    if result["status"] == "succeeded" and "inspection" not in clean:
        raise RemoteError("Successful lifecycle operation omitted inspection")
    if not _current_authority(request, hosts, store):
        return {"status": "needs-inspection", "error": "Operator authority changed during remote observation/action; inspect again"}
    if clean["status"] == "succeeded":
        observed_at = now()
        revision = digest({"authority": request["authority_fingerprint"], "inspection": clean["inspection"], "observed_at": observed_at, "nonce": uuid.uuid4().hex})
        with store.transaction() as db:
            db.execute("INSERT INTO lifecycle_inspections(workload_id,authority_fingerprint,inspection,inspected_at,revision) VALUES(?,?,?,?,?) "
                       "ON CONFLICT(workload_id) DO UPDATE SET authority_fingerprint=excluded.authority_fingerprint,inspection=excluded.inspection,inspected_at=excluded.inspected_at,revision=excluded.revision",
                       (request["workload_id"], request["authority_fingerprint"], encode(clean["inspection"]), observed_at, revision))
            db.execute("DELETE FROM lifecycle_inspections WHERE workload_id NOT IN "
                       "(SELECT workload_id FROM lifecycle_inspections ORDER BY inspected_at DESC,workload_id LIMIT 64)")
            store.bump(db)
        clean.update(inspected_at=observed_at, inspection_fingerprint=revision)
    return clean
