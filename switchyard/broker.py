"""Explicitly configured operation authority, durable plans and private receipts."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading
import uuid

from .collector import _json, _validate_config
from . import operations_policy
from .operation_store import Store, digest, encode, now, process_identity
from .remote import RemoteError, run_bounded
from .workload_store import WorkloadStore

ACTIONS = operations_policy.MANAGED_ACTIONS
REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
DEVICE_PATH = re.compile(r"/dev/[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*\Z")
_SLOTS = threading.BoundedSemaphore(2)


class Broker:
    def __init__(self, config_path, *, hosts: dict, state_dir: Path, lease_state_dir: Path | None = None):
        self.config_path = Path(config_path) if config_path is not None else None
        self.hosts = {key: dict(value) for key, value in hosts.items()}
        self.store = Store(state_dir)
        self.lease_state_dir = Path(lease_state_dir if lease_state_dir is not None else state_dir).resolve()
        self._configuration()

    def _configuration(self):
        """The operations policy with every granted workload described by its workload store record: `workloads`
        maps IDs to descriptions (the broker's internal form), `grants` to `{actions, hosts}`."""
        if self.config_path is None:
            return None
        try:
            config = operations_policy.parse(operations_policy.read(self.config_path), self.config_path)
            self._host_list(config["shell_hosts"])
            key_hosts = self.operation_hosts(config)
            fleet_hosts = config.get("fleet_key_hosts", [])
            if not isinstance(fleet_hosts, list) or len(fleet_hosts) > 32 or any(not isinstance(item, str) for item in fleet_hosts) or len(set(fleet_hosts)) != len(fleet_hosts):
                raise ValueError("Invalid fleet key host allowlist")
            for host_id in fleet_hosts:
                if host_id not in key_hosts or key_hosts[host_id].get("transport") != "ssh":
                    raise ValueError("Fleet keys require configured SSH or explicit local key targets")
                _validate_config(key_hosts[host_id])
            # Separate authorities: Switchyard-deployed workloads, and start tokens of registered (adopted) ones.
            for key, label in (("deploy_hosts", "Deploy"), ("token_hosts", "Token")):
                allowed = config.get(key, [])
                if not isinstance(allowed, list) or len(allowed) > 32 or any(not isinstance(item, str) for item in allowed) or len(set(allowed)) != len(allowed):
                    raise ValueError("Invalid " + label.lower() + " host allowlist")
                for host_id in allowed:
                    if host_id not in key_hosts or key_hosts[host_id].get("transport") != "ssh":
                        raise ValueError(label + " hosts require configured SSH or explicit local targets")
                    _validate_config(key_hosts[host_id])
            # Devices a deployment may be given, per deploy host: authority, never read from a template.
            devices = config.get("deploy_devices", {})
            if not isinstance(devices, dict) or len(devices) > 32:
                raise ValueError("Invalid deploy device grants")
            for host_id, paths in devices.items():
                if host_id not in config.get("deploy_hosts", []):
                    raise ValueError("Device grants are for deploy hosts only: " + str(host_id))
                if (not isinstance(paths, list) or not 1 <= len(paths) <= 16 or len(set(paths)) != len(paths)
                        or any(not isinstance(path, str) or not DEVICE_PATH.fullmatch(path) or "/../" in path + "/"
                               or "/./" in path + "/" for path in paths)):
                    raise ValueError("Device grants of " + str(host_id) + " must be 1-16 distinct /dev/... paths")
            from .lifecycle_ops import validate_workload
            with self.store.workloads.reading() as db:
                records = {key: WorkloadStore.record(db, key) for key in config["workloads"]}
            workloads, grants = {}, {}
            for workload_id, grant in config["workloads"].items():
                workload, grants[workload_id] = operations_policy.resolve(workload_id, grant, records[workload_id])
                if workload.get("backend"):
                    workloads[workload_id] = validate_workload(workload_id, workload, key_hosts)
                    continue
                self._host_list(workload["allowed_hosts"])
                if workload["container_name"] != "switchyard-foobar" or workload["image"] != "docker.io/nginxinc/nginx-unprivileged:1.28.0-alpine" or type(workload["port"]) is not int or workload["port"] != 18080:
                    raise ValueError("Only the disposable rootless nginx recipe is supported")
                if not isinstance(workload["name"], str) or not 1 <= len(workload["name"]) <= 128:
                    raise ValueError("Invalid workload name")
                path = workload["site_file"]
                if not isinstance(path, str) or len(path) > 4096 or not Path(path).is_absolute():
                    raise ValueError("Site content must be an operator-selected absolute path")
                workloads[workload_id] = workload
            return {**config, "workloads": workloads, "grants": grants}
        except (OSError, TypeError, KeyError, UnicodeError) as error:
            raise ValueError("Invalid or unreadable operations configuration") from error

    def _host_list(self, value):
        if not isinstance(value, list) or len(value) > 32 or any(not isinstance(item, str) for item in value) or len(set(value)) != len(value):
            raise ValueError("Invalid operations host list")
        for host_id in value:
            host = self.hosts.get(host_id)
            if host is None or host.get("transport") != "ssh":
                raise ValueError("Operations require an enrolled SSH host")
            _validate_config(host)  # Revalidate the target and its declared resource identity.
        return value

    def operation_hosts(self, config):
        """Collector hosts, with collector-local hosts given their operator-declared execution identity.

        A local target names the account and canonical device ledger that operations on the control-plane
        host itself must use. Fixed sources then run in a local child instead of bootstrap self-SSH."""
        targets = config.get("local_targets", {})
        if not isinstance(targets, dict) or len(targets) > 32:
            raise ValueError("Invalid local operation targets")
        hosts = dict(self.hosts)
        for host_id, target in targets.items():
            original = hosts.get(host_id)
            if not original or original.get("transport") != "local" or not isinstance(target, dict) or set(target) != {"target", "ledger"}:
                raise ValueError("Local operation targets are only for configured local collectors")
            hosts[host_id] = _validate_config({"host_id": host_id, "transport": "ssh", "target": target["target"],
                                              "ledger": target["ledger"], "expected_hostname": original["expected_hostname"],
                                              "user_units": [], "system_units": []})
        return hosts

    @staticmethod
    def local_host_ids(config):
        return sorted(config.get("local_targets", {}))

    def _enabled(self):
        config = self._configuration()
        if config is None:
            raise ValueError("Operations are not configured")
        return config

    def policy(self):
        config = self._configuration()
        if config is None:
            return {"enabled": False, "shell_hosts": [], "workloads": [], "fleet_key_hosts": []}
        from .lifecycle_ops import policy_entry
        return {"enabled": True, "shell_hosts": list(config["shell_hosts"]),
                "fleet_key_hosts": list(config.get("fleet_key_hosts", [])), "workloads": [
            (policy_entry(key, value, config["grants"][key]["actions"]) if value.get("backend") else
             {"id": key, "name": value["name"], "allowed_hosts": list(value["allowed_hosts"]),
              "actions": list(config["grants"][key]["actions"]), "backend": "podman", "container_name": value["container_name"]})
            for key, value in config["workloads"].items()]}

    @staticmethod
    def _granted(config, action, workload_id):
        if action not in config["grants"][workload_id]["actions"]:
            raise ValueError(f"The operations policy does not grant {action} on {workload_id}")

    def _content(self, workload):
        try:
            with Path(workload["site_file"]).open("rb") as stream:
                content = stream.read(65537)
            if not content or len(content) > 65536:
                raise ValueError("Static page must contain 1–65536 UTF-8 bytes")
            return content.decode("utf-8")
        except (OSError, UnicodeError) as error:
            raise ValueError("Static page must be readable UTF-8 operator-selected content") from error

    def _fingerprint(self, config, content):
        relevant = set(config["shell_hosts"])
        for workload in config["workloads"].values():
            relevant.update([workload["host_id"]] if workload.get("backend") else workload["allowed_hosts"])
        return digest({"configuration": config, "hosts": {key: self.hosts[key] for key in sorted(relevant)},
                       "content_sha256": hashlib.sha256(content.encode()).hexdigest()})

    def plan(self, action, workload_id, target_id=None):
        config = self._enabled()
        if not isinstance(action, str) or not isinstance(workload_id, str) or workload_id not in config["workloads"]:
            raise ValueError("Unsupported workload operation")
        workload = config["workloads"][workload_id]
        if workload.get("backend"):
            from .lifecycle_ops import plan
            return plan(self, config, action, workload_id, target_id)
        if action not in ACTIONS:
            raise ValueError("Unsupported workload operation")
        self._granted(config, action, workload_id)
        if target_id is not None and (not isinstance(target_id, str) or target_id not in workload["allowed_hosts"]):
            raise ValueError("Target host is not authorized for this workload")
        content = self._content(workload)
        with self.store.transaction() as db:
            self.store.reconcile(db)
            state = self.store.ownership(db, workload_id)
            placement = state["placement"]
            source_id = placement.get("host_id") if placement else None
            if action == "deploy":
                if placement is not None:
                    raise ValueError("Workload already has recorded placement; use start or explicit recovery")
                target_id = target_id or workload["initial_host"]
            elif not placement:
                raise ValueError("No broker-owned placement exists; observation is not lifecycle authority")
            elif action == "migrate":
                if target_id is None or target_id == source_id:
                    raise ValueError("Cold migration requires a different explicit target host")
            elif action == "recover":
                recovery = placement.get("recovery")
                expected = (recovery["source"]["host_id"] if isinstance(recovery, dict)
                            and isinstance(recovery.get("source"), dict) else source_id)
                if target_id is not None and target_id != expected:
                    raise ValueError("Recovery target must be the recorded original source")
                target_id = expected
            elif target_id is not None and target_id != source_id:
                raise ValueError("Start/stop cannot change recorded placement")
            else:
                target_id = source_id
            if action in {"start", "migrate"} and (placement.get("uncertain") or placement.get("lifecycle") == "unknown"):
                raise ValueError("Placement is uncertain; inspect and explicitly recover before start or migration")
            if source_id is not None and source_id not in workload["allowed_hosts"]:
                raise ValueError("Recorded source is no longer authorized")
            plan = {"id": uuid.uuid4().hex, "action": action, "workload_id": workload_id,
                    "source_id": source_id, "target_id": target_id,
                    "steps": self._steps(action), "warnings": [
                        "Only the owned disposable foobar workload may be changed.",
                        "Transport loss can leave uncertain effects; no command is automatically retried."],
                    "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
                    "approval_required": True, "placement_fingerprint": digest(placement)}
            db.execute("DELETE FROM plans WHERE consumed=0 AND json_extract(data,'$.expires_at') < ?", (now(),))
            if db.execute("SELECT count(*) FROM plans WHERE consumed=0").fetchone()[0] >= 256:
                raise ValueError("Too many outstanding plans")
            db.execute("INSERT INTO plans(id,data,fingerprint) VALUES(?,?,?)",
                       (plan["id"], encode(plan), self._fingerprint(config, content)))
            self.store.bump(db)
        return plan

    @staticmethod
    def _steps(action):
        return {
            "deploy": ["Acquire every host lease", "Verify rootless target, ownership, path and port", "Pull and pin image identity", "Create restricted container and verify exact HTTP page"],
            "start": ["Acquire host lease", "Verify recorded ownership and configuration", "Start owned container and verify exact HTTP page"],
            "stop": ["Acquire host lease", "Verify recorded native identity and ownership", "Stop only the owned container and verify it stopped"],
            "migrate": ["Acquire source and target leases", "Verify source and preflight/prestage target before stopping source", "Stop owned source and transfer verified page", "Start destination and verify stopped source plus exact destination HTTP page"],
            "recover": ["Acquire source and destination leases", "Prove owned destination stopped or absent", "Verify original source identity and content", "Start original source and verify exact HTTP page"],
        }[action]

    @staticmethod
    def _request_id(value):
        if not isinstance(value, str) or not REQUEST_ID.fullmatch(value):
            raise ValueError("Request ID must be 1–128 safe identifier characters")

    def _begin(self, db, *, request_id, intent, kind, host_ids, workload_id=None, plan_id=None, details=None):
        self._request_id(request_id)
        self.store.reconcile(db)
        row = db.execute("SELECT intent_hash,receipt FROM operations WHERE request_id=?", (request_id,)).fetchone()
        intent_hash = digest(intent)
        if row:
            if row["intent_hash"] != intent_hash:
                raise ValueError("Request ID is already bound to a different intent")
            return {"receipt": json.loads(row["receipt"]), "replayed": True}
        receipt = {"id": uuid.uuid4().hex, "kind": kind, "status": "running", "host_ids": sorted(set(host_ids)),
                   "started_at": now(), "events": [], **(details or {})}
        if kind in {"fleet-keys", "fleet-key-inspect"}:
            receipt["action"] = intent.get("action", "inspect")
        if kind in {"deploy", "token"}:
            receipt["action"] = intent.get("action")
            for key in ("instance_id", "application_id", "component"):
                if intent.get(key) is not None:
                    receipt[key] = intent[key]
        if workload_id:
            receipt["workload_id"] = workload_id
            receipt["action"] = intent["action"]
            receipt["target_id"] = intent.get("target_id")
        if plan_id:
            consumed = db.execute("UPDATE plans SET consumed=1 WHERE id=? AND consumed=0", (plan_id,)).rowcount
            if not consumed:
                raise ValueError("Plan was already executed; use its original request ID or create a new plan")
        busy = db.execute("SELECT count(*) FROM operations WHERE json_extract(receipt,'$.status')='running'").fetchone()[0] >= 2
        db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?)", (receipt["id"], request_id, intent_hash,
                   encode(receipt), os.getpid(), process_identity()))
        self.store.bump(db)
        if busy:
            receipt = self.store.finish(db, receipt["id"], {"status": "busy", "error": "Two operations are already executing; submit a new request after inspecting receipts"})
        return {"receipt": receipt}

    def plan_kind(self, plan_id):
        self._request_id(plan_id)
        with self.store.transaction() as db:
            row = db.execute("SELECT json_extract(data,'$.kind') FROM plans WHERE id=?", (plan_id,)).fetchone()
        return row[0] if row is not None else None

    def execute(self, plan_id, *, approved, request_id):
        if approved is not True:
            raise ValueError("Execution requires literal approved=true")
        self._request_id(request_id)
        if not isinstance(plan_id, str) or not REQUEST_ID.fullmatch(plan_id):
            raise ValueError("Invalid plan ID")
        config = self._enabled()
        with self.store.transaction() as db:
            row = db.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
            if row is None:
                raise ValueError("Unknown operation plan")
            plan = json.loads(row["data"])
            if plan.get("kind") not in {None, "lifecycle"}:
                raise ValueError("This plan kind requires its dedicated execute method")
            intent = {"plan_id": plan_id, "action": plan["action"], "target_id": plan["target_id"]}
            # Existing intent is returned even after plan expiry/config change, never re-executed.
            old = db.execute("SELECT intent_hash,receipt FROM operations WHERE request_id=?", (request_id,)).fetchone()
            if old:
                self.store.reconcile(db)
                if old["intent_hash"] != digest(intent):
                    raise ValueError("Request ID is already bound to a different intent")
                return {"receipt": json.loads(db.execute("SELECT receipt FROM operations WHERE request_id=?", (request_id,)).fetchone()[0]), "replayed": True}
            workload = config["workloads"].get(plan["workload_id"])
            if workload is None:
                raise ValueError("Workload is no longer authorized")
            self._granted(config, plan["action"], plan["workload_id"])
            if plan.get("kind") == "lifecycle":
                from .lifecycle_ops import execute
                result, request = execute(self, config, db, row, plan, request_id)
                kind = "lifecycle"
            else:
                if workload.get("backend"):
                    raise ValueError("Managed Podman plan cannot execute scoped lifecycle authority")
                content = self._content(workload)
                if datetime.fromisoformat(plan["expires_at"]) <= datetime.now(timezone.utc) or row["fingerprint"] != self._fingerprint(config, content):
                    raise ValueError("Plan expired or operator configuration/content changed; plan again")
                self.store.reconcile(db)
                state = self.store.ownership(db, plan["workload_id"])
                placement = state["placement"]
                if digest(placement) != plan["placement_fingerprint"]:
                    raise ValueError("Recorded placement changed; plan again")
                host_ids = {item for item in (plan["source_id"], plan["target_id"]) if item}
                if placement and placement.get("recovery"):
                    recovery = placement["recovery"]
                    host_ids.update(item for item in (recovery.get("target_id"), recovery.get("source", {}).get("host_id")) if item)
                if not host_ids <= set(workload["allowed_hosts"]):
                    raise ValueError("Recovery includes a host no longer authorized")
                result = self._begin(db, request_id=request_id, intent=intent, kind="managed", host_ids=host_ids,
                                     workload_id=plan["workload_id"], plan_id=plan_id)
                request = {key: plan[key] for key in ("action", "workload_id", "source_id", "target_id")}
                request.update(config={**workload, "ownership_id": state["ownership_id"]}, placement=placement,
                               site_content=content, site_sha256=hashlib.sha256(content.encode()).hexdigest(),
                               operation_id=result["receipt"]["id"])
                kind = "managed"
        if result["receipt"]["status"] != "running" or result.get("replayed"):
            return result
        payload = {"kind": kind, "request": request}
        if kind == "lifecycle":
            payload["operation_hosts"] = self.operation_hosts(config)
        return self._dispatch(result["receipt"], payload)

    def shell(self, host_id, script, *, timeout_seconds=30, request_id, extra_host_ids=None):
        config = self._enabled()
        if not isinstance(host_id, str) or host_id not in config["shell_hosts"]:
            raise ValueError("Shell host is not explicitly authorized")
        if not isinstance(script, str) or not script.strip() or len(script.encode()) > 16384 or "\0" in script:
            raise ValueError("Shell script must contain 1–16384 UTF-8 bytes without NUL")
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 240:
            raise ValueError("Shell timeout must be 1–240 seconds")
        extra_host_ids = [] if extra_host_ids is None else extra_host_ids
        self._host_list(extra_host_ids)
        if not set(extra_host_ids) <= set(config["shell_hosts"]):
            raise ValueError("Every declared shell host must be explicitly authorized")
        host_ids = sorted(set([host_id, *extra_host_ids]))
        intent = {"host_id": host_id, "script_sha256": hashlib.sha256(script.encode()).hexdigest(),
                  "timeout_seconds": timeout_seconds, "host_ids": host_ids}
        with self.store.transaction() as db:
            # The audit entry records exactly what ran (operator request 2026-11-23); output is never stored.
            result = self._begin(db, request_id=request_id, intent=intent, kind="shell", host_ids=host_ids,
                                 details={"script": script, "script_sha256": intent["script_sha256"],
                                          "timeout_seconds": timeout_seconds})
        if result["receipt"]["status"] != "running" or result.get("replayed"):
            return result
        return self._dispatch(result["receipt"], {"kind": "shell", "host_id": host_id, "script": script,
                                                  "timeout_seconds": timeout_seconds})

    def _dispatch(self, receipt, payload):
        if not _SLOTS.acquire(blocking=False):
            with self.store.transaction() as db:
                final = self.store.finish(db, receipt["id"], {"status": "busy",
                    "error": "Two operations are already executing in this process; no remote command executed"})
            return {"receipt": final}
        try:
            return self._dispatch_locked(receipt, payload)
        finally:
            _SLOTS.release()

    def _dispatch_locked(self, receipt, payload):
        operation_id = receipt["id"]
        try:
            configured = payload.pop("operation_hosts", self.hosts)
            hosts = {key: _validate_config(configured[key]) for key in receipt["host_ids"]}
        except (ValueError, OSError):
            with self.store.transaction() as db:
                final = self.store.finish(db, operation_id, {"status": "failed",
                    "error": "Host authority changed before dispatch; no remote command executed"})
            return {"receipt": final}
        payload.update(operation_id=operation_id, state_dir=str(self.store.directory),
                       lease_state_dir=str(self.lease_state_dir), hosts=hosts)
        root = str(Path(__file__).resolve().parents[1])
        command = [sys.executable, "-I", "-c", "import sys; sys.path.insert(0," + repr(root)
                   + "); from switchyard.operation_worker import main; main()"]
        # Compound switches get more time; bounded LAN route inspections and probes need less.
        bound = payload.pop("worker_seconds", 285)
        if type(bound) is not int or not 85 <= bound <= 600:
            bound = 285
        source = encode(payload).encode()
        try:
            status, output = run_bounded(command, source, timeout=bound, cleanup_seconds=5.0)
            if status == 75:
                final = {"status": "busy", "error": "A canonical device lease is busy; no remote action was dispatched"}
            elif status != 0:
                final = {"status": "needs-inspection", "error": "Operation worker did not finish normally; inspect its receipt and remote effects"}
            else:
                value = _json(output)
                if not isinstance(value, dict) or value.get("operation_id") != operation_id:
                    raise RemoteError("Invalid operation worker response; effects need inspection")
                returned = {key: value[key] for key in ("stdout", "stderr") if key in value}
                returned["receipt"] = self.store.get(operation_id)
                return returned
        except (OSError, ValueError, RemoteError):
            final = {"status": "needs-inspection", "error": "Operation transport interrupted; remote effects need inspection"}
        except BaseException:
            with self.store.transaction() as db:
                self.store.finish(db, operation_id, {"status": "needs-inspection", "error": "Operation caller interrupted; inspect remote effects"})
            raise
        with self.store.transaction() as db:
            result = self.store.finish(db, operation_id, final)
        return {"receipt": result}

    def inspect_workload(self, workload_id, *, request_id):
        from .lifecycle_ops import inspect
        return inspect(self, workload_id, request_id)

    def lifecycle_inspections(self):
        from .lifecycle_ops import inspections
        return inspections(self)

    def fleet_keys(self):
        from .fleet_keys import status
        return status(self)

    def inspect_fleet_keys(self, host_ids, *, request_id):
        from .fleet_keys import inspect
        return inspect(self, host_ids, request_id)

    def plan_fleet_keys(self, action, host_ids):
        from .fleet_keys import plan
        return plan(self, action, host_ids)

    def execute_fleet_keys(self, plan_id, *, approved, request_id):
        from .fleet_keys import execute
        return execute(self, plan_id, approved, request_id)

    def receipts(self):
        with self.store.transaction() as db:
            self.store.reconcile(db)
            return [json.loads(row[0]) for row in db.execute("SELECT receipt FROM operations ORDER BY rowid DESC LIMIT 200")]

    def receipt(self, operation_id):
        if not isinstance(operation_id, str) or not REQUEST_ID.fullmatch(operation_id):
            raise ValueError("Invalid operation ID")
        return self.store.get(operation_id)

    def placements(self):
        with self.store.transaction() as db:
            self.store.reconcile(db)
            return self.store.placements(db)

    def revision(self):
        with self.store.transaction() as db:
            self.store.reconcile(db)
            return db.execute("SELECT value FROM metadata WHERE key='revision'").fetchone()[0]
