"""Private subprocess entrypoint: hold every device lease around operation effects."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import signal
import sys
import time

from .collector import _json, _validate_config
from .lease_db import resource_label
from .leases import LedgerBroker, LeaseBusy, mark_uncertain
from .operation_store import Store, digest, process_identity
from .remote import MAX_INPUT, RemoteError, SHELL_SOURCE, run_remote


def operation_lease_wait():
    """Seconds an operation waits for a busy device before reporting busy (default 10, 0-600).
    The monitor's sub-second observation leases collide often; nothing has executed while waiting."""
    value = float(os.environ.get("SWITCHYARD_OPERATION_LEASE_WAIT", "10"))
    if not 0 <= value <= 600:
        raise ValueError("SWITCHYARD_OPERATION_LEASE_WAIT must be 0-600 seconds")
    return value


def main():
    started = time.monotonic()
    data = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise ValueError("Worker input exceeds limit")
    payload = _json(data)
    store = Store(payload["state_dir"])
    operation_id = payload["operation_id"]
    interrupted = False

    def cancel(signum, frame):
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise InterruptedError("Operation cancelled")

    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)
    # Transfer durable liveness to the actual worker before it can acquire leases.
    with store.transaction() as db:
        row = db.execute("SELECT receipt FROM operations WHERE id=?", (operation_id,)).fetchone()
        if row is None or json.loads(row[0])["status"] != "running":
            raise RuntimeError("Operation is no longer active")
        db.execute("UPDATE operations SET pid=?,birth=? WHERE id=?", (os.getpid(), process_identity(), operation_id))
    result = {"status": "needs-inspection", "error": "Operation worker interrupted; inspect remote effects"}
    returned = {"operation_id": operation_id}
    try:
        hosts = {key: _validate_config(value) for key, value in payload["hosts"].items()}
        ordered = sorted(hosts.values(), key=lambda host: resource_label(host["host_id"], host["ledger"]))
        wait = operation_lease_wait()
        with ExitStack() as leases:
            try:
                for host in ordered:
                    leases.enter_context(LedgerBroker({host["host_id"]: Path(host["ledger"])},
                                                      state_dir=payload["lease_state_dir"]).hold(
                        host["host_id"], owner="switchyard", scope="operation=" + operation_id + "; consult private receipt",
                        worktree=str(Path(__file__).resolve().parents[1]), wait=wait))
            except BaseException:
                # No host action was dispatched. Earlier grants in this batch can end normally.
                leases.close()
                raise
            store.event(operation_id, "leases-acquired", {"host_ids": sorted(hosts)})
            if payload["kind"] == "shell":
                store.event(operation_id, "shell-dispatched", {
                    "host_id": payload["host_id"], "timeout_seconds": payload["timeout_seconds"],
                    "caveat": "Unrestricted unprivileged shell; declared leases only. Detached or remote work may outlive transport; no automatic retries."})
                result = run_remote(hosts[payload["host_id"]], SHELL_SOURCE,
                                    {"script": payload["script"], "timeout_seconds": payload["timeout_seconds"]},
                                    timeout=payload["timeout_seconds"] + 5)
                if result.get("status") == "needs-inspection":
                    mark_uncertain("shell completion unconfirmed", resource=payload["host_id"])
                if result.get("status") not in {"succeeded", "failed", "needs-inspection"}:
                    raise RemoteError("Invalid shell result; effects need inspection")
                for key in ("stdout", "stderr"):
                    value = result.get(key)
                    if not isinstance(value, str) or len(value.encode()) > 65536:
                        raise RemoteError("Invalid bounded shell output; effects need inspection")
                    returned[key] = value
                # Output and arbitrary scripts deliberately never reach the store.
                result = {key: result[key] for key in ("status", "exit_code", "error") if key in result}
            elif payload["kind"] == "managed":
                request = payload["request"]
                with store.transaction() as db:
                    found = store.placement(db, request["workload_id"])
                    current = found["placement"] if found else None
                if digest(current) != digest(request["placement"]):
                    result = {"status": "failed", "error": "Placement changed before dispatch; no remote command executed; plan again"}
                else:
                    # Import only after all canonical host leases have been acquired.
                    from .podman_ops import execute_managed
                    result = execute_managed(request, hosts, lambda event, data: store.event(operation_id, event, data))
                    if not isinstance(result, dict):
                        raise RemoteError("Invalid lifecycle result; effects need inspection")
                    for key in ("stdout", "stderr"):
                        if key in result:
                            if not isinstance(result[key], str) or len(result[key].encode()) > 65536:
                                raise RemoteError("Invalid lifecycle diagnostics")
                            returned[key] = result[key]
            elif payload["kind"] == "lifecycle":
                from .lifecycle_ops import execute_worker
                result = execute_worker(payload["request"], hosts, store, operation_id)
            elif payload["kind"] == "fleet-keys":
                from .fleet_keys import execute_worker
                result = execute_worker(payload["request"], hosts, store, operation_id,
                                        local_host_ids=payload.get("local_host_ids", []))
            elif payload["kind"] == "deploy":
                from .deploy import execute_worker
                result = execute_worker(payload["request"], hosts, store, operation_id,
                                        local_host_ids=payload.get("local_host_ids", []), started=started)
            elif payload["kind"] == "token":
                from .tokens import execute_worker
                result = execute_worker(payload["request"], hosts, store, operation_id,
                                        local_host_ids=payload.get("local_host_ids", []))
            else:
                raise ValueError("Unknown internal operation kind")
            with store.transaction() as db:
                store.finish(db, operation_id, result)
    except LeaseBusy as error:
        result = {"status": "busy", "error": str(error)[:500] + "; no remote command executed"}
    except (RemoteError, InterruptedError):
        result = {"status": "needs-inspection", "error": "Operation transport interrupted; remote effects need inspection; no automatic retry"}
    except Exception:
        result = {"status": "needs-inspection", "error": "Operation worker failed; inspect private receipt and remote effects"}
    finally:
        with store.transaction() as db:
            store.finish(db, operation_id, result)
    print(json.dumps(returned))


if __name__ == "__main__":
    main()
