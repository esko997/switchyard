"""Durable, explicitly approved public-key mesh enrollment via leased workers."""
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
from pathlib import Path
import os
import time
import stat
import uuid

from .collector import _json, _validate_config
from .operation_store import digest, encode, now
from .remote import RemoteError, run_remote
from . import fleet_keys_remote

ACTIONS = {"enroll", "remove", "rotate", "reconcile"}


def initial_state():
    return {"members": [], "participants": [], "hosts": {}, "connections": []}


def load(db):
    row = db.execute("SELECT data FROM fleet_keys WHERE id=1").fetchone()
    return json.loads(row[0]) if row else initial_state()


def save(store, state):
    with store.transaction() as db:
        db.execute("INSERT INTO fleet_keys(id,data) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", (encode(state),))
        store.bump(db)


def authority(broker, config):
    hosts = broker.operation_hosts(config)
    return digest({"allowed_hosts": config.get("fleet_key_hosts", []), "targets": config.get("local_targets", {}),
                   "hosts": {host_id: hosts[host_id] for host_id in config.get("fleet_key_hosts", [])}})


def status(broker):
    config = broker._configuration()
    allowed = config.get("fleet_key_hosts", []) if config else []
    with broker.store.transaction() as db:
        broker.store.reconcile(db)
        state = load(db)
    records = []
    for host_id in sorted(set(allowed) | set(state["hosts"]) | set(state["members"])):
        record = state["hosts"].get(host_id, {})
        item = {"host_id": host_id, "status": record.get("status", "unknown"),
                "detail": record.get("detail", "Not inspected; explicit read-only inspection is required")}
        generation = record.get("generation")
        key = record.get("inspection", {}).get("keys", {}).get(generation)
        if key:
            item["fingerprint"] = fleet_keys_remote.fingerprint(key)
        if record.get("retiring"):
            item["retiring_generations"] = list(record["retiring"])
        records.append(item)
    return {"enabled": bool(allowed), "allowed_hosts": list(allowed), "members": list(state["members"]),
            "hosts": records, "connections": state["connections"], "revision": digest(state),
            "usage": "ssh -F ~/.ssh/switchyard/config switchyard-<host-id>",
            "caveat": "Cached observations only; SSH trust is not sudo or a cross-host device lease"}


def selected(broker, config, host_ids, *, empty=False):
    if not isinstance(host_ids, list) or len(host_ids) > 32 or any(not isinstance(item, str) for item in host_ids) or len(set(host_ids)) != len(host_ids):
        raise ValueError("Invalid fleet key host list")
    if (not host_ids and not empty) or not set(host_ids) <= set(config.get("fleet_key_hosts", [])):
        raise ValueError("Fleet key hosts must be explicitly authorized")
    return sorted(host_ids)


def inspect(broker, host_ids, request_id):
    config = broker._enabled()
    host_ids = selected(broker, config, host_ids)
    with broker.store.transaction() as db:
        result = broker._begin(db, request_id=request_id, intent={"kind": "fleet-key-inspect", "host_ids": host_ids},
                               kind="fleet-key-inspect", host_ids=host_ids)
    if result.get("replayed") or result["receipt"]["status"] != "running":
        return result
    return broker._dispatch(result["receipt"], {"kind": "fleet-keys", "operation_hosts": broker.operation_hosts(config),
                            "local_host_ids": broker.local_host_ids(config),
                            "request": {"action": "inspect", "host_ids": host_ids}})


def plan(broker, action, host_ids):
    config = broker._enabled()
    if not isinstance(action, str) or action not in ACTIONS:
        raise ValueError("Unsupported fleet key action")
    with broker.store.transaction() as db:
        broker.store.reconcile(db)
        state = load(db)
        host_ids = selected(broker, config, host_ids, empty=action == "reconcile")
        if action == "reconcile":
            if not set(host_ids) <= set(state["participants"]) | set(state["members"]):
                raise ValueError("Reconcile repairs existing desired/former members; use enroll for new hosts")
            # Reconciliation always repairs the full desired mesh, not a misleading subset.
            host_ids = host_ids or list(state["members"])
        if action in {"rotate", "remove"} and not set(host_ids) <= set(state["members"]):
            raise ValueError("Rotation/removal requires desired fleet members")
        participants = sorted(set(state["participants"]) | set(state["members"]) | set(host_ids))
        if not participants or not set(participants) <= set(config.get("fleet_key_hosts", [])):
            raise ValueError("Every current/former peer requiring reconciliation must remain authorized")
        for host_id in participants:
            record = state["hosts"].get(host_id, {})
            if not record.get("inspection"):
                raise ValueError("Inspect every participating host before planning fleet keys: " + host_id)
        if action == "enroll" and set(host_ids) <= set(state["members"]):
            raise ValueError("Hosts are already desired members; use reconcile")
        if action == "rotate" and any(state["hosts"].get(host_id, {}).get("retiring") for host_id in participants):
            raise ValueError("Finish pending rotation with reconcile before rotating again")
        proposal = {"id": uuid.uuid4().hex, "kind": "fleet-keys", "action": action, "host_ids": host_ids,
                    "participants": participants, "state_revision": digest(state),
                    "generations": {host_id: uuid.uuid4().hex for host_id in host_ids if action == "rotate"
                                    or (action == "enroll" and not state["hosts"].get(host_id, {}).get("generation"))},
                    "steps": ["Acquire every source and destination canonical lease",
                              "Compare fresh public metadata and file revisions with inspected state",
                              "Persist desired membership and staged identity generations before changes",
                              "Atomically reconcile only managed sections with on-host prior versions",
                              "Verify every directed connection with dedicated identities and pinned server keys",
                              "Retire old grants only after all new connections verify; retain offline revocations as pending"],
                    "warnings": ["Membership permits each member account to authenticate to its peers; no sudo is granted.",
                                 "Multi-host changes are not atomic; offline hosts and interrupted writes remain pending. No automatic retry.",
                                 "Private keys stay on their source hosts; retired files are retained locally.",
                                 "Managed aliases use ssh -F ~/.ssh/switchyard/config switchyard-<host-id> (port 22)."],
                    "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(), "approval_required": True}
        proposal["warnings"].extend(
            host_id + ": " + state["hosts"][host_id].get("detail", "Verification pending")
            for host_id in participants
            if state["hosts"][host_id].get("status") in {"conflict", "unsupported"}
        )
        db.execute("DELETE FROM plans WHERE consumed=0 AND json_extract(data,'$.expires_at') < ?", (now(),))
        if db.execute("SELECT count(*) FROM plans WHERE consumed=0").fetchone()[0] >= 256:
            raise ValueError("Too many outstanding plans")
        db.execute("INSERT INTO plans(id,data,fingerprint) VALUES(?,?,?)", (proposal["id"], encode(proposal), authority(broker, config)))
        broker.store.bump(db)
    return proposal


def execute(broker, plan_id, approved, request_id):
    if approved is not True:
        raise ValueError("Execution requires literal approved=true")
    broker._request_id(plan_id)
    broker._request_id(request_id)
    config = broker._enabled()
    with broker.store.transaction() as db:
        row = db.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown fleet key plan")
        proposal = json.loads(row["data"])
        if proposal.get("kind") != "fleet-keys":
            raise ValueError("This is not a fleet key plan")
        intent = {"kind": "fleet-keys", "plan_id": plan_id, "action": proposal["action"]}
        old = db.execute("SELECT intent_hash,receipt FROM operations WHERE request_id=?", (request_id,)).fetchone()
        if old:
            broker.store.reconcile(db)
            if old["intent_hash"] != digest(intent):
                raise ValueError("Request ID is already bound to a different intent")
            return {"receipt": json.loads(db.execute("SELECT receipt FROM operations WHERE request_id=?", (request_id,)).fetchone()[0]), "replayed": True}
        if datetime.fromisoformat(proposal["expires_at"]) <= datetime.now(timezone.utc) or row["fingerprint"] != authority(broker, config):
            raise ValueError("Plan expired or fleet key operator authority changed; plan again")
        if proposal["state_revision"] != digest(load(db)):
            raise ValueError("Fleet key inspected state or membership changed; plan again")
        result = broker._begin(db, request_id=request_id, intent=intent, kind="fleet-keys",
                               host_ids=proposal["participants"], plan_id=plan_id)
    if result.get("replayed") or result["receipt"]["status"] != "running":
        return result
    return broker._dispatch(result["receipt"], {"kind": "fleet-keys", "operation_hosts": broker.operation_hosts(config),
                            "local_host_ids": broker.local_host_ids(config), "request": proposal})


def execute_worker(request, hosts, store, operation_id, *, local_host_ids=()):
    # Disjoint host inspections must not overwrite a concurrent mesh/inspection snapshot.
    path = store.directory / "fleet-keys.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise ValueError("Unsafe fleet key state lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"status": "busy", "error": "Another fleet-key operation owns the state lease; no remote command executed"}
        return _execute_worker(request, hosts, store, operation_id, local_host_ids=local_host_ids)
    finally:
        os.close(fd)


def _execute_worker(request, hosts, store, operation_id, *, local_host_ids=()):
    """Called only inside the existing worker's whole-operation canonical leases."""
    source = Path(fleet_keys_remote.__file__).read_text() + "\nmain(PAYLOAD)\n"
    deadline = time.monotonic() + 240
    with store.transaction() as db:
        state = load(db)
    if request["action"] != "inspect" and digest(state) != request["state_revision"]:
        return {"status": "failed", "error": "Fleet key state changed before leases were acquired; no remote command executed"}
    unavailable = set()

    def call(host_id, payload):
        remaining = int(deadline - time.monotonic())
        if remaining < 20:
            unavailable.add(host_id)
            return {"ok": False, "status": "pending", "detail": "Whole-operation deadline reached; explicit reconcile required"}
        try:
            result = run_remote(hosts[host_id], source, payload, timeout=min(20, remaining), local=host_id in local_host_ids)
            if not isinstance(result, dict) or type(result.get("ok")) is not bool:
                raise RemoteError("Invalid key metadata response")
            return result
        except (RemoteError, OSError, ValueError):
            unavailable.add(host_id)
            return {"ok": False, "status": "pending", "detail": "Bootstrap unavailable or interrupted; effects unproven; inspect before explicit reconciliation"}

    def remember(host_id, result):
        record = state["hosts"].setdefault(host_id, {})
        if result.get("ok") and "revision" in result:
            record["inspection"] = {key: result[key] for key in ("supported", "revision", "keys", "server_key")}
            record["inspected_at"] = now()
            record["status"] = "pending" if result["supported"] else "unsupported"
            record["detail"] = result["detail"]
            if result.get("residual_access"):
                record["status"] = "conflict"
                record["detail"] = "Unmanaged authorized_keys duplicates retain retired credentials: " + ", ".join(result["residual_access"])
                record["residual_access"] = result["residual_access"]
            else:
                record.pop("residual_access", None)
        else:
            record["status"] = result.get("status", "pending")
            record["detail"] = result.get("detail", "Remote state unknown")
        return record

    ids = request["host_ids"] if request["action"] == "inspect" else request["participants"]
    # Offline/conflicting fresh observations invalidate old successful connection claims too.
    for connection in state["connections"]:
        if connection["source_id"] in ids or connection["target_id"] in ids:
            connection.update(status="pending", detail="Fresh inspection invalidated prior connection proof; reconcile required")
            connection.pop("verified_at", None)
    fresh = {}
    conflict = False
    for host_id in ids:
        result = call(host_id, {"action": "inspect"})
        previous = state["hosts"].get(host_id, {}).get("inspection")
        if request["action"] != "inspect" and result.get("ok") and previous and result["revision"] != previous["revision"]:
            conflict = True
            # Do not silently accept this new baseline into the approved plan.
            state["hosts"][host_id]["status"] = "conflict"
            state["hosts"][host_id]["detail"] = "SSH files/public identities changed since inspection; explicitly inspect and plan again"
        else:
            remember(host_id, result)
            if result.get("ok") and result.get("supported"):
                fresh[host_id] = result
    if request["action"] == "inspect":
        save(store, state)
        return {"status": "succeeded" if len(fresh) == len(ids) else "needs-inspection",
                "error": None if len(fresh) == len(ids) else "Some hosts are offline, conflicting or unsupported; see cached fleet key status"}
    if conflict:
        save(store, state)
        return {"status": "failed", "error": "Fresh leased file check conflicts with inspected proposal; no key mutation executed; inspect and plan again"}

    # Durable intent precedes the first identity or grant mutation. Process death cannot lose membership/rotation.
    members = set(state["members"])
    if request["action"] == "enroll":
        members.update(request["host_ids"])
    elif request["action"] == "remove":
        members.difference_update(request["host_ids"])
    state["members"] = sorted(members)
    state["participants"] = sorted(set(state["participants"]) | set(ids))
    for host_id, generation in request["generations"].items():
        record = state["hosts"].setdefault(host_id, {})
        if record.get("generation") and record["generation"] != generation:
            record["retiring"] = sorted(set(record.get("retiring", [])) | {record["generation"]})
        record["generation"] = generation
    for record in state["hosts"].values():
        if record.get("status") == "verified":
            record.update(status="pending", detail="Desired mesh changed; verification pending")
    state["connections"] = []
    save(store, state)
    store.event(operation_id, "fleet-key-intent", {"action": request["action"], "members": state["members"], "host_ids": ids})

    def update(host_id, payload):
        payload["expected_revision"] = fresh[host_id]["revision"]
        result = call(host_id, payload)
        remember(host_id, result)
        if result.get("ok") and result.get("supported"):
            fresh[host_id] = result
        else:
            fresh.pop(host_id, None)
        save(store, state)
        return result

    for host_id in sorted(members & fresh.keys()):
        generation = state["hosts"][host_id].get("generation")
        if not generation:
            # Re-enrollment/reconcile of legacy incomplete state still needs a durable generation before creation.
            generation = uuid.uuid4().hex
            state["hosts"][host_id]["generation"] = generation
            save(store, state)
        update(host_id, {"action": "identity", "generation": generation})

    def keys(host_id, *, retiring=True):
        record = state["hosts"].get(host_id, {})
        generations = [record.get("generation"), *(record.get("retiring", []) if retiring else [])]
        public = record.get("inspection", {}).get("keys", {})
        return [(generation, public[generation]) for generation in generations if generation in public]

    def issued_keys(host_id):
        # Retired private files remain on the owner host: removal must check
        # every issued generation, including keys retired by earlier rotations.
        return list(state["hosts"].get(host_id, {}).get("inspection", {}).get("keys", {}).items())

    def peer(host_id):
        inspection = state["hosts"].get(host_id, {}).get("inspection", {})
        return {"host_id": host_id, "target": hosts[host_id]["target"], "server_key": inspection.get("server_key")}

    def configure(host_id, *, retire=False):
        grants = [key for member in members if member != host_id for _, key in keys(member, retiring=not retire)] if host_id in members else []
        peers = [peer(member) for member in sorted(members) if member != host_id] if host_id in members else []
        peers = [item for item in peers if item["server_key"]]
        revoked = [key for member in ids for generation, key in issued_keys(member)
                   if member not in members or host_id not in members
                   or (retire and generation in state["hosts"][member].get("retiring", []))]
        result = update(host_id, {"action": "configure", "generation": state["hosts"][host_id].get("generation"),
                                  "grants": grants, "peers": peers, "revoked_keys": revoked})
        return bool(result.get("ok") and not result.get("residual_access"))

    configured = set()
    for host_id in ids:
        if host_id in fresh and configure(host_id, retire=bool(state.get("retirement_started"))):
            configured.add(host_id)

    def verify_connections():
        connections = []
        for source_id in ids:
            for target_id in ids:
                if source_id == target_id:
                    continue
                desired = source_id in members and target_id in members
                identities = keys(source_id, retiring=False) if desired else issued_keys(source_id)
                item = {"source_id": source_id, "target_id": target_id, "desired": desired, "status": "pending",
                        "detail": "Peer unavailable/unconfigured; revocation or authentication remains pending"}
                if not desired and state["hosts"][target_id].get("residual_access"):
                    item.update(status="conflict", detail="Unmanaged duplicate key grants retain removed credentials")
                if not desired and not identities and source_id in configured and target_id in configured:
                    item.update(status="verified", detail="Source has no recorded issued identity; no managed credential to revoke", verified_at=now())
                if source_id in configured and target_id in configured and identities and peer(target_id)["server_key"]:
                    results = [call(source_id, {"action": "verify", "generation": generation, "peer": peer(target_id)})
                               for generation, _ in identities]
                    if desired and all(result.get("status") == "verified" for result in results):
                        item.update(status="verified", detail="Dedicated identity authenticated with pinned host key", verified_at=now())
                    elif not desired and all(result.get("status") == "revoked" for result in results):
                        item.update(status="verified", detail="Pinned listener rejected every recorded retired identity", verified_at=now())
                    elif not desired and any(result.get("status") == "verified" for result in results):
                        item.update(status="conflict", detail="Removed credential still authenticates; check unmanaged/alternate authorized keys")
                    elif desired and any(result.get("status") == "revoked" for result in results):
                        item.update(status="pending", detail="Listener rejected dedicated identity; check account, AuthorizedKeysFile and key authentication; no daemon settings changed")
                connections.append(item)
        return connections

    state["connections"] = verify_connections()
    complete = configured == set(ids) and all(item["status"] == "verified" for item in state["connections"])
    # Rotation keeps all old managed grants until the complete new directed mesh has authenticated.
    if complete and any(record.get("retiring") for record in state["hosts"].values()):
        # Persist the one-way retirement phase before removing even one old grant.
        # A crash/partial write must never cause a later reconcile to resurrect old access.
        state["retirement_started"] = True
        save(store, state)
        retired_everywhere = True
        for host_id in ids:
            if host_id not in fresh or not configure(host_id, retire=True):
                retired_everywhere = False
        if retired_everywhere:
            # Prove each old source credential is rejected, not merely absent from our block.
            for source_id in ids:
                for generation in state["hosts"][source_id].get("retiring", []):
                    for target_id in ids:
                        if source_id == target_id:
                            continue
                        result = call(source_id, {"action": "verify", "generation": generation, "peer": peer(target_id)})
                        if result.get("status") != "revoked":
                            retired_everywhere = False
                            state["hosts"][source_id].update(status="conflict" if result.get("status") == "verified" else "pending",
                                                              detail="Old-key retirement unproven on " + target_id + "; reconcile required")
        if retired_everywhere:
            for record in state["hosts"].values():
                record.pop("retiring", None)
            state.pop("retirement_started", None)
        complete = complete and retired_everywhere
    for connection in state["connections"]:
        if connection["source_id"] in unavailable or connection["target_id"] in unavailable:
            if connection["status"] == "verified":
                connection.update(status="pending", detail="A later transport/deadline failure invalidated earlier proof; explicit reconcile required")
                connection.pop("verified_at", None)
    complete = complete and not unavailable
    for host_id in ids:
        record = state["hosts"][host_id]
        relevant = [item for item in state["connections"] if host_id in (item["source_id"], item["target_id"])]
        if complete and not record.get("residual_access"):
            record.update(status="verified", detail="Desired mesh verified" if host_id in members else "Managed grants withdrawn; recorded credentials rejected by every peer; local retired identity files retained")
        elif record.get("status") not in {"conflict", "unsupported"}:
            record.update(status="pending", detail="Partial desired mesh; explicit inspect/reconcile required; no automatic retry")
        if any(item["status"] == "conflict" for item in relevant):
            record.update(status="conflict", detail="A removed credential still authenticates; manual/alternate grants require operator review")
    if complete:
        # Fully revoked former members no longer gate future membership/rotation.
        # Their public history and revocation evidence remain visible in cached status.
        state["participants"] = sorted(members)
    save(store, state)
    return {"status": "succeeded" if complete else "needs-inspection",
            "error": None if complete else "Partial fleet-key change; desired membership is durable, offline peers/retirements remain pending; inspect status and explicitly reconcile"}
