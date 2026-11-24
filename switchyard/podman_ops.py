"""Lease-scoped orchestration for the disposable, single-placement foobar.

This module never obtains transports or leases itself. Broker persists intent
before calling it and owns the remote hosts passed to execute_managed.
"""
import base64
import copy
from datetime import datetime, timezone
import hashlib
import re
import uuid

from .podman_remote import SOURCE, IMAGE, NAME
from .remote import run_remote


ACTIONS = ("deploy", "start", "stop", "migrate", "recover")


def _now():
    return datetime.now(timezone.utc).isoformat()


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def execute_managed(request: dict, hosts: dict, emit) -> dict:
    """Execute exactly one approved operation under already-held host leases.

    Transport exceptions and partial mutations are uncertain, not failed. There
    are no command retries, automatic failbacks, removals or source adoption.
    """
    placement = copy.deepcopy(request.get("placement"))
    current = copy.deepcopy(placement)
    mutation_started = False
    try:
        action, config = request["action"], request["config"]
        _require(action in ACTIONS and request["workload_id"] == "foobar", "Unsupported managed operation")
        _require(config.get("container_name") == NAME and config.get("image") == IMAGE
                 and type(config.get("port")) is int and config["port"] == 18080,
                 "Only the fixed foobar rootless Podman recipe is supported")
        owner = config["ownership_id"]
        _require(str(uuid.UUID(owner)) == owner, "Invalid persisted ownership UUID")
        content = request["site_content"].encode("utf-8")
        digest = request["site_sha256"]
        _require(len(content) <= 65536 and re.fullmatch(r"[0-9a-f]{64}", digest)
                 and hashlib.sha256(content).hexdigest() == digest, "Site content hash or size mismatch")
        _require(isinstance(request["operation_id"], str) and request["operation_id"], "Missing operation identity")
        allowed = config["allowed_hosts"]
        source, target = request.get("source_id"), request.get("target_id")
        for host_id in (source, target):
            if host_id is not None:
                _require(host_id in allowed and host_id in hosts, "Host is not enrolled for this workload")
        if placement is not None:
            _require(placement.get("ownership_id") == owner and placement.get("workload_id") == "foobar",
                     "Placement ownership mismatch")
            _require(placement.get("host_id") in allowed, "Placement host is not enrolled")
        base = {"workload_id": "foobar", "container_name": NAME, "image": IMAGE,
                "ownership_id": owner, "port": 18080, "content_sha256": digest,
                "operation_id": request["operation_id"]}

        def call(host_id, remote_action, identity=None, **extra):
            nonlocal mutation_started
            host = hosts[host_id]
            _require(host.get("transport") == "ssh" and isinstance(host.get("target"), str)
                     and host["target"].count("@") == 1, "Managed operations require an enrolled explicit SSH user")
            user = host["target"].split("@", 1)[0]
            _require(re.fullmatch(r"[a-z_][a-z0-9_-]*", user), "Invalid configured SSH user")
            payload = {**base, "expected_user": user, "action": remote_action}
            if identity:
                for key in ("image_id", "image_digest", "content_sha256"):
                    _require(isinstance(identity.get(key), str), "Incomplete placement identity")
                    payload[key] = identity[key]
                if identity.get("native_id") is not None:
                    _require(re.fullmatch(r"[0-9a-f]{64}", identity["native_id"]),
                             "Invalid native placement identity")
                    payload["native_id"] = identity["native_id"]
                if identity.get("scope"):
                    _require(re.fullmatch(r"user:[1-9][0-9]*", identity["scope"]), "Invalid rootless scope")
                    payload["expected_scope"] = identity["scope"]
            payload.update(extra)
            emit("remote-step", {"host_id": host_id, "action": remote_action})
            # Even a transport failure on a read cannot prove host state; the
            # caller must surface uncertainty rather than infer stopped state.
            if remote_action in ("prestage", "deploy", "start", "stop"):
                mutation_started = True
            try:
                result = run_remote(host, SOURCE, payload, timeout=120 if remote_action == "prestage" else 60)
            except Exception:
                raise StepError("needs-inspection", "Remote transport did not return a verified result") from None
            if not isinstance(result, dict) or result.get("status") not in ("succeeded", "failed", "needs-inspection"):
                raise StepError("needs-inspection", "Malformed lifecycle result")
            if result["status"] != "succeeded":
                raise StepError(result["status"], result.get("error", "Remote operation did not verify"),
                                result.get("stderr", ""))
            return result

        def new_placement(host_id, result, image, content_hash, recovery=None):
            _require(re.fullmatch(r"[0-9a-f]{64}", result.get("native_id", "")), "Missing verified container ID")
            _require(re.fullmatch(r"user:[1-9][0-9]*", result.get("scope", "")), "Missing verified rootless scope")
            value = {"workload_id": "foobar", "host_id": host_id, "native_id": result["native_id"],
                     "image_id": image["image_id"], "image_digest": image["image_digest"],
                     "content_sha256": content_hash, "lifecycle": "running", "verified_at": _now(),
                     "ownership_id": owner, "uncertain": False, "scope": result["scope"]}
            if recovery:
                value["recovery"] = recovery
            return value

        if action == "deploy":
            _require(placement is None, "Deployment already has a placement; use start, migrate or recover")
            _require(source is None and target is not None, "Deployment requires only a target host")
            call(target, "preflight")
            image = call(target, "prestage")
            _require(re.fullmatch(r"sha256:[0-9a-f]{64}", image.get("image_id", ""))
                     and re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", image.get("image_digest", "")),
                     "Missing verified immutable image metadata")
            # Persist image + intended host even if the subsequent run is lost.
            current = {"workload_id": "foobar", "host_id": target, "native_id": None,
                       "image_id": image["image_id"], "image_digest": image["image_digest"],
                       "content_sha256": digest, "lifecycle": "unknown", "verified_at": None,
                       "ownership_id": owner, "uncertain": True, "scope": image.get("scope")}
            emit("deployment-intent", current)
            result = call(target, "deploy", image_id=image["image_id"], image_digest=image["image_digest"],
                          content_b64=base64.b64encode(content).decode("ascii"))
            current = new_placement(target, result, image, digest)
        elif action in ("start", "stop"):
            _require(placement is not None and source == placement["host_id"]
                     and target in (None, source), "Action must bind the current placement")
            if placement.get("recovery") and action == "start":
                retained = placement["recovery"]["source"]
                _require(call(retained["host_id"], "inspect", retained)["running"] is False,
                         "Retained source must be stopped before starting destination")
            result = call(source, action, placement)
            current["lifecycle"] = "running" if result["running"] else "stopped"
            current["verified_at"] = _now()
        elif action == "migrate":
            _require(placement is not None and source == placement["host_id"]
                     and target is not None and target != source, "Migration requires different bound hosts")
            _require(not placement.get("recovery"), "Resolve retained migration recovery state before another migration")
            # All destination rejection/immutable image staging happens before
            # the sole source stop. Its verified bytes, not the authoring file,
            # are the transfer payload.
            retained_target = placement.get("retained_target")
            reuse = bool(retained_target and retained_target.get("host_id") == target
                         and retained_target.get("ownership_id") == owner)
            reuse_identity = {key: placement[key] for key in
                              ("image_id", "image_digest", "content_sha256")}
            if reuse and retained_target.get("native_id"):
                reuse_identity["native_id"] = retained_target["native_id"]
            preflight = call(target, "preflight", reuse_identity if reuse else None,
                             allow_owned=reuse, content_sha256=placement["content_sha256"])
            original = call(source, "inspect-running", placement)
            _require(preflight["architecture"] == original["architecture"], "Host architectures differ")
            transferred = base64.b64decode(original["content_b64"], validate=True)
            _require(len(transferred) <= 65536 and hashlib.sha256(transferred).hexdigest()
                     == placement["content_sha256"], "Verified source content hash mismatch")
            call(target, "prestage", image_id=placement["image_id"], image_digest=placement["image_digest"])
            recovery = {"source": copy.deepcopy(placement), "target_id": target,
                        "target_scope": preflight.get("scope")}
            current["recovery"] = recovery
            emit("recovery-intent", recovery)
            call(source, "stop", placement)
            current["lifecycle"] = "stopped"
            current["verified_at"] = _now()
            emit("source-stopped", {"host_id": source, "native_id": placement["native_id"]})
            result = call(target, "deploy", image_id=placement["image_id"], image_digest=placement["image_digest"],
                          content_sha256=placement["content_sha256"],
                          content_b64=base64.b64encode(transferred).decode("ascii"),
                          **({"native_id": preflight["native_id"]} if preflight.get("native_id") else {}))
            recovery["target_native_id"] = result["native_id"]
            # A successful target health check alone is not a cutover proof.
            stopped = call(source, "inspect", placement)
            _require(stopped["running"] is False, "Source is not confirmed stopped after cutover")
            current = new_placement(target, result, placement, placement["content_sha256"], recovery)
        elif action == "recover" and placement is not None and not placement.get("recovery"):
            _require(source == placement["host_id"] and target in (None, source),
                     "Initial deployment recovery must bind its original host")
            observed = call(source, "inspect-target", placement)
            if observed.get("absent"):
                _require(digest == placement["content_sha256"],
                         "Original authored content is required to recover an absent deployment")
                result = call(source, "deploy", image_id=placement["image_id"],
                              image_digest=placement["image_digest"],
                              content_sha256=placement["content_sha256"],
                              content_b64=base64.b64encode(content).decode("ascii"))
            elif observed["running"]:
                result = call(source, "inspect-running", placement)
            else:
                result = call(source, "start", placement)
            current = new_placement(source, result, placement, placement["content_sha256"])
        else:
            _require(placement is not None and isinstance(placement.get("recovery"), dict),
                     "No retained source recovery metadata")
            recovery = placement["recovery"]
            original, destination = recovery["source"], recovery["target_id"]
            origin = original["host_id"]
            _require(source == placement["host_id"] and target in (None, origin), "Recovery target must be original source")
            _require(origin in hosts and destination in hosts and origin in allowed and destination in allowed
                     and origin != destination and original.get("ownership_id") == owner,
                     "Invalid recovery identities")
            dest_identity = {**original}
            if recovery.get("target_native_id"):
                dest_identity["native_id"] = recovery["target_native_id"]
            else:
                # Unknown native ID still requires the unguessable ownership
                # UUID, exact image, file/configuration and name. Never adopt it.
                dest_identity.pop("native_id", None)
            if recovery.get("target_scope"):
                dest_identity["scope"] = recovery["target_scope"]
            else:
                dest_identity.pop("scope", None)
            # Recovery is a separately approved operation. Inspect the original
            # owned destination first, then stop that exact incarnation only.
            observed = call(destination, "inspect-target", dest_identity)
            if observed.get("running"):
                dest_identity["native_id"] = observed["native_id"]
                call(destination, "stop", dest_identity)
            call(destination, "absent-or-stopped", dest_identity)
            retained = call(origin, "inspect", original)
            if retained["running"]:
                result = call(origin, "inspect-running", original)
            else:
                result = call(origin, "start", original)
            current = new_placement(origin, result, original, original["content_sha256"])
            # Retain the stopped target's identity for safe explicit reuse.
            current["retained_target"] = {"host_id": destination,
                "native_id": observed.get("native_id"), "ownership_id": owner}
        current["uncertain"] = bool(action == "stop" and placement.get("uncertain")
                                    and placement.get("recovery"))
        emit("verified-placement", current)
        return {"status": "succeeded", "placement": current}
    except StepError as error:
        if error.status == "needs-inspection" and current:
            current["lifecycle"] = "unknown"
            current["uncertain"] = True
        return {"status": error.status, "placement": current, "error": str(error)[:512], "stderr": error.stderr}
    except Exception as error:
        # Do not turn lost transport, malformed remote data, or interrupted
        # mutation into a confirmed failed/still-running placement assertion.
        uncertain = mutation_started or not isinstance(error, (ValueError, KeyError, TypeError))
        if uncertain and current:
            current["lifecycle"] = "unknown"
            current["uncertain"] = True
        return {"status": "needs-inspection" if uncertain else "failed", "placement": current,
                "error": str(error)[:512] if isinstance(error, (ValueError, StepError)) else type(error).__name__}


class StepError(Exception):
    def __init__(self, status, message, stderr=""):
        super().__init__(message)
        self.status = status
        self.stderr = stderr
