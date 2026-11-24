"""Start tokens for adopted (registered) applications.

Registration stays metadata-only; this is its first, narrow host write: one small file per
component at `~/.local/state/switchyard/tokens/<application>/<component>.token` on a host the
operator listed in the operations policy key `token_hosts`. Line 1 is the token, the only
thing a gate compares (`[ "$(head -n 1 -- "PATH")" = "LINE" ]`):

    switchyard-generation-token/v1 application=<app> component=<c> host=<host> generation=<N>

Issue and revoke run through the broker under the host's canonical lease (receipt kind
`token`); verify is leased and read-only; show and gate never contact a host. Revoking a token
stops nothing that is running. Generations only move forward.
"""
from pathlib import Path
import json
import time
import uuid

from . import tokens_remote
from .collector import _json, _validate_config
from .deploy import _id, shell_gate, systemd_gate
from .workload_store import WorkloadStore
from .operation_store import digest, now
from .remote import RemoteError, run_remote

ACTIONS = ("issue", "revoke")
ROOT = "~/.local/state/switchyard/tokens"
VERIFY_HOST_LIMIT = 256
WORKER_SECONDS = 120
REVOCATION_LIMIT = ("Revocation stops nothing that is running: a component already started keeps running until it "
                    "stops by itself or is stopped by its owner. Stopping adopted units needs a separate stop grant.")
FINDINGS = {"token-missing": "drift", "token-valid-while-revoked": "drift", "token-revoked-while-valid": "drift",
            "token-generation-mismatch": "drift", "token-foreign-host": "drift", "token-malformed": "drift",
            "token-journal-uncertain": "drift", "extra-valid-line": "info", "unreachable": "unknown"}


def token_line(application, component, host_id, generation, revoked=False):
    return tokens_remote.token_line({"application": application, "component": component, "host_id": host_id,
                                     "generation": generation}, revoked)


def default_path(application, component):
    return ROOT + "/" + application + "/" + component + ".token"


def authority(config, host_id, host, registration_revision):
    return digest({"token_hosts": sorted(config.get("token_hosts", [])), "host": _validate_config(host),
                   "local_target": config.get("local_targets", {}).get(host_id), "registration": registration_revision})


def registered_target(store, application, component, host_id):
    """(registration, placement) for a registered application placing `component` on `host_id`, or ValueError."""
    registration = store.registration(application)
    if registration is None:
        raise ValueError("Application " + application + " is not registered (switchyard spec register)")
    placements = [p for p in registration["bundle"]["placements"] if p["host_id"] == host_id]
    if not placements:
        raise ValueError("Registered application " + application + " has no placement on " + host_id)
    if component is not None:
        placements = [p for p in placements if component in [c["component"] for c in p["components"]]]
        if not placements:
            raise ValueError("Component " + component + " is not placed on " + host_id + " by registration "
                             + application + "@" + str(registration["revision"]))
    return registration, placements[0]


def next_generation(row, action):
    """Generation the action writes. Issue re-uses a valid one (verified no-op) and otherwise moves forward;
    revoke revokes the current one. A pending (crashed) operation counts as written."""
    if row is None:
        if action == "revoke":
            raise ValueError("No token was ever issued for this component on this host")
        return 1, "new"
    pending = (row["data"].get("pending") or {}).get("generation", 0)
    high = max(row["generation"], pending)
    if action == "revoke":
        return high, "revoke"
    if row["state"] == "valid" and not pending:
        return row["generation"], "reissue-same"
    return high + 1, "bump"


class TokenManager:
    """Controller side; takes the broker for policy, receipts and leases."""

    def __init__(self, broker):
        self.broker = broker
        self.store = WorkloadStore(broker.store.directory)

    def policy(self):
        config = self.broker._configuration()
        return {"enabled": bool(config and config.get("token_hosts")),
                "token_hosts": list(config.get("token_hosts", [])) if config else []}

    def _authority(self, config, application, component, host_id):
        _id(application, "application")
        _id(host_id, "host")
        if component is not None:
            _id(component, "component")
        if host_id not in config.get("token_hosts", []):
            raise ValueError("Host " + host_id + " is not listed in the operations policy token_hosts")
        registration, placement = registered_target(self.store, application, component, host_id)
        hosts = self.broker.operation_hosts(config)
        return authority(config, host_id, hosts[host_id], registration["revision"]), registration, placement

    def _request_common(self, config, host_id, fingerprint):
        return {"config_path": str(self.broker.config_path.resolve()), "authority": fingerprint,
                "local": host_id in self.broker.local_host_ids(config)}

    def _run(self, request_id, intent, host_id, request, config):
        self.broker._request_id(request_id)
        with self.broker.store.transaction() as db:
            old = db.execute("SELECT intent_hash,receipt FROM operations WHERE request_id=?", (request_id,)).fetchone()
            if old is not None:
                self.broker.store.reconcile(db)
                if old["intent_hash"] != digest(intent):
                    raise ValueError("Request ID is already bound to a different intent")
                return json.loads(db.execute("SELECT receipt FROM operations WHERE request_id=?", (request_id,)).fetchone()[0]), True
            result = self.broker._begin(db, request_id=request_id, intent=intent, kind="token", host_ids=[host_id])
        if result["receipt"]["status"] != "running" or result.get("replayed"):
            return result["receipt"], bool(result.get("replayed"))
        receipt = self.broker._dispatch(result["receipt"], {"kind": "token", "operation_hosts": self.broker.operation_hosts(config),
                                                            "local_host_ids": self.broker.local_host_ids(config),
                                                            "request": request})["receipt"]
        return receipt, False

    # issue / revoke ------------------------------------------------------------
    def issue(self, application, component, host_id, *, approved=False, request_id=None):
        return self._act("issue", application, component, host_id, approved=approved, request_id=request_id)

    def revoke(self, application, component, host_id, *, approved=False, request_id=None):
        return self._act("revoke", application, component, host_id, approved=approved, request_id=request_id)

    def _act(self, action, application, component, host_id, *, approved, request_id):
        config = self.broker._enabled()
        intent = {"kind": "token", "action": action, "application_id": application, "component": component, "host_id": host_id}
        if approved and request_id:
            self.broker._request_id(request_id)
            with self.broker.store.transaction() as db:
                old = db.execute("SELECT intent_hash FROM operations WHERE request_id=?", (request_id,)).fetchone()
            if old is not None:
                receipt, _ = self._run(request_id, intent, host_id, None, config)
                return self._outcome(receipt, application, component, host_id, replayed=True)
        if component is None:
            raise ValueError("A component is required")
        fingerprint, registration, placement = self._authority(config, application, component, host_id)
        with self.store.transaction() as db:
            row = self.store.token_row(db, application, component, host_id)
        generation, kind = next_generation(row, action)
        line = token_line(application, component, host_id, generation, revoked=action == "revoke")
        preview = {"action": action, "application_id": application, "component": component, "host_id": host_id,
                   "registration": {"revision": registration["revision"], "placement_id": placement["id"]},
                   "path": (row or {}).get("data", {}).get("path") or default_path(application, component),
                   "line": line, "generation": generation,
                   "from": None if row is None else {"generation": row["generation"], "state": row["state"]},
                   "to": {"generation": generation, "state": "revoked" if action == "revoke" else "valid"},
                   "change": {"new": "first token for this component on this host (generation 1)",
                              "reissue-same": "rewrite of the current valid generation (verified no-op)",
                              "bump": "new generation after a revoke or an uncertain earlier write",
                              "revoke": "line 1 rewritten as revoked for the current generation"}[kind],
                   "touches": ["the token file", ROOT + "/.nobackup and README (create-only)"],
                   "approval_required": True,
                   "how": "switchyard token " + action + " " + application + " " + component + " --host " + host_id
                          + " --approve --request-id ID"}
        if action == "revoke":
            preview["warning"] = REVOCATION_LIMIT
        if not approved:
            return {"preview": preview}
        if not request_id:
            raise ValueError("Approved token actions require --request-id")
        request = {"action": action, "application_id": application, "component": component, "host_id": host_id,
                   "registration_revision": registration["revision"], **self._request_common(config, host_id, fingerprint)}
        receipt, replayed = self._run(request_id, intent, host_id, request, config)
        return self._outcome(receipt, application, component, host_id, replayed=replayed)

    def _outcome(self, receipt, application, component, host_id, *, replayed=False):
        with self.store.transaction() as db:
            row = self.store.token_row(db, application, component, host_id)
        result = {"receipt": receipt, "token": public(row)}
        if replayed:
            result["replayed"] = True
        if receipt.get("action") == "revoke":
            result["warning"] = REVOCATION_LIMIT
        return result

    # show / gate (journal only) ------------------------------------------------
    def show(self, application, component=None, host_id=None):
        _id(application, "application")
        with self.store.transaction() as db:
            rows = self.store.token_rows(db, application, component, host_id)
        return {"application_id": application, "tokens": [public(row) for row in rows],
                "note": "Journal only; run `switchyard token verify` to compare with the host"}

    def gate(self, application, component, host_id):
        with self.store.transaction() as db:
            row = self.store.token_row(db, application, component, host_id)
        if row is None or not row["data"].get("path"):
            raise ValueError("No token was issued for " + application + "/" + component + " on " + host_id
                             + "; issue one first (the gate needs its recorded path)")
        path = row["data"]["path"]
        line = token_line(application, component, host_id, row["generation"])
        result = {"application_id": application, "component": component, "host_id": host_id,
                  "generation": row["generation"], "state": row["state"], "path": path, "line": line,
                  "shell": shell_gate(path, line), "systemd": "ExecStartPre=" + systemd_gate(path, line),
                  "notes": ["Compare line 1 only; a whole-file grep passes when a valid line is appended beside a revoked one.",
                            "The line names the generation: a revoke followed by a new issue bumps it, and gates "
                            "embedding the old line then refuse until they are regenerated with `token gate`.",
                            "Map a refusal to your own exit code (residents use 12)."]}
        if row["state"] != "valid":
            result["warning"] = ("Token is " + row["state"] + " in the journal: this gate refuses until "
                                 "a token is issued (which bumps the generation)")
        return result

    # verify (leased, read-only) ------------------------------------------------
    def verify(self, application, component=None, host_id=None, *, request_id=None):
        config = self.broker._enabled()
        _id(application, "application")
        with self.store.transaction() as db:
            rows = self.store.token_rows(db, application, component, host_id)
        if not rows:
            raise ValueError("No token records match; nothing to verify")
        by_host = {}
        for row in rows:
            by_host.setdefault(row["host_id"], []).append(row)
        if request_id and len(by_host) > 1:
            raise ValueError("--request-id applies to one host; add --host")
        results = []
        for host, items in sorted(by_host.items()):
            try:
                results.append(self._verify_host(config, application, host, items, request_id))
            except ValueError as error:
                results.append({"host_id": host, "error": str(error), "verifications": []})
        verifications = [v for item in results for v in item["verifications"]]
        return {"consistent": bool(verifications) and all(v["consistent"] for v in verifications)
                and not any("error" in item for item in results), "hosts": results}

    def _verify_host(self, config, application, host_id, rows, request_id):
        if len(rows) > VERIFY_HOST_LIMIT:
            raise ValueError("Too many tokens on one host for one operation")
        fingerprint, registration, _ = self._authority(config, application, None, host_id)
        components = sorted(row["component"] for row in rows)
        intent = {"kind": "token", "action": "verify", "application_id": application, "host_id": host_id,
                  "components": components}
        if request_id is None:
            intent["nonce"] = uuid.uuid4().hex
        request = {"action": "verify", "application_id": application, "host_id": host_id, "components": components,
                   "registration_revision": registration["revision"], **self._request_common(config, host_id, fingerprint)}
        receipt, _ = self._run(request_id or "token-verify-" + uuid.uuid4().hex, intent, host_id, request, config)
        verifications = []
        with self.store.transaction() as db:
            for component in components:
                row = self.store.token_row(db, application, component, host_id)
                recorded = row["last_verification"]
                if recorded and recorded.get("operation_id") == receipt["id"]:
                    verifications.append(recorded)
                else:
                    verifications.append(unobserved(row, "Host not observed: receipt " + str(receipt.get("status"))
                                                    + ": " + str(receipt.get("error")), receipt["id"]))
        return {"host_id": host_id, "receipt": receipt, "verifications": verifications,
                "consistent": all(v["consistent"] for v in verifications)}


def public(row):
    if row is None:
        return None
    data = row["data"]
    return {"application_id": row["application"], "component": row["component"], "host_id": row["host_id"],
            "generation": row["generation"], "state": row["state"], "path": data.get("path"),
            "issued_at": data.get("issued_at"), "revoked_at": data.get("revoked_at"),
            "uncertain": row["state"] == "unknown" or bool(data.get("pending")), "pending": data.get("pending"),
            "operations": data.get("operations", []), "evidence": data.get("evidence"),
            "last_verification": None if row["last_verification"] is None else {
                k: row["last_verification"][k] for k in ("verified_at", "consistent", "findings", "operation_id")}}


def _finding(code, detail):
    return {"code": code, "severity": FINDINGS[code], "detail": detail}


def unobserved(row, detail, operation_id):
    return {"application_id": row["application"], "component": row["component"], "host_id": row["host_id"],
            "generation": row["generation"], "journal_state": row["state"], "operation_id": operation_id,
            "verified_at": now(), "consistent": False, "findings": [_finding("unreachable", detail)], "observed": None}


def compare(row, observed, operation_id):
    """Journal token record vs line 1 on the host → findings. Pure function."""
    findings = []
    state = observed["state"]
    application, component, host_id = row["application"], row["component"], row["host_id"]
    if not state.get("exists"):
        findings.append(_finding("token-missing", "no token file at " + str(observed.get("path"))))
    else:
        parsed = state["parsed"]
        if parsed is None or (parsed["application"], parsed["component"]) != (application, component):
            findings.append(_finding("token-malformed", "line 1 is not this component's token: " + repr(state["line1"][:200])))
        elif parsed["host_id"] != host_id:
            findings.append(_finding("token-foreign-host", "line 1 names host " + parsed["host_id"] + " (copied or restored from another host)"))
        elif parsed["generation"] != row["generation"]:
            findings.append(_finding("token-generation-mismatch", "host generation " + str(parsed["generation"])
                                     + ", journal " + str(row["generation"])))
        elif row["state"] == "unknown" or (row["data"].get("pending")):
            findings.append(_finding("token-journal-uncertain", "journal outcome unknown; host line 1 is "
                                     + ("revoked" if parsed["revoked"] else "valid") + "; issue or revoke to settle it"))
        elif row["state"] == "revoked" and not parsed["revoked"]:
            findings.append(_finding("token-valid-while-revoked", "line 1 is the valid token although the journal revoked it"))
        elif row["state"] == "valid" and parsed["revoked"]:
            findings.append(_finding("token-revoked-while-valid", "line 1 is revoked although the journal issued it"))
        if state.get("extra_valid_lines"):
            findings.append(_finding("extra-valid-line", "lines " + ", ".join(map(str, state["extra_valid_lines"]))
                                     + " look like valid tokens; line-1 gates ignore them, but this is evidence of tampering"))
    return {"application_id": application, "component": component, "host_id": host_id, "generation": row["generation"],
            "journal_state": row["state"], "operation_id": operation_id, "verified_at": now(),
            "consistent": not any(f["severity"] != "info" for f in findings), "findings": findings,
            "observed": {"path": observed.get("path"), **{k: state.get(k) for k in ("exists", "line1", "mode", "sha256")}}}


# ---------------------------------------------------------------- worker side

def _live_authority(request, hosts, store):
    try:
        with Path(request["config_path"]).open("rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            return False
        config = _json(raw)
        host_id = request["host_id"]
        if (host_id in config.get("local_targets", {})) != (request.get("local") is True):
            return False
        if host_id not in config.get("token_hosts", []):
            return False
        registration, _ = registered_target(store, request["application_id"], request.get("component"), host_id)
        return (registration["revision"] == request["registration_revision"]
                and authority(config, host_id, hosts[host_id], registration["revision"]) == request["authority"])
    except (OSError, ValueError, TypeError, KeyError):
        return False


class Worker:
    def __init__(self, request, hosts, store, operation_id, local_host_ids):
        self.request, self.hosts, self.ops, self.operation_id = request, hosts, store, operation_id
        self.store = WorkloadStore(store.directory)
        self.host_id = request["host_id"]
        self.local = self.host_id in local_host_ids
        self.deadline = time.monotonic() + WORKER_SECONDS
        self.source = Path(tokens_remote.__file__).read_text() + "\nprint(json.dumps(main(PAYLOAD)))\n"

    def call(self, payload, budget):
        remaining = int(self.deadline - time.monotonic())
        if remaining < 10:
            raise RemoteError("Operation deadline reached")
        self.ops.event(self.operation_id, "remote-step", {"host_id": self.host_id, "action": payload["action"]})
        result = run_remote(self.hosts[self.host_id], self.source, payload, timeout=max(5, min(budget, remaining - 5)),
                            local=self.local)
        if not isinstance(result, dict) or result.get("status") not in {"succeeded", "failed", "needs-inspection"}:
            raise RemoteError("Malformed token step result")
        return result

    def run(self):
        if not _live_authority(self.request, self.hosts, self.store):
            return {"status": "failed", "error": "Token authority or registration changed before the lease; no remote command executed"}
        if self.request["action"] == "verify":
            return self.verify()
        return self.write()

    def write(self):
        request = self.request
        key = (request["application_id"], request["component"], self.host_id)
        with self.store.transaction() as db:
            row = self.store.token_row(db, *key)
        try:
            generation, kind = next_generation(row, request["action"])
        except ValueError as error:
            return {"status": "failed", "error": str(error) + "; no remote command executed"}
        data = dict(row["data"]) if row else {"operations": []}
        pending = {"action": request["action"], "generation": generation, "operation_id": self.operation_id, "at": now()}
        # Journal intent (target generation) before the host write.
        with self.store.transaction() as db:
            revision = self.store.put_token(db, *key, expected_revision=row["revision"] if row else 0,
                                            generation=row["generation"] if row else generation,
                                            state=row["state"] if row else "unknown", data={**data, "pending": pending})
        self.ops.event(self.operation_id, "token-intent", {"application_id": key[0], "component": key[1],
                                                           "host_id": key[2], "generation": generation, "change": kind})
        payload = {"action": "write", "application": key[0], "component": key[1], "host_id": key[2],
                   "generation": generation, "mode": "revoked" if request["action"] == "revoke" else "valid",
                   "operation_id": self.operation_id, "issued_at": data.get("issued_at")}
        try:
            result = self.call(payload, 60)
        except RemoteError:
            self._settle(key, revision, generation, "unknown", data, None)
            raise
        if result["status"] != "succeeded":
            if result["status"] == "failed":  # nothing replaced on the host: withdraw the intent
                with self.store.transaction() as db:
                    if row is None:
                        db.execute("DELETE FROM tokens WHERE application=? AND component=? AND host_id=?", key)
                    else:
                        self.store.put_token(db, *key, expected_revision=revision, generation=row["generation"],
                                             state=row["state"], data=data)
            else:
                self._settle(key, revision, generation, "unknown", data, None)
            return {"status": result["status"], "error": "Token " + request["action"] + " failed: " + str(result.get("error"))}
        state = "revoked" if request["action"] == "revoke" else "valid"
        evidence = {"path": result["path"], "line1": result["after"]["line1"], "sha256": result["after"]["sha256"],
                    "mode": result["after"]["mode"], "written_at": result["at"],
                    "before": {k: result["before"].get(k) for k in ("exists", "line1")},
                    "markers_created": result["markers_created"]}
        data = {**data, "path": result["path"], "evidence": evidence}
        data["issued_at" if state == "valid" else "revoked_at"] = result["at"]
        if state == "valid" and kind != "reissue-same":
            data.pop("revoked_at", None)
        self._settle(key, revision, generation, state, data, request["action"])
        self.ops.event(self.operation_id, "token-" + ("revoked" if state == "revoked" else "issued"),
                       {"generation": generation, "path": result["path"], "line1": result["after"]["line1"],
                        "sha256": result["after"]["sha256"], "change": kind, "markers_created": result["markers_created"],
                        **({"caveat": REVOCATION_LIMIT} if state == "revoked" else {})})
        return {"status": "succeeded"}

    def _settle(self, key, revision, generation, state, data, action):
        data = {k: v for k, v in data.items() if k != "pending"}
        data["operations"] = [*data.get("operations", []), {"operation_id": self.operation_id, "action": action or "uncertain",
                                                            "generation": generation, "state": state, "at": now()}][-16:]
        with self.store.transaction() as db:
            self.store.put_token(db, *key, expected_revision=revision, generation=generation, state=state, data=data)

    def verify(self):
        request = self.request
        with self.store.transaction() as db:
            rows = [self.store.token_row(db, request["application_id"], component, self.host_id) for component in request["components"]]
        rows = [row for row in rows if row is not None]
        items = [{"application": row["application"], "component": row["component"]} for row in rows]
        try:
            result = self.call({"action": "read", "items": items}, 60)
            if result["status"] != "succeeded":
                raise RemoteError(str(result.get("error")))
            observed = {item["component"]: item for item in result["results"]}
        except RemoteError as error:
            with self.store.transaction() as db:
                for row in rows:
                    self.store.save_token_verification(db, row["application"], row["component"], row["host_id"],
                                                       unobserved(row, "Host unreachable: " + str(error)[:300], self.operation_id))
            return {"status": "needs-inspection", "error": "Host could not be observed; no token is known to be consistent"}
        unreachable, summary = False, {}
        with self.store.transaction() as db:
            for row in rows:
                item = observed.get(row["component"])
                if item is None or "error" in item:
                    unreachable = True
                    verification = unobserved(row, "Observation failed: " + str((item or {}).get("error", "missing")), self.operation_id)
                else:
                    verification = compare(row, item, self.operation_id)
                self.store.save_token_verification(db, row["application"], row["component"], row["host_id"], verification)
                summary[row["component"]] = [f["code"] for f in verification["findings"]]
        self.ops.event(self.operation_id, "token-verified", summary)
        if unreachable:
            return {"status": "needs-inspection", "error": "Some tokens could not be observed"}
        return {"status": "succeeded"}


def execute_worker(request, hosts, store, operation_id, *, local_host_ids=()):
    """Called by operation_worker inside the canonical host lease."""
    return Worker(request, hosts, store, operation_id, local_host_ids).run()


# ---------------------------------------------------------------- CLI

def register_cli(commands):
    token = commands.add_parser("token", help="Start tokens for registered (adopted) applications")
    actions = token.add_subparsers(dest="token_command", required=True)
    for name, text in (("issue", "Issue (or re-issue) a start token; previews without --approve"),
                       ("revoke", "Revoke a start token (stops nothing that is running); previews without --approve")):
        sub = actions.add_parser(name, help=text)
        sub.add_argument("application")
        sub.add_argument("component")
        sub.add_argument("--host", required=True)
        sub.add_argument("--approve", action="store_true")
        sub.add_argument("--request-id")
    show = actions.add_parser("show", help="Journal only; no host contact")
    show.add_argument("application")
    show.add_argument("component", nargs="?")
    show.add_argument("--host")
    verify = actions.add_parser("verify", help="Leased, read-only comparison of line 1 on the host with the journal")
    verify.add_argument("application")
    verify.add_argument("component", nargs="?")
    verify.add_argument("--host")
    verify.add_argument("--request-id")
    gate = actions.add_parser("gate", help="Print the path, exact line and canonical checks; no host contact")
    gate.add_argument("application")
    gate.add_argument("component")
    gate.add_argument("--host", required=True)


def _manager(service):
    factory = getattr(service, "tokens", None)
    return factory() if factory else TokenManager(service._broker)


def handle_cli(args, service):
    if args.command != "token":
        return None
    manager, command = _manager(service), args.token_command
    if command == "issue":
        return manager.issue(args.application, args.component, args.host, approved=args.approve, request_id=args.request_id)
    if command == "revoke":
        return manager.revoke(args.application, args.component, args.host, approved=args.approve, request_id=args.request_id)
    if command == "show":
        return manager.show(args.application, args.component, args.host)
    if command == "verify":
        return manager.verify(args.application, args.component, args.host, request_id=args.request_id)
    return manager.gate(args.application, args.component, args.host)
