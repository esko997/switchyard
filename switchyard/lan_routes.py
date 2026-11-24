"""Published LAN URLs: one revisioned route registry and its staged gateway (Caddy) and DNS changes.

The registry is one workload store metadata value under `META_KEY`:
    {"revision", "routes": [route snapshots], "caddy_sha256", "adopted", "pending", "last_apply", "updated_at"}
`routes` is the last verified state: a route appears there only after every stage of its change succeeded.
`pending` is the checkpoint of a change in progress (`running`) or stopped part way (`partial`). It is written
before the first remote effect and after each stage. A stopped change continues only through an explicit
`resume` plan with fresh revision guards; nothing is retried automatically. Every write bumps the operation
journal revision, so views that follow the broker revision notice route changes.

Order of effects. Each Caddy and DNS change is an ordinary deploy refresh (inspection and apply receipts) that
takes the host's canonical lease inside the deploy manager; this module holds only a local flock serializing
route changes, never a fleet lease and never a database write lock across remote calls.
  create/update: Caddy prepare (the new routes, plus the old name while renaming) -> leased HTTPS probe of every
                 route in that Caddyfile -> DNS (adds and removes in one refresh) -> Caddy cleanup (drops the old
                 name) -> probe of the remaining routes
  delete:        DNS withdraw -> Caddy cleanup -> probe of the remaining routes


Standalone DNS changes use the same revision, lock and pending checkpoint, but refresh and verify DNS only.
Their authority is the DNS application's operator records, not another record registry in this metadata.
Adoption (first use) is explicit and needs no host access: the gateway's journal Caddyfile hash must equal the
configured `adopt_caddy_sha256`, and every configured adopted route must resolve to exactly one endpoint candidate
with a DNS record that already points at the gateway. Other DNS records and the gateway's other files (CA files)
are never touched.
"""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
import re
import time
import uuid

from . import deploy_config
from . import lan_route_config as rc
from . import spec
from .deploy import DISPATCH_SECONDS, LAN_ROUTE_INSPECT_SECONDS
from .lan_route_probe import PROBE_SECONDS, verify_dns, verify_proxy
from .operation_store import digest, now
from .workload_store import WorkloadStore

META_KEY = "lan_routes"
PLAN_KIND = "lan-url"
ACTIONS = ("create", "update", "delete", "dns-create", "dns-update", "dns-delete", "resume")
FIELDS = {"create": {"hostname", "workload_id", "endpoint_id"},
          "update": {"current_hostname", "hostname", "workload_id", "endpoint_id"},
          "delete": {"current_hostname"}, "resume": set(),
          "dns-create": {"hostname", "address"},
          "dns-update": {"current_hostname", "hostname", "address"},
          "dns-delete": {"current_hostname"}}
PLAN_TTL = timedelta(minutes=10)
PLAN_LIMIT = 32
PLAN_ID = re.compile(r"[0-9a-f]{32}\Z")
LOCK_NAME = "lan-routes.lock"
GATEWAY_FILE = "caddyfile"
# A refresh stage is one leased inspection and one leased apply, each bounded by the broker's operation worker (the
# DNS stage adds a leased answer check); a probe is one leased operation. A stage starts only when its worst case fits
# the remaining budget, so one apply stays under DEADLINE_SECONDS (normally it takes seconds); what does not fit stops
# as `partial` for `resume`.
REFRESH_SECONDS = LAN_ROUTE_INSPECT_SECONDS + DISPATCH_SECONDS + 10
STAGE_SECONDS = {"caddy": REFRESH_SECONDS, "dns": REFRESH_SECONDS + PROBE_SECONDS + 5,
                 "verify": PROBE_SECONDS + 5}
DEADLINE_SECONDS = 870


def _sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _expired(value):
    return datetime.fromisoformat(value) <= datetime.now(timezone.utc)


def _snapshot(item):
    return {key: item[key] for key in rc.ROUTE_KEYS}


def _sorted(routes):
    return sorted((_snapshot(item) for item in routes), key=lambda item: item["hostname"])


def _view(item):
    return {**_snapshot(item), "url": "https://" + item["hostname"] + "/"}


def _line(item):
    return (item["hostname"] + " -> " + item["scheme"] + "://" + item["address"] + ":" + str(item["port"])
            + " (" + item["profile"] + ", " + item["workload_id"] + "/" + item["endpoint_id"] + ")\n")


def _records_text(records, zone):
    return "".join(name + "." + zone + " " + records[name] + "\n" for name in sorted(records))


def _public(plan):
    """The plan as shown to clients: no internal keys, no full stage texts (the diffs show them)."""
    result = {key: value for key, value in plan.items() if not key.startswith("_")}
    result["stages"] = [{key: value for key, value in stage.items() if key not in ("text", "routes")}
                        | ({"hostnames": [item["hostname"] for item in stage["routes"]]} if "routes" in stage else {})
                        for stage in plan["_stages"]]
    return result


class LanRoutes:
    def __init__(self, service, config):
        self.service = service
        self.config = config
        self.manager = service.deployments()
        self.store = self.manager.store
        self.journal = self.manager.broker.store
        self.fingerprint = digest(config)
        self.lock_path = self.store.directory / LOCK_NAME

    # ------------------------------------------------------------------------------------------ reading
    def _context(self, *, dns_only=False):
        """One store snapshot of the registry, the gateway and DNS instances, and the problems that stop planning."""
        cfg = self.config
        with self.store.reading() as db:
            state = WorkloadStore.meta(db, META_KEY)
            gateway = self.store.instance_row(db, cfg["gateway_id"]) if not dns_only else None
            gplace = self.store.placement_row(db, cfg["gateway_id"]) if not dns_only else None
            dns = self.store.instance_row(db, cfg["dns_id"])
            dplace = self.store.placement_row(db, cfg["dns_id"])
            claims = self.store.claims_for(db, cfg["gateway_id"]) if not dns_only else []
        problems = []
        ctx = {"state": state, "problems": problems, "gateway": None, "dns": None, "gateway_ip": None}
        if gateway is None or gplace is None or gplace["state"] == "retired":
            if not dns_only:
                problems.append("Gateway instance " + cfg["gateway_id"] + " has no current deployed placement")
        else:
            files = gateway["application"].get("config_files") or []
            item = next((f for f in files if f["id"] == GATEWAY_FILE), None)
            if gateway["template_ref"]["id"] != "caddy-lan" or item is None or item.get("content") is None:
                problems.append("Gateway instance " + cfg["gateway_id"] + " is not a caddy-lan instance with a literal Caddyfile")
            else:
                meta = gplace["meta"]
                recorded = next((f for f in meta["native"].get("config") or [] if f["name"] == item["path"]), None)
                ctx["gateway"] = {"id": cfg["gateway_id"], "revision": gateway["revision"], "host_id": gplace["host_id"],
                                  "generation": gplace["generation"], "placement_revision": gplace["revision"],
                                  "state": gplace["state"], "uncertain": bool(meta.get("uncertain") or meta.get("pending")),
                                  "text": item["content"], "sha256": _sha(item["content"]),
                                  "journal_sha256": recorded["sha256"] if recorded else None,
                                  "files": sorted(f["path"] for f in files)}
            addresses = sorted({c["address"] for c in claims
                                if c["owner_kind"] == "placement" and c["protocol"] == "tcp" and c["port"] == 443})
            if len(addresses) != 1:
                problems.append("Gateway placement must hold exactly one HTTPS (tcp/443) address claim; found "
                                + (", ".join(addresses) or "none"))
            elif cfg.get("gateway_ip") is not None and cfg["gateway_ip"] != addresses[0]:
                problems.append("Configured gateway_ip " + cfg["gateway_ip"] + " is not the gateway's claimed address " + addresses[0])
            else:
                try:
                    rc.lan_address(addresses[0], "gateway address")
                    ctx["gateway_ip"] = addresses[0]
                except ValueError as error:
                    problems.append(str(error))
        gateway_problems = list(problems)
        if dns is None or dplace is None or dplace["state"] == "retired":
            problems.append("DNS instance " + cfg["dns_id"] + " has no current deployed placement")
        elif dns["template_ref"]["id"] != "coredns-lan":
            problems.append("DNS instance " + cfg["dns_id"] + " is not a coredns-lan instance")
        else:
            try:
                app = dns["application"]
                item = deploy_config.generator_file(app)
                zone = deploy_config.zone_of(item["generator"], deploy_config.parameter_values(app))
            except ValueError as error:
                problems.append("DNS instance " + cfg["dns_id"] + ": " + str(error))
            else:
                if zone != cfg["zone"]:
                    problems.append("DNS instance " + cfg["dns_id"] + " answers zone " + zone + ", not " + cfg["zone"])
                else:
                    meta = dplace["meta"]
                    recorded = next((f["sha256"] for f in meta.get("native", {}).get("config", [])
                                     if f["name"] == item["path"]), None)
                    ctx["dns"] = {"id": cfg["dns_id"], "revision": dns["revision"], "host_id": dplace["host_id"],
                                  "generation": dplace["generation"], "placement_revision": dplace["revision"],
                                  "state": dplace["state"], "uncertain": bool(meta.get("uncertain") or meta.get("pending")),
                                  "file_id": item["id"],
                                  "journal_sha256": recorded,
                                  "generator": item["generator"], "values": deploy_config.parameter_values(app),
                                  "records": {r["name"]: r["address"] for r in item["generator"].get("records") or []}}
        ctx["dns_problems"] = problems[len(gateway_problems):]
        return ctx

    def _scan(self):
        return rc.endpoint_scan(self.store, self.config, hosts=self.manager._registry())

    def _rel(self, hostname):
        return rc.relative_name(hostname, self.config["zone"])

    def _adoption(self, ctx, candidates):
        """(routes, problems): the routes the configuration adopts, checked against the journal only."""
        cfg = self.config
        if ctx["problems"]:
            return None, list(ctx["problems"])
        gateway, records, ip = ctx["gateway"], ctx["dns"]["records"], ctx["gateway_ip"]
        problems = []
        if gateway["journal_sha256"] != gateway["sha256"]:
            problems.append("The gateway's journal and application disagree about its Caddyfile; verify the gateway first")
        adopt = cfg.get("adopt_routes") or []
        expected = cfg.get("adopt_caddy_sha256") or _sha(rc.render(cfg, ip, []))
        if gateway["journal_sha256"] != expected:
            problems.append("The gateway's recorded Caddyfile (sha256 " + str(gateway["journal_sha256"])
                            + ") is not the adoption baseline; review the file and set adopt_caddy_sha256")
        routes = []
        for entry in adopt:
            try:
                item = rc.check_route(cfg, rc.route(cfg, candidates, entry["hostname"], entry["workload_id"], entry["endpoint_id"]), ip)
            except ValueError as error:
                problems.append("Adopted route " + entry["hostname"] + ": " + str(error))
                continue
            found = records.get(self._rel(item["hostname"]))
            if found != ip:
                problems.append("Adopted route " + item["hostname"] + ": its DNS record must point at the gateway " + ip
                                + " (found " + (found or "no record") + ")")
            routes.append(item)
        names = [item["hostname"] for item in routes]
        if len(set(names)) != len(names):
            problems.append("adopt_routes name a hostname twice")
        if len(routes) > rc.MAX_ROUTES:
            problems.append("More than " + str(rc.MAX_ROUTES) + " adopted routes")
        return (None, problems) if problems else (_sorted(routes), [])

    def _ensure(self, ctx, candidates):
        """The registry, adopting it on first use (idempotent). (None, problems) while adoption is not possible."""
        if ctx["state"] is not None:
            return ctx["state"], []
        routes, problems = self._adoption(ctx, candidates)
        if routes is None:
            return None, problems
        seeded = False
        with self.store.transaction() as db:
            state = WorkloadStore.meta(db, META_KEY)
            if state is None:
                stamp = now()
                state = {"revision": 1, "routes": routes, "caddy_sha256": ctx["gateway"]["sha256"],
                         "adopted": {"caddy_sha256": ctx["gateway"]["journal_sha256"],
                                     "hostnames": [item["hostname"] for item in routes], "at": stamp},
                         "pending": None, "last_apply": None, "updated_at": stamp}
                WorkloadStore.set_meta(db, META_KEY, state)
                seeded = True
        if seeded:
            self._bump()
        ctx["state"] = state
        return state, []

    def _bump(self):
        with self.journal.transaction() as db:
            self.journal.bump(db)

    def _update(self, mutate):
        """Compare-and-set the registry in one short transaction; every write is a new revision."""
        with self.store.transaction() as db:
            state = WorkloadStore.meta(db, META_KEY)
            if state is None:
                raise ValueError("LAN route registry disappeared")
            new = mutate(deepcopy(state))
            new["revision"] = state["revision"] + 1
            new["updated_at"] = now()
            WorkloadStore.set_meta(db, META_KEY, new)
        self._bump()
        return new

    @contextmanager
    def _locked(self):
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError("Another LAN route change is running; wait for it to finish") from None
            yield
        finally:
            os.close(fd)

    def _running(self):
        """Whether some process is applying a route change now (holds the flock)."""
        try:
            with self._locked():
                return False
        except ValueError:
            return True

    def _pending_view(self, state):
        pending = (state or {}).get("pending")
        if not pending:
            return None
        view = deepcopy(pending)
        view["from_routes"] = [_view(item) for item in pending["from_routes"]]
        view["to_routes"] = [_view(item) for item in pending["to_routes"]]
        view["remaining"] = [stage["id"] for stage in pending["stages"] if stage["id"] not in pending["completed"]]
        if view["status"] == "running" and not self._running():
            view["status"] = "interrupted"
            view["error"] = view.get("error") or "The process applying this change stopped; inspect, then resume"
        if view["status"] != "running":
            view["resume"] = {"action": "resume", "expected_revision": state["revision"]}
        return view

    # ------------------------------------------------------------------------------------------ views
    def list(self):
        ctx = self._context()
        candidates, skipped = self._scan()
        state, problems = self._ensure(ctx, candidates)
        routes = state["routes"] if state else []
        adopted = set(state["adopted"]["hostnames"]) if state else set()
        published = {}
        for item in routes:
            published.setdefault((item["workload_id"], item["endpoint_id"]), []).append(item["hostname"])
        gateway, dns = ctx["gateway"], ctx["dns"]
        dns_records, sync_pending = [], False
        if dns is not None:
            text, rendered = deploy_config.render_registry_hosts(dns["generator"], dns["values"], self.manager._registry())
            sync_pending = bool(dns["journal_sha256"] and _sha(text) != dns["journal_sha256"])
            owned = {item["hostname"] for item in routes}
            for record in rendered["records"]:
                if record["name"] in owned:
                    continue
                source = record["source"]
                dns_records.append({"hostname": record["name"], "address": record["address"],
                                    "source": "manual" if source == "operator" else "registry",
                                    **({"host_id": source.split(":", 1)[1]} if source.startswith("registry:") else {})})
        dns_ready = (state is not None and not ctx["dns_problems"] and dns is not None
                     and dns["state"] == "active" and not dns["uncertain"])
        return {"configured": True, "ready": state is not None and not ctx["problems"],
                "revision": state["revision"] if state else 0, "zone": self.config["zone"],
                "routes": [{**_view(item), "adopted": item["hostname"] in adopted} for item in routes],
                "dns_records": sorted(dns_records, key=lambda item: item["hostname"]), "dns_ready": dns_ready,
                "dns_sync_pending": sync_pending,
                "endpoints": [{**row, "published_as": published.get((row["workload_id"], row["endpoint_id"]), [])}
                              for row in candidates],
                "excluded": skipped, "pending": self._pending_view(state),
                "gateway": {"id": self.config["gateway_id"], "address": ctx["gateway_ip"],
                            **({key: gateway[key] for key in ("host_id", "state", "revision")} if gateway else {})},
                "dns": {"id": self.config["dns_id"], **({key: dns[key] for key in ("host_id", "state", "revision")} if dns else {})},
                "problems": problems or ctx["problems"]}

    def published(self):
        """Verified routes for fleet views; read-only: before first use, the adoption the configuration allows."""
        ctx = self._context()
        state = ctx["state"]
        if state is not None:
            routes = state["routes"]
        else:
            routes, _ = self._adoption(ctx, self._scan()[0])
        return [_view(item) for item in routes or []]

    # ------------------------------------------------------------------------------------------ planning
    def plan(self, data):
        if not isinstance(data, dict):
            raise ValueError("A LAN route plan request is an object")
        action = data.get("action")
        if action not in ACTIONS:
            raise ValueError("Action must be one of " + ", ".join(ACTIONS))
        unknown = sorted(set(data) - FIELDS[action] - {"action", "expected_revision"})
        if unknown:
            raise ValueError("Unexpected field(s) for " + action + ": " + ", ".join(unknown))
        expected = data.get("expected_revision")
        if type(expected) is not int or expected < 0:
            raise ValueError("expected_revision must be the registry revision you reviewed")
        ctx = self._context(dns_only=action.startswith("dns-") or action == "resume")
        existing = ctx["state"]
        dns_only = action.startswith("dns-") or bool(action == "resume" and existing and existing["pending"]
                                                   and existing["pending"]["action"].startswith("dns-"))
        if existing is None or not dns_only:
            ctx = self._context()  # First use still requires explicit URL-registry adoption.
        candidates = self._scan()[0] if existing is None or not dns_only else []
        state, problems = self._ensure(ctx, candidates)
        if state is None:
            raise ValueError("LAN routes are not ready: " + "; ".join(problems))
        problems = ctx["dns_problems"] if dns_only else ctx["problems"]
        if problems:
            raise ValueError("LAN routes are not ready: " + "; ".join(problems))
        if expected != state["revision"]:
            raise ValueError("The LAN routes changed since you looked (revision " + str(expected) + ", now "
                             + str(state["revision"]) + "); reload and plan again")
        pending = state["pending"]
        if action == "resume":
            if not pending:
                raise ValueError("No pending LAN route change to resume")
            if pending["status"] == "running" and self._running():
                raise ValueError("The pending LAN route change is still running")
            if dns_only:
                return self._make_dns_plan(action, ctx, state, pending["dns_stage"],
                                           {key: pending.get(key) for key in
                                            ("action", "hostname", "current_hostname", "address", "previous_address")})
            old, new = pending["from_routes"], pending["to_routes"]
            change = {key: pending[key] for key in ("action", "hostname", "current_hostname")}
        else:
            if pending:
                raise ValueError("A LAN route change is pending (" + pending["action"] + " "
                                 + str(pending["hostname"] or pending["current_hostname"]) + ", " + pending["status"]
                                 + "); resume it first")
            if dns_only:
                stage, change = self._dns_change(action, data, ctx["dns"]["records"])
                return self._make_dns_plan(action, ctx, state, stage, change)
            old = state["routes"]
            new, change = self._change(action, data, old, candidates)
        return self._make_plan(action, ctx, state, old, new, change, candidates)

    def _dns_change(self, action, data, records):
        current = None
        if action != "dns-create":
            current = rc.hostname_in(self.config["zone"], data.get("current_hostname"))
            if self._rel(current) not in records:
                raise ValueError("No standalone manual DNS record " + current)
        hostname, address = None, None
        if action != "dns-delete":
            hostname = rc.hostname_in(self.config["zone"], data.get("hostname"))
            name = self._rel(hostname)
            address = data.get("address")
            try:
                spec.HostRecord.model_validate({"name": name, "address": address})
            except ValueError:
                raise ValueError("Record " + hostname + " needs a canonical IPv4/IPv6 address") from None
            if name in records and hostname != current:
                raise ValueError(hostname + " already has a manual DNS record; edit it instead")
            if hostname == current and records[name] == address:
                raise ValueError("Nothing changes")
        add = {self._rel(hostname): address} if hostname else {}
        remove = [self._rel(current)] if current else []
        touched = set(add) | set(remove)
        return ({"id": "dns", "kind": "dns", "add": add, "remove": remove,
                 "before": {name: records.get(name) for name in sorted(touched)}},
                {"action": action, "hostname": hostname, "current_hostname": current, "address": address,
                 "previous_address": records.get(self._rel(current)) if current else None})

    @staticmethod
    def _dns_after(stage):
        return {name: stage["add"].get(name) for name in stage["before"]}

    def _dns_answers(self, stage, dns):
        generator = deepcopy(dns["generator"])
        records = {name: address for name, address in dns["records"].items() if name not in stage["remove"]}
        records.update(stage["add"])
        generator["records"] = [{"name": name, "address": address} for name, address in sorted(records.items())]
        _, rendered = deploy_config.render_registry_hosts(generator, dns["values"], self.manager._registry())
        effective = {self._rel(item["name"]): item["address"] for item in rendered["records"]}
        answers = {name: effective[name] for name in stage["before"] if name in effective}
        return answers, sorted(set(stage["before"]) - set(answers))

    def _dns_blockers(self, stage, ctx, state, resuming):
        dns = ctx["dns"]
        blockers = []
        reserved = deploy_config.registry_dns_names(self.manager._registry())
        owned = {self._rel(item["hostname"]) for item in state["routes"]}
        after = self._dns_after(stage)
        for name, before in stage["before"].items():
            hostname = name + "." + self.config["zone"]
            if name in owned:
                blockers.append(hostname + " is reserved by a published LAN URL; change its URL instead")
            if name in reserved and name in stage["add"]:
                blockers.append(hostname + " is a read-only registry host name in DNS")
            found = dns["records"].get(name)
            allowed = (before, after[name]) if resuming else (before,)
            if found not in allowed:
                blockers.append("DNS record " + hostname + " changed since the change was planned; inspect DNS")
        if dns["uncertain"] or dns["state"] != "active":
            blockers.append("DNS placement is not confirmed active; inspect it before changing records")
        if "answers" in stage and self._dns_answers(stage, dns) != (stage["answers"], stage["withdrawn"]):
            blockers.append("Registry DNS answers changed since planning; plan again")
        return blockers

    def _make_dns_plan(self, action, ctx, state, stage, change):
        dns = ctx["dns"]
        pending = state["pending"] if action == "resume" else None
        stage = deepcopy(stage)
        stages = [stage] if not pending or stage["id"] not in pending["completed"] else []
        stage["answers"], stage["withdrawn"] = self._dns_answers(stage, dns)
        blockers = self._dns_blockers(stage, ctx, state, pending is not None)
        reserved = [dns["id"]]
        busy = self._outstanding(reserved)
        if busy:
            blockers.append("Another unexpired deploy plan reserves " + ", ".join(busy) + "; apply it or let it expire")
        routes = _sorted(state["routes"])
        plan = {"id": uuid.uuid4().hex, "kind": PLAN_KIND, "action": action, "change": change,
                "expires_at": (datetime.now(timezone.utc) + PLAN_TTL).isoformat(),
                "executable": not blockers, "blockers": blockers, "warnings": [],
                "changes": self._changes(stages, None, dns, routes, routes),
                "steps": ["Lock LAN route and DNS changes; recheck the shared revision, DNS instance and placement, "
                          "published URL names and registry names", "Record the pending change before any remote effect",
                          "dns: refresh " + dns["id"] + " under the " + dns["host_id"]
                          + " lease; verify the resulting answers over UDP and TCP",
                          "Record the shared revision; on failure stop and offer an explicit resume plan"],
                "routes": {"from": [_view(item) for item in routes], "to": [_view(item) for item in routes]},
                "expected_revision": state["revision"], "resume_of": pending["change_id"] if pending else None,
                "attempt": pending["attempt"] if pending else 0, "gateway": None,
                "dns": {key: dns[key] for key in ("id", "host_id", "revision", "generation", "placement_revision")},
                "deadline_seconds": DEADLINE_SECONDS, "approval_required": True,
                "_dns_only": True, "_dns_stage": stage, "_stages": stages,
                "_all_stages": [{"id": "dns", "kind": "dns", "sha256": None}], "_reserved": reserved,
                "_from_routes": routes, "_to_routes": routes, "_targets": [],
                "_final_sha256": state["caddy_sha256"], "_caddy_from_sha256": None}
        return self._save_plan(plan)

    def _change(self, action, data, old, candidates):
        cfg = self.config
        names = {item["hostname"]: item for item in old}
        if action == "create":
            item = rc.route(cfg, candidates, data.get("hostname"), data.get("workload_id"), data.get("endpoint_id"))
            if item["hostname"] in names:
                raise ValueError(item["hostname"] + " is already published; edit it instead")
            return old + [item], {"action": action, "hostname": item["hostname"], "current_hostname": None}
        current = rc.hostname_in(cfg["zone"], data.get("current_hostname"))
        if current not in names:
            raise ValueError("No published LAN URL " + current)
        rest = [item for item in old if item["hostname"] != current]
        if action == "delete":
            return rest, {"action": action, "hostname": None, "current_hostname": current}
        item = rc.route(cfg, candidates, data.get("hostname"), data.get("workload_id"), data.get("endpoint_id"))
        if item["hostname"] != current and item["hostname"] in names:
            raise ValueError(item["hostname"] + " is already published")
        if item == _snapshot(names[current]):
            raise ValueError("Nothing changes")
        return rest + [item], {"action": action, "hostname": item["hostname"], "current_hostname": current}

    def _stages(self, ip, old, new):
        """Every stage of the change from `old` to `new` routes, in order, with the exact texts and records."""
        cfg = self.config
        old_n = {item["hostname"]: item for item in old}
        new_n = {item["hostname"]: item for item in new}
        added = sorted(set(new_n) - set(old_n))
        removed = sorted(set(old_n) - set(new_n))
        changed = sorted(name for name in set(new_n) & set(old_n) if new_n[name] != old_n[name])
        final = rc.render(cfg, ip, new)
        stages = []
        prepare_text = None
        if added or changed:
            prepare = _sorted(new + [old_n[name] for name in removed])
            prepare_text = rc.render(cfg, ip, prepare)
            stages.append({"id": "caddy-prepare", "kind": "caddy", "text": prepare_text, "sha256": _sha(prepare_text),
                           "routes": prepare})
            stages.append({"id": "verify-prepare", "kind": "verify", "sha256": _sha(prepare_text), "routes": prepare})
        if added or removed:
            stages.append({"id": "dns", "kind": "dns", "add": {self._rel(name): ip for name in added},
                           "remove": [self._rel(name) for name in removed]})
        if prepare_text != final:
            stages.append({"id": "caddy-cleanup", "kind": "caddy", "text": final, "sha256": _sha(final), "routes": new})
            if new:
                stages.append({"id": "verify-final", "kind": "verify", "sha256": _sha(final), "routes": new})
        return stages, {"added": added, "removed": removed, "changed": changed, "final_sha256": _sha(final)}

    def _outstanding(self, instance_ids):
        with self.journal.transaction() as db:
            rows = db.execute("SELECT DISTINCT json_extract(data,'$.instance_id') FROM plans WHERE consumed=0 "
                              "AND json_extract(data,'$.kind')='deploy' AND json_extract(data,'$.expires_at') > ?",
                              (now(),)).fetchall()
        return sorted({row[0] for row in rows} & set(instance_ids))

    def _make_plan(self, action, ctx, state, old, new, change, candidates):
        cfg = self.config
        gateway, dns, ip = ctx["gateway"], ctx["dns"], ctx["gateway_ip"]
        pending = state["pending"] if action == "resume" else None
        old, new = _sorted(old), _sorted(new)
        stages, summary = self._stages(ip, old, new)
        outline = [{key: stage.get(key) for key in ("id", "kind", "sha256")} for stage in stages]
        if pending is not None:
            if outline != pending["stages"]:
                raise ValueError("The stopped change renders differently now (renderer or gateway address changed); "
                                 "inspect the gateway and DNS before continuing")
            stages = [stage for stage in stages if stage["id"] not in pending["completed"]]
        blockers, warnings = [], []
        # Endpoint snapshots this change writes must still be exactly what the candidates offer.
        for name in summary["added"] + summary["changed"]:
            item = next(entry for entry in new if entry["hostname"] == name)
            try:
                current = rc.route(cfg, candidates, name, item["workload_id"], item["endpoint_id"])
            except ValueError as error:
                current = None
                blockers.append("Endpoint of " + name + " is no longer publishable: " + str(error))
            if current is not None and current != item:
                blockers.append("Endpoint of " + name + " changed since the change was planned; start a new change")
        for item in new:
            try:
                rc.check_route(cfg, item, ip)
            except ValueError as error:
                blockers.append(str(error))
        missing = sorted(set(rc.ca_files(cfg, new)) - set(gateway["files"]))
        if missing:
            blockers.append("The gateway carries no CA file " + ", ".join(missing) + "; add it to the gateway before publishing")
        # Gateway: its Caddyfile must be the one this registry wrote (or a step of the stopped change).
        known = {state["caddy_sha256"]}
        if pending is not None:
            known |= {pending["caddy_from_sha256"]} | {stage["sha256"] for stage in pending["stages"] if stage["kind"] == "caddy"}
        if gateway["sha256"] not in known:
            blockers.append("The gateway Caddyfile changed outside LAN routes (sha256 " + gateway["sha256"][:12]
                            + "...); inspect the gateway before changing routes")
        caddy_refreshes = [stage for stage in stages if stage["kind"] == "caddy" and stage["sha256"] != gateway["sha256"]]
        if caddy_refreshes and gateway["uncertain"]:
            blockers.append("Gateway placement is uncertain or has a pending operation; verify or fence it first")
        if caddy_refreshes and gateway["journal_sha256"] != gateway["sha256"]:
            blockers.append("The gateway's journal and application disagree about its Caddyfile; verify the gateway first")
        if gateway["state"] != "active" and any(stage["kind"] in ("caddy", "verify") for stage in stages):
            blockers.append("Gateway placement is " + gateway["state"] + ", not active; routes cannot be changed")
        # DNS: route names only; every other record stays as it is.
        records = dns["records"]
        hosts = self.manager._registry()
        registry_names = deploy_config.registry_dns_names(hosts)
        dns_stage = next((stage for stage in stages if stage["kind"] == "dns"), None)
        dns_needed = False
        if dns_stage:
            for name, address in dns_stage["add"].items():
                found = records.get(name)
                if name in registry_names:
                    blockers.append(name + "." + cfg["zone"] + " is a registry host name in DNS")
                if found is not None and (pending is None or found != address):
                    blockers.append("DNS already has " + name + "." + cfg["zone"] + " -> " + found
                                    + " (not a LAN route); remove that record first")
                dns_needed |= found != address
            for name in dns_stage["remove"]:
                found = records.get(name)
                if name in registry_names:
                    blockers.append(name + "." + cfg["zone"] + " is a registry host name in DNS; "
                                    "removing its URL record would expose the registry answer")
                if (found is not None and found != ip) or (found is None and pending is None):
                    blockers.append("DNS record " + name + "." + cfg["zone"] + " no longer points at the gateway (found "
                                    + (found or "no record") + "); inspect DNS first")
                dns_needed |= found is not None
            if dns["uncertain"] or dns["state"] != "active":
                blockers.append("DNS placement is not confirmed active; inspect it before changing records")
        touched = set(summary["added"]) | set(summary["removed"])
        for item in old:
            if item["hostname"] not in touched and records.get(self._rel(item["hostname"])) != ip:
                warnings.append("DNS for " + item["hostname"] + " does not point at the gateway (left unchanged)")
        reserved = ([cfg["gateway_id"]] if caddy_refreshes else []) + ([cfg["dns_id"]] if dns_needed else [])
        busy = self._outstanding(reserved)
        if busy:
            blockers.append("Another unexpired deploy plan reserves " + ", ".join(busy) + "; apply it or let it expire")
        if dns["host_id"] != gateway["host_id"]:
            warnings.append("DNS (" + dns["host_id"] + ") and the gateway (" + gateway["host_id"] + ") run on different hosts")
        if caddy_refreshes:
            warnings.append("The gateway restarts " + str(len(caddy_refreshes)) + " time(s): every LAN URL is briefly unavailable")
        if summary["added"] or summary["changed"]:
            warnings.append("Anyone who can reach the LAN gateway can reach this endpoint. Caddy does not add sign-in; "
                            "the workload's own access controls still apply.")
        if state["adopted"] and gateway["sha256"] == state["adopted"]["caddy_sha256"] and caddy_refreshes:
            warnings.append("This first change replaces the adopted Caddyfile with the rendered one; every route is probed")
        if any(stage["kind"] == "caddy" and stage["sha256"] == gateway["sha256"] for stage in stages):
            warnings.append("The gateway already holds a Caddyfile of this change; it is verified, not written again")
        changes = self._changes(stages, gateway, dns, old, new)
        steps = self._steps(stages, gateway, dns)
        plan = {"id": uuid.uuid4().hex, "kind": PLAN_KIND, "action": action, "change": change,
                "expires_at": (datetime.now(timezone.utc) + PLAN_TTL).isoformat(),
                "executable": not blockers, "blockers": blockers, "warnings": warnings, "changes": changes, "steps": steps,
                "routes": {"from": [_view(item) for item in old], "to": [_view(item) for item in new]},
                "expected_revision": state["revision"], "resume_of": pending["change_id"] if pending else None,
                "attempt": pending["attempt"] if pending else 0,
                "gateway": {"id": gateway["id"], "host_id": gateway["host_id"], "address": ip,
                            **{key: gateway[key] for key in ("revision", "generation", "placement_revision", "sha256")}},
                "dns": {key: dns[key] for key in ("id", "host_id", "revision", "generation", "placement_revision")},
                "deadline_seconds": DEADLINE_SECONDS, "approval_required": True,
                "_stages": stages, "_all_stages": outline, "_reserved": reserved,
                "_from_routes": old, "_to_routes": new, "_targets": summary["added"] + summary["changed"],
                "_final_sha256": summary["final_sha256"], "_caddy_from_sha256": gateway["sha256"]}
        return self._save_plan(plan)

    def _save_plan(self, plan):
        if plan["executable"]:
            with self.journal.transaction() as db:
                db.execute("DELETE FROM plans WHERE consumed=0 AND json_extract(data,'$.kind')=? "
                           "AND json_extract(data,'$.expires_at') < ?", (PLAN_KIND, now()))
                count = db.execute("SELECT count(*) FROM plans WHERE consumed=0 AND json_extract(data,'$.kind')=?",
                                   (PLAN_KIND,)).fetchone()[0]
                if count >= PLAN_LIMIT:
                    raise ValueError("Too many outstanding LAN route plans; let them expire")
                db.execute("INSERT INTO plans(id,data,fingerprint) VALUES(?,?,?)",
                           (plan["id"], json.dumps(plan, sort_keys=True, separators=(",", ":")), self.fingerprint))
                self.journal.bump(db)
        return _public(plan)

    def _changes(self, stages, gateway, dns, old, new):
        cfg = self.config
        changes, text = [], gateway["text"] if gateway else None
        for stage in stages:
            if stage["kind"] == "caddy":
                entry = {"target": "gateway " + gateway["id"] + " Caddyfile (" + stage["id"] + ")", "stage": stage["id"],
                         "diff": deploy_config.diff(text, stage["text"], "Caddyfile") if stage["text"] != text else ""}
                if stage["text"] == text:
                    entry["note"] = "already in place; verified only"
                changes.append(entry)
                text = stage["text"]
            elif stage["kind"] == "dns":
                before = dict(dns["records"])
                after = {name: address for name, address in before.items() if name not in stage["remove"]}
                after.update(stage["add"])
                changes.append({"target": "DNS " + dns["id"] + " records", "stage": stage["id"],
                                "diff": deploy_config.diff(_records_text(before, cfg["zone"]), _records_text(after, cfg["zone"]),
                                                           "records")})
        if gateway is not None:
            changes.append({"target": "LAN route registry", "stage": None,
                            "diff": deploy_config.diff("".join(map(_line, old)), "".join(map(_line, new)), "routes")})
        return changes

    def _steps(self, stages, gateway, dns):
        steps = ["Lock LAN route changes; recheck the registry revision, gateway and DNS instance revisions and placements, "
                 "the gateway address claim and every endpoint snapshot",
                 "Record the pending change before any remote effect"]
        for stage in stages:
            if stage["kind"] == "caddy":
                steps.append(stage["id"] + ": refresh gateway " + gateway["id"] + " with the reviewed Caddyfile ("
                             + str(len(stage["routes"])) + " routes; restart) under the " + gateway["host_id"]
                             + " lease; skipped if the gateway already holds it")
            elif stage["kind"] == "verify":
                steps.append(stage["id"] + ": leased HTTPS probe on " + gateway["host_id"] + " of every route in that Caddyfile "
                             "(exact marker, pinned CA, no backend contacted)")
            else:
                steps.append("dns: one refresh of " + dns["id"] + " under the " + dns["host_id"] + " lease adding "
                             + (", ".join(sorted(stage["add"])) or "nothing") + " and removing "
                             + (", ".join(stage["remove"]) or "nothing") + "; verify the answers over UDP and TCP")
        steps.append("Record the new registry revision. On any failure stop, keep the pending change and offer an explicit "
                     "resume plan; nothing is retried automatically")
        return steps

    # ------------------------------------------------------------------------------------------ applying
    def apply(self, plan_id, *, approved, request_id):
        if approved is not True:
            raise ValueError("Applying a LAN route plan requires explicit approval")
        self.manager.broker._request_id(request_id)
        if not isinstance(plan_id, str) or not PLAN_ID.match(plan_id):
            raise ValueError("Invalid plan ID")
        with self.journal.transaction() as db:
            row = db.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown plan")
        plan = json.loads(row["data"])
        if plan.get("kind") != PLAN_KIND:
            raise ValueError("Not a LAN route plan")
        if row["consumed"]:
            state = self._context(dns_only=bool(plan.get("_dns_only")))["state"] or {}
            last, pending = state.get("last_apply"), state.get("pending")
            if last and (last["plan_id"], last["request_id"]) == (plan_id, request_id):
                return {**last["result"], "replayed": True}
            if pending and (pending["plan_id"], pending["request_id"]) == (plan_id, request_id):
                view = self._pending_view(state)
                return {"status": view["status"], "plan_id": plan_id, "request_id": request_id,
                        "pending": view, "replayed": True}
            raise ValueError("Plan already applied; plan again")
        if _expired(plan["expires_at"]):
            raise ValueError("Plan expired; plan again")
        if row["fingerprint"] != self.fingerprint:
            raise ValueError("LAN route configuration changed since planning; plan again")
        with self._locked():
            ctx = self._context(dns_only=bool(plan.get("_dns_only")))
            self._check_current(plan, ctx, [] if plan.get("_dns_only") else self._scan()[0])
            with self.journal.transaction() as db:
                if not db.execute("UPDATE plans SET consumed=1 WHERE id=? AND consumed=0", (plan_id,)).rowcount:
                    raise ValueError("Plan already applied; plan again")
            state = self._begin(plan, request_id)
            return self._execute(plan, state, request_id)

    def _check_current(self, plan, ctx, candidates):
        """Fail closed on any drift between the reviewed plan and the current registry, instances and claims."""
        cfg = self.config
        problems = ctx["dns_problems"] if plan.get("_dns_only") else ctx["problems"]
        if problems:
            raise ValueError("LAN routes are not ready: " + "; ".join(problems))
        state = ctx["state"]
        if state is None or state["revision"] != plan["expected_revision"]:
            raise ValueError("The LAN routes changed since planning; plan again")
        pending = state["pending"]
        if plan["resume_of"]:
            if not pending or (pending["change_id"], pending["attempt"]) != (plan["resume_of"], plan["attempt"]):
                raise ValueError("The pending change moved on since this resume plan; plan again")
        elif pending:
            raise ValueError("A LAN route change is pending; resume it first")
        gateway, dns = ctx["gateway"], ctx["dns"]
        if not plan.get("_dns_only") and (ctx["gateway_ip"] != plan["gateway"]["address"] or any(
                gateway[key] != plan["gateway"][key] for key in ("host_id", "revision", "generation", "placement_revision", "sha256"))):
            raise ValueError("Gateway instance, placement or address changed since planning; plan again")
        if any(dns[key] != plan["dns"][key] for key in ("host_id", "revision", "generation", "placement_revision")):
            raise ValueError("DNS instance or placement changed since planning; plan again")
        if plan.get("_dns_only"):
            blockers = self._dns_blockers(plan["_dns_stage"], ctx, state, bool(plan["resume_of"]))
            if blockers:
                raise ValueError("; ".join(blockers) + "; plan again")
        else:
            reserved = deploy_config.registry_dns_names(self.manager._registry())
            for stage in plan["_stages"]:
                if stage["kind"] == "dns" and reserved.intersection(set(stage["add"]) | set(stage["remove"])):
                    raise ValueError("DNS name became a registry host name since planning; plan again")
                if stage["kind"] == "dns":
                    for name, address in stage["add"].items():
                        found = dns["records"].get(name)
                        if found is not None and (not plan["resume_of"] or found != address):
                            raise ValueError("DNS record changed since planning; plan again")
        for name in plan["_targets"]:
            item = next(entry for entry in plan["_to_routes"] if entry["hostname"] == name)
            try:
                current = rc.route(cfg, candidates, name, item["workload_id"], item["endpoint_id"])
            except ValueError as error:
                raise ValueError("Endpoint of " + name + " is no longer publishable: " + str(error)) from None
            if current != item:
                raise ValueError("Endpoint of " + name + " changed since planning; plan again")
        for stage in plan["_stages"]:
            if stage["kind"] == "caddy" and _sha(rc.render(cfg, ctx["gateway_ip"], stage["routes"])) != stage["sha256"]:
                raise ValueError("The rendered Caddyfile differs from the plan; plan again")
        busy = self._outstanding(plan["_reserved"])
        if busy:
            raise ValueError("Another unexpired deploy plan reserves " + ", ".join(busy) + "; plan again later")

    def _begin(self, plan, request_id):
        def mutate(state):
            if state["revision"] != plan["expected_revision"]:
                raise ValueError("The LAN routes changed since planning; plan again")
            stamp = now()
            if plan["resume_of"]:
                pending = state["pending"]
                if not pending or (pending["change_id"], pending["attempt"]) != (plan["resume_of"], plan["attempt"]):
                    raise ValueError("The pending change moved on since this resume plan; plan again")
                pending.update(status="running", attempt=pending["attempt"] + 1, plan_id=plan["id"], request_id=request_id,
                               error=None, stage=None, updated_at=stamp)
            else:
                if state["pending"]:
                    raise ValueError("A LAN route change is pending; resume it first")
                pending = {"change_id": plan["id"], "plan_id": plan["id"], "request_id": request_id, "attempt": 1,
                           **plan["change"], "from_routes": plan["_from_routes"], "to_routes": plan["_to_routes"],
                           "caddy_from_sha256": plan["_caddy_from_sha256"], "stages": plan["_all_stages"],
                           "completed": [], "stage": None, "status": "running", "error": None, "receipts": [],
                           "stage_results": [], "started_at": stamp, "updated_at": stamp}
            if plan.get("_dns_only"):
                pending["dns_stage"] = plan["_dns_stage"]
            state["pending"] = pending
            return state
        return self._update(mutate)

    def _checkpoint(self, change_id, attempt, mutate):
        def guarded(state):
            pending = state["pending"]
            if not pending or (pending["change_id"], pending["attempt"]) != (change_id, attempt):
                raise ValueError("The pending LAN route change was replaced while running")
            mutate(state)
            return state
        return self._update(guarded)

    def _execute(self, plan, state, request_id):
        pending = state["pending"]
        change_id, attempt = pending["change_id"], pending["attempt"]
        base = request_id if len(request_id) <= 96 else "lan-" + _sha(request_id)[:40]
        run = {"gateway_revision": plan["gateway"]["revision"] if plan["gateway"] else None,
               "dns_revision": plan["dns"]["revision"],
               "address": plan["gateway"]["address"] if plan["gateway"] else None,
               "dns_only": bool(plan.get("_dns_only"))}
        results, receipts = [], []
        started = time.monotonic()
        error = None
        for index, stage in enumerate(plan["_stages"]):
            if time.monotonic() - started + STAGE_SECONDS[stage["kind"]] > DEADLINE_SECONDS:
                error = "Time budget reached before stage " + stage["id"] + " (nothing of it started); resume to continue"
                break
            self._checkpoint(change_id, attempt, lambda s, stage_id=stage["id"]: s["pending"].update(stage=stage_id))
            detail = {"stage": stage["id"], "kind": stage["kind"], "status": "running", "receipts": [], "at": now()}
            try:
                getattr(self, "_stage_" + stage["kind"])(stage, run, base + "." + str(attempt) + "." + str(index), detail)
            except Exception as failure:  # every failure stops the change with its evidence; never retried
                detail["status"] = "failed"
                detail["error"] = str(failure) if isinstance(failure, ValueError) else type(failure).__name__ + ": " + str(failure)
            results.append(detail)
            receipts += [item["id"] for item in detail["receipts"] if item.get("id")]

            def record(s, detail=detail):
                s["pending"]["stage_results"].append(detail)
                s["pending"]["receipts"] += [item["id"] for item in detail["receipts"] if item.get("id")]
                if detail["status"] in ("succeeded", "already"):
                    s["pending"]["completed"].append(detail["stage"])
            self._checkpoint(change_id, attempt, record)
            if detail["status"] not in ("succeeded", "already"):
                error = "Stage " + stage["id"] + " failed: " + detail["error"]
                break
        if error is None and not plan.get("_dns_only"):
            current = self._context()["gateway"]
            if current is None or current["sha256"] != plan["_final_sha256"]:
                error = "The gateway does not hold the final Caddyfile of this change; inspect, then resume"
        result = {"plan_id": plan["id"], "request_id": request_id, "receipts": receipts, "stages": results}

        def save_result(s):
            pending_view = self._pending_view({**s, "revision": s["revision"] + 1})
            result.update(revision=s["revision"] + 1, routes=[_view(item) for item in s["routes"]], pending=pending_view)
            if pending_view is not None:
                result["resume"] = pending_view["resume"]
            s["last_apply"] = {"plan_id": plan["id"], "request_id": request_id, "result": result}

        if error is not None:
            result.update(status="partial", error=error)

            def stop(s):
                s["pending"].update(status="partial", error=error, stage=None)
                save_result(s)
            self._checkpoint(change_id, attempt, stop)
            return result
        result["status"] = "succeeded"

        def finish(s):
            touched = {item["hostname"] for item in s["pending"]["from_routes"]} ^ {item["hostname"] for item in plan["_to_routes"]}
            touched |= {name for name in plan["_targets"]}
            s["routes"] = plan["_to_routes"]
            s["caddy_sha256"] = plan["_final_sha256"]
            if s["adopted"]:
                s["adopted"]["hostnames"] = [name for name in s["adopted"]["hostnames"] if name not in touched]
            s["pending"] = None
            save_result(s)
        self._checkpoint(change_id, attempt, finish)
        return result

    # ------------------------------------------------------------------------------------------ stages
    def _discard(self, deploy_plan_id):
        with self.journal.transaction() as db:
            db.execute("DELETE FROM plans WHERE id=? AND consumed=0", (deploy_plan_id,))

    def _refresh(self, planned, file_id, rid, detail):
        """Apply one deploy refresh plan that changes exactly `file_id`; its receipts land in `detail`."""
        detail["receipts"].append({"id": planned.get("inspection_receipt"), "kind": "refresh-inspect", "status": "succeeded"})
        if not planned["executable"]:
            detail["preconditions"] = [item for item in planned.get("preconditions", []) if not item["ok"]]
            raise ValueError("Refresh plan refused: " + ", ".join(planned["blockers"]))
        updated = sorted(item["id"] for item in planned["changes"] if item["change"] == "update")
        if updated != [file_id]:
            self._discard(planned["id"])
            raise ValueError("Refresh would change " + (", ".join(updated) or "nothing") + ", not only " + file_id)
        try:
            outcome = self.manager.refresh_apply(planned["id"], approved=True, request_id=rid + ".apply")
        except Exception:
            self._discard(planned["id"])
            raise
        receipt = outcome["receipt"]
        detail["receipts"].append({"id": receipt.get("id"), "kind": "refresh", "status": receipt.get("status"),
                                   "error": receipt.get("error"), "placement": outcome.get("placement")})
        if receipt.get("status") != "succeeded":
            raise ValueError("Refresh " + str(receipt.get("status")) + ": " + str(receipt.get("error"))
                             + "; receipt " + str(receipt.get("id")))

    def _stage_caddy(self, stage, run, rid, detail):
        ctx = self._context()
        gateway = ctx["gateway"]
        if gateway is None or ctx["gateway_ip"] != run["address"]:
            raise ValueError("Gateway instance or address changed during the change")
        if gateway["revision"] != run["gateway_revision"]:
            raise ValueError("Gateway instance revision changed during the change (expected " + str(run["gateway_revision"])
                             + ", found " + str(gateway["revision"]) + ")")
        if gateway["sha256"] == stage["sha256"]:
            detail.update(status="already", note="The gateway application already holds this Caddyfile (journal sha256 "
                          + str(gateway["journal_sha256"])[:12] + "...); not written again")
            return
        planned = self.manager.refresh_plan(self.config["gateway_id"], config_contents={"caddyfile": stage["text"]},
                                            expected_instance_revision=gateway["revision"], request_id=rid + ".inspect")
        self._refresh(planned, GATEWAY_FILE, rid, detail)
        after = self._context()["gateway"]
        if after is None or after["sha256"] != stage["sha256"] or after["journal_sha256"] != stage["sha256"]:
            raise ValueError("The refresh succeeded but the journal does not hold the planned Caddyfile; inspect the gateway")
        run["gateway_revision"] = after["revision"]
        detail["status"] = "succeeded"

    def _stage_dns(self, stage, run, rid, detail):
        ctx = self._context(dns_only=run["dns_only"])
        dns = ctx["dns"]
        if dns is None or dns["revision"] != run["dns_revision"]:
            raise ValueError("DNS instance changed during the change; inspect DNS")
        records, ip = dns["records"], run["address"]
        add, remove = {}, []
        if "before" in stage:
            # Accept only the reviewed value or its already-written final value. In particular, an update
            # removes and re-adds its name in one refresh; a resumed successful write is verification only.
            after = self._dns_after(stage)
            for name, before in stage["before"].items():
                found, wanted = records.get(name), after[name]
                if found not in (before, wanted):
                    raise ValueError("DNS record " + name + " changed during the change; inspect DNS")
                if found != wanted:
                    if found is not None:
                        remove.append(name)
                    if wanted is not None:
                        add[name] = wanted
        else:
            for name, address in stage["add"].items():
                found = records.get(name)
                if found is not None and found != address:
                    raise ValueError("DNS record " + name + " now points at " + found + "; inspect DNS")
                if found is None:
                    add[name] = address
            for name in stage["remove"]:
                found = records.get(name)
                if found is not None and found != ip:
                    raise ValueError("DNS record " + name + " now points at " + found + "; inspect DNS")
                if found is not None:
                    remove.append(name)
        if add or remove:
            planned = self.manager.refresh_plan(self.config["dns_id"], add_records=add, remove_records=remove,
                                                expected_instance_revision=dns["revision"], request_id=rid + ".inspect")
            self._refresh(planned, dns["file_id"], rid, detail)
            after = self._context(dns_only=run["dns_only"])["dns"]
            expected = {name: address for name, address in records.items() if name not in remove} | add
            if after is None or after["records"] != expected:
                raise ValueError("The refresh succeeded but the journal's DNS records differ from the plan; inspect DNS")
            run["dns_revision"] = after["revision"]
            dns = after
        answers, withdrawn = stage["add"], [name for name in stage["remove"] if name not in stage["add"]]
        if "before" in stage:
            answers, withdrawn = self._dns_answers(stage, dns)
            if (answers, withdrawn) != (stage["answers"], stage["withdrawn"]):
                raise ValueError("Registry DNS answers changed during the change; inspect DNS")
        receipt = verify_dns(self.service, self.config, dns["host_id"], answers, withdrawn)
        detail["receipts"].append({"id": receipt.get("id"), "kind": "dns-check", "status": receipt.get("status"),
                                   "error": receipt.get("error")})
        if receipt.get("status") != "succeeded":
            raise ValueError("DNS check " + str(receipt.get("status")) + ": " + str(receipt.get("error"))
                             + "; receipt " + str(receipt.get("id")))
        detail["status"] = "succeeded" if add or remove else "already"

    def _stage_verify(self, stage, run, rid, detail):
        ctx = self._context()
        gateway = ctx["gateway"]
        if gateway is None or ctx["gateway_ip"] != run["address"] or gateway["sha256"] != stage["sha256"]:
            raise ValueError("The gateway does not hold the Caddyfile this probe verifies; inspect the gateway")
        if gateway["state"] != "active":
            raise ValueError("Gateway placement is " + gateway["state"] + ", not active")
        receipt = verify_proxy(self.service, self.config, run["address"], gateway["host_id"], stage["routes"])
        detail["receipts"].append({"id": receipt.get("id"), "kind": "route-probe", "status": receipt.get("status"),
                                   "error": receipt.get("error"), "verified": receipt.get("verified")})
        if receipt.get("status") != "succeeded":
            raise ValueError("Route probe " + str(receipt.get("status")) + ": " + str(receipt.get("error"))
                             + "; receipt " + str(receipt.get("id")))
        detail["status"] = "succeeded"
