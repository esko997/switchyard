"""LAN route manager: registry, adoption, staged gateway/DNS orchestration, partial changes and resume.

A real temporary workload store and operation journal; a fake deploy manager whose refreshes change the stored
instances exactly as a successful refresh records them; fake leased probes.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import uuid

import unittest
from unittest.mock import patch

from switchyard import deploy_config, lan_route_config as rc, lan_routes
from switchyard.broker import REQUEST_ID
from switchyard.lan_routes import META_KEY, LanRoutes
from switchyard.operation_store import Store, now
from switchyard.workload_store import WorkloadStore

ZONE = "example.test"
GATEWAY_IP = "192.168.50.233"
HAND_WRITTEN = "# hand-written gateway\nchat.example.test {\n    reverse_proxy 192.168.50.143:3000\n}\n"
SITE = re.compile(r"^([a-z0-9.-]+\.example\.test) \{$", re.M)


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def candidate(workload_id, endpoint_id, address, port):
    return {"workload_id": workload_id, "endpoint_id": endpoint_id, "address": address, "port": port, "scheme": "http",
            "profile": "plain", "host_id": "host-d", "relation": "deployed", "hostnames": None, "ca_file": None}


class FakeBroker:
    def __init__(self, directory):
        self.store = Store(directory)

    @staticmethod
    def _request_id(value):
        if not isinstance(value, str) or not REQUEST_ID.fullmatch(value):
            raise ValueError("Request ID must be 1–128 safe identifier characters")


class FakeDeployManager:
    """Refresh plans and applies with the recorded effects of a successful refresh, and an ordered event log."""

    def __init__(self, directory, events):
        self.broker = FakeBroker(directory)
        self.store = WorkloadStore(directory)
        self.events = events
        self.hosts = [{"id": "host-b", "collector": {"transport": "ssh", "target": "operator@192.168.50.233"}}]
        self.fail_apply = None  # callable(instance_id) -> receipt status/error override, or raise

    def _registry(self):
        return list(self.hosts)

    def refresh_plan(self, instance_id, *, params=None, add_records=None, remove_records=(), request_id=None,
                     config_contents=None, expected_instance_revision=None):
        with self.store.reading() as db:
            instance = self.store.instance_row(db, instance_id)
        if expected_instance_revision is not None and instance["revision"] != expected_instance_revision:
            raise ValueError("Instance changed since the route plan; prepare a new plan")
        assert REQUEST_ID.fullmatch(request_id)
        app = deepcopy(instance["application"])
        changed = []
        if config_contents is not None:
            item = next(f for f in app["config_files"] if f["id"] == "caddyfile")
            if item["content"] != config_contents["caddyfile"]:
                item["content"] = config_contents["caddyfile"]
                changed.append("caddyfile")
        if add_records or remove_records:
            app = deploy_config.change_records(app, add=dict(add_records or {}), remove=list(remove_records or []), hosts=self.hosts)
            changed.append("hosts")
        plan = {"id": uuid.uuid4().hex, "kind": "deploy", "action": "refresh", "instance_id": instance_id,
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
                "executable": bool(changed), "blockers": [] if changed else ["changes"], "preconditions": [],
                "inspection_receipt": request_id, "application": app,
                "changes": [{"id": f["id"], "change": "update" if f["id"] in changed else "unchanged"} for f in app["config_files"]]}
        with self.broker.store.transaction() as db:
            db.execute("INSERT INTO plans(id,data,fingerprint) VALUES(?,?,?)", (plan["id"], json.dumps(plan), "f"))
        self.events.append(("refresh-plan", instance_id))
        return plan

    def refresh_apply(self, plan_id, *, approved, request_id):
        assert approved is True and REQUEST_ID.fullmatch(request_id)
        with self.broker.store.transaction() as db:
            plan = json.loads(db.execute("SELECT data FROM plans WHERE id=?", (plan_id,)).fetchone()[0])
            assert db.execute("UPDATE plans SET consumed=1 WHERE id=? AND consumed=0", (plan_id,)).rowcount == 1
        instance_id, app = plan["instance_id"], plan["application"]
        if self.fail_apply:
            override = self.fail_apply(instance_id)
            if override:
                self.events.append(("refresh-failed", instance_id))
                return {"receipt": {"id": request_id, "status": override, "error": "worker said no"}}
        write_instance(self.store, app, revision_bump=True)
        caddy = next((f for f in app["config_files"] if f["id"] == "caddyfile"), None)
        if caddy:
            self.events.append(("caddy", tuple(SITE.findall(caddy["content"]))))
        else:
            records = deploy_config.generator_file(app)["generator"]["records"]
            self.events.append(("dns", tuple(sorted((r["name"], r["address"]) for r in records))))
        return {"receipt": {"id": request_id, "status": "succeeded"}, "placement": {"state": "active"}}


def write_instance(store, app, *, template_id=None, revision_bump=False, placement=None):
    """Store a deployed instance (and its placement); a bump records a refresh: new revision, new file hashes."""
    with store.transaction() as db:
        row = db.execute("SELECT revision, template_id FROM workloads WHERE id=?", (app["id"],)).fetchone()
        revision = row[0] + 1 if row and revision_bump else app["revision"]
        app = {**app, "revision": revision}
        stamp = now()
        db.execute("INSERT OR REPLACE INTO workloads(id,relation,revision,content_sha256,template_id,template_revision,"
                   "data,meta,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (app["id"], "deployed", revision, sha(json.dumps(app, sort_keys=True)), template_id or row[1], 1,
                    json.dumps(app), "{}", stamp, stamp))
        native = [{"name": f["path"], "sha256": sha(f["content"])} for f in app["config_files"] if f.get("content") is not None]
        if placement is not None:
            db.execute("INSERT INTO placements VALUES(?,?,?,?,?,?,?,?)",
                       (app["id"], 1, placement, "active", json.dumps({"apiVersion": "switchyard/v1alpha3", "kind": "Placement"}),
                        json.dumps({"ownership_id": "o", "native": {"config": native}}), 1, stamp))
        else:
            meta = json.loads(db.execute("SELECT meta FROM placements WHERE instance_id=?", (app["id"],)).fetchone()[0])
            meta["native"]["config"] = native
            db.execute("UPDATE placements SET meta=?, revision=revision+1 WHERE instance_id=?", (json.dumps(meta), app["id"]))


def gateway_app(content=HAND_WRITTEN):
    return {"apiVersion": "switchyard/v1alpha3", "kind": "Application", "id": "lan-web", "revision": 1,
            "config_files": [{"id": "caddyfile", "component": "proxy", "path": "Caddyfile", "on_change": "restart", "content": content},
                             {"id": "learning-box-ca", "component": "proxy", "path": "learning-box-ca.crt", "on_change": "restart",
                              "content": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"}]}


def dns_app(records):
    return {"apiVersion": "switchyard/v1alpha3", "kind": "Application", "id": "lan-dns", "revision": 1,
            "parameters": [{"id": "zone", "format": "dns-name", "value": ZONE}],
            "config_files": [{"id": "corefile", "component": "dns", "path": "Corefile", "on_change": "restart", "content": "x\n"},
                             {"id": "hosts", "component": "dns", "path": "hosts", "on_change": "none",
                              "generator": {"kind": "registry-hosts", "zone": "{{zone}}",
                                            "records": [{"name": n, "address": a} for n, a in sorted(records.items())]}}]}


def make_env(tmp_path, test):
    events = []
    manager = FakeDeployManager(tmp_path / "state", events)
    write_instance(manager.store, gateway_app(), template_id="caddy-lan", placement="host-b")
    write_instance(manager.store, dns_app({"chat": GATEWAY_IP, "controller": "192.168.50.68", "printer": "192.168.50.50"}),
                   template_id="coredns-lan", placement="host-b")
    with manager.store.transaction() as db:
        for port, endpoint in ((443, "https"), (80, "redirect")):
            db.execute("INSERT INTO claims VALUES(?,?,?,?,?,?,?,?,?,?)",
                       ("host-b", 4, GATEWAY_IP, "tcp", port, "placement", "lan-web", endpoint, 1, None))
    candidates = [candidate("open-webui", "http", "192.168.50.143", 3000), candidate("comfyui", "http", "192.168.50.143", 8188),
                  candidate("sillytavern", "http", "192.168.50.143", 8000), candidate("printer-ui", "http", "192.168.50.50", 8080)]
    test.enterContext(patch.object(rc, "endpoint_scan", lambda store, config, hosts=None: (deepcopy(candidates), [])))
    probes = {"fail": None, "dns_fail": None, "dns_checks": []}

    def verify_proxy(service, config, gateway_ip, gateway_host, routes):
        assert (gateway_ip, gateway_host) == (GATEWAY_IP, "host-b")
        events.append(("probe", tuple(item["hostname"] for item in routes)))
        receipt = {"id": "probe-" + str(len(events)), "status": "succeeded", "verified": [item["hostname"] for item in routes]}
        if probes["fail"]:
            receipt.update(status="failed", error=probes["fail"], verified=[])
        return receipt

    def verify_dns(service, config, host_id, add, remove):
        events.append(("dns-check", tuple(sorted(add)), tuple(sorted(remove))))
        probes["dns_checks"].append((deepcopy(add), list(remove)))
        if probes["dns_fail"]:
            return {"id": "dns-check-" + str(len(events)), "status": "failed", "error": probes["dns_fail"]}
        return {"id": "dns-check-" + str(len(events)), "status": "succeeded"}

    test.enterContext(patch.object(lan_routes, "verify_proxy", verify_proxy))
    test.enterContext(patch.object(lan_routes, "verify_dns", verify_dns))
    config = rc.normalize({"gateway_id": "lan-web", "dns_id": "lan-dns", "zone": ZONE, "ca_sha256": "a" * 64,
                           "adopt_caddy_sha256": sha(HAND_WRITTEN),
                           "adopt_routes": [{"hostname": "chat.example.test", "workload_id": "open-webui", "endpoint_id": "http"}]})
    service = SimpleNamespace(deployments=lambda: manager)
    return SimpleNamespace(manager=manager, events=events, probes=probes, config=config, service=service,
                           routes=lambda: LanRoutes(service, config))


def state(env):
    with env.manager.store.reading() as db:
        return WorkloadStore.meta(db, META_KEY)


def dns_records(env):
    with env.manager.store.reading() as db:
        app = env.manager.store.instance_row(db, "lan-dns")["application"]
    return {r["name"]: r["address"] for r in deploy_config.generator_file(app)["generator"]["records"]}


def gateway_text(env):
    with env.manager.store.reading() as db:
        app = env.manager.store.instance_row(db, "lan-web")["application"]
    return next(f for f in app["config_files"] if f["id"] == "caddyfile")["content"]


def publish(env, hostname, workload_id, request_id="req-1"):
    routes = env.routes()
    plan = routes.plan({"action": "create", "hostname": hostname, "workload_id": workload_id, "endpoint_id": "http",
                        "expected_revision": routes.list()["revision"]})
    assert plan["executable"], plan["blockers"]
    return plan, routes.apply(plan["id"], approved=True, request_id=request_id)


class LanRoutesTests(unittest.TestCase):
    def setUp(self):
        self.env = make_env(Path(self.enterContext(TemporaryDirectory())), self)


    def test_adoption_is_read_only_until_first_use_then_idempotent(self):
        env = self.env
        routes = env.routes()
        assert [item["url"] for item in routes.published()] == ["https://chat.example.test/"]
        assert state(env) is None
        listed = routes.list()
        assert listed["configured"] and listed["ready"] and listed["revision"] == 1 and listed["pending"] is None
        assert [(item["hostname"], item["adopted"], item["address"], item["port"]) for item in listed["routes"]] == \
            [("chat.example.test", True, "192.168.50.143", 3000)]
        assert next(row for row in listed["endpoints"] if row["workload_id"] == "open-webui")["published_as"] == ["chat.example.test"]
        assert env.routes().list()["revision"] == 1
        assert env.events == []  # no host contact, no refresh


    def test_adoption_refused_when_live_caddyfile_differs(self):
        env = self.env
        write_instance(env.manager.store, gateway_app(HAND_WRITTEN + "# edited\n"), revision_bump=True)
        routes = env.routes()
        assert routes.published() == []
        listed = routes.list()
        assert listed["revision"] == 0 and not listed["ready"] and "adoption baseline" in listed["problems"][0]
        assert state(env) is None
        with self.assertRaisesRegex(ValueError, "not ready"):
            routes.plan({"action": "create", "hostname": "comfy", "workload_id": "comfyui", "endpoint_id": "http",
                         "expected_revision": 0})


    def test_create_orders_gateway_probe_dns_and_keeps_unrelated_records(self):
        env = self.env
        plan, result = publish(env, "comfy", "comfyui")
        assert [stage["id"] for stage in plan["stages"]] == ["caddy-prepare", "verify-prepare", "dns"]
        assert any("adopted Caddyfile" in warning for warning in plan["warnings"])
        assert result["status"] == "succeeded" and result["pending"] is None
        assert env.events == [("refresh-plan", "lan-web"), ("caddy", ("chat.example.test", "comfy.example.test")),
                              ("probe", ("chat.example.test", "comfy.example.test")),  # adopted route verified too
                              ("refresh-plan", "lan-dns"),
                              ("dns", (("chat", GATEWAY_IP), ("comfy", GATEWAY_IP), ("controller", "192.168.50.68"),
                                       ("printer", "192.168.50.50")))] + [e for e in env.events if e[0] == "dns-check"]
        assert dns_records(env) == {"chat": GATEWAY_IP, "comfy": GATEWAY_IP, "controller": "192.168.50.68", "printer": "192.168.50.50"}
        assert gateway_text(env) == rc.render(env.config, GATEWAY_IP, state(env)["routes"])
        listed = env.routes().list()
        assert [item["hostname"] for item in listed["routes"]] == ["chat.example.test", "comfy.example.test"]
        assert listed["revision"] == result["revision"] > 1
        assert len(result["receipts"]) >= 4 and "probe-3" in result["receipts"]
        # Same plan and request ID: the recorded result, not a second change.
        replay = env.routes().apply(plan["id"], approved=True, request_id="req-1")
        self.assertEqual(replay, {**result, "replayed": True})
        with self.assertRaisesRegex(ValueError, "already applied"):
            env.routes().apply(plan["id"], approved=True, request_id="req-other")


    def test_stale_revision_and_drift_fail_closed_before_any_remote_effect(self):
        env = self.env
        routes = env.routes()
        revision = routes.list()["revision"]
        first = routes.plan({"action": "create", "hostname": "comfy", "workload_id": "comfyui", "endpoint_id": "http",
                             "expected_revision": revision})
        second = routes.plan({"action": "create", "hostname": "tavern", "workload_id": "sillytavern", "endpoint_id": "http",
                              "expected_revision": revision})
        assert routes.apply(first["id"], approved=True, request_id="a")["status"] == "succeeded"
        count = len(env.events)
        with self.assertRaisesRegex(ValueError, "changed since"):
            routes.apply(second["id"], approved=True, request_id="b")
        with self.assertRaisesRegex(ValueError, "changed since you looked"):
            routes.plan({"action": "delete", "current_hostname": "comfy", "expected_revision": revision})
        # Gateway instance changes between plan and apply: refused, nothing remote.
        fresh = routes.list()["revision"]
        third = routes.plan({"action": "create", "hostname": "tavern", "workload_id": "sillytavern", "endpoint_id": "http",
                             "expected_revision": fresh})
        write_instance(env.manager.store, gateway_app(gateway_text(env)), revision_bump=True)
        with self.assertRaisesRegex(ValueError, "Gateway instance"):
            routes.apply(third["id"], approved=True, request_id="c")
        assert len(env.events) == count
        with self.assertRaisesRegex(ValueError, "approval"):
            routes.apply(third["id"], approved=False, request_id="d")


    def test_out_of_band_gateway_edit_and_dns_collisions_block(self):
        env = self.env
        routes = env.routes()
        revision = routes.list()["revision"]
        plan = routes.plan({"action": "create", "hostname": "printer", "workload_id": "printer-ui", "endpoint_id": "http",
                            "expected_revision": revision})
        assert not plan["executable"] and any("not a LAN route" in item for item in plan["blockers"])
        plan = routes.plan({"action": "create", "hostname": "host-b", "workload_id": "printer-ui", "endpoint_id": "http",
                            "expected_revision": revision})
        assert any("registry host" in item for item in plan["blockers"])
        write_instance(env.manager.store, gateway_app(HAND_WRITTEN + "# edited\n"), revision_bump=True)
        plan = routes.plan({"action": "create", "hostname": "comfy", "workload_id": "comfyui", "endpoint_id": "http",
                            "expected_revision": revision})
        assert any("changed outside LAN routes" in item for item in plan["blockers"])
        with self.assertRaisesRegex(ValueError, "Unknown plan"):
            routes.apply(plan["id"], approved=True, request_id="x")
        assert env.events == []


    def test_rename_prepares_both_names_switches_dns_together_then_cleans_up(self):
        env = self.env
        publish(env, "comfy", "comfyui")
        env.events.clear()
        routes = env.routes()
        plan = routes.plan({"action": "update", "current_hostname": "comfy.example.test", "hostname": "images",
                            "workload_id": "comfyui", "endpoint_id": "http", "expected_revision": routes.list()["revision"]})
        assert [stage["id"] for stage in plan["stages"]] == ["caddy-prepare", "verify-prepare", "dns", "caddy-cleanup", "verify-final"]
        result = routes.apply(plan["id"], approved=True, request_id="rename")
        assert result["status"] == "succeeded"
        ordered = [e for e in env.events if e[0] != "refresh-plan"]
        assert ordered[0] == ("caddy", ("chat.example.test", "comfy.example.test", "images.example.test"))
        assert ordered[1] == ("probe", ("chat.example.test", "comfy.example.test", "images.example.test"))
        assert ordered[2][0] == "dns" and ("images", GATEWAY_IP) in ordered[2][1] and all(n != "comfy" for n, _ in ordered[2][1])
        rest = [e for e in ordered[3:] if e[0] != "dns-check"]
        assert rest == [("caddy", ("chat.example.test", "images.example.test")), ("probe", ("chat.example.test", "images.example.test"))]
        assert dns_records(env) == {"chat": GATEWAY_IP, "images": GATEWAY_IP, "controller": "192.168.50.68", "printer": "192.168.50.50"}


    def test_delete_withdraws_dns_before_gateway_cleanup(self):
        env = self.env
        publish(env, "comfy", "comfyui")
        env.events.clear()
        routes = env.routes()
        plan = routes.plan({"action": "delete", "current_hostname": "comfy", "expected_revision": routes.list()["revision"]})
        assert [stage["id"] for stage in plan["stages"]] == ["dns", "caddy-cleanup", "verify-final"]
        assert routes.apply(plan["id"], approved=True, request_id="del")["status"] == "succeeded"
        kinds = [e[0] for e in env.events if e[0] != "refresh-plan"]
        assert kinds == ["dns", "dns-check", "caddy", "probe"]
        assert dns_records(env) == {"chat": GATEWAY_IP, "controller": "192.168.50.68", "printer": "192.168.50.50"}
        assert [item["hostname"] for item in routes.list()["routes"]] == ["chat.example.test"]

    def test_dns_verification_refusal_keeps_proxy_until_resume(self):
        env = self.env
        publish(env, "comfy", "comfyui")
        env.events.clear()
        routes = env.routes()
        plan = routes.plan({"action": "delete", "current_hostname": "comfy", "expected_revision": routes.list()["revision"]})
        with patch.object(lan_routes, "verify_dns", return_value={"status": "failed", "error": "old answer still served"}):
            result = routes.apply(plan["id"], approved=True, request_id="del")
        self.assertEqual(result["status"], "partial")
        self.assertIn("old answer still served", result["error"])
        self.assertIn("comfy.example.test", gateway_text(env))
        self.assertNotIn("comfy", dns_records(env))
        env.events.clear()
        resume = routes.plan({"action": "resume", "expected_revision": routes.list()["revision"]})
        self.assertEqual(routes.apply(resume["id"], approved=True, request_id="del-verify")["status"], "succeeded")
        self.assertEqual(env.events[0], ("dns-check", (), ("comfy",)))
        self.assertNotIn("comfy.example.test", gateway_text(env))


    def test_failed_probe_stops_partial_and_explicit_resume_continues(self):
        env = self.env
        env.probes["fail"] = "Caddy route did not match the plan: comfy.example.test"
        routes = env.routes()
        revision = routes.list()["revision"]
        plan = routes.plan({"action": "create", "hostname": "comfy", "workload_id": "comfyui", "endpoint_id": "http",
                            "expected_revision": revision})
        result = routes.apply(plan["id"], approved=True, request_id="r1")
        assert result["status"] == "partial" and "did not match" in result["error"]
        failed = result["stages"][-1]
        assert failed["stage"] == "verify-prepare" and failed["receipts"][0]["status"] == "failed"
        listed = routes.list()
        assert [item["hostname"] for item in listed["routes"]] == ["chat.example.test"]  # never claimed before verified
        assert listed["pending"]["status"] == "partial" and listed["pending"]["completed"] == ["caddy-prepare"]
        assert listed["pending"]["remaining"] == ["verify-prepare", "dns"]
        assert "comfy" not in dns_records(env)
        with self.assertRaisesRegex(ValueError, "pending"):
            routes.plan({"action": "create", "hostname": "tavern", "workload_id": "sillytavern", "endpoint_id": "http",
                         "expected_revision": listed["revision"]})
        with self.assertRaisesRegex(ValueError, "changed since you looked"):
            routes.plan({"action": "resume", "expected_revision": revision})
        env.probes["fail"] = None
        env.events.clear()
        resume = routes.plan({"action": "resume", "expected_revision": listed["revision"]})
        assert resume["executable"] and [stage["id"] for stage in resume["stages"]] == ["verify-prepare", "dns"]
        done = routes.apply(resume["id"], approved=True, request_id="r2")
        assert done["status"] == "succeeded"
        assert [e[0] for e in env.events if e[0] != "dns-check"] == ["probe", "refresh-plan", "dns"]  # gateway not rewritten
        assert [item["hostname"] for item in routes.list()["routes"]] == ["chat.example.test", "comfy.example.test"]
        assert state(env)["pending"] is None


    def test_rejected_refresh_keeps_receipt_details_and_later_resume(self):
        env = self.env
        env.manager.fail_apply = lambda instance_id: "failed" if instance_id == "lan-dns" else None
        routes = env.routes()
        plan, result = publish(env, "comfy", "comfyui")
        assert result["status"] == "partial"
        stage = result["stages"][-1]
        assert stage["stage"] == "dns" and stage["receipts"][-1] == {"id": stage["receipts"][-1]["id"], "kind": "refresh",
                                                                        "status": "failed", "error": "worker said no",
                                                                        "placement": None}
        pending = routes.list()["pending"]
        assert pending["stage_results"][-1]["receipts"][-1]["status"] == "failed"
        env.manager.fail_apply = None
        resume = routes.plan({"action": "resume", "expected_revision": routes.list()["revision"]})
        assert [stage["id"] for stage in resume["stages"]] == ["dns"]
        assert routes.apply(resume["id"], approved=True, request_id="again")["status"] == "succeeded"
        assert dns_records(env)["comfy"] == GATEWAY_IP and dns_records(env)["controller"] == "192.168.50.68"


    def test_interrupted_apply_resumes_without_rewriting_an_already_written_gateway(self):
        env = self.env
        routes = env.routes()
        plan = routes.plan({"action": "create", "hostname": "comfy", "workload_id": "comfyui", "endpoint_id": "http",
                            "expected_revision": routes.list()["revision"]})
        original = env.manager.refresh_apply

        def crash_after_write(plan_id, *, approved, request_id):
            original(plan_id, approved=approved, request_id=request_id)
            raise KeyboardInterrupt  # the broker process dies after the gateway refresh was recorded

        env.manager.refresh_apply = crash_after_write
        with self.assertRaises(KeyboardInterrupt):
            routes.apply(plan["id"], approved=True, request_id="crash")
        env.manager.refresh_apply = original
        listed = routes.list()
        assert listed["pending"]["status"] == "interrupted" and listed["pending"]["completed"] == []
        assert [item["hostname"] for item in listed["routes"]] == ["chat.example.test"]
        env.events.clear()
        resume = routes.plan({"action": "resume", "expected_revision": listed["revision"]})
        assert [stage["id"] for stage in resume["stages"]] == ["caddy-prepare", "verify-prepare", "dns"]
        assert any("verified, not written again" in warning for warning in resume["warnings"])
        result = routes.apply(resume["id"], approved=True, request_id="resume")
        assert result["status"] == "succeeded" and result["stages"][0]["status"] == "already"
        assert not any(e == ("refresh-plan", "lan-web") for e in env.events)
        assert ("probe", ("chat.example.test", "comfy.example.test")) in env.events


    def test_running_change_is_serialized_by_the_local_lock(self):
        env = self.env
        routes = env.routes()
        plan = routes.plan({"action": "create", "hostname": "comfy", "workload_id": "comfyui", "endpoint_id": "http",
                            "expected_revision": routes.list()["revision"]})
        fd = os.open(routes.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            with self.assertRaisesRegex(ValueError, "Another LAN route change"):
                routes.apply(plan["id"], approved=True, request_id="busy")
        finally:
            os.close(fd)
        assert env.events == []
        assert routes.apply(plan["id"], approved=True, request_id="free")["status"] == "succeeded"


    def test_time_budget_stops_between_stages_and_resume_finishes(self):
        env = self.env
        clock = iter([0, 0, 800, 800, 800])  # start, before stage 1, before stage 2 (the probe no longer fits)
        self.enterContext(patch.object(lan_routes, "time", SimpleNamespace(monotonic=lambda: next(clock))))
        plan, result = publish(env, "comfy", "comfyui")
        assert result["status"] == "partial" and "Time budget" in result["error"]
        assert [stage["stage"] for stage in result["stages"]] == ["caddy-prepare"]
        self.enterContext(patch.object(lan_routes, "time", SimpleNamespace(monotonic=lambda: 0)))
        routes = env.routes()
        resume = routes.plan({"action": "resume", "expected_revision": routes.list()["revision"]})
        assert routes.apply(resume["id"], approved=True, request_id="rest")["status"] == "succeeded"


    def test_long_request_ids_derive_valid_stage_ids(self):
        env = self.env
        plan, result = publish(env, "comfy", "comfyui", request_id="r" * 128)
        assert result["status"] == "succeeded"


    def test_plan_input_is_strict(self):
        env = self.env
        routes = env.routes()
        revision = routes.list()["revision"]
        with self.assertRaisesRegex(ValueError, "Unexpected field"):
            routes.plan({"action": "delete", "current_hostname": "chat", "address": "192.168.50.1", "expected_revision": revision})
        with self.assertRaisesRegex(ValueError, "No publishable endpoint"):
            routes.plan({"action": "create", "hostname": "x", "workload_id": "nope", "endpoint_id": "http",
                         "expected_revision": revision})
        with self.assertRaisesRegex(ValueError, "already published"):
            routes.plan({"action": "create", "hostname": "chat", "workload_id": "comfyui", "endpoint_id": "http",
                         "expected_revision": revision})
        with self.assertRaisesRegex(ValueError, "No pending"):
            routes.plan({"action": "resume", "expected_revision": revision})
        with self.assertRaisesRegex(ValueError, "Nothing changes"):
            routes.plan({"action": "update", "current_hostname": "chat", "hostname": "chat", "workload_id": "open-webui",
                         "endpoint_id": "http", "expected_revision": revision})


class DnsRoutesTests(unittest.TestCase):
    def setUp(self):
        self.env = make_env(Path(self.enterContext(TemporaryDirectory())), self)
        self.routes = self.env.routes()
        self.revision = self.routes.list()["revision"]

    def plan(self, action, **values):
        return self.routes.plan({"action": action, "expected_revision": state(self.env)["revision"], **values})

    def apply(self, action, **values):
        plan = self.plan(action, **values)
        self.assertTrue(plan["executable"], plan["blockers"])
        self.assertIsNone(plan["gateway"])
        self.assertEqual([stage["id"] for stage in plan["stages"]], ["dns"])
        self.assertEqual([change["target"] for change in plan["changes"]], ["DNS lan-dns records"])
        result = self.routes.apply(plan["id"], approved=True, request_id=uuid.uuid4().hex)
        self.assertEqual(result["status"], "succeeded", result.get("error"))
        return plan, result

    def add_verified_host(self, host_id="host-d", hostname="gaming-pc", address="192.168.50.143"):
        self.env.manager.hosts.append({"id": host_id,
                                      "collector": {"transport": "ssh", "target": "operator@" + address,
                                                    "expected_hostname": hostname},
                                      "verification": {"state": "verified"}})

    def test_listing_uses_dns_application_and_registry_excluding_url_names(self):
        self.add_verified_host()
        listed = self.routes.list()
        self.assertTrue(listed["dns_ready"])
        records = {record["hostname"]: record for record in listed["dns_records"]}
        self.assertNotIn("chat.example.test", records)
        self.assertEqual(records["printer.example.test"],
                         {"hostname": "printer.example.test", "address": "192.168.50.50", "source": "manual"})
        for hostname in ("host-d", "gaming-pc"):
            self.assertEqual(records[hostname + ".example.test"],
                             {"hostname": hostname + ".example.test", "address": "192.168.50.143",
                              "source": "registry", "host_id": "host-d"})
        app = dns_app(dns_records(self.env) | {"new-alias": "2001:db8::1"})
        write_instance(self.env.manager.store, app, revision_bump=True)
        self.assertIn("new-alias.example.test", {row["hostname"] for row in self.routes.list()["dns_records"]})
        self.assertNotIn("dns_records", state(self.env))  # no second authority
        self.assertEqual(self.env.events, [])

    def test_create_edit_rename_remove_refresh_dns_only_and_verify_addresses(self):
        original = gateway_text(self.env)
        self.apply("dns-create", hostname="console", address="192.168.50.60")
        self.assertEqual(self.env.probes["dns_checks"][-1], ({"console": "192.168.50.60"}, []))
        self.apply("dns-update", current_hostname="console", hostname="console", address="2001:db8::60")
        self.assertEqual(self.env.probes["dns_checks"][-1], ({"console": "2001:db8::60"}, []))
        self.apply("dns-update", current_hostname="console", hostname="CONSOLE-V6.EXAMPLE.TEST.", address="2001:db8::60")
        self.assertEqual(self.env.probes["dns_checks"][-1], ({"console-v6": "2001:db8::60"}, ["console"]))
        self.apply("dns-delete", current_hostname="console-v6")
        self.assertEqual(self.env.probes["dns_checks"][-1], ({}, ["console-v6"]))
        self.assertEqual(dns_records(self.env), {"chat": GATEWAY_IP, "controller": "192.168.50.68", "printer": "192.168.50.50"})
        self.assertEqual(gateway_text(self.env), original)
        self.assertEqual([item["hostname"] for item in state(self.env)["routes"]], ["chat.example.test"])
        self.assertIsNone(state(self.env)["pending"])
        self.assertFalse(any(event[0] in ("caddy", "probe") or event == ("refresh-plan", "lan-web")
                             for event in self.env.events))

    def test_dns_ready_and_changes_do_not_depend_on_absent_or_drifted_caddy(self):
        write_instance(self.env.manager.store, gateway_app("outside registry\n"), revision_bump=True)
        self.assertTrue(self.routes.list()["dns_ready"])
        self.apply("dns-create", hostname="alias", address="192.168.50.61")
        with self.env.manager.store.transaction() as db:
            db.execute("DELETE FROM placements WHERE instance_id='lan-web'")
        listed = self.routes.list()
        self.assertTrue(listed["dns_ready"])
        self.assertFalse(listed["ready"])
        self.apply("dns-delete", current_hostname="alias")
        self.assertFalse(any(event[0] in ("caddy", "probe") for event in self.env.events))

    def test_dns_planning_apply_and_replay_never_read_gateway_after_adoption(self):
        original = self.env.manager.store.instance_row

        def instance_row(db, instance_id):
            if instance_id == "lan-web":
                raise AssertionError("DNS-only operation read Caddy")
            return original(db, instance_id)

        with patch.object(self.env.manager.store, "instance_row", side_effect=instance_row):
            plan = self.plan("dns-create", hostname="alias", address="192.168.50.61")
            result = self.routes.apply(plan["id"], approved=True, request_id="no-caddy")
            self.assertEqual(result["status"], "succeeded")
            replay = self.routes.apply(plan["id"], approved=True, request_id="no-caddy")
            self.assertTrue(replay["replayed"])

    def test_url_and_registry_names_are_reserved_for_dns_mutations(self):
        self.add_verified_host()
        for hostname in ("chat", "host-b", "host-d", "gaming-pc"):
            with self.subTest(hostname=hostname):
                # URL-owned explicit records cannot be edited/deleted through DNS either.
                if hostname == "chat":
                    for action, fields in (("dns-delete", {"current_hostname": hostname}),
                                           ("dns-update", {"current_hostname": hostname, "hostname": "other",
                                                           "address": "192.168.50.80"})):
                        plan = self.plan(action, **fields)
                        self.assertFalse(plan["executable"])
                        self.assertTrue(any("published LAN URL" in blocker for blocker in plan["blockers"]))
                else:
                    plan = self.plan("dns-create", hostname=hostname, address="192.168.50.80")
                    self.assertFalse(plan["executable"])
                    self.assertTrue(any("registry host" in blocker for blocker in plan["blockers"]))
                    with self.assertRaisesRegex(ValueError, "No standalone manual"):
                        self.plan("dns-delete", current_hostname=hostname)
        self.assertEqual(self.env.events, [])

    def test_url_plans_reject_verified_actual_hostname_aliases(self):
        self.add_verified_host()
        plan = self.routes.plan({"action": "create", "hostname": "gaming-pc", "workload_id": "comfyui",
                                 "endpoint_id": "http", "expected_revision": self.revision})
        self.assertFalse(plan["executable"])
        self.assertTrue(any("registry host" in blocker for blocker in plan["blockers"]))
        self.assertEqual(self.env.events, [])

    def test_dns_inputs_require_canonical_ipv4_or_ipv6_and_known_manual_record(self):
        for address in (None, 123, "host.local", "192.168.050.3", " 192.168.50.3", "2001:0db8::1", "2001:DB8::1",
                        "192.168.50.2/24", ""):
            with self.subTest(address=address), self.assertRaisesRegex(ValueError, "canonical IPv4/IPv6"):
                self.plan("dns-create", hostname="alias", address=address)
        with self.assertRaisesRegex(ValueError, "already has a manual"):
            self.plan("dns-create", hostname="printer", address="192.168.50.80")
        with self.assertRaisesRegex(ValueError, "already has a manual"):
            self.plan("dns-update", current_hostname="printer", hostname="controller", address="192.168.50.80")
        with self.assertRaisesRegex(ValueError, "No standalone manual"):
            self.plan("dns-update", current_hostname="missing", hostname="alias", address="192.168.50.80")
        with self.assertRaisesRegex(ValueError, "Nothing changes"):
            self.plan("dns-update", current_hostname="printer", hostname="printer", address="192.168.50.50")
        with self.assertRaisesRegex(ValueError, "Unexpected field"):
            self.plan("dns-delete", current_hostname="printer", address="192.168.50.80")
        with self.assertRaisesRegex(ValueError, "outside zone"):
            self.plan("dns-create", hostname="outside.example", address="192.168.50.80")
        self.assertEqual(self.env.events, [])

    def test_dns_and_urls_share_revision_approval_and_lock(self):
        dns_plan = self.plan("dns-create", hostname="alias", address="192.168.50.80")
        url_plan = self.routes.plan({"action": "create", "hostname": "images", "workload_id": "comfyui",
                                     "endpoint_id": "http", "expected_revision": self.revision})
        with self.assertRaisesRegex(ValueError, "explicit approval"):
            self.routes.apply(dns_plan["id"], approved=False, request_id="unapproved")
        fd = os.open(self.routes.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            with self.assertRaisesRegex(ValueError, "Another LAN route change"):
                self.routes.apply(dns_plan["id"], approved=True, request_id="busy")
        finally:
            os.close(fd)
        self.assertEqual(self.env.events, [])
        self.assertEqual(self.routes.apply(dns_plan["id"], approved=True, request_id="dns")["status"], "succeeded")
        count = len(self.env.events)
        with self.assertRaisesRegex(ValueError, "changed since planning"):
            self.routes.apply(url_plan["id"], approved=True, request_id="stale-url")
        with self.assertRaisesRegex(ValueError, "changed since you looked"):
            self.routes.plan({"action": "dns-delete", "current_hostname": "alias", "expected_revision": self.revision})
        another = self.plan("dns-delete", current_hostname="alias")
        publish(self.env, "images", "comfyui", request_id="url")
        count = len(self.env.events)
        with self.assertRaisesRegex(ValueError, "changed since planning"):
            self.routes.apply(another["id"], approved=True, request_id="stale-dns")
        self.assertEqual(len(self.env.events), count)

    def test_registry_and_dns_drift_between_plan_and_apply_are_rechecked(self):
        dns_plan = self.plan("dns-create", hostname="gaming-pc", address="192.168.50.80")
        url_plan = self.routes.plan({"action": "create", "hostname": "gaming-pc", "workload_id": "comfyui",
                                     "endpoint_id": "http", "expected_revision": self.revision})
        self.add_verified_host()
        for plan in (dns_plan, url_plan):
            with self.subTest(action=plan["action"]), self.assertRaisesRegex(ValueError, "registry host"):
                self.routes.apply(plan["id"], approved=True, request_id=plan["action"])
        fresh = self.plan("dns-create", hostname="alias", address="192.168.50.80")
        write_instance(self.env.manager.store, dns_app(dns_records(self.env) | {"alias": "192.168.50.81"}), revision_bump=True)
        with self.assertRaisesRegex(ValueError, "DNS instance or placement changed"):
            self.routes.apply(fresh["id"], approved=True, request_id="dns-drift")
        self.assertEqual(self.env.events, [])

    def test_dns_verification_failure_blocks_other_changes_and_resumes_without_rewrite(self):
        self.env.probes["dns_fail"] = "UDP/TCP answers differ"
        plan = self.plan("dns-update", current_hostname="printer", hostname="printer", address="2001:db8::50")
        result = self.routes.apply(plan["id"], approved=True, request_id="dns-fail")
        self.assertEqual(result["status"], "partial")
        self.assertIn("UDP/TCP answers differ", result["error"])
        self.assertEqual(dns_records(self.env)["printer"], "2001:db8::50")
        self.assertEqual(self.routes.list()["pending"]["remaining"], ["dns"])
        for action, values in (("dns-create", {"hostname": "other", "address": "192.168.50.80"}),
                               ("delete", {"current_hostname": "chat"})):
            with self.assertRaisesRegex(ValueError, "pending"):
                self.plan(action, **values)
        self.env.probes["dns_fail"] = None
        self.env.events.clear()
        original = self.env.manager.store.instance_row

        def no_caddy(db, instance_id):
            if instance_id == "lan-web":
                raise AssertionError("DNS resume read Caddy")
            return original(db, instance_id)

        with patch.object(self.env.manager.store, "instance_row", side_effect=no_caddy):
            resume = self.plan("resume")
            done = self.routes.apply(resume["id"], approved=True, request_id="dns-resume")
        self.assertEqual(done["status"], "succeeded")
        self.assertEqual(self.env.events, [("dns-check", ("printer",), ())])
        self.assertEqual(done["stages"][0]["status"], "already")

    def test_interrupted_dns_write_resumes_without_second_refresh(self):
        plan = self.plan("dns-create", hostname="alias", address="192.168.50.80")
        original = self.env.manager.refresh_apply

        def crash_after_write(plan_id, *, approved, request_id):
            original(plan_id, approved=approved, request_id=request_id)
            raise KeyboardInterrupt

        self.env.manager.refresh_apply = crash_after_write
        with self.assertRaises(KeyboardInterrupt):
            self.routes.apply(plan["id"], approved=True, request_id="dns-crash")
        self.env.manager.refresh_apply = original
        self.assertEqual(self.routes.list()["pending"]["status"], "interrupted")
        self.assertEqual(dns_records(self.env)["alias"], "192.168.50.80")
        self.env.events.clear()
        resume = self.plan("resume")
        done = self.routes.apply(resume["id"], approved=True, request_id="dns-after-crash")
        self.assertEqual(done["status"], "succeeded")
        self.assertEqual(self.env.events, [("dns-check", ("alias",), ())])

    def test_delete_or_rename_explicit_override_verifies_revealed_registry_record(self):
        for action in ("dns-delete", "dns-update"):
            with self.subTest(action=action):
                self.add_verified_host(host_id="printer-host-" + action, hostname="printer", address="192.168.50.99")
                if action == "dns-update":
                    # Restore an explicit override, as a preexisting application can contain one.
                    write_instance(self.env.manager.store, dns_app(dns_records(self.env) | {"printer": "192.168.50.50"}),
                                   revision_bump=True)
                    self.env.manager.hosts.pop(-2)  # keep the hostname unambiguous
                fields = {"current_hostname": "printer"}
                if action == "dns-update":
                    fields.update(hostname="printer-alias", address="192.168.50.50")
                plan = self.plan(action, **fields)
                self.assertTrue(plan["executable"], plan["blockers"])
                self.assertEqual(plan["stages"][0]["answers"]["printer"], "192.168.50.99")
                result = self.routes.apply(plan["id"], approved=True, request_id=action)
                self.assertEqual(result["status"], "succeeded", result.get("error"))
                answers, removed = self.env.probes["dns_checks"][-1]
                self.assertEqual(answers["printer"], "192.168.50.99")
                self.assertNotIn("printer", removed)
                self.assertNotIn("printer", dns_records(self.env))

    def test_registry_fallback_drift_is_refused_before_apply(self):
        self.add_verified_host(hostname="printer", address="192.168.50.99")
        plan = self.plan("dns-delete", current_hostname="printer")
        self.env.manager.hosts[-1]["collector"]["target"] = "operator@192.168.50.100"
        with self.assertRaisesRegex(ValueError, "Registry DNS answers changed"):
            self.routes.apply(plan["id"], approved=True, request_id="fallback-drift")
        self.assertEqual(self.env.events, [])

    def test_unconfirmed_dns_and_outstanding_deploy_plans_block_dns_changes(self):
        with self.env.manager.store.transaction() as db:
            db.execute("UPDATE placements SET state='fenced' WHERE instance_id='lan-dns'")
        self.assertFalse(self.routes.list()["dns_ready"])
        plan = self.plan("dns-delete", current_hostname="printer")
        self.assertFalse(plan["executable"])
        self.assertTrue(any("not confirmed active" in blocker for blocker in plan["blockers"]))
        with self.env.manager.store.transaction() as db:
            db.execute("UPDATE placements SET state='active' WHERE instance_id='lan-dns'")
        self.env.manager.refresh_plan("lan-dns", add_records={"unrelated": "192.168.50.81"}, request_id="other-inspect")
        plan = self.plan("dns-delete", current_hostname="printer")
        self.assertFalse(plan["executable"])
        self.assertTrue(any("reserves lan-dns" in blocker for blocker in plan["blockers"]))
