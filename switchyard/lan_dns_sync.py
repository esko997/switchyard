"""Project host registry names into the LAN DNS deployment without touching Caddy."""
import uuid

from . import deploy_config
from .lan_routes import META_KEY
from .workload_store import WorkloadStore


def reconcile(service, *, dry_run=False):
    routes = service.lan_routes()
    if routes is None:
        return {"status": "disabled"}
    if dry_run:
        return _reconcile(routes, dry_run=True)
    with routes._locked():
        return _reconcile(routes, dry_run=False)


def _reconcile(routes, *, dry_run):
    manager = routes.manager
    instance_id, zone = routes.config["dns_id"], routes.config["zone"]
    with routes.store.reading() as db:
        state = WorkloadStore.meta(db, META_KEY)
        instance = routes.store.instance_row(db, instance_id)
        placement = routes.store.placement_row(db, instance_id)
    if not instance or not placement or placement["state"] == "retired":
        return {"status": "deferred", "reason": "No current LAN DNS deployment"}
    if state and state.get("pending"):
        return {"status": "deferred", "reason": "A LAN URLs change is pending"}
    if placement["state"] != "active" or any(placement["meta"].get(key) for key in ("pending", "uncertain")):
        return {"status": "deferred", "reason": "LAN DNS has no confirmed active placement"}
    if instance["template_ref"]["id"] != "coredns-lan":
        raise ValueError("Automatic LAN DNS requires a coredns-lan deployment")
    app = instance["application"]
    file = deploy_config.generator_file(app)
    text, projection = deploy_config.render_registry_hosts(file["generator"], deploy_config.parameter_values(app),
                                                           manager._registry())
    if projection["zone"] != zone or file["on_change"] != "none":
        raise ValueError("Automatic LAN DNS requires the configured zone and a hot-reloadable hosts file")
    desired = deploy_config.sha(text)
    recorded = next((item["sha256"] for item in placement["meta"]["native"].get("config", [])
                     if item["name"] == file["path"]), None)
    if recorded is None:
        raise ValueError("LAN DNS has no journaled hosts file; verify the deployment")
    result = {"instance_id": instance_id, "host_id": placement["host_id"], "sha256": desired}
    if dry_run:
        return {"status": "preview", "changed": desired != recorded, **result, **projection}
    if desired == recorded:
        return {"status": "unchanged", **result}

    request_id = "lan-host-dns-" + uuid.uuid4().hex
    plan = manager.refresh_plan(instance_id, expected_instance_revision=instance["revision"],
                                request_id=request_id + ".inspect")
    if not plan["executable"]:
        raise ValueError("Automatic LAN DNS refresh refused: " + ", ".join(plan["blockers"]))
    writes = [(item["id"], item["sha256"]) for item in plan["changes"] if item["change"] == "update"]
    if writes != [(file["id"], desired)] or plan["restart"] or plan["application_changed"]:
        routes._discard(plan["id"])
        raise ValueError("LAN DNS changed while planning or would update more than the generated hosts file")
    detail = {"receipts": []}
    routes._refresh(plan, file["id"], request_id, detail)
    return {"status": "refreshed", **result, "receipts": detail["receipts"], "skipped": projection["skipped"]}
