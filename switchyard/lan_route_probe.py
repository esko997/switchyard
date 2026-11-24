"""Verify routed HTTPS and DNS using leased, read-only deployment operations."""
import uuid

from .lan_route_config import probe_value

PROBE_SECONDS = 90


def verify_proxy(service, config, gateway_ip, gateway_host, routes):
    probes = {item["hostname"]: probe_value(item) for item in routes}
    return _run(service, "lan-route-probe", config["gateway_id"], gateway_host,
                {"address": gateway_ip, "ca_sha256": config["ca_sha256"], "probes": probes})


def verify_dns(service, config, host_id, added, removed):
    zone = config["zone"]
    records = {f"{name}.{zone}": address for name, address in added.items()}
    records.update({f"{name}.{zone}": None for name in removed})
    return _run(service, "lan-dns-probe", config["dns_id"], host_id, {"zone": zone, "records": records})


def _run(service, action, identity, host_id, probe):
    manager = service.deployments()
    authority = manager.broker._enabled()
    fingerprint = manager._authority(authority, host_id)
    with manager.store.reading() as db:
        row = manager.store.placement_row(db, identity)
    if row is None or row["host_id"] != host_id or row["state"] != "active":
        raise ValueError("LAN service placement changed or is not active")
    nonce = uuid.uuid4().hex
    intent = {"kind": "deploy", "action": action, "instance_id": identity, "nonce": nonce}
    request = {"action": action, "instance_id": identity, "host_id": host_id,
               "generation": row["generation"], "placement_revision": row["revision"], "probe": probe,
               **manager._request_common(authority, host_id, fingerprint)}
    return manager._run(action + "-" + nonce, intent, host_id, request, authority, worker_seconds=PROBE_SECONDS)
