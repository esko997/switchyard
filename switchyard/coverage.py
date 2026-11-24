"""Cached integration coverage: configured authority is not verification."""


def _coverage_status(records):
    if not records:
        return "configured", "No observations in this scope yet."
    if any(item.get("freshness") != "fresh" for item in records):
        return "stale", "Some scope evidence is missing or stale; inspect individual timestamps."
    if any(item.get("status") != "complete" for item in records):
        return "partial", "Some readings are unavailable; inspect scope coverage."
    return "verified", "Configured scope observed; this does not establish application health."


def host_integration(host, collector, *, shell_hosts, managed_workloads, key_state):
    """Summarize the host view without I/O, inferred grants or invented capability."""
    identity = host["id"]
    observation = host.get("observation", {})
    snapshot = observation.get("snapshot")
    fresh = observation.get("freshness") == "fresh"
    attempt = observation.get("last_attempt") or {}
    scopes = host.get("coverage", [])
    items = []

    def add(key, label, status, detail):
        items.append({"id": key, "label": label, "status": status, "detail": detail})

    if snapshot:
        add("identity", "Identity", "verified" if fresh else "stale",
            "Collector-verified host identity; retained evidence is not current reachability.")
    else:
        add("identity", "Identity", "configured" if collector else "unconfigured",
            "Declared identity has not been verified by this collector configuration.")

    if not collector:
        add("access", "Observation access", "unconfigured", host.get("notes") or "No approved collector configured.")
    elif attempt.get("status") in {"error", "busy"}:
        add("access", "Observation access", "blocked", attempt.get("message") or
            "Latest attempt failed or its lease was busy; this does not prove the host is off.")
    elif snapshot and fresh:
        add("access", "Observation access", "verified", "Recent bounded observation using " + collector["transport"] + ".")
    else:
        add("access", "Observation access", "stale" if snapshot else "configured",
            "Access configured; no recent successful observation. No wakeup or connection repair is automatic.")

    resource_scopes = [record for record in scopes if record.get("scope") in {"cpu", "memory", "gpus", "storage"}]
    if collector:
        status, detail = _coverage_status(resource_scopes)
        if status == "verified" and len({r["scope"] for r in resource_scopes}) < 4:
            status, detail = "partial", "Some resource scopes have not been observed."
        add("resources", "Resource telemetry", status, detail + " Sampled availability is not placement permission.")
    else:
        add("resources", "Resource telemetry", "unconfigured", "No resource collector configured; hardware declarations are not measurements.")

    if collector:
        discovery = [record for record in scopes if record.get("scope", "").startswith(("systemd:", "podman:", "docker:", "android:", "android-package:"))]
        has_scope = bool(collector.get("packages") or collector.get("user_units") or
                         collector.get("system_units") or collector.get("container_engines"))
        if has_scope:
            status, detail = _coverage_status(discovery)
            add("discovery", "Workload discovery", status, detail + " Limited to configured runtimes, units or packages; not all processes.")
        else:
            add("discovery", "Workload discovery", "unconfigured", "Resource collector exists, but no workload discovery scope is selected.")
    else:
        add("discovery", "Workload discovery", "unconfigured", "No workload observer configured.")

    add("shell", "Brokered shell", "configured" if identity in shell_hosts else "unconfigured",
        "Explicit unrestricted shell requests are authorized; configuration does not prove current connectivity."
        if identity in shell_hosts else "No brokered shell authority granted; existing direct access is unaffected.")
    managed = [item for item in managed_workloads if identity in item.get("allowed_hosts", [])]
    for key, label, action in (("lifecycle", "Workload control", None), ("migration", "Cold migration", "migrate")):
        selected = [item for item in managed if action is None or action in item.get("actions", [])]
        if selected:
            add(key, label, "configured", "Explicit approval only for: " + ", ".join(item["id"] for item in selected) +
                ". Other discovered or defined workloads are not adopted.")
        else:
            add(key, label, "unconfigured", "No authorized service-specific operation recipe. Definition is not lifecycle permission.")

    key_host = next((item for item in key_state.get("hosts", []) if item.get("host_id") == identity), None)
    if key_host:
        status = key_host.get("status", "unknown")
        mapped = {"verified": "verified", "pending": "partial", "conflict": "blocked", "unsupported": "unsupported"}
        add("fleet-keys", "Fleet SSH keys", mapped.get(status, "configured"),
            key_host.get("detail") or "Inspect key-management status and directed peer verification.")
    elif identity in key_state.get("allowed_hosts", []):
        add("fleet-keys", "Fleet SSH keys", "configured", "Eligible for explicit enrollment; no verified mesh membership yet.")
    elif host.get("platform") == "android":
        add("fleet-keys", "Fleet SSH keys", "unsupported", "Excluded from the Unix SSH trust group; use the device-specific gateway.")
    else:
        add("fleet-keys", "Fleet SSH keys", "unconfigured", "SSH key enrollment is not configured; compatible access and host identity are prerequisites.")

    if not collector:
        summary = "Inventory only · integration needed"
    elif any(item["status"] == "blocked" for item in items):
        summary = "Integration needs attention"
    elif not snapshot:
        summary = "Configured · awaiting observation"
    elif not fresh:
        summary = "Integrated observer · evidence stale"
    else:
        summary = "Observer active · control explicitly scoped"
    return {"summary": summary, "items": items}
