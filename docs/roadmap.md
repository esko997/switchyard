# Roadmap and design boundaries

This is a design reference, not permission to inspect or change devices. Current interfaces are documented in [the README](../README.md).

## Ownership levels

| Relation | Meaning | Possible separately authorized actions |
|---|---|---|
| Discovered resource | Native evidence, not a workload definition | Observation only |
| Observed workload | Named binding to existing native resources | Inspect/start/stop/restart through a supported lifecycle adapter |
| Registered application | Owner-supplied metadata bundle | Separately granted start tokens; registration itself changes no host |
| Deployed workload | Switchyard-created instance with ownership ID and journaled placement | Deployment lifecycle, explicit upgrade and owned-resource undeploy |

A host is where a workload runs; its manager is who may change it. Never introduce a second owner or delete resources Switchyard did not create. Ownership conversion requires its own reviewed handoff.

## Existing foundations

- Revisioned host registry with pinned SSH identity and explicit verification after connection edits.
- One workload store for observed, registered and deployed records.
- Cached Linux/Android observation, scoped freshness and an independently launched Linux monitor.
- Explicit systemd, Quadlet and complete Compose lifecycle adapters.
- Rootless Podman/Quadlet deployment, port registry, generation gates, verification, explicit template upgrades and retained generation history.
- Canonical device leases, remote SSH clients and reduced remote MCP.
- Single-operator HTTPS authentication, scoped enrollment and revocation.
- Operator-owned Ansible registration, check-mode planning, approved apply and receipts.
- Opt-in LAN DNS/proxy publication with preview and verification.

See [architecture](architecture.md), [workload spec](spec/workload.md), [deploy](deploy.md), [auth](auth.md) and [Ansible](ansible.md) for the actual limits. These are capabilities, not a claim that any specific installation has been verified.

## Further work and acceptance gates

1. **Broader service-specific migration:** prove quiescence, snapshot/restore, data ownership, credential handling and recovery for each service; do not generalize the static-page rehearsal to databases.
2. **Durable single-active enforcement:** test reboot/manual paths, token restores, partitioned or returning sources, journal loss and credential reissue. Local files alone provide detection on contact, not prevention of stale actors.
3. **Ownership conversion:** capture reproducible native sources/artifacts and a verified create/restore/remove contract; journal an explicit identity handoff without recreating live resources implicitly.
4. **More backend coverage:** add Android artifact delivery or legacy Unix/appliance adapters only with exact identity, supported interfaces and separate mutation permission. Never equate physical jobs with migratable server processes.
5. **Runtime subset validation:** maintain an explicit version-tested Podman subset; unsupported native controls must block rather than be ignored.
6. **Operator experience:** preserve concise views, keyboard/mobile access, visible uncertainty and shared CLI/web/MCP policy; avoid a scheduler or enterprise identity platform without an actual need.

Kubernetes notation is useful without requiring a cluster. A future orchestrator backend must retain ownership of its native reconciliation. Native systemd remains appropriate for workloads that need it; no universal container or agent requirement is imposed.
