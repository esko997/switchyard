# Architecture and integration boundaries

## Decisions

- One management model, explicit native backends; no universal host agent requirement.
- Discovery, named definitions, registration, placement and lifecycle authority are separate.
- Native supervisors own startup, restart and health behavior. Switchyard adds policy, evidence, approvals and receipts, not a second reconciliation loop.
- Migration means service-specific stop/transfer/restart, not live process migration.
- Web, CLI and MCP share the same service and policy boundary. Unrestricted shell is intentional, separately authorized and not sandboxed.
- Reads and streams use cache; explicit observation and approved operations contact configured devices under canonical leases.

## Current implementation

Hosts live in a revisioned registry; named workloads, registered application bundles and deployed instances share the [workload store](domain-model.md#the-workload-store). The catalog is a one-time seed, not a second authority. Edits are compare-and-swap; long-lived consumers refresh validated records. Descriptive edits grant no execution rights.

The [observation contract](observation-contract.md) keeps native resources, installed artifacts, environments and named workload definitions distinct. Each scope/resource has its own timestamp and coverage. Failed or omitted scopes retain older evidence. Unknown, unreachable and stale never mean stopped or healthy.

An explicitly started monitor holds one local leader lock and dispatches at most two bounded Linux collectors. Fast/storage/inventory lanes have independent cooldowns and release device leases between samples. Android is manual. HTTP/SSE reads cannot start a monitor or trigger probes.

[LedgerBroker and agent leases](access.md) hold the same canonical inode across complete bounded transport lifetimes. Hostname and SSH-key verification bind access to a declared host. Other machines request gateway-held leases; local flock is not distributed fencing.

Existing-service control uses small native adapters: `systemd_remote` for exact systemd/Quadlet services, `compose_remote` for complete local Compose projects. Fresh inspection-bound start/stop/restart preserves the native manager as owner. These adapters do not deploy or migrate.

The [deploy adapter](deploy.md) creates rootless Podman/Quadlet workloads from stored templates, with ownership labels, port claims, generation gates, health checks and explicit undeploy/upgrades. [Registered applications](spec/workload.md#registration-of-adopted-applications) remain metadata only; their separately authorized [start tokens](tokens.md) do not install gates or stop running processes.

The operation journal persists intent before effects and receipts afterwards. Plans bind grants and input hashes; request IDs deduplicate results. Lost or interrupted effects require inspection. Removing authority does not erase placement or receipts.

Runtime dependencies use uv; MCP uses the official SDK. The UI is static HTML/CSS/JS with bundled fonts and no frontend build step. The stdlib HTTP server is intended for trusted local/LAN use with the documented [authentication boundary](auth.md), not arbitrary Internet exposure.

## Cold migration

The fictional Compose planner is offline. A separate static-web executor supports only the narrow disposable Foobar recipe; see [rehearsal requirements](disposable-workload.md). It does not establish database consistency, writable-data reconciliation or automatic traffic routing.

Before implementing another recipe:

1. Review exact identities, platform/architecture, dependencies, capacity, artifacts and secret references.
2. Acquire source/destination resources in stable order and approve the concrete plan.
3. Quiesce writers and activators, fence/stop the source and verify it stopped. Unreachable is not stopped.
4. Capture an application-consistent snapshot; verify restore, transfer hashes and ownership.
5. Start the destination isolated from writes where possible; verify service-specific health and data invariants.
6. Publish endpoints explicitly, retaining the fenced source and verified recovery material.
7. Before destination writes, recovery can return to an unchanged source only after proving the destination inactive. Afterwards require explicit reconciliation/reverse transfer, never automatic failback to stale data.

ABI/endianness differences need portable application exports and compatible artifacts. Token files cannot prevent an out-of-band restore from reviving old authority; verification is detection on contact, not a distributed fence.

## Adapter boundaries

| Backend | Observation | Mutation prerequisites |
|---|---|---|
| Linux SSH/systemd | Allowlisted units and attributed resource readings | Canonical lease, pinned host identity, exact lifecycle grant |
| Podman/Docker/Compose | Scoped runtime metadata, no environment or logs | Verified complete ownership, provider support and approved native action |
| Android SDK ADB | Configured USB serial, selected profile/packages/process evidence | Separate reviewed operation; no UI interaction by default |
| Legacy Unix/console | Actual OS, architecture, firmware and transport capabilities | OS-specific adapter and compatible artifacts; never assume systemd/Python |
| Kubernetes/Nomad | Future scoped inventory | Explicit adoption; orchestrator retains reconciliation ownership |
| Printer/appliance | Future model-specific identity and job telemetry | Separate physical-action permission; no interrupt by default |

A running print is not cold-migratable. Installed Android packages do not prove running processes, application health, data portability or update permission. Legacy cryptography, if unavoidable, needs isolated per-host policy, never a global downgrade.

## Product views and progressive disclosure

The desk presents named workloads first, hosts and resources second, then technical evidence and receipts through expandable detail. The yard diagram shows placement without pretending declarations are observations. Preserve filters, open detail and drafts during cache updates.

Reachability, native lifecycle, application health, management relation, authority and freshness are separate axes. Unknown/stale state and safety-critical blockers stay visible; raw payloads do not dominate the landing page. Device capacity, measured availability and operator placement budgets are distinct; shared storage and unified GPU memory cannot be counted twice.

Use plain-language state labels, keyboard-accessible controls and responsive rows. Blue denotes authority, not health. Remote metadata is untrusted text; never insert it as markup. See [domain model](domain-model.md) and [roadmap](roadmap.md).
