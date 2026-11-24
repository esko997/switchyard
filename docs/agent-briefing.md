# Switchyard briefing for agents

Read [the quickstart](../README.md), [architecture](architecture.md) and the operator's current policy before acting. The bundled catalog is fictional and grants no permission to contact or mutate a real device.

## Concepts

- **Host:** a stable registry identity with timestamped observations. Unknown data stays unknown, never zero.
- **Native resource:** a unit, container, package or process observed on a host. Discovery is not adoption.
- **Workload:** one revisioned store record, related as `observed`, `registered` or `deployed`. Naming or registering it grants no control.
- **Authority:** a separate operator-owned operations policy, scoped to capabilities, workloads and hosts.
- **Operation:** inspection, expiring plan, approval, leased execution and durable receipt. Unknown outcomes require inspection, not retry.
- **Cold migration:** service-specific stop/transfer/restart with explicit data, consistency, artifacts, health and recovery boundaries; not live migration.

## Offline interface

From the checkout, these commands use declarations or cache rather than contacting hosts:

```sh
uv run --locked switchyard --catalog catalogs/example.json inventory
uv run --locked switchyard --catalog catalogs/example.json fleet
uv run --locked switchyard --catalog catalogs/example.json definitions
uv run --locked switchyard --catalog catalogs/example.json store status
uv run --locked switchyard --catalog catalogs/example.json operations
uv run --locked switchyard --catalog catalogs/example.json plan-migration foobar destination
```

The first use of a state namespace may seed local databases. GET fleet/API reads and SSE are cache-only; an explicit collection is a different operation. The stdio MCP server uses the same service; remote mode intentionally exposes reads and leases only.

Do not run collection, monitoring, inspections, shell, key changes, definition saves, deployment or lifecycle commands without current authorization for that scope. A checked-in example, old receipt or this briefing is not an execution grant.

## Device access

Use the designated control host's lease API, never files copied into a checkout.
Use `switchyard lease run` for one command or `hold`/`release` across steps.
Release the exact ID once work is confirmed complete. Busy, suspect or blocked
means defer, not bypass. Only the human operator may attest that uncertain
work stopped and clear the reservation. Do not hold device leases while building.

Android needs a configured immutable USB serial and SDK root (`ANDROID_HOME`, then `ANDROID_SDK_ROOT`, then `~/Android/Sdk`). Use that SDK's `platform-tools/adb` with exact serial and disconnected stdin in scripts. Do not start/restart the server, connect wireless transports, wake a device or send input as part of observation.

Report limitations explicitly: native running is not healthy; installed is not running; unreachable is not stopped; local leases are not runtime fences; restored generation tokens can reopen start paths until verification detects them. See [access](access.md), [remote agents](remote-agents.md) and [deployment](deploy.md).
