# Switchyard

One control desk for heterogeneous devices. Native services, containers and Android endpoints share an inventory and policy model, not an execution environment.

**Observation is the default; operations require separate authority and approval.** Switchyard wraps native supervisors rather than becoming a scheduler. There is no automatic failover or workload reconciliation. Page loads, streams and ordinary reads use cached evidence; they do not poll devices.

## Quickstart: offline example

Install Python 3.11+ and [uv](https://docs.astral.sh/uv/), then run from this checkout:

```sh
uv sync --locked
uv run --locked switchyard --catalog catalogs/example.json web
# Open http://127.0.0.1:8710
```

The tracked catalog is fictional: `source`, `destination`, a static-page workload `foobar`, and a user service `notes-sync`. No collector or operation policy is enabled by this command. The declared hosts need not exist, and unknown runtime state stays unknown.

In another terminal:

```sh
uv run --locked switchyard --catalog catalogs/example.json inventory
uv run --locked switchyard --catalog catalogs/example.json fleet
uv run --locked switchyard --catalog catalogs/example.json plan-migration foobar destination
```

The migration command produces an offline proposal with evidence gaps, not a runnable script. The nginx image tag in the example is unverified. Nothing is installed, contacted, started or stopped by these commands.

### Rootless Podman option

```sh
podman build --file Containerfile --tag localhost/switchyard:local .
tools/run-container.sh demo --image localhost/switchyard:local
# GET-only fictional desk: http://localhost:8710 (requires host slirp4netns)
```

The image packages Python 3.13 and locked dependencies; the build context is allowlisted and includes no private fleet configuration or state. The disposable demo mounts no host files. For a real control plane, [integrated container mode](docs/container.md) preserves canonical catalog/state/ledger paths and runs as the control user's UID with explicitly selected SSH, SDK and playbook mounts. It shares host PID/network and the systemd user bus: **packaging, not isolation**. Existing native CLI access, policies, approvals, leases and systemd timers remain in charge.

## Configure your own fleet

Keep private addresses, accounts, serials and policy in your own configuration, not the tracked examples:

```sh
cp catalogs/example.json catalogs/home-lab.json
cp catalogs/collectors.example.json catalogs/home-lab.collectors.json
cp catalogs/operations.example.json catalogs/home-lab.operations.json
cp catalogs/ansible.example.json catalogs/home-lab.ansible.json
```

The `catalogs/home-lab*.json` files are git-ignored. Review all four before enabling them. In particular, the operations example **grants authority** for shell, fleet keys, deployment and a named service; it is not required for observation.

The catalog's hosts and workloads seed private databases once. Afterwards the host registry and workload store are authoritative; editing the seed does not update them. The catalog's absolute path namespaces state, so keep that path stable. Use `hosts-export`/`hosts-import` for hosts and `export`/`import` for the store, with their revision checks.

State defaults below the XDG state root (`~/.local/state/switchyard` without an override); `--state-dir` selects another private directory. Use the same catalog, state and configuration for web, CLI and MCP consumers.

### Device lease authority

The control host's private state directory holds one `leases/leases.sqlite3`
for the whole fleet. A lease coordinates access; it does not authorize an
operation or fence a disconnected actor.

Collector `ledger` paths remain resource-label hints for existing configurations.
For example, `DEVICE_ACCESS_HOSTA.md` maps to the same reservation as host ID
`host-a`. No such file needs to exist. Existing installations must follow
the [offline lease migration](docs/access.md#migrating-an-existing-authority).

### Enable observation

Edit the collector seed **before its first use**, or update an already-seeded host through the host registry. Supply the real SSH account/address, expected hostname, existing trusted host keys, resource label, and exact unit/runtime allowlists. The example addresses are documentation addresses, not endpoints to use.

```sh
uv run --locked switchyard --catalog catalogs/home-lab.json \
  --collectors catalogs/home-lab.collectors.json collect-host source
uv run --locked switchyard --catalog catalogs/home-lab.json \
  --collectors catalogs/home-lab.collectors.json fleet
uv run --locked switchyard --catalog catalogs/home-lab.json \
  --collectors catalogs/home-lab.collectors.json web
```

Collection is explicit and read-only, but it contacts a device and writes cache/coordination records. Linux SSH collection needs remote Python 3 and standard Linux tools; it installs nothing. It verifies the configured hostname and SSH trust, and holds the device lease through transport cleanup. Container inspection uses an existing runtime and refuses daemon socket-activation paths.

For Android, configure an exact immutable **USB serial**, host ID, user/profile and package allowlist. There is no built-in device or serial allowlist. Its ledger must be the exact canonical filename under the ledger root. SDK selection is `ANDROID_HOME`, then `ANDROID_SDK_ROOT`, then `~/Android/Sdk`; only that root's `platform-tools/adb` is used. Prepare the SDK and its server yourself. Observation requires an already-running local server and registered transport: no server startup/restart, wireless discovery/connect, installation, UI input or wakeup.

An independently launched monitor samples only opted-in Linux hosts:

```sh
uv run --locked switchyard --catalog catalogs/home-lab.json \
  --collectors catalogs/home-lab.collectors.json monitor
# Ctrl+C stops; --cycles 4 bounds dispatch batches, not seconds.
```

The minimum example cadences are 10 seconds for CPU/memory/exact systemd state, 60 for storage, and 300 for full inventory. One leader and at most two collectors operate per cache namespace. Busy hosts are deferred; missed ticks do not queue. Android remains manual. Failed observations preserve last-known data and its original timestamps.

### Host registry and SSH identity

Host edits are compare-and-swap on the registry revision. SSH pins are tied to host IDs, so changing an address does not silently trust a different server. Address changes mark a host unverified; key changes require a leased scan and explicit fingerprint confirmation. Unpinned hosts refuse address edits.

The Hosts view edits descriptions and connection details. CLI `host-update --connection --allowlists` also edits collector allowlists. The Agents view offers opt-in Paseo metadata observation; this does not grant agent lifecycle control.

## Workload ownership and operations

Every workload is a revisioned record in one workload store (`<state>/operations/<catalog-hash>/deploy.sqlite3`):

| Relation | Meaning |
|---|---|
| `observed` | A named definition bound to exact native resources; watching only |
| `registered` | An application described by its owner; metadata only |
| `deployed` | An instance created by Switchyard, with journaled placement and ownership |

Discovery does not create a definition, and definitions or registrations do not grant control. The [workload spec](docs/spec/workload.md) describes records; the separate operations file grants capabilities.

```sh
uv run --locked switchyard --catalog catalogs/home-lab.json store status
uv run --locked switchyard --catalog catalogs/home-lab.json export store.json
# Import plans first; applying requires the expected store revision.
uv run --locked switchyard --catalog catalogs/home-lab.json import store.json
```

To opt in to reviewed policy:

```sh
uv run --locked switchyard --catalog catalogs/home-lab.json \
  --collectors catalogs/home-lab.collectors.json \
  --operations catalogs/home-lab.operations.json web
```

Structured operations use inspection → expiring plan → explicit approval and request ID → execution under whole-operation leases → durable receipt. Reusing a request ID with identical intent returns the receipt, not a second execution. Unknown outcomes require inspection, never blind retry.

- **Existing services:** exact systemd services, Quadlet services and complete Compose projects can receive inspect/start/stop/restart authority. These adapters never install, pull, recreate, enable or migrate.
- **Deployments:** stored templates deploy rootless Podman/Quadlet workloads with ownership labels, port claims, generation gates, health checks, explicit upgrades and undeploy. Generic Stop fences a deployment; low-level `deploy stop` leaves its start token valid. See [deployment](docs/deploy.md).
- **Cold migration:** the general planner is offline. The executable static-page rehearsal is a separate narrowly configured recipe, not general database or live-process migration. See [Foobar](docs/disposable-workload.md).
- **Shell:** explicitly granted SSH accounts can run unrestricted `/bin/sh` scripts. This is not a sandbox or sudo grant. Scripts are retained in private receipts; output is returned only to the caller. Reference secret files rather than embedding secret values. Declare every additional device a script touches.
- **Fleet SSH keys:** separately approved enrollment, rotation, removal and reconciliation preserve manual SSH configuration. Private keys stay on their source hosts. Authentication does not replace device leases.
- **Ansible:** operator-owned playbooks use registry-generated pinned inventory, check-mode plans and separately approved applies. Registration, planning and applying require the operator; MCP reads only. See [Ansible](docs/ansible.md).

## Agent device leases

Use the same control host and state directory for all device access:

```sh
switchyard lease run source --scope "inspect service" -- sh -c 'ssh "$SWITCHYARD_SSH_TARGET" uname -n'
switchyard lease hold destination --scope "multi-step maintenance"
switchyard lease release LEASE_ID
switchyard lease status source
switchyard lease list --json
```

`run` keeps the lease for the command and exports connection metadata. After a `hold`, release the exact ID as soon as completion is confirmed. Deadlines default to 60 minutes (maximum 120); missed deadlines do not free the device. For suspect or blocked devices, the operator must inspect the target before attesting that work stopped. Never hold device leases while building. See [access](docs/access.md) and [remote agents](docs/remote-agents.md).

`tools/install-agent-cli.sh` installs wrappers using your configuration. `tools/install-services.sh --lan-address ADDRESS --allowed-clients CIDR` can install systemd user services; inspect its options first because it starts listeners and monitoring. Use consistent state and Android SDK settings for native and containerized processes. Systemd user services need explicit `Environment=` overrides rather than shell exports.

## LAN access

Loopback `127.0.0.1:8710` trusts local processes; do not expose that listener through a public bind, tunnel or reverse proxy. For LAN control, initialize TLS and have the human operator set a password at a terminal:

```sh
switchyard tls init --name desk.home.arpa --name 192.168.50.5
switchyard auth set-password
switchyard web --lan --host 192.168.50.5 --port 8712 --allowed-clients 192.168.50.0/24
```

These commands assume the installed wrapper selects your private configuration. Replace the example bind address with an address assigned to the control host. The listener requires HTTPS, sign-in/session CSRF protection or an appropriately scoped access key. Clients must verify the local CA fingerprint before trusting it. Enrollment grants nothing until approval.

`--allowed-clients CIDR` explicitly selects the client network. Without it, a private literal bind derives an IPv4 /24 or IPv6 /64. A legacy GET-only listener is available with `--lan-read-only`; it is **not authentication**, and everyone on its allowed network can read shared metadata. Prefer authenticated HTTPS. See [authentication and enrollment](docs/auth.md).

## MCP

The official Python MCP SDK serves stdio; no unauthenticated network MCP listener is installed. Example client configuration:

```json
{
  "mcpServers": {
    "switchyard": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/switchyard", "--locked", "switchyard-mcp", "--catalog", "/path/to/switchyard/catalogs/example.json"]
    }
  }
}
```

Add your reviewed absolute `--collectors`, `--operations` and `--state-dir` arguments only when needed. Reads share cached state with CLI/web; explicit inspection contacts hosts. Remote MCP deliberately exposes a smaller read/lease surface.

## Reference

- [Architecture](docs/architecture.md), [domain model](docs/domain-model.md), [fictional model shapes](docs/domain-examples.json)
- [Device access](docs/access.md), [observation contract](docs/observation-contract.md), [agent briefing](docs/agent-briefing.md)
- [Workload specification](docs/spec/workload.md), [deployment](docs/deploy.md), [registered-application tokens](docs/tokens.md)
- [Ansible](docs/ansible.md), [remote agents](docs/remote-agents.md), [authentication](docs/auth.md)
- [Rootless container packaging and systemd setup](docs/container.md)
- [Disposable rehearsal](docs/disposable-workload.md), [roadmap](docs/roadmap.md)

Tests use isolated fixtures and temporary ledgers. A test run is not evidence that your hosts support an operation:

```sh
uv run --locked python -m unittest discover -s tests -v
```

## License

Switchyard is licensed under the [GNU General Public License](LICENSE), version 3 or (at your option) any later version (`GPL-3.0-or-later`).

The UI has no frontend build step or external font request. The bundled Big Shoulders and Source Sans 3 font files remain separately licensed under the SIL Open Font License 1.1; see [FONT-LICENSES.txt](switchyard/static/FONT-LICENSES.txt).
