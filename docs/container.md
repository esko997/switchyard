# Rootless container packaging

The image packages Switchyard's Python runtime. **Integrated mode is not an isolation boundary.** It deliberately shares the control user's host network, process view, systemd user bus and selected files. Existing operation policies, approvals, leases, process identity checks and SSH trust still apply. Running a container does not grant permission to contact or change a host.

Use a local rootless Podman installation on the Linux control host (including Bazzite), Bash, and an unprivileged account. The launcher explicitly uses local Podman, not a remote Podman connection. No runtime socket, USB device, privileged container, systemd daemon inside the image, or extra recurring host supervisor is needed. The native public CLI remains the entry point for arbitrary host `lease run ... -- COMMAND` jobs.

## Build a local image

From the repository root:

```sh
podman build --file Containerfile --tag localhost/switchyard:local .
```

The base is Python 3.13 on slim Debian; `uv sync --locked --no-dev --no-editable` installs the application and locked dependencies. The image includes `uv`/`uvx`, Git, OpenSSH clients, `systemctl`, `systemd-run`, OpenSSL, CA certificates, and the C++ runtime needed by a mounted Android SDK client. It does not contain a local Podman client or an Ansible environment; Ansible's pinned runner remains configured separately.

`.containerignore` denies the build context by default, allowing only project metadata/license, Python package source and static assets, and `catalogs/example.json`. `COPY` names those inputs explicitly. No private catalog, operation policy, SSH identity, state database, TLS material, audit capture, test fixture or checkout history belongs in the image. Do not loosen the allowlist to copy a whole checkout or home directory. No registry push is required.

Build and review an image before use. The launcher uses `--pull=never`, so restarting a service cannot silently pull a changed image. Use a distinct local tag or digest when promoting an update, and retain the old image until rollback is no longer needed.

## Disposable loopback demo

```sh
tools/run-container.sh demo --image localhost/switchyard:local
# Open http://localhost:8710 (the accepted HTTP Host for the forwarded port).
# Ctrl+C stops it; all demo state is discarded.
```

This mode requires the host's `slirp4netns` networking helper. It uses a private network with the guest at `10.0.2.100` and publishes only on host IPv4 loopback. The application serves its **GET-only** fictional catalog on the guest address; this is not the trusted local-control listener. `--port 18710` changes the port on both sides, so the server can validate the browser's `Host: localhost:18710`. It mounts no host files, shares neither host PID nor host networking, enables no collectors or operations, and does not contact the fictional hosts.

Do not change the publish address to a LAN/wildcard address or proxy the demo externally. This read-only view has no operator authentication. For a real desk, use integrated mode with existing authentication/TLS state instead.

## Integrated paths and authority

Keep the resolved absolute paths identical to native Switchyard:

| Input | Container access |
|---|---|
| `--config-dir DIR` | Read-only, same absolute directory; contains the catalog and optional seed/policy files |
| `--catalog FILE` | Required; existing file below the configuration directory |
| `--collectors FILE`, `--operations FILE` | Optional existing files below that same directory |
| `--state-dir DIR` | Read-write private state; same absolute directory used by native CLI/MCP |
| `--ledger-dir DIR` | Optional read-only legacy audit directory for migration detection; not used for live exclusion |
| `--home DIR` | Canonical control-user home identity; defaults to the launcher's home, but does **not** mount the whole home |
| `--host-holder FILE` | Installed native host lease-holder helper, executable on the host at this absolute path |
| `--sdk DIR` | Optional read-only SDK; must contain `platform-tools/adb` |
| `--ssh-dir DIR` | Optional read-only canonical `HOME/.ssh`, including existing trust and identities |
| `--known-hosts FILE` with `--ssh-agent SOCKET` | Alternative: read-only canonical `HOME/.ssh/known_hosts` plus an explicitly mounted agent socket |
| `--playbook-repo DIR` | Repeatable read-only playbook checkout, at its original absolute path |

Relative catalog/collector/operation filenames are interpreted below `--config-dir`. All host paths must already exist; the launcher resolves symlinks and rejects paths containing commas, colons or newlines because they cannot safely be represented in its mount syntax. Preserve the *resolved* catalog path: it namespaces databases. Do not relocate an established catalog into `/config`, move state into `/state`, or create copied ledgers for the container. Ancillary configuration files referenced by a catalog must also be inside the explicitly mounted configuration directory.

State contains credentials, TLS private keys and operational history, including the authoritative lease database used by native and containerized entry points. Prepare it with owner-only access (`umask 077`); never run `podman unshare chown` against it. Use the same resolved catalog and state for all callers, and migrate before replacing a legacy authority. Back up private state outside the build context.

The launcher sets:

- `--userns=keep-id`, the current numeric UID/GID, an explicit passwd home, a read-only image, no capabilities, and `no-new-privileges`;
- `--pid=host --network=host`, preserving real process identity and the existing host ADB server/SSH transports;
- `--security-opt=label=disable` in **integrated mode only**: sharing canonical files and the user bus on SELinux hosts must not relabel them. Do not add `:z`/`:Z` to shared state, ledgers, SDK or SSH mounts;
- the existing user bus and systemd manager sockets (`/run/user/UID/bus` and `/run/user/UID/systemd/private`), `XDG_RUNTIME_DIR`, and `DBUS_SESSION_BUS_ADDRESS` for transient tasks on the host's systemd user manager;
- `SWITCHYARD_CONTAINER_HOST=1`, `SWITCHYARD_HOST_HOLDER`, and optionally `SWITCHYARD_LEDGER_DIR`. If defined in the launcher's environment, `SWITCHYARD_EXTERNAL_LEASE_HOSTS` is forwarded unchanged (a private comma-separated list of externally coordinated host IDs).

The image does not acquire a new host identity. The launcher checks the container's passwd home before executing Switchyard because OpenSSH uses passwd, not just `HOME`, for default identity, known-host and Include paths. An existing image account with the same UID but a different home fails closed. The home and runtime directories are private temporary filesystems; only explicitly selected subpaths are mounted. `/tmp` and uv's scratch cache are ephemeral too.

Access to the user bus lets Switchyard request native transient jobs as that user. It is broad host authority, not a sandbox escape prevention mechanism. Local host probes and long-lived lease holders run in the **host** context, not against the image's hostname, image files or PID 1. PID/UID/start-time identity checks are not disabled. Install the native public CLI and its host-holder helper first; do not point the helper at a temporary developer worktree. Native host transient jobs need their own usable Python/uv tooling. If the user manager has a minimal PATH, set the native CLI's `SWITCHYARD_UVX` to the absolute host `uvx` executable when configuring its runner.

Run `uv sync --locked` in the stable native checkout, then point `--host-holder` at its absolute `.venv/bin/switchyard` executable. If you need a wrapper, it must forward all arguments unchanged; Switchyard passes only `--state-dir PATH lease _holder ID`. Use the same release for this native executable and the image.

### Foreground launch

These fictional paths illustrate an already-prepared installation. Replace them with the original canonical paths of your own installation, not new paths chosen solely for the container:

```sh
tools/run-container.sh integrated \
  --image localhost/switchyard:local \
  --config-dir /srv/switchyard/config --catalog fleet.json \
  --collectors fleet.collectors.json --operations fleet.operations.json \
  --state-dir /var/home/operator/.local/state/switchyard \
  --ledger-dir /var/home/operator/.local/state/switchyard/ledgers \
  --home /var/home/operator \
  --host-holder /var/home/operator/.local/bin/switchyard-host-holder \
  --ssh-dir /var/home/operator/.ssh \
  --sdk /var/home/operator/Android/Sdk \
  --playbook-repo /var/home/operator/Repos/host-playbooks \
  --name switchyard-desk -- web
```

This starts the trusted loopback desk at `127.0.0.1:8710`. There is no TTY, detached child, shell evaluation of arguments, or supervisor added by the launcher: it execs foreground Podman. Everything after `--` is passed as the Switchyard command, after the same global catalog/state/collector/operation options. Use `monitor` for a standalone monitor or `lan-dns-sync` for a one-shot DNS reconcile. The latter is a real leased operation, not an offline preview; append `--dry-run` to preview.

To run loopback and authenticated HTTPS desks with monitoring in one container, use the optional combined command instead:

```sh
# Use the identical integrated options above, then this suffix after --:
container-service --lan-host 192.168.50.5 --lan-port 8712 \
  --allowed-clients 192.168.50.0/24 --name desk.home.arpa
```

`container-service` starts the loopback desk and, when supplied, the HTTPS desk, plus a monitor when collectors are configured. If a listener or monitor exits, the combined command fails so systemd can restart the group. Without `--lan-host`, no LAN listener is created. A standalone authenticated desk uses `web --lan --host 192.168.50.5 --port 8712 --allowed-clients 192.168.50.0/24`. TLS and the operator password must already be initialized in the same native state; do not create replacement identities during a migration. Keep the local trusted listener on loopback. See [authentication](auth.md).

### SSH, Android and playbooks

Choose the smallest credential mount that meets your operations:

- A read-only SSH directory preserves the host's existing configuration, identity selection and known hosts. Every absolute `IdentityFile`, `Include` or certificate path must be available at that same path; keep the required material under the mounted SSH tree. A missing path is not permission to disable strict host-key checking.
- With an agent, pass its actual socket explicitly, for example `--known-hosts /var/home/operator/.ssh/known_hosts --ssh-agent /run/user/1000/ssh-agent.socket`. Only public trust data enters the container, but the agent can still authenticate as its loaded identities; this is real authority, even through a read-only socket bind. An existing agent can also supplement `--ssh-dir`.
- Read-only SSH mounts do not support creating/rotating local private keys or editing local SSH trust/configuration. Perform those explicitly approved changes through the native CLI on the control host, rather than broadening a long-running container's mounts. Password/TTY-based SSH prompts are not available in the service.
- Start and prepare the SDK ADB server **on the host**, before enabling Android observations. The SDK bind does not expose USB and does not start a private server. Host networking reaches the existing server. Do not mount USB or allow another ADB version to restart it.
- Mount registered playbook repositories explicitly at their original absolute paths. The image cannot see arbitrary checkouts, private files or interpreter paths referenced by playbooks. Host-context Ansible runs still need the native configured runner and access to their host-side inputs. Read-only repository mounts are not a grant to execute a playbook or handle sudo non-interactively.

## Existing systemd user scheduling

Keep systemd as the scheduler. Do not run systemd inside the image or add cron/a new background host agent. For each foreground launcher command, use a normal user service. For example, put the full integrated command on `ExecStart` (systemd lines do not expand shell variables or `~`):

```ini
[Unit]
Description=Switchyard container control plane
After=network-online.target

[Service]
Type=simple
ExecStart=/opt/switchyard/tools/run-container.sh integrated --image localhost/switchyard:local --config-dir /srv/switchyard/config --catalog fleet.json --collectors fleet.collectors.json --operations fleet.operations.json --state-dir /var/home/operator/.local/state/switchyard --home /var/home/operator --host-holder /var/home/operator/.local/bin/switchyard-host-holder --ssh-dir /var/home/operator/.ssh --name switchyard-control -- container-service
ExecStop=/usr/bin/podman --remote=false stop --ignore --time 50 switchyard-control
Restart=on-failure
RestartSec=5
TimeoutStopSec=65

[Install]
WantedBy=default.target
```

The launcher gives Podman a 50-second stop grace; retain a longer systemd stop timeout (65 seconds above) so graceful host-job cancellation can finish. Do not add a TTY or background the launcher. For separate desks/monitor, use separate service names and Podman `--name` values; do not also run a second monitor inside `container-service`. Keep public/authenticated listener choices explicit rather than reviving a retired read-only LAN service. Login/linger semantics remain those of the existing systemd user manager; enabling linger is an operator choice, not part of the image.

Retain the existing LAN DNS timer. Its oneshot service may run the same launcher with `-- lan-dns-sync`; use a distinct container name or omit `--name`. An equivalent native CLI invocation with the same configuration and state paths is also supported. Preserve the timer cadence and `TimeoutStartSec`; the launcher does not schedule work.

For a new installation only, a conventional timer is:

```ini
[Unit]
Description=Reconcile Switchyard LAN hostnames

[Timer]
OnActiveSec=30s
OnUnitInactiveSec=60s
AccuracySec=5s
Unit=switchyard-lan-dns-sync.service

[Install]
WantedBy=timers.target
```

Its service is `Type=oneshot`, has `TimeoutStartSec=7min`, and uses the full integrated `ExecStart` with `lan-dns-sync`. Do not schedule it until the private DNS deployment and policy are configured. Inspect unit files and existing services before enabling/replacing anything; container packaging does not authorize a live rollout.

## Boundaries and rollback

The launcher never edits host configuration, creates ledgers, copies private homes, publishes a registry image, starts the host ADB server, or installs/enables units. A read-only image does not make the mounted state or user bus read-only. Processes sharing the control user's UID remain trusted participants; leases coordinate access, not hostile-code containment.

For migration, stop the old control-plane processes, back up private state and configuration securely, and replace only the selected service commands. Verify the catalog namespace, shared SQLite authority, host identity/lease attribution, SSH trust, ADB transport, listeners/authentication and DNS timer. A native rollback must use the same database and compatible code; never reopen an old backend or restore a stale lease database without reconciling newer work. See [the lease cutover](access.md#migrating-an-existing-authority).
