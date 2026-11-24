# Device leases for agents on other hosts

Agents on the control host take device locks with `switchyard lease`. Canonical ledgers and kernel flock live on that host only; agents elsewhere must request leases through it. The default ledger root is the XDG state root plus `switchyard/ledgers` (normally `~/.local/state/switchyard/ledgers`), overridden by `SWITCHYARD_LEDGER_DIR`. A remote copy of those files is not a lock.

Hosts that have no SSH trust to the control host use the same client with an **API key** instead: `switchyard enroll` asks the Switchyard HTTPS listener for a key, the operator approves the request from any browser, and the client then reads state and takes leases over HTTPS (see "Keyed HTTPS access" below).

## Pieces

| Where | What |
|---|---|
| the control host | `switchyard lease attach`: a lease held for a caller on the other end of stdin (one SSH connection). It is released when the caller reports `done`, and kept fail-closed as *suspect* when the caller goes silent. |
| the control host | `switchyard lease hold --detached`: a hold limited only by its TTL, for callers whose owning process is not on the control host. |
| the control host | `tools/install-agent-cli.sh`: installs `~/.local/bin/switchyard`, `switchyard-mcp` and `switchyard-mcp-remote` with uv's absolute path, so the wrappers work from non-interactive SSH. |
| Other host | `tools/switchyard-remote`, installed as `~/.local/bin/switchyard`: a single file that uses only the Python 3 standard library (3.9 or newer). |
| the control host → host | `tools/install-remote-client.sh <host-id>`: installs the client, its configuration and the agent guidance while holding that host's lease. |

## Server side (control host)

```sh
switchyard lease attach <device> --scope S [--owner O] [--wait N] [--heartbeat SECONDS] \
    [--origin-host H [--agent-id PASEO_ID] [--origin-user U]] [--worktree W]
```

- `attach` acquires the lease the same way as `run`, writes CLAIM, and prints one JSON line on stdout: `{"status": "claimed", "lease_id", "device", "expires_at", "env": {...}}`.
- **Release means the command is confirmed finished.** A `done` line on stdin releases with reason `released`. So does `switchyard lease release <id>`. SIGTERM or SIGINT gives reason `signal`, and the 120-minute hard cap gives `expired`. After RELEASE, `attach` prints `{"status": "released", "lease_id", "device", "reason"}` (best effort) and exits 0. Attach leases cannot be renewed.
- **Without `--heartbeat`** (manual use at a terminal on the control host), EOF on stdin also releases (`released`) and SIGHUP gives `signal`.
- **With `--heartbeat N`**, which the remote client always passes (`60`), the caller sends a byte at least every N seconds. Losing contact is fail-closed:
  - No byte for N seconds (cause `silent`), or EOF without `done` (cause `disconnected`), marks the lease **suspect**. The state file gets `suspect`, `suspect_since` and `suspect_cause`.
  - The flock stays held and no RELEASE is written, because the remote command may still be touching the device.
  - The holder ignores SIGHUP, and the CLI moves it into its own session (`setsid`), so SSH teardown cannot end it. With `KillUserProcesses=no` on the control host, logind does not kill it either.
  - A suspect lease ends only by explicit `lease release <id>`, by SIGTERM to the attach process on the control host, or by the cap. Its RELEASE records `suspect_cause` and `suspect_since`, plus `released_after_loss: true` for an explicit release. A late `done` from a client that recovers also releases it.
- **Visibility.** `lease status`/`list`, `/api/locks` and MCP `device_locks` include `suspect`, `suspect_since` and `suspect_cause` in `switchyard_lease`. Busy messages end with `connection lost <age> ago (<cause>), command state unknown; clear with switchyard lease release <id> once the remote command is confirmed stopped`.
- **Clearing a suspect lease.** First confirm on the origin host that the command is not running. The client kills it when it dies, but see Limits. Then run `switchyard lease release <lease_id>`. If the attach process does not respond, or the holder is something else entirely, the operator uses `switchyard lease break <device> --reason …` at a terminal on the control host. Its RELEASE then carries reason `broken` plus the suspect cause, and the device stays blocked for new leases until `--attest-stopped` or `switchyard lease clear`. See [device access and breakglass](access.md#agent-leases-and-breakglass).
- If the device is busy, `attach` exits 75. The holder message goes to stderr and nothing goes to stdout. If stdin closes while `--wait` is still polling a busy lock, `attach` gives up without a CLAIM and exits 1.
- `lease hold ... --detached` drops the owner-exit watch. Release, the TTL and signals still end the hold. `--origin-host` requires `--detached` on `hold`.
- Owner attribution: `--origin-host` must be a registry host. `--agent-id` resolves to `"<agent name> (paseo:<id8>)@<host>"` through the cached Paseo agent names, but only when Switchyard saw that agent on that same host. An agent ID it has not seen gives `paseo:<id8>@<host>`. Without an agent ID the owner is `<user>@<host>`, and an explicit `--owner` becomes `<owner>@<host>`. The ledger's `via` field reads `switchyard lease attach from <host>` or `switchyard lease hold --detached from <host>`.
- A detached hold also passes `PASEO_AGENT_ID` to its holder unit, so the locks view names the remote agent.
- Busy messages prefer the owner of the matched Switchyard lease to the kernel holder's process name. For a remote lease that owner is `…@host-a`, where the process name would only say `python3`.

## Client (other hosts)

The installer writes `~/.config/switchyard/remote.json`; these addresses and account paths are fictional and must be configured for your control host:

```json
{"control": "operator@192.0.2.5", "switchyard": "/home/operator/.local/bin/switchyard",
 "mcp": "/home/operator/.local/bin/switchyard-mcp-remote", "host_id": "host-a"}
```

```sh
switchyard lease run <device> --scope S [--wait N] [--owner O] -- CMD...
switchyard lease hold <device> --scope S [--ttl 60m] [--wait N] [--owner O]   # becomes hold --detached
switchyard lease release <lease-id|device>
switchyard lease renew <lease-id> [--ttl 30m]
switchyard lease status <device>
switchyard lease list [--json]
switchyard hosts | fleet | definitions | operations [--id ID]                   # read-only
switchyard mcp                                                                  # stdio MCP over ssh
```

- **`lease run`** starts `ssh -T -o BatchMode=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 <control> switchyard lease attach … --heartbeat 60` with a pipe on stdin. It waits at most `--wait` + 20 s for the claim line, then runs CMD locally.
  - CMD runs in its own process group with `PR_SET_PDEATHSIG=SIGTERM`, so a crashed or killed client takes CMD down.
  - CMD receives exactly `SWITCHYARD_LEASE_ID`, `SWITCHYARD_DEVICE` and either `ANDROID_SERIAL` or `SWITCHYARD_SSH_TARGET`/`SWITCHYARD_SSH_PORT`. Stale copies of these variables and `DEVICE_LOCK_FD` are removed from the inherited environment, and any other keys in the claim are ignored.
  - While CMD runs, the client writes a newline heartbeat every 15 s.
  - SIGINT, SIGTERM and SIGHUP are forwarded to CMD. The SSH process runs in its own session, so a terminal Ctrl-C reaches only CMD and never the lease connection.
  - Once CMD has exited **and been reaped**, the client writes `done`, closes the pipe and waits up to 30 s for the `released` line. It then returns CMD's exit code. If the release is not confirmed, it releases explicitly (see below).
  - If the client gives up before running CMD (signal, no claim in time), it also sends `done`, so a late claim is released at once.
- **Exit codes:** CMD's own code; **75** busy, with the holder message passed through and nothing run; **76** lease lost while CMD ran; **255** control host unreachable, nothing run; **2** usage errors and refused commands.
- **Lease lost (76).** This covers an SSH connection that dies, heartbeats that can no longer be written, and a control host that ends the lease early (cap or operator release). The client prints a loud `LEASE LOST` warning, then:
  1. It sends SIGTERM to CMD's process group.
  2. Ten seconds later it sends SIGKILL to anything still in that group, including descendants that outlived the leader, and waits until CMD is reaped.
  3. Unless the control host already ended the lease, it reconnects and runs `lease release <lease_id>`: every 5 s, for up to 2 minutes.
  4. It reports whether the release worked, was refused because the lease had already ended, or was left **suspect** on the control host.
- **Attribution.** `lease run` and `lease hold` send `--origin-host <host_id>`, the caller's `--origin-user` and `--worktree <host>:<cwd>`. They also send `--agent-id` from `PASEO_AGENT_ID`, which Paseo sets for its agents and their child processes.
- **Refused remotely:** `shell`, operations, registry and definition edits, the `web` command, `lease attach`/`_holder`, `lease break`/`clear` (an operator breakglass at a terminal on the control host only) and `--pass-lock-fd` (the locked descriptor exists only on the control host). Global options such as `--catalog` and `--state-dir` are also refused; the control host's wrapper sets them.
- **Blocked devices.** After an operator's `lease break` without attestation, `lease run`/`hold` and MCP `lease_hold` get exit 75 with `<DEVICE> blocked: lease broken by … clear with switchyard lease clear …`. Defer and tell the user; only the operator clears it.
- **Leasing the caller's own host** (`host-a` from host-a) works the same way. Use it to coordinate with control-host agents working on that host. Never lease `host-a` from inside a control-host-side `host-a` lease: that deadlocks.
- **ADB.** `ANDROID_SERIAL` names a USB device on the control host, which is usually unreachable from another host.

### MCP

`switchyard mcp` runs `ssh … ~/.local/bin/switchyard-mcp-remote --origin-host <host_id> [--agent-id $PASEO_AGENT_ID] --origin-user <user>`, with stdio passed through. That wrapper is `switchyard-mcp --remote` without `--operations`.

Remote mode registers a fixed allowlist of tools, and only those:

- Reads: `inventory`, `fleet`, `hosts`, `device_locks`, `agents`, `operation_policy`, `operation_receipts`, `operation_receipt`, `fleet_keys`, `definition_inventory`.
- Leases: `lease_hold`, `lease_release`, `lease_renew`.

There are no host or definition edits, no collection, inspection or planning, and no execution or shell. A tool not on the list is never registered, so new tools stay local-only by default.

In remote mode, `lease_hold` is always a detached (TTL-only) hold. It is attributed like the CLI (`<agent> (paseo:<id8>)@<host>` or `<user>@<host>`), with worktree `<host>:mcp`. The local `switchyard-mcp` keeps its full tool set.

## Installing on a host

```sh
tools/install-agent-cli.sh                       # on the control host first (absolute uv path, MCP wrappers)
export SWITCHYARD_CONTROL_TARGET=operator@192.0.2.5  # replace with the control host SSH account/address
tools/install-remote-client.sh --render host-a   # review the program that will run on the host
tools/install-remote-client.sh host-a            # under `switchyard lease run host-a`
```

`SWITCHYARD_CONTROL_TARGET` sets the control host account/address; otherwise the installer uses a single configured `local_targets` policy entry and refuses if none is unambiguous. The example account/address above is not a reachable installation. The remote account needs existing SSH trust to that target.

The installer runs the rendered Python program on the host and prints a JSON report. On the host it writes:

- `~/.local/bin/switchyard` (0755), written to a temporary file and renamed into place. A file at that path that is not this client is backed up first.
- `~/.config/switchyard/remote.json` (0600).
- It checks `ssh -o BatchMode=yes <control>` from the host, together with the presence of the control-host wrappers. It reports a missing `known_hosts` entry or an unauthorized key and then exits 3; it never adds keys.
- Agent guidance. Any file it changes gets a `.bak-<timestamp>` copy first, and rerunning changes nothing:
  - omp: the managed skill `~/.omp/agent/managed-skills/switchyard-device-lease/SKILL.md`, using remote-client guidance rather than local-controller commands.
  - omp: a marked "Hardware & Networked Device Locks" section in `~/.omp/agent/RULES.md` (the file is created if absent).
  - omp: a `switchyard` stdio entry in `~/.omp/agent/mcp.json`, added only if the control host's omp uses the `mcpServers` stdio format. Other entries are preserved.
  - Claude Code: the same marked section in `~/.claude/CLAUDE.md`, if `~/.claude` exists.

The marked block sits between `<!-- BEGIN switchyard-remote-device-locks … -->` and `<!-- END switchyard-remote-device-locks -->`. A rerun replaces only that block.

**Scope rule for remote hosts:** before any adb, ssh or network access from this host to ANOTHER Switchyard registry host, take that host's lease. Work on this host itself needs no lease unless you are coordinating with control-host agents.

## Keyed HTTPS access (enrollment)

### SSH leases or a key?

- **SSH leases** (`switchyard lease run|hold …`) are the default wherever the host's SSH key is trusted on the control host. `lease run` holds the lease exactly for the command's lifetime, sends heartbeats, kills the command when the lease is lost (exit 76) and fails closed (*suspect*) when the connection dies. Prefer them.
- **A key** (`switchyard enroll`) is for hosts without that SSH trust, for example a fresh host or a laptop that should only read. Keyed HTTP leases (`switchyard http-lease`) are TTL-only holds: nothing ties them to a running command. Release them yourself.

Scopes are granted by the operator. A request can only narrow what it asks for.

| Scope | Allows |
|---|---|
| `read` | every read the desk offers, with the same redaction as the LAN view; no host list |
| `lease` | `read`, plus leases on the devices whose registry host IDs are in the key's `hosts` |
| `operate` | `lease`, plus operations touching only those hosts |

A `lease` or `operate` key always has a non-empty host list; a device outside it gets 403 before any lock is attempted.

### Headless walkthrough

On the new host, in a plain SSH session:

```sh
switchyard enroll --server https://192.168.50.5:8712 --scope lease --hosts host-a
```

1. The client downloads the CA from `GET /api/tls/ca` and prints its fingerprint. Compare it with `switchyard tls show` on the control host, or with the Access tab. To pin it instead, pass `--ca-fingerprint sha256:<hex>`; a different CA is then refused before anything is sent.
   - That first download is the only unverified connection, and it carries nothing but the download request.
   - Before sending anything else, the client opens a verified connection. The server's certificate must chain to that CA, name the address you typed, and be the certificate the download connection saw.
   - From then on, every connection is verified against the stored CA, including the hostname or IP.
2. It generates the key locally and sends only its SHA-256, together with the name (default: the hostname), the user, this host's registry ID (if the SSH installer recorded one), `PASEO_AGENT_ID` (if set), and the scope and hosts.
3. It prints three lines:
   - the approve address, `https://192.168.50.5:8712/#access/<request id>`;
   - a code such as `Code: ABCD-EFGH`, computed from the certificate this host actually saw;
   - a line asking the operator to check the code.
4. Open the address on any device (a phone works), sign in, check that the Access page shows the same code for that request, and approve. A different code means something is intercepting the connection: deny the request.
5. The client polls until the request is approved (exit 0), denied or expired (exit 1). On denial or expiry it deletes the unused key.
   - Ctrl-C stops waiting without touching the request.
   - `switchyard enroll --status` checks once: exit 0 approved, 3 still pending, 1 denied or expired.
   - `--no-wait` submits the request and returns.

`--scope lease` or `operate` without `--hosts` is allowed; the operator then chooses the hosts when approving. A `read` request cannot name hosts.

### Using a key

```sh
switchyard whoami                                  # kind, key id, scope, hosts, expiry
switchyard api GET /api/hosts                      # any GET the key's scope allows; JSON on stdout
switchyard http-lease hold host-a --scope "why" [--ttl 30]   # {lease_id, device, expires_at}
switchyard http-lease renew LEASE_ID [--ttl 30]
switchyard http-lease release LEASE_ID
switchyard http-lease list
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | the key is expired or revoked ("enroll again"), the lease is unknown, or the certificate does not match the stored CA (nothing was sent) |
| 2 | usage error, or a refused command |
| 75 | the device is busy; the holder is printed |
| 77 | not allowed for this key: wrong scope, or a device outside its hosts (the allowed hosts are printed) |
| 255 | the server is unreachable |

`api` performs GET requests only, and only on paths of this server.

### Storage

`~/.config/switchyard/` (mode 0700) holds:

- `key`: the bearer, 0600, written atomically. This is the only place the key is ever written; it is never printed and never passed on a command line.
- `ca.pem`: the pinned CA, 0600.
- `client.json`: server URL, request ID, name, status, CA fingerprint and the granted key record (id, scope, hosts, expiry), 0600, with no secret.

The client refuses a key file that others can read. `SWITCHYARD_CONFIG_DIR` overrides the directory.

### Replacing, revoking and CA changes

- **Replace a key.** `switchyard enroll … --replace` first asks the server to revoke the current key (`POST /api/keys/self/revoke`, best effort; the outcome is printed), then deletes it and enrolls again. Without `--replace`, enrolling over an existing or pending key is refused.
- **Revoke a key.** `switchyard unenroll` revokes the key on the server and then deletes it locally. If the server cannot be reached, the key is kept so you can retry. The operator can revoke any key from the Access tab or with `switchyard auth revoke KEY_ID`.
- **CA replaced.** A renewed server certificate from the same CA keeps working. If the operator replaces the CA itself, the client refuses the new certificate ("does not match the stored CA … nothing was sent"). Compare the new fingerprint, delete `~/.config/switchyard/ca.pem`, and enroll again with `--ca-fingerprint`.

## Limits

- This is coordination, not fencing. A remote agent that ignores exit 76 or bypasses the client is not stopped.
- `PR_SET_PDEATHSIG` covers CMD itself, not processes it spawns. A daemonizing or double-forked descendant can outlive a killed client, which is exactly why the control host keeps such a lease suspect instead of releasing it.
- A SIGSTOPped (or hung) client leaves CMD running; after 60 s of silence the control host marks the lease suspect while still holding the lock.
- A detached hold that nobody releases blocks the device until its TTL expires, because the control host cannot see the remote process exit. A suspect attach lease blocks it until someone releases it or the 120-minute cap. Agents should prefer `lease run`.
- Every command costs an SSH connection plus CLI startup on the control host; avoid using reads as a polling loop.
- Claude Code's MCP configuration (`~/.claude.json`) is not edited. Claude Code agents use the CLI.
- Enrollment trusts the first CA download unless `--ca-fingerprint` is given. Comparing the printed fingerprint, or the code on the Access page, is what catches interception on that first contact.
- A key holder on an approved host is as trusted as that host. Anyone who can read `~/.config/switchyard/key` as that user can use the key until it expires or is revoked.
- Keyed HTTP leases are not bound to a command or a connection: a forgotten `http-lease hold` blocks the device until its TTL. Use SSH `lease run` where it works.
