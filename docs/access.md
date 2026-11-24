# Device access broker

## Boundary

Switchyard coordinates access through append-only `DEVICE_ACCESS_*.md` ledgers on one control host. A lease is coordination, not operation approval, device state or runtime fencing.

`LedgerBroker` requires an operator-supplied mapping to existing canonical absolute paths. It rejects symlink aliases, takes an exclusive flock, reads the baseline under that lock, appends CLAIM/RELEASE records in place, flushes them and holds the descriptor for the complete operation. It never replaces a ledger. Process death releases the kernel lock; a missing RELEASE remains crash evidence.

The default ledger root is:

```sh
${XDG_STATE_HOME:-$HOME/.local/state}/switchyard/ledgers
```

`SWITCHYARD_LEDGER_DIR` overrides it. A registry host's default filename is `DEVICE_ACCESS_<LABEL>.md` (uppercase host ID, non-alphanumeric characters removed). `host-add` creates missing ledgers; lease acquisition never creates one. Linux collectors may name an explicit existing canonical ledger. Android requires the exact default filename under this root. Keep ledgers outside checkouts and configure every writer to use the same inode.

## Required gateway contract

1. Resolve a registry host ID to trusted connection data and canonical ledger; callers cannot supply arbitrary paths or targets.
2. Verify authority and approval separately. Read-only device inspection also requires a lease.
3. Acquire all required resources in deterministic order, with bounded contention; release earlier acquisitions if one is busy. Do not hold leases while building artifacts.
4. Read the locked baseline and append the owner, scope and operation identity before device access.
5. Keep the descriptor open through transport teardown. Never detach device work that outlives the lease.
6. Record observed outcomes and recovery caveats. Unknown outcomes require inspection, not blind retry.
7. Append RELEASE and unlock in a finally path. Never replace, rename or atomically rewrite a ledger.

Context completion is not an application health check. The observation monitor runs fixed bounded batches, closes transport before releasing, releases between samples, and skips contention rather than accumulating work.

## Agent leases and breakglass

```sh
switchyard lease run host-a --scope "bounded inspection" -- COMMAND ARGUMENTS
switchyard lease hold host-a --scope "multi-step maintenance"
switchyard lease renew LEASE_ID --ttl 30m
switchyard lease release LEASE_ID
switchyard lease status host-a
switchyard lease list --json
```

`run` owns the lock for the command and exports connection metadata. `hold` uses a systemd user holder across tool calls. The default TTL is 60 minutes, maximum 120; release immediately when finished. Local owner exit also ends ordinary holds. Busy exits 75 and names the holder; `--wait` is bounded to 600 seconds. MCP offers `lease_hold`, `lease_renew` and `lease_release`. Remote connection loss can leave a lease **suspect**, because the command's state is unknown; see [remote agents](remote-agents.md).

A kernel flock cannot be stolen. Human-only `lease break` runs on the control host, enumerates inherited descriptor holders, revokes Switchyard leases, and signals foreign holders only when explicitly requested. It must prove the lock gone before recording BREAK. Unless the operator attests the old operation stopped, the device stays blocked until `lease clear --attest-stopped ...`. Agents must defer, never bypass a suspect or blocked device. Raw-flock callers cannot enforce Switchyard's administrative block; migrate all callers to the gateway before relying on it.

## Android and additional gates

Configure the immutable USB serial, exact user/profile and package scope yourself; no real-device allowlist is bundled. SDK lookup is `ANDROID_HOME`, then `ANDROID_SDK_ROOT`, then `~/Android/Sdk`, using only `platform-tools/adb` beneath that root. Commands select the exact serial and disconnect stdin in scripts. Collection uses an already-running local ADB server and registered transport; it never starts/restarts the server, discovers/connects wireless devices, installs packages or sends UI input.

Device-specific maintenance/relay gates must be integrated before enabling a device; a plain ledger is not a substitute. Keep host build locks separate from device coordination. Never infer freedom from a static RELEASED header or an old timestamp; the current kernel lock and gateway owner govern access.

## Cross-host coordination

A flock on one machine does not exclude a script on another. Route all device access through a designated gateway holding the canonical inode. Fleet SSH authentication does not make exclusion distributed. Every additional device reached by a shell script must be declared so its lease is held too; arbitrary shell cannot infer or enforce nested destinations.

Before decentralizing, migrate all writers, timers, bridges and relays to the same protocol. Expiring distributed locks alone cannot stop a disconnected actor. Mutation needs fencing at the execution gateway or device, durable receipts and uncertain-outcome recovery.

## Opt-in operation broker

Operator-owned policy separately grants shell, lifecycle, fleet-key, deployment and token capabilities. Discovery and definitions confer none. Plans bind authority and input fingerprints for ten minutes, then require explicit approval and a request ID. Identical reuse returns the receipt; conflicting reuse is refused. Bounded concurrency and whole-operation leases apply.

Receipts retain operation metadata, hashes and uncertainty/recovery evidence. **Shell scripts are retained privately**, with a hash and preview; stdout/stderr are not retained. Lists and remote/read-only views redact scripts. Do not put secrets in scripts: reference target-side files instead. Interrupted work becomes `needs-inspection`, never an automatic replay.

Unrestricted shell runs `/bin/sh` as the configured account, with no password automation, new sudo permission or command allowlist. Foreground timeout is 1–240 seconds; scripts and each output stream are bounded to 16 KiB. Detached effects may outlive the deadline. This is a trusted-operator coordination tool, not a hostile-code sandbox.

## Fleet key management

`fleet_key_hosts` is separate authority. Modern OpenSSH/Ed25519 and Python 3 are required; discovery never enrolls a member. Inspect actual legacy-host capabilities rather than weakening fleet-wide cryptography.

Each host creates its own identity under `~/.ssh/switchyard/`; private keys never leave it. Public metadata, inspected revisions, desired membership and retirement progress live in the private journal. The workflow is inspect → expiring plan → approval → leased application → directed connection verification.

Only managed authorized-key blocks and dedicated client config/pins are changed. Manual keys and main SSH configuration are preserved; unsafe ownership, aliases and conflicting entries fail closed. Rotation verifies the new mesh before withdrawing old grants; retired private files remain locally. Removal checks every recorded generation. Offline is pending, not proof of revocation. Multi-host changes are not atomic; inspect and explicitly reconcile uncertainty.

```sh
ssh -F ~/.ssh/switchyard/config switchyard-host-a
```

Membership grants account access, not sudo, operation authority or device leases. A compromised member can use its peer grants.

## Existing-service lifecycle authority

Definition promotion is descriptive. A separate policy grant targets one exact systemd/Quadlet service or a complete existing Compose project. Supporting bindings are not extra control targets.

`inspect_workload` contacts the configured host under its lease. Evidence expires after 120 seconds; cached reads never renew it. Plans bind the inspection and authority. Execution rechecks definitions, ownership, dependencies, native identities and state under the lease before start/stop/restart.

These adapters never deploy, recreate, enable, reload, pull or migrate. Unsupported activators, conflicting owners and ambiguous provider capabilities are refused. System scope grants no new privilege. Native running state is not application health. See [deployment](deploy.md) for separately owned workloads and [authentication](auth.md) for HTTP access.
