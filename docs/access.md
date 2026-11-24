# Device access broker

## Boundary

Switchyard coordinates device access through one private SQLite lease database
on the control host (`<state-dir>/leases/leases.sqlite3`). Granting a device
reserves it and records the claim in a short transaction. No transaction or
file lock stays open for the duration of the work. A lease is coordination,
not operation approval or device-side fencing.

Existing collector `ledger` fields identify historical resource labels.
Registry aliases for the same label share the same reservation. They no longer
require a file to exist or grant access through an open descriptor.

## Required gateway contract

1. Resolve requests to trusted registry resource identities and connection data.
2. Verify approval separately. Read-only device access still takes a lease.
3. Acquire required resources in a consistent order. If any acquisition fails, no dispatch occurs; release previously acquired grants.
4. Commit the claim before dispatching work. Never hold a device lease during builds.
5. Only release the matching lease ID once the command has confirmed completion.
6. If transport or process death leaves completion unknown, keep the reservation. Do not retry.

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

`run` keeps working directory and stdio on the caller and exports connection
metadata. Ordinary child exits (including a confirmed failure) release.
Disconnects, signals, lost process identity, and deadlines without completion
make a lease **suspect**, not free. Hold TTL defaults to 60 minutes and is
capped at 120; crossing it does not prove the user stopped touching the device.
Busy exits 75, including blocked and suspect devices. `--wait` is bounded to
600 seconds. The CLI, MCP, and keyed HTTPS lease entry points share the store.

Operator-only `lease break` can quarantine an unresolved grant. Use
`lease clear --attest-stopped ...` only after checking that the previous work
really ended. No API can infer a remote command stopped just because the
coordinator or SSH process disappeared. There is no raw-file fallback.

## Android and additional gates

Configure the immutable USB serial, exact user/profile and package scope yourself; no real-device allowlist is bundled. SDK lookup is `ANDROID_HOME`, then `ANDROID_SDK_ROOT`, then `~/Android/Sdk`, using only `platform-tools/adb` beneath that root. Commands select the exact serial and disconnect stdin in scripts. Collection uses an already-running local ADB server and registered transport; it never starts/restarts the server, discovers/connects wireless devices, installs packages or sends UI input.

Device-specific maintenance/relay gates must still coordinate with their own
runtime. Keep independent host build locks separate. A stale backup is not
authority: it cannot prove that newer work stopped.

## Migrating an existing authority

1. Replace direct file consumers and upgrade installed SSH clients before they
   can acquire a SQLite-backed lease. Older clients may assert completion
   after a lost command; do not mix versions on the same devices.
2. Stop and fence all old writers (CLI/MCP ingress, desks, monitor, scheduled
   work). Confirm that no legacy holder remains. Do not copy ledgers and run a
   second authority.
3. Back up the private state and the legacy ledgers. With the same original
   `SWITCHYARD_LEDGER_DIR` and `--state-dir`, run `switchyard lease migrate --dry-run`.
   Review the unresolved and blocked devices; neither is silently cleared.
   Include a `--legacy-ledger LABEL=/absolute/path` for each explicitly
   configured ledger outside the legacy directory. Use the same list on apply.
4. From the operator terminal run `switchyard lease migrate --confirm-drained`.
   The import preserves history and unresolved leases; it does not modify
   legacy files. Start only the new authority and verify the lease list first.

Do not reopen an old backend as rollback after new grants. On restore or
failback, fence all writers and reconcile all work newer than the snapshot
before enabling grants. An expired deadline is not a completion receipt.

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
