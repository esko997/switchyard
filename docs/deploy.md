# Deployed workloads

Switchyard creates container workloads from stored templates and owns them by an explicit ownership ID. The deploy adapter currently supports one application/component/Pod/container on one host, using the workload-spec `podman-pod-v2` subset and a rootless Quadlet `.kube` unit. General multi-component migration, secret delivery and arbitrary host networking remain outside this executor.

Configuration refreshes, explicit template upgrades, policy-granted host devices, detached image pulls, datasets by sub-path, readiness windows and exclusive-resource switching are described below. Supporting a field in the declaration schema does not imply this executor can execute it.

Code: `switchyard/deploy.py` (rendering, plans, operations, worker, CLI),
`switchyard/deploy_config.py` (parameters, `{{parameter}}` substitution, generators; pure),
`switchyard/deploy_remote.py` (fixed remote program, stdlib only),
`switchyard/workload_store.py` (the workload store, which holds the journal). Tests: `tests/test_deploy.py`.

## The workload store

Deployed instances are `deployed` records of the one workload store (see
[domain model](domain-model.md#the-workload-store)): `deploy.sqlite3` beside the operation
journal (`<state>/operations/<catalog-hash>/`), tables `workloads` (current record) and
`workload_revisions` (every revision, byte for byte). The deploy journal's own state
stays in the same database: `placements` (generation, state, compare-and-swap revision),
`claims` (port registry), `verifications`, `tokens` (start tokens of registered
applications) and `templates`. Instance, registration and observed-workload IDs share one
namespace: a deploy cannot reuse an observed or registered ID and vice versa.

## Authority

- Operations policy key `deploy_hosts` (list of enrolled SSH host IDs, or local targets)
  grants deploy/fence/start/stop/undeploy on those hosts. It is separate from
  `shell_hosts`, workload lifecycle and `fleet_key_hosts`. Without it everything except
  `spec validate`, template storage and listing is refused.
- Operations policy key `deploy_devices` (`{"<deploy host>": ["/dev/..."]}`) lists the host
  devices a deployment may be given on that host ([GPU workloads](#gpu-workloads)). A
  device a template declares but the policy does not grant blocks the plan; withdrawing a
  grant refuses later `start`, `unfence` and switches (fence, stop and undeploy stay
  available). The grant is part of the plan's authority fingerprint only for hosts that
  have one, so existing fingerprints are unchanged.
- Only instances in the deploy journal are touched, and on the host only resources that
  carry their ownership ID: the `owner.json` marker, unit/YAML files whose SHA-256 equals
  the recorded hash, the token with this deployment's identity, and pods labelled
  `io.switchyard/ownership-id`. Adopted workloads (lifecycle adapters) are never touched.
- Every host step runs in the operation worker while it holds the host's canonical
  device lease. Plans expire after 10 minutes and bind the authority fingerprint
  (deploy hosts, host connection, local target). Execution requires `--approve` and a
  request ID; the same request ID returns the same receipt; non-idempotent steps are
  never retried; unknown outcomes are `needs-inspection`.

## Host layout (rootless account)

| Path | Mode | Content |
|---|---|---|
| `~/.config/containers/systemd/switchyard-<instance>-<component>.kube` | 0644 | Quadlet unit with the generation gate |
| `~/.local/share/switchyard/apps/<instance>/<component>.yaml` | 0644 | Pod manifest (JSON, which is YAML 1.2) |
| `~/.local/share/switchyard/apps/<instance>/<component>.token` | 0600 | Generation token |
| `~/.local/share/switchyard/apps/<instance>/owner.json` | 0600 | Ownership marker (ID, instance, component, generation, uid) |
| `~/.local/share/switchyard/apps/<instance>/generation` | 0600 | Host generation high-water mark (kept after undeploy) |
| `~/.local/share/switchyard/apps/<instance>/data/<dataset>/` | 0755 | Default dataset directories |
| `~/.local/share/switchyard/apps/<instance>/config/<component>/` | 0755 dir, 0644 files | Configuration files, mounted read-only (`config://<component>`); removed at undeploy |

Native names: unit/service/pod `switchyard-<instance>-<component>` (at most 63 characters:
the pod name is the pod hostname), containers `<pod>-<container>`. Files are written
atomically (temp file + `link`, never replacing an existing name; tokens by rename).

Labels on the pod and every container (Podman copies pod `metadata.labels` to
containers): `io.switchyard/ownership-id`, `io.switchyard/instance`,
`io.switchyard/component`, `io.switchyard/generation`. Labels under `io.switchyard/`
are reserved; templates may not set them.

## Fail-closed generation gate

The generated unit contains a check of the token file's **first line** (and nothing else):

```ini
[Service]
ExecStartPre=/bin/sh -c '[ "$$(head -n 1 -- "/home/<user>/.local/share/switchyard/apps/<instance>/<component>.token")" = "switchyard-generation-token/v1 application=<instance> component=<component> generation=<N> ownership-id=<uuid>" ]'
```

(`$$` is systemd's escape for a literal `$`.) Quadlet copies it into the generated service
ahead of `podman kube play`, so every systemd start path (Switchyard, manual
`systemctl --user start`, `default.target` at boot, `Restart=`) refuses to start unless line
1 of the token file is exactly that identity line. Revocation rewrites line 1 as
`switchyard-generation-token/v1 revoked …` plus `revoked_at=`; a missing token also refuses.
No Switchyard connectivity is needed. The same check is used for adopted applications'
start tokens ([tokens.md](tokens.md)).

Legacy units using whole-file `grep -qxF` checks can accept a valid token appended below a revoked first line. Verify the journaled gate and use an explicit redeploy/upgrade to install the first-line form. Verification compares against the recorded native hash, not the newest generator output. The Quadlet dry run and generated-fragment check require the intended gate verbatim.

Not gated: direct `podman kube play` on the YAML, a filesystem rollback restoring an old valid token, or a hand-copied token. Fence stops the unit and verifies its pod/containers gone. A restored valid token can reopen starts until `deploy verify` detects drift; re-running `deploy fence` explicitly re-enforces it. This is **detection on contact**, not prevention or distributed fencing.

## Placement states

| State | Token | Running | Reached by |
|---|---|---|---|
| `staged` | valid | no | `unfence`, `stop` (boot/manual start possible: fence to prevent) |
| `staged` | revoked/absent/unknown | no | apply that failed after writing files |
| `active` | valid | yes (health verified) | `apply`, `start` |
| `fenced` | revoked | no (verified) | `fence` (again on a fenced placement: re-enforced) |
| `retired` | removed | no | `undeploy-apply` |

`active` and `fenced` records carry a spec `FenceRecord` (journal and host generation,
token with evidence for the declared `generation-gate` incl. the unit hash, activators,
stopped native IDs, evidence). Staged records carry no fence record. `uncertain: true`
(after transport loss or an unverified cleanup) blocks `start`/`stop`/`unfence`;
`fence` and `undeploy` remain available as recovery. Each placement record is
checked against its instance application (`spec.check_placement`, workload spec
`switchyard/v1alpha3`) before it is journaled.

## Routine lifecycle

Use **Workloads → Manage** in the desk, or the generic operation interface:

```sh
switchyard plan-operation restart garden
switchyard execute-operation PLAN_ID --approve --request-id garden-restart-1
```

The same interface offers `start` and `stop`. Stop proves the workload down and fences it,
keeping its files and reservations but releasing its exclusive resources. Start checks those
resources and starts only the selected workload; it never stops another holder. Restart requires
an active deployment and performs the stop, start and health checks under one lease and receipt.
These operations use the recorded placement, not a target supplied by the operator.

The low-level `deploy stop` and `deploy unfence` commands below deliberately retain their
separate token semantics.

## CLI

All commands print JSON. Exit 2 on a user error (the parent CLI maps `ValueError`).

```sh
switchyard spec validate FILE                     # Application/Placement/ActivationInput/Bundle: hashes or errors
switchyard template save catalogs/templates/static-web.json --expected-revision 0
switchyard template list
switchyard template show static-web[@1]

switchyard deploy plan --template static-web[@REV] --instance garden --host destination \
    [--port http=18100] [--address http=127.0.0.1] [--dataset site=/abs/existing/dir] \
    [--param NAME=VALUE] [--record NAME=ADDRESS]
switchyard deploy apply PLAN_ID --approve --request-id garden-apply-1
switchyard deploy list | show garden | claims
switchyard deploy fence garden                    # preview only
switchyard deploy fence|unfence|start|stop garden --approve --request-id ID
switchyard deploy verify garden [--request-id ID]  # leased, read-only: host vs journal
switchyard deploy verify --all                     # every non-retired placement, one lease per host
switchyard deploy undeploy-plan garden [--delete-data]
switchyard deploy undeploy-apply PLAN_ID --approve --request-id ID
switchyard deploy plan --instance garden --host destination   # redeploy a retired instance: generation N+1
switchyard deploy refresh-plan lan-dns [--param upstreams=192.168.50.1] [--record test-record=192.168.50.250] \
    [--remove-record NAME]                       # re-render config files; leased read-only diff against the host
switchyard deploy refresh-apply PLAN_ID --approve --request-id ID
switchyard deploy plan ... --fenced               # install with a revoked token, start nothing (second GPU holder)
switchyard deploy switch-plan TARGET [--restore-on-failure]   # move an exclusive host resource; leased read
switchyard deploy switch-apply PLAN_ID --approve --request-id ID
switchyard deploy pull-start --host H (--image REF | --template T) [--approve --request-id ID]   # detached pull
switchyard deploy pull-status --host H (--image REF | --template T)                              # leased read
switchyard deploy pulls                           # journaled pulls, no host access
```

Template revisions are immutable and content-hashed; `save` is compare-and-swap on the
latest revision (0 for a new template) and the file must declare revision latest+1.
Templates declare no gates. A new instance stores a complete application (not an
overlay) with `template_ref {id, revision}`, `role: instance`, the pod name set to the
native name, the image pinned to the resolved digest and exactly one declared gate:
`generation-gate`, kind `exec-start-pre`, target the generated service. Instance IDs
are unique across the whole workload store and may not reuse a registered adopted
application's ID ([registration](spec/workload.md#registration-of-adopted-applications)
grants no deploy authority) or an observed workload's ID. Redeploy normally uses the
stored instance application; changing its template revision requires an [explicit upgrade](#upgrade-a-template-revision).

Stored `switchyard/v1alpha2` rows (templates, instances, placements written before
2026-11-23) load through an in-memory upgrade; their stored bytes and hashes are not
rewritten (`template show` reports `upgraded_from` and the original hash). Redeploying
a retired v1alpha2 instance plans `instance_upgrade`: apply stores the v1alpha3 form
with its generation gate as instance revision N+1 and the new placement references
it. Instance revisions are immutable: every revision's exact stored document and
hash stay in `workload_revisions` (instances journaled before the workload store were
copied there by its seed), so retired placements keep resolving their revision:
`switchyard deploy show INSTANCE@REVISION`; `deploy show INSTANCE` lists revisions and
each generation's application revision. If nothing is written on the host, the new
revision is withdrawn with the rest of the journal intent. `spec validate` and
`template save` accept v1alpha2 input the same way.

## Verify (detection on contact)

`deploy verify INSTANCE` runs one leased, read-only operation through the broker
(receipt kind `deploy`, action `verify`). It observes the host and compares it with the
journal placement: unit load/active state, the pod named for the deployment and its
ownership labels, containers labelled with the ownership ID or the generated unit,
the token file (valid/revoked/absent/foreign for the recorded generation and ownership
ID), `owner.json`, the host generation mark, and the unit/YAML hashes against the
journal. It runs no start, stop, reload, pull or write on the host and does not change
the placement (state, revision, meta). The result is recorded per placement in a
separate journal table, so it never invalidates an outstanding plan; `deploy show`
returns `last_verification`, `deploy list` returns `last_verified {verified_at,
consistent, drift, info}`.

`consistent` is true only when the host was observed and there is no drift finding.
Finding codes (stable):

| Code | Severity | Meaning |
|---|---|---|
| `running-while-fenced` | drift | unit active/activating, pod running or a labelled container running on a `fenced` placement |
| `valid-token-while-fenced` | drift | the token file holds the valid identity line on a `fenced` placement (restored/rolled back): every start path is open |
| `running-while-staged` | info | running on a `staged` placement: a manual or boot start through a valid token, allowed by design |
| `token-mismatch-while-staged` | drift | host token state (valid/revoked/absent) differs from the journal on a `staged` placement |
| `stopped-while-active` | drift | nothing running on an `active` placement |
| `token-missing-or-revoked-while-active` | drift | no valid token on an `active` placement (the next restart/boot is refused) |
| `ownership-mismatch` | drift | `owner.json`, token file or pod labels belong to someone else (or are unreadable) |
| `native-files-changed` | drift | unit or YAML missing/hash differs from the journal, or `owner.json` missing |
| `config-files-changed` | drift | a configuration file is missing, unreadable or differs from the journal hash, or an unexpected file sits in the configuration directory |
| `health-check-failed` | drift | an `active`, running placement failed one of its declared health checks (one attempt each, inside a 30 s budget per remote call) |
| `host-generation-ahead` / `host-generation-behind` | drift | host high-water mark above / below (or missing) the journal generation |
| `unreachable` | unknown | host not observed (transport loss, remote failure, busy lease): receipt `needs-inspection` (`busy` for a lease), never consistent |
| `devices-changed` | drift | a running container's devices (read from its OCI runtime configuration) differ from the journaled device set |
| `exclusive-resource-contended` | drift | two placements on the host that declare the same host-scoped exclusive resource are both running or hold a valid token |
| `operation-interrupted` | drift | the placement still carries the journaled intent (`pending`) of an operation that did not finish (crash, killed worker); the receipt's status is named |

Verify reports; it repairs nothing. Act on drift explicitly: `deploy fence` for
anything running or holding a valid token that should not. Fence and undeploy refuse
to touch resources whose ownership or hashes do not match, so ownership or file drift
needs operator inspection first. A busy lease is reported but not recorded (the previous
verification stays). The same `--request-id` returns the same receipt and result.
`deploy verify --all` verifies every non-retired placement: hosts sequentially, exactly
one lease and receipt per host. Inside that lease the worker observes placements in
batches of 16 per remote call (60 s each) under the operation's overall deadline; a
batch that fails or misses the deadline marks its placements `unreachable` and the
receipt `needs-inspection`, while the other batches still report. At most 256
placements per host per operation; a host above that, or without deploy authority, is
listed with its error.

**Re-fence.** `deploy fence` on an already `fenced` placement is allowed and redoes the
enforcement: verify ownership, stop the unit, prove pod and containers are gone, rewrite
the token as revoked, record a fresh fence record. Its evidence starts with
`re-enforced fence on an already fenced placement (host had drifted)` or `(host was
already clean; no-op with fresh evidence)` and records the state found before (unit,
pod, token). Request-ID idempotency and receipts are unchanged.

## Plan

`deploy plan` runs one leased **read-only** inspection (receipt kind `deploy`, action
`plan-inspect`): account facts, Podman version/rootless, `systemctl --user` state,
linger, architecture, a Quadlet `-dryrun -user` of the exact rendered unit in a private
temp directory (proves the gate survives generation), name collisions (Quadlet sources
and `.service` in user search paths, loaded unit, pod, container names, application
directory), dataset directories, listening sockets (`/proc/net/{tcp,tcp6,udp,udp6}`), the
host's interface addresses (`ip -j address show`), `net.ipv4.ip_unprivileged_port_start` and
the host generation mark. Image tags resolve without pulling: `skopeo inspect --raw` if
installed, else the anonymous registry v2 API (manifest bytes hashed; header must agree),
else the local image store (warning), else **pull at apply**: apply pulls the tag, pins
the digest it observed, re-renders the YAML and records the hashes in the receipt.

The plan contains the complete instance application and its hash, rendered unit and
YAML text with hashes, token path, gate command, port claims, dataset bindings, health
checks, the rendered configuration files (`native.config`: text, size, SHA-256;
`config_files`: path, size, hash and generator output with skipped hosts), LAN exposure
items, every precondition with evidence (`blocking` ones make the plan
non-executable; it is then returned but not stored), warnings (linger off, local-store
digest), the approvals (configured `deploy_hosts` authority + explicit plan approval,
which lists every LAN exposure; no destructive checkpoint at deploy) and the steps.
Executable plans reserve their port claims until they expire or are applied.

## Apply

Under the host lease the worker rechecks authority from the live operations file,
account facts and the journal, then:

1. pulls the image by digest (or tag, see above) and verifies digest and platform;
2. journals intent: instance (new), `staged` placement, plan reservation → placement claims;
3. `prepare`: rechecks collisions, live ports, that every claimed non-loopback address is
   still assigned, and the host generation; creates the application directory,
   `owner.json`, generation mark, default dataset directories, the configuration directory
   and files (exact planned bytes, hashes verified), YAML, valid token and finally the
   `.kube` unit; `daemon-reload`; verifies the generated unit loaded from that source with
   the gate line, and the file hashes;
4. `start`: `systemctl --user --job-mode=fail start`, verifies the pod's ownership labels,
   runs the spec's http/tcp/dns health checks against the claimed bind with retries inside
   one bounded step;
5. records `active` with native identities (service invocation, pod and container IDs).

If nothing was written (drift, collision, busy port), the journal intent is withdrawn
and the instance ID stays free. If a step fails after writing, the remote step stops the
unit, proves pod and containers are gone, revokes the token and the placement stays
`staged` (receipt `failed`); if that cleanup cannot be verified or the transport is lost,
the receipt is `needs-inspection` and the placement `uncertain`. Never retried.
This includes start refusals before `systemctl start` (for example a listener that
appeared after `prepare`): apply still proves nothing runs and revokes the token. The
journal records `runtime` and token state only from that observed cleanup evidence;
anything unobserved is `unknown` and marks the placement `uncertain`.

## Undeploy

`undeploy-plan` verifies ownership on the host (read-only) and lists what will be
removed, the claims to release and every dataset with its size. With `--delete-data`
only **Switchyard-created** default dataset directories are deleted (destructive
checkpoint, shown separately); operator-provided `--dataset` directories are never
deleted. Apply re-verifies ownership, stops the unit, proves pod/containers gone,
revokes the token, removes the unit, reloads, verifies the service is gone, removes YAML,
token, `owner.json` and the recorded configuration files (and their directory when
empty), releases claims and records `retired`. The application directory
keeps `generation` (and kept data); the template and instance records remain, so the
instance can be redeployed as generation N+1 reusing retained data.

## Upgrade a template revision

Save the new revision, then plan the replacement of the existing instance. An upgrade
must name an explicit higher revision of the **same** template.

```sh
switchyard deploy upgrade-plan INSTANCE --template TEMPLATE@REVISION
switchyard deploy apply PLAN_ID --approve --request-id UNIQUE_ID
```

The plan keeps the instance ID, host, bound addresses and ports, dataset paths, display
name, and compatible parameter values (including inherited defaults from the old
revision). Pass `--param ID=VALUE` to pick a new value. It carries forward operator DNS
records and non-conflicting local config overrides. Removing a bound endpoint or
dataset, changing its protocol, or replacing the native component ID needs a separate
migration. Review `template_upgrade` in the plan for old/new revisions, port claims and
exclusive resources, and review the new rendered files and device grants.

Apply verifies the new image and rechecks the old generation before it stops anything.
Under one host lease it revokes the old token, removes only that generation's owned
runtime files, and installs generation N+1. It never deletes or migrates datasets.
Active instances have downtime and must pass health checks again; fenced instances
remain fenced and staged instances are not started. If the replacement fails after
removal, inspect the receipt and the recorded placement before recovering. Switchyard
does not automatically roll back a template or dataset writes.

For a retired instance, `deploy plan --instance INSTANCE --host HOST --template
TEMPLATE@REVISION` plans a higher revision using its previous bindings on that host.
Omit `--template` to redeploy its currently stored application unchanged. Retired
records and host generation marks are deliberate: do not purge them as orphan files.

## Port registry

Claims key: host, address family/address, protocol, port. Wildcards (`0.0.0.0`, `::`)
conflict with every address on that port and protocol (conservative dual-stack).
Placement claims are held by staged/active/fenced placements and released only at
retirement (unknown outcomes keep them). Plan reservations last until the plan expires
or is applied. Live listeners are checked at plan time and again immediately before
writing; unmanaged listeners are visible only through that live check. Without
`--port`, the plan picks the first free port in 18100–18999. Default bind 127.0.0.1.
Endpoints that share a container port with different protocols (DNS on UDP and TCP)
are separate claims on the same host port: the registry key includes the protocol, and
without `--port` the plan picks the first port free for every protocol of the group.

**LAN exposure.** A claim on a non-loopback address is listed in `lan_exposure` (claim,
interface, network, "reachable from every host on <network>; Switchyard changes no
firewall") and in the plan approval. Blocking precondition `address-<endpoint>`: the
address must be assigned on the host (`ip -j address show`; unknown addresses block). A
wildcard claim lists every network of the host. Live listeners on the same port and
protocol at that address **or a wildcard** block the claim (`port-<endpoint>`).

**Ports below the unprivileged range.** Rootless Podman binds host ports from the
account's own processes (`rootlessport`), so a port below the host's
`net.ipv4.ip_unprivileged_port_start` (default 1024) fails at start. Blocking
precondition `unprivileged-port-<endpoint>` names the operator command (Switchyard never
runs sudo):

```sh
printf 'net.ipv4.ip_unprivileged_port_start=53\n' | sudo tee /etc/sysctl.d/60-unprivileged-ports.conf && sudo sysctl --system
sudo sysctl -w net.ipv4.ip_unprivileged_port_start=53     # alternative: until reboot
```

Meaning: every unprivileged process on that host may then bind TCP and UDP ports from 53
upward (IPv4 and IPv6, host network namespace); ports below stay privileged.

## Configuration files and parameters

Templates may declare `parameters` and `config_files` ([spec](spec/workload.md#application-resources)).

- **Parameters** are set at plan time for a new instance (`--param zone=lab.home.arpa`) and
  validated by their declared `format`; a template `default` applies when no value is
  given; a referenced parameter without either refuses the plan. The instance application
  records the values. Use `refresh-plan` for configuration-only changes or
  `upgrade-plan --param` to change a value as part of a template upgrade.
- **Substitution** is exactly `{{parameter-id}}`, in file content, a generator `zone`,
  DNS check names/answers, and container args, env values and volume `subPath`
  ([GPU workloads](#parameters-in-the-pod-datasets-by-sub-path)). Nothing else is
  interpreted; any other `{{`/`}}` and any secret reference is rejected when the template
  is saved.
- **Generator `registry-hosts`** writes an alias for each registry ID with an IP-literal SSH
  target. After verifying the connection, it also uses the short hostname reported by the
  host (for example `source` → `192.168.50.10 source.lab.home.arpa`). Local, ADB, and
  hostname-only connections do not establish a LAN IP; use an explicit record if needed.
  Existing explicit records and registry-ID aliases are never taken over by a hostname
  alias; collisions are shown in `generated.skipped`. Operator records are stored in the
  instance application and survive regeneration. New records cannot take a registry name.
- **Rendering** happens at plan time; the plan carries each file's text, size and
  SHA-256; apply writes exactly those bytes (at most 16 files, 64 KiB each, 512 KiB
  together, so one remote payload always fits the transport bound). The journal
  keeps paths and hashes (not texts). Files are written atomically into
  `apps/<instance>/config/<component>/` (directory 0755, files 0644, so a non-root
  container user reads them through the rootless user namespace like the static-web
  `site` dataset) and mounted read-only as a directory, so an atomic rename is visible in
  the container.

## Refresh (configuration of a placed instance)

`deploy refresh-plan INSTANCE [--param …] [--record NAME=ADDRESS] [--remove-record NAME]`
re-renders every configuration file against the current registry, parameters and records,
requires the rendered unit and Pod YAML to equal the journal (image, ports and datasets
cannot change), then reads the host under its lease (read-only: ownership, unit/YAML
hashes, every recorded file's hash and the text of the files that change). The plan shows
per file `unchanged`/`update` with journal, host and new hashes and a unified diff
(`host/…` → `plan/…`), the effect (`restart` when an active unit's changed file declares
`on_change: restart`; otherwise none: the service reloads by itself, or the unit is not
running), the health checks, and what stays unchanged (generation, start token, unit and
YAML). Blocking: `ownership`, `config-files-match-journal` (a hand-edited file is never
overwritten silently, and an unexpected file in the configuration directory blocks too:
it is the same drift `deploy verify` reports, is never removed by Switchyard, and must be
dealt with by the operator first), `changes` (nothing to write). Uncertain placements are
refused.

`deploy refresh-apply PLAN --approve --request-id ID` under the host lease re-verifies
placement revision, state and instance revision; journals intent (`pending` with the new
hashes); the remote step re-verifies ownership, that every file still matches the journal
and that no unexpected file has appeared in the directory since the plan (otherwise
nothing is written), replaces each changed file by rename and verifies it, restarts the unit if
declared, verifies the pod's ownership labels, and runs the health checks when the unit
is active. The worker then records the new configuration, the new instance revision (when
parameters or records changed) and a new placement revision in one transaction. The
generation and token do not change. Outcomes: nothing written → `failed`, journal
unchanged; files written but a health check fails → `failed`, configuration recorded,
service left running (verify will report it); restart fails → the unit is stopped and
proven down, placement `staged` with a valid token (`deploy start` after fixing);
transport loss, or any failure once the write phase started (a rename can land before its
fsync or hash check fails) → `needs-inspection`, placement `uncertain`, `pending` keeps the
intended hashes. Never
retried; the same request ID returns the same receipt.

## DNS health check

`type: dns` sends one query (stdlib, random ID, recursion desired) to the claimed address
and port over the endpoint's protocol (UDP; TCP with length prefix) and passes on NOERROR
with at least one answer of `record_type` and every `expect` value. Apply and refresh
retry it until their step deadline; verify runs one attempt per check for `active`
placements. A reply with another ID is ignored; truncated, malformed and refused replies fail.

## LAN DNS template (`coredns-lan`)

`catalogs/templates/lan-dns.json`, template ID `coredns-lan` (an instance may not share
its template's ID, and the instance is called `lan-dns`): `docker.io/coredns/coredns:1.15.0`
(digest at plan), uid/gid 65532, read-only root filesystem, no privilege escalation,
container port 5353 for endpoints `dns-udp` and `dns-tcp`, `-conf /etc/coredns/Corefile`.

- Zone `{{zone}}` (parameter, no default): `hosts` plugin on the generated hosts file
  (`reload 5s`, `ttl 60`, `fallthrough`) followed by a SOA-only `file` zone, so unknown
  names get NXDOMAIN with a SOA and are never forwarded (the hosts plugin alone answers
  SERVFAIL). Reverse lookups for the same addresses come from the hosts file.
- Everything else: `cache 300`, `forward . {{upstreams}}`; supply explicit resolver addresses with `--param upstreams="ADDRESS ADDRESS"`. There is no baked-in resolver default.
- `errors` only, no `log` (no query log); no health, ready or metrics listener.
- The hosts file is `on_change: none` (CoreDNS rereads it within 5 s, the listener stays
  up); Corefile and zone file are `on_change: restart`.
- Capabilities: the image's `/coredns` carries file capability
  `cap_net_bind_service=+ep`; with **every** capability dropped the bounding set is empty
  and `execve` can fail with EPERM. The template
  therefore drops every capability except `NET_BIND_SERVICE` by name; with
  `allowPrivilegeEscalation: false` (no_new_privs) and uid 65532 the process has no
  effective capability; inspect the actual container capability sets on the target.
- Health: `zone-soa-udp` and `zone-soa-tcp` query `{{zone}} SOA`.

### Serving DNS on port 53

First inspect the target's resolver and all listeners. A loopback-only resolver does not necessarily collide with a specific LAN-address claim; wildcard listeners can. Rootless port 53 requires a separately approved host privilege setting described above. Plan both protocol claims explicitly with `--port dns-udp=53 --port dns-tcp=53` and their assigned LAN addresses. Router DHCP and client resolver configuration remain outside deployment authority.

Ports cannot change by configuration refresh; use an explicit retirement/redeployment plan. Never assume a resolver returning NXDOMAIN will fall back to another configured server.

## Publish a LAN URL

In the desk, sign in as the operator and open **LAN URLs**. The list shows the hostname,
workload endpoint, and upstream; **Publish LAN URL**, **Edit**, and **Remove** prepare a
plan. Review the changes to Caddy and CoreDNS before approving. Published addresses appear
on workload rows. A URL can outlive a stopped workload; publication does not start it.

**Add DNS record** publishes just an IPv4 (`A`) or IPv6 (`AAAA`) address inside the zone,
without configuring or restarting Caddy. Edit and remove manual records from the same page.
Switchyard lists generated host records separately; change their source in the host registry,
not in the DNS editor.

Publication is opt-in (`<catalog basename>.lan-routes.json` beside the catalog). The private
file selects the existing `caddy-lan` and `coredns-lan` deployments, the DNS zone, and the
Caddy CA fingerprint. The gateway uses the private LAN address on TCP 80/443 and persists its TLS state.
Users must trust its CA and resolve the zone through CoreDNS. Use it as the DHCP DNS server
(or send this zone to it via split DNS); a second resolver that does not serve the zone can
return `NXDOMAIN` instead of falling back.

**Candidates come from workloads.** Declare `scheme: http` or `scheme: https` on the
application's TCP endpoint and bind it to an exact private IPv4 address and port in its
placement. For an observed service, declare both under **Web endpoints** when you
first **Define workload**, or change them later with **Edit definition**.
A registered application uses its bundle's declarations;
a deployment uses its current placement. Older applications with an unambiguous HTTP
check can still supply the scheme. No check has to run to list candidates.
Loopback, wildcard, non-web and ambiguous targets are not eligible. An adopted endpoint's
address must match its registry host. Selecting a target plans a change; saving an
endpoint never writes Caddy or DNS.

Use `upstream_policies` in the private LAN URL config for per-endpoint proxy policy, not
for addresses. For example, a verified HTTPS upstream needs a trusted CA already in the
gateway deployment's config files:

```json
{
  "upstream_policies": [
    {
      "workload_id": "desk",
      "endpoint_id": "https",
      "profile": "verified-https",
      "ca_file": "desk-ca.pem",
      "hostnames": ["desk.example.test"]
    }
  ]
}
```

`hostnames` is optional and constrains the public names; it does not change the backend's
Host or Origin checks. Existing `observed_endpoints` entries keep their behavior for
existing installations. Do not add a second address entry for new workload declarations.
Caddy does not add authentication to the backend.

To adopt existing records, the operator supplies the exact existing Caddyfile SHA-256
and a reviewed mapping of DNS names to endpoints. Switchyard checks the mappings against
the deployed gateway and DNS journal before saving the registry. Adoption itself makes no
host changes. Standalone DNS records stay independent of gateway routes.

Apply uses leased deployment refreshes. It prepares and verifies new Caddy routes over
HTTPS before publishing DNS, and withdraws DNS before removing old proxy routes. Proxy
verification checks the selected hostname, pinned CA, and route marker without sending
requests to the backend. The DNS change is checked over UDP and TCP against CoreDNS itself.
Caddyfile updates can restart the gateway; CoreDNS hosts updates hot-reload, and cached DNS
answers can outlive a change. If an apply stops partway through, inspect the receipts and use
**Resume** to review and approve the remaining work. No automatic mutation retries.
Do not rewrite managed proxy/DNS records outside LAN URLs; a changed baseline can block an apply.

For catalogs with LAN URLs configured, `tools/install-services.sh` enables the
`switchyard-lan-dns-sync.timer` user unit. About once a minute it reconciles the registry into
the active CoreDNS deployment. Unchanged records require no remote access. Changes take the
DNS host's usual deployment lease, are audited as deployment refreshes, and hot-reload only
the generated hosts file. An unfinished LAN URL change blocks automatic refresh; it never
bypasses deployment authority or overwrites host drift. `switchyard lan-dns-sync --dry-run`
previews records and skipped hosts without contacting the fleet.

## Static-web template

`catalogs/templates/static-web.json`: `docker.io/nginxinc/nginx-unprivileged:1.28.0-alpine`
(digest resolved at plan), container port 8080, endpoint `http` (default
127.0.0.1, port chosen at plan), HTTP health check `GET /` → 200, uid/gid 101, no
privilege escalation, all capabilities dropped, no secrets. The optional content dataset
`site` is mounted read-only at `/usr/share/nginx/html/site`, so the image's own page keeps
the health check meaningful while the site is empty; content is served under `/site/`.
Bind existing content with `--dataset site=/abs/dir` (read-only, never deleted).

## SearXNG template

`catalogs/templates/searxng.json` runs the pinned upstream image as a rootless
CPU-only Pod. Switchyard mounts `settings.yml` read-only; HTML and JSON search
are enabled. The signing key is generated on each container start. No persistent
dataset or Valkey is needed for private LAN use. There is no authentication or
rate limiter; bind only to a trusted LAN address, never a public interface.

The health check uses `GET /` so an upstream engine outage does not mark the
service dead. Verify search separately with
`curl -fsSG http://HOST:PORT/search --data-urlencode 'q=Debian release notes' --data-urlencode 'format=json'`.
In Open WebUI, select the `searxng` engine and set **SearXNG Query URL** to
`http://HOST:PORT/search`. Open WebUI adds the query and JSON parameters.

## GPU workloads

GPU deployments combine policy-granted devices, explicit model datasets, bounded readiness checks and exclusive host-resource identities. Code lives in `deploy.py` and `deploy_remote.py`; schema fields are described in [the workload specification](spec/workload.md#application-resources).

### Device access

A template declares the devices a container needs (`devices: [{id, component, container,
host_path, container_path, access, description}]`); the operations policy grants them per
host (`deploy_devices`). Rendering: each device becomes a `hostPath` volume of **type
`CharDevice`** named `switchyard-device-N`, mounted at the container path. `podman kube play`
turns such a volume into a device (`pkg/specgen/generate/kube`, present since Podman 4.2.0;
read in the 4.9.3, 5.4.2 and 6.2.0 sources); rootless Podman then bind-mounts the node
read-write with `nosuid,noexec` (`pkg/specgen/generate/config_linux.go`, `addDevice`). A
CharDevice volume always asks for `rwm`, so `access: read` is refused at plan time rather
than silently granted write. The Podman 5+ alternative (`resources.limits` key
`podman.io/device=<path>`) is not used because 4.9.3 lacks it. Volume names starting with
`switchyard-` are reserved for these derived volumes.

The plan has one item per device (`devices`): path, type, major:minor, owner, group, mode,
who can open it, whether the deploying user and a rootless container can open it, the GPU
behind a DRM render node (vendor, device, driver, PCI address, VRAM total and in use) and
what access means (submit compute and Vulkan work and allocate VRAM, shared with every other
process on the host; no display). Blocking preconditions: `podman-device-support` (Podman
4.2.0 or later), `device-grant-<id>` (the policy lists it for the host) and `device-<id>`
(exists, is a character device and not a symlink, the deploying user can open it
read-write, and a rootless container can: the container's processes keep none of the
account's supplementary groups, and only container root maps to the deploying account, so
the node must be world read-write, or owned by the account with the container declaring
`runAsUser: 0`; a non-root or unstated container user maps to a subordinate ID. Verify the actual mapping on the target. The plan approval lists every device. Apply rechecks the device (same
major:minor) before writing anything. `start` reads the running containers' OCI runtime
configuration (`podman container inspect` → `OCIConfigPath`) and fails, cleaning up, unless
each container has exactly its declared devices; the result is fence-record evidence.
`deploy verify` repeats that read for running placements and reports `devices-changed`.

### Large images: detached pulls

The registry's compressed size of the host's platform image (config plus layers) is read at
plan time. Above 256 MiB, `deploy plan` requires the image to be in the host's store by
digest (blocking `image-present`, naming the `deploy pull-start` command) and apply only
verifies it there (`pull` with `local_only`); it never pulls a large image inside its
bounded step. Smaller images and images whose size the registry does not report keep the
pull inside apply, as before.

`deploy pull-start --host H --image REF|--template T --approve --request-id ID` runs one
leased operation: resolve the digest without pulling (registry API), read the size, and
return at once when the image is present or its pull is already running. Otherwise it checks
free space in Podman's graphRoot (at least 3 × compressed size + 1 GiB, or 20 GiB when the
registry gives no size), journals the pull (`pulls` table, state `starting`) and starts

```sh
systemd-run --user --quiet --collect --unit=switchyard-pull-<digest16>.service \
  --property=RuntimeMaxSec=21600 -- /bin/sh -c '<fixed script>' switchyard-pull /usr/bin/podman REPO@DIGEST DIR
```

The fixed script runs `podman pull` with its output in `DIR/log` and writes the exit code
atomically to `DIR/result` (`DIR` = `~/.local/share/switchyard/pulls/<digest16>/`, beside
`request.json`); every value is a positional argument, nothing is interpolated. The unit
name per digest allows one pull per image per host. The pull belongs to the user's systemd
manager, so a lost SSH session or a finished operation does not stop it; RuntimeMaxSec bounds
it. `deploy pull-status` (leased, read-only) reports `running`, `succeeded`, `failed` (exit
code), `interrupted` (stopped before podman returned: no result file), `present` or `absent`,
with progress counted from the log (blobs started, config copied, manifest written; the log
text is never returned) and updates the journal. A failed or interrupted pull may be started
again; layers already stored are reused. `deploy pulls`, `deploy show` and `deploy list`
(`image_pull` on the instance whose image it is) show journaled pulls without host access.
Without lingering, the pull ends with the user's last session, like any user unit.

### Parameters in the pod, datasets by sub-path

`{{parameter}}` is substituted in container `args`, env values and volume `subPath`, with
the same format validation and the same refusal of undeclared parameters; an
`argument-list` parameter stands alone in one args element and expands to one argument
per token (`-ngl all -fa on` → four args; no shell anywhere). A parameter without a value
fails the plan before any host is contacted. Parameters used in the pod change only by
redeploy (refresh changes configuration files only).

A `subPath` is never handed to Podman (its handling differs across 4.9, 5.x and 6.x).
Switchyard binds the resolved directory itself as its own `Directory` volume
(`switchyard-sub-N`) after the host inspection proves it is a directory under the dataset
reached without any symlink, readable by the account (and lists its entries with modes, so a
file a non-root container user could not read shows up as a warning). A subPath inside a
dataset Switchyard would create empty blocks the plan. An operator dataset
(`--dataset models=/srv/models`) is mounted with the declared read-only flag and no
`:z`, `:Z` or `:U` option: Podman neither relabels nor chowns it, Switchyard never creates,
changes or deletes it, and undeploy (also with `--delete-data`) leaves it in place. The plan's
dataset item states the mount mode and this.

### Readiness windows

An HTTP check may declare `ready_within_seconds` (deploy accepts up to 150): `/health` of a
loading model answers 503, so apply, start, refresh, switch and restore retry it for that
long once the unit is active. The start step is lengthened to fit (systemctl start 60 s +
window + 45 s cleanup + margin; 110 s without a window, unchanged) and never past the
operation's deadline. `deploy verify` retries such a check up to the window, inside a
verify budget of at most 150 s per batch. The operation worker's deadline now also counts
the time spent waiting for the lease (the broker's bound runs from the worker's start), so
a long `SWITCHYARD_OPERATION_LEASE_WAIT` can no longer let a step run into the broker's kill.

### One at a time: exclusive host resources and switching

A template declares the GPU as an exclusive identity with `scope: host` (`kind: gpu`,
`name: /dev/dri/renderD128`); its key on a host is `<host>:gpu:/dev/dri/renderD128`. A
placement **holds** it while it is `active`, `staged` with a token that is not revoked (boot
and manual starts are open), uncertain, or carrying an unfinished operation; only `fenced`
and `retired` placements are proven free. While another placement on the host holds it:

- `deploy plan` blocks (`exclusive-gpu`, naming the holder) unless `--fenced`: apply then
  writes everything, issues the token and revokes it **before the unit file exists**, starts
  nothing and records `fenced` (`installed_fenced`);
- `deploy unfence` and `deploy start` refuse and name the holder (start of a fenced
  placement already refused);
- apply and the worker of every start or unfence recheck it under the lease.

`deploy switch-plan TARGET [--restore-on-failure]` requires the target fenced and every
holder without uncertain effects, then observes target and holders under the lease (read
only; any drift finding blocks) and stores an expiring plan with the steps, the end state of
every failure and the devices' VRAM. `deploy switch-apply PLAN --approve --request-id ID`
runs under one host lease and one receipt (its worker bound is 600 s instead of 285 s):

1. recheck placements (generation and revision), the holder set, authority and grants;
2. journal the switch intent (`pending`) on the target and every holder;
3. fence each holder (stop, prove pod and containers gone, revoke the token);
4. read VRAM; unfence the target; start it with its health checks (readiness window);
5. record the target `active`, the holders `fenced`; `last_switch` on the target keeps the
   steps with seconds, the VRAM readings and the outcome.

| Failure | End state | Receipt |
|---|---|---|
| A holder's fence is refused before any change (ownership, file hashes) | nothing switched; holders already fenced by this switch are named | `failed` |
| Transport lost or stop unproven while fencing | that holder `uncertain`; target untouched | `needs-inspection` |
| Target unfence refused | target `fenced`; holders `fenced` (restored when chosen) | `failed` |
| Target does not start or become healthy, cleanup proven | target stopped, pod gone, token revoked, recorded `fenced`; holders stay `fenced` unless `--restore-on-failure`, which unfences and starts each once (a failed restore leaves it fenced the same way) | `failed` (restore incomplete: `needs-inspection`) |
| Transport lost while starting the target, or its stop unproven | target `uncertain` (it may hold the GPU); holders `fenced`; no restore | `needs-inspection` |
| Worker crash or kill | each placement keeps the journaled intent; `deploy verify` reports `operation-interrupted` with the receipt's status | `needs-inspection` |

No step is retried. The same request ID returns the same receipt. Recovery is explicit:
`deploy fence` clears an uncertain or interrupted placement; then switch or start again.
`deploy verify INSTANCE` observes every placement on the host that declares the same
resource in the same operation and reports `exclusive-resource-contended` when two of them
run or hold a valid token at once.

An optional application-level device lock can add protection against direct native starts, but it does not replace generation gates, declared exclusive identities or verification. The supplied template does not install a shared lock file.

### `llama-server-vulkan` template

`catalogs/templates/llama-server-vulkan.json`: `ghcr.io/ggml-org/llama.cpp:server-vulkan`
(digest at plan; the image's entrypoint is `/app/llama-server`), uid/gid 1000 inside the
container (not root; on the host a subordinate ID), no privilege escalation, all capabilities
dropped; the render node `/dev/dri/renderD128`; dataset `models` mounted read-only at
`/models` through `subPath: {{model-dir}}`; args `--host 0.0.0.0 --port 8080 --model
/models/{{model-file}} --ctx-size {{context-size}} {{extra-args}}` (defaults: 65536 and
`-ngl all --fit off -fa on -ctk q8_0 -ctv q8_0 -np 1`; review these model-specific defaults); the
host port is the claim (`--port http=…`), the container port stays 8080; HTTP `/health` with
a 120 s readiness window; exclusive identity `gpu` (scope host). The endpoint's consumer
notes say what it does not do, and the plan's LAN-exposure item repeats them: **no
authentication** (anyone who can reach the port can use the model; a risk to review before any LAN exposure), and the chat page needs gzip. The render node number is per host: another host needs a
template revision with its own path and a grant.

```sh
switchyard template save catalogs/templates/llama-server-vulkan.json --expected-revision 0
switchyard deploy plan --template llama-server-vulkan --instance llm-a --host host-a \
    --port http=18190 --address http=192.168.50.10 --dataset models=/srv/models \
    --param model-dir=example/model --param model-file=model.gguf
switchyard deploy apply PLAN --approve --request-id llm-a-apply-1
switchyard deploy plan --template llama-server-vulkan --instance llm-b ... --fenced   # second model
switchyard deploy switch-plan llm-b
switchyard deploy switch-apply PLAN --approve --request-id switch-1
```

## Runtime requirements

Inspect the exact host and runtime before deployment: rootless Podman, its separately packaged pause helper where required, a usable systemd user manager, Quadlet generator, architecture, network prerequisites and the exact rendered unit. The plan performs a Quadlet dry run and blocks unsupported or missing prerequisites before writing. A successful schema validation is not runtime compatibility evidence.

Generator locations differ by distribution (`/usr/libexec/podman/quadlet` and `/usr/lib/podman/quadlet` are common). A generated service that waits for `network-online.target` needs that system target active. Installing packages, changing network targets or enabling lingering requires separate operator approval.

Podman can create shared runtime infrastructure outside the deployment's owned files. Undeploy removes owned resources only, not shared networks or unrelated images. Keep host generation high-water marks after retirement. Validate boot/manual-start behavior on each supported runtime; low-level Stop is not a durable fence.

## Open items

- Verify boot/login behavior (including linger and `WantedBy=default.target`) on each supported host; a staged placement can start natively when its token is valid.
- SELinux hosts need an explicitly reviewed labeling strategy; never relabel an operator dataset implicitly.
- Rootless UID mapping of datasets is reported (`ownership: unknown`), not verified.
- Health checks run on the target host against the claimed bind; a `0.0.0.0` claim is
  probed on 127.0.0.1. HTTPS checks verify TLS (no override).
- `daemon-reload` reloads the whole user manager (no restarts of other units).
