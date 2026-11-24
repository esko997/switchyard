# Workload specification v2 (`switchyard/v1alpha3`)

> **Status — 2026-11-23:** `switchyard/spec.py` implements this declaration schema,
> `switchyard/v1alpha3`: v1alpha2 plus several start gates per component, exclusive
> identities and secrets in several locations (see [Version history](#version-history)),
> extended additively with parameters, configuration files and DNS health checks.
> Examples are review inputs, not running-state evidence
> or authority. Any `PLACEHOLDER` blocks execution (the one exception: a tagged
> image digest placeholder that deploy resolves and pins at plan/apply time).
> The first executor is the single-component `kube`/Quadlet deploy flow
> ([deploy.md](../deploy.md)); adopted applications can be registered as metadata
> ([Registration](#registration-of-adopted-applications)); other adapters remain proposals.

## Contract and identity

Switchyard wraps native workloads; it does not add a scheduler, reconciliation
loop, automatic failover or second restart supervisor. Native definitions own
startup order, restart policy and native health. `depends_on` is informational.
Containers are the default for new workloads; native systemd covers exceptions.
Components in one application may occupy different hosts now, without k3s.

`Application` is host-free, revisioned intent. It declares logical resources;
`Placement` binds host paths, accounts, identities and listener claims. A placement
contains one or more components on **one** host. Several placements form a
multi-host application. An instance has its own `id` and optional
`template_ref: {id, revision}`; templates have no placements. Several independent
instances may derive from the same template. A template cannot reference itself
or another template. The instance stores a complete application, not an overlay.

Every component has exactly one discriminated `native` reference: `kube`,
`compose`, `quadlet`, `systemd` or `observed` (a component Switchyard only watches;
see below). Applications may mix these formats.
The single-active invariant is **per `(application_id, component)`**, across
revisions and hosts: at most one active placement generation. There is no
`single_active` switch. A dataset has at most one active writer placement;
all components writing the same dataset must share that placement. Zero writers
is valid while stopped or staged. Read-only placements do not gain write authority.
Logical writer ownership includes provisioning/restore of a read-only serving dataset.
**Exclusive identities** (Application `identities`) add a second, separate
invariant: among `active` placements of a bundle, at most one holder component
of an identity is active, across components, placements and applications.

Persisted revisions are immutable, updated with compare-and-swap.
`Application.content_sha256()` hashes UTF-8 JSON of `model_dump(mode="json")`,
including defaults and nulls, sorted keys, compact separators and unescaped Unicode.
It excludes placements and activation inputs because those are separate records.
Record the resulting hash in the journal/plan; it is not a self-referential field.
Run deadlines, resume threads and model choices belong only in `ActivationInput`.

`SpecBundle` packages the application revisions, placements and activation inputs
needed to validate their reference closure. A referenced template revision must
be included. Standalone models check local structure; `SpecBundle` also checks
cross-record references, placement overlap and writer uniqueness.

## Schema rules

All objects reject unknown fields (`extra="forbid"`) and type coercion
(`strict=True`). IDs are lowercase `[a-z0-9][a-z0-9-]{0,63}`. Text is nonempty,
NUL-free and at most 8192 characters. Integers are positive unless a field below
permits zero; ports are 1–65535. Digests are lowercase 64-digit SHA-256.
Unknown digests, images, paths, timestamps and deadlines may use explicit
`PLACEHOLDER` strings in review inputs; they are never executable substitutes.
Absolute paths must be canonical, without empty, `.` or `..` segments; relative
health/secret paths cannot escape their dataset. Symlink resolution, allowlisting,
permissions and all physical containment checks still happen under lease.

Defaults: optional list/map fields are empty unless stated otherwise; optional
scalar/object fields are null. `Application.role` defaults to `instance`; dataset
`include` to `["**"]`. Top-level and Pod `apiVersion`/`kind` default to their literal
values; native `kind` and check `type` discriminators are required. The complete
field inventory below is mechanically checked against the models by
`tests/test_spec_examples.py`; fields not in it are rejected.

### Application resources

- **Component:** `sources` holds `{id, sha256}` pins for stored, deployed native
  source artifacts. References are logical IDs, never host filenames. Adopted
  components cannot put source hash pins in an Application: inspect and pin
  their native files, drop-ins, input files and runtime incarnations at **PLAN**
  time only. Hash drift invalidates that plan. Deployed sources remain pinned;
  inline kube source is covered by the application hash and the plan records the
  effective rendered source hash too.
- **Gates:** a component declares every enforcement point that refuses to start
  it without its generation token: `gates: [{id, kind, target, covers, misses}]`
  with `kind` `exec-start-pre` (a unit or drop-in), `launcher` or `script`;
  `target` names the native unit/drop-in/script; `covers` and optional `misses`
  are reviewed free text. Gate IDs are unique per component. A gated transient
  component needs a `launcher` gate and may add `exec-start-pre` gates on its
  related units (body templates), never on the transient unit itself.
- **Identities:** `identities: [{id, kind, name, holders, description}]` names an
  external identity that must never be used twice at once: `kind` is free text
  (use `minecraft-user`, `codex-thread`), `name` the native value (a username, a
  thread ID or a `PLACEHOLDER`), `holders` the components that may use it.
  `(kind, name)` is unique per application; placeholder names never collide.
  `scope: host` makes it an **exclusive host resource** (for example `kind: gpu`,
  `name: /dev/dri/renderD128`): its key is `<placement host>:<kind>/<name>`, so
  several instances may declare it, at most one holder per host is active, and the same
  name on another host is a different resource. Unset `scope` (global) keeps the
  original meaning.
- **Devices:** `devices: [{id, component, container, host_path, container_path,
  access, description}]` declares a host device node one kube container needs
  (`host_path` under `/dev/`, `container_path` defaults to it, `access`
  `read-write` (default) or `read`). It declares need only: which devices may be
  passed on which host is operations-policy authority (`deploy_devices`), and the
  deploy plan reviews each device on the host. A device path may not collide with a
  volume mount of its container.
- **Observed components:** `observed` (`{kind, backend, resource_kind}`) names only the
  native manager (`systemd`, `podman`, `docker`, `android`, …) and whether the
  resource is a `service` (default) or `scheduled-job`; its native definition is
  not described. Such a component has no gates or source pins, and its placement is
  `adopted` and `declared` (or `retired`): Switchyard never deploys, gates, fences or
  starts it. Observed workloads in the workload store use exactly one, named `main`.
- **Native references:** Compose declares a complete ordered `files` ID list,
  project name and complete service set; provider is `podman-compose`.
  Quadlet declares a `.container` source ID and generated unit.
  Systemd declares an exact unit, `unit_type` (`service` default, `timer`,
  `instance`, `transient`), optional source ID and grouped `related_units`.
  A transient reference requires `{id, command_ref}` `launcher`; other unit
  types reject it. Switchyard invokes the launcher's existing owned entrypoint;
  it does not manufacture transient units. Source files, scope/account,
  project directory and launcher path bind only on Placement.
- **Dataset:** `snapshot` is `sqlite-backup`, `files-quiesced`,
  `btrfs-snapshot` or `podman-volume-export`; `verify` is `sha256-manifest`,
  `sqlite-integrity` or `manifest-and-sqlite`. `writers` is nonempty;
  `readers` and `external_actors` declare other access. An external actor has
  `access: read|write`; writers require a declared `quiesce_check`.
  A `ConsistencyGroup` names datasets captured together; quiesce the union of
  their writers and external writers, not just one SQLite connection.
  `include`/`exclude` are the only manifest-glob spellings.
  Preserve uncommitted files, required sidecars, metadata and hardlinks according
  to the reviewed manifest. Never copy only a live SQLite main file.
- **Secret:** logical `kind` is `file`, `environment-file`, `podman-secret` or
  `credential`; `consumers` names components; `transfer` is `copy`, `reissue` or
  `operator-provides`. `rotates_on_use` is a boolean or `"unknown"`. Plans surface
  true/unknown rotation as a rollback-independence risk. Secret values never enter
  declarations, plans, command output or receipts.
- **Secret locations:** every secret lists **all** places it lives,
  `locations: [{id, form, role, component | external_dependency, dataset}]`.
  `form` is `value`, `hash` or `embedded` (inside a URL/config file); `role` is
  `holder` (uses it; a declared consumer), `verifier` (checks it, often a hash) or
  `copy`. Holders and copies keep a usable value, never only a hash. Each location
  names exactly one component, or one external dependency (for example a server
  config that holds the hash; never inside this application's datasets). A location
  in a dataset belongs to a component that writes or reads that dataset. A secret
  may live in several datasets and on several placements; at least one location is
  a holder. Location (where it lives) and transfer policy are independent: a
  dataset may hold a `reissue` secret. One rule couples them: a `copy` secret whose
  `value` lives in a dataset travels only with that dataset, so it has no `value`
  location outside datasets, and placements bind dataset locations by
  `relative_path` only. Reissue enumerates every location
  (`SpecBundle.secret_locations(application, secret)` lists them with each
  placement binding). Private escrow/access control and at-rest protection are
  mandatory for datasets with `value` locations.
- **Endpoint:** component owner, `protocol: tcp|udp`, `target_port`, and a free-text
  `consumers` checklist. Declare optional `scheme: http|https` on TCP for web
  endpoints; an HTTP health check on that endpoint must use the same scheme.
  Address and host port exist only in Placement. Publishing must account for
  PWA/bookmark origins, firewall rules and operational wrappers; no
  implicit DNS/proxy update exists. Two endpoints may share a container port with
  different protocols (DNS over UDP and TCP); their claims then share the host port.
- **Parameter:** `{id, description, format, default, value}` names one per-instance
  value; `format` is `text` (one line, no braces), `dns-name` (lowercase LDH labels,
  no trailing dot), `ip-address` or `ip-address-list` (1–8 canonical addresses
  separated by single spaces). Templates declare `default` only; an instance records
  the operator's `value`. The only substitution syntax is `{{parameter-id}}`, allowed
  in configuration-file `content`, a generator's `zone` and DNS check `name`/`expect`
  (and, since the GPU round, in parts of the Pod manifest, below). Every other `{{` or
  `}}` is rejected: there is no
  template language, no expression and no escape. A reference to an undeclared
  parameter, to a declared secret ID or of the form `{{secret…}}` is rejected:
  configuration files never carry secret values.
  Since 2026-11-23 (GPU round) `format` may also be `integer` (decimal, no leading zero),
  `relative-path` (segments of `[A-Za-z0-9._+-]` starting with a letter or digit; no
  leading `/`, no `.`/`..`/empty segment) or `argument-list` (1–32 tokens of
  `[A-Za-z0-9._:/=,+@%-]` separated by single spaces, no quotes or shell syntax). In a
  kube Pod manifest `{{parameter-id}}` is substituted in container `args`, env `value`s
  and volume-mount `subPath`, nowhere else (a `{{`/`}}` anywhere else in the manifest is
  rejected). An `argument-list` parameter stands alone as one whole `args` element and
  expands to one argument per token; it may not appear in any other text.
- **Configuration file:** `{id, component, path, content | generator, on_change}`, at
  most 16 per application, each rendering to at most 64 KiB (512 KiB together). `path` is a single file
  name. `generator` is a named generator, today only `registry-hosts`
  (`{kind, zone, records}`): a hosts-format file with one `address name.zone` line per
  registry host whose SSH target is an IP literal, plus operator `records`
  (`{name, address}`, `name` relative to the zone, unique). `on_change` (`restart`
  default, or `none` when the service reloads the file itself) tells a refresh what to
  do. A component mounts its files through exactly one Directory volume
  `hostPath: config://<component>`, always `readOnly`; Switchyard owns that directory
  (no placement binding). Rendering happens at plan time against the registry of that
  moment ([deploy.md](../deploy.md#configuration-files-and-parameters)).
- **Requirement:** free-string `name`, optional affected `components` (empty means
  application-wide), optional `capacity` and `probe_ref`. Capacity has positive
  `memory_mib`, positive numeric `disk_gib` and free-text `gpu` requirement.
  Component-scoped amounts apply per component; admission sums colocated demand
  with headroom and does not double-count shared/unified GPU memory.
  Declared requirements do not constitute fresh verified probe results.
- **ExternalDependency:** logical description and optional probe/secret reference;
  it is not an owned component or permission to change another service.
- **Health checks:** all have component, ID and positive `timeout_seconds` (5
  default). HTTP uses a TCP endpoint, `scheme: http|https` (`http`), nonsecret
  `path` (`/`), `status` (200), `redirects` (false), optional `body_sha256`,
  `predicate_ref`, `credential_ref`. TLS verification is not disabled. An HTTP check may
  declare `ready_within_seconds` (1–600): a bounded readiness window from the moment
  the unit is active, during which the check is retried (a model server answers 503
  while it loads); deploy accepts up to 150 s, so a start step can hold it.
  TCP checks also require a TCP endpoint. A `dns` check sends one query (`name`,
  `record_type` A, AAAA, PTR, CNAME, NS, SOA, TXT, MX or SRV, default A) over its
  endpoint's protocol and passes on NOERROR with at least one answer of that type
  and every value in `expect`. `process`, `unit-state` and `predicate` require a
  stored `predicate_ref`, not an inline shell command. A file-freshness check
  references dataset + declared health-file ID + `max_age_seconds`. Every dataset
  health file requires `stale_on_restore: true`; freshness requires mtime **after
  this activation** as well as maximum age. Copied health files never prove liveness.
  Unit/process state proves only its stated predicate, not application health.

### Recipe and operation inputs

A recipe is a first-class revisioned object with ordered steps, never a boot DAG.
Each step names one component/dataset `target` and an `action`:
`stop`, `start`, `restart`, `quiesce-check`, `snapshot`, `transfer`, `verify`,
`fence`, `unfence`, `activate-gate`, `publish`, or `script`. Only `script` requires
a stored `{id, sha256}` script reference. Checks reference application health/check
IDs. Scripts do not hide grants, preconditions, input hashes or postconditions.

`checkpoint` has exactly four values:

| Value | Human decision |
|---|---|
| `none` (default) | Machine-checked preconditions shown in the plan |
| `downtime` | Interrupt source; reversible until destination writes |
| `writer-switch` | Destination becomes writer; point of no return |
| `destructive` | Exact destructive cleanup and retained recovery material |

These are the **only three human phase gates**. Registration/lifecycle/deployment
authority is a separately configured prerequisite, not another prompt at every
phase. Secret handling, compatibility, provisioning, fence evidence and publish
checks are visible preconditions, not extra migration gates.

Every step declares `idempotent`. Resuming an idempotent step requires nonempty
verification checks and matching persisted intent/hashes; hash-verified resumable
transfer is permitted. Non-idempotent steps never auto-retry. An unknown native
start/stop outcome requires inspection, not a repeat invocation. Native startup
policy still owns runtime supervision.

`ActivationInput` binds an application revision, placement IDs and `runs`.
Each run supplies component, absolute `deadline_epoch`, optional `resume_thread`
and optional `model`. Verify deadline/identity/model authority before activation;
a migrated or expired health file is not permission to renew a run.

## Placement, fencing and recovery

`Placement.state` is `declared`, `staged`, `active`, `fenced` or `retired`.
`declared` is inventory/intent, never a fresh activation assertion. `staged`
does not permit Switchyard to start without an explicit start that records
`active`. A staged placement without a fence record may hold a valid token
(gate activated, for example after unfence or stop); its native boot/manual
start paths are then open, so fence to keep it down. `ownership: adopted` has no ownership ID;
`deployed` requires an execution-issued `ownership_id`.

Each `ComponentPlacement` binds exact native identities/scopes and the complete
logical `source_paths` set. Only Compose binds `project_directory`; only a
transient component binds `launcher_path`. A `NativeIdentity` selects one resource by
exact `native_id` or, for Podman/Docker containers only, exact container `name`; its
optional `backend` names the native manager when it is not the component's own
(default: `systemd` for systemd/Quadlet, `podman` for Compose/kube, the `backend` of an
observed component) and its optional `role` marks the resource whose state is the
component's state (`primary`, at most one per component; default: the first identity)
or a `supporting` one. These are the bindings the fleet joins with host observations,
declared for observed and registered workloads alike. `Placement.migration_recipe`
(optional) carries the legacy static-web cold-migration declaration of `planning.py`
(its own strict models) for an observed workload: it must move this placement's
application from its host to a different host. Derived container/process bindings
are **observed evidence resolved from native refs**, not Application fields.
Plan-time observations pin invocation/container IDs and native file hashes.
`DatasetBinding.access` is `read|write`; `ownership` is `native`, `idmapped`,
`remap-required` or `unknown` (default). Activation verifies `ownership_check`,
UID/subuid mapping, permissions and write/read-only mounts on the destination.
Never assume equal usernames mean equal rootless UID mappings.
`SecretBinding` binds one secret **location** on the placement that hosts the
location's component: `path` outside datasets, `relative_path` inside the
location's (bound) dataset. Staged/active placements bind every location of their
components. `mode` defaults to `0600` and is a four-digit octal mode.
`EndpointClaim.address` is a canonical IPv4/IPv6 bind address (or unresolved
placeholder), not a hostname requiring ambiguous listener-overlap resolution.
`ReviewedPath` explicitly binds exceptional native host paths with access and
review reference; it does not weaken host allowlisting.

### Fail-closed generation token

Each active component holds **one** host-side token containing
application/component identity, generation N and `issued_at`, at its
placement's `token_path`. Every **declared gate** of the component checks that
token before starting anything; the `FenceToken` records, per gate, evidence that
it does (`gates: [{gate, evidence}]`). Typical gates:

- systemd/Quadlet: an `ExecStartPre` generation-gate drop-in (`exec-start-pre`);
- launcher-owned transient units: a check in the launcher (`launcher`), plus
  script gates in the session/loop scripts it starts and `exec-start-pre`
  drop-ins on related templates. [Example 03](examples/03-residents.json) illustrates
  several such gates. Installing them belongs to the application owner, not a generic
  Switchyard transient-unit creator.

Gate **every** supported entrypoint, related unit, timer, watchdog and manual
launch path. A launcher gate does not cover a manually started body template:
that path needs its own declared gate or must be closed before the component is
eligible. Gate completeness is inspected evidence, not inferred from one token:
an `active` component needs a valid token **and** evidence for every declared
gate. A component with no declared gates cannot be `active` in a deployed
placement; an adopted placement may run it ungated only with an explicit
`ComponentPlacement.ungated_reason`, so the absence is a recorded decision.
`ungated_reason` beside declared gates is rejected. Each `misses` text is the
residual risk an operator accepts.

Fencing revokes/removes the token and optionally masks native activation.
Fence drop-ins, masks and token artifacts are an explicit permitted modification
to **adopted as well as deployed** workloads; this does not grant recreation or
source-file rewriting. Record previous policy and all activators.
Active placements require valid tokens for every component; staged/fenced/retired
placements with a fence record require revoked tokens. Fenced placements retain
evidence of stopped native identities and explicit recovery release conditions.
`masked` defaults to false; `release_requires` is the literal
`explicit-recovery-other-generation-inactive`. A revoked token requires
`revoked_at`; a valid token rejects it.

The control journal and host both persist generation high-water marks.
`FenceRecord` records both plus tokens, evidence and verification time.
Mismatch blocks activation: the higher generation wins **only after explicit
operator reconciliation**; never silently roll a journal back or choose a host.
The schema rejects unreconciled records, rather than representing them as active.
Journal intent precedes token issue/revocation and first-writer start.
Fences survive device-lease release and operation failure.

For a dead/unreachable source, an **operator-attested takeover** records `who`,
`why`, evidence, time, source generation, latest verified `snapshot_ref` and
credential-reissue evidence where available. Restore that snapshot, bump the
generation and reissue shared-resource credentials wherever possible. First
contact with a returning stale source detects/fences it before other operations.
**Residual risk:** an out-of-band revived source may start before contact.
A source filesystem rollback can resurrect an old token. Local token files
alone cannot prevent either case; shared-resource credential reissue or a
contact-time generation check is required to detect/inhibit them. A network
partition or Minecraft duplicate-login rejection is not a fence.

### Phases, leases, claims and receipts

1. Inspect application revision, grants, native source/incarnations, all writers,
   activators, dependencies, secret policies and destination compatibility.
   Stage native source/artifacts/data destinations behind activation gates.
2. At **downtime**, fence source, stop supervisors before children/writers, then
   prove quiescence of each consistency group and external writers.
3. Snapshot, transfer and verify manifests, SQLite state, private credentials,
   rootless UID mapping and restore ownership. Keep a verified recovery snapshot.
4. At **writer-switch**, recheck source fence and snapshot; journal new write
   ownership **before** the first destination writer/credential refresh starts.
   Activate through native/launcher paths and verify fresh application health.
5. Publish accepted endpoint placements and consumer checklist. Keep source fenced.
   At **destructive**, clean only listed owned resources/paths and retained archives.

Each phase acquires operation-owned host/device leases in stable order,
re-inspects, performs bounded work and releases. These leases have **no TTL**;
their operation owner controls their lifetime. Human gates are between phases
without held leases. This is a proposed operation lease contract, distinct from
today's TTL-bound agent lease API; do not reuse that TTL for long transfers.
Crash recovery uses the journal and re-inspection, never a timed automatic takeover.

Port reservations last for the plan's lifetime, not an independent timer.
Claim keys are host + bind address/address family + protocol + port.
Wildcard/specific overlaps conflict; conservative dual-stack conflicts need fresh
listener inspection. A registry cannot see unmanaged listeners: recheck under
lease immediately before bind. Unknown outcomes retain blocking claims; release
only after verified stop/retirement, not merely a failed SSH connection.
Bundle validation catches declared/staged/active overlap but is not the runtime
port registry or proof that a fenced listener has stopped.

Plans pin spec/source/image hashes, host identities, component generations,
grants, claims, check evidence and recovery policy. Deployed source pins remain
in the spec; adopted native hashes belong only to the plan.
Receipts record intent before effect, result after inspection, exact identities,
hashes, checks, phase and gate decisions, never secret material. Request IDs
deduplicate known results; uncertain effects require explicit recovery inspection.

Before destination writes, recovery may release the source fence only after
proving destination inactive and source snapshot unchanged. After writes (or
uncertainty), stop/fence destination, capture its latest consistent state and
explicitly reconcile/reverse-transfer before restarting source. Never boot a
stale dataset or roll back the external Minecraft world.

## Kubernetes notation: `podman-pod-v2`

The only kind is **`v1/Pod`**, in `kube-play` or `quadlet-kube` mode (default).
This is a placement-free template subset, not a Kubernetes API server.
`hostPath.path` is `dataset://<id>`, `reviewed://<id>` or `config://<component>` (the
component's Switchyard-owned configuration directory, read-only); render it from Placement
to a canonical real host path at plan time. Container paths remain container
paths. Host addresses/ports render from endpoint claims, never inline `hostPort`
or `hostIP`. All native runtime listeners must be covered by inspected claims.

The inventory below is the exact allowlist. Metadata is name + string labels.
Container images must be digest-pinned (or explicit unresolved placeholder).
`env` accepts nonsecret `value` **or** `valueFrom.secretKeyRef {name,key}`, not both.
Ports are container ports only; mount names must resolve. A volume mount may carry
`subPath` (a relative path, `{{parameter}}` allowed) on a `dataset://` volume only;
Switchyard renders it by binding the resolved sub-directory as its own volume (it is
never handed to Podman) after checking on the host that it is a directory reached
without symlinks.
Volumes are exactly one of `hostPath` (`Directory|File`, no automatic creation),
`emptyDir: {}`, or `configMap {name}`.
ConfigMap volume references require `configmap-volume-unverified` in
`compatibility_gates`; supplying that flag records a blocker, not compatibility.
ConfigMap creation/data translation is outside this initial subset.

`hostNetwork: true` requires `reviews: ["host-network"]` and endpoint declarations
plus claims at staged/active placement. Privilege, capability additions or
escalation require `privileged-access` review. Pod/user IDs allow zero; timings
allow zero only for initial delay and termination grace.
Resource amounts allow only CPU/memory strings; enforcement is separate evidence.
Pod defaults: `restartPolicy: Always`, grace 30 seconds, `hostNetwork: false`.
Container defaults: `imagePullPolicy: IfNotPresent`, mount `readOnly: false`,
port `protocol: TCP`. Liveness uses exactly one `httpGet` or `tcpSocket`;
defaults: initial delay 0, period 10, timeout 1, success threshold 1, failure 3.
HTTP liveness scheme defaults to `HTTP`. No user-supplied exec probe.

Reject Deployment, PVC, `volumeMode`, readiness/startup probes, `runAsNonRoot`,
`fsGroup`, init containers, Service/Ingress, arbitrary annotations, secret
volumes/literals and every unlisted kind/field. This intentionally cuts the v1
draft; future k3s/UltraSPARC portability is not a reason to accept ignored controls.

[Podman 4.9.3 manual](https://docs.podman.io/en/v4.9.3/markdown/podman-kube-play.1.html)
marks the remaining declared container fields supported. Actual httpGet/tcpSocket
liveness execution/image-tool dependencies, rootless CPU enforcement/networking,
ConfigMap volumes and boot/fence behavior remain **unverified**. Repeat against
Podman 5.4 before enabling them there; accepting the schema proves no runtime support.
Podman stores a Kubernetes Secret **whole** as a Podman secret: a kube secret
reference therefore requires `SecretBinding.conversion: podman-kube-secret`.
Private conversion/staging consumes its value outside specs/plans/receipts;
no empty Secret object or direct file-as-key assumption is permitted.

## Worked records

All examples are JSON, using existing dependencies only:

1. [Adopted game-server Compose](examples/01-game-compose.json): a fictional complete project, not one controller per container. Inspect actual services, datasets, endpoints and credential references before adoption.
2. [Static-web template and instance](examples/02-static-web.json): separate template/instance identities, a Pod and a logical site dataset. The template declares no gate; the instance declares the generated gate.
3. [Multi-host agent application](examples/03-residents.json): synthetic hub/station, client, caretaker and video roles demonstrating multiple gates, exclusive identities and multi-location credentials. These are illustrative declarations, not a production registration or live run record.
4. [Adopted educational app](examples/04-learning-box.json): fictional Quadlet ownership and data/TLS boundaries. Paths and secrets require independent inspection.
5. [LAN DNS template and instance](examples/05-lan-dns.json): parameterized zone/upstreams, generated hosts, configuration mounts and UDP/TCP health checks. The placement is illustrative, not proof of a working listener.
6. [Observed scheduled job](examples/06-observed-job.json): one observed component binding a primary timer and supporting service, with no lifecycle grant.
7. [Observed Compose runtime](examples/07-observed-runtime.json): an observed component with provider, project directory, manifests and complete services; policy names only granted workload IDs/actions/hosts.
8. [GPU model server](examples/08-llama-gpu.json): device grant, host-scoped exclusive identity, parameterized read-only model dataset and bounded HTTP readiness. Placeholder digests, ownership and evidence are not executable facts.

`declared` records do not claim these services have working generation gates.
Proposed health thresholds are policy choices, not measured fleet facts.

## Version history

`switchyard/v1alpha3` replaces v1alpha2 with these structural changes:

| v1alpha2 | v1alpha3 |
|---|---|
| One token gate per component (`FenceToken.gate`, `gate_ref`); transient = launcher only | `Component.gates` declares every gate; one token per component with evidence per gate (`FenceToken.gates`); `ComponentPlacement.ungated_reason` |
| Single-active only per component | Also `Application.identities`: an identity is active in at most one holder |
| `Dataset.contains_secrets` (one dataset per secret, policy must be `copy`); `SecretBinding.within_dataset` | `Secret.locations` (several datasets, placements, verifiers, external holders); `SecretBinding.location`; containment independent of transfer policy |

Stored v1alpha2 records keep loading: `spec.upgrade(document)` converts them in
memory (contained secrets become a `value`/`holder` location named after the
dataset; other secrets a `file` location held by the first consumer; bindings name
those locations; a single-gate token becomes evidence for gate `legacy-<kind>`,
which a bundle upgrade also declares on the component). Stored bytes and content
hashes are never rewritten: a stored v1alpha2 template revision keeps its recorded
hash as its identity; the upgraded content hashes differently, so persisting it
is a new revision. The workload store upgrades on read and stores a redeployed
v1alpha2 instance as a new instance revision ([deploy.md](../deploy.md)).
`spec validate`, `template save` and `spec register` accept v1alpha2 input the same
way and report `upgraded_from`.

**Additive extension (2026-11-23, still `switchyard/v1alpha3`):** `Application.parameters`,
`Application.config_files` (with `ConfigFile`, `ConfigGenerator`, `HostRecord`,
`Parameter`), the `dns` health check and the `config://` host-path scheme. Not a version
bump because every new field is optional with an empty default, no existing field changed
meaning, and every stored v1alpha3 record still validates unchanged; the new fields are
left out of `content_sha256` while empty, so records stored before them keep the hash
they were recorded with (`HASH_NEUTRAL_WHEN_EMPTY` in `spec.py`). Readers older than
this change reject records that use the new fields (strict models), which is the
intended failure mode: such a record cannot be deployed by code that cannot render it.

**Second additive extension (2026-11-23, still `switchyard/v1alpha3`): observed workloads.**
So that the workload store can hold every workload in this format, including the ones
Switchyard only watches: the `observed` native kind (`ObservedNative`), `Application.notes`
(`Notes`: free `text`, descriptive `health`, `data_locations` and `workload_dependencies`,
never parsed into checks, datasets or ordering), `NativeIdentity.name`/`backend`/`role`
(`native_id` becomes optional, exactly one of `native_id` or `name`), and
`Placement.migration_recipe`. Same rules as above: optional, empty by default, `notes` is
hash-neutral while empty, every stored record keeps validating and hashing unchanged;
older readers reject records that use them.

**Third additive extension (2026-11-23, still `switchyard/v1alpha3`): runtimes of observed
components.** `ObservedNative.runtime` describes how the native runtime starts and stops
a component Switchyard watches, so the operations policy (schema 2) can state authority
only and read every description from the store: `quadlet` (`QuadletRuntime`: the primary
systemd unit is Quadlet-generated; unit and scope stay on the primary native identity),
`compose` (`ComposeRuntime`: provider `docker-compose-v2` or `podman-compose`, project
name and directory, manifest paths, complete service set; the component's backend must
be the provider's engine) and `static-web` (`StaticWebRuntime`: image, host port and the
control-host page of the disposable Foobar recipe; container name = the primary
identity's name). A plain systemd unit needs none. Services only. Optional, and left
out of the serialized document while unset (not merely out of the hash), so stored
records keep their bytes and hashes; older readers reject records that use it.

**Fourth additive extension (2026-11-23, still `switchyard/v1alpha3`): GPU workloads.**
`Application.devices` (`Device`), `Identity.scope` (`host`), `HTTPCheck.ready_within_seconds`,
`VolumeMount.subPath`, the parameter formats `integer`, `relative-path` and `argument-list`, and
`{{parameter}}` in container args, env values and subPath. Every new field is optional and
left out of the serialized document while unset (`exclude_if`), so every stored record keeps
its bytes and its content hash; older readers reject records that use them. One rule became
stricter: a `{{` or `}}` elsewhere in a Pod manifest is now rejected (it was accepted as
literal text, and no stored record contained one).

## Known modeling gaps

The declaration schema is broader than the implemented executor. Remaining design boundaries include launchers on a different control host, richer per-run input schemas, credential presentation methods for health checks, selective portability of shared session archives, nested dataset overlap and native source pins for related transient-unit templates. Display/login prerequisites are free-string requirements unless an adapter explicitly verifies them.

An external plugin inside another application's deployment remains an external dependency, not ownership of that deployment. Do not use declarations or placeholders to claim that these execution problems are solved.

## Observed workloads: definitions in this format

The workload store holds the former catalog definitions as `observed` records, converted
losslessly in both directions (`workloads.py`): one Application (ID, name, purpose,
`requires` = requirements plus `architecture:<arch>` entries, `notes` = notes, health text,
data locations and workload dependencies, provenance), one component `main` with an
`observed` native naming the definition's backend and kind, and one `declared` `adopted`
Placement on the definition's host whose native identities are its bindings (backend,
scope, native ID or container name, role) and whose `migration_recipe` is its recipe.
Nothing is inferred: the converter does not guess Compose projects, Quadlet provenance or
typed checks. `observed` grants nothing; verified operation placement still wins for where
it runs (Foobar), and existing grants stay separate and are never broadened.

Turning an observed workload into a typed one is an explicit review: resolve primary/supporting selectors through native provenance, adopt complete Compose projects, verify Quadlet source ownership, and retain exact service/timer references. Similar names or shared images do not establish a common lifecycle. Descriptive health/data/recipe prose needs review into typed checks and datasets; never parse prose into commands.

An observed workload already belonging to a registered application needs an identity handoff with no overlapping owners. The legacy static-web executor also needs source/ownership-preserving conversion to an allowed native format, not an invented second deployment.

Adoption alone permits only separately granted lifecycle actions. Migration,
redeploy and undeploy require deployed ownership or an explicit reviewed
ownership-conversion contract: capture a complete reproducible source/artifact
set, logical resources, verified creation/restore/removal recipe and ownership
marker/ID; journal the identity transition and separate grant without recreating
live resources implicitly. Fence-artifact installation remains the narrow adoption
carve-out. Artifact delivery stays a separate copy/hash/placement primitive,
not a fake component kind.

## Registration of adopted applications

Registration folds an existing (adopted) application into Switchyard as
**metadata only**: it never contacts a host and grants no lifecycle, deploy,
fence or undeploy authority (lifecycle stays the operator-configured adapters;
deploy/fence/undeploy keep refusing anything Switchyard did not deploy).

```sh
switchyard spec register BUNDLE.json --expected-revision 0 --submitted-by operator
switchyard spec registered                      # latest revision of each registration
switchyard spec show APPLICATION_ID[@1]
switchyard spec unregister APPLICATION_ID --expected-revision 1   # removes the registration only
```

A registration is a validated `Bundle` holding one application ID (any of its
revisions) with `role: instance`, its placements and activation inputs. Every
placement must be `adopted` without an ownership ID; claiming `deployed` is
refused. Revisions use compare-and-swap (`--expected-revision`, 0 for new); each
stores provenance: submitter (default: the application's provenance), time,
source name, SHA-256 of the submitted bytes and of the normalized bundle, the
application content hashes, and `upgraded_from` for v1alpha2 input. Cross-checks
are warnings, not errors: placement hosts missing from the host registry, endpoint
claims colliding with the deploy port registry, and identities (by kind/name,
placeholders excluded) also held by another registration or a deployed instance.
An ID used by a deployed instance cannot be registered, and a registered ID
cannot be used for a new deployment. Unregistering removes all its revisions.
Registrations are `registered` records of the workload store (`deploy.sqlite3`, tables
`workloads` and `workload_revisions`; see [deploy.md](../deploy.md#the-workload-store)).

## Field inventory

The row lists **all** accepted keys, including inherited check fields. Literal
values, unions, constraints and defaults are specified above and in the models.

| Model | Fields |
|---|---|
| `TemplateRef` | `id`, `revision` |
| `SourcePin` | `id`, `sha256` |
| `LauncherRef` | `id`, `command_ref` |
| `ComposeNative` | `kind`, `provider`, `project_name`, `files`, `services` |
| `QuadletNative` | `kind`, `source`, `unit` |
| `SystemdNative` | `kind`, `unit`, `unit_type`, `related_units`, `source`, `launcher` |
| `PodMetadata` | `name`, `labels` |
| `KeyRef` | `name`, `key` |
| `ValueFrom` | `secretKeyRef` |
| `Env` | `name`, `value`, `valueFrom` |
| `ContainerPort` | `name`, `containerPort`, `protocol` |
| `VolumeMount` | `name`, `mountPath`, `readOnly`, `subPath` |
| `HostPath` | `path`, `type` |
| `ConfigMapVolume` | `name` |
| `Volume` | `name`, `hostPath`, `emptyDir`, `configMap` |
| `Capabilities` | `add`, `drop` |
| `ContainerSecurity` | `runAsUser`, `runAsGroup`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation`, `capabilities`, `privileged` |
| `PodSecurity` | `runAsUser`, `runAsGroup` |
| `ResourceAmounts` | `cpu`, `memory` |
| `Resources` | `requests`, `limits` |
| `HTTPGet` | `path`, `port`, `scheme` |
| `TCPSocket` | `port` |
| `LivenessProbe` | `httpGet`, `tcpSocket`, `initialDelaySeconds`, `periodSeconds`, `timeoutSeconds`, `successThreshold`, `failureThreshold` |
| `Container` | `name`, `image`, `imagePullPolicy`, `command`, `args`, `workingDir`, `env`, `ports`, `volumeMounts`, `resources`, `securityContext`, `livenessProbe` |
| `PodSpec` | `containers`, `volumes`, `restartPolicy`, `terminationGracePeriodSeconds`, `securityContext`, `hostNetwork` |
| `Pod` | `apiVersion`, `kind`, `metadata`, `spec` |
| `KubeNative` | `kind`, `subset`, `mode`, `manifest`, `compatibility_gates`, `reviews` |
| `QuadletRuntime` | `kind` |
| `ComposeRuntime` | `kind`, `provider`, `project_name`, `project_directory`, `files`, `services` |
| `StaticWebRuntime` | `kind`, `image`, `port`, `site_file` |
| `ObservedNative` | `kind`, `backend`, `resource_kind`, `runtime` |
| `Gate` | `id`, `kind`, `target`, `covers`, `misses` |
| `Component` | `id`, `native`, `sources`, `depends_on`, `gates` |
| `Identity` | `id`, `kind`, `name`, `holders`, `description`, `scope` |
| `Device` | `id`, `component`, `container`, `host_path`, `container_path`, `access`, `description` |
| `ExternalActor` | `id`, `description`, `access`, `quiesce_check` |
| `HealthFile` | `id`, `path`, `stale_on_restore` |
| `Dataset` | `id`, `snapshot`, `verify`, `writers`, `readers`, `external_actors`, `include`, `exclude`, `health_files` |
| `SecretLocation` | `id`, `form`, `role`, `component`, `external_dependency`, `dataset` |
| `Secret` | `id`, `kind`, `consumers`, `transfer`, `rotates_on_use`, `locations` |
| `Endpoint` | `id`, `component`, `protocol`, `target_port`, `consumers`, `scheme` |
| `Capacity` | `memory_mib`, `disk_gib`, `gpu` |
| `Requirement` | `name`, `components`, `capacity`, `probe_ref` |
| `ExternalDependency` | `id`, `description`, `probe_ref`, `secret_ref` |
| `CheckBase` | `id`, `component`, `timeout_seconds` |
| `HTTPCheck` | `id`, `component`, `timeout_seconds`, `type`, `endpoint`, `scheme`, `path`, `status`, `redirects`, `body_sha256`, `predicate_ref`, `credential_ref`, `ready_within_seconds` |
| `TCPCheck` | `id`, `component`, `timeout_seconds`, `type`, `endpoint` |
| `FileCheck` | `id`, `component`, `timeout_seconds`, `type`, `dataset`, `health_file`, `max_age_seconds` |
| `PredicateCheck` | `id`, `component`, `timeout_seconds`, `type`, `predicate_ref` |
| `DNSCheck` | `id`, `component`, `timeout_seconds`, `type`, `endpoint`, `name`, `record_type`, `expect` |
| `Target` | `kind`, `id` |
| `ScriptRef` | `id`, `sha256` |
| `RecipeStep` | `id`, `action`, `target`, `script`, `idempotent`, `checks`, `checkpoint` |
| `Recipe` | `id`, `revision`, `steps` |
| `ConsistencyGroup` | `id`, `datasets` |
| `Provenance` | `submitted_by`, `source`, `evidence` |
| `Parameter` | `id`, `description`, `format`, `default`, `value` |
| `HostRecord` | `name`, `address` |
| `ConfigGenerator` | `kind`, `zone`, `records` |
| `ConfigFile` | `id`, `component`, `path`, `content`, `generator`, `on_change` |
| `Notes` | `text`, `health`, `data_locations`, `workload_dependencies` |
| `Application` | `apiVersion`, `kind`, `id`, `revision`, `name`, `purpose`, `role`, `template_ref`, `components`, `datasets`, `secrets`, `endpoints`, `requires`, `external_dependencies`, `health_checks`, `consistency_groups`, `recipes`, `identities`, `parameters`, `config_files`, `devices`, `notes`, `provenance` |
| `NativeIdentity` | `native_id`, `scope`, `name`, `backend`, `role` |
| `ComponentPlacement` | `component`, `native_identities`, `source_paths`, `project_directory`, `launcher_path`, `ungated_reason` |
| `DatasetBinding` | `dataset`, `path`, `access`, `ownership`, `ownership_check` |
| `SecretBinding` | `secret`, `location`, `path`, `relative_path`, `mode`, `conversion` |
| `EndpointClaim` | `endpoint`, `address`, `host_port` |
| `ReviewedPath` | `id`, `path`, `access`, `review_ref` |
| `TakeoverAttestation` | `who`, `why`, `evidence`, `attested_at`, `source_generation`, `snapshot_ref`, `credential_reissue_evidence` |
| `GateEvidence` | `gate`, `evidence` |
| `FenceToken` | `application_id`, `component`, `generation`, `issued_at`, `token_path`, `gates`, `state`, `revoked_at` |
| `FenceRecord` | `journal_generation`, `host_generation`, `tokens`, `masked`, `activators`, `previous_policy`, `stopped_native_ids`, `evidence`, `verified_at`, `release_requires`, `takeover` |
| `Placement` | `apiVersion`, `kind`, `id`, `application_id`, `revision`, `host_id`, `generation`, `state`, `ownership`, `ownership_id`, `components`, `datasets`, `secrets`, `endpoints`, `reviewed_paths`, `fence`, `migration_recipe` |
| `ActivationParameters` | `component`, `deadline_epoch`, `resume_thread`, `model` |
| `ActivationInput` | `apiVersion`, `kind`, `application_id`, `revision`, `placement_ids`, `runs` |
| `SpecBundle` | `apiVersion`, `kind`, `applications`, `placements`, `activation_inputs` |

## Remaining operator questions

1. Choose/verify escrow storage, encryption/access, retention and destructive cleanup policy.
2. Verify native/launcher generation gates across reboot, manual starts, filesystem
   rollback and loss of journal; decide shared-resource credential reissue coverage.
3. Confirm each application's writer/credential manifests, token rotation, acceptance
   thresholds, session prerequisites and approved per-run inputs.
4. Validate the Podman 4.9.3/5.4 runtime subset and source/ownership conversion
   contract before enabling a backend or migrating adopted production resources.
