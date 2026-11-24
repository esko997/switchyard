# Host, workload and resource model

The workload store and its three relations are implemented. Broader resource shapes below are design guidance, not an independent runtime API. No observed resource gains lifecycle authority from this model.

## The workload store

One database is the authority for which workloads exist and how Switchyard relates to each:
the **workload store**, `deploy.sqlite3` in `<state>/operations/<catalog-hash>/` (its historical
file name). Every workload is one revisioned record in the [workload-spec](spec/workload.md)
format, with one `relation`:

| Relation | Meaning | Record | Bindings the fleet joins |
|---|---|---|---|
| `observed` | Switchyard only watches it (the former catalog "definitions") | Bundle: one Application with one `observed` component, one declared adopted Placement | declared: the placement's native identities (backend, scope, native ID or container name, primary/supporting) |
| `registered` | Described by its owner (`spec register`); no lifecycle authority; may hold start tokens | the owner's Bundle, as registered | declared: every placement's native identities, per component |
| `deployed` | Switchyard created it (`deploy apply`) and holds its placements | the instance Application; placements, generations, claims, verifications in the same database | derived from the deploy journal's current placement |

Records change by compare-and-swap on their own revision (`spec register --expected-revision`,
deploy's instance revisions) and every revision is kept (`workload_revisions`). The whole
store has a content revision too: the definition editor saves observed workloads against it
(`expected_revision`), so a registration or deploy in between makes an open draft re-review.
Templates and application groups live in the store as well. Hosts stay in the host registry,
which was already authoritative; receipts, the observation cache, leases and the auth store
are logs, caches and credentials and stay where they are. The operations configuration remains
the authority for what Switchyard may *do* (lifecycle, deploy, token, shell hosts), and only that:
since schema 2 it names workload IDs, granted actions and hosts, and every description of a
granted workload (unit and scope, Compose project, container, image, port, page) is read from
its store record (`ObservedNative.runtime` where a plain unit is not enough). A grant the record
cannot support is refused when the file is loaded.

**Managed placements.** The narrow static-web executor keeps its workload location
and container ownership ID in a store row too
(`managed_placements`), so a workload's placement has one home for every relation. Receipts
stay in the operation journal (`operations.sqlite3`); a placement change is recorded there as an
intent in the receipt's own transaction, applied to the store in journal order right after it
commits, and by the next process that opens the journal if the writer died in between. Readers
inside a journal transaction see an unapplied intent before the store row, so the placement and
the receipt that explains it never disagree. The journal's old `workloads` table is moved once by
`switchyard migrate-operations`, which also converts schema-1 policy files.

**One read path.** The fleet view, `inventory`, `definitions`, the web desk, CLI and MCP read
workloads only from the store, joined with observations. A fleet workload's `management` is
its relation. An observed workload whose primary unit or container is a component of a
registered application on the same host carries `part_of: {application_id, component,
placement_id, host_id}`, matched on exactly what both declare; the registered application row
lists its components with their observed state and linked workloads.

**Seeding.** The `--catalog` file stays on the command line (state directories are namespaced by
its path hash) and seeds the store exactly once, in one transaction, the pattern the host
registry uses: its `workloads` become `observed` records (revision 1, catalog provenance kept),
its `application_groups` become store groups, and the deploy journal's older `instances`,
`instance_revisions` and `registrations` tables are copied byte for byte with their revisions,
hashes and provenance. Placements, claims, verifications and tokens are already in the same
database and are untouched. The seed verifies the copy (every legacy revision present and
equal, every catalog workload converts back to its definition) and aborts with nothing written
otherwise; ID conflicts refuse it. The old tables are left in place and a copy of the file from
before the store added its tables is kept beside it (`deploy.sqlite3.pre-store-<time>.bak`).
After seeding, the catalog's workloads and groups are ignored; `switchyard store status` says
whether the file still differs. `switchyard store seed --dry-run` reports exactly what a seed
would create without writing anything.

**Export and import.** `switchyard export [PATH]` writes hosts, workloads (all three relations),
templates and groups as one deterministic JSON document without secrets or journal state.
`switchyard import PATH` plans; `--apply --expected-revision REV` loads it into an empty or
matching store: it creates absent observed and registered records, templates and groups, never
overwrites a differing record, and refuses to create deployed records (their placements and
generations belong to the deploy journal). An operations file is resolved against the store when
it is loaded, so load an export into an empty store without `--operations`, then start with it.

## Why the boundaries matter

A container can run while its engine's user service is inactive. A timer can wait while its worker is stopped. Several mount paths may share one capacity pool. A package, launcher and process can be overlapping evidence of one application, not three workloads. Identical images do not establish common ownership or lifetime.

Model identities and relationships first, normalize observed state second, and add desired state only through explicit adoption. The [fictional JSON example](domain-examples.json) illustrates these distinctions without asserting observed fleet facts.

## Core objects

| Object | What it means | Important fields |
|---|---|---|
| **Host** | Stable inventory identity for a computer, VM, endpoint or appliance | Assigned ID, display name, device class, observed identities, OS/architecture, declared policy, transport references |
| **Host observation** | Attributed facts collected from a specific host and scope at a time | Collector, timestamps, completeness/errors, accessible scopes, evidence references, resources and readings |
| **Application group** | Optional operator-recognized collection of related workloads | Member IDs and evidenced relationships; grouping does not imply shared restart, migration or data-consistency boundaries |
| **Backend resource** | A concrete thing a native runtime manages | Backend, host, authority/scope, native ID, native state, normalized lifecycle, backend extensions |
| **Workload candidate** | A proposed operational grouping discovered by audit | Proposed kind/name, member resource IDs, classification evidence, unresolved boundaries; no desired state |
| **Workload definition** | Operator-authored operational description, not lifecycle adoption | Name/purpose, primary/supporting native selectors, dependencies, data locations, health criteria, proposed operations; separate authority |
| **Deployment** | Placement of a workload definition into a backend/host scope | Workload revision, host, backend resources, desired state, observed state, ownership |
| **Execution attempt** | One run of a deployment/job/session | Attempt ID, start/end, native instance IDs, outcome and receipts; PID is evidence, not logical identity |
| **Trigger** | What activates execution | Schedule/socket/event/manual source, target, observed enabled state; timer idle is not workload failure |
| **Data set** | Data ownership and consistency boundary | Storage references, writer/reader ownership, backup/recovery/export method and portability constraints |
| **Operation** | An authorized action over adopted resources | Immutable plan/preconditions, approval, leases, steps, receipts and uncertain-outcome/recovery state |

Not every object needs its own service or database table immediately. These are semantic boundaries to preserve, not an invitation to build a distributed framework.

## What qualifies as a workload?

A workload is a useful operational unit with a comprehensible lifecycle, owner and state/data boundary. A process or installed package is evidence of one, not sufficient proof of one.

Kinds should describe behavior, not implementation:

- `service`: continuously available application or infrastructure service.
- `scheduled-job`: timer/cron/event-activated work; individual runs are attempts.
- `batch-job`: finite manually or programmatically initiated work.
- `interactive-session`: desktop/game/development/agent session, normally passive-only until explicit authorization.
- `environment`: a development container/VM with child workloads; avoid double-counting its entire allocation and all child usage.
- `device-job`: physical or device-bound work such as a print; not presumed cold-migratable.

Backend is orthogonal: a service could use systemd, Compose, Kubernetes or another runtime. Android installed packages are artifacts; foreground activities and running service components are observed instances. An Android background sync application can be a workload candidate, while the package manager's full installed-app list should not flood Active workloads.

Keep operating-system daemons and infrastructure inspectable under host detail. Promote them to top-level workloads only when they are meaningful operator-owned units. No heuristic automatically adopts or groups them.

Relationships distinguish `contains`, `implemented_by`, `activated_by`, `depends_on`, `uses_data` and `shares_capacity`. Each relation has evidence/confidence (`observed`, `operator-declared`, `inferred`). Naming similarity is not proof of dependency. Multiple discovery sources should attach evidence to a native identity rather than create duplicate resources.

## Identity and state

A native key needs `(host_id, backend, authority_scope, native_id)`. System and per-user units named `syncthing.service` are not the same resource. Rootless Podman belonging to one UID is not the rootful engine. Compose project/service and changing container IDs occupy different levels. Android package identity includes user/profile; process IDs recycle. IPs, friendly hostnames and runtime PIDs are aliases/evidence, never the only stable host/workload key.

Separate these axes:

- `reachability`: observed reachable / unreachable / unknown; SSH permission failure is not proof of host outage.
- `lifecycle`: running / idle / stopped / starting / stopping / completed / failed / unknown, with the native state preserved.
- `health`: healthy / degraded / unhealthy / unknown, based on an actual health check, not merely process existence.
- `management`: observed / registered / deployed (the store's relation); none of them alone grants lifecycle control, which the operations configuration grants separately.
- `freshness`: computed from measurement time and policy, never stored as permanently fresh.
- `coverage`: complete within an explicitly named scope / partial / denied / busy / unavailable / not attempted.

A failed collection must not overwrite a previous good observation with a synthetic stopped/zero state. Keep last-known evidence with its age and the latest collection outcome. Missing from a partial inventory is not deletion. Only a complete snapshot for the same authority/scope can support a disappearance inference.

## Backend-specific extensions

Common fields must serve actual cross-backend questions. Preserve native information in versioned namespaced extensions, not a huge common object full of systemd/Android/printer flags.

Examples:

```json
{
  "backend": "systemd",
  "scope": "user:1000",
  "native_id": "notes-sync.service",
  "lifecycle": "stopped",
  "health": "unknown",
  "extensions": {
    "systemd.v1": {
      "active_state": "inactive",
      "sub_state": "dead",
      "triggered_by": ["notes-sync.timer"]
    }
  }
}
```

Other extension examples: `oci.v1` (engine, image digest, project/service, selected mount references), `android.v1` (package, profile, component, version, signing evidence if accessible), `desktop.v1` (session/display requirements), `printer.v1` (model/firmware, job and material constraints). Whitelist allowed fields at collection. Do not pass raw inspect/dumpsys/environment/log payloads through as an extension; they can contain secrets.

Backend capabilities are explicit operations and requirements, not invented universal support. Unsupported/unobserved fields remain unknown. The first common operations are enumerate, inspect and observe. Migration requires a service-specific recipe and proven compatibility; a running print must report unsupported rather than inherit the server workflow.

## Dynamic resources and capacity

Model resource topology separately from timestamped readings:

- **CPU:** architecture/model, sockets/physical cores/logical CPUs; busy fraction measured over a stated interval, load averages separately. Load is not utilization. Preserve CPU set/quota constraints where observed.
- **Memory:** total and OS-estimated available bytes, swap total/used, optional pressure/stall measures. `MemAvailable` is not `MemFree`; zram is not extra physical RAM.
- **GPU:** individual devices, driver/runtime capabilities, device versus shared/unified memory heaps, utilization and sampled VRAM use where available. Missing telemetry is null/unsupported, never 0%. CPU RAM and GTT/shared heaps cannot be added as independent capacity.
- **Storage devices:** physical/virtual identity, model, bus/transport (NVMe/SATA/USB/etc.), rotational characteristic and nominal size. Do not infer measured throughput or endurance from an SSD label.
- **Storage pools/filesystems:** usable total, available-to-observer, used and optional quota/inode limits; access mode and backing devices. Btrfs/ZFS/RAID, encryption and thin provisioning may break simple one-device/one-filesystem mapping.
- **Mounts/volumes:** access paths into backing pools, not extra capacity. A bind mount, Android emulated storage, Btrfs subvolume and repeated df entry may all refer to shared bytes. Host paths and application data ownership are separate concerns.

Every reading includes unit, source, observation time and status. Utilization includes sample duration/definition. Each resource has a stable local ID plus backing/shared-pool references. Unknown topology blocks additive totals. A read-only image at 100% and a full writable pool need different alert semantics. Space visible to a user can differ from root free space, quotas, reservations and thin-pool physical headroom.

### Placement headroom is policy, not telemetry

Show three distinct concepts:

1. **Physical/advertised capacity**: what the device exposes.
2. **Observed availability**: a timestamped measurement, not a promise.
3. **Placement budget**: operator-authorized capacity after policy headroom and explicit reservations, only when the accounting is known.

Do not blindly subtract reservations from free memory: their active use may already be reflected in the sample. Separate admission accounting (declared reservations/quotas) from telemetry-based pressure/headroom checks, and use both. A personal gaming desktop may expose 32 CPUs while contributing no automatic placement budget.

### Observation cadence

Initial audit is on demand. Proposed collectors use batched probes, a shared cached snapshot and per-scope single-flight refresh. Page loads, panels and MCP reads consume the cache, not independent SSH commands. TTLs should be configurable per metric/scope; hardware inventory can age much more slowly than usage. Low-frequency counters can later use a sampled ring buffer without turning this into a metrics platform first.

For current canonical device locks, one bounded SSH observation session may reuse a single authenticated TCP connection for several channels while holding the lease. Close it before release. Continuous pooled connections/streams and shared readers need an explicit access-policy decision; do not silently bypass the exclusive access invariant. Collection failure/busy state is visible, not an excuse for tight retries.

## Proposed UI implications

**Hosts:** compact summary shows availability/freshness and CPU, available RAM, GPU use (when supported) and the constrained writable storage pool. Detail panels expose per-disk/pool/mount topology, per-GPU heaps, collection coverage and raw-but-redacted evidence. Display unavailable readings plainly; no decorative fake gauges.

**Active workloads:** grouped host/backend resources with lifecycle and health separate. Show scheduled workloads as waiting/idle rather than hiding them as stopped failures. Candidate grouping must be identified as proposed. Filters expose historical/unknown observations, inactive deployments and installed artifacts without equating them to active work.

**Cold migration:** resolve an adopted workload's data boundary, compatible backend/artifacts and destination resource pools. Show measured headroom age, storage target, secrets references, downtime, preconditions, recovery and exact ownership. No execution until separately authorized.

## Implementation gate

See [representative JSON examples](domain-examples.json) for proposed host/resource/backend-resource/candidate shapes using explicitly fictional declarations. These are documentation examples, not an implemented versioned API or automatically imported fleet state.

Before changing runtime schemas, review current coverage and a small set of representative examples: native user service + timer, containerized application, nested development environment, interactive desktop session, Android background component and device-bound job. Promote only shared semantics into the common model. Keep observation separate from installation or scheduler adoption.
