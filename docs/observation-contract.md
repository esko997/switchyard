# Observation integration contract

This document describes read-only collection and cache semantics. Workload mutation belongs to separately authorized adapters; observation grants none. Definitions, native observations, installed artifacts and associations remain separate. See [architecture](architecture.md) for execution boundaries.

## Snapshot dict returned by collect_host(config)

Parent validates with strict Pydantic models. All keys required unless explicitly optional; unknown values use null, never fabricated zero. Bytes are bytes. Times UTC ISO8601 with timezone.

```
{
 "schema_version": 1,
 "host_id": str, "observed_at": str, "collector": "linux-v1"|"android-v1",
 "host": {"hostname": "source", "os": "Linux", "distribution": "Debian GNU/Linux 13", "architecture": "x86_64"},
 "cpu": {"model": str|null, "logical_count": int|null, "utilization_percent": number|null, "sample_seconds": number|null, "load_1m": number|null},
 "memory": {"total_bytes": int|null, "available_bytes": int|null, "swap_total_bytes": int|null, "swap_free_bytes": int|null},
 "gpus": [{"id": str, "name": str, "driver": str|null, "memory_kind": "unknown"|"shared"|"dedicated", "busy_percent": number|null, "vram_total_bytes": int|null, "vram_used_bytes": int|null}],
 "storage": {
   "devices": [{"id": str, "name": str, "model": str|null, "transport": str|null, "rotational": bool|null, "size_bytes": int|null}],
   "filesystems": [{"id": str, "source": str, "type": str, "mounts": [str], "total_bytes": int|null, "available_bytes": int|null, "used_bytes": int|null, "read_only": bool|null, "kind": "persistent"|"volatile"|"image"|"unknown", "backing_device_ids": [str]}]
 },
 "workloads": [{"id": str, "host_id": str, "backend": str, "scope": str, "native_id": str, "name": str, "kind": "service"|"scheduled-job"|"interactive-session"|"environment"|"batch-job"|"device-job"|"application", "lifecycle": "running"|"idle"|"stopped"|"starting"|"stopping"|"completed"|"failed"|"unknown", "health": "unknown", "management": "discovered", "observed_at": str, "extensions": {versioned_namespace: selected_native_fields}}],
 "coverage": [{"scope": str, "status": "complete"|"partial"|"unavailable", "message": str, "observed_at": str|null}],
 "warnings": [str],
 "resource_observed_at": {"host": str, "cpu": str, "memory": str, "gpus": str, "storage": str},
 "artifacts": [{"id": str, "host_id": str, "backend": str, "scope": str, "native_id": str, "name": str, "kind": "package"|"image", "observed_at": str, "extensions": {versioned_namespace: selected_native_fields}}]
}
```

`distribution` may be null. Collectors may omit `resource_observed_at`, `artifacts` and individual coverage timestamps; the cache stamps successfully observed scopes, never failed resource values. A retained CPU/memory/GPU/storage reading keeps its own original timestamp even when another scope advances. Complete backend/scope coverage replaces only that scope's native resources/artifacts; omitted or unavailable scopes cannot erase another backend's evidence.

`cpu.counters` is optional: `{total_ticks:int,idle_ticks:int,uptime_seconds:number,boot_id:str}`. Fast samples use matching boot identity and increasing counters/uptime to calculate utilization over the actual elapsed interval. Initial/reset intervals remain unknown. CPU model metadata is read in both full and fast modes, not erased by a fast sample.

Full Linux CPU sampling is at most 0.25 seconds; fast mode reads counters once without sleeping. GPU counters are passive sysfs reads on active devices and remain on the slow inventory lane. Storage deduplicates shared mounts and backing capacity. Exact systemd allowlist states are included in fast mode; timer waiting is idle, active/exited completed, not-found unknown. Containers/images remain slow inventory, independent of runtime service-manager state. Android packages are artifacts and matched processes are evidence, not health or persistence. Native IDs are host/backend/scope-specific; raw environments, logs and private data are not retained.

## Collector configuration (operator-only JSON)

Top-level `{schema_version:1, hosts:[...]}`. Each host record:
Linux: `{host_id, transport:"local"|"ssh", expected_hostname, user_units:[str], system_units:[str], [container_engines:["podman"|"docker"]], [target], [ledger], [monitor:{fast_seconds,storage_seconds,inventory_seconds}]}`. Monitor interval minimums are 10/60/300 seconds respectively, maximum 86400; booleans and unknown keys are rejected. Android cannot opt into monitoring.
Android: `{host_id, transport:"adb", expected_hostname:verified_serial, serial, ledger, user_id:0, packages:[exact_package_ids]}`. The serial must be an exact configured immutable USB identity; there is no built-in serial allowlist. SDK selection is `ANDROID_HOME`, then `ANDROID_SDK_ROOT`, then `~/Android/Sdk`; only `<SDK>/platform-tools/adb` is accepted. Existing local server only; no transport discovery/connect, server startup/restart or UI interaction. Android ledgers use the exact default host-ID filename under the configured ledger root.
For SSH target is `user@literal-or-hostname` validated, ledger existing canonical absolute path, expected_hostname required and verified. Every SSH host is leased by LedgerBroker on its configured canonical inode. The default ledger root is the XDG state root plus `switchyard/ledgers` (normally `~/.local/state/switchyard/ledgers`), overridden by `SWITCHYARD_LEDGER_DIR`; Linux may use an explicit existing canonical absolute ledger. Append the actual observation receipt before release. No API takes a command/path/target/config; only configured host IDs.

Collector exports `load_config(path: str|Path|None) -> dict[str, dict]` (None means empty), and `collect_host(config, *, mode="full", previous=None) -> snapshot`. Modes: full inventory; fast host/CPU/memory/exact systemd states; storage host/storage only. Only scopes read are emitted, so omitted inventory retains its timestamps. Validation is offline; identity mismatch fails closed. Each fixed Python3 stdin probe uses one bounded SSH batch, existing strict host-key trust, no forwarding/TTY/remote installation, and total collection/cleanup within 20 seconds. Leases span transport teardown; no detached masters. `CollectionError` hides remote stderr; `LeaseBusy` identifies contention. No API accepts commands, paths, targets or mode/cooldown overrides.

## Parent Service additions

`Service(catalog_path, *, state_dir=None, collectors_path=None)`.
`fleet()` returns `{mode:"observe-and-propose",generated_at,hosts,workloads,resources,environments,artifacts,groups,monitoring,policy,backends}`. `workloads` are resolved operator definitions; `resources` are native discovered records (snapshot.workloads); `environments` are the native environment subset. The obsolete candidates field is removed. Only definition IDs can be migration inputs. A definition includes purpose, one primary binding, optional supporting bindings, descriptive health/data/dependency fields and observation/proposal operations. Missing, ambiguous, mismatched or stale primary evidence cannot assert a running application; native running is never application health.

Hosts retain observation wrappers `{snapshot,freshness,age_seconds,last_attempt,retry_after_seconds}` and authority `{observe,execute:false,approval:"not-granted"}`. `last_attempt` identifies its lane; cooldown is a transient internal outcome, not a new saved sample. `resource_status` maps host/CPU/memory/GPU/storage to timestamps, ages, freshness and expected interval. Timed native records, artifacts, coverage, definitions and host observations include `freshness_ttl_seconds` so the browser can age them between events.

`collect_host(host_id)` returns the same fleet after explicit full collection or a cached/cooldown/busy result. Manual cooldown is 60 seconds; automatic lanes are independent. One host lock covers all lanes. Current monitor intervals determine display freshness (three intervals, minimum 30 seconds); manual-only freshness is 120 seconds. Failure preserves evidence. Catalog/authority scope determines cache identity; monitoring cadence alone does not discard observations.

`inventory()` returns declarations/definitions only. `plan_migration` accepts defined IDs and resolves their exact primary resource, rejecting discovery/artifact/group IDs. Proposals remain non-executable and bind complete definitions and snapshots into their ID. Migration evidence stays stricter than slow-inventory display freshness: 120 seconds. No recipe or missing source binding is a blocker, not an invitation to infer portability.

`monitor_context()` returns `(ObservationCache, opted_in_configs)`; `fleet_revision()` returns a stable cache/lifecycle revision. `Monitor.run(stop_event=None,max_cycles=None)` owns one leader lock and at most two collectors, defers busy hosts, caps error backoff at 300 seconds and does not queue missed ticks. Shutdown waits for bounded collector cleanup. `configure_monitor` advertises settings without starting a process or overwriting a live leader; `read_monitor` reports disabled/running/stopped/unavailable, actual intervals, heartbeat, last duration/status and next due times. Expired heartbeat changes the revision without inventing new observations.

## CLI / HTTP / MCP

CLI: global `--state-dir`, `--collectors`; `fleet`, `collect-host HOST_ID`, and explicit `monitor [--cycles N]`. Cycles are dispatch batches, not seconds. Importing, serving or reading never starts the monitor.

Web `create_server`/`serve` retain loopback-only binding and configuration keywords. GET `/api/fleet` and `/api/inventory` read cache/declarations; `/api/events` emits cache-only SSE event `fleet`, initially and on revisions, with heartbeat comments and bounded reconnect lifetime. HTTP has at most eight workers and two SSE slots, short input deadlines, bounded response writes and shutdown handling. Host/Origin/body/static defenses remain. POST `/api/observations/host` accepts exact `{host_id}`; POST `/api/plans/migration` accepts defined workload/destination IDs and never executes. Only a validated observation receives the longer execution deadline.
MCP create_mcp same keyword options; add `fleet` (readOnlyHint true), `collect_host` (readOnlyHint false because it updates cache/ledger and performs explicit read-only remote inspection; description explains no workload mutations). Existing tools remain. Stdio only. Known host IDs in schema; no command/config/path parameters. Changes/tests must cover explicit cache-vs-refresh semantics, denial boundaries. Test collectors mocked for interface boundary tests; parent does actual transport smoke.

## UI

The observation views are Workloads (default), Hosts and Cold migration; other views expose separately authorized capabilities. The workload view is a short named list with purpose, primary state, freshness and observation-only authority. Discovery is separately disclosed, with backend/scope/lifecycle filters; development environments appear inside host details. Packages/images remain artifacts. Promotion and descriptive editing are explicit metadata-only operations in the revisioned workload store, never automatic adoption.

Host summaries show CPU, available memory, passive GPU and writable persistent filesystem capacity with independent resource ages. Detail panels expose topology, provenance, coverage and native evidence. The browser's single SSE connection never performs collection; disconnect means live cache updates are unavailable, not that a host is stopped. Filters, opened details, migration selections and prior proposal evidence survive updates. Old proposals are labelled as retaining their original evidence.

Wizard: defined workload → destination → review, with service-specific steps and blockers but no execute button. Unknown compatibility remains visible. Use textContent for untrusted data, keyboard-accessible responsive views and no external assets. Explicit observation timeout is 35 seconds; failures preserve last-known evidence without retrying a device operation.
