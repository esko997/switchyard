# Foobar: disposable static-page rehearsal

`catalogs/example.json` contains a non-executing Docker/Compose definition on fictional hosts `source` and `destination`. It is an offline design, not runtime evidence. A separate rootless-Podman executor can use a narrowly authorized `static-web` runtime stored with an observed workload. Configure and review that separately; the tracked catalog does not grant execution authority. Loading a definition or requesting a proposal grants no lifecycle permission.

This rehearsal concerns static content, configuration and image movement followed by stop/start verification. It is neither live migration nor an application-write/data-reconciliation exercise.

## Fictional Docker planner: definition and recipe shape

The workload uses the definition schema: identity, human name/purpose, `device_id`, backend, `management: defined`, kind, exactly one primary binding, requirements/architectures, recipe, notes, descriptive health check, data locations, dependencies and observation/proposal-only supported operations. Its exact primary binding is Docker scope `system`, container name `switchyard-foobar`. A name chooses one observed container within that host/backend/scope; it **does not pin an incarnation**. Resolved full native IDs and observations must be bound into each proposal.

`validate_recipe(recipe)` and `assess_recipe(recipe, workload, target, observations)` retain their public signatures. Every recipe key below is required, including nullable keys. Unknown fields at every level are errors; there is no previous-recipe compatibility path.

- `schema_version: 1`, `kind: static-web`.
- `stop`, `transfer`, `start`, `verify`, `recovery`: nonblank human-readable requirements, each at most 2048 characters. Never commands or authorization.
- `source`: `{definition_id, device_id, backend, scope, selector}`. Backend is `docker`, scope is `system`, and selector is exactly `{name: exact_string}` or `{native_id: full_64_hex_container_id}`. IDs use the lowercase/dash, at-most-64 convention. The complete tuple must match the definition's one primary binding and source device.
- `destination`: the same binding fields plus `{filesystem_id, data_root}`. Definition ID must equal the source definition ID; device ID must equal the chosen different target. It declares a prospective destination, not a second deployed definition. Filesystem ID selects one exact observed persistent, writable storage pool.
- `artifact`: `{kind: image, reference, digest, architectures, reference_status: unverified}`. Reference must be an explicit versioned nginx tag, not `latest`; the example uses **UNVERIFIED** `nginxinc/nginx-unprivileged:1.28.0-alpine`. Digest is `null` until independently established, or lowercase `sha256:` plus 64 hex digits. It denotes the local image content ID emitted by observers, not an interchangeable registry manifest digest. Architectures is 1–16 unique strings. A tag does not prove availability or compatibility.
- `site`: `{source_path, destination_path, container_path, content_sha256, upper_bound_bytes, read_only: true}`. Container path is `/usr/share/nginx/html/index.html`. Host paths are normalized absolute non-root paths; destination lies strictly below `destination.data_root`. Content digest and unsigned 63-bit byte budget may be `null`, explicitly unknown. The example's 65536-byte upper bound is a design budget, not a measured deployment size.
- `resources`: `{cpu_count, memory_bytes, storage_reserve_bytes}`. CPU count is 1–4096; byte amounts are unsigned 63-bit integers, never booleans. Storage must cover content budget plus reserve. Independently size configuration/image/log overhead against the reserve; the planner does not measure image size or reserve resources.
- `network`: `{bind_address: 127.0.0.1, host_port: 18080, container_port, protocol: tcp}`. Container port is an integer 1–65535; this asset expects 8080. Port 18080 is dedicated, not permission to take an occupied port.
- `restart_policy: no`.
- `verification`: `{method: http-body-sha256, path: /, expected_status: 200, follow_redirects: false, baseline: unobserved}`. Hash exact HTTP body bytes without newline normalization or decompression ambiguity against `site.content_sha256`. A listening port, nginx welcome page, HTTP 200 alone or declared checksum is not success.
- `recovery_conditions`: `{strategy: restart-unchanged-source-before-cutover, require_destination_stopped: true, require_source_unchanged: true, retain_source_content: true, automatic_restart: false}`. Retain unchanged source content/configuration; independently prove destination stopped and source unchanged before explicitly approving source restart. Unknown outcomes require inspection, never automatic replay.

References are 1–256 allowlisted identifier characters; selector maps contain one key. Text excludes controls and common credential-bearing forms. The sanitized recipe is bounded to 32768 characters. Never put secrets in this static page, configuration or declaration.

The authored `index.html` is 459 bytes and has SHA256 `a8b10871b3d8c6d6bcfefc5f646b0ee0f0ad8dbce5c7a9c95b61402f0205a20e`. This is an authored asset declaration, not evidence of a deployment; the fictional catalog deliberately leaves the image digest `null`.

## Evidence-bound readiness

Assessment returns `{blockers, checks}`; each check retains `{id, status, detail, declaration, evidence}`. Supported applies only to that one observed precondition, never to an executable migration. Assessment reads only supplied cache wrappers: no host/file access, runtime call or HTTP request.

Host identity must match its observation-wrapper key. Wrapper age, per-resource times, runtime coverage, native records and image times must each be within the strict 120-second migration window. Unrelated fresh CPU sampling cannot refresh retained storage/image/container evidence. Slow-inventory UI freshness does not relax this bound. Wrong host, stale or ambiguous source, mismatching definition/selector, short native IDs and unknown runtimes block.

Checks cover fresh architecture/runtime evidence, exact source/destination bindings, image content IDs, CPU/memory capacity, selected storage capacity/path mapping, source stop and the exact readonly source content mount. Parent filesystems cannot lend free bytes to more-specific child mounts. Runtime coverage establishes only limited observer access, not application readiness.

Current observers do **not** measure port ownership/exclusive loopback exposure, destination name availability, restart automation, deployed content hashes/actual bounds, HTTP response body hashes or recovery conditions. These remain blocked in the cache-only planner even with supported capacity checks. Absence from bounded discovery is not proof of absence. Declarations cannot fill evidence gaps. The separate Podman executor obtains its own fresh leased checks; it never executes this planner's prose.

## Rehearsal requirements

1. Obtain runtime-installation and disposable-deployment authorization. Identify actual hosts, Docker access model, image architecture and immutable image content. Review Compose against that verified image, including UID, port, writable paths and entrypoint behavior. The unverified tag is not a compatibility guarantee.
2. Stage only this synthetic page and reviewed configuration in dedicated storage; record filesystem identities, actual content hashes/sizes, image/log overhead and capacity, and observe the exact source native ID. Never use personal services, credentials, sessions or save directories.
3. Publish only `127.0.0.1:18080` to container TCP 8080. First smoke is **localhost or an explicitly authorized tunnel only**: no firewall, routing, public bind or LAN/tailnet exposure changes. Require HTTP 200 without redirects and body SHA256 matching the page, then repeat after transfer.
4. Obtain exact-operation approval and canonical leases before stopping anything. Establish source stop/no-restart, retain unchanged content/configuration, transfer and compare bytes, then separately approve destination start after fresh runtime/identity/port/capacity checks. This tests restart, not live migration.
5. Exercise failure before cutover: prove destination stopped and retained source unchanged, then explicitly approve source recovery. Never automatically replay an interrupted operation. Keep receipts separately; do not turn declarations into fabricated observations.

Compose declares no restart, non-root UID/GID 101, readonly root/content, dropped capabilities, no-new-privileges, bounded `/tmp`, CPU/memory/PID/log limits, and no host namespaces, host sockets or privileged mode. Compatibility is untested. Neither Compose nor this document is an execution broker.
