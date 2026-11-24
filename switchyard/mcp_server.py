"""Official MCP SDK adapter; the supported entry point is stdio only.

Catalog, cache, collector and operations paths are supplied only at startup.
Observation stays read-only. Explicit operations require operator configuration;
the shell tool is unrestricted unprivileged shell, not a command allowlist.

Remote mode (`--remote --origin-host H`, used by `switchyard mcp` on other hosts through the
switchyard-mcp-remote wrapper) serves only cache reads and device leases: no edits, collection,
inspection, planning, execution or shell, and every `lease_hold` is a detached hold attributed to the
calling host (and its Paseo agent).
"""

import argparse
from pathlib import Path
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .agent_leases import PASEO_ID, USER_NAME
from .core import Service

# Default-deny: a tool not named here is never registered on a remote-mode server.
REMOTE_TOOLS = frozenset({
    "inventory", "fleet", "hosts", "device_locks", "agents", "operation_policy", "operation_receipts",
    "operation_receipt", "fleet_keys", "definition_inventory", "store_status", "lease_hold", "lease_release", "lease_renew",
})


class _StrictMCP(FastMCP):
    """Keep SDK dispatch, but do not silently discard unsupported arguments."""

    def __init__(self, service: Service, *, allowed: frozenset[str] | None = None, **kwargs: Any):
        self._allowed = allowed
        super().__init__("Switchyard", **kwargs)
        self._service = service

    def add_tool(self, fn: Any, name: str | None = None, **kwargs: Any) -> None:
        if self._allowed is not None and (name or fn.__name__) not in self._allowed:
            return
        super().add_tool(fn, name=name, **kwargs)

    async def list_tools(self) -> list[Any]:
        tools = await super().list_tools()
        for tool in tools:
            if tool.name == "plan_migration":
                declared = self._service.definition_inventory()["workloads"]
                tool.inputSchema["properties"]["workload_id"]["enum"] = [record["id"] for record in declared]
            tool.inputSchema["additionalProperties"] = False
        return tools

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        for tool in await self.list_tools():
            if tool.name == name:
                properties = set(tool.inputSchema.get("properties", {}))
                required = set(tool.inputSchema.get("required", []))
                if not required <= set(arguments) <= properties:
                    raise ValueError("only the advertised tool arguments are accepted")
                break
        return await super().call_tool(name, arguments)


def create_mcp(
    catalog: str | Path, *,
    state_dir: str | Path | None = None, collectors_path: str | Path | None = None,
    operations_path: str | Path | None = None, origin_host: str | None = None,
    agent_id: str | None = None, origin_user: str | None = None,
) -> FastMCP:
    """Create a fresh SDK server without collecting or starting transport I/O. A non-None `origin_host`
    selects remote mode (see module docstring)."""
    service = Service(catalog, state_dir=state_dir, collectors_path=collectors_path,
                      operations_path=operations_path)
    remote = origin_host is not None
    if remote:
        service.redact_commands = True  # Shell scripts in receipts stay on the control host.
        if origin_host not in {record["id"] for record in service.hosts()["hosts"]}:
            raise ValueError(f"--origin-host must be a registry host ID, not {origin_host!r}")
        if agent_id is not None and not PASEO_ID.fullmatch(agent_id):
            raise ValueError("--agent-id is not a Paseo agent ID")
        if origin_user is not None and not USER_NAME.fullmatch(origin_user):
            raise ValueError("--origin-user is not a user name")
    elif agent_id is not None or origin_user is not None:
        raise ValueError("--agent-id and --origin-user require remote mode (--origin-host)")
    declared = service.inventory()
    cached = service.fleet()
    # Only observed workloads (definition form) are migration-proposal inputs; discovery never grants authority.
    # Core remains authoritative if a client disregards the advertised choices.
    workload_ids = [w["id"] for w in service.definition_inventory()["workloads"]]
    WorkloadID = Annotated[str, Field(strict=True, min_length=1, max_length=128, json_schema_extra={"enum": workload_ids})]
    DeviceID = Annotated[str, Field(strict=True, min_length=1, max_length=128, json_schema_extra={"enum": [d["id"] for d in declared["devices"]]})]
    HostID = Annotated[str, Field(strict=True, min_length=1, max_length=128, json_schema_extra={"enum": [h["id"] for h in cached["hosts"] if h["collection_enabled"]]})]
    ID = Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    Script = Annotated[str, Field(strict=True, min_length=1, max_length=16384)]
    Timeout = Annotated[int, Field(strict=True, ge=1, le=240)]
    Approval = Annotated[bool, Field(strict=True)]
    mcp = _StrictMCP(
        service,
        allowed=REMOTE_TOOLS if remote else None,
        instructions=(f"Remote Switchyard for agents on {origin_host}: cached reads and device leases only. Take a "
                      "lease (lease_hold) before any access from your host to another registry host and release it "
                      "(lease_release) as soon as the work is done: holds from a remote host are TTL-only. Busy means "
                      "wait or defer, never bypass. Edits, collection, operations and shell run on the control host."
                      if remote else
                      "Inventory and fleet read declarations/cache without contacting hosts. collect_host explicitly performs bounded read-only inspection. Legacy plan_migration is a non-executable proposal. operation_policy reports opt-in authority. plan_operation prepares an expiring exact plan; execute_operation needs explicit approval and a request ID. shell runs unrestricted unprivileged shell only on enrolled hosts with declared extra host leases. Never automatically retry execution or shell; inspect durable receipts after uncertain outcomes. No operations configuration means no execution authority."),
    )

    def annotations() -> ToolAnnotations:
        return ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)

    @mcp.tool(annotations=annotations())
    def inventory() -> dict[str, Any]:
        """Read hosts and every workload in the workload store (observed, registered, deployed); never contact devices."""
        return service.inventory()

    @mcp.tool(annotations=annotations())
    def fleet() -> dict[str, Any]:
        """Read cached definitions, native resources, environments and monitoring; never contact a host."""
        return service.fleet()

    @mcp.tool(annotations=annotations())
    def hosts() -> dict[str, Any]:
        """Read editable host descriptions, registry revision, verification and pinned fingerprints; never contact hosts."""
        return service.hosts()

    @mcp.tool(annotations=annotations())
    def device_locks() -> dict[str, Any]:
        """Read local device-lock holders and ledger tails without taking leases or contacting hosts."""
        return service.device_locks()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
    def lease_hold(device: ID, scope: Annotated[str, Field(strict=True, min_length=1, max_length=512)],
                   ttl_minutes: Annotated[int, Field(strict=True, ge=1, le=120)] = 60,
                   owner: Annotated[str, Field(strict=True, min_length=1, max_length=512)] | None = None) -> dict[str, Any]:
        """Hold a canonical local device lock for multi-step agent work. Returns connection hints and expiry; release promptly. Coordination only, not device-operation authorization. On a remote-host server the hold is TTL-only (detached) and attributed to the calling host."""
        if remote:
            # The owning agent is on origin_host, invisible to this host: TTL-only, attributed there.
            return service.agent_leases().hold(device, scope=scope, ttl=ttl_minutes * 60, owner=owner, detached=True,
                                               worktree=f"{origin_host}:mcp", origin_host=origin_host,
                                               agent_id=agent_id, origin_user=origin_user)
        return service.agent_leases().hold(device, scope=scope, ttl=ttl_minutes * 60, owner=owner)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
    def lease_release(lease_id: ID) -> dict[str, Any]:
        """Release only a Switchyard holder lease, never a raw-flock holder. Confirms its RELEASE."""
        return service.agent_leases().release(lease_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
    def lease_renew(lease_id: ID, ttl_minutes: Annotated[int, Field(strict=True, ge=1, le=120)]) -> dict[str, Any]:
        """Extend an active Switchyard holder lease from now, within the two-hour TTL limit. Never contacts the device."""
        return service.agent_leases().renew(lease_id, ttl=ttl_minutes * 60)

    @mcp.tool(annotations=annotations())
    def agents() -> dict[str, Any]:
        """Read cached Paseo daemon/agent metadata and local device-lock ownership; never contact hosts."""
        return service.agents()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
    def update_host_description(host_id: ID, changes: Annotated[dict[str, Any], Field(strict=True)], expected_revision: ID) -> dict[str, Any]:
        """Save descriptive host metadata at an exact revision. Cannot edit connections, scan or pin keys. On conflict review the current hosts; never overwrite automatically."""
        allowed = {"name", "platform", "architecture", "capabilities", "notes"}
        if not changes or not set(changes) <= allowed:
            raise ValueError("only descriptive host fields are accepted")
        for key, value in changes.items():
            if key == "capabilities":
                if not isinstance(value, list) or len(value) > 128 or not all(
                    isinstance(item, str) and 1 <= len(item) <= 128 for item in value
                ) or len(set(value)) != len(value):
                    raise ValueError("capabilities must be a bounded unique list of strings")
            elif not isinstance(value, str) or len(value) > 8192:
                raise ValueError("host descriptions must be bounded strings")
        return service.update_host(host_id, changes, expected_revision=expected_revision, connection=False)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True))
    def collect_host(host_id: HostID) -> dict[str, Any]:
        """Explicitly inspect a configured host read-only, updating cache/access ledger, never workloads."""
        return service.collect_host(host_id)

    @mcp.tool(annotations=annotations())
    def plan_migration(workload_id: WorkloadID, target_id: DeviceID) -> dict[str, Any]:
        """Propose a cold migration for a defined workload ID, never a discovered resource or execution."""
        return service.plan_migration(workload_id, target_id)

    @mcp.tool(annotations=annotations())
    def observe_local() -> dict[str, Any]:
        """Explicitly read basic facts about this control-plane host, not a catalog device."""
        return service.observe_local()

    @mcp.tool(annotations=annotations())
    def operation_policy() -> dict[str, Any]:
        """Read configured shell hosts and managed workload authority; never contact a host."""
        return service.operation_policy()
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True))
    def inspect_workload(workload_id: ID, request_id: ID) -> dict[str, Any]:
        """Explicit leased read-only inspection of an existing service authorized for lifecycle control. Updates receipts/evidence, never starts or adopts services. Required before planning for adopted systemd, Quadlet and Compose services."""
        return service.inspect_workload(workload_id, request_id=request_id)


    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
    def plan_operation(action: ID, workload_id: ID, target_id: ID | None = None) -> dict[str, Any]:
        """Plan a granted action for a workload, including start/stop/restart of deployed workloads. Adopted services require fresh inspect_workload evidence. Use operation_policy for capability discovery. Never executes."""
        return service.plan_operation(action, workload_id, target_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True))
    def execute_operation(plan_id: ID, approved: Approval, request_id: ID) -> dict[str, Any]:
        """Execute one exact prepared plan only with approved=true. Request ID binds intent; never retry automatically."""
        return service.execute_operation(plan_id, approved=approved, request_id=request_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True))
    def shell(host_id: ID, script: Script, request_id: ID, timeout_seconds: Timeout = 30,
              extra_host_ids: list[ID] | None = None) -> dict[str, Any]:
        """Run unrestricted unprivileged /bin/sh on a named enrolled host, not a command allowlist.

        Declare every additional enrolled host touched by the script in extra_host_ids
        to hold its lease too. No sudo/password automation or automatic retries.
        Foreground time/output are bounded; detached effects may outlive transport.
        Receipts omit scripts/output; replay returns the receipt, not recovered output.
        """
        if len(script.encode("utf-8")) > 16384:
            raise ValueError("shell script exceeds 16 KiB")
        return service.run_shell(host_id, script, timeout_seconds=timeout_seconds,
                                 request_id=request_id, extra_host_ids=extra_host_ids)

    @mcp.tool(annotations=annotations())
    def operation_receipts() -> list[dict[str, Any]]:
        """Read durable operation receipts without contacting hosts or recovering shell output."""
        return service.operation_receipts()

    @mcp.tool(annotations=annotations())
    def operation_receipt(operation_id: ID) -> dict[str, Any]:
        """Inspect one durable operation receipt, including uncertain outcomes; never execute anything."""
        return service.operation_receipt(operation_id)

    @mcp.tool(annotations=annotations())
    def fleet_keys() -> dict[str, Any]:
        """Read cached membership, fingerprints and directed connection status; never contact hosts."""
        return service.fleet_keys()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True))
    def inspect_fleet_keys(host_ids: list[ID], request_id: ID) -> dict[str, Any]:
        """Explicit leased read-only SSH inspection. Does not create keys or enroll hosts; inspect receipts after uncertainty."""
        return service.inspect_fleet_keys(host_ids, request_id=request_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
    def plan_fleet_keys(action: ID, host_ids: list[ID]) -> dict[str, Any]:
        """Prepare enroll/remove/rotate/reconcile from cached inspection; no remote changes. Reconcile may use an empty list."""
        return service.plan_fleet_keys(action, host_ids)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True))
    def execute_fleet_keys(plan_id: ID, approved: Approval, request_id: ID) -> dict[str, Any]:
        """Apply an exact fleet-key plan with approved=true; partial/offline peers are not atomic rollback. Never automatically retry."""
        return service.execute_fleet_keys(plan_id, approved=approved, request_id=request_id)

    @mcp.tool(annotations=annotations())
    def definition_inventory() -> dict[str, Any]:
        """Read observed workloads in the editor's definition form and the store's compare-and-swap revision; no host access."""
        return service.definition_inventory()

    @mcp.tool(annotations=annotations())
    def store_status() -> dict[str, Any]:
        """Read what the workload store holds, where each record came from and whether the seed catalog differs; no host access."""
        return service.store_status()

    @mcp.tool(annotations=annotations())
    def propose_workload_definition(resource_id: ID, workload_id: ID,
                                    name: Annotated[str, Field(strict=True, min_length=1, max_length=4096)],
                                    purpose: Annotated[str, Field(strict=True, min_length=1, max_length=8192)],
                                    supporting_resource_ids: list[ID] | None = None) -> dict[str, Any]:
        """Review promotion of a cached service or scheduled job, not an environment. Definition only; grants no lifecycle authority."""
        return service.propose_workload_definition(
            resource_id, workload_id=workload_id, name=name, purpose=purpose,
            supporting_resource_ids=supporting_resource_ids,
        )

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
    def save_workload_definition(definition: dict[str, Any], expected_revision: ID) -> dict[str, Any]:
        """Create a reviewed observed workload at the exact store revision. On conflict review again; never overwrite automatically."""
        return service.save_workload_definition(definition, expected_revision=expected_revision)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
    def update_workload_definition(workload_id: ID, definition: dict[str, Any], expected_revision: ID) -> dict[str, Any]:
        """Update a canonical definition with immutable ID and revision checks; cannot grant lifecycle authority or silently migrate ownership."""
        return service.update_workload_definition(workload_id, definition, expected_revision=expected_revision)

    # ---- deployed workloads (docs/deploy.md): Switchyard-created, template-based ----------------

    @mcp.tool(annotations=annotations())
    def templates() -> Any:
        """List stored deploy templates (host-free application specs with immutable revisions)."""
        return service.deployments().templates()

    @mcp.tool(annotations=annotations())
    def template(reference: ID) -> Any:
        """Read one template as `id` or `id@revision`."""
        return service.deployments().template(reference)

    @mcp.tool(annotations=annotations())
    def deployments() -> Any:
        """List deployed instances with host, generation, state and port claims; never contacts hosts."""
        return service.deployments().list()

    @mcp.tool(annotations=annotations())
    def deployment(instance_id: ID) -> Any:
        """Read one deployed instance: placement, native identities, claims and last receipt; never contacts hosts."""
        return service.deployments().show(instance_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True))
    def deploy_plan(instance_id: ID, host_id: ID, template: ID | None = None,
                    ports: dict[str, Annotated[int, Field(strict=True, ge=1, le=65535)]] | None = None,
                    addresses: dict[str, ID] | None = None, datasets: dict[str, ID] | None = None,
                    params: dict[str, str] | None = None, records: dict[str, str] | None = None,
                    install_fenced: Approval = False) -> Any:
        """Prepare an expiring deploy plan: read-only inspection of the target under its lease, resolved image digest,
        rendered files (configuration files included), port claims, LAN exposure, devices, exclusive resources and
        every precondition. `params` sets the template's declared parameters; `records` adds name-to-address records
        for templates that generate host records. `install_fenced` installs it with a revoked token and starts
        nothing (a second holder of an exclusive resource such as a GPU; move it with deploy_switch_plan).
        Executes nothing; omit template to redeploy a retired instance."""
        return service.deployments().plan(instance_id=instance_id, host_id=host_id, template=template, ports=ports,
                                          addresses=addresses, datasets=datasets, params=params, records=records,
                                          install_fenced=install_fenced)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True))
    def deploy_upgrade_plan(instance_id: ID, template: ID, params: dict[str, str] | None = None) -> Any:
        """Plan an upgrade to an explicitly higher revision (ID@REVISION) of the same template. Keeps
        the instance ID, host, bound endpoints and datasets; fenced instances stay fenced. Review downtime,
        files, claims and exclusive resources before calling deploy_apply. Does not stop or modify the workload."""
        return service.deployments().upgrade_plan(instance_id, template, params=params)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True))
    def deploy_refresh_plan(instance_id: ID, params: dict[str, str] | None = None,
                            add_records: dict[str, str] | None = None, remove_records: list[str] | None = None) -> Any:
        """Prepare an expiring plan to change a running instance's configuration files in place: re-rendered
        against the current host registry, parameters and records, with a per-file diff read from the host under
        its lease. Image, ports and datasets cannot change this way. Executes nothing."""
        return service.deployments().refresh_plan(instance_id, params=params, add_records=add_records,
                                                  remove_records=remove_records or ())

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True))
    def deploy_refresh_apply(plan_id: ID, approved: Approval, request_id: ID) -> Any:
        """Write the planned configuration files only with approved=true, restart if the changed files require it,
        and run the health checks. Generation and start token are unchanged. Never retry automatically."""
        return service.deployments().refresh_apply(plan_id, approved=approved, request_id=request_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True))
    def deploy_apply(plan_id: ID, approved: Approval, request_id: ID) -> Any:
        """Install or upgrade the planned workload only with approved=true. Request ID binds intent; never retry automatically."""
        return service.deployments().apply(plan_id, approved=approved, request_id=request_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True))
    def deploy_action(instance_id: ID, action: Annotated[str, Field(strict=True, json_schema_extra={"enum": ["fence", "unfence", "start", "stop"]})],
                      approved: Approval = False, request_id: ID | None = None) -> Any:
        """Fence (stop and revoke the start token), unfence, start or stop a Switchyard-deployed instance.
        Without approved=true and a request ID this only previews."""
        return service.deployments().act(instance_id, action, approved=approved, request_id=request_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True))
    def deploy_verify(instance_id: ID | None = None, request_id: ID | None = None) -> Any:
        """Compare a Switchyard-deployed instance on its host with the journal, under the host lease; omit
        instance_id to verify every placement. Read-only on the host: reports drift such as running-while-fenced
        or valid-token-while-fenced, repairs nothing. Re-enforce a drifted fence with deploy_action fence."""
        manager = service.deployments()
        return manager.verify_all() if instance_id is None else manager.verify(instance_id, request_id=request_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True))
    def undeploy_plan(instance_id: ID, delete_data: Approval = False) -> Any:
        """Prepare an expiring undeploy plan for an owned instance; data is kept unless delete_data is true. Executes nothing."""
        return service.deployments().undeploy_plan(instance_id, delete_data=delete_data)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True))
    def undeploy_apply(plan_id: ID, approved: Approval, request_id: ID) -> Any:
        """Remove the owned resources named in an undeploy plan only with approved=true; never retry automatically."""
        return service.deployments().undeploy_apply(plan_id, approved=approved, request_id=request_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True))
    def deploy_switch_plan(target: ID, restore_on_failure: Approval = False) -> Any:
        """Prepare an expiring plan that moves the target's exclusive host resource (for example the GPU) to it: under
        one host lease, fence the current holder (stop, prove the pod gone, revoke its token), then unfence and start
        the target and run its health checks. With restore_on_failure the previous holder is started again once if
        the target fails and is proven stopped; default off. Reads the host under its lease; executes nothing."""
        return service.deployments().switch_plan(target, restore_on_failure=restore_on_failure)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True))
    def deploy_switch_apply(plan_id: ID, approved: Approval, request_id: ID) -> Any:
        """Execute a switch plan only with approved=true: one lease, one receipt, never retried; the same request ID
        returns the same receipt. The result names every placement's end state and the step timings."""
        return service.deployments().switch_apply(plan_id, approved=approved, request_id=request_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True))
    def deploy_pull_start(host_id: ID, image: str | None = None, template: ID | None = None, approved: Approval = False,
                          request_id: ID | None = None) -> Any:
        """Start a detached pull of one image (registry/repository[:tag][@sha256:digest], or a template's image) on a
        deploy host, by digest, after disk checks; it runs on the host under the user's systemd manager and survives
        a lost connection. Without approved=true and a request ID this only previews. One pull per image at a time."""
        return service.deployments().pull_start(host_id, image=image, template=template, approved=approved, request_id=request_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True))
    def deploy_pull_status(host_id: ID, image: str | None = None, template: ID | None = None) -> Any:
        """Read one image's detached pull on the host under its lease (running, succeeded, failed, interrupted,
        present or absent, with layer progress); updates the journal. Changes nothing on the host."""
        return service.deployments().pull_status(host_id, image=image, template=template)

    @mcp.tool(annotations=annotations())
    def deploy_pulls() -> Any:
        """Journaled detached image pulls with their last known state; never contacts hosts."""
        return service.deployments().pulls()

    # ---- registration of adopted applications (docs/spec/workload.md): metadata only ------------

    @mcp.tool(annotations=annotations())
    def registered_applications() -> Any:
        """List registered (adopted) application bundles with revisions and provenance; never contacts hosts."""
        return service.deployments().registered_applications()

    @mcp.tool(annotations=annotations())
    def registered_application(reference: ID) -> Any:
        """Read one registered application bundle as `id` or `id@revision`."""
        return service.deployments().registered_application(reference)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
    def register_application(document: dict[str, Any], expected_revision: Annotated[int, Field(strict=True, ge=0)],
                             submitted_by: ID | None = None) -> Any:
        """Register a workload-spec Bundle describing one existing (adopted) application: validated, revision-checked
        (0 for new), stored with provenance. Metadata only: grants no lifecycle authority and contacts no host."""
        return service.deployments().register_application(
            document, expected_revision=expected_revision, submitted_by=submitted_by, source="mcp",
            host_ids=[record["id"] for record in service.hosts()["hosts"]])

    # ---- Start tokens for registered applications (docs/tokens.md) ----------------------------

    @mcp.tool(annotations=annotations())
    def token_show(application_id: ID, component: ID | None = None, host_id: ID | None = None) -> Any:
        """Read the journal of start tokens for a registered application. No host contact."""
        return service.tokens().show(application_id, component, host_id)

    @mcp.tool(annotations=annotations())
    def token_gate(application_id: ID, component: ID, host_id: ID) -> Any:
        """Return the token path, the exact line 1 expected for the current generation, and the canonical check
        for a shell script and a systemd ExecStartPre= line. Gates compare line 1 only. No host contact."""
        return service.tokens().gate(application_id, component, host_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True))
    def token_verify(application_id: ID, component: ID | None = None, host_id: ID | None = None,
                     request_id: ID | None = None) -> Any:
        """Compare token files on their hosts with the journal, under each host lease. Read-only on the host."""
        return service.tokens().verify(application_id, component, host_id, request_id=request_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True))
    def token_issue(application_id: ID, component: ID, host_id: ID, approved: Approval = False,
                    request_id: ID | None = None) -> Any:
        """Issue the start token for one component of a registered application on one authorized host. Without
        approved=true and a request ID this only previews. Writes one file; starts and stops nothing."""
        return service.tokens().issue(application_id, component, host_id, approved=approved, request_id=request_id)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True))
    def token_revoke(application_id: ID, component: ID, host_id: ID, approved: Approval = False,
                     request_id: ID | None = None) -> Any:
        """Revoke the start token for one component on one host. Without approved=true and a request ID this only
        previews. Revocation stops nothing that is running; it only makes the next gated start refuse."""
        return service.tokens().revoke(application_id, component, host_id, approved=approved, request_id=request_id)

    # ---- Access requests and keys (docs/auth.md): a model may approve read-only access at most ----

    def access():
        from .auth import Auth
        return Auth(service.state_dir, registry_hosts=lambda: [record["id"] for record in service.hosts()["hosts"]])

    @mcp.tool(annotations=annotations())
    def enrollment_requests() -> Any:
        """List pending and recent access requests from hosts and agents (codes, claimed identity, requested scope)."""
        return access().enrollments()

    @mcp.tool(annotations=annotations())
    def access_keys() -> Any:
        """List access keys with scope, hosts, expiry and last use. Never contains key material."""
        return access().keys()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False))
    def enrollment_approve(request_id: ID, label: ID | None = None,
                           expires_in_days: Annotated[int, Field(strict=True, ge=1, le=365)] | None = None) -> Any:
        """Approve an access request that asks for READ-ONLY access. Requests for lease or operate access are
        refused here and left pending for the operator's sign-in (approving them as read would consume them)."""
        from .auth import Identity
        manager = access()
        pending = {item["id"]: item for item in manager.enrollments()["pending"]}
        if request_id in pending and pending[request_id]["requested_scope"] != "read":
            raise ValueError("This request asks for " + pending[request_id]["requested_scope"]
                             + " access; only the operator can approve it (Access tab or `switchyard auth approve`)")
        return manager.approve(request_id, Identity("local"), scope="read", label=label, expires_in_days=expires_in_days)

    # ---- Ansible host initialization (docs/ansible.md): read-only over MCP -------------------

    def ansible():
        from types import SimpleNamespace
        from . import ansible_ops
        return ansible_ops.from_service(service, ansible_ops.config_path(SimpleNamespace(catalog=str(catalog), ansible_config=None)))

    @mcp.tool(annotations=annotations())
    def ansible_playbooks() -> Any:
        """List registered Ansible playbooks with repository state and per-host eligibility; never contacts hosts."""
        return ansible().playbooks()

    @mcp.tool(annotations=annotations())
    def ansible_playbook(playbook_id: ID) -> Any:
        """One registered Ansible playbook: repository state, plays, roles, the variables it exposes and recent
        plans, runs and receipts. Reads the repository locally; never contacts hosts. Registering, planning and
        applying are not available over MCP."""
        return ansible().playbook(playbook_id)

    @mcp.tool(annotations=annotations())
    def ansible_variables(playbook_id: ID) -> Any:
        """Variables a registered playbook exposes (type, description, which may be overridden, which are secret)
        and what the repository inventory sets for each allowed host. Secret values are never returned."""
        return ansible().discover(playbook_id)

    @mcp.tool(annotations=annotations())
    def ansible_plans() -> Any:
        """List stored Ansible check-mode plans; planning and applying stay with the operator (desk or CLI)."""
        return ansible().plans()

    @mcp.tool(annotations=annotations())
    def ansible_receipts() -> Any:
        """List durable Ansible apply receipts (changed tasks, commit, status)."""
        return ansible().receipts()

    return mcp


def main() -> None:
    parser = argparse.ArgumentParser(description="Switchyard MCP server (stdio; operations opt-in)")
    parser.add_argument("--catalog", required=True, help="operator-owned JSON catalog path")
    parser.add_argument("--state-dir", help="operator-owned observation cache directory")
    parser.add_argument("--collectors", help="operator-owned collector configuration JSON path")
    parser.add_argument("--operations", help="operator-owned operations configuration JSON path")
    parser.add_argument("--remote", action="store_true",
                        help="serve agents on another host: reads and leases only; requires --origin-host")
    parser.add_argument("--origin-host", help="registry host ID of the remote caller (implies --remote)")
    parser.add_argument("--agent-id", help="the remote caller's Paseo agent ID (lease attribution)")
    parser.add_argument("--origin-user", help="the remote caller's user name (attribution without an agent)")
    args = parser.parse_args()
    if args.remote and not args.origin_host:
        parser.error("--remote requires --origin-host")
    try:
        mcp = create_mcp(args.catalog, state_dir=args.state_dir, collectors_path=args.collectors,
                         operations_path=args.operations, origin_host=args.origin_host,
                         agent_id=args.agent_id, origin_user=args.origin_user)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
