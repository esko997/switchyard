"""Cached inspection, proposals and explicitly configured brokered operations."""
import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path
import sys

from . import ansible_ops, auth, deploy, tokens
from .core import Service
from .leases import LeaseBusy


def main():
    parser = argparse.ArgumentParser(description="Switchyard fleet desk and explicit operations")
    parser.add_argument("--catalog", help="Operator-authored catalog JSON (required except lease with installed defaults)")
    parser.add_argument("--state-dir", help="Private local cache directory (shared with web/MCP)")
    parser.add_argument("--collectors", help="Operator-owned allowlisted collector configuration")
    parser.add_argument("--operations", help="Operator-owned operations configuration; actions disabled without it")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("inventory", help="Read declarations; do not contact devices")
    commands.add_parser("observe-local", help="Observe only this control-plane host")
    commands.add_parser("fleet", help="Read cached fleet observations without contacting hosts")
    commands.add_parser("hosts", help="Read authoritative host registry and verification")
    dns_sync = commands.add_parser("lan-dns-sync", help="Reconcile verified hostnames in the configured LAN DNS deployment")
    dns_sync.add_argument("--dry-run", action="store_true", help="Preview the desired records without contacting hosts")
    commands.add_parser("hosts-export", help="Export registry hosts as JSON")
    host_update = commands.add_parser("host-update", help="Revision-safe descriptive or explicitly authorized connection edit")
    host_update.add_argument("host_id")
    host_update.add_argument("--changes-json", required=True)
    host_update.add_argument("--expected-revision", required=True)
    host_update.add_argument("--connection", action="store_true")
    host_update.add_argument("--allowlists", action="store_true")
    host_add = commands.add_parser("host-add", help="Add one host declaration and optional collector")
    host_add.add_argument("--record-json", required=True)
    host_add.add_argument("--expected-revision", required=True)
    host_remove = commands.add_parser("host-remove", help="Remove an unreferenced registry host")
    host_remove.add_argument("host_id")
    host_remove.add_argument("--expected-revision", required=True)
    host_scan = commands.add_parser("host-scan-key", help="Explicit leased host key scan; does not trust the key")
    host_scan.add_argument("host_id")
    host_scan.add_argument("--request-id", required=True)
    host_pin = commands.add_parser("host-pin-key", help="Confirm exactly the scanned fingerprints")
    host_pin.add_argument("host_id")
    host_pin.add_argument("--scan-id", required=True)
    host_pin.add_argument("--fingerprint", action="append", required=True)
    host_pin.add_argument("--expected-revision", required=True)
    hosts_import = commands.add_parser("hosts-import", help="Explicitly replace registry hosts from catalog/collector seeds")
    hosts_import.add_argument("--replace", action="store_true", required=True)
    hosts_import.add_argument("--expected-revision", required=True)
    collect = commands.add_parser("collect-host", help="Explicit bounded read-only collection for one configured host")
    collect.add_argument("host_id")
    monitor = commands.add_parser("monitor", help="Run automatic read-only monitoring for opted-in Linux hosts")
    monitor.add_argument("--cycles", type=int, help="Stop after this many scheduling cycles")
    plan = commands.add_parser("plan-migration", help="Propose, never execute, a cold migration")
    plan.add_argument("workload_id")
    plan.add_argument("target_id")
    inspect_workload = commands.add_parser("inspect-workload", help="Explicit leased read-only inspection of an authorized lifecycle workload")
    inspect_workload.add_argument("workload_id")
    inspect_workload.add_argument("--request-id", required=True)
    operation_plan = commands.add_parser("plan-operation", help="Prepare a brokered operation; never execute it")
    operation_plan.add_argument("action", choices=["deploy", "start", "stop", "restart", "migrate", "recover"])
    operation_plan.add_argument("workload_id")
    operation_plan.add_argument("--target")
    execute = commands.add_parser("execute-operation", help="Execute one exact prepared plan with explicit approval")
    execute.add_argument("plan_id")
    execute.add_argument("--approve", action="store_true", required=True)
    execute.add_argument("--request-id", required=True)
    shell = commands.add_parser("shell", help="Run unrestricted unprivileged shell on an enrolled host; no automatic retries")
    shell.add_argument("host_id")
    shell.add_argument("--script-file", required=True, help="UTF-8 script file or - for stdin; at most 16 KiB")
    shell.add_argument("--request-id", required=True)
    shell.add_argument("--timeout", type=int, default=30)
    shell.add_argument("--also-host", action="append", default=[], help="Also lease this enrolled host (repeatable)")
    receipts = commands.add_parser("operations", help="Inspect durable operation receipts without contacting hosts")
    receipts.add_argument("--id", help="Inspect one operation receipt")
    commands.add_parser("fleet-keys", help="Read cached fleet-key status and connection matrix; no host access")
    inspect_keys = commands.add_parser("inspect-fleet-keys", help="Explicit leased read-only SSH key inspection")
    inspect_keys.add_argument("host_ids", nargs="+")
    inspect_keys.add_argument("--request-id", required=True)
    plan_keys = commands.add_parser("plan-fleet-keys", help="Prepare fleet membership changes; never execute")
    plan_keys.add_argument("action", choices=["enroll", "remove", "rotate", "reconcile"])
    plan_keys.add_argument("host_ids", nargs="*")
    execute_keys = commands.add_parser("execute-fleet-keys", help="Apply one exact approved fleet-key plan")
    execute_keys.add_argument("plan_id")
    execute_keys.add_argument("--approve", action="store_true", required=True)
    execute_keys.add_argument("--request-id", required=True)
    commands.add_parser("definitions", help="Read observed workloads (definition form) and the workload store revision")
    propose_definition = commands.add_parser("propose-workload-definition", help="Review promotion from cached native evidence")
    propose_definition.add_argument("resource_id")
    propose_definition.add_argument("--workload-id", required=True)
    propose_definition.add_argument("--name", required=True)
    propose_definition.add_argument("--purpose", required=True)
    propose_definition.add_argument("--supporting-resource", action="append", default=[])
    for command in ("save-workload-definition", "update-workload-definition"):
        definition = commands.add_parser(command, help="Save metadata only; grants no restart/deployment permission")
        if command == "update-workload-definition":
            definition.add_argument("workload_id")
        definition.add_argument("--definition-file", required=True, help="Canonical definition JSON object, or - for stdin")
        definition.add_argument("--expected-revision", required=True)
    store = commands.add_parser("store", help="The workload store: the one authority for which workloads exist")
    store_commands = store.add_subparsers(dest="store_command", required=True)
    store_commands.add_parser("status", help="What the store holds, where it came from, whether the catalog file differs")
    seeding = store_commands.add_parser("seed", help="Seed the store once from the catalog and the legacy journals")
    seeding.add_argument("--dry-run", action="store_true", help="Report exactly what a seed would create; change nothing")
    migrate = commands.add_parser("migrate-operations", help="Convert an old (schema 1) operations policy and move "
                                  "managed placements and workload descriptions into the workload store (once)")
    migrate.add_argument("source", help="The old operations policy file (left unchanged)")
    migrate.add_argument("--output", required=True, help="Where to write the converted policy (must not exist, "
                         "or already hold exactly the converted policy)")
    migrate.add_argument("--dry-run", action="store_true",
                         help="Print the new policy and what moves into the store; change nothing")
    export = commands.add_parser("export", help="Write hosts, workloads, templates and groups as one deterministic JSON document")
    export.add_argument("path", nargs="?", help="Output file (default: standard output)")
    importing = commands.add_parser("import", help="Plan loading an export into an empty or matching store; --apply to load it")
    importing.add_argument("path", help="Export document, or - for stdin")
    importing.add_argument("--apply", action="store_true", help="Apply the plan (requires --expected-revision)")
    importing.add_argument("--expected-revision", help="Store revision from the plan")
    web = commands.add_parser("web", help="Serve the loopback desk, or a read-only LAN view")
    web.add_argument("--port", type=int, default=8710)
    web.add_argument("--host", default="127.0.0.1", help="Literal bind address (loopback unless --lan-read-only)")
    web.add_argument("--lan-read-only", action="store_true",
                     help="Serve a GET-only view on a private LAN address for clients in --allowed-clients")
    web.add_argument("--allowed-clients", help="Private client CIDR for --lan-read-only and --lan (default: bind address /24 for IPv4, /64 for IPv6)")
    web.add_argument("--lan", action="store_true",
                     help="Serve the authenticated desk over HTTPS on a private LAN address (docs/auth.md)")
    web.add_argument("--name", action="append", default=[], metavar="DNS_OR_IP",
                     help="Additional name the --lan server certificate must cover (repeatable)")
    stack = commands.add_parser("container-service", help="Run the loopback desk, optional HTTPS desk and configured monitor together")
    stack.add_argument("--port", type=int, default=8710)
    stack.add_argument("--lan-host", help="Private literal address for the optional HTTPS desk")
    stack.add_argument("--lan-port", type=int, default=8712)
    stack.add_argument("--allowed-clients", help="Private client CIDR for the HTTPS desk")
    stack.add_argument("--name", action="append", default=[], metavar="DNS_OR_IP",
                       help="Additional HTTPS certificate name (repeatable)")
    auth.register_cli(commands)
    ansible_ops.register_cli(commands)
    deploy.register_cli(commands)
    tokens.register_cli(commands)
    lease = commands.add_parser("lease", help="Attributed canonical device leases for agent commands")
    leases = lease.add_subparsers(dest="lease_command", required=True)
    for action in ("run", "hold", "attach"):
        sub = leases.add_parser(action)
        sub.add_argument("device")
        sub.add_argument("--scope", required=True)
        sub.add_argument("--owner")
        sub.add_argument("--worktree")
        sub.add_argument("--wait", type=float, default=0)
        if action == "run":
            sub.add_argument("--pass-lock-fd", action="store_true", help=argparse.SUPPRESS)
            continue
        if action == "hold":
            sub.add_argument("--ttl", default="60m")
            sub.add_argument("--detached", action="store_true",
                             help="Hold for a caller on another host (no local owner-exit watch)")
        else:
            sub.add_argument("--heartbeat", type=float,
                             help="Mark completion unconfirmed if stdin is silent this many seconds (1-600)")
            sub.add_argument("--completion-proof", action="store_true", help=argparse.SUPPRESS)
        # Remote callers (switchyard-remote on another registry host) attribute the lease to their agent.
        sub.add_argument("--agent-id", help="Paseo agent ID on --origin-host")
        sub.add_argument("--origin-host", help="Registry host ID the caller runs on")
        sub.add_argument("--origin-user", help="Caller's user name on --origin-host (attribution without an agent)")
    release = leases.add_parser("release")
    release.add_argument("reference")
    renew = leases.add_parser("renew")
    renew.add_argument("lease_id")
    renew.add_argument("--ttl", default="60m")
    listing = leases.add_parser("list")
    listing.add_argument("--json", action="store_true")
    status = leases.add_parser("status")
    status.add_argument("device")
    # Operator breakglass: human-only (refused under any agent ancestry), confirmed by typing the label.
    breaking = leases.add_parser("break", help="Operator only: block new grants while investigating unresolved work")
    breaking.add_argument("device")
    breaking.add_argument("--reason", required=True)
    breaking.add_argument("--signal-holders", action="store_true", help=argparse.SUPPRESS)
    breaking.add_argument("--kill", action="store_true", help=argparse.SUPPRESS)
    breaking.add_argument("--attest-stopped", help="How you know the old operation no longer touches the device (no block)")
    breaking.add_argument("--yes-device", help="Non-interactive confirmation: the exact ledger label")
    clearing = leases.add_parser("clear", help="Operator only: clear a block or suspect lease after attesting that work stopped")
    clearing.add_argument("device")
    clearing.add_argument("--attest-stopped", required=True, help="How you know the old operation no longer touches the device")
    clearing.add_argument("--yes-device", help="Non-interactive confirmation: the exact ledger label")
    migration = leases.add_parser("migrate", help="Import quiesced legacy leases and audit history into SQLite")
    migration.add_argument("--legacy-ledger", action="append", default=[], metavar="LABEL=/PATH",
                           help="Import an additional explicitly configured legacy ledger")
    mode = migration.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Read legacy state without writing anything")
    mode.add_argument("--confirm-drained", action="store_true", help="Old lease writers have been stopped and cannot restart")
    holder = leases.add_parser("_holder", help=argparse.SUPPRESS)
    holder.add_argument("lease_id")
    # argparse.REMAINDER would swallow --scope after the device positional.
    # Split only lease run's explicit delimiter; argv is passed to Popen verbatim.
    arguments = sys.argv[1:]
    command_argv = []
    if "lease" in arguments and arguments[arguments.index("lease") + 1:][:1] == ["run"] and "--" in arguments:
        delimiter = arguments.index("--")
        command_argv = arguments[delimiter + 1:]
        arguments = arguments[:delimiter]
    args = parser.parse_args(arguments)
    if args.command == "lease":
        args.catalog = args.catalog or os.environ.get("SWITCHYARD_CATALOG")
        args.collectors = args.collectors or os.environ.get("SWITCHYARD_COLLECTORS")
        args.operations = args.operations or os.environ.get("SWITCHYARD_OPERATIONS")
    if not args.catalog and not (args.command == "lease" and args.lease_command in {"_holder", "migrate"}):
        parser.error("--catalog is required (lease also accepts SWITCHYARD_CATALOG)")
    if args.command == "monitor" and args.cycles is not None and args.cycles < 1:
        parser.error("--cycles must be a positive integer")
    try:
        if args.command == "lease" and args.lease_command == "migrate":
            from .agent_leases import agent_ancestry, state_root
            from .lease_migration import migrate
            if not args.dry_run and agent_ancestry():
                raise ValueError("Lease migration is operator-only; stop every old lease writer first")
            print(json.dumps(migrate(args.state_dir or state_root(), legacy_ledgers=args.legacy_ledger,
                                     dry_run=args.dry_run), indent=2))
            return
        if args.command == "lease" and args.lease_command == "_holder":
            from .agent_leases import holder_main, state_root
            holder_main(args.state_dir or state_root(), args.lease_id)
            return
        if args.command == "container-service":
            from .service_stack import serve_stack
            raise SystemExit(serve_stack(args))
        if args.command == "web":
            from .web import serve
            lan = {"lan": True, "names": args.name} if args.lan else {}
            serve(args.catalog, host=args.host, port=args.port, state_dir=args.state_dir, collectors_path=args.collectors,
                  operations_path=args.operations, lan_read_only=args.lan_read_only, allowed_clients=args.allowed_clients, **lan)
            return
        if args.command == "migrate-operations":
            # Never loads --operations: that file may still be the old format this command converts.
            from .core import namespace, state_root
            from .operations_policy import migrate
            result = migrate(args.source, args.output, state_root(args.state_dir) / "operations" / namespace(args.catalog),
                             apply=not args.dry_run)
            print(json.dumps(result, indent=2))
            return
        if args.command == "store" and (args.store_command == "status" or args.dry_run):
            # Neither may seed: a dry run or the status of an unseeded store reads without writing any state.
            from .core import seed_dry_run
            plan = seed_dry_run(args.catalog, state_dir=args.state_dir)
            if args.store_command == "seed" or not plan["seeded"]:
                print(json.dumps(plan, indent=2))
                return
        service = Service(args.catalog, state_dir=args.state_dir, collectors_path=args.collectors,
                          operations_path=args.operations)
        if args.command == "lease":
            from .agent_leases import ttl_seconds
            manager = service.agent_leases()
            if args.lease_command == "run":
                raise SystemExit(manager.run(args.device, command_argv, scope=args.scope, owner=args.owner,
                                             worktree=args.worktree, wait=args.wait, pass_lock_fd=args.pass_lock_fd))
            if args.lease_command == "attach":
                # Claim line, then hold until the caller's `done` (see AgentLeases.attach). A heartbeat lease
                # must outlive its SSH session if the connection drops (fail-closed `suspect`): leave the
                # session's process group so teardown signals aimed at it cannot end the lease.
                if args.heartbeat is not None:
                    try:
                        os.setsid()
                    except OSError:
                        pass
                raise SystemExit(manager.attach(args.device, scope=args.scope, owner=args.owner, worktree=args.worktree,
                                                wait=args.wait, agent_id=args.agent_id, origin_host=args.origin_host,
                                                origin_user=args.origin_user, heartbeat=args.heartbeat,
                                                completion_proof=args.completion_proof))
            if args.lease_command == "hold":
                result = manager.hold(args.device, scope=args.scope, owner=args.owner, worktree=args.worktree,
                                      ttl=ttl_seconds(args.ttl), wait=args.wait, detached=args.detached,
                                      agent_id=args.agent_id, origin_host=args.origin_host, origin_user=args.origin_user)
            elif args.lease_command == "release":
                result = manager.release(args.reference)
            elif args.lease_command == "renew":
                result = manager.renew(args.lease_id, ttl=ttl_seconds(args.ttl))
            elif args.lease_command in {"break", "clear"}:
                from .agent_leases import BREAK_REFUSED, agent_ancestry
                if why := agent_ancestry():
                    raise ValueError(f"{BREAK_REFUSED} ({why})")
                if args.yes_device is None and not sys.stdin.isatty():
                    raise ValueError(f"lease {args.lease_command} needs a terminal to confirm, or --yes-device <LABEL>")

                def confirm(label):
                    if args.yes_device is not None:
                        return args.yes_device == label
                    return input(f"Type the device label {label} to {args.lease_command} it: ").strip() == label

                if args.lease_command == "break":
                    result = manager.break_lease(args.device, reason=args.reason, signal_holders=args.signal_holders,
                                                 kill=args.kill, attest_stopped=args.attest_stopped, confirm=confirm)
                else:
                    result = manager.clear_block(args.device, attest_stopped=args.attest_stopped, confirm=confirm)
                print(json.dumps(result, indent=2))
                raise SystemExit({"broken": 0, "cleared": 0, "still-held": 1, "not-applicable": 75}[result["status"]])
            elif args.lease_command == "status":
                result = manager.status(args.device)
                print(json.dumps(result, indent=2))
                # A blocked device is not available to new leases even when its lock is free.
                raise SystemExit(1 if result.get("blocked") and result["state"] == "free"
                                 else {"free": 0, "held": 1}.get(result["state"], 2))
            else:
                result = manager.list()
                if not args.json:
                    from .agent_leases import busy_message
                    for row in result["ledgers"]:
                        line = busy_message(row) if row["state"] == "held" else f"{row['device']}: {row['state']}"
                        if row.get("blocked") and row["state"] != "held":
                            from .agent_leases import blocked_message
                            line += "; " + blocked_message(row["device"], row["blocked"])
                        lease_state = row.get("switchyard_lease")
                        if lease_state:
                            line += f"; lease {lease_state['lease_id']}; deadline {lease_state.get('expires_at') or 'command completion'}"
                        print(line)
                    return
            print(json.dumps(result, indent=2))
            return
        if args.command == "inventory":
            result = service.inventory()
        elif args.command == "observe-local":
            result = service.observe_local()
        elif args.command == "fleet":
            result = service.fleet()
        elif args.command == "hosts":
            result = service.hosts()
        elif args.command == "lan-dns-sync":
            from .lan_dns_sync import reconcile
            result = reconcile(service, dry_run=args.dry_run)
        elif args.command == "hosts-export":
            result = service.export_hosts()
        elif args.command == "host-update":
            if len(args.changes_json.encode("utf-8")) > 65536:
                raise ValueError("host changes exceed 64 KiB")
            result = service.update_host(args.host_id, json.loads(args.changes_json),
                                         expected_revision=args.expected_revision,
                                         connection=args.connection, allowlists=args.allowlists)
        elif args.command == "host-add":
            if len(args.record_json.encode("utf-8")) > 65536:
                raise ValueError("host record exceeds 64 KiB")
            record = json.loads(args.record_json)
            result = service.add_host(record, expected_revision=args.expected_revision)
        elif args.command == "ansible":
            result = ansible_ops.handle_cli(args, service)
        elif args.command in {"spec", "template", "deploy"}:
            result = deploy.handle_cli(args, service)
        elif args.command == "token":
            result = tokens.handle_cli(args, service)
        elif args.command in {"auth", "tls"}:
            result = auth.handle_cli(args, service)
        elif args.command == "host-remove":
            result = service.remove_host(args.host_id, expected_revision=args.expected_revision)
        elif args.command == "host-scan-key":
            result = service.scan_host_key(args.host_id, request_id=args.request_id)
        elif args.command == "host-pin-key":
            result = service.pin_host_key(args.host_id, scan_id=args.scan_id, fingerprints=args.fingerprint,
                                          expected_revision=args.expected_revision)
        elif args.command == "hosts-import":
            result = service.import_hosts(replace=args.replace, expected_revision=args.expected_revision)
        elif args.command == "collect-host":
            result = service.collect_host(args.host_id)
        elif args.command == "monitor":
            from .monitoring import Monitor
            try:
                Monitor(*service.monitor_context()).run(max_cycles=args.cycles)
            except KeyboardInterrupt:
                pass
            return
        elif args.command == "inspect-workload":
            result = service.inspect_workload(args.workload_id, request_id=args.request_id)
        elif args.command == "plan-operation":
            result = service.plan_operation(args.action, args.workload_id, args.target)
        elif args.command == "execute-operation":
            result = service.execute_operation(args.plan_id, approved=args.approve, request_id=args.request_id)
        elif args.command == "shell":
            if args.script_file == "-":
                source = sys.stdin.buffer.read(16385)
            else:
                with Path(args.script_file).open("rb") as stream:
                    source = stream.read(16385)
            if len(source) > 16384:
                raise ValueError("shell script exceeds 16 KiB")
            result = service.run_shell(args.host_id, source.decode("utf-8"), timeout_seconds=args.timeout,
                                       request_id=args.request_id, extra_host_ids=args.also_host)
        elif args.command == "operations":
            result = service.operation_receipt(args.id) if args.id else service.operation_receipts()
        elif args.command == "fleet-keys":
            result = service.fleet_keys()
        elif args.command == "inspect-fleet-keys":
            result = service.inspect_fleet_keys(args.host_ids, request_id=args.request_id)
        elif args.command == "plan-fleet-keys":
            result = service.plan_fleet_keys(args.action, args.host_ids)
        elif args.command == "execute-fleet-keys":
            result = service.execute_fleet_keys(args.plan_id, approved=args.approve, request_id=args.request_id)
        elif args.command == "definitions":
            result = service.definition_inventory()
        elif args.command == "store":
            status = service.store_status()
            result = status if args.store_command == "status" else {"seeded": True, "seed": status["seed"],
                                                                      "relations": status["relations"]}
        elif args.command == "export":
            from .workloads import export_bytes
            encoded = export_bytes(service.export_store())
            if args.path is None:
                sys.stdout.buffer.write(encoded)
                return
            target = Path(args.path)
            temporary = target.with_name("." + target.name + ".switchyard-export")
            temporary.write_bytes(encoded)
            temporary.replace(target)
            result = {"path": str(target.resolve()), "sha256": hashlib.sha256(encoded).hexdigest(), "bytes": len(encoded)}
        elif args.command == "import":
            if args.apply != bool(args.expected_revision):
                raise ValueError("import applies only with both --apply and --expected-revision (from the plan)")
            source = sys.stdin.buffer.read(16 * 1048576 + 1) if args.path == "-" else Path(args.path).read_bytes()
            if len(source) > 16 * 1048576:
                raise ValueError("export document exceeds 16 MiB")
            result = service.import_store(json.loads(source.decode("utf-8")), source_sha256=hashlib.sha256(source).hexdigest(),
                                          expected_revision=args.expected_revision if args.apply else None)
        elif args.command == "propose-workload-definition":
            result = service.propose_workload_definition(
                args.resource_id, workload_id=args.workload_id, name=args.name, purpose=args.purpose,
                supporting_resource_ids=args.supporting_resource,
            )
        elif args.command in {"save-workload-definition", "update-workload-definition"}:
            if args.definition_file == "-":
                source = sys.stdin.buffer.read(102401)
            else:
                with Path(args.definition_file).open("rb") as stream:
                    source = stream.read(102401)
            if len(source) > 102400:
                raise ValueError("definition exceeds 100 KiB")
            definition = json.loads(source.decode("utf-8"))
            if not isinstance(definition, dict):
                raise ValueError("definition must be a JSON object")
            if args.command == "save-workload-definition":
                result = service.save_workload_definition(definition, expected_revision=args.expected_revision)
            else:
                result = service.update_workload_definition(
                    args.workload_id, definition, expected_revision=args.expected_revision,
                )
        else:
            result = service.plan_migration(args.workload_id, args.target_id)
        print(json.dumps(result, indent=2))
    except LeaseBusy as error:
        print(f"switchyard: {error}", file=sys.stderr)
        raise SystemExit(75) from error
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"switchyard: {error}", file=sys.stderr)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()
