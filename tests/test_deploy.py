"""Deploy flow (templates, plans, apply, fence gate, undeploy, port registry) with fixture hosts only.

The fake host runs the real fixed remote program (`deploy_remote.main`) in-process
against a temporary $HOME; only systemctl, podman, Quadlet, listeners and the
registry are emulated. No real host, ledger, systemd or network is touched.
"""
import argparse
import hashlib
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import copy
import io
import json
import os
from pathlib import Path
import platform
import pwd
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from switchyard import deploy, deploy_config, deploy_remote, lan_dns_sync, operation_worker, spec
from switchyard.lan_routes import LanRoutes
from switchyard.broker import Broker
from switchyard.lease_db import resource_label
from switchyard.leases import LedgerBroker, mark_uncertain
from switchyard.operation_store import encode
from switchyard.remote import RemoteError

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = json.loads((ROOT / "catalogs" / "templates" / "static-web.json").read_text())
DIGEST = "sha256:" + "c" * 64
DNS_TEMPLATE = json.loads((ROOT / "catalogs" / "templates" / "lan-dns.json").read_text())
REGISTRY = [
    {"id": "controller", "collector": {"transport": "local", "host_id": "controller"}},
    {"id": "host-a", "collector": {"transport": "ssh", "target": "operator@192.168.50.120"}},
    {"id": "test-portable", "collector": {"transport": "ssh", "target": "operator@test-portable.example.test"}},
    {"id": "host-b", "collector": {"transport": "ssh", "target": "operator@192.168.50.233"}},
    {"id": "test-handheld", "collector": {"transport": "adb", "serial": "TEST_SERIAL_001"}},
    {"id": "test-unix", "collector": None}]
LAN = {"dns-udp": "192.168.50.120", "dns-tcp": "192.168.50.120"}


def run_gate(value):
    """Execute an ExecStartPre= gate: the line-1 shell gate really runs in /bin/sh (systemd `$$` → `$`);
    the legacy whole-file grep gate (units journaled before 2026-11-23) is emulated."""
    if value.startswith("/bin/sh -c '") and value.endswith("'"):
        script = value[len("/bin/sh -c '"):-1].replace("$$", "$")
        return subprocess.run(["/bin/sh", "-c", script], stdin=subprocess.DEVNULL, capture_output=True).returncode == 0
    match = re.fullmatch(r'/usr/bin/grep -qxF -- "([^"]+)" (\S+)', value)
    identity, token = match.groups()
    try:
        return identity in Path(token).read_text().splitlines()
    except FileNotFoundError:
        return False


class FakeHost:
    """systemd --user + rootless podman + quadlet emulation over a real temp filesystem."""

    def __init__(self, root):
        self.home = root / "home" / "user"
        self.home.mkdir(parents=True)
        self.generator = root / "run" / "generator"
        self.generator.mkdir(parents=True)
        self.units = {}       # service -> {"fragment", "source", "active", "invocation"}
        self.pods = {}        # name -> record
        self.images = {}
        self.listeners = []
        self.fail_health = False
        self.fail_pull = False
        self.leave_pod_on_stop = False
        self.fail_reload = False
        self.foreign_containers = set()
        self.calls = []
        self.counter = 0
        self.restarts = []
        self.fail_restart = False
        self.port_start = 1024
        self.addresses = [{"ifname": "lo", "address": "127.0.0.1", "prefixlen": 8, "network": "127.0.0.0/8", "scope": "host"},
                          {"ifname": "wlan0", "address": "192.168.50.120", "prefixlen": 24, "network": "192.168.50.0/24",
                           "scope": "global"}]
        self.root = root
        # Devices (device_state is emulated: test machines differ), registry sizes, OCI configs and detached pulls.
        self.devices = {"/dev/dri/renderD128": {
            "path": "/dev/dri/renderD128", "exists": True, "symlink": False, "char": True, "block": False, "uid": 0, "gid": 989,
            "mode": "0666", "readable": True, "writable": True, "major": 226, "minor": 128, "owner": "root", "group": "render",
            "group_members": [], "gpu": {"vendor": "0x1002", "device": "0x744c", "mem_info_vram_total": "25753026560",
                                         "mem_info_vram_used": "390860800", "driver": "amdgpu", "pci": "0000:03:00.0"}}}
        self.image_size = 30_000_000
        self.drop_devices = False
        self.pull_units = {}
        self.vram_per_pod = 19_000_000_000
        self.unhealthy_ports = set()
        self.health_deadlines = []
        self.podman_version = "5.4.2"

    # quadlet -----------------------------------------------------------
    def generate(self, source):
        sections, section = {}, None
        for line in Path(source).read_text().splitlines():
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                sections.setdefault(section, [])
            elif line and not line.startswith("#") and section:
                sections[section].append(line)
        yaml = next(line.split("=", 1)[1] for line in sections["Kube"] if line.startswith("Yaml="))
        lines = ["[Unit]", *sections.get("Unit", []), "SourcePath=" + str(source), "", "[X-Kube]", *sections["Kube"], "",
                 "[Service]", *sections.get("Service", []), "Type=notify",
                 "ExecStart=/usr/bin/podman kube play --replace --service-container=true " + yaml,
                 "ExecStopPost=/usr/bin/podman kube down " + yaml, "", "[Install]", *sections.get("Install", []), ""]
        return "\n".join(lines)

    def quadlet(self, directory):
        output = []
        for source in sorted(Path(directory).glob("*.kube")):
            output += ["---" + source.stem + ".service---", self.generate(source)]
        return 0, "\n".join(output).encode()

    def reload(self):
        directory = self.home / ".config/containers/systemd"
        present = {}
        for source in sorted(directory.glob("*.kube")) if directory.is_dir() else []:
            service = source.stem + ".service"
            fragment = self.generator / service
            fragment.write_text(self.generate(source))
            present[service] = str(source)
        for service in list(self.units):
            if service not in present:
                self.units.pop(service)
        for service, source in present.items():
            unit = self.units.setdefault(service, {"active": "inactive", "invocation": ""})
            unit.update(fragment=str(self.generator / service), source=source)
        return 0, b""

    # systemd -----------------------------------------------------------
    def systemctl(self, args):
        args = [a for a in args if a not in ("--user", "--no-ask-password", "--no-pager", "--job-mode=fail", "--")]
        if args[0] == "is-system-running":
            return 0, b"running\n"
        if args[0] == "daemon-reload":
            return (1, b"") if self.fail_reload else self.reload()
        if args[0] == "show":
            if args[-1] in self.pull_units:
                return 0, b"LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\n"
            unit = self.units.get(args[-1])
            if unit is None:
                return 0, b"LoadState=not-found\nActiveState=inactive\nSubState=dead\nFragmentPath=\nSourcePath=\nInvocationID=\nNeedDaemonReload=no\n"
            return 0, ("LoadState=loaded\nActiveState=" + unit["active"] + "\nSubState=" + ("running" if unit["active"] == "active" else "dead")
                       + "\nFragmentPath=" + unit["fragment"] + "\nSourcePath=" + unit["source"] + "\nInvocationID=" + unit["invocation"]
                       + "\nNeedDaemonReload=no\n").encode()
        if args[0] == "start":
            return self.start(args[1])
        if args[0] == "stop":
            return self.stop(args[1])
        if args[0] == "restart":
            self.restarts.append(args[1])
            self.stop(args[1])
            if self.fail_restart:
                self.units[args[1]]["active"] = "failed"
                return 1, b""
            return self.start(args[1])
        if args[0] == "reset-failed":
            self.reset_failed = getattr(self, "reset_failed", []) + [args[1]]
            return 0, b""
        raise AssertionError("unexpected systemctl " + repr(args))

    def gate_passes(self, unit):
        line = next(l for l in Path(unit["fragment"]).read_text().splitlines() if l.startswith("ExecStartPre="))
        return run_gate(line.removeprefix("ExecStartPre="))

    def start(self, service):
        unit = self.units.get(service)
        if unit is None:
            return 5, b""
        if unit["active"] == "active":
            return 0, b""
        if not self.gate_passes(unit):
            unit["active"] = "failed"
            return 1, b""
        yaml = next(l for l in Path(unit["fragment"]).read_text().splitlines() if l.startswith("ExecStart=")).rsplit(" ", 1)[1]
        manifest = deploy.parse_pod(Path(yaml).read_text())
        name = manifest["metadata"]["name"]
        self.counter += 1
        pod_id = "%064x" % self.counter
        labels = manifest["metadata"]["labels"]
        self.pods[name] = {"Id": pod_id, "Name": name, "State": "Running", "Labels": dict(labels),
                           "Containers": [{"Id": "%064x" % (1000 + self.counter), "Name": name + "-" + c["name"], "State": "running"}
                                          for c in manifest["spec"]["containers"]],
                           "unit": service}
        devices = {v["name"]: v["hostPath"]["path"] for v in manifest["spec"].get("volumes", [])
                   if v.get("hostPath", {}).get("type") == "CharDevice"}
        self.pods[name]["devices"] = bool(devices)
        (self.root / "oci").mkdir(exist_ok=True)
        for container, record in zip(manifest["spec"]["containers"], self.pods[name]["Containers"]):
            # What kube play gives a rootless container for a CharDevice hostPath: a read-write bind of the node.
            mounts = [] if self.drop_devices else [
                {"type": "bind", "source": devices[m["name"]], "destination": m["mountPath"], "options": ["slave", "nosuid", "noexec", "rw", "rbind"]}
                for m in container.get("volumeMounts", []) if m["name"] in devices]
            path = self.root / "oci" / (record["Id"] + ".json")
            path.write_text(json.dumps({"mounts": [{"type": "tmpfs", "source": "tmpfs", "destination": "/dev"}, *mounts]}))
            record["oci"] = str(path)
        for container in manifest["spec"]["containers"]:
            for port in container.get("ports", []):
                self.listeners.append({"protocol": port["protocol"].lower(), "address": port.get("hostIP", "0.0.0.0"),
                                       "port": port["hostPort"], "pod": name})
        unit["active"] = "active"
        unit["invocation"] = "%032x" % self.counter
        return 0, b""

    def stop(self, service):
        unit = self.units.get(service)
        if unit is None:
            return 5, b""
        unit["active"] = "inactive"
        if not self.leave_pod_on_stop:
            for name in [n for n, pod in self.pods.items() if pod["unit"] == service]:
                self.pods.pop(name)
                self.listeners = [l for l in self.listeners if l.get("pod") != name]
        return 0, b""

    # podman ------------------------------------------------------------
    def containers(self):
        for pod in self.pods.values():
            for container in pod["Containers"]:
                yield container, {**pod["Labels"], "PODMAN_SYSTEMD_UNIT": pod["unit"]}

    def podman(self, args):
        if args[0] == "--version":
            return 0, ("podman version " + self.podman_version + "\n").encode()
        if args[:2] == ["info", "--format"]:
            (self.root / "storage").mkdir(exist_ok=True)
            return 0, json.dumps({"host": {"arch": "amd64", "security": {"rootless": True}},
                                  "store": {"graphRoot": str(self.root / "storage")}}).encode()
        if args[:2] == ["pod", "exists"]:
            return (0 if args[2] in self.pods else 1), b""
        if args[:2] == ["pod", "inspect"]:
            pod = self.pods[args[2]]
            return 0, json.dumps([{k: v for k, v in pod.items() if k not in ("unit", "devices")}]).encode()
        if args[:2] == ["container", "inspect"]:
            found = [c for c, _ in self.containers() if c["Id"] == args[2]]
            return (0, json.dumps([{"Id": found[0]["Id"], "OCIConfigPath": found[0]["oci"]}]).encode()) if found else (125, b"")
        if args[0] == "ps":
            key, _, value = args[args.index("--filter") + 1].removeprefix("label=").partition("=")
            return 0, json.dumps([{"Id": c["Id"], "State": c["State"]} for c, labels in self.containers() if labels.get(key) == value]).encode()
        if args[:2] == ["container", "exists"]:
            return (0 if args[2] in self.foreign_containers or any(c["Name"] == args[2] for c, _ in self.containers()) else 1), b""
        if args[:2] == ["image", "inspect"]:
            record = self.images.get(args[2])
            return (0, json.dumps([record]).encode()) if record else (125, b"")
        if args[0] == "pull":
            if self.fail_pull:
                return 125, b""
            reference = args[-1]
            repository = reference.split("@")[0].rsplit(":", 1)[0] if "@" not in reference else reference.split("@")[0]
            digest = reference.split("@", 1)[1] if "@" in reference else DIGEST
            self.images[reference] = {"Id": "f" * 64, "RepoDigests": [repository + "@" + digest], "Architecture": "amd64", "Os": "linux"}
            return 0, b"f" * 64
        raise AssertionError("unexpected podman " + repr(args))

    def run(self, argv, timeout, env_extra=None):
        self.calls.append(list(argv))
        if argv[0] == deploy_remote.SYSTEMCTL:
            return self.systemctl(argv[1:])
        if argv[0] == deploy_remote.PODMAN:
            return self.podman(argv[1:])
        if argv[0] == deploy_remote.QUADLET:
            return self.quadlet(env_extra["QUADLET_UNIT_DIRS"])
        if argv[0] == deploy_remote.SYSTEMD_RUN:
            unit = next(a for a in argv if a.startswith("--unit=")).removeprefix("--unit=")
            if unit in self.pull_units:
                return 1, b""
            self.pull_units[unit] = {"reference": argv[-2], "directory": Path(argv[-1]), "argv": list(argv)}
            return 0, b""
        raise AssertionError("unexpected command " + repr(argv))

    def finish_pull(self, unit, code=0):
        """The detached pull's shell writes its exit code; a successful one leaves the image in the store."""
        pull = self.pull_units.pop(unit)
        (pull["directory"] / "log").write_text("Trying to pull " + pull["reference"] + "...\nCopying blob sha256:" + "a" * 64
                                               + "\nCopying blob sha256:" + "b" * 64 + "\nCopying config sha256:" + "c" * 64
                                               + ("\nWriting manifest to image destination\n" if code == 0 else "\nError: denied\n"))
        (pull["directory"] / "result").write_text(str(code) + "\n")
        if code == 0:
            self.images[pull["reference"]] = {"Id": "e" * 64, "RepoDigests": [pull["reference"]], "Architecture": "amd64", "Os": "linux"}

    def device_state(self, path):
        state = self.devices.get(path)
        if state is None:
            return {"path": path, "exists": False}
        state = copy.deepcopy(state)
        if state.get("gpu"):
            running = sum(1 for pod in self.pods.values() if pod.get("devices"))
            state["gpu"]["mem_info_vram_used"] = str(390860800 + running * self.vram_per_pod)
        return state

    def health(self, check, deadline):
        listening = any(l["port"] == check["port"] and l["protocol"] == check.get("protocol", "tcp") for l in self.listeners)
        ok = listening and not self.fail_health and check["port"] not in self.unhealthy_ports
        self.health_deadlines.append((check["id"], check["port"], deadline))
        return {"ok": ok, "attempts": 1, "type": check["type"], **({"status": 200} if ok else {"last": {"error": "refused"}})}

    def started(self, service):
        return self.units.get(service, {}).get("active") == "active"


class DeployFixture(unittest.TestCase):
    """Broker, manager and fake host; no tests (shared with test_deploy_gpu)."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.hosts = {}
        for name in ("alpha", "beta"):
            ledger = self.root / (name + ".ledger")
            self.hosts[name] = {"host_id": name, "transport": "ssh", "target": pwd.getpwuid(os.getuid()).pw_name + "@fixture.invalid",
                                "expected_hostname": platform.node(), "ledger": str(ledger), "user_units": [], "system_units": []}
        self.config = {"schema_version": 2, "shell_hosts": [], "workloads": {}, "deploy_hosts": ["alpha"]}
        self.config_path = self.root / "operations.json"
        self.write_config()
        self.broker = Broker(self.config_path, hosts=self.hosts, state_dir=self.root / "state")
        self.leases = LedgerBroker({name: Path(host["ledger"]) for name, host in self.hosts.items()},
                                  state_dir=self.broker.lease_state_dir)
        self.manager = deploy.DeployManager(self.broker)
        self.host = FakeHost(self.root)
        self.remote_actions, self.remote_payloads = [], []
        patch.object(self.broker, "_dispatch", side_effect=self.dispatch).start()
        patch.object(deploy, "run_remote", side_effect=self.fake_remote).start()
        for name, value in (("run", self.host.run), ("home", lambda: str(self.host.home)), ("listeners", lambda: copy.deepcopy(self.host.listeners)),
                            ("linger", lambda: True), ("health", self.host.health), ("QUADLET", sys.executable), ("SKOPEO_CANDIDATES", ()),
                            ("CATATONIT_CANDIDATES", (sys.executable,)), ("host_addresses", lambda: copy.deepcopy(self.host.addresses)),
                            ("unprivileged_port_start", lambda: self.host.port_start),
                            ("registry_manifest", lambda reference, timeout=10: (DIGEST, ["linux/amd64", "linux/arm64"])),
                            ("registry_size", lambda reference, arch, timeout=10: None if self.host.image_size is None
                             else {"bytes": self.host.image_size, "layers": 3}),
                            ("device_state", self.host.device_state),
                            ("is_device_node", lambda path: path in self.host.devices)):
            patch.object(deploy_remote, name, value).start()
        for signum in (operation_worker.signal.SIGTERM, operation_worker.signal.SIGINT):
            self.addCleanup(operation_worker.signal.signal, signum, operation_worker.signal.getsignal(signum))
        self.addCleanup(patch.stopall)

    def write_config(self):
        self.config_path.write_text(json.dumps(self.config))

    def fake_remote(self, host, source, payload, *, timeout, local=False):
        lease = self.leases.store.current(resource_label(host["host_id"], host["ledger"]))
        self.assertIsNotNone(lease)  # durable authority is held for the whole remote step
        self.assertEqual((lease["resource"], lease["owner"], lease["status"]), (host["host_id"], "switchyard", "claimed"))
        self.assertFalse(Path(host["ledger"]).exists())  # metadata only, never a second authority
        self.assertIn("def main(payload)", source)
        self.assertTrue(1 <= timeout <= 270)
        self.remote_actions.append(payload["action"])
        self.remote_payloads.append(copy.deepcopy(payload))
        hook = getattr(self, "remote_hook", None)
        if hook:
            hook(payload)  # a test may raise here: transport loss or a worker crash before the step runs
        return json.loads(json.dumps(deploy_remote.main(json.loads(json.dumps(payload)))))

    def dispatch(self, receipt, payload):
        payload = {**payload, "operation_id": receipt["id"], "state_dir": str(self.broker.store.directory),
                   "lease_state_dir": str(self.broker.lease_state_dir),
                   "hosts": {key: self.hosts[key] for key in receipt["host_ids"]}}
        payload.pop("operation_hosts", None)
        output = io.StringIO()
        with patch.object(operation_worker.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(encode(payload).encode()))), \
                patch.object(operation_worker.signal, "signal"), redirect_stdout(output):
            operation_worker.main()
        return {"receipt": self.broker.receipt(receipt["id"])}

    # helpers -------------------------------------------------------------
    def save_template(self, revision=1, expected=0, **changes):
        document = copy.deepcopy(TEMPLATE)
        document.update(revision=revision, **changes)
        return self.manager.save_template(document, expected_revision=expected)

    def plan(self, instance="garden", **kwargs):
        kwargs.setdefault("template", "static-web")
        return self.manager.plan(instance_id=instance, host_id=kwargs.pop("host", "alpha"), **kwargs)

    def deploy(self, instance="garden", request_id=None, **kwargs):
        plan = self.plan(instance, **kwargs)
        self.assertTrue(plan["executable"], plan["blockers"])
        result = self.manager.apply(plan["id"], approved=True, request_id=request_id or "apply-" + instance)
        return plan, result

    def act(self, instance, action, request_id):
        return self.manager.act(instance, action, approved=True, request_id=request_id)

    def state(self, instance="garden"):
        return self.manager.show(instance)["placement"]

    def paths(self, instance="garden"):
        return self.state(instance)["meta"]["native"]["paths"]


class DeployTests(DeployFixture):
    # tests ---------------------------------------------------------------
    def test_template_cas_and_revision_pinning(self):
        saved = self.save_template()
        self.assertEqual((saved["revision"], saved["deployable"]), (1, True))
        with self.assertRaisesRegex(ValueError, "revision conflict"):
            self.save_template(expected=0)
        with self.assertRaisesRegex(ValueError, "must declare revision 2"):
            self.save_template(revision=3, expected=1)
        second = self.save_template(revision=2, expected=1, purpose="Second revision.")
        self.assertNotEqual(saved["content_sha256"], second["content_sha256"])
        self.assertEqual(self.manager.template("static-web@1")["content_sha256"], saved["content_sha256"])
        self.assertEqual(self.manager.template("static-web")["revision"], 2)
        plan = self.plan(template="static-web@1")
        self.assertEqual(plan["application"]["template_ref"], {"id": "static-web", "revision": 1})
        self.assertEqual(plan["template"]["content_sha256"], saved["content_sha256"])
        with self.assertRaisesRegex(ValueError, "role template"):
            self.manager.save_template({**copy.deepcopy(TEMPLATE), "id": "other", "role": "instance"}, expected_revision=0)

    def test_spec_validate_reports_hash_or_errors(self):
        result = deploy.validate_document(json.loads((ROOT / "docs/spec/examples/02-static-web.json").read_text()))
        self.assertEqual(len(result["applications"]), 2)
        current = spec.upgrade(TEMPLATE)[0]  # the catalog file may still be in the stored v1alpha2 form
        self.assertEqual(deploy.validate_document(TEMPLATE)["content_sha256"], spec.Application.model_validate(current).content_sha256())
        with self.assertRaisesRegex(ValueError, "Invalid Application"):
            deploy.validate_document({**TEMPLATE, "surprise": 1})

    def test_missing_pause_binary_blocks_the_plan(self):
        # Podman without the separate `catatonit` package cannot start any pod.
        self.save_template()
        with patch.object(deploy_remote, "CATATONIT_CANDIDATES", ()):
            plan = self.plan()
        self.assertFalse(plan["executable"])
        self.assertIn("pod-pause-binary", [item["id"] for item in plan["preconditions"] if not item["ok"]])
        self.assertEqual(self.host.units, {})

    def test_inactive_network_online_target_blocks_units_that_wait_for_it(self):
        # With Podman 6.2, the generated unit waits up to 90 s for the system's
        # network-online.target, which nothing had pulled into boot, so every start ran past the deadline.
        self.save_template()
        real = deploy_remote.quadlet_dryrun
        waiting = lambda payload: {**real(payload), "waits_network_online": True}
        with patch.object(deploy_remote, "quadlet_dryrun", side_effect=waiting), \
                patch.object(deploy_remote, "network_online", return_value=False):
            plan = self.plan()
        blocked = {item["id"]: item for item in plan["preconditions"] if not item["ok"]}
        self.assertEqual(plan["blockers"], ["network-online"])
        self.assertIn("add-wants multi-user.target network-online.target", blocked["network-online"]["evidence"]["operator_command"])
        with patch.object(deploy_remote, "quadlet_dryrun", side_effect=waiting), \
                patch.object(deploy_remote, "network_online", return_value=True):
            self.assertTrue(self.plan("orchard")["executable"])
        self.assertTrue(self.plan("meadow")["executable"])  # A unit that does not wait is never asked about the target.

    def test_plan_contents_expiry_and_approval(self):
        self.save_template()
        plan = self.plan()
        self.assertEqual(self.remote_actions, ["facts", "inspect"])
        self.assertTrue(plan["executable"])
        self.assertEqual(plan["generation"], 1)
        self.assertEqual(plan["image"]["digest"], DIGEST)
        self.assertIn("@" + DIGEST, plan["application"]["components"][0]["native"]["manifest"]["spec"]["containers"][0]["image"])
        self.assertEqual(plan["native"]["claims"], [{"endpoint": "http", "address": "127.0.0.1", "protocol": "tcp", "port": 18100}])
        unit = plan["native"]["files"]["unit"]["text"]
        self.assertIn("ExecStartPre=" + plan["native"]["gate_command"], unit)
        self.assertIn("ownership-id=" + plan["ownership_id"], plan["native"]["gate_command"])
        self.assertEqual(plan["token_path"], str(self.host.home) + "/.local/share/switchyard/apps/garden/web.token")
        self.assertEqual([a["gate"] for a in plan["approvals"]], ["deploy authority", "plan approval"])
        self.assertFalse(plan["checkpoints"]["destructive"])
        self.assertTrue(all(p["ok"] for p in plan["preconditions"]), plan["preconditions"])
        self.assertLessEqual(datetime.fromisoformat(plan["expires_at"]) - datetime.now(timezone.utc), timedelta(minutes=10))
        with self.assertRaisesRegex(ValueError, "explicit approval"):
            self.manager.apply(plan["id"], approved=False, request_id="no-approval")
        with self.broker.store.transaction() as db:
            stale = {**plan, "expires_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()}
            db.execute("UPDATE plans SET data=? WHERE id=?", (encode(stale), plan["id"]))
        with self.assertRaisesRegex(ValueError, "expired"):
            self.manager.apply(plan["id"], approved=True, request_id="expired")
        self.assertEqual(self.host.units, {})

    def test_rendered_pod_stays_inside_subset_with_ownership_labels(self):
        self.save_template()
        plan = self.plan()
        manifest = deploy.parse_pod(plan["native"]["files"]["yaml"]["text"])
        labels = manifest["metadata"]["labels"]
        self.assertEqual({labels["io.switchyard/" + k] for k in ("ownership-id", "instance", "generation")},
                         {plan["ownership_id"], "garden", "1"})
        bindings = {d["id"]: d["path"] for d in plan["native"]["datasets"]}
        pod = deploy.unpublish(manifest, bindings)
        self.assertEqual(pod.spec.volumes[0].hostPath.path, "dataset://site")
        port = manifest["spec"]["containers"][0]["ports"][0]
        self.assertEqual((port["hostIP"], port["hostPort"]), ("127.0.0.1", 18100))
        self.assertEqual(manifest["metadata"]["name"], "switchyard-garden-web")

    def test_deploy_fence_unfence_start_stop_undeploy_redeploy(self):
        self.save_template()
        plan, result = self.deploy()
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        self.assertEqual(result["receipt"]["instance_id"], "garden")
        events = {e["event"]: e["data"] for e in result["receipt"]["events"]}
        self.assertEqual(events["deploy-intent"]["files"]["unit"]["sha256"], plan["native"]["files"]["unit"]["sha256"])
        state = self.state()
        self.assertEqual((state["state"], state["meta"]["token"]["state"]), ("active", "valid"))
        placement = spec.Placement.model_validate(state["placement"])
        self.assertEqual(placement.fence.tokens[0].state, "valid")
        paths = self.paths()
        self.assertEqual(Path(paths["unit"]).read_text(), plan["native"]["files"]["unit"]["text"])
        self.assertEqual(oct(Path(paths["token"]).stat().st_mode & 0o777), "0o600")
        self.assertTrue(Path(paths["data_root"], "site").is_dir())
        service = plan["native"]["names"]["service"]
        self.assertTrue(self.host.started(service))
        claims = self.manager.store.all_claims()
        self.assertEqual([(c["owner_kind"], c["port"]) for c in claims], [("placement", 18100)])

        fenced = self.act("garden", "fence", "fence-1")
        self.assertEqual(fenced["receipt"]["status"], "succeeded", fenced)
        state = self.state()
        self.assertEqual(state["state"], "fenced")
        self.assertEqual(spec.Placement.model_validate(state["placement"]).fence.tokens[0].state, "revoked")
        self.assertFalse(self.host.started(service))
        self.assertEqual(self.host.pods, {})
        self.assertTrue(Path(paths["token"]).read_text().startswith("switchyard-generation-token/v1 revoked "))
        # Manual start while fenced: the native gate refuses without Switchyard.
        self.assertEqual(self.host.start(service)[0], 1)
        self.assertEqual(self.host.pods, {})
        with self.assertRaisesRegex(ValueError, "fenced; unfence first"):
            self.act("garden", "start", "start-while-fenced")
        self.assertEqual(self.act("garden", "fence", "fence-1")["receipt"]["id"], fenced["receipt"]["id"])

        self.assertEqual(self.act("garden", "unfence", "unfence-1")["receipt"]["status"], "succeeded")
        state = self.state()
        self.assertEqual((state["state"], state["meta"]["token"]["state"]), ("staged", "valid"))
        self.assertFalse(self.host.started(service))
        self.assertEqual(self.act("garden", "start", "start-1")["receipt"]["status"], "succeeded")
        self.assertEqual(self.state()["state"], "active")
        self.assertEqual(self.act("garden", "stop", "stop-1")["receipt"]["status"], "succeeded")
        state = self.state()
        self.assertEqual((state["state"], state["meta"]["token"]["state"]), ("staged", "valid"))
        self.assertFalse(self.host.started(service))

        Path(paths["data_root"], "site", "index.html").write_text("<p>kept</p>")
        undeploy = self.manager.undeploy_plan("garden")
        self.assertEqual(undeploy["datasets"][0]["action"], "keep")
        self.assertFalse(undeploy["checkpoints"]["destructive"]["required"])
        done = self.manager.undeploy_apply(undeploy["id"], approved=True, request_id="undeploy-1")
        self.assertEqual(done["receipt"]["status"], "succeeded", done)
        self.assertEqual(self.state()["state"], "retired")
        for key in ("unit", "yaml", "token", "owner"):
            self.assertFalse(os.path.lexists(paths[key]), key)
        self.assertEqual(Path(paths["data_root"], "site", "index.html").read_text(), "<p>kept</p>")
        self.assertNotIn(service, self.host.units)
        self.assertEqual(self.manager.store.all_claims(), [])
        self.assertEqual(self.manager.show("garden")["instance"]["template_ref"], {"id": "static-web", "revision": 1})

        again = self.plan(template=None)
        self.assertEqual((again["generation"], again["redeploy"]), (2, True))
        self.assertTrue(again["executable"], again["blockers"])
        result = self.manager.apply(again["id"], approved=True, request_id="apply-garden-2")
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        self.assertEqual(self.state()["generation"], 2)
        self.assertEqual(Path(paths["data_root"], "site", "index.html").read_text(), "<p>kept</p>")
        self.assertIn("generation=2", Path(paths["token"]).read_text())

    def test_request_id_idempotency(self):
        self.save_template()
        plan, first = self.deploy(request_id="same")
        actions = list(self.remote_actions)
        replay = self.manager.apply(plan["id"], approved=True, request_id="same")
        self.assertEqual(replay["receipt"]["id"], first["receipt"]["id"])
        self.assertEqual(self.remote_actions, actions)
        with self.assertRaisesRegex(ValueError, "different intent"):
            self.act("garden", "fence", "same")
        other = self.plan("other")
        with self.assertRaisesRegex(ValueError, "different intent"):
            self.manager.apply(other["id"], approved=True, request_id="same")

    def test_health_failure_after_write_leaves_staged_revoked_and_stopped(self):
        self.save_template()
        self.host.fail_health = True
        plan, result = self.deploy()
        self.assertEqual(result["receipt"]["status"], "failed", result)
        state = self.state()
        self.assertEqual((state["state"], state["meta"]["token"]["state"], state["meta"]["uncertain"]), ("staged", "revoked", False))
        self.assertFalse(self.host.started(plan["native"]["names"]["service"]))
        self.assertEqual(self.host.pods, {})
        self.assertIn("revoked", Path(self.paths()["token"]).read_text())
        self.assertEqual(self.remote_actions.count("start"), 1)  # never retried
        with self.assertRaisesRegex(ValueError, "valid generation token"):
            self.act("garden", "start", "start-revoked")
        self.assertEqual(self.act("garden", "unfence", "unfence-after-failure")["receipt"]["status"], "succeeded")
        self.host.fail_health = False
        self.assertEqual(self.act("garden", "start", "start-after-unfence")["receipt"]["status"], "succeeded")

    def test_listener_between_prepare_and_start_revokes_token_and_proves_stopped(self):
        self.save_template()
        plan = self.plan()
        service = plan["native"]["names"]["service"]

        def race(host, source, payload, *, timeout, local=False):
            if payload["action"] == "start":
                self.host.listeners.append({"protocol": "tcp", "address": "0.0.0.0", "port": 18100})
            return self.fake_remote(host, source, payload, timeout=timeout, local=local)

        with patch.object(deploy, "run_remote", side_effect=race):
            result = self.manager.apply(plan["id"], approved=True, request_id="race")
        self.assertEqual(result["receipt"]["status"], "failed", result)
        state = self.state()
        self.assertEqual((state["state"], state["meta"]["token"]["state"], state["meta"]["runtime"], state["meta"]["uncertain"]),
                         ("staged", "revoked", "stopped", False))
        self.assertIn("revoked", Path(self.paths()["token"]).read_text())
        self.assertFalse(self.host.started(service))
        self.assertEqual(self.host.start(service)[0], 1)  # boot/manual start path stays gated
        self.assertEqual(self.host.pods, {})

    def test_start_precheck_failure_with_unrevokable_token_is_uncertain(self):
        self.save_template()
        plan = self.plan()

        def race(host, source, payload, *, timeout, local=False):
            if payload["action"] == "start":
                self.host.listeners.append({"protocol": "tcp", "address": "0.0.0.0", "port": 18100})
            return self.fake_remote(host, source, payload, timeout=timeout, local=local)

        def broken_revoke(payload):
            raise OSError("read-only filesystem")

        with patch.object(deploy, "run_remote", side_effect=race), patch.object(deploy_remote, "revoke_token", broken_revoke):
            result = self.manager.apply(plan["id"], approved=True, request_id="race-unrevoked")
        self.assertEqual(result["receipt"]["status"], "needs-inspection", result)
        state = self.state()
        self.assertEqual((state["state"], state["meta"]["token"]["state"], state["meta"]["uncertain"]), ("staged", "unknown", True))
        with self.assertRaisesRegex(ValueError, "uncertain"):
            self.act("garden", "start", "start-after-unrevoked")
        self.assertEqual(self.act("garden", "fence", "fence-recovery")["receipt"]["status"], "succeeded")
        self.assertEqual(self.state()["state"], "fenced")

    def test_prepare_failure_after_writing_observes_runtime_and_revokes(self):
        self.save_template()
        plan = self.plan()
        self.host.fail_reload = True
        result = self.manager.apply(plan["id"], approved=True, request_id="reload-fails")
        self.assertEqual(result["receipt"]["status"], "failed", result)
        state = self.state()
        self.assertEqual((state["state"], state["meta"]["token"]["state"], state["meta"]["runtime"], state["meta"]["uncertain"]),
                         ("staged", "revoked", "stopped", False))
        failed = next(e["data"] for e in result["receipt"]["events"] if e["event"] == "deploy-failed")
        self.assertTrue(failed["cleanup"]["stop"]["pod_absent"])
        self.assertNotIn("start", self.remote_actions)

    def test_apply_refuses_drift_and_withdraws_unwritten_intent(self):
        self.save_template()
        plan = self.plan()
        self.host.listeners.append({"protocol": "tcp", "address": "0.0.0.0", "port": 18100})
        result = self.manager.apply(plan["id"], approved=True, request_id="drift")
        self.assertEqual(result["receipt"]["status"], "failed")
        self.assertIn("Nothing written", result["receipt"]["error"])
        self.assertFalse((self.host.home / ".local/share/switchyard/apps/garden").exists())
        self.assertEqual(self.manager.list(), [])
        self.assertEqual(self.manager.store.all_claims(), [])
        with self.assertRaisesRegex(ValueError, "already executed"):
            self.manager.apply(plan["id"], approved=True, request_id="drift-again")
        # A foreign pod with the generated name is a collision at plan time.
        self.host.listeners.clear()
        self.host.pods["switchyard-garden-web"] = {"Id": "e" * 64, "Name": "switchyard-garden-web", "State": "Running",
                                                   "Labels": {}, "Containers": [], "unit": "other.service"}
        blocked = self.plan()
        self.assertFalse(blocked["executable"])
        self.assertIn("name-collisions", blocked["blockers"])

    def test_port_registry_conflicts_wildcards_listeners_and_reservations(self):
        self.save_template()
        self.deploy("first", ports={"http": 18100})
        explicit = self.plan("second", ports={"http": 18100})
        self.assertIn("port-http", explicit["blockers"])
        wildcard = self.plan("second", ports={"http": 18100}, addresses={"http": "0.0.0.0"})
        self.assertIn("port-http", wildcard["blockers"])
        other_address = self.plan("second", ports={"http": 18100}, addresses={"http": "127.0.0.2"})
        self.assertTrue(other_address["executable"], other_address["blockers"])
        # That plan's reservation now blocks a third plan until it expires.
        self.assertIn("port-http", self.plan("third", ports={"http": 18100}, addresses={"http": "127.0.0.2"})["blockers"])
        with self.manager.store.transaction() as db:
            db.execute("UPDATE claims SET expires_at=? WHERE owner_kind='plan'", ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),))
        self.assertTrue(self.plan("third", ports={"http": 18100}, addresses={"http": "127.0.0.2"})["executable"])
        self.host.listeners.append({"protocol": "tcp", "address": "::", "port": 18101})
        auto = self.plan("fourth")
        self.assertEqual(auto["native"]["claims"][0]["port"], 18102)
        live = self.plan("fifth", ports={"http": 18101})
        self.assertEqual(live["preconditions"][[p["id"] for p in live["preconditions"]].index("port-http")]["evidence"]["conflicts"]["listeners"][0]["port"], 18101)
        with self.assertRaisesRegex(ValueError, "unexpired plan"):
            self.plan("fourth")

    def test_instance_uniqueness_and_policy(self):
        self.save_template()
        self.deploy()
        with self.assertRaisesRegex(ValueError, "already placed"):
            self.plan()
        with self.assertRaisesRegex(ValueError, "deploy_hosts"):
            self.plan("elsewhere", host="beta")
        self.config["deploy_hosts"] = []
        self.write_config()
        with self.assertRaisesRegex(ValueError, "deploy_hosts"):
            self.act("garden", "fence", "fence-unauthorized")
        self.config["deploy_hosts"] = ["nowhere"]
        self.write_config()
        with self.assertRaisesRegex(ValueError, "Deploy hosts require"):
            self.broker.policy()

    def test_authority_revoked_after_dispatch_executes_nothing(self):
        self.save_template()
        plan = self.plan()
        original = self.dispatch

        def revoke(receipt, payload):
            self.config["deploy_hosts"] = []
            self.write_config()
            return original(receipt, payload)

        self.remote_actions.clear()
        with patch.object(self.broker, "_dispatch", side_effect=revoke):
            result = self.manager.apply(plan["id"], approved=True, request_id="revoked")
        self.assertEqual(result["receipt"]["status"], "failed")
        self.assertEqual(self.remote_actions, [])

    def test_undeploy_touches_only_owned_resources(self):
        self.save_template()
        operator_site = self.root / "operator-site"
        operator_site.mkdir()
        (operator_site / "index.html").write_text("operator content")
        foreign = self.host.home / ".config/containers/systemd/other-app.container"
        self.deploy(datasets={"site": str(operator_site)})
        foreign.write_text("[Container]\nImage=example\n")
        paths = self.paths()
        unit = Path(paths["unit"]).read_text()
        Path(paths["unit"]).chmod(0o644)
        Path(paths["unit"]).write_text(unit + "# edited\n")
        with self.assertRaisesRegex(ValueError, "differs from the recorded deployment hash"):
            self.manager.undeploy_plan("garden")
        Path(paths["unit"]).write_text(unit)
        self.host.pods["switchyard-garden-web"]["Labels"]["io.switchyard/ownership-id"] = "someone-else"
        with self.assertRaisesRegex(ValueError, "ownership labels"):
            self.manager.undeploy_plan("garden")
        self.host.pods["switchyard-garden-web"]["Labels"]["io.switchyard/ownership-id"] = self.state()["meta"]["ownership_id"]
        plan = self.manager.undeploy_plan("garden", delete_data=True)
        self.assertEqual(plan["datasets"][0]["action"], "keep")  # operator path: never deleted
        self.assertEqual(self.manager.undeploy_apply(plan["id"], approved=True, request_id="undeploy")["receipt"]["status"], "succeeded")
        self.assertEqual((operator_site / "index.html").read_text(), "operator content")
        self.assertTrue(foreign.exists())
        # A unit that refused to start stays "failed" after its file is gone; undeploy clears only its own.
        self.assertEqual(self.host.reset_failed, ["switchyard-garden-web.service"])

    def test_retired_instance_can_move_to_a_host_it_never_ran_on(self):
        # One fake filesystem stands in for whichever host is asked; removing the mark makes it a fresh host.
        self.save_template()
        self.deploy()
        app_dir = Path(self.paths()["app_dir"])
        plan = self.manager.undeploy_plan("garden", delete_data=True)
        self.assertEqual(self.manager.undeploy_apply(plan["id"], approved=True, request_id="leave-alpha")["receipt"]["status"], "succeeded")
        (app_dir / "generation").unlink()
        self.config["deploy_hosts"] = ["alpha", "beta"]
        self.write_config()
        moved = self.plan("garden", host="beta", template=None)
        self.assertEqual((moved["blockers"], moved["generation"], moved["expected_host_generation"]), ([], 2, None))
        # On a host it did run on, a missing mark is still a blocker: the journal expects generation 1 there.
        self.deploy("orchard")
        orchard_dir = Path(self.paths("orchard")["app_dir"])
        plan = self.manager.undeploy_plan("orchard", delete_data=True)
        self.assertEqual(self.manager.undeploy_apply(plan["id"], approved=True, request_id="leave-orchard")["receipt"]["status"], "succeeded")
        (orchard_dir / "generation").unlink()
        back = self.plan("orchard", host="alpha", template=None)
        self.assertEqual((back["blockers"], back["expected_host_generation"]), (["host-generation"], 1))

    def test_placed_instances_join_the_fleet_as_workloads_observed_like_defined_ones(self):
        from switchyard.definitions import resolve_definitions
        self.save_template()
        self.deploy()
        item, = self.manager.workload_definitions()
        definition, deployment = item["definition"], item["deployment"]
        self.assertEqual((definition["id"], definition["device_id"], definition["management"]), ("garden", "alpha", "deployed"))
        self.assertEqual((deployment["state"], deployment["token"], deployment["generation"]), ("active", "valid", 1))
        container = definition["bindings"][0]["selector"]["name"]
        self.assertEqual((container, definition["bindings"][0]["role"]), ("switchyard-garden-web-web", "primary"))
        # The same join the fleet uses for defined workloads finds the running container by that name.
        observed = {"id": "container:1", "host_id": "alpha", "backend": "podman", "scope": definition["bindings"][0]["scope"],
                    "native_id": "abc", "name": container, "kind": "service", "lifecycle": "running",
                    "observed_at": datetime.now(timezone.utc).isoformat()}
        workload, = resolve_definitions([definition], [observed])
        self.assertEqual((workload["lifecycle"], workload["bindings_evidence"][0]["status"]), ("running", "matched"))
        # Fenced instances stay listed (the journal still places them); retired ones leave the fleet.
        self.assertEqual(self.act("garden", "fence", "fence-for-fleet")["receipt"]["status"], "succeeded")
        self.assertEqual(self.manager.workload_definitions()[0]["deployment"]["state"], "fenced")
        plan = self.manager.undeploy_plan("garden", delete_data=True)
        self.assertEqual(self.manager.undeploy_apply(plan["id"], approved=True, request_id="leave-fleet")["receipt"]["status"], "succeeded")
        self.assertEqual(self.manager.workload_definitions(), [])

    def test_delete_data_removes_only_switchyard_created_dataset(self):
        self.save_template()
        self.deploy()
        site = Path(self.paths()["data_root"], "site")
        (site / "page.html").write_text("x" * 100)
        plan = self.manager.undeploy_plan("garden", delete_data=True)
        destructive = plan["checkpoints"]["destructive"]
        self.assertTrue(destructive["required"])
        self.assertEqual(destructive["delete"][0]["size"]["bytes"], 100)
        self.assertEqual(self.manager.undeploy_apply(plan["id"], approved=True, request_id="purge")["receipt"]["status"], "succeeded")
        self.assertFalse(site.exists())
        app_dir = Path(self.paths()["app_dir"])
        self.assertEqual(sorted(os.listdir(app_dir)), ["generation"])

    def test_leftover_pod_after_stop_makes_fence_uncertain(self):
        self.save_template()
        self.deploy()
        self.host.leave_pod_on_stop = True
        result = self.act("garden", "fence", "fence-leftover")
        self.assertEqual(result["receipt"]["status"], "needs-inspection")
        state = self.state()
        self.assertTrue(state["meta"]["uncertain"])
        with self.assertRaisesRegex(ValueError, "uncertain"):
            self.act("garden", "start", "start-uncertain")

    def test_transport_loss_after_intent_is_needs_inspection(self):
        self.save_template()
        plan = self.plan()

        def lost(host, source, payload, *, timeout, local=False):
            if payload["action"] == "start":
                raise RemoteError("transport lost")
            return self.fake_remote(host, source, payload, timeout=timeout, local=local)

        with patch.object(deploy, "run_remote", side_effect=lost):
            result = self.manager.apply(plan["id"], approved=True, request_id="lost")
        self.assertEqual(result["receipt"]["status"], "needs-inspection")
        state = self.state()
        self.assertEqual(state["state"], "staged")
        self.assertTrue(state["meta"]["uncertain"])
        self.assertEqual([c["owner_kind"] for c in self.manager.store.all_claims()], ["placement"])

    def test_pull_at_apply_pins_observed_digest(self):
        self.save_template()
        with patch.object(deploy_remote, "registry_manifest", side_effect=OSError("offline")):
            plan = self.plan()
        self.assertEqual(plan["image"]["resolution"], "pull-at-apply")
        self.assertTrue(plan["executable"], plan["blockers"])
        result = self.manager.apply(plan["id"], approved=True, request_id="pull-at-apply")
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        app = self.manager.show("garden")["application"]
        self.assertTrue(app["components"][0]["native"]["manifest"]["spec"]["containers"][0]["image"].endswith("@" + DIGEST))

    def test_cli_register_and_handle(self):
        parser = argparse.ArgumentParser()
        commands = parser.add_subparsers(dest="command", required=True)
        deploy.register_cli(commands)
        service = SimpleNamespace(deployments=lambda: self.manager)
        path = self.root / "template.json"
        path.write_text(json.dumps(TEMPLATE))
        saved = deploy.handle_cli(parser.parse_args(["template", "save", str(path), "--expected-revision", "0"]), service)
        self.assertEqual(saved["revision"], 1)
        self.assertEqual(deploy.handle_cli(parser.parse_args(["spec", "validate", str(path)]), service)["id"], "static-web")
        plan = deploy.handle_cli(parser.parse_args(["deploy", "plan", "--template", "static-web", "--instance", "garden",
                                                    "--host", "alpha", "--port", "http=18150"]), service)
        self.assertEqual(plan["native"]["claims"][0]["port"], 18150)
        with self.assertRaisesRegex(ValueError, "approval"):
            deploy.handle_cli(parser.parse_args(["deploy", "apply", plan["id"], "--request-id", "x"]), service)
        self.assertEqual(deploy.handle_cli(parser.parse_args(["deploy", "list"]), service), [])
        self.manager.apply(plan["id"], approved=True, request_id="cli-apply")
        before = list(self.remote_actions)
        preview = deploy.handle_cli(parser.parse_args(["deploy", "fence", "garden"]), service)["preview"]
        self.assertEqual((preview["from"]["state"], preview["action"]), ("active", "fence"))
        self.assertEqual(self.remote_actions, before)  # preview never contacts the host
        with self.assertRaisesRegex(ValueError, "request-id"):
            deploy.handle_cli(parser.parse_args(["deploy", "fence", "garden", "--approve"]), service)
        self.assertEqual(deploy.handle_cli(parser.parse_args(["deploy", "list"]), service)[0]["state"], "active")
        with self.assertRaisesRegex(ValueError, "KEY=VALUE"):
            deploy.handle_cli(parser.parse_args(["deploy", "plan", "--instance", "x", "--host", "alpha", "--port", "http"]), service)
        self.assertIsNone(deploy.handle_cli(SimpleNamespace(command="fleet"), service))

    # ---------------------------------------------------------------- v1alpha3 gates and stored v1alpha2 rows
    def test_deployed_instance_declares_and_binds_its_generation_gate(self):
        self.save_template()
        plan, result = self.deploy()
        gates = plan["application"]["components"][0]["gates"]
        self.assertEqual([(g["id"], g["kind"], g["target"]) for g in gates],
                         [("generation-gate", "exec-start-pre", "switchyard-garden-web.service")])
        state = self.state()
        token = spec.Placement.model_validate(state["placement"]).fence.tokens[0]
        self.assertEqual([g.gate for g in token.gates], ["generation-gate"])
        app = spec.Application.model_validate(self.manager.show("garden")["application"])
        spec.check_placement(app, spec.Placement.model_validate(state["placement"]))
        gated = copy.deepcopy(spec.upgrade(TEMPLATE)[0])
        gated.update(id="gated", revision=1)
        gated["components"][0]["gates"] = [deploy.generation_gate("x.service")]
        saved = self.manager.save_template(gated, expected_revision=0)
        self.assertEqual((saved["deployable"], saved["reason"]),
                         (False, "Templates declare no gates: Switchyard generates the instance's generation gate"))

    def downgrade_rows(self, instance="garden"):
        """Rewrite stored rows into the switchyard/v1alpha2 form the deploy store held before this version."""
        with self.manager.store.transaction() as db:
            for row in db.execute("SELECT id, revision, data FROM templates").fetchall():
                data = json.loads(row["data"])
                data["apiVersion"] = "switchyard/v1alpha2"
                db.execute("UPDATE templates SET data=? WHERE id=? AND revision=?", (encode(data), row["id"], row["revision"]))
            row = db.execute("SELECT revision, data FROM workloads WHERE id=? AND relation='deployed'", (instance,)).fetchone()
            data = json.loads(row["data"])
            data["apiVersion"] = "switchyard/v1alpha2"
            data["components"][0].pop("gates", None)
            db.execute("UPDATE workloads SET data=?, content_sha256=? WHERE id=?", (encode(data), "1" * 64, instance))
            db.execute("UPDATE workload_revisions SET data=?, content_sha256=? WHERE id=? AND revision=?",
                       (encode(data), "1" * 64, instance, row["revision"]))
            for row in db.execute("SELECT generation, data FROM placements WHERE instance_id=?", (instance,)).fetchall():
                data = json.loads(row["data"])
                data["apiVersion"] = "switchyard/v1alpha2"
                for token in (data.get("fence") or {}).get("tokens", []):
                    token.pop("gates")
                    token.update(gate="exec-start-pre", gate_ref="legacy unit ExecStartPre")
                db.execute("UPDATE placements SET data=? WHERE instance_id=? AND generation=?", (encode(data), instance, row["generation"]))

    def test_stored_v1alpha2_rows_load_and_redeploy_as_a_new_instance_revision(self):
        self.save_template()
        self.deploy()
        self.downgrade_rows()  # an active row with a single-gate token
        stored_hash = self.manager.store.templates()[0]["revisions"][0]["content_sha256"]
        template = self.manager.template("static-web@1")
        self.assertEqual((template["upgraded_from"], template["content_sha256"]), ("switchyard/v1alpha2", stored_hash))
        self.assertEqual(template["application"]["apiVersion"], spec.API_VERSION)
        legacy = self.state()["placement"]
        self.assertEqual(legacy["fence"]["tokens"][0]["gates"], [{"gate": "generation-gate", "evidence": "legacy unit ExecStartPre"}])
        self.assertEqual(self.act("garden", "fence", "fence-legacy")["receipt"]["status"], "succeeded")
        undeploy = self.manager.undeploy_plan("garden")
        self.assertEqual(self.manager.undeploy_apply(undeploy["id"], approved=True, request_id="undeploy-legacy")["receipt"]["status"], "succeeded")
        self.downgrade_rows()  # retired rows as stored by the previous version
        self.assertEqual(self.manager.list()[0]["state"], "retired")
        plan = self.plan(template=None)
        self.assertEqual(plan["instance_upgrade"]["from_revision"], 1)
        self.assertEqual((plan["application"]["revision"], plan["application"]["apiVersion"]), (2, spec.API_VERSION))
        result = self.manager.apply(plan["id"], approved=True, request_id="redeploy-upgraded")
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        shown = self.manager.show("garden")
        self.assertEqual((shown["instance"]["revision"], shown["placement"]["placement"]["revision"]), (2, 2))
        self.assertEqual(shown["instance"]["meta"]["history"][0]["from_content_sha256"], "1" * 64)
        self.assertEqual(shown["application"]["components"][0]["gates"][0]["id"], "generation-gate")
        self.assertEqual(self.manager.store.templates()[0]["revisions"][0]["content_sha256"], stored_hash)  # never rewritten
        # Revision 1, still referenced by the retired generation 1, keeps its exact stored form and hash.
        self.assertEqual([(g["generation"], g["state"], g["application_revision"]) for g in shown["generations"]],
                         [(1, "retired", 1), (2, "active", 2)])
        self.assertEqual([r["revision"] for r in shown["revisions"]], [1, 2])
        first = self.manager.instance_revision("garden@1")
        self.assertEqual((first["content_sha256"], first["stored_application"]["apiVersion"], first["upgraded_from"]),
                         ("1" * 64, "switchyard/v1alpha2", "switchyard/v1alpha2"))
        self.assertNotIn("gates", first["stored_application"]["components"][0])
        self.assertEqual(self.manager.instance_revision("garden@2")["stored_application"], shown["application"])
        with self.assertRaisesRegex(ValueError, "Unknown instance revision"):
            self.manager.instance_revision("garden@3")

    def test_upgrade_is_withdrawn_when_nothing_was_written(self):
        self.save_template()
        self.deploy()
        undeploy = self.manager.undeploy_plan("garden")
        self.manager.undeploy_apply(undeploy["id"], approved=True, request_id="undeploy")
        self.downgrade_rows()
        plan = self.plan(template=None)
        self.host.listeners.append({"protocol": "tcp", "address": "0.0.0.0", "port": plan["native"]["claims"][0]["port"]})
        result = self.manager.apply(plan["id"], approved=True, request_id="redeploy-busy")
        self.assertIn("Nothing written", result["receipt"]["error"])
        with self.manager.store.transaction() as db:
            row = self.manager.store.raw_instance(db, "garden")
        self.assertEqual((row[2], row[3], json.loads(row[6])["apiVersion"]), (1, "1" * 64, "switchyard/v1alpha2"))
        self.assertEqual([r["revision"] for r in self.manager.show("garden")["revisions"]], [1])  # withdrawn revision 2 gone

    # ---------------------------------------------------------------- registration of adopted applications
    def residents(self):
        return json.loads((ROOT / "tests/fixtures/residents.json").read_text())

    def renamed_residents(self, new_id):
        value = self.residents()
        value["applications"][0]["id"] = new_id
        for placement in value["placements"]:
            placement["application_id"] = new_id
        value["activation_inputs"][0]["application_id"] = new_id
        return value

    def test_register_adopted_application_with_revisions_and_provenance(self):
        raw = (ROOT / "tests/fixtures/residents.json").read_bytes()
        first = self.manager.register_application(json.loads(raw), expected_revision=0, submitted_by="residents agent",
                                                  source="03-residents.json", source_bytes=raw, host_ids=["host-c", "host-a"])
        self.assertEqual((first["id"], first["revision"], first["submitted_by"], first["warnings"]),
                         ("test-agent-cluster", 1, "residents agent", []))
        self.assertEqual(first["source_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertIn("no lifecycle", first["authority"])
        with self.assertRaisesRegex(ValueError, "revision conflict: latest is 1, expected 0"):
            self.manager.register_application(self.residents(), expected_revision=0)
        second = self.manager.register_application(self.residents(), expected_revision=1, host_ids=["host-c"])
        self.assertEqual(second["revision"], 2)
        self.assertEqual(second["warnings"], ["Placement test-cluster-station names host host-a, which is not in the host registry"])
        self.assertEqual(self.manager.registered_application("test-agent-cluster@1")["meta"]["submitted_by"], "residents agent")
        listed = self.manager.registered_applications()
        self.assertEqual([(r["id"], r["revision"], len(r["placements"])) for r in listed], [("test-agent-cluster", 2, 2)])
        self.assertEqual(self.remote_actions, [])  # never contacts a host
        with self.assertRaisesRegex(ValueError, "revision conflict"):
            self.manager.unregister_application("test-agent-cluster", expected_revision=1)
        self.assertEqual(self.manager.unregister_application("test-agent-cluster", expected_revision=2)["removed_revisions"], 2)
        with self.assertRaisesRegex(ValueError, "Unknown registration"):
            self.manager.registered_application("test-agent-cluster")

    def test_registration_refuses_deployed_ownership_templates_and_mixed_applications(self):
        deployed = self.residents()
        deployed["placements"][0].update(ownership="deployed", ownership_id="claimed-by-hand")
        with self.assertRaisesRegex(ValueError, "only adopted placements"):
            self.manager.register_application(deployed, expected_revision=0)
        templates_only = json.loads((ROOT / "docs/spec/examples/02-static-web.json").read_text())
        templates_only.update(applications=templates_only["applications"][:1], placements=[])
        with self.assertRaisesRegex(ValueError, "templates with `template save`"):
            self.manager.register_application(templates_only, expected_revision=0)
        mixed = self.residents()
        mixed["applications"].append(self.renamed_residents("other")["applications"][0])
        with self.assertRaisesRegex(ValueError, "one application"):
            self.manager.register_application(mixed, expected_revision=0)
        with self.assertRaisesRegex(ValueError, "takes a Bundle"):
            self.manager.register_application(TEMPLATE, expected_revision=0)
        self.assertEqual(self.manager.registered_applications(), [])

    def test_registration_warns_on_port_and_identity_collisions(self):
        self.save_template()
        self.deploy(ports={"http": 18100})
        box = json.loads((ROOT / "docs/spec/examples/04-learning-box.json").read_text())
        box["placements"][0].update(host_id="alpha")
        box["placements"][0]["endpoints"] = [{"endpoint": "https", "address": "0.0.0.0", "host_port": 18100}]
        warned = self.manager.register_application(box, expected_revision=0, host_ids=["alpha"])
        self.assertEqual(warned["warnings"], ["Port tcp/0.0.0.0:18100 on alpha collides with deploy registry claim of garden"])
        self.manager.register_application(self.residents(), expected_revision=0, host_ids=["host-c", "host-a"])
        warnings = self.manager.register_application(self.renamed_residents("residents-rehearsal"), expected_revision=0,
                                                     host_ids=["host-c", "host-a"])["warnings"]
        self.assertEqual(warnings, ["Identity minecraft-user/" + name + " is also held by registered application test-agent-cluster"
                                    for name in ("TEST_ALICE", "TEST_BOB", "TEST_CAROL", "TEST_CLIENT", "TEST_DAVE")])  # placeholders never collide

    def test_registration_grants_no_deploy_authority(self):
        self.manager.register_application(self.residents(), expected_revision=0)
        self.save_template()
        with self.assertRaisesRegex(ValueError, "registered adopted application"):
            self.plan("test-agent-cluster")
        with self.assertRaisesRegex(ValueError, "no current deployed placement"):
            self.manager.act("test-agent-cluster", "fence", approved=True, request_id="fence-adopted")
        with self.assertRaisesRegex(ValueError, "no placement to undeploy"):
            self.manager.undeploy_plan("test-agent-cluster")
        self.deploy()
        with self.assertRaisesRegex(ValueError, "Switchyard-deployed instance"):
            self.manager.register_application(self.renamed_residents("garden"), expected_revision=0)

    def test_cli_registration_commands(self):
        parser = argparse.ArgumentParser()
        commands = parser.add_subparsers(dest="command", required=True)
        deploy.register_cli(commands)
        service = SimpleNamespace(deployments=lambda: self.manager,
                                  hosts=lambda: {"revision": "r", "hosts": [{"id": "host-c"}, {"id": "host-a"}]})
        path = str(ROOT / "tests/fixtures/residents.json")
        registered = deploy.handle_cli(parser.parse_args(["spec", "register", path, "--expected-revision", "0",
                                                          "--submitted-by", "operator"]), service)
        self.assertEqual((registered["revision"], registered["warnings"], registered["source"]), (1, [], path))
        self.assertEqual(deploy.handle_cli(parser.parse_args(["spec", "registered"]), service)[0]["id"], "test-agent-cluster")
        self.assertEqual(deploy.handle_cli(parser.parse_args(["spec", "show", "test-agent-cluster@1"]), service)["revision"], 1)
        removed = deploy.handle_cli(parser.parse_args(["spec", "unregister", "test-agent-cluster", "--expected-revision", "1"]), service)
        self.assertEqual(removed["removed_revisions"], 1)

    # ---------------------------------------------------------------- verify (detection on contact) and re-fence
    def host_snapshot(self):
        files = {}
        for path in sorted(self.host.home.rglob("*")):
            if path.is_file():
                files[str(path)] = (path.read_bytes(), oct(path.stat().st_mode))
        return files, copy.deepcopy(self.host.units), copy.deepcopy(self.host.pods), copy.deepcopy(self.host.listeners)

    def placement_snapshot(self, instance="garden"):
        state = self.state(instance)
        return state["state"], state["revision"], state["meta"], state["placement"]

    def verify(self, instance="garden", **kwargs):
        result = self.manager.verify(instance, **kwargs)
        self.assertEqual(len(result["verifications"]), 1)
        return result, result["verifications"][0]

    @staticmethod
    def codes(verification):
        return sorted(f["code"] for f in verification["findings"])

    def test_verify_consistent_active_placement_and_never_mutates(self):
        self.save_template()
        self.deploy()
        host_before, placement_before = self.host_snapshot(), self.placement_snapshot()
        calls = len(self.host.calls)
        result, verification = self.verify()
        self.assertEqual((result["receipt"]["status"], result["receipt"]["action"], result["receipt"]["kind"]),
                         ("succeeded", "verify", "deploy"))
        self.assertEqual((verification["consistent"], verification["findings"]), (True, []))
        self.assertEqual(self.host_snapshot(), host_before)
        self.assertEqual(self.placement_snapshot(), placement_before)  # state and revision untouched
        for argv in self.host.calls[calls:]:
            if argv[0] == deploy_remote.SYSTEMCTL:
                self.assertFalse({"start", "stop", "daemon-reload", "restart", "kill", "reset-failed"} & set(argv), argv)
            if argv[0] == deploy_remote.PODMAN:
                self.assertIn(argv[1], {"pod", "ps"}, argv)
                self.assertIn(argv[2], {"exists", "inspect", "--all"}, argv)
        self.assertEqual(self.remote_actions[-1], "verify")
        shown = self.manager.show("garden")["last_verification"]
        self.assertEqual((shown["consistent"], shown["operation_id"]), (True, result["receipt"]["id"]))
        listed = self.manager.list()[0]["last_verified"]
        self.assertEqual((listed["consistent"], listed["drift"]), (True, []))

    def test_rollback_scenario_verify_refence_verify(self):
        self.save_template()
        plan, _ = self.deploy()
        service = plan["native"]["names"]["service"]
        saved_token = Path(self.paths()["token"]).read_bytes()
        self.assertEqual(self.act("garden", "fence", "fence-1")["receipt"]["status"], "succeeded")
        self.assertEqual(self.host.start(service)[0], 1)  # gate refuses while revoked
        Path(self.paths()["token"]).write_bytes(saved_token)  # filesystem rollback restores the old valid token
        self.assertEqual(self.host.start(service)[0], 0)  # residual risk: the unit starts
        self.assertEqual(self.state()["state"], "fenced")  # the journal cannot know yet
        placement_before, host_before = self.placement_snapshot(), self.host_snapshot()
        result, verification = self.verify()
        self.assertEqual((result["receipt"]["status"], verification["consistent"]), ("succeeded", False))
        self.assertEqual(self.codes(verification), ["running-while-fenced", "valid-token-while-fenced"])
        self.assertEqual(self.placement_snapshot(), placement_before)
        self.assertEqual(self.host_snapshot(), host_before)  # detects; stops nothing
        self.assertEqual(self.manager.list()[0]["last_verified"]["drift"], ["running-while-fenced", "valid-token-while-fenced"])
        self.assertEqual(self.manager.act("garden", "fence")["preview"]["from"]["state"], "fenced")
        refenced = self.act("garden", "fence", "refence-1")
        self.assertEqual(refenced["receipt"]["status"], "succeeded", refenced)
        self.assertFalse(self.host.started(service))
        self.assertEqual(self.host.pods, {})
        self.assertTrue(Path(self.paths()["token"]).read_text().startswith("switchyard-generation-token/v1 revoked "))
        state = self.state()
        self.assertIn("re-enforced fence on an already fenced placement (host had drifted)", state["placement"]["fence"]["evidence"][0])
        self.assertIn("token valid", state["placement"]["fence"]["evidence"][3])
        self.assertEqual(len(state["meta"]["fence_history"]), 2)
        self.assertEqual(self.act("garden", "fence", "refence-1")["receipt"]["id"], refenced["receipt"]["id"])  # idempotent
        _, verification = self.verify()
        self.assertEqual((verification["consistent"], verification["findings"]), (True, []))
        self.assertEqual(self.host.start(service)[0], 1)

    def test_refence_of_a_clean_host_is_a_no_op_with_fresh_evidence(self):
        self.save_template()
        self.deploy()
        self.act("garden", "fence", "fence-1")
        first = self.state()["placement"]["fence"]
        identity = Path(self.paths()["token"]).read_text().splitlines()[0]
        self.assertEqual(self.act("garden", "fence", "fence-2")["receipt"]["status"], "succeeded")
        state = self.state()
        self.assertEqual(state["state"], "fenced")
        self.assertIn("host was already clean; no-op with fresh evidence", state["placement"]["fence"]["evidence"][0])
        self.assertNotEqual(state["placement"]["fence"]["verified_at"], first["verified_at"])
        self.assertEqual(Path(self.paths()["token"]).read_text().splitlines()[0], identity)

    def test_verify_running_while_staged_is_informational(self):
        self.save_template()
        plan, _ = self.deploy()
        self.act("garden", "stop", "stop-1")
        self.host.start(plan["native"]["names"]["service"])  # boot or manual start: allowed by the valid token
        _, verification = self.verify()
        self.assertEqual(self.codes(verification), ["running-while-staged"])
        self.assertEqual((verification["consistent"], verification["findings"][0]["severity"]), (True, "info"))

    def test_verify_token_mismatch_while_staged(self):
        self.save_template()
        self.deploy()
        self.act("garden", "stop", "stop-1")
        Path(self.paths()["token"]).unlink()
        _, verification = self.verify()
        self.assertEqual((verification["consistent"], self.codes(verification)), (False, ["token-mismatch-while-staged"]))

    def test_verify_active_placement_findings(self):
        self.save_template()
        plan, _ = self.deploy()
        service = plan["native"]["names"]["service"]
        self.host.stop(service)
        _, verification = self.verify()
        self.assertEqual(self.codes(verification), ["stopped-while-active"])
        self.host.start(service)
        Path(self.paths()["token"]).unlink()
        _, verification = self.verify()
        self.assertEqual(self.codes(verification), ["token-missing-or-revoked-while-active"])

    def test_verify_ownership_native_files_and_generation_findings(self):
        self.save_template()
        self.deploy()
        paths = self.paths()
        self.host.pods["switchyard-garden-web"]["Labels"]["io.switchyard/ownership-id"] = "someone-else"
        Path(paths["unit"]).write_text(Path(paths["unit"]).read_text() + "# edited\n")
        generation = Path(paths["app_dir"]) / "generation"
        generation.write_text("2\n")
        _, verification = self.verify()
        self.assertEqual(self.codes(verification), ["host-generation-ahead", "native-files-changed", "ownership-mismatch"])
        self.assertIn("unit sha256", next(f for f in verification["findings"] if f["code"] == "native-files-changed")["detail"])
        generation.unlink()
        Path(paths["owner"]).write_text(json.dumps({"ownership_id": "other"}))
        _, verification = self.verify()
        self.assertIn("host-generation-behind", self.codes(verification))
        self.assertIn("owner.json mismatch", next(f for f in verification["findings"] if f["code"] == "ownership-mismatch")["detail"])

    def test_verify_unreachable_is_needs_inspection_never_consistent(self):
        self.save_template()
        self.deploy()
        placement_before = self.placement_snapshot()

        def lost(host, source, payload, *, timeout, local=False):
            if payload["action"] == "verify":
                mark_uncertain("fixture verification transport lost", resource=host["host_id"])
                raise RemoteError("transport lost")
            return self.fake_remote(host, source, payload, timeout=timeout, local=local)

        with patch.object(deploy, "run_remote", side_effect=lost):
            result, verification = self.verify()
        self.assertEqual(result["receipt"]["status"], "needs-inspection")
        self.assertEqual((verification["consistent"], self.codes(verification)), (False, ["unreachable"]))
        self.assertEqual(self.placement_snapshot(), placement_before)
        self.assertEqual(self.manager.list()[0]["last_verified"]["consistent"], False)

    def test_verify_busy_lease_is_unreachable_and_not_recorded(self):
        self.save_template()
        self.deploy()
        with patch.dict(os.environ, {"SWITCHYARD_OPERATION_LEASE_WAIT": "0"}), \
                self.leases.hold("alpha", owner="fixture", scope="busy verification", worktree=str(self.root)):
            result, verification = self.verify()
        self.assertEqual(result["receipt"]["status"], "busy")
        self.assertEqual((verification["consistent"], self.codes(verification)), (False, ["unreachable"]))
        self.assertIsNone(self.manager.show("garden")["last_verification"])

    def test_verify_request_id_replay_and_retired_refusal(self):
        self.save_template()
        self.deploy()
        first, _ = self.verify(request_id="verify-1")
        actions = list(self.remote_actions)
        again, verification = self.verify(request_id="verify-1")
        self.assertEqual((again["receipt"]["id"], verification["consistent"]), (first["receipt"]["id"], True))
        self.assertEqual(self.remote_actions, actions)
        undeploy = self.manager.undeploy_plan("garden")
        self.manager.undeploy_apply(undeploy["id"], approved=True, request_id="undeploy")
        with self.assertRaisesRegex(ValueError, "no current deployed placement to verify"):
            self.manager.verify("garden")

    def test_verify_all_one_lease_per_host(self):
        self.save_template()
        plan, _ = self.deploy("garden")
        self.deploy("orchard")
        self.act("orchard", "fence", "fence-orchard")
        self.deploy("meadow")
        undeploy = self.manager.undeploy_plan("meadow")
        self.manager.undeploy_apply(undeploy["id"], approved=True, request_id="undeploy-meadow")
        self.host.stop(plan["native"]["names"]["service"])
        before = self.remote_actions.count("verify")
        result = self.manager.verify_all()
        self.assertFalse(result["consistent"])
        self.assertEqual(len(result["hosts"]), 1)
        host = result["hosts"][0]
        self.assertEqual((host["host_id"], host["instance_ids"], host["receipt"]["host_ids"]),
                         ("alpha", ["garden", "orchard"], ["alpha"]))
        self.assertEqual({v["instance_id"]: self.codes(v) for v in host["verifications"]},
                         {"garden": ["stopped-while-active"], "orchard": []})
        self.assertEqual(self.remote_actions.count("verify") - before, 1)

    def test_verify_all_batches_more_than_sixteen_placements_inside_one_lease(self):
        self.save_template()
        names = ["site-%02d" % index for index in range(deploy.VERIFY_BATCH + 1)]
        for name in names:
            self.deploy(name)
        leases_before = {lease["lease_id"] for lease in self.leases.store.records()}
        calls = []

        def second_batch_lost(host, source, payload, *, timeout, local=False):
            if payload["action"] == "verify":
                calls.append([item["instance_id"] for item in payload["items"]])
                if len(calls) == 2:
                    mark_uncertain("fixture verification transport lost", resource=host["host_id"])
                    raise RemoteError("transport lost")
            return self.fake_remote(host, source, payload, timeout=timeout, local=local)

        with patch.object(deploy, "run_remote", side_effect=second_batch_lost):
            result = self.manager.verify_all()
        acquired = [lease for lease in self.leases.store.records() if lease["lease_id"] not in leases_before]
        self.assertEqual(len(acquired), 1)  # one durable lease for both batches on the host
        self.assertEqual((acquired[0]["device"], acquired[0]["status"]), ("ALPHA", "suspect"))
        self.assertEqual(len(result["hosts"]), 1)
        host = result["hosts"][0]
        self.assertEqual((host["instance_ids"], host["receipt"]["status"]), (names, "needs-inspection"))
        self.assertEqual([len(batch) for batch in calls], [deploy.VERIFY_BATCH, 1])  # batched inside the one lease
        outcome = {v["instance_id"]: (v["consistent"], self.codes(v)) for v in host["verifications"]}
        self.assertEqual(outcome[names[-1]], (False, ["unreachable"]))
        self.assertTrue(all(outcome[name] == (True, []) for name in names[:-1]))
        self.assertFalse(result["consistent"])
        self.assertEqual(len([e for e in host["receipt"]["events"] if e["event"] == "verified"]), 2)

    def test_deployed_gate_compares_line_one_only(self):
        self.save_template()
        plan, _ = self.deploy()
        service = plan["native"]["names"]["service"]
        gate = next(l for l in plan["native"]["files"]["unit"]["text"].splitlines() if l.startswith("ExecStartPre="))
        self.assertIn("$$(head -n 1 -- ", gate)
        self.assertTrue(gate.startswith("ExecStartPre=/bin/sh -c '"))
        valid = Path(self.paths()["token"]).read_text().splitlines()[0]
        self.act("garden", "fence", "fence-1")
        with Path(self.paths()["token"]).open("a") as stream:  # revoked line 1 + an appended valid line
            stream.write(valid + "\n")
        self.assertEqual(self.host.start(service)[0], 1)  # the real shell gate refuses
        legacy = '/usr/bin/grep -qxF -- "' + valid + '" ' + self.paths()["token"]
        self.assertTrue(run_gate(legacy))  # the old whole-file grep gate would have started it
        self.assertEqual(self.host.pods, {})

    def test_units_journaled_with_the_legacy_gate_still_verify_consistent(self):
        self.save_template()
        legacy = lambda identity, path: '/usr/bin/grep -qxF -- "' + identity + '" ' + path
        with patch.object(deploy, "gate_command", legacy):
            plan, result = self.deploy()
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        self.assertIn("grep -qxF", plan["native"]["files"]["unit"]["text"])
        _, verification = self.verify()
        self.assertEqual((verification["consistent"], verification["findings"]), (True, []))  # journaled hash, not the generator
        self.assertEqual(self.act("garden", "fence", "fence-legacy")["receipt"]["status"], "succeeded")
        _, verification = self.verify()
        self.assertTrue(verification["consistent"])

    def test_cli_verify(self):
        parser = argparse.ArgumentParser()
        commands = parser.add_subparsers(dest="command", required=True)
        deploy.register_cli(commands)
        service = SimpleNamespace(deployments=lambda: self.manager)
        self.save_template()
        self.deploy()
        self.assertTrue(deploy.handle_cli(parser.parse_args(["deploy", "verify", "garden"]), service)["consistent"])
        self.assertTrue(deploy.handle_cli(parser.parse_args(["deploy", "verify", "--all"]), service)["consistent"])
        with self.assertRaisesRegex(ValueError, "exactly one of INSTANCE or --all"):
            deploy.handle_cli(parser.parse_args(["deploy", "verify"]), service)

    # ---------------------------------------------------------------- configuration files, parameters, refresh (lan-dns)
    def save_dns(self):
        self.manager.registry_hosts = lambda: copy.deepcopy(REGISTRY)
        return self.manager.save_template(copy.deepcopy(DNS_TEMPLATE), expected_revision=0)

    def dns_plan(self, instance="lan-dns", port=1053, addresses=LAN, params=None, **kwargs):
        return self.plan(instance, template="coredns-lan", params={"zone": "example.test", "upstreams": "192.168.50.1 192.168.50.2", **(params or {})},
                         ports={"dns-udp": port, "dns-tcp": port}, addresses=dict(addresses), **kwargs)

    def dns_deploy(self, **kwargs):
        plan = self.dns_plan(**kwargs)
        self.assertTrue(plan["executable"], [p for p in plan["preconditions"] if not p["ok"]])
        result = self.manager.apply(plan["id"], approved=True, request_id="apply-dns")
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        return plan, result

    def host_config(self, name, instance="lan-dns"):
        return Path(self.paths(instance)["config_dir"]) / name

    def test_dns_deploy_writes_read_only_config_and_claims_udp_and_tcp_on_one_port(self):
        self.assertTrue(self.save_dns()["deployable"])
        plan, _ = self.dns_deploy()
        self.assertEqual(sorted((c["protocol"], c["address"], c["port"]) for c in plan["native"]["claims"]),
                         [("tcp", "192.168.50.120", 1053), ("udp", "192.168.50.120", 1053)])
        self.assertEqual(sorted((c["protocol"], c["port"]) for c in self.manager.store.all_claims()), [("tcp", 1053), ("udp", 1053)])
        self.assertEqual(sorted(self.manager.list()[0]["claims"]), ["tcp/192.168.50.120:1053", "udp/192.168.50.120:1053"])
        exposure = {item["endpoint"]: item for item in plan["lan_exposure"]}
        self.assertEqual((exposure["dns-udp"]["scope"], exposure["dns-udp"]["network"], exposure["dns-udp"]["interface"]),
                         ("lan", "192.168.50.0/24", "wlan0"))
        self.assertIn("LAN exposure: udp/192.168.50.120:1053 (lan)", plan["approvals"][1]["includes"])
        files = {f["id"]: f for f in plan["config_files"]}
        self.assertEqual(sorted(files), ["corefile", "hosts", "zone-file"])
        generated = files["hosts"]["generated"]
        self.assertEqual([r["name"] for r in generated["records"]], ["host-a.example.test", "host-b.example.test"])
        self.assertEqual({s["host_id"] for s in generated["skipped"]}, {"controller", "test-portable", "test-handheld", "test-unix"})
        directory = Path(self.paths("lan-dns")["config_dir"])
        self.assertEqual(oct(directory.stat().st_mode & 0o777), "0o755")
        hosts = self.host_config("hosts").read_text()
        self.assertIn("192.168.50.233 host-b.example.test\n", hosts)
        self.assertEqual(oct(self.host_config("hosts").stat().st_mode & 0o777), "0o644")
        corefile = self.host_config("Corefile").read_text()
        self.assertIn("forward . 192.168.50.1 192.168.50.2", corefile)
        self.assertIn("example.test:5353 {", corefile)
        self.assertNotIn("{{", corefile + self.host_config("zone.db").read_text())
        self.assertNotIn("text", self.state("lan-dns")["meta"]["native"]["config"][0])  # the journal keeps hashes, the plan the text
        manifest = deploy.parse_pod(Path(self.paths("lan-dns")["yaml"]).read_text())
        volume = manifest["spec"]["volumes"][0]["hostPath"]
        self.assertEqual((volume["path"], volume["type"]), (str(directory), "Directory"))
        self.assertTrue(manifest["spec"]["containers"][0]["volumeMounts"][0]["readOnly"])
        ports = manifest["spec"]["containers"][0]["ports"]
        self.assertEqual(sorted((p["protocol"], p["hostIP"], p["hostPort"]) for p in ports),
                         [("TCP", "192.168.50.120", 1053), ("UDP", "192.168.50.120", 1053)])
        self.assertNotIn("NET_BIND_SERVICE", manifest["spec"]["containers"][0]["securityContext"]["capabilities"]["drop"])
        app = self.manager.show("lan-dns")["application"]
        self.assertEqual({p["id"]: p.get("value") for p in app["parameters"]}, {"zone": "example.test", "upstreams": "192.168.50.1 192.168.50.2"})
        health = next(e["data"] for e in self.manager.show("lan-dns")["last_receipt"]["events"] if e["event"] == "deploy-verified")["health"]
        self.assertEqual([h["id"] for h in health], ["zone-soa-udp", "zone-soa-tcp"])
        # Undeploy removes the configuration files and their directory.
        undeploy = self.manager.undeploy_plan("lan-dns")
        self.assertEqual(len(undeploy["remove"]["config_files"]), 3)
        self.assertEqual(self.manager.undeploy_apply(undeploy["id"], approved=True, request_id="undeploy-dns")["receipt"]["status"],
                         "succeeded")
        self.assertFalse(directory.parent.exists())
        self.assertEqual(sorted(os.listdir(self.paths("lan-dns")["app_dir"])), ["generation"])

    def test_dns_parameters_are_declared_validated_and_required(self):
        self.save_dns()
        with self.assertRaisesRegex(ValueError, "without a value: upstreams, zone"):
            self.plan("lan-dns", template="coredns-lan", ports={"dns-udp": 1053, "dns-tcp": 1053})
        with self.assertRaisesRegex(ValueError, "parameter zone: expected a lowercase DNS name"):
            self.dns_plan(params={"zone": "Example.TEST"})
        with self.assertRaisesRegex(ValueError, "parameter upstreams: expected 1-8 distinct"):
            self.dns_plan(params={"upstreams": "192.168.50.1 192.168.50.1"})
        with self.assertRaisesRegex(ValueError, "Unknown parameter"):
            self.dns_plan(params={"colour": "blue"})
        plan = self.dns_plan(params={"upstreams": "9.9.9.9"})
        corefile = next(f for f in plan["native"]["config"] if f["name"] == "Corefile")["text"]
        self.assertIn("forward . 9.9.9.9\n", corefile)
        self.assertEqual(plan["native"]["health_checks"][0]["name"], "example.test")
        template = copy.deepcopy(DNS_TEMPLATE)
        template["parameters"][0]["value"] = "example.test"
        with self.assertRaisesRegex(ValueError, "values belong to instances"):
            self.manager.save_template({**template, "id": "other-dns"}, expected_revision=0)

    def test_dns_records_skipped_hosts_and_duplicates(self):
        self.save_dns()
        plan = self.dns_plan(records={"romm.example.test": "192.168.50.233", "nas": "192.168.50.40"})
        hosts = next(f for f in plan["native"]["config"] if f["name"] == "hosts")["text"]
        self.assertTrue(hosts.endswith("192.168.50.40 nas.example.test\n192.168.50.233 romm.example.test\n"), hosts)
        self.assertEqual({r["name"] for r in plan["application"]["config_files"][2]["generator"]["records"]}, {"romm", "nas"})
        with self.assertRaisesRegex(ValueError, "Duplicate name host-b.example.test: operator record collides with registry host host-b"):
            self.dns_plan(instance="dup", records={"host-b": "192.168.50.9"})
        with self.assertRaisesRegex(ValueError, "outside zone example.test"):
            self.dns_plan(instance="out", records={"romm.example.com": "192.168.50.9"})
        with self.assertRaisesRegex(ValueError, "LDH labels"):
            self.dns_plan(instance="bad", records={"bad_name": "192.168.50.9"})
        with self.assertRaisesRegex(ValueError, "canonical IPv4/IPv6"):
            self.dns_plan(instance="bad", records={"ok": "192.168.050.9"})
        self.manager.registry_hosts = None  # a manager built without the registry never renders an empty host list
        with self.assertRaisesRegex(ValueError, "needs the host registry"):
            self.dns_plan(instance="unwired")

    def test_config_rendering_bounds_and_placeholder_syntax(self):
        app = spec.Application.model_validate(DNS_TEMPLATE).model_dump(mode="json")
        app["parameters"][0]["default"] = "example.test"
        app["parameters"][1]["default"] = "192.168.50.1 192.168.50.2"
        big = copy.deepcopy(app)
        big["config_files"][0]["content"] = "{{upstreams}}" * 6000  # 13 characters each, 25 bytes rendered
        with self.assertRaisesRegex(ValueError, "renders to 150000 bytes"):
            deploy_config.render_files(big, [])
        for text, message in (("{{ zone }}", "malformed placeholder"), ("{{nope}}", "unknown parameter"),
                              ("{{secret:token}}", "secret references"), ("a }} b", "malformed placeholder")):
            broken = copy.deepcopy(DNS_TEMPLATE)
            broken["config_files"][0]["content"] = text
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, message):
                spec.Application.model_validate(broken)
        many = copy.deepcopy(DNS_TEMPLATE)
        many["config_files"] += [{"id": "extra-" + str(i), "component": "dns", "path": "x" + str(i), "content": "x"} for i in range(14)]
        with self.assertRaisesRegex(ValueError, "at most 16"):
            spec.Application.model_validate(many)
        writable = copy.deepcopy(DNS_TEMPLATE)
        writable["components"][0]["native"]["manifest"]["spec"]["containers"][0]["volumeMounts"][0]["readOnly"] = False
        with self.assertRaisesRegex(ValueError, "mounted read-only"):
            spec.Application.model_validate(writable)
        unchanged = spec.Application.model_validate(spec.upgrade(TEMPLATE)[0])
        dump = unchanged.model_dump(mode="json")
        del dump["parameters"], dump["config_files"], dump["notes"]
        self.assertEqual(unchanged.content_sha256(), hashlib.sha256(json.dumps(
            dump, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest())  # hash-neutral addition

    def test_privileged_port_is_a_blocking_precondition_with_operator_command(self):
        self.save_dns()
        plan = self.dns_plan(port=53)
        self.assertFalse(plan["executable"])
        self.assertIn("unprivileged-port-dns-udp", plan["blockers"])
        evidence = next(p for p in plan["preconditions"] if p["id"] == "unprivileged-port-dns-tcp")["evidence"]
        self.assertEqual(evidence["operator_command_persistent"], "printf 'net.ipv4.ip_unprivileged_port_start=53\\n' | sudo tee "
                         "/etc/sysctl.d/60-unprivileged-ports.conf && sudo sysctl --system")
        self.assertEqual(evidence["operator_command_until_reboot"], "sudo sysctl -w net.ipv4.ip_unprivileged_port_start=53")
        self.assertIn("every unprivileged process", evidence["meaning"])
        self.assertEqual(self.manager.store.all_claims(), [])  # not stored, nothing reserved
        self.host.port_start = 53
        self.assertTrue(self.dns_plan(port=53)["executable"])

    def test_lan_address_must_belong_to_the_host_and_be_free_for_each_protocol(self):
        self.save_dns()
        foreign = self.dns_plan(addresses={"dns-udp": "192.168.50.77", "dns-tcp": "192.168.50.77"})
        self.assertEqual(sorted(b for b in foreign["blockers"] if b.startswith("address-")), ["address-dns-tcp", "address-dns-udp"])
        self.host.listeners.append({"protocol": "udp", "address": "0.0.0.0", "port": 1053})  # a wildcard UDP listener
        busy = self.dns_plan()
        self.assertEqual([b for b in busy["blockers"] if b.startswith("port-")], ["port-dns-udp"])
        self.host.listeners.clear()
        self.host.listeners.append({"protocol": "tcp", "address": "192.168.50.120", "port": 18100})
        auto = self.plan("lan-dns", template="coredns-lan", params={"zone": "example.test", "upstreams": "192.168.50.1 192.168.50.2"}, addresses=dict(LAN))
        self.assertEqual(sorted((c["protocol"], c["port"]) for c in auto["native"]["claims"]), [("tcp", 18101), ("udp", 18101)])
        self.assertEqual(auto["lan_exposure"][0]["network"], "192.168.50.0/24")
        loopback = self.plan("lan-dns-lo", template="coredns-lan", params={"zone": "example.test", "upstreams": "192.168.50.1 192.168.50.2"})
        self.assertEqual(loopback["lan_exposure"], [])

    def refresh(self, request_id="refresh-1", **kwargs):
        plan = self.manager.refresh_plan("lan-dns", **kwargs)
        self.assertTrue(plan["executable"], [p for p in plan["preconditions"] if not p["ok"]])
        return plan, self.manager.refresh_apply(plan["id"], approved=True, request_id=request_id)

    def test_lan_host_sync_preserves_manual_records_and_runtime_and_follows_registry(self):
        self.save_dns()
        self.dns_deploy(records={"manual": "192.168.50.70", "conflict": "192.168.50.71"})
        hosts = copy.deepcopy(REGISTRY)
        self.manager.registry_hosts = lambda: hosts
        service = SimpleNamespace(deployments=lambda: self.manager)
        routes = LanRoutes(service, {"dns_id": "lan-dns", "zone": "example.test"})
        service.lan_routes = lambda: routes
        before = self.manager.show("lan-dns")
        native = self.state("lan-dns")["meta"]["native"]
        unit = self.host.units[native["names"]["service"]]
        invocation = unit["invocation"]
        path = self.host_config("hosts")
        workstation = {"id": "workstation", "name": "Friendly desktop", "verification": {"state": "verified"},
                       "collector": {"transport": "ssh", "target": "operator@192.168.50.128",
                                     "expected_hostname": "workstation-01"}}
        hosts.append(workstation)
        hosts.append({"id": "other", "verification": {"state": "verified"},
                      "collector": {"transport": "ssh", "target": "operator@192.168.50.129",
                                    "expected_hostname": "conflict"}})
        preview = lan_dns_sync.reconcile(service, dry_run=True)
        self.assertTrue(preview["changed"])
        self.assertNotIn("workstation-01.example.test", path.read_text())
        self.assertEqual([item["reason"] for item in preview["skipped"] if item["host_id"] == "other"],
                         ["conflict.example.test is already an explicit DNS record"])
        result = lan_dns_sync.reconcile(service)
        self.assertEqual(result["status"], "refreshed", result)
        text = path.read_text()
        self.assertIn("192.168.50.128 workstation-01.example.test\n", text)
        self.assertIn("192.168.50.128 workstation.example.test\n", text)
        self.assertIn("192.168.50.70 manual.example.test\n", text)
        self.assertIn("192.168.50.71 conflict.example.test\n", text)
        self.assertNotIn("192.168.50.129 conflict.example.test", text)
        self.assertEqual(self.manager.show("lan-dns")["application"], before["application"])
        self.assertEqual(self.host.units[native["names"]["service"]]["invocation"], invocation)
        actions = list(self.remote_actions)
        self.assertEqual(lan_dns_sync.reconcile(service)["status"], "unchanged")
        self.assertEqual(self.remote_actions, actions)
        hosts.remove(workstation)
        self.assertEqual(lan_dns_sync.reconcile(service)["status"], "refreshed")
        self.assertNotIn("workstation", path.read_text())

    def test_refresh_adds_a_record_without_restart_and_keeps_generation_and_token(self):
        self.save_dns()
        self.dns_deploy()
        before = self.state("lan-dns")
        token = Path(self.paths("lan-dns")["token"]).read_text()
        service = before["meta"]["native"]["names"]["service"]
        invocation = self.host.units[service]["invocation"]
        plan = self.manager.refresh_plan("lan-dns", add_records={"test-record.example.test": "192.168.50.250"})
        self.assertTrue(plan["executable"], plan["blockers"])
        changes = {c["id"]: c for c in plan["changes"]}
        self.assertEqual({k: c["change"] for k, c in changes.items()}, {"corefile": "unchanged", "zone-file": "unchanged", "hosts": "update"})
        self.assertIn("+192.168.50.250 test-record.example.test\n", changes["hosts"]["diff"])
        self.assertIn("--- host/hosts", changes["hosts"]["diff"])
        self.assertEqual((plan["restart"], plan["application_revision"]), (False, 2))
        self.assertTrue(plan["effect"].startswith("none: the running service reloads"))
        actions = list(self.remote_actions)
        result = self.manager.refresh_apply(plan["id"], approved=True, request_id="refresh-1")
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        self.assertEqual(self.remote_actions[len(actions):], ["refresh"])
        self.assertIn("192.168.50.250 test-record.example.test\n", self.host_config("hosts").read_text())
        after = self.state("lan-dns")
        self.assertEqual((after["generation"], after["state"], after["revision"]), (before["generation"], "active", before["revision"] + 2))
        self.assertEqual(after["placement"]["revision"], 2)  # the placement references instance revision 2
        self.assertEqual(Path(self.paths("lan-dns")["token"]).read_text(), token)
        self.assertEqual((self.host.restarts, self.host.units[service]["invocation"]), ([], invocation))
        shown = self.manager.show("lan-dns")
        self.assertEqual([r["revision"] for r in shown["revisions"]], [1, 2])
        self.assertEqual(shown["application"]["config_files"][2]["generator"]["records"],
                         [{"name": "test-record", "address": "192.168.50.250"}])
        replay = self.manager.refresh_apply(plan["id"], approved=True, request_id="refresh-1")
        self.assertEqual((replay["receipt"]["id"], self.remote_actions.count("refresh")), (result["receipt"]["id"], 1))
        with self.assertRaisesRegex(ValueError, "Placement changed since planning"):  # a plan executes once
            self.manager.refresh_apply(plan["id"], approved=True, request_id="refresh-again")
        _, verification = self.verify("lan-dns")
        self.assertEqual((verification["consistent"], verification["findings"]), (True, []))
        nothing = self.manager.refresh_plan("lan-dns")
        self.assertEqual((nothing["executable"], nothing["blockers"]), (False, ["changes"]))
        with self.assertRaisesRegex(ValueError, "Duplicate name test-record.example.test"):
            self.manager.refresh_plan("lan-dns", add_records={"test-record": "192.168.50.251"})
        _, done = self.refresh("refresh-2", remove_records=["test-record"])
        self.assertEqual(done["receipt"]["status"], "succeeded", done)
        self.assertNotIn("test-record", self.host_config("hosts").read_text())

    def test_refresh_of_corefile_restarts_and_registry_changes_regenerate(self):
        self.save_dns()
        self.dns_deploy(records={"romm": "192.168.50.233"})
        service = self.state("lan-dns")["meta"]["native"]["names"]["service"]
        REGISTRY.append({"id": "host-d", "collector": {"transport": "ssh", "target": "operator@192.168.50.143"}})
        self.addCleanup(REGISTRY.pop)
        plan, result = self.refresh(params={"upstreams": "9.9.9.9 149.112.112.112"})
        self.assertEqual({c["id"] for c in plan["changes"] if c["change"] == "update"}, {"corefile", "hosts"})
        self.assertIn("+192.168.50.143 host-d.example.test\n", next(c for c in plan["changes"] if c["id"] == "hosts")["diff"])
        self.assertTrue(plan["restart"])
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        self.assertEqual(self.host.restarts, [service])
        self.assertIn("romm.example.test", self.host_config("hosts").read_text())  # operator records survive regeneration
        state = self.state("lan-dns")
        self.assertEqual((state["state"], state["meta"]["native_identities"]["invocation_id"]),
                         ("active", self.host.units[service]["invocation"]))
        self.assertEqual(self.manager.show("lan-dns")["application"]["parameters"][1]["value"], "9.9.9.9 149.112.112.112")

    def test_refresh_refusals_host_drift_failed_restart_and_unknown_outcome(self):
        self.save_dns()
        self.dns_deploy()
        with self.assertRaisesRegex(ValueError, "Unknown parameter"):
            self.manager.refresh_plan("lan-dns", params={"image": "x"})
        hosts = self.host_config("hosts")
        original = hosts.read_text()
        hosts.write_text(original + "192.168.50.1 hand-edit.example.test\n")
        drift = self.manager.refresh_plan("lan-dns", add_records={"a": "192.168.50.2"})
        self.assertEqual(drift["blockers"], ["config-files-match-journal"])
        hosts.write_text(original)
        # Restart failure: files are written, the unit is stopped and the placement staged (token stays valid).
        self.host.fail_restart = True
        _, result = self.refresh("refresh-restart", params={"upstreams": "9.9.9.9"})
        self.assertEqual(result["receipt"]["status"], "failed", result)
        state = self.state("lan-dns")
        self.assertEqual((state["state"], state["meta"]["token"]["state"], state["meta"]["runtime"], state["meta"]["uncertain"]),
                         ("staged", "valid", "stopped", False))
        self.assertIn("forward . 9.9.9.9", self.host_config("Corefile").read_text())
        self.host.fail_restart = False
        self.assertEqual(self.act("lan-dns", "start", "start-after-refresh")["receipt"]["status"], "succeeded")

        def lost(host, source, payload, *, timeout, local=False):
            if payload["action"] == "refresh":
                raise RemoteError("transport lost")
            return self.fake_remote(host, source, payload, timeout=timeout, local=local)

        plan = self.manager.refresh_plan("lan-dns", add_records={"b": "192.168.50.3"})
        with patch.object(deploy, "run_remote", side_effect=lost):
            result = self.manager.refresh_apply(plan["id"], approved=True, request_id="refresh-lost")
        self.assertEqual(result["receipt"]["status"], "needs-inspection")
        self.assertTrue(self.state("lan-dns")["meta"]["uncertain"])
        with self.assertRaisesRegex(ValueError, "uncertain"):
            self.manager.refresh_plan("lan-dns", add_records={"c": "192.168.50.4"})
        lease = self.leases.store.current("ALPHA")
        self.assertEqual(lease["status"], "suspect")
        self.leases.store.break_device("ALPHA", reason="fixture recovery", operator="test",
                                       attest_stopped="The injected refresh transport failed before the remote call ran",
                                       expected_id=lease["lease_id"])
        self.save_template()
        self.deploy("garden")
        with self.assertRaisesRegex(ValueError, "no configuration files"):
            self.manager.refresh_plan("garden")

    def test_refresh_refuses_an_unexpected_file_at_plan_time_and_between_plan_and_apply(self):
        self.save_dns()
        self.dns_deploy()
        hosts = self.host_config("hosts")
        before = hosts.read_text()
        stray = hosts.parent / "stray.conf"
        stray.write_text("not Switchyard's\n")
        blocked = self.manager.refresh_plan("lan-dns", add_records={"a": "192.168.50.2"})
        self.assertEqual(blocked["blockers"], ["config-files-match-journal"])
        stray.unlink()
        plan = self.manager.refresh_plan("lan-dns", add_records={"a": "192.168.50.2"})
        self.assertEqual(plan.get("blockers", []), [])
        # The file appears after the plan was made: apply must refuse before writing, not report success
        # over drift that verify would flag at once.
        stray.write_text("appeared after the plan\n")
        result = self.manager.refresh_apply(plan["id"], approved=True, request_id="refresh-stray")
        self.assertEqual(result["receipt"]["status"], "failed", result)
        self.assertIn("stray.conf", result["receipt"]["error"])
        self.assertEqual(hosts.read_text(), before)
        self.assertTrue(stray.exists())  # Not Switchyard's file: reported, never removed.
        state = self.state("lan-dns")
        self.assertEqual((state["state"], state["meta"]["uncertain"]), ("active", False))

    def test_refresh_failure_after_the_rename_is_uncertain_not_nothing_written(self):
        self.save_dns()
        self.dns_deploy()
        plan = self.manager.refresh_plan("lan-dns", add_records={"late": "192.168.50.5"})
        hosts_before = self.host_config("hosts").read_text()

        def fsync_fails(path):  # os.replace already landed; the directory fsync then fails
            raise OSError("EIO")

        with patch.object(deploy_remote, "_sync_dir", fsync_fails):
            result = self.manager.refresh_apply(plan["id"], approved=True, request_id="refresh-eio")
        self.assertEqual(result["receipt"]["status"], "needs-inspection", result)
        self.assertNotEqual(self.host_config("hosts").read_text(), hosts_before)  # the new file is in place
        state = self.state("lan-dns")
        self.assertTrue(state["meta"]["uncertain"])
        self.assertEqual(state["meta"]["pending"]["files"]["hosts"], next(c["sha256"] for c in plan["changes"] if c["id"] == "hosts"))
        self.assertNotIn("refresh-refused", [e["event"] for e in result["receipt"]["events"]])
        with self.assertRaisesRegex(ValueError, "uncertain"):
            self.manager.refresh_plan("lan-dns", add_records={"later": "192.168.50.6"})

    def test_verify_reports_changed_configuration_files_and_failed_health(self):
        self.save_dns()
        self.dns_deploy()
        _, verification = self.verify("lan-dns")
        self.assertEqual((verification["consistent"], [h["ok"] for h in verification["observed"]["health"]]), (True, [True, True]))
        self.host_config("hosts").write_text("192.168.50.1 hand-edit.example.test\n")
        (self.host_config("hosts").parent / "stray").write_text("x")
        _, verification = self.verify("lan-dns")
        self.assertEqual(self.codes(verification), ["config-files-changed"])
        detail = verification["findings"][0]["detail"]
        self.assertIn("hosts sha256", detail)
        self.assertIn("unexpected file stray", detail)
        self.host.fail_health = True
        _, verification = self.verify("lan-dns")
        self.assertEqual(self.codes(verification), ["config-files-changed", "health-check-failed"])

    def test_cli_dns_plan_and_refresh(self):
        parser = argparse.ArgumentParser()
        commands = parser.add_subparsers(dest="command", required=True)
        deploy.register_cli(commands)
        service = SimpleNamespace(deployments=lambda: deploy.DeployManager(self.broker),
                                  hosts=lambda: {"hosts": copy.deepcopy(REGISTRY)})
        self.save_dns()
        plan = deploy.handle_cli(parser.parse_args(
            ["deploy", "plan", "--template", "coredns-lan", "--instance", "lan-dns", "--host", "alpha", "--param", "zone=example.test", "--param", "upstreams=192.168.50.1 192.168.50.2",
             "--port", "dns-udp=1053", "--port", "dns-tcp=1053", "--address", "dns-udp=192.168.50.120",
             "--address", "dns-tcp=192.168.50.120", "--record", "romm=192.168.50.233"]), service)
        self.assertIn("host-b.example.test", next(f for f in plan["native"]["config"] if f["name"] == "hosts")["text"])
        self.manager.apply(plan["id"], approved=True, request_id="cli-dns")
        refresh = deploy.handle_cli(parser.parse_args(["deploy", "refresh-plan", "lan-dns", "--record",
                                                       "test-record.example.test=192.168.50.250", "--remove-record", "romm"]), service)
        self.assertIn("-192.168.50.233 romm.example.test\n", next(c for c in refresh["changes"] if c["id"] == "hosts")["diff"])
        done = deploy.handle_cli(parser.parse_args(["deploy", "refresh-apply", refresh["id"], "--approve", "--request-id", "r1"]), service)
        self.assertEqual(done["receipt"]["status"], "succeeded", done)


class DeployLifecycleTests(DeployFixture):
    """The generic surface uses the real leased worker and remote primitives, not the direct-action API."""

    def setUp(self):
        super().setUp()
        self.save_template()

    def lifecycle(self, action, instance="garden", request_id=None):
        plan = self.manager.lifecycle_plan(action, instance)
        self.assertTrue(plan["executable"], plan["blockers"])
        return self.manager.lifecycle_apply(plan["id"], approved=True, request_id=request_id or action + "-" + instance)

    def gpu_setup(self):
        template = json.loads((ROOT / "catalogs" / "templates" / "llama-server-vulkan.json").read_text())
        template["revision"] = 1  # seed a new fixture store, independent of the live catalog's revision
        self.manager.save_template(template, expected_revision=0)
        self.config["deploy_devices"] = {"alpha": ["/dev/dri/renderD128"]}
        self.write_config()
        self.models = self.root / "models"
        model = self.models / "model"
        model.mkdir(parents=True)
        (model / "weights.gguf").write_bytes(b"GGUF" + b"\0" * 60)
        (model / "weights.gguf").chmod(0o644)

    def gpu_deploy(self, instance, *, port=18190, fenced=False):
        plan = self.manager.plan(instance_id=instance, host_id="alpha", template="llama-server-vulkan",
                                 ports={"http": port}, datasets={"models": str(self.models)},
                                 params={"model-dir": "model", "model-file": "weights.gguf"}, install_fenced=fenced)
        self.assertTrue(plan["executable"], plan["blockers"])
        result = self.manager.apply(plan["id"], approved=True, request_id="apply-" + instance)
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        return plan

    def test_stop_fences_and_start_opens_own_gate_with_auditable_workload_action(self):
        deployed, _ = self.deploy()
        service = deployed["native"]["names"]["service"]
        claims = self.manager.store.all_claims()
        plan = self.manager.lifecycle_plan("stop", "garden")
        self.assertEqual((plan["kind"], plan["workload_id"], plan["source_id"], plan["target_id"]),
                         ("deploy-lifecycle", "garden", "alpha", "alpha"))
        self.assertEqual((plan["generation"], plan["placement_revision"]),
                         (self.state()["generation"], self.state()["revision"]))
        self.assertEqual(plan["execution_timeout_seconds"], 450)
        self.assertTrue(all(isinstance(item, str) for item in plan["steps"] + plan["warnings"]))
        self.remote_actions.clear()
        with patch.object(self.broker, "_dispatch", side_effect=self.dispatch) as dispatched:
            stopped = self.manager.lifecycle_apply(plan["id"], approved=True, request_id="generic-stop")
        self.assertEqual(dispatched.call_count, 1)
        self.assertEqual(dispatched.call_args.args[1]["worker_seconds"], 435)
        self.assertEqual(self.remote_actions, ["fence"])
        self.assertEqual((stopped["receipt"]["workload_id"], stopped["receipt"]["action"]), ("garden", "stop"))
        self.assertEqual(stopped["receipt"]["status"], "succeeded", stopped)
        state = self.state()
        self.assertEqual((state["state"], state["meta"]["runtime"], state["meta"]["token"]["state"]),
                         ("fenced", "stopped", "revoked"))
        self.assertFalse(deploy.holds(state))
        self.assertEqual(self.host.start(service)[0], 1)  # boot/manual start uses the same durable gate
        self.assertEqual(self.host.pods, {})
        self.assertEqual(self.manager.store.all_claims(), claims)  # ports/data remain this deployment's
        self.remote_actions.clear()
        started = self.lifecycle("start")
        self.assertEqual(self.remote_actions, ["verify", "unfence", "start"])
        self.assertEqual((started["receipt"]["status"], started["receipt"]["action"]), ("succeeded", "start"))
        self.assertTrue(self.host.started(service))
        self.assertEqual((self.state()["state"], self.state()["meta"]["token"]["state"]), ("active", "valid"))
        self.assertIsNone(self.state()["meta"]["pending"])

    def test_stop_reenforces_fence_after_a_restored_token_and_manual_start(self):
        deployed, _ = self.deploy()
        service = deployed["native"]["names"]["service"]
        token = Path(self.paths()["token"])
        valid = token.read_text()
        self.lifecycle("stop")
        token.write_text(valid)
        self.assertEqual(self.host.start(service)[0], 0)
        self.assertEqual(self.state()["state"], "fenced")
        result = self.lifecycle("stop", request_id="enforce-stop")
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        self.assertFalse(self.host.started(service))
        self.assertEqual(self.host.pods, {})
        self.assertEqual(self.host.start(service)[0], 1)
        self.assertEqual((self.state()["state"], self.state()["meta"]["token"]["state"]), ("fenced", "revoked"))

    def test_restart_is_one_receipt_one_lease_and_one_start_after_proven_stop(self):
        deployed, _ = self.deploy()
        previous = self.state()["meta"]["native_identities"]["invocation_id"]
        self.remote_actions.clear()
        self.host.calls.clear()
        with patch.object(self.broker, "_dispatch", side_effect=self.dispatch) as dispatched, \
                patch.object(self.manager, "act", side_effect=AssertionError("must not call the public direct API")):
            result = self.lifecycle("restart")
        self.assertEqual(dispatched.call_count, 1)
        self.assertEqual(self.remote_actions, ["verify", "fence", "unfence", "start"])
        self.assertEqual((result["receipt"]["status"], result["receipt"]["workload_id"], result["receipt"]["action"]),
                         ("succeeded", "garden", "restart"))
        starts = [call for call in self.host.calls if call[0] == deploy_remote.SYSTEMCTL and "start" in call]
        self.assertEqual(len(starts), 1)
        self.assertEqual(self.host.restarts, [])
        self.assertNotEqual(self.state()["meta"]["native_identities"]["invocation_id"], previous)
        self.assertTrue(self.host.started(deployed["native"]["names"]["service"]))

    def test_restart_recovers_unit_stopped_while_journal_active(self):
        deployed, _ = self.deploy()
        service = deployed["native"]["names"]["service"]
        self.host.stop(service)
        self.assertEqual(self.state()["state"], "active")
        result = self.lifecycle("restart")
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        self.assertTrue(self.host.started(service))

    def test_blocked_preview_is_readable_and_does_not_fill_plan_queue(self):
        self.deploy()
        self.remote_actions.clear()
        with self.broker.store.transaction() as db:
            count = db.execute("SELECT count(*) FROM plans").fetchone()[0]
        for _ in range(3):
            plan = self.manager.lifecycle_plan("start", "garden")
            self.assertFalse(plan["executable"])
            self.assertIn("Start requires a stopped placement", plan["blockers"])
        with self.broker.store.transaction() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM plans").fetchone()[0], count)
        self.assertEqual(self.remote_actions, [])
        with self.assertRaisesRegex(ValueError, "Unknown plan"):
            self.manager.lifecycle_apply(plan["id"], approved=True, request_id="blocked")
        self.lifecycle("stop")
        self.assertIn("Restart requires an active placement", self.manager.lifecycle_plan("restart", "garden")["blockers"])

    def test_only_generic_lifecycle_plan_kinds_and_actions_are_accepted(self):
        deployment = self.plan()
        with self.assertRaisesRegex(ValueError, "lifecycle plan"):
            self.manager.lifecycle_apply(deployment["id"], approved=True, request_id="not-lifecycle")
        self.manager.apply(deployment["id"], approved=True, request_id="deploy")
        for action in ("deploy", "undeploy", "fence", "unfence", "switch", "refresh", "pull-start"):
            with self.subTest(action=action), self.assertRaisesRegex(ValueError, "Unsupported"):
                self.manager.lifecycle_plan(action, "garden")
        lifecycle = self.manager.lifecycle_plan("stop", "garden")
        with self.assertRaisesRegex(ValueError, "Not a deploy plan"):
            self.manager.apply(lifecycle["id"], approved=True, request_id="not-deploy")
        with self.assertRaisesRegex(ValueError, "approval"):
            self.manager.lifecycle_apply(lifecycle["id"], approved=False, request_id="unapproved")
        with self.assertRaisesRegex(ValueError, "current deployed placement"):
            self.manager.lifecycle_plan("start", "unknown")

    def test_expiry_replay_consumption_and_request_binding(self):
        self.deploy()
        expired = self.manager.lifecycle_plan("stop", "garden")
        expired["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        with self.broker.store.transaction() as db:
            db.execute("UPDATE plans SET data=? WHERE id=?", (encode(expired), expired["id"]))
        with self.assertRaisesRegex(ValueError, "expired"):
            self.manager.lifecycle_apply(expired["id"], approved=True, request_id="expired")
        plan = self.manager.lifecycle_plan("stop", "garden")
        first = self.manager.lifecycle_apply(plan["id"], approved=True, request_id="once")
        self.assertEqual(first["receipt"]["status"], "succeeded")
        commands = self.remote_actions[:]
        with self.assertRaises(ValueError):
            self.manager.lifecycle_apply(plan["id"], approved=True, request_id="twice")
        self.assertEqual(self.remote_actions, commands)
        other = self.manager.lifecycle_plan("start", "garden")
        with self.assertRaisesRegex(ValueError, "different intent"):
            self.manager.lifecycle_apply(other["id"], approved=True, request_id="once")
        plan["expires_at"] = expired["expires_at"]
        with self.broker.store.transaction() as db:
            db.execute("UPDATE plans SET data=? WHERE id=?", (encode(plan), plan["id"]))
        self.config["deploy_hosts"] = []
        self.write_config()
        self.remote_actions.clear()
        replay = self.manager.lifecycle_apply(plan["id"], approved=True, request_id="once")
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["receipt"]["id"], first["receipt"]["id"])
        self.assertEqual(self.remote_actions, [])

    def test_placement_is_bound_at_approval_and_again_inside_worker(self):
        self.deploy()
        plan = self.manager.lifecycle_plan("stop", "garden")
        self.act("garden", "fence", "out-of-band-fence")
        self.remote_actions.clear()
        with self.assertRaisesRegex(ValueError, "changed since planning"):
            self.manager.lifecycle_apply(plan["id"], approved=True, request_id="stale")
        self.assertEqual(self.remote_actions, [])
        plan = self.manager.lifecycle_plan("start", "garden")

        def change_before_lease(receipt, payload):
            with self.manager.store.transaction() as db:
                row = self.manager.store.placement_row(db, "garden")
                self.manager.store.cas_placement(db, "garden", row["generation"], row["revision"], row["placement"], row["meta"])
            return self.dispatch(receipt, payload)

        with patch.object(self.broker, "_dispatch", side_effect=change_before_lease):
            result = self.manager.lifecycle_apply(plan["id"], approved=True, request_id="stale-at-lease")
        self.assertEqual(result["receipt"]["status"], "failed", result)
        self.assertEqual(self.remote_actions, [])

    def test_authority_and_host_are_bound_and_rechecked_after_preflight(self):
        self.deploy()
        plan = self.manager.lifecycle_plan("stop", "garden")
        self.broker.hosts["alpha"]["expected_hostname"] = "changed"
        with self.assertRaisesRegex(ValueError, "configuration changed"):
            self.manager.lifecycle_apply(plan["id"], approved=True, request_id="host-changed")
        self.broker.hosts["alpha"]["expected_hostname"] = platform.node()
        self.lifecycle("stop")
        plan = self.manager.lifecycle_plan("start", "garden")

        def revoke_during_verify(payload):
            if payload["action"] == "verify":
                self.config["deploy_hosts"] = []
                self.write_config()

        self.remote_hook = revoke_during_verify
        self.remote_actions.clear()
        result = self.manager.lifecycle_apply(plan["id"], approved=True, request_id="revoke-during-preflight")
        self.assertEqual(result["receipt"]["status"], "failed", result)
        self.assertEqual(self.remote_actions, ["verify"])
        self.assertEqual(self.state()["meta"]["token"]["state"], "revoked")

    def test_restart_health_failure_stays_proven_fenced_without_retry(self):
        self.deploy()
        self.host.fail_health = True
        self.remote_actions.clear()
        result = self.lifecycle("restart")
        self.assertEqual(result["receipt"]["status"], "failed", result)
        self.assertEqual(self.remote_actions.count("start"), 1)
        state = self.state()
        self.assertEqual((state["state"], state["meta"]["runtime"], state["meta"]["token"]["state"], state["meta"]["uncertain"]),
                         ("fenced", "stopped", "revoked", False))
        self.assertFalse(deploy.holds(state))
        self.assertEqual(self.host.pods, {})

    def test_ambiguous_stop_keeps_pending_and_uncertainty_until_explicit_stop_proves_fence(self):
        self.deploy()
        self.host.leave_pod_on_stop = True
        result = self.lifecycle("stop")
        self.assertEqual(result["receipt"]["status"], "needs-inspection", result)
        state = self.state()
        self.assertTrue(state["meta"]["uncertain"])
        self.assertEqual(state["meta"]["pending"]["action"], "stop")
        self.assertTrue(deploy.holds(state))
        self.assertFalse(self.manager.lifecycle_plan("start", "garden")["executable"])
        self.host.leave_pod_on_stop = False
        # Simulate the host cleaning up the lingering pod. A repeat Stop still has to prove it is gone.
        self.host.stop(self.state()["meta"]["native"]["names"]["service"])
        recovered = self.lifecycle("stop", request_id="recover-stop")
        self.assertEqual(recovered["receipt"]["status"], "succeeded", recovered)
        self.assertEqual((self.state()["state"], self.state()["meta"]["uncertain"], self.state()["meta"]["pending"]),
                         ("fenced", False, None))

    def test_lost_start_ack_keeps_intent_and_replay_never_retries(self):
        self.deploy()
        self.lifecycle("stop")
        plan = self.manager.lifecycle_plan("start", "garden")

        def lost(host, source, payload, *, timeout, local=False):
            result = self.fake_remote(host, source, payload, timeout=timeout, local=local)
            if payload["action"] == "start":
                mark_uncertain("fixture start acknowledgement lost", resource=host["host_id"])
                raise RemoteError("start acknowledgement lost")
            return result

        with patch.object(deploy, "run_remote", side_effect=lost):
            result = self.manager.lifecycle_apply(plan["id"], approved=True, request_id="lost-start")
        self.assertEqual(result["receipt"]["status"], "needs-inspection", result)
        state = self.state()
        self.assertTrue(state["meta"]["uncertain"])
        self.assertEqual(state["meta"]["pending"]["action"], "start")
        self.assertTrue(deploy.holds(state))
        self.assertTrue(self.host.pods)  # it really started; losing the response is not a stop proof
        self.remote_actions.clear()
        replay = self.manager.lifecycle_apply(plan["id"], approved=True, request_id="lost-start")
        self.assertTrue(replay["replayed"])
        self.assertEqual(self.remote_actions, [])
        lease = self.leases.store.current("ALPHA")
        self.assertEqual(lease["status"], "suspect")
        self.leases.store.break_device("ALPHA", reason="fixture recovery", operator="test",
                                       attest_stopped="The in-process remote start returned; no transport or worker remains",
                                       expected_id=lease["lease_id"])
        self.assertEqual(self.lifecycle("stop", request_id="recover-lost-start")["receipt"]["status"], "succeeded")
        self.assertEqual(self.host.pods, {})

    def test_gpu_stop_releases_exclusive_resource_then_start_other_without_displacement(self):
        self.gpu_setup()
        self.gpu_deploy("model-a")
        self.gpu_deploy("model-b", port=18191, fenced=True)
        blocked = self.manager.lifecycle_plan("start", "model-b")
        self.assertFalse(blocked["executable"])
        self.assertIn("model-a", " ".join(blocked["blockers"]))
        self.assertEqual(self.state("model-a")["state"], "active")
        self.lifecycle("stop", "model-a")
        self.remote_actions.clear()
        result = self.lifecycle("start", "model-b")
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        self.assertEqual(self.remote_actions, ["verify", "facts", "devices", "unfence", "start"])
        self.assertEqual((self.state("model-a")["state"], self.state("model-b")["state"]), ("fenced", "active"))
        self.assertEqual(len(self.host.pods), 1)

    def test_gpu_holder_acquired_after_plan_is_refused_inside_lease(self):
        self.gpu_setup()
        self.gpu_deploy("model-a", fenced=True)
        self.gpu_deploy("model-b", port=18191, fenced=True)
        plan = self.manager.lifecycle_plan("start", "model-b")
        self.lifecycle("start", "model-a")
        self.remote_actions.clear()
        result = self.manager.lifecycle_apply(plan["id"], approved=True, request_id="holder-changed")
        self.assertEqual(result["receipt"]["status"], "failed", result)
        self.assertIn("model-a", result["receipt"]["error"])
        self.assertEqual(self.remote_actions, [])
        self.assertEqual((self.state("model-a")["state"], self.state("model-b")["state"]), ("active", "fenced"))

    def test_gpu_live_contender_token_rollback_blocks_start_without_mutating_either(self):
        self.gpu_setup()
        self.gpu_deploy("model-a")
        valid_token = Path(self.paths("model-a")["token"]).read_text()
        self.lifecycle("stop", "model-a")
        self.gpu_deploy("model-b", port=18191, fenced=True)
        plan = self.manager.lifecycle_plan("start", "model-b")
        Path(self.paths("model-a")["token"]).write_text(valid_token)
        self.remote_actions.clear()
        result = self.manager.lifecycle_apply(plan["id"], approved=True, request_id="rolled-back-contender")
        self.assertEqual(result["receipt"]["status"], "failed", result)
        self.assertIn("model-a", result["receipt"]["error"])
        self.assertEqual(self.remote_actions, ["verify"])
        self.assertEqual(self.state("model-b")["meta"]["token"]["state"], "revoked")
        self.assertEqual(self.host.pods, {})

    def test_gpu_device_grant_and_live_node_identity_access_are_checked_before_unfence(self):
        self.gpu_setup()
        self.gpu_deploy("model-a", fenced=True)
        self.config["deploy_devices"] = {}
        self.write_config()
        blocked = self.manager.lifecycle_plan("start", "model-a")
        self.assertFalse(blocked["executable"])
        self.assertIn("/dev/dri/renderD128", " ".join(blocked["blockers"]))
        self.config["deploy_devices"] = {"alpha": ["/dev/dri/renderD128"]}
        self.write_config()
        device = self.host.devices["/dev/dri/renderD128"]
        for change in ({"minor": 129}, {"mode": "0600"}, {"char": False}):
            with self.subTest(change=change):
                original = copy.deepcopy(device)
                plan = self.manager.lifecycle_plan("start", "model-a")
                device.update(change)
                self.remote_actions.clear()
                result = self.manager.lifecycle_apply(plan["id"], approved=True,
                                                      request_id="device-" + next(iter(change)))
                self.assertEqual(result["receipt"]["status"], "failed", result)
                self.assertIn("device", result["receipt"]["error"])
                self.assertEqual(self.remote_actions, ["verify", "facts", "devices"])
                self.assertEqual(self.state("model-a")["meta"]["token"]["state"], "revoked")
                device.clear()
                device.update(original)


class DNSResponder:
    """Tiny in-test DNS server on 127.0.0.1 (UDP and TCP): A records from a dict, NXDOMAIN otherwise.
    Over UDP it first sends a reply with the wrong ID, which the client must ignore."""

    def __init__(self, records):
        self.records = records
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.port = self.udp.getsockname()[1]
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.bind(("127.0.0.1", self.port))
        self.tcp.listen(4)
        for target in (self.serve_udp, self.serve_tcp):
            threading.Thread(target=target, daemon=True).start()

    def answer(self, query):
        offset, labels = 12, []
        while query[offset]:
            labels.append(query[offset + 1:offset + 1 + query[offset]].decode())
            offset += 1 + query[offset]
        question = query[12:offset + 5]
        qtype = struct.unpack("!H", query[offset + 1:offset + 3])[0]
        address = self.records.get(".".join(labels)) if qtype == 1 else None
        flags = 0x8580 if address else 0x8583
        reply = query[:2] + struct.pack("!HHHHH", flags, 1, 1 if address else 0, 0, 0) + question
        if address:  # owner name as a compression pointer to the question
            reply += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(address)
        return reply

    def serve_udp(self):
        while True:
            try:
                query, peer = self.udp.recvfrom(512)
                self.udp.sendto(bytes([query[0] ^ 0xFF]) + self.answer(query)[1:], peer)
                self.udp.sendto(self.answer(query), peer)
            except OSError:
                return

    def serve_tcp(self):
        while True:
            try:
                connection, _ = self.tcp.accept()
            except OSError:
                return
            with connection:
                length = struct.unpack("!H", connection.recv(2))[0]
                reply = self.answer(connection.recv(length))
                connection.sendall(struct.pack("!H", len(reply)) + reply)

    def close(self):
        self.udp.close()
        self.tcp.close()


class DNSCheckTests(unittest.TestCase):
    """The stdlib `dns` health check of deploy_remote against a real local responder (no patching)."""

    def setUp(self):
        self.server = DNSResponder({"host-b.example.test": "192.168.50.233"})
        self.addCleanup(self.server.close)

    def check(self, **changes):
        value = {"id": "lookup", "type": "dns", "address": "127.0.0.1", "port": self.server.port, "timeout_seconds": 2,
                 "protocol": "udp", "record_type": "A", "name": "host-b.example.test", "expect": []}
        value.update(changes)
        return deploy_remote.health(value, 0)  # one attempt

    def test_answer_expected_value_over_udp_and_tcp(self):
        for protocol in ("udp", "tcp"):
            with self.subTest(protocol=protocol):
                result = self.check(protocol=protocol, expect=["192.168.50.233"])
                self.assertEqual((result["ok"], result["rcode"], result["answers"]), (True, "NOERROR", ["192.168.50.233"]))
        self.assertTrue(self.check()["ok"])  # at least one answer

    def test_wrong_answer_nxdomain_and_silence_fail(self):
        wrong = self.check(expect=["192.168.50.234"])
        self.assertEqual((wrong["ok"], wrong["last"]["missing"]), (False, ["192.168.50.234"]))
        missing = self.check(name="nope.example.test")
        self.assertEqual((missing["ok"], missing["last"]["rcode"]), (False, "NXDOMAIN"))
        self.server.close()
        silent = self.check(timeout_seconds=1)
        self.assertFalse(silent["ok"])
        self.assertIn(silent["last"]["error"], {"timeout", "TimeoutError", "ConnectionRefusedError"})


if __name__ == "__main__":
    unittest.main()
