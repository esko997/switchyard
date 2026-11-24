"""Ansible backend: fake uvx/ansible-playbook/ansible-inventory/ssh on PATH, a temp Git repo and temp ledgers."""
import base64
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

from switchyard import ansible_ops
from switchyard.ansible_ops import AnsibleOps, outcome, validate_config
from switchyard.ansible_runner import parse_events
from switchyard.leases import LeaseBusy

ROOT = Path(__file__).resolve().parents[1]

FAKE_UVX = """
import os, sys
from pathlib import Path
here = Path(__file__).resolve().parent
args = sys.argv[1:]
assert args[0] == "--from" and args[1].startswith("ansible-core=="), args
with open(here.parent / "uvx.log", "a") as log:
    log.write(" ".join(args[2:3]) + "\\n")
os.execv(str(here / args[2]), [str(here / args[2]), *args[3:]])
"""

FAKE_PLAYBOOK = """
import fcntl, hashlib, json, os, sys, time
from pathlib import Path
here = Path(__file__).resolve().parent.parent
args = sys.argv[1:]
if "--version" in args:
    print("ansible-playbook [core 2.19.15]")
    sys.exit(0)
mode = "check" if "--check" in args else "apply"
behaviour = json.loads((here / "playbook.json").read_text())[mode]
ledger = (here / "ledger").read_text().strip()
fd = os.open(ledger, os.O_RDONLY)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    held = False
except BlockingIOError:
    held = True
os.close(fd)
extra = [args[i + 1] for i, a in enumerate(args) if a == "-e"]
user_vars = [json.loads(Path(e[1:]).read_text()) for e in extra if e.startswith("@") and "extra-vars" in e]
# `--become-password-file -`: ansible-core reads the password from stdin to EOF. Log only its digest.
password = sys.stdin.buffer.read().strip(b"\\r\\n").decode() if "--become-password-file" in args else None
with open(here / "runs.jsonl", "a") as log:
    log.write(json.dumps({"mode": mode, "argv": args, "lease_held": held, "env_events": bool(os.environ.get("SWITCHYARD_ANSIBLE_EVENTS")),
                          "user_vars": user_vars, "ansible_home": os.environ.get("ANSIBLE_HOME"),
                          "env_keys": sorted(os.environ),
                          "stdin_sha256": hashlib.sha256(password.encode()).hexdigest() if password is not None else None}) + "\\n")
refuse = behaviour.get("refuse_password") and password != behaviour["refuse_password"]
with open(os.environ["SWITCHYARD_ANSIBLE_EVENTS"], "a") as events:
    events.write(json.dumps({"at": time.time(), "event": "start", "check_mode": mode == "check"}) + "\\n")
    events.flush()
    for event in ([{"event": "result", "task": "Gathering Facts", "host": "host-a", "status": "failed",
                    "msg": "Incorrect sudo password"}, {"event": "stats", "hosts": {"host-a": {"ok": 0, "changed": 0,
                    "unreachable": 0, "failures": 1, "skipped": 0, "rescued": 0, "ignored": 0}}}, {"event": "end"}]
                  if refuse else behaviour.get("events", [])):
        if event.get("event") == "pause":
            time.sleep(event["seconds"])
            continue
        if password and behaviour.get("echo_password"):
            event = json.loads(json.dumps(event).replace("PASSWORD", password))
        events.write(json.dumps({"at": time.time(), **event}) + "\\n")
        events.flush()
stderr = behaviour.get("stderr", "")
sys.stderr.write(stderr.replace("PASSWORD", password) if password and behaviour.get("echo_password") else stderr)
time.sleep(behaviour.get("sleep", 0))
sys.exit(2 if refuse else behaviour.get("exit", 0))
"""

FAKE_INVENTORY = """
import sys
from pathlib import Path
here = Path(__file__).resolve().parent.parent
sys.stdout.write((here / "inventory.json").read_text())
"""

def yaml_python():
    """An interpreter with PyYAML for the YAML bridge: the pinned runner's own Python when uv has it cached
    (offline), else a system Python with PyYAML. Tests that parse YAML skip without one."""
    candidates = []
    uvx = shutil.which("uvx")
    if uvx and os.access(uvx, os.X_OK):
        try:
            found = subprocess.run([uvx, "--offline", "--from", "ansible-core==2.19.15", "python", "-c",
                                    "import sys, yaml; print(sys.executable)"], capture_output=True, text=True,
                                   timeout=120, stdin=subprocess.DEVNULL)
            if found.returncode == 0:
                candidates.append(found.stdout.strip())
        except (OSError, subprocess.SubprocessError):
            pass
    candidates += ["/usr/bin/python3"]
    for candidate in candidates:
        try:
            if subprocess.run([candidate, "-c", "import yaml"], capture_output=True, timeout=30).returncode == 0:
                return candidate
        except (OSError, subprocess.SubprocessError):
            continue
    return None


YAML_PYTHON = yaml_python()

FAKE_SSH = """
import sys
from pathlib import Path
here = Path(__file__).resolve().parent.parent
with open(here / "ssh.log", "a") as log:
    log.write(" ".join(sys.argv[1:]) + "\\n")
sys.exit(int((here / "ssh_exit").read_text()))
"""


def public_key():
    kind = b"ssh-ed25519"
    return "ssh-ed25519 " + base64.b64encode(struct.pack(">I", len(kind)) + kind + struct.pack(">I", 32) + b"x" * 32).decode()


def result(task, status, **extra):
    return {"event": "result", "task": task, "host": "host-a", "status": status, **extra}


def finished(**stats):
    base = {"ok": 0, "changed": 0, "unreachable": 0, "failures": 0, "skipped": 0, "rescued": 0, "ignored": 0}
    return [{"event": "stats", "hosts": {"host-a": {**base, **stats}}}, {"event": "end"}]


CHECK_EVENTS = [result("Gathering Facts", "ok"), result("Install packages", "changed", diff_bytes=120),
                result("Apply policy to the existing desktop", "skipped", not_predicted=True),
                *finished(ok=2, changed=1, skipped=1)]
APPLY_EVENTS = [result("Gathering Facts", "ok"), result("Install packages", "changed"), *finished(ok=2, changed=1)]


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                   check=True, capture_output=True)


class AnsibleFixture(unittest.TestCase):
    """Fake uvx/ansible-playbook/ansible-inventory/ssh, a temp Git repo inside a temp "home", temp ledger and state."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.fake = self.root / "fake"
        bin_dir = self.fake / "bin"
        bin_dir.mkdir(parents=True)
        for name, source in (("uvx", FAKE_UVX), ("ansible-playbook", FAKE_PLAYBOOK),
                             ("ansible-inventory", FAKE_INVENTORY), ("ssh", FAKE_SSH)):
            path = bin_dir / name
            path.write_text(f"#!{sys.executable}\n" + source)
            path.chmod(0o755)
        if YAML_PYTHON is None:
            self.skipTest("No Python with PyYAML for the YAML bridge")
        # A wrapper, not a symlink: a virtualenv interpreter finds its packages only through its own path.
        (bin_dir / "python").write_text(f"#!/bin/sh\nexec {shlex.quote(YAML_PYTHON)} \"$@\"\n")
        (bin_dir / "python").chmod(0o755)
        self.ledger = self.root / "DEVICE_ACCESS_HOSTA.md"
        self.ledger.write_text("fixture baseline\n")
        (self.fake / "ledger").write_text(str(self.ledger))
        (self.fake / "ssh_exit").write_text("0")
        self.behave(check={"events": CHECK_EVENTS}, apply={"events": APPLY_EVENTS})
        self.inventory_output({"_meta": {"hostvars": {"test-host-a": {
            "ansible_host": "192.168.50.99", "ansible_user": "other", "compute_user": "operator",
            "compute_rdp_allow_cidrs": ["192.168.50.0/24"]}}},
            "all": {"children": ["ungrouped", "compute_hosts"]}, "compute_hosts": {"children": ["desktops"]},
            "desktops": {"hosts": ["test-host-a"]}})
        environment = patch.dict(os.environ, {"PATH": f"{bin_dir}:{os.environ['PATH']}"})
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop("SWITCHYARD_UVX", None)
        self.repo = self.root / "host-init"
        (self.repo / "inventories").mkdir(parents=True)
        (self.repo / "site.yml").write_text("- hosts: compute_hosts\n  become: true\n  roles: []\n")
        (self.repo / "inventories/hosts.yml").write_text("all: {}\n")
        git(self.repo, "init", "-q")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-q", "-m", "initial")
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.pins = self.state / "pins.known_hosts"
        self.pins.write_text("switchyard-host-a " + public_key() + "\n")
        self.records = [
            {"id": "host-a", "host_keys": [public_key()], "connection_revision": 1,
             "collector": {"host_id": "host-a", "transport": "ssh", "target": "operator@192.168.50.120",
                           "expected_hostname": "test-host-a", "ledger": str(self.ledger),
                           "user_units": [], "system_units": []}},
            {"id": "test-portable", "host_keys": [], "connection_revision": 1,
             "collector": {"host_id": "test-portable", "transport": "ssh", "target": "operator@192.168.50.20",
                           "expected_hostname": "test-portable", "ledger": str(self.ledger),
                           "user_units": [], "system_units": []}},
            {"id": "test-handheld", "host_keys": [], "connection_revision": 1,
             "collector": {"host_id": "test-handheld", "transport": "adb", "serial": "x"}},
        ]
        self.config = {"schema_version": 1, "runner": {"ansible_core": "2.19.15", "collections": []},
                       "playbooks": {"host-init": {
                           "description": "fixture", "repo": str(self.repo), "playbook": "site.yml",
                           "inventory": "inventories/hosts.yml", "groups": ["compute_hosts"],
                           "allowed_hosts": ["host-a", "test-portable"], "become": True, "check_mode": "partial",
                           "extra_vars_allowed": ["api_token"]}}}
        self.now = time.time()

    def behave(self, **modes):
        (self.fake / "playbook.json").write_text(json.dumps(modes))

    def inventory_output(self, value):
        (self.fake / "inventory.json").write_text(json.dumps(value))

    def ops(self, **kwargs):
        path = self.root / "ansible.json"
        path.write_text(json.dumps(self.config))
        kwargs.setdefault("owner", "test-agent")
        return AnsibleOps(path, hosts=self.records, pins_path=self.pins, state_dir=self.state,
                          cache_dir=self.root / "cache", clock=lambda: self.now, home=self.root, **kwargs)

    def runs(self):
        path = self.fake / "runs.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def assert_ledger_free(self):
        fd = os.open(self.ledger, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
        text = self.ledger.read_text()
        self.assertEqual(text.count('"event": "CLAIM"'), text.count('"event": "RELEASE"'))


class AnsibleOpsTests(AnsibleFixture):
    # ---- registry ----

    def test_shipped_registry_validates_and_unknown_keys_are_rejected(self):
        shipped = ansible_ops.load_config(ROOT / "catalogs/ansible.example.json")
        self.assertTrue(shipped["playbooks"]["host-init"]["become"])
        self.assertEqual(ansible_ops.config_path(types.SimpleNamespace(catalog=str(ROOT / "catalogs/home-lab.json"), ansible_config=None)),
                         str(ROOT / "catalogs/home-lab.ansible.json"))
        for change in (lambda c: c.update(extra=1), lambda c: c["runner"].update(pip=[]),
                       lambda c: c["playbooks"]["host-init"].update(tags=["x"]),
                       lambda c: c["playbooks"]["host-init"].update(check_mode="maybe"),
                       lambda c: c["playbooks"]["host-init"].update(extra_vars_allowed=["ansible_become_password"]),
                       lambda c: c["playbooks"]["host-init"].update(playbook="../escape.yml"),
                       lambda c: c["runner"].update(ansible_core="2.19"),
                       lambda c: c["playbooks"]["host-init"].pop("allowed_hosts")):
            config = json.loads(json.dumps(self.config))
            change(config)
            with self.assertRaises(ValueError):
                validate_config(config)

    # ---- inventory ----

    def test_inventory_uses_pinned_identity_and_refuses_unpinned_hosts(self):
        ops = self.ops()
        view = ops.inventory("host-a")
        host = view["inventory"]["all"]["hosts"]["host-a"]
        self.assertEqual((host["ansible_host"], host["ansible_user"], host["ansible_port"]), ("192.168.50.120", "operator", 22))
        for option in ("HostKeyAlias=switchyard-host-a", f"UserKnownHostsFile={self.pins}",
                       "StrictHostKeyChecking=yes", "BatchMode=yes", "GlobalKnownHostsFile=/dev/null"):
            self.assertIn(option, host["ansible_ssh_args"])
        self.assertEqual(host["ansible_ssh_common_args"], "")
        everything = ops.inventory()
        self.assertEqual(list(everything["inventory"]["all"]["hosts"]), ["host-a"])
        self.assertEqual([row["host_id"] for row in everything["refused"]], ["test-portable"])
        with self.assertRaisesRegex(ValueError, "no pinned SSH host keys"):
            ops.inventory("test-portable")
        with self.assertRaisesRegex(ValueError, "not an SSH host"):
            ops.inventory("test-handheld")
        with self.assertRaisesRegex(ValueError, "no pinned"):
            ops.plan("host-init", "test-portable")

    def test_repo_inventory_vars_layer_under_switchyard_connection_vars(self):
        view = self.ops().inventory("host-a", "host-init")
        host = view["inventory"]["all"]["hosts"]["host-a"]
        self.assertEqual(host["compute_user"], "operator")
        self.assertEqual(host["ansible_host"], "192.168.50.120")
        self.assertEqual(view["layering"]["repo_inventory_host"], "test-host-a")
        self.assertEqual(view["layering"]["repo_vars_replaced"], ["ansible_host", "ansible_user"])
        self.assertEqual(sorted(view["inventory"]["all"]["children"]), ["compute_hosts", "desktops"])

    # ---- plan ----

    def test_dirty_repo_is_refused_unless_allowed_and_recorded(self):
        (self.repo / "site.yml").write_text("- hosts: all\n")
        with self.assertRaisesRegex(ValueError, "uncommitted"):
            self.ops().plan("host-init", "host-a")
        self.assertEqual(self.runs(), [])
        plan = self.ops().plan("host-init", "host-a", allow_dirty=True)
        self.assertTrue(plan["allow_dirty"])
        self.assertTrue(plan["repo"]["dirty"])

    def test_plan_runs_check_mode_under_the_lease_and_stores_task_results(self):
        plan = self.ops().plan("host-init", "host-a")
        self.assertEqual(plan["status"], "planned")
        self.assertTrue(plan["applicable"])
        self.assertEqual(plan["check"]["changed_tasks"], ["Install packages"])
        self.assertEqual(plan["check"]["not_predicted"], ["Apply policy to the existing desktop"])
        self.assertEqual(plan["repo"]["commit"], subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"],
                                                                capture_output=True, text=True).stdout.strip())
        [run] = self.runs()
        self.assertEqual(run["mode"], "check")
        self.assertTrue(run["lease_held"])
        self.assertIn("--diff", run["argv"])
        self.assertEqual(run["argv"][run["argv"].index("--limit") + 1], "host-a")
        self.assertTrue(run["ansible_home"].startswith(str(self.state)))
        self.assertEqual(self.ops().plan_record(plan["id"])["check"]["changed_tasks"], ["Install packages"])
        self.assert_ledger_free()

    def test_busy_lease_executes_nothing(self):
        fd = os.open(self.ledger, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        with self.assertRaises(LeaseBusy):
            self.ops().plan("host-init", "host-a", wait=0)
        self.assertEqual(self.runs(), [])

    def test_device_blocked_after_lease_break_refuses_probe_plan_and_apply(self):
        # `switchyard lease break` blocks the device until the operator clears it; an Ansible apply could
        # change the host, so it must honour the block exactly like agent leases and brokered operations.
        ops = self.ops()
        plan = ops.plan("host-init", "host-a")
        leases = self.state / "leases"
        leases.mkdir(mode=0o700, parents=True, exist_ok=True)
        block = leases / "blocked-HOSTA.json"
        block.write_text(json.dumps({"device": "HOSTA", "operator": "tester", "at": "2026-11-23T00:00:00+00:00", "reason": "fixture"}))
        block.chmod(0o600)
        before = len(self.runs())
        for call in (lambda: ops.probe("host-a"), lambda: ops.plan("host-init", "host-a"),
                     lambda: ops.apply(plan["id"], approved=True, request_id="blocked-1")):
            with self.assertRaisesRegex(LeaseBusy, "HOSTA blocked"):
                call()
        self.assertEqual(len(self.runs()), before)
        self.assert_ledger_free()
        block.unlink()
        self.assertEqual(ops.apply(plan["id"], approved=True, request_id="unblocked-1")["status"], "succeeded")

    def test_become_without_passwordless_sudo_prints_operator_command_and_runs_nothing(self):
        (self.fake / "ssh_exit").write_text("10")
        ops = self.ops()
        plan = ops.plan("host-init", "host-a")
        self.assertEqual(plan["status"], "needs-operator-privilege")
        self.assertFalse(plan["applicable"])
        self.assertEqual(self.runs(), [])
        command = plan["operator_commands"]["apply"]
        self.assertTrue(command.startswith("switchyard lease run host-a --scope"))
        self.assertIn("--ask-become-pass", command)
        self.assertIn(plan["inventory"]["path"], command)
        self.assertIn("ansible-core==2.19.15", command)
        self.assertIn("--check", plan["operator_commands"]["check"])
        with self.assertRaisesRegex(ValueError, "not applicable"):
            ops.apply(plan["id"], approved=True, request_id="r-1")
        self.assertIn("sudo -n true", (self.fake / "ssh.log").read_text())
        self.assert_ledger_free()

    def test_operator_run_is_recorded_from_its_events(self):
        (self.fake / "ssh_exit").write_text("10")
        ops = self.ops()
        plan = ops.plan("host-init", "host-a")
        with self.assertRaisesRegex(ValueError, "No operator apply run"):
            ops.record_manual(plan["id"], request_id="m-1")
        events = self.state / "ansible/manual" / f"{plan['id']}-apply.jsonl"
        events.write_text("".join(json.dumps({"at": time.time() + 1, **event}) + "\n" for event in
                                  [{"event": "start", "check_mode": False}, *APPLY_EVENTS]))
        receipt = ops.record_manual(plan["id"], request_id="m-1")
        self.assertEqual((receipt["status"], receipt["executor"]), ("succeeded", "operator"))
        self.assertEqual(receipt["changed_tasks"], ["Install packages"])
        self.assertEqual(ops.record_manual(plan["id"], request_id="m-1")["id"], receipt["id"])

    # ---- apply ----

    def test_apply_requires_approval_and_refuses_changed_inputs(self):
        ops = self.ops()
        plan = ops.plan("host-init", "host-a")
        with self.assertRaisesRegex(ValueError, "approval"):
            ops.apply(plan["id"], approved=False, request_id="r-1")
        self.now += ansible_ops.PLAN_TTL + 1
        with self.assertRaisesRegex(ValueError, "expired"):
            ops.apply(plan["id"], approved=True, request_id="r-1")
        self.now -= ansible_ops.PLAN_TTL + 1
        with self.assertRaisesRegex(ValueError, "only its secret variables are typed again"):
            ops.apply(plan["id"], approved=True, request_id="r-1", extra_vars={"api_token": "x"})
        # Repo inventory output changed: the generated inventory no longer matches.
        self.inventory_output({"_meta": {"hostvars": {"test-host-a": {"compute_user": "root2"}}},
                               "compute_hosts": {"hosts": ["test-host-a"]}})
        with self.assertRaisesRegex(ValueError, "inventory changed"):
            ops.apply(plan["id"], approved=True, request_id="r-1")
        self.records[0]["collector"]["target"] = "operator@192.168.50.121"
        with self.assertRaisesRegex(ValueError, "registry entry changed"):
            self.ops().apply(plan["id"], approved=True, request_id="r-1")
        self.records[0]["collector"]["target"] = "operator@192.168.50.120"
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "moved")
        with self.assertRaisesRegex(ValueError, "HEAD moved"):
            self.ops().apply(plan["id"], approved=True, request_id="r-1")
        self.assertEqual([run["mode"] for run in self.runs()], ["check"])
        self.assertEqual(ops.receipts(), [])

    def test_apply_writes_receipt_and_request_id_is_idempotent(self):
        ops = self.ops()
        plan = ops.plan("host-init", "host-a")
        receipt = ops.apply(plan["id"], approved=True, request_id="r-1")
        self.assertEqual(receipt["status"], "succeeded")
        self.assertEqual(receipt["changed_tasks"], ["Install packages"])
        self.assertEqual(receipt["commit"], plan["repo"]["commit"])
        self.assertEqual(receipt["ansible_core"], "2.19.15")
        again = ops.apply(plan["id"], approved=True, request_id="r-1")
        self.assertEqual((again["id"], again["replayed"]), (receipt["id"], True))
        with self.assertRaisesRegex(ValueError, "already used"):
            ops.apply(plan["id"], approved=True, request_id="r-2")
        self.assertEqual([run["mode"] for run in self.runs()], ["check", "apply"])
        self.assertTrue(self.runs()[1]["lease_held"])
        self.assertEqual(ops.receipt("r-1")["id"], receipt["id"])
        self.assert_ledger_free()

    def test_failed_apply_releases_the_lease_and_records_changed_tasks(self):
        self.behave(check={"events": CHECK_EVENTS}, apply={"exit": 2, "events": [
            result("Gathering Facts", "ok"), result("Install packages", "changed"),
            result("Configure xrdp", "failed", msg="boom"), *finished(ok=2, changed=1, failures=1)]})
        ops = self.ops()
        receipt = ops.apply(ops.plan("host-init", "host-a")["id"], approved=True, request_id="r-1")
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["failed_tasks"], ["Configure xrdp"])
        self.assertEqual(receipt["changed_tasks"], ["Install packages"])
        self.assertTrue(self.runs()[1]["lease_held"])
        self.assert_ledger_free()
        self.assertIn('"ansible_status": "failed"', self.ledger.read_text())

    def test_timeout_kills_runner_and_needs_inspection(self):
        self.behave(check={"events": CHECK_EVENTS}, apply={"sleep": 30, "events": [result("Install packages", "changed")]})
        ops = self.ops(apply_timeout=1)
        plan = ops.plan("host-init", "host-a")
        started = time.monotonic()
        receipt = ops.apply(plan["id"], approved=True, request_id="r-1")
        self.assertLess(time.monotonic() - started, 15)
        self.assertEqual(receipt["status"], "needs-inspection")
        self.assertTrue(receipt["timed_out"])
        self.assert_ledger_free()

    def test_extra_var_values_are_never_stored_or_printed(self):
        secret = "s3cr3t-token-value"
        # Task names are templated and failure messages are free text: both can echo an extra-var value.
        leaky_check = [result(f"Register token {secret}", "changed"),
                       result("Probe API", "failed", ignored=True, msg=f"401 for token {secret}"),
                       *CHECK_EVENTS]
        leaky_apply = [result("Gathering Facts", "ok"), result(f"Register token {secret}", "changed"),
                       result("Call API", "failed", msg=f"HTTP 500 with Authorization: {secret}"),
                       *finished(ok=1, changed=1, failures=1)]
        self.behave(check={"events": leaky_check, "stderr": f"warning: token {secret} seen\n"},
                    apply={"exit": 2, "events": leaky_apply})
        self.config["playbooks"]["host-init"]["secret_vars"] = ["api_token"]
        ops = self.ops()
        plan = ops.plan("host-init", "host-a", extra_vars={"api_token": secret})
        self.assertEqual(plan["status"], "planned")
        self.assertEqual(plan["extra_vars"], {"names": ["api_token"], "values": {}, "secret_names": ["api_token"]})
        self.assertNotIn(secret, json.dumps(plan))
        self.assertIn("Register token ***", plan["check"]["changed_tasks"])
        self.assertEqual(self.runs()[0]["user_vars"], [{"api_token": secret}])
        # A secret value is typed again for the apply; nothing derived from it is kept to compare against.
        with self.assertRaisesRegex(ValueError, "typed again: api_token"):
            ops.apply(plan["id"], approved=True, request_id="r-1")
        receipt = ops.apply(plan["id"], approved=True, request_id="r-1", extra_vars={"api_token": secret})
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["failed_tasks"], ["Call API"])
        self.assertEqual(receipt["changed_tasks"], ["Register token ***"])
        self.assertNotIn(secret, json.dumps(receipt) + json.dumps(ops.receipts()) + json.dumps(ops.plans()))
        stored = b"".join(path.read_bytes() for path in (self.state / "ansible").rglob("*") if path.is_file())
        self.assertNotIn(secret.encode(), stored)
        self.assertEqual(list((self.root / "cache/runs").iterdir()), [])
        with self.assertRaisesRegex(ValueError, "may not be overridden"):
            ops.plan("host-init", "host-a", extra_vars={"compute_user": "root"})

    def test_sigterm_during_apply_reaps_runner_and_needs_inspection(self):
        self.behave(check={"events": CHECK_EVENTS}, apply={"sleep": 30, "events": [result("Install packages", "changed")]})
        ops = self.ops()
        plan = ops.plan("host-init", "host-a")
        timer = threading.Timer(1.0, os.kill, (os.getpid(), signal.SIGTERM))
        timer.start()
        self.addCleanup(timer.cancel)
        with self.assertRaises(SystemExit):
            ops.apply(plan["id"], approved=True, request_id="r-1")
        self.assertEqual(ops.receipt("r-1")["status"], "needs-inspection")
        self.assert_ledger_free()

    def test_outcome_distinguishes_unreachable_before_and_during_the_run(self):
        early = {"stats": {"host-a": {"unreachable": 1}}, "ended": 1, "no_hosts_matched": False,
                 "tasks": [result("Gathering Facts", "unreachable")]}
        self.assertEqual(outcome(4, False, early, "host-a", 60)[0], "failed")
        late = {**early, "tasks": [result("Gathering Facts", "ok"), result("Install", "unreachable")]}
        self.assertEqual(outcome(4, False, late, "host-a", 60)[0], "needs-inspection")
        self.assertEqual(outcome(None, False, {**early, "ended": None}, "host-a", 60)[0], "needs-inspection")


class CallbackTests(unittest.TestCase):
    """The plugin with ansible stubbed: content-free events, no_log respected, check-mode prediction gaps."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.events = Path(temp.name) / "events.jsonl"
        callback_base = types.ModuleType("ansible.plugins.callback")
        callback_base.CallbackBase = type("CallbackBase", (), {"__init__": lambda self, display=None: None})
        context = types.ModuleType("ansible.context")
        context.CLIARGS = {"check": True}
        modules = {"ansible": types.ModuleType("ansible"), "ansible.plugins": types.ModuleType("ansible.plugins"),
                   "ansible.plugins.callback": callback_base, "ansible.context": context}
        modules["ansible"].context = context
        patcher = patch.dict(sys.modules, modules)
        patcher.start()
        self.addCleanup(patcher.stop)
        spec = importlib.util.spec_from_file_location("switchyard_events", ROOT / "switchyard/ansible_callback.py")
        module = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {"SWITCHYARD_ANSIBLE_EVENTS": str(self.events)}):
            spec.loader.exec_module(module)
            self.plugin = module.CallbackModule()

    @staticmethod
    def result(name, data, **task):
        host = types.SimpleNamespace(get_name=lambda: "host-a")
        task = types.SimpleNamespace(**{"get_name": lambda: name, "action": "ansible.builtin.copy", "no_log": False,
                                        "when": [], **task})
        return types.SimpleNamespace(task=task, host=host, result=data)

    def test_events_hold_names_statuses_and_sizes_only(self):
        self.plugin.v2_playbook_on_start(None)
        self.plugin.v2_runner_on_ok(self.result("write config", {"changed": True, "diff": {"after": "password=hunter2"}}))
        self.plugin.v2_runner_on_failed(self.result("hidden", {"msg": "token hunter2"}, no_log=True))
        self.plugin.v2_runner_on_skipped(self.result("live only", {"skip_reason": "Conditional result was False"},
                                                     when=["not ansible_check_mode"]))
        self.plugin.v2_runner_on_skipped(self.result("command", {"msg": "Command would have run if not in check mode"}))
        stats = types.SimpleNamespace(processed={"host-a": 1}, summarize=lambda host: {"ok": 1, "changed": 1, "failures": 1})
        self.plugin.v2_playbook_on_stats(stats)
        text = self.events.read_text()
        self.assertNotIn("hunter2", text)
        summary = parse_events(self.events)
        self.assertEqual(summary["changed_tasks"], ["write config"])
        self.assertGreater(summary["tasks"][0]["diff_bytes"], 0)
        self.assertEqual(summary["tasks"][1]["msg"], "(hidden by no_log)")
        self.assertEqual(summary["not_predicted"], ["live only", "command"])
        self.assertEqual(summary["stats"]["host-a"]["failures"], 1)
        self.assertIsNotNone(summary["ended"])


if __name__ == "__main__":
    unittest.main()
