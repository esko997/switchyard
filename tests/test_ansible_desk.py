"""Ansible in the desk: registrations (seed, revisions, path refusals), variable discovery, typed overrides, background
runs, the one-run become password and the HTTP routes. Fake runner and SSH; nothing contacts a host."""
import contextlib
import hashlib
import http.client
import io
import json
import logging
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from switchyard import ansible_discovery, ansible_ops
from switchyard.ansible_ops import JOBS, SUDO_REFUSED, SUPPLIED
from tests.test_ansible_ops import APPLY_EVENTS, CHECK_EVENTS, AnsibleFixture, finished, git, result
from tests.test_interfaces import operator_headers, write_catalog

PASSWORD = "TEST_PASSWORD_ONLY"

ARGUMENT_SPECS = """\
argument_specs:
  main:
    short_description: Web server
    options:
      web_mode:
        type: str
        choices: [static, proxy]
        required: true
        description: How the server answers.
      api_key:
        type: str
        no_log: true
        description: Upstream API key.
      upstream_hosts:
        type: list
        elements: str
        description:
          - Upstreams for proxy mode.
          - One per line.
"""
DEFAULTS = """\
---
# Serve on all interfaces unless a host says otherwise.
# Second line of the comment.
web_bind: 0.0.0.0
web_mode: static
# A section heading, not about web_workers

web_workers: 4
web_tls: false
web_root: "{{ web_base }}/html"
upstream_hosts: []
api_key: "default-key-in-repo"
"""
SITE = """\
- name: Configure the web host
  hosts: web
  become: true
  vars:
    listen_port: 8080
    banner: "{{ inventory_hostname }} welcomes you"
  vars_files:
    - vars/common.yml
  vars_prompt:
    - name: admin_password
      prompt: Admin password
    - name: release
      prompt: Release to deploy
      private: false
      default: stable
  roles:
    - webserver
"""


class DeskFixture(AnsibleFixture):
    def setUp(self):
        super().setUp()
        self.web = self.root / "webapp"
        files = {
            "site.yml": SITE, "vars/common.yml": "log_level: info\n",
            "roles/webserver/meta/argument_specs.yml": ARGUMENT_SPECS,
            "roles/webserver/defaults/main.yml": DEFAULTS,
            "roles/webserver/vars/main.yml": "web_user: www-data\n",
            "roles/webserver/tasks/main.yml": ("- name: Include the TLS role\n  ansible.builtin.include_role:\n"
                                               "    name: tls\n  when: web_tls\n"),
            "roles/tls/defaults/main.yml": "tls_cert_days: 365\n",
            "inventories/hosts.yml": "all:\n  children:\n    web:\n      hosts:\n        host-a:\n          custom: inline\n",
            "inventories/host_vars/host-a.yml": "listen_port: 9090\n",
            "inventories/group_vars/web.yml": ("web_mode: proxy\ndb_password: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n"
                                               "  6162636465\n"),
            ".venv/lib/ignored.yml": "not: scanned\n",
        }
        for name, text in files.items():
            (self.web / name).parent.mkdir(parents=True, exist_ok=True)
            (self.web / name).write_text(text)
        git(self.web, "init", "-q")
        (self.web / ".gitignore").write_text(".venv/\n")
        git(self.web, "add", ".")
        git(self.web, "commit", "-q", "-m", "initial")
        self.listing = {"_meta": {"hostvars": {"host-a": {
            "listen_port": 9090, "web_mode": "proxy", "custom": "inline", "ansible_host": "192.168.50.9"}}},
            "all": {"children": ["ungrouped", "web"]}, "web": {"hosts": ["host-a"]}}
        self.inventory_output(self.listing)
        self.entry = {"description": "Web host", "repo": str(self.web), "playbook": "site.yml",
                      "inventory": "inventories/hosts.yml", "groups": ["web"], "allowed_hosts": ["host-a"],
                      "become": True, "check_mode": "full",
                      "extra_vars_allowed": ["web_mode", "web_tls", "web_workers", "upstream_hosts", "api_key", "release"],
                      "secret_vars": []}

    def register(self, ops=None, **changes):
        ops = ops or self.ops()
        return ops.register("webapp", {**self.entry, **changes})

    def wait_run(self, ops, run_id, until=lambda run: run["status"] not in ("queued", "running"), timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            run = ops.run(run_id)
            if until(run):
                return run
            time.sleep(0.1)
        self.fail(f"run {run_id} did not reach the expected state: {ops.run(run_id)}")


class RegistrationTests(DeskFixture):
    def test_seed_is_one_time_idempotent_and_loses_nothing(self):
        ops = self.ops()
        [seeded] = ops.store.registrations()
        self.assertEqual((seeded["id"], seeded["revision"]), ("host-init", 1))
        self.assertTrue(seeded["updated_by"].startswith("seed from "))
        self.assertEqual(seeded["spec"]["secret_vars"], [])
        self.assertEqual([item["revision"] for item in self.ops().store.registrations()], [1])  # Not seeded again.
        edited = ops.update_registration("host-init", {**self.config["playbooks"]["host-init"], "description": "edited"},
                                         expected_revision=1)
        self.assertEqual(edited["revision"], 2)
        # The file changes after the seed: the database keeps the operator's edit and gains nothing from the file.
        self.config["playbooks"]["host-init"]["description"] = "file edit"
        self.config["playbooks"]["other"] = {**self.config["playbooks"]["host-init"]}
        view = self.ops().playbooks()
        self.assertEqual([row["id"] for row in view["playbooks"]], ["host-init"])
        self.assertEqual(view["playbooks"][0]["description"], "edited")
        self.assertEqual(view["registry"]["config_playbooks_not_in_database"], ["host-init", "other"])
        self.assertEqual(view["registry"]["seed"]["ids"], ["host-init"])
        # A file with only the runner pin is valid configuration.
        self.config.pop("playbooks")
        self.assertEqual([row["id"] for row in self.ops().playbooks()["playbooks"]], ["host-init"])

    def test_register_edit_remove_use_revisions(self):
        ops = self.ops()
        added = self.register(ops)
        self.assertEqual((added["revision"], added["spec"]["repo"]), (1, str(self.web)))
        with self.assertRaisesRegex(ValueError, "already registered"):
            self.register(ops)
        changed = ops.update_registration("webapp", {**self.entry, "secret_vars": ["release"]}, expected_revision=1)
        self.assertEqual(changed["revision"], 2)
        with self.assertRaisesRegex(ValueError, "changed since you read it \\(now revision 2\\)"):
            ops.update_registration("webapp", self.entry, expected_revision=1)
        with self.assertRaisesRegex(ValueError, "changed since you read it"):
            ops.remove_registration("webapp", expected_revision=1)
        self.assertTrue(ops.remove_registration("webapp", expected_revision=2)["removed"])
        with self.assertRaisesRegex(ValueError, "Unknown Ansible playbook"):
            ops.playbook("webapp")
        for bad, message in ((["test-handheld"], "not an SSH host"), (["nowhere"], "not an SSH host")):
            with self.assertRaisesRegex(ValueError, message):
                self.register(ops, allowed_hosts=bad)
        with self.assertRaisesRegex(ValueError, "cannot override ansible_"):
            self.register(ops, extra_vars_allowed=["ansible_become_password"])

    def test_paths_outside_home_symlink_escapes_and_foreign_files_are_refused(self):
        ops = self.ops()
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        elsewhere = Path(outside.name).resolve()
        git(elsewhere, "init", "-q")
        (elsewhere / "site.yml").write_text("- hosts: all\n")
        for path in (str(elsewhere), "relative/path"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "home directory|absolute path"):
                ops.inspect_directory(path)
        (self.root / "link").symlink_to(elsewhere)
        with self.assertRaisesRegex(ValueError, "a symlink leads outside"):
            ops.inspect_directory(str(self.root / "link"))
        with self.assertRaisesRegex(ValueError, "a symlink leads outside"):
            self.register(ops, repo=str(self.root / "link"))
        (self.web / "escape.yml").symlink_to(elsewhere / "site.yml")
        with self.assertRaisesRegex(ValueError, "leads outside the repository"):
            self.register(ops, playbook="escape.yml")
        self.assertIn({"path": "escape.yml", "reason": "symlink leading outside the repository"},
                      ops.inspect_directory(str(self.web))["skipped"])
        with patch.object(ansible_discovery.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaisesRegex(ValueError, "not the operator's own file"):
                ops.inspect_directory(str(self.web))
        self.web.chmod(0o777)
        self.addCleanup(self.web.chmod, 0o755)
        with self.assertRaisesRegex(ValueError, "writable by every user"):
            self.register(ops)

    def test_inspect_directory_offers_playbooks_inventories_and_variables(self):
        found = self.ops().inspect_directory(str(self.web))
        self.assertTrue(found["git"]["repository"])
        self.assertEqual([item["path"] for item in found["playbooks"]], ["site.yml"])
        self.assertEqual(found["playbooks"][0]["plays"][0]["hosts"], "web")
        self.assertIn("web_mode", [var["name"] for var in found["playbooks"][0]["variables"]])
        [inventory] = found["inventories"]
        self.assertEqual((inventory["path"], inventory["groups"], inventory["registry_hosts"]),
                         ("inventories/hosts.yml", ["web"], ["host-a"]))
        self.assertNotIn(".venv/lib/ignored.yml", json.dumps(found))


class DiscoveryTests(DeskFixture):
    def test_variables_from_specs_defaults_plays_roles_and_inventory(self):
        ops = self.ops()
        self.register(ops)
        vaulted = json.loads(json.dumps(self.listing))
        vaulted["_meta"]["hostvars"]["host-a"]["db_password"] = {"__ansible_vault": "$ANSIBLE_VAULT;1.1;AES256\n6162636465"}
        self.inventory_output(vaulted)
        found = ops.discover("webapp")
        variables = {var["name"]: var for var in found["variables"]}
        self.assertEqual([role["name"] for role in found["roles"]], ["webserver", "tls"])
        mode = variables["web_mode"]
        self.assertEqual((mode["type"], mode["choices"], mode["required"], mode["description"]),
                         ("str", ["static", "proxy"], True, "How the server answers."))
        self.assertEqual(mode["effective"]["host-a"], {"source": "repository inventory", "templated": False,
                                                          "origin": "inventories/group_vars/web.yml", "value": "proxy"})
        self.assertEqual((variables["upstream_hosts"]["type"], variables["upstream_hosts"]["elements"],
                          variables["upstream_hosts"]["description"]), ("list", "str", "Upstreams for proxy mode. One per line."))
        self.assertEqual(variables["web_bind"]["description"],
                         "Serve on all interfaces unless a host says otherwise. Second line of the comment.")
        self.assertIsNone(variables["web_workers"]["description"])
        self.assertEqual((variables["web_workers"]["type"], variables["web_tls"]["type"]), ("int", "bool"))
        # Jinja stays text, never evaluated.
        self.assertEqual(variables["web_root"]["default"]["value"], "{{ web_base }}/html")
        self.assertTrue(variables["web_root"]["templated"])
        self.assertEqual(variables["banner"]["effective"]["host-a"]["value"], "{{ inventory_hostname }} welcomes you")
        # Play vars beat the inventory's host_vars; role vars beat play vars.
        self.assertEqual(variables["listen_port"]["effective"]["host-a"]["value"], 8080)
        self.assertEqual(variables["listen_port"]["effective"]["host-a"]["source"], "play vars")
        self.assertEqual(variables["web_user"]["effective"]["host-a"]["source"], "role vars")
        self.assertEqual(variables["log_level"]["sources"][0]["origin"], "vars/common.yml")
        self.assertEqual(variables["tls_cert_days"]["sources"][0]["origin"], "roles/tls/defaults/main.yml")
        self.assertEqual((variables["release"]["secret"], variables["release"]["default"]["value"]), (False, "stable"))
        # no_log and private prompts are secret, as are vaulted inventory values: their values never leave discovery.
        for name in ("api_key", "admin_password"):
            self.assertTrue(variables[name]["secret"], name)
        self.assertNotIn("default-key-in-repo", json.dumps(found))
        self.assertNotIn("6162636465", json.dumps(found))
        host = found["hosts"]["host-a"]
        self.assertEqual(host["values"]["custom"], {"origin": "inventories/hosts.yml", "value": "inline", "templated": False})
        self.assertEqual(host["values"]["listen_port"]["origin"], "inventories/host_vars/host-a.yml")
        self.assertEqual(host["values"]["db_password"], {"origin": "inventories/group_vars/web.yml", "hidden": True})
        self.assertNotIn("ansible_host", host["values"])
        self.assertEqual([var["name"] for var in found["variables"] if var["overridable"]],
                         ["api_key", "release", "upstream_hosts", "web_mode", "web_tls", "web_workers"])
        # Discovery shows a vaulted value as hidden; a run still refuses vaulted inventory vars.
        with self.assertRaisesRegex(ValueError, "Vault-encrypted"):
            ops.plan("webapp", "host-a")

    def test_overrides_are_typed_allowed_and_secret_values_never_stored(self):
        ops = self.ops()
        self.register(ops)
        for values, message in (({"web_tls": "yes"}, "true or false"), ({"web_mode": "cgi"}, "declared choices"),
                                ({"web_workers": 4.5}, "whole number"), ({"upstream_hosts": ["a", 3]}, "text"),
                                ({"web_bind": "127.0.0.1"}, "may not be overridden"),
                                ({"listen_port": 1}, "may not be overridden")):
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, message):
                ops.plan("webapp", "host-a", extra_vars=values)
        self.assertEqual(self.runs(), [])
        secret = "TEST_API_KEY_ONLY"
        plan = ops.plan("webapp", "host-a", extra_vars={"web_mode": "proxy", "web_tls": True,
                                                         "upstream_hosts": ["a", "b"], "api_key": secret})
        self.assertEqual(plan["extra_vars"], {"names": ["api_key", "upstream_hosts", "web_mode", "web_tls"],
                                              "values": {"upstream_hosts": ["a", "b"], "web_mode": "proxy", "web_tls": True},
                                              "secret_names": ["api_key"]})
        self.assertEqual(self.runs()[0]["user_vars"], [{"web_mode": "proxy", "web_tls": True,
                                                        "upstream_hosts": ["a", "b"], "api_key": secret}])
        self.assertNotIn(secret, " ".join(self.runs()[0]["argv"]))
        with self.assertRaisesRegex(ValueError, "typed again: api_key"):
            ops.apply(plan["id"], approved=True, request_id="r-1", extra_vars={"web_mode": "static"})
        receipt = ops.apply(plan["id"], approved=True, request_id="r-1", extra_vars={"api_key": secret})
        self.assertEqual(receipt["extra_vars"]["values"]["web_mode"], "proxy")
        self.assertEqual(self.runs()[1]["user_vars"][0]["api_key"], secret)
        stored = b"".join(path.read_bytes() for path in self.state.rglob("*") if path.is_file())
        self.assertNotIn(secret.encode(), stored)
        self.assertIn(b"proxy", stored)  # Non-secret overrides are recorded.


class RunLifecycleTests(DeskFixture):
    def test_background_plan_reports_progress_survives_reload_and_allows_one_run_per_host(self):
        self.behave(check={"events": [{"event": "task", "name": "Gathering Facts"}, result("Gathering Facts", "ok"),
                                      {"event": "task", "name": "Install packages"}, {"event": "pause", "seconds": 2.5},
                                      result("Install packages", "changed"), *finished(ok=2, changed=1)]},
                    apply={"events": APPLY_EVENTS})
        ops = self.ops()
        run = ops.plan("host-init", "host-a", background=True)
        self.assertEqual((run["kind"], run["status"]), ("plan", "running"))
        with self.assertRaisesRegex(ValueError, "already has a run in progress"):
            ops.plan("host-init", "host-a", background=True)
        # A new instance (a reloaded page, another request) reads the same run and its live progress.
        live = self.wait_run(self.ops(), run["id"], lambda item: (item.get("progress") or {}).get("task") == "Install packages")
        self.assertEqual(live["status"], "running")
        self.assertEqual(live["progress"]["counts"], {"ok": 1})
        done = self.wait_run(self.ops(), run["id"])
        self.assertEqual(done["status"], "planned")
        self.assertEqual(done["plan"]["check"]["changed_tasks"], ["Install packages"])
        self.assertEqual(done["plan"]["run_id"], run["id"])
        self.assert_ledger_free()

    def test_busy_lease_names_the_holder_and_runs_nothing(self):
        fd = os.open(self.ledger, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX)
        ops = self.ops()
        run = self.wait_run(ops, ops.plan("host-init", "host-a", wait=0, background=True)["id"])
        self.assertEqual(run["status"], "busy")
        self.assertIn("HOSTA busy", run["error"])
        self.assertIn(str(os.getpid()), run["error"])
        self.assertEqual(self.runs(), [])

    def test_failed_apply_and_host_lost_mid_run(self):
        self.behave(check={"events": CHECK_EVENTS}, apply={"exit": 2, "events": [
            result("Gathering Facts", "ok"), result("Configure", "failed", msg="boom"), *finished(ok=1, failures=1)]})
        ops = self.ops()
        plan = ops.plan("host-init", "host-a")
        run = self.wait_run(ops, ops.apply(plan["id"], approved=True, request_id="f-1", background=True)["id"])
        self.assertEqual((run["status"], run["receipt"]["failed_tasks"]), ("failed", ["Configure"]))
        self.behave(check={"events": CHECK_EVENTS}, apply={"exit": 4, "events": [
            result("Gathering Facts", "ok"), result("Install packages", "unreachable", msg="Connection reset"),
            *finished(ok=1, unreachable=1)]})
        plan = ops.plan("host-init", "host-a")
        run = self.wait_run(ops, ops.apply(plan["id"], approved=True, request_id="f-2", background=True)["id"])
        self.assertEqual(run["status"], "needs-inspection")
        self.assertIn("unreachable mid-run", run["error"])
        self.assertEqual([item["status"] for item in ops.receipts()], ["needs-inspection", "failed"])
        self.assert_ledger_free()

    def test_stopped_desk_and_dead_process_leave_needs_inspection(self):
        self.behave(check={"events": CHECK_EVENTS}, apply={"events": [
            {"event": "task", "name": "Install packages"}, {"event": "pause", "seconds": 30}, *APPLY_EVENTS]})
        ops = self.ops()
        plan = ops.plan("host-init", "host-a")
        run = ops.apply(plan["id"], approved=True, request_id="s-1", background=True)
        self.wait_run(ops, run["id"], lambda item: (item.get("progress") or {}).get("task") == "Install packages")
        started = time.monotonic()
        JOBS.shutdown(timeout=20)  # What SIGTERM to the desk does.
        self.assertLess(time.monotonic() - started, 15)
        stopped = ops.run(run["id"])
        self.assertEqual((stopped["status"], stopped["receipt"]["status"]), ("needs-inspection", "needs-inspection"))
        self.assert_ledger_free()
        # A run whose process vanished (desk killed without cleanup) is settled on the next read.
        with sqlite3.connect(ops.store.path) as db:
            db.execute("UPDATE runs SET data=json_set(data,'$.status','running'), birth='gone' WHERE id=?", (run["id"],))
        self.assertEqual(self.ops().run(run["id"])["status"], "needs-inspection")


class BecomePasswordTests(DeskFixture):
    def setUp(self):
        super().setUp()
        (self.fake / "ssh_exit").write_text("10")  # The host has no passwordless sudo.

    def test_password_reaches_the_runner_by_pipe_only_and_is_never_recorded(self):
        self.behave(check={"echo_password": True, "stderr": "debug: PASSWORD\n", "events": [
                        result("Probe with PASSWORD", "ok"), result("Check", "failed", ignored=True, msg="saw PASSWORD"),
                        *CHECK_EVENTS]},
                    apply={"echo_password": True, "events": [
                        {"event": "task", "name": "Task PASSWORD"}, {"event": "pause", "seconds": 1.5},
                        result("Install PASSWORD", "changed"), *finished(ok=1, changed=1)]})
        logs = io.StringIO()
        handler = logging.StreamHandler(logs)
        logging.getLogger().addHandler(handler)
        self.addCleanup(logging.getLogger().removeHandler, handler)
        captured_out, captured_err = io.StringIO(), io.StringIO()
        ops = self.ops()
        with contextlib.redirect_stdout(captured_out), contextlib.redirect_stderr(captured_err):
            unprivileged = ops.plan("host-init", "host-a")
            self.assertEqual(unprivileged["status"], "needs-operator-privilege")
            self.assertIn("--ask-become-pass", unprivileged["operator_commands"]["apply"])  # The terminal path stays.
            run = ops.plan("host-init", "host-a", become_password=PASSWORD, background=True)
            self.assertEqual(run["become_password"], SUPPLIED)
            plan = self.wait_run(ops, run["id"])["plan"]
            self.assertEqual((plan["status"], plan["become_password"]), ("planned", SUPPLIED))
            self.assertIn("Probe with ***", [task["task"] for task in plan["check"]["tasks"]])
            self.assertIn("***", plan["check"]["stderr_tail"])
            # Not carried from the plan: the apply asks again, refused before the plan is consumed.
            with self.assertRaisesRegex(ValueError, "type the sudo password for this apply"):
                ops.apply(plan["id"], approved=True, request_id="b-1")
            run = ops.apply(plan["id"], approved=True, request_id="b-1", become_password=PASSWORD, background=True)
            live = self.wait_run(ops, run["id"], lambda item: (item.get("progress") or {}).get("task"))
            self.assertEqual(live["progress"]["task"], "Task ***")
            # Mid-run (the runner has already echoed the password into an event): nothing on disk holds it.
            # The callback's events path is a FIFO read into memory; there is no events file to find.
            kinds = []
            for root in (self.root / "cache", self.state):
                for path in root.rglob("*"):
                    try:  # Files come and go while the run writes its records.
                        mode = path.lstat().st_mode
                        kinds.append(stat.S_IFMT(mode))
                        if stat.S_ISREG(mode):
                            self.assertNotIn(PASSWORD.encode(), path.read_bytes(), str(path))
                    except FileNotFoundError:
                        continue
            self.assertIn(stat.S_IFIFO, kinds)
            done = self.wait_run(ops, run["id"])
        self.assertEqual((done["status"], done["receipt"]["become_password"]), ("succeeded", SUPPLIED))
        self.assertEqual(done["receipt"]["changed_tasks"], ["Install ***"])
        runner_runs = [item for item in self.runs() if item["mode"] in {"check", "apply"}]
        digest = hashlib.sha256(PASSWORD.encode()).hexdigest()
        self.assertEqual([item["stdin_sha256"] for item in runner_runs], [digest, digest])
        for item in runner_runs:
            self.assertEqual(item["argv"][item["argv"].index("--become-password-file") + 1], "-")
        # Every database and state file, the ledger, the runner log, run scratch, every event and log line.
        haystacks = [path.read_bytes() for root in (self.state, self.root / "cache") for path in root.rglob("*")
                     if path.is_file()]
        haystacks += [self.ledger.read_bytes(), (self.fake / "runs.jsonl").read_bytes(),
                      json.dumps([ops.runs(), ops.plans(), ops.receipts(), ops.playbooks()]).encode(),
                      logs.getvalue().encode(), captured_out.getvalue().encode(), captured_err.getvalue().encode()]
        self.assertTrue(any(b"supplied by the operator" in item for item in haystacks))
        for item in haystacks:
            self.assertNotIn(PASSWORD.encode(), item)
        self.assertEqual(list((self.root / "cache/runs").iterdir()), [])
        self.assert_ledger_free()

    def test_wrong_password_is_reported_once_and_not_retried(self):
        self.behave(check={"refuse_password": "the right one", "events": CHECK_EVENTS}, apply={"events": APPLY_EVENTS})
        ops = self.ops()
        plan = ops.plan("host-init", "host-a", become_password=PASSWORD)
        self.assertEqual(plan["status"], "failed")
        self.assertTrue(plan["become_refused"])
        self.assertEqual(plan["blockers"], [SUDO_REFUSED])
        self.assertEqual(len([item for item in self.runs() if item["mode"] == "check"]), 1)
        with self.assertRaisesRegex(ValueError, "not applicable"):
            ops.apply(plan["id"], approved=True, request_id="w-1", become_password=PASSWORD)

    def test_password_rules(self):
        ops = self.ops()
        for value in ("", "two\nlines", "x" * 1025):
            with self.subTest(value=value[:8]), self.assertRaisesRegex(ValueError, "1-1024 characters on one line"):
                ops.plan("host-init", "host-a", become_password=value)
        ops.register("plain", {**self.config["playbooks"]["host-init"], "become": False})
        with self.assertRaisesRegex(ValueError, "not registered as using become"):
            ops.plan("plain", "host-a", become_password=PASSWORD)
        self.assertEqual(repr(ansible_ops.BecomePassword(PASSWORD)), "<become password>")

    def test_cli_prompts_only_on_a_terminal(self):
        with patch("sys.stdin", io.StringIO(PASSWORD)), self.assertRaisesRegex(ValueError, "needs a terminal"):
            ansible_ops.ask_become_password()
        with patch("sys.stdin.isatty", return_value=True), patch("getpass.getpass", return_value=PASSWORD):
            secret = ansible_ops.ask_become_password()
        self.assertTrue(secret)
        self.assertEqual(secret.take(), PASSWORD)
        self.assertFalse(secret)


class AnsibleHTTPTests(DeskFixture):
    """The routes over a real loopback desk, with the backend pointed at the fixture."""

    ROUTES = {("GET", "/api/ansible/playbooks"): "read", ("GET", "/api/ansible/playbooks/{id}"): "read",
              ("GET", "/api/ansible/runs"): "read", ("GET", "/api/ansible/runs/{id}"): "read",
              ("POST", "/api/ansible/inspect"): "operator", ("POST", "/api/ansible/playbooks"): "operator",
              ("POST", "/api/ansible/playbooks/{id}/update"): "operator",
              ("POST", "/api/ansible/playbooks/{id}/remove"): "operator", ("POST", "/api/ansible/plan"): "operator",
              ("POST", "/api/ansible/apply"): "operator", ("POST", "/api/ansible/plans/{id}/record-manual"): "operator"}

    def setUp(self):
        super().setUp()
        from switchyard.web import _Handler, create_server
        self.server = create_server(write_catalog(str(self.root)), port=0, state_dir=self.state)
        thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        self.addCleanup(lambda: (self.server.shutdown(), thread.join(7), self.server.server_close()))
        self.port = self.server.server_address[1]
        fixture = self
        patcher = patch.object(_Handler, "_ansible", lambda handler: fixture.ops(
            owner=f"operator:{handler.identity.username} (web)" if handler.identity.kind == "operator" else None))
        patcher.start()
        self.addCleanup(patcher.stop)

    def call(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            payload = None if body is None else json.dumps(body)
            connection.request(method, path, payload, {**({"Content-Type": "application/json"} if body is not None else {}),
                                                       **(headers or {})})
            response = connection.getresponse()
            return response.status, json.loads(response.read() or b"null")
        finally:
            connection.close()

    def poll(self, run_id, headers):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            status, run = self.call("GET", f"/api/ansible/runs/{run_id}", headers=headers)
            self.assertEqual(status, 200, run)
            if run["status"] not in ("queued", "running"):
                return run
            time.sleep(0.1)
        self.fail("run did not finish")

    def test_route_table_entries_and_authority(self):
        from switchyard.web import ROUTES
        table = {(route.method, route.path): route.authority for route in ROUTES if "/api/ansible/" in route.path}
        self.assertEqual(table, self.ROUTES)
        # Loopback without a session (`local`) reads but cannot register, plan or apply.
        self.assertEqual(self.call("GET", "/api/ansible/playbooks")[0], 200)
        for path, body in (("/api/ansible/inspect", {"path": str(self.web)}), ("/api/ansible/plan", {}),
                           ("/api/ansible/apply", {}), ("/api/ansible/playbooks", {}),
                           ("/api/ansible/playbooks/host-init/update", {}), ("/api/ansible/playbooks/host-init/remove", {}),
                           ("/api/ansible/plans/" + "0" * 32 + "/record-manual", {})):
            with self.subTest(path=path):
                status, answer = self.call("POST", path, body)
                self.assertEqual((status, "operator" in answer["error"]), (403, True))
        # A key (even operate on this host) reads, and cannot run playbooks.
        key = {"id": "k" * 16, "scope": "operate", "hosts": ["host-a"], "name": "agent", "user": "u"}
        with patch.object(self.server.auth, "key_for_bearer", return_value=key):
            bearer = {"Authorization": "Bearer sy1_" + "A" * 43}
            self.assertEqual(self.call("GET", "/api/ansible/runs", headers=bearer)[0], 200)
            status, answer = self.call("POST", "/api/ansible/plan", {"playbook_id": "host-init", "host_id": "host-a"}, bearer)
            self.assertEqual(status, 403)
        self.assertEqual(self.runs(), [])

    def test_operator_registers_plans_with_password_and_applies_end_to_end(self):
        (self.fake / "ssh_exit").write_text("10")
        operator = operator_headers(self.server, self.port)
        status, found = self.call("POST", "/api/ansible/inspect", {"path": str(self.web)}, operator)
        self.assertEqual((status, found["playbooks"][0]["path"]), (200, "site.yml"))
        status, added = self.call("POST", "/api/ansible/playbooks", {"playbook_id": "webapp", "registration": self.entry}, operator)
        self.assertEqual((status, added["revision"], added["updated_by"]), (200, 1, "operator:operator (web)"))
        status, detail = self.call("GET", "/api/ansible/playbooks/webapp")
        self.assertEqual(status, 200)
        self.assertIn("web_mode", [var["name"] for var in detail["discovery"]["variables"]])
        plan_body = {"playbook_id": "webapp", "host_id": "host-a", "extra_vars": {"web_mode": "static"},
                     "become_password": PASSWORD}
        status, run = self.call("POST", "/api/ansible/plan", plan_body, operator)
        self.assertEqual((status, run["status"]), (202, "running"))
        plan = self.poll(run["id"], operator)["plan"]
        self.assertEqual((plan["status"], plan["extra_vars"]["values"]), ("planned", {"web_mode": "static"}))
        status, answer = self.call("POST", "/api/ansible/apply", {"plan_id": plan["id"], "approved": True,
                                                                  "request_id": "http-1"}, operator)
        self.assertEqual(status, 400)
        self.assertIn("type the sudo password", answer["error"])
        status, run = self.call("POST", "/api/ansible/apply", {"plan_id": plan["id"], "approved": True,
                                                               "request_id": "http-1", "become_password": PASSWORD}, operator)
        self.assertEqual(status, 202)
        done = self.poll(run["id"], operator)
        self.assertEqual(done["status"], "succeeded")
        # The receipt is in the Audit log, by its ID too.
        status, audit = self.call("GET", "/api/operations")
        self.assertIn(done["receipt_id"], [item["id"] for item in audit])
        status, entry = self.call("GET", f"/api/operations/{done['receipt_id']}")
        self.assertEqual((status, entry["host_ids"], entry["action"]), (200, ["host-a"], "ansible-apply"))
        stored = b"".join(path.read_bytes() for path in self.state.rglob("*") if path.is_file())
        self.assertNotIn(PASSWORD.encode(), stored)
        # Revisions: a stale edit is refused, the current one applies, removal needs the current revision.
        stale = self.call("POST", "/api/ansible/playbooks/webapp/update", {"registration": self.entry, "expected_revision": 0}, operator)
        self.assertEqual(stale[0], 400)
        status, edited = self.call("POST", "/api/ansible/playbooks/webapp/update",
                                   {"registration": {**self.entry, "description": "Edited"}, "expected_revision": 1}, operator)
        self.assertEqual((status, edited["revision"]), (200, 2))
        self.assertEqual(self.call("POST", "/api/ansible/playbooks/webapp/remove", {"expected_revision": 2}, operator)[0], 200)

    def test_password_refused_on_a_plain_http_network_listener(self):
        self.server.listener = "lan"  # As a plain-HTTP listener reached over the network would be.
        self.server.auth.set_password("operator", "correct horse battery staple", scrypt_n=2 ** 10)
        status, headers, body = None, None, None
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=7)
        connection.request("POST", "/api/auth/login", json.dumps({"username": "operator", "password": "correct horse battery staple"}),
                           {"Content-Type": "application/json"})
        response = connection.getresponse()
        body = json.loads(response.read())
        cookie = response.getheader("Set-Cookie").split(";", 1)[0]
        connection.close()
        operator = {"Cookie": cookie, "X-Switchyard-CSRF": body["csrf_token"]}
        status, answer = self.call("POST", "/api/ansible/plan", {"playbook_id": "host-init", "host_id": "host-a",
                                                                 "become_password": PASSWORD}, operator)
        self.assertEqual(status, 400)
        self.assertIn("only over HTTPS or on the desk itself", answer["error"])
        self.assertEqual(self.runs(), [])


if __name__ == "__main__":
    unittest.main()
