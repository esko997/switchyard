"""Remote client (tools/switchyard-remote) against a fake `ssh` on PATH; temporary ledgers only."""
from contextlib import redirect_stderr, redirect_stdout
import getpass
import shlex
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

CLIENT = Path(__file__).resolve().parents[1] / "tools/switchyard-remote"

# The fake ssh: records its argv, then plays the control host. Mode `real` runs the real CLI
# (`switchyard lease attach`) on temporary ledgers; the others script one control-host behaviour.
FAKE_SSH = r'''
import json, os, shlex, sys, time
with open(os.environ["FAKE_SSH_LOG"], "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\n")
remote = shlex.split(sys.argv[-1])
mode = os.environ.get("FAKE_SSH_MODE", "real")
claim = {"status": "claimed", "lease_id": "f" * 32, "device": "TESTHANDHELD", "expires_at": "2033-01-01T00:00:00+00:00",
         "env": {"SWITCHYARD_LEASE_ID": "f" * 32, "SWITCHYARD_DEVICE": "TESTHANDHELD", "ANDROID_SERIAL": "fake-serial"}}
if remote[1:3] != ["lease", "attach"]:
    if "mcp" in remote[0]:
        sys.stdout.write("mcp:" + sys.stdin.read())
    else:
        print("remote-ok " + " ".join(remote[1:]))
    sys.stderr.write(os.environ.get("FAKE_SSH_STDERR", ""))
    sys.exit(int(os.environ.get("FAKE_SSH_EXIT", "0")))
if mode == "real":
    from unittest.mock import patch
    from switchyard import cli
    from switchyard.agent_leases import AgentLeases
    manager = AgentLeases(collectors={"test-handheld": {"transport": "adb", "serial": "fake-serial",
                                                   "ledger": os.environ["FAKE_LEDGER"]}},
                          ledger_dir=os.path.dirname(os.environ["FAKE_LEDGER"]), state_dir=os.environ["FAKE_STATE"],
                          hosts=("test-handheld", "host-b"))
    with patch.object(cli, "Service") as service:
        service.return_value.agent_leases.return_value = manager
        sys.argv = ["switchyard", "--catalog", "fixture", *remote[1:]]
        cli.main()
elif mode == "busy":
    print("switchyard: TESTHANDHELD busy: FixtureAgent; fixture scope; 3s ago", file=sys.stderr)
    sys.exit(75)
elif mode == "unreachable":
    print("ssh: connect to host control port 22: No route to host", file=sys.stderr)
    sys.exit(255)
elif mode == "die":
    print(json.dumps(claim), flush=True)
    time.sleep(0.5)
    sys.exit(255)
elif mode == "expire":
    print(json.dumps(claim), flush=True)
    time.sleep(0.5)
    print(json.dumps({"status": "released", "lease_id": "f" * 32, "device": "TESTHANDHELD", "reason": "expired"}), flush=True)
elif mode == "extra":
    claim["env"].update({"LD_PRELOAD": "/tmp/evil.so", "PATH": "/nowhere", "SWITCHYARD_SSH_PORT": 22})
    print(json.dumps(claim), flush=True)
    sys.stdin.read()
    print(json.dumps({"status": "released", "lease_id": "f" * 32, "device": "TESTHANDHELD", "reason": "released"}), flush=True)
elif mode == "record":
    # Logs every input line; on `done`, whether the command (pid in FAKE_PID_FILE) is already reaped.
    print(json.dumps(claim), flush=True)
    with open(os.environ["FAKE_DONE_LOG"], "a") as log:
        for line in sys.stdin:
            entry = {"line": line.strip()}
            if line.strip() == "done":
                pid = open(os.environ["FAKE_PID_FILE"]).read().strip()
                entry["command_reaped"] = not os.path.exists(f"/proc/{pid}")
            log.write(json.dumps(entry) + "\n")
            log.flush()
            if line.strip() == "done":
                break
    print(json.dumps({"status": "released", "lease_id": "f" * 32, "device": "TESTHANDHELD", "reason": "released"}), flush=True)
'''


def process_running(pid):
    """False once the process is gone or a zombie (exited, awaiting its new parent's reap)."""
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


def load_client():
    loader = importlib.machinery.SourceFileLoader("switchyard_remote", str(CLIENT))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


class RemoteClientTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        ssh = bin_dir / "ssh"
        ssh.write_text(f"#!{sys.executable}\n{FAKE_SSH}")
        ssh.chmod(0o755)
        (self.root / "ledgers").mkdir()
        self.ledger = self.root / "ledgers/DEVICE_ACCESS_TESTHANDHELD.md"
        self.ledger.write_text("baseline\n")
        self.log = self.root / "ssh.log"
        self.config = self.root / "remote.json"
        self.config.write_text(json.dumps({"control": "tester@control.invalid", "switchyard": "/opt/sy/switchyard",
                                           "mcp": "/opt/sy/switchyard-mcp-remote", "host_id": "host-b"}))
        self.environment = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "FAKE_SSH_LOG": str(self.log),
                            "FAKE_LEDGER": str(self.ledger), "FAKE_STATE": str(self.root / "state"),
                            "SWITCHYARD_REMOTE_CONFIG": str(self.config), "PASEO_AGENT_ID": "test-agent-b-0001"}
        patcher = patch.dict(os.environ, self.environment)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = load_client()

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def remote(self, index=-1):
        import shlex
        return shlex.split(self.calls()[index][-1])

    def events(self):
        return [json.loads(line) for line in self.ledger.read_text().splitlines() if line.startswith("{")]

    def spawn(self, *argv, **kwargs):
        return subprocess.Popen([sys.executable, str(CLIENT), *argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env={**os.environ}, **kwargs)

    def test_run_exports_only_lease_hints_propagates_exit_and_releases(self):
        output = self.root / "env.json"
        source = "import json,os,sys; json.dump(dict(os.environ), open(sys.argv[1], 'w')); sys.exit(7)"
        with patch.dict(os.environ, {"SWITCHYARD_SSH_TARGET": "stale", "DEVICE_LOCK_FD": "9"}):
            code = self.client.main(["lease", "run", "test-handheld", "--scope", "remote smoke", "--wait", "5", "--",
                                     sys.executable, "-c", source, str(output)])
        self.assertEqual(code, 7)
        environment = json.loads(output.read_text())
        self.assertEqual(environment["ANDROID_SERIAL"], "fake-serial")
        self.assertEqual(environment["SWITCHYARD_DEVICE"], "TESTHANDHELD")
        self.assertNotIn("SWITCHYARD_SSH_TARGET", environment)
        self.assertNotIn("DEVICE_LOCK_FD", environment)
        events = self.events()
        self.assertEqual([(event["event"], event.get("reason")) for event in events], [("CLAIM", None), ("RELEASE", "released")])
        self.assertEqual(events[0]["lease_id"], environment["SWITCHYARD_LEASE_ID"])
        self.assertEqual(events[0]["owner"], "paseo:test-age@host-b")
        self.assertEqual(events[0]["worktree"], f"host-b:{os.getcwd()}")
        ssh_argv = self.calls()[0]
        self.assertIn("BatchMode=yes", ssh_argv)
        self.assertIn("ServerAliveInterval=15", ssh_argv)
        self.assertEqual(ssh_argv[-2], "tester@control.invalid")
        remote = self.remote()
        self.assertEqual(remote[:4], ["/opt/sy/switchyard", "lease", "attach", "test-handheld"])
        for flag, value in (("--scope", "remote smoke"), ("--origin-host", "host-b"), ("--agent-id", "test-agent-b-0001"), ("--wait", "5")):
            self.assertEqual(remote[remote.index(flag) + 1], value)

    def test_claim_env_is_filtered_to_the_lease_variables(self):
        os.environ["FAKE_SSH_MODE"] = "extra"
        output = self.root / "env.json"
        source = "import json,os,sys; json.dump(dict(os.environ), open(sys.argv[1], 'w'))"
        self.assertEqual(self.client.main(["lease", "run", "test-handheld", "--scope", "s", "--", sys.executable, "-c", source, str(output)]), 0)
        environment = json.loads(output.read_text())
        self.assertNotIn("LD_PRELOAD", environment)
        self.assertEqual(environment["PATH"], os.environ["PATH"])
        self.assertNotIn("SWITCHYARD_SSH_PORT", environment)  # Not a string: ignored.
        self.assertEqual(environment["SWITCHYARD_LEASE_ID"], "f" * 32)

    def test_busy_exits_75_passes_holder_message_and_never_runs_command(self):
        os.environ["FAKE_SSH_MODE"] = "busy"
        marker = self.root / "ran"
        child = self.spawn("lease", "run", "test-handheld", "--scope", "s", "--", "touch", str(marker))
        stdout, stderr = child.communicate(timeout=20)
        self.assertEqual(child.returncode, 75)
        self.assertIn("TESTHANDHELD busy: FixtureAgent", stderr)
        self.assertFalse(marker.exists())

    def test_busy_real_server_and_unreachable_control_host(self):
        script = "import fcntl,sys; f=open(sys.argv[1], 'a'); fcntl.flock(f, fcntl.LOCK_EX); print('locked', flush=True); sys.stdin.read()"
        holder = subprocess.Popen([sys.executable, "-c", script, str(self.ledger)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(holder.stdout.readline().strip(), "locked")
            child = self.spawn("lease", "run", "test-handheld", "--scope", "s", "--", "true")
            _, stderr = child.communicate(timeout=20)
            self.assertEqual(child.returncode, 75, stderr)
            self.assertIn("TESTHANDHELD busy", stderr)
        finally:
            holder.communicate(input="", timeout=5)
        self.assertEqual(self.events(), [])
        os.environ["FAKE_SSH_MODE"] = "unreachable"
        child = self.spawn("lease", "run", "test-handheld", "--scope", "s", "--", "true")
        _, stderr = child.communicate(timeout=20)
        self.assertEqual(child.returncode, 255)
        self.assertIn("cannot reach the control host", stderr)

    def test_connection_death_mid_command_terminates_it_and_exits_76(self):
        for mode in ("die", "expire"):
            with self.subTest(mode=mode):
                os.environ["FAKE_SSH_MODE"] = mode
                started, terminated = self.root / f"{mode}-started", self.root / f"{mode}-terminated"
                source = ("import pathlib,signal,sys,time\n"
                          "def stop(*_):\n    pathlib.Path(sys.argv[2]).touch(); sys.exit(0)\n"
                          "signal.signal(signal.SIGTERM, stop); pathlib.Path(sys.argv[1]).touch(); time.sleep(30)")
                began = time.monotonic()
                with redirect_stderr(io.StringIO()) as stderr:
                    code = self.client.main(["lease", "run", "test-handheld", "--scope", "s", "--",
                                             sys.executable, "-c", source, str(started), str(terminated)])
                self.assertEqual(code, 76)
                self.assertLess(time.monotonic() - began, 10)
                self.assertTrue(started.exists())
                self.assertTrue(terminated.exists())
                self.assertIn("LEASE LOST on TESTHANDHELD", stderr.getvalue())
                releases = [call for call in self.calls() if call[-1].endswith("lease release " + "f" * 32)]
                if mode == "die":
                    # Lost connection: command reaped first, then an explicit release over a new connection.
                    self.assertEqual(len(releases), 1)
                    self.assertIn("ConnectTimeout=10", releases[0])
                    self.assertIn("released explicitly", stderr.getvalue())
                else:
                    self.assertEqual(releases, [])  # The control host already ended the lease.
                self.log.unlink()

    def test_lost_lease_kills_a_command_that_ignores_sigterm(self):
        os.environ["FAKE_SSH_MODE"] = "die"
        self.client.KILL_GRACE = 0.5
        pid_file = self.root / "pid"
        source = "import os,signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(60)"
        with redirect_stderr(io.StringIO()):
            self.assertEqual(self.client.main(["lease", "run", "test-handheld", "--scope", "s", "--", sys.executable, "-c", source, str(pid_file)]), 76)
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)

    def test_lost_lease_kills_descendants_that_outlive_the_group_leader(self):
        # Leader (sh) exits on SIGTERM; its child ignores SIGTERM and stays in the process group.
        os.environ["FAKE_SSH_MODE"] = "die"
        self.client.KILL_GRACE = 0.5
        pid_file = self.root / "descendant"
        source = "import os,signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(60)"
        script = f"{shlex.quote(sys.executable)} -c {shlex.quote(source)} {shlex.quote(str(pid_file))} & wait"
        with redirect_stderr(io.StringIO()):
            self.assertEqual(self.client.main(["lease", "run", "test-handheld", "--scope", "s", "--", "sh", "-c", script]), 76)
        pid = int(pid_file.read_text())
        deadline = time.monotonic() + 5
        while process_running(pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(process_running(pid))

    def test_unreachable_after_loss_leaves_the_lease_suspect_after_bounded_attempts(self):
        os.environ.update(FAKE_SSH_MODE="die", FAKE_SSH_EXIT="255")
        self.client.RELEASE_RETRY_WINDOW, self.client.RELEASE_RETRY_PAUSE = 1.0, 0.2
        with redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(self.client.main(["lease", "run", "test-handheld", "--scope", "s", "--", "sleep", "30"]), 76)
        attempts = [call for call in self.calls() if call[-1].endswith("lease release " + "f" * 32)]
        self.assertGreaterEqual(len(attempts), 2)
        self.assertLessEqual(len(attempts), 6)
        self.assertIn("left SUSPECT", stderr.getvalue())

    def test_heartbeats_then_done_only_after_the_command_is_reaped(self):
        os.environ.update(FAKE_SSH_MODE="record", FAKE_DONE_LOG=str(self.root / "done.log"),
                          FAKE_PID_FILE=str(self.root / "pid"))
        self.client.HEARTBEAT_INTERVAL = 0.2
        source = "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(1.2); sys.exit(3)"
        self.assertEqual(self.client.main(["lease", "run", "test-handheld", "--scope", "s", "--", sys.executable, "-c", source,
                                           os.environ["FAKE_PID_FILE"]]), 3)
        entries = [json.loads(line) for line in (self.root / "done.log").read_text().splitlines()]
        self.assertGreaterEqual(sum(entry["line"] == "" for entry in entries), 3)
        self.assertEqual(entries[-1], {"line": "done", "command_reaped": True})
        self.assertEqual(self.remote()[self.remote().index("--heartbeat") + 1], "60")

    def test_command_dies_with_a_killed_client(self):
        os.environ["FAKE_SSH_MODE"] = "extra"
        pid_file = self.root / "pid"
        source = "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(60)"
        client = self.spawn("lease", "run", "test-handheld", "--scope", "s", "--", sys.executable, "-c", source, str(pid_file))
        deadline = time.monotonic() + 20
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        time.sleep(0.1)
        pid = int(pid_file.read_text())
        client.kill()  # SIGKILL: no handler runs, only PR_SET_PDEATHSIG can stop the command.
        client.communicate(timeout=10)
        deadline = time.monotonic() + 5
        while process_running(pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(process_running(pid))

    def test_sigterm_is_forwarded_to_the_command_and_the_lease_released(self):
        ready = self.root / "ready"
        source = ("import pathlib,signal,sys,time; signal.signal(signal.SIGTERM, lambda *_: sys.exit(23)); "
                  "pathlib.Path(sys.argv[1]).touch(); time.sleep(30)")
        child = self.spawn("lease", "run", "test-handheld", "--scope", "s", "--", sys.executable, "-c", source, str(ready))
        deadline = time.monotonic() + 20
        while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(ready.exists(), child.stderr.read() if child.poll() is not None else "not ready")
        child.send_signal(signal.SIGTERM)
        _, stderr = child.communicate(timeout=20)
        self.assertEqual(child.returncode, 23, stderr)
        self.assertEqual([(event["event"], event.get("reason")) for event in self.events()], [("CLAIM", None), ("RELEASE", "released")])

    def test_passthrough_preserves_exit_code_stdout_and_adds_detached_attribution(self):
        os.environ["FAKE_SSH_EXIT"] = "1"
        child = self.spawn("lease", "status", "test-handheld")
        stdout, _ = child.communicate(timeout=20)
        self.assertEqual((child.returncode, stdout), (1, "remote-ok lease status test-handheld\n"))
        os.environ["FAKE_SSH_EXIT"] = "0"
        with redirect_stdout(io.StringIO()):
            self.assertEqual(self.client.main(["lease", "hold", "test-handheld", "--scope", "multi step; $(touch /tmp/x)", "--ttl", "30m"]), 0)
        remote = self.remote()
        self.assertEqual(remote[:4], ["/opt/sy/switchyard", "lease", "hold", "test-handheld"])
        self.assertEqual(remote[remote.index("--scope") + 1], "multi step; $(touch /tmp/x)")
        for flag in ("--detached", "--origin-host", "--agent-id", "--origin-user", "--worktree"):
            self.assertIn(flag, remote)
        self.assertEqual(remote[remote.index("--ttl") + 1], "30m")
        cases = ((["lease", "release", "abc"], ["lease", "release", "abc"]),
                 (["lease", "renew", "abc", "--ttl", "10m"], ["lease", "renew", "abc", "--ttl", "10m"]),
                 (["lease", "list", "--json"], ["lease", "list", "--json"]),
                 (["hosts"], ["hosts"]), (["fleet"], ["fleet"]), (["definitions"], ["definitions"]),
                 (["operations", "--id", "op-1"], ["operations", "--id", "op-1"]))
        for argv, expected in cases:
            with self.subTest(argv=argv), redirect_stdout(io.StringIO()):
                self.assertEqual(self.client.main(argv), 0)
                self.assertEqual(self.remote()[1:], expected)

    def test_refused_commands_never_contact_the_control_host(self):
        for argv in (["shell", "host-b"], ["execute-operation", "plan", "--approve"], ["host-update", "x"],
                     ["--catalog", "x", "hosts"], ["web"], ["lease", "attach", "test-handheld", "--scope", "s"],
                     ["lease", "_holder", "abc"], ["lease", "run", "test-handheld", "--scope", "s", "--pass-lock-fd", "--", "true"],
                     ["lease", "run", "test-handheld", "--scope", "s"], ["mcp", "--operations", "x"]):
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(self.client.main(argv), 2)
                self.assertIn("switchyard:", stderr.getvalue())
        for argv in (["hosts", "--state-dir", "/tmp"], ["lease", "hold", "test-handheld"]):
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                self.client.main(argv)
            self.assertEqual(error.exception.code, 2)
        self.assertEqual(self.calls(), [])

    def test_missing_configuration_is_explained(self):
        os.environ["SWITCHYARD_REMOTE_CONFIG"] = str(self.root / "absent.json")
        with redirect_stderr(io.StringIO()) as stderr, self.assertRaises(SystemExit) as error:
            self.client.main(["hosts"])
        self.assertEqual(error.exception.code, 2)
        self.assertIn("install-remote-client.sh", stderr.getvalue())

    def test_mcp_execs_ssh_with_stdio_passthrough(self):
        child = self.spawn("mcp", stdin=subprocess.PIPE)
        stdout, _ = child.communicate(input='{"jsonrpc":"2.0"}', timeout=20)
        self.assertEqual((child.returncode, stdout), (0, 'mcp:{"jsonrpc":"2.0"}'))
        self.assertEqual(self.remote(), ["/opt/sy/switchyard-mcp-remote", "--origin-host", "host-b",
                                         "--agent-id", "test-agent-b-0001", "--origin-user", getpass.getuser()])
        self.assertIn("BatchMode=yes", self.calls()[-1])


class RemoteMCPTests(unittest.TestCase):
    """switchyard-mcp --remote: reads and leases only; holds detached and attributed to the origin host."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.catalog = root / "catalog.json"
        self.catalog.write_text((CLIENT.parents[1] / "catalogs/example.json").read_text())
        self.state = root / "state"

    def test_remote_mode_tool_set_and_attributed_detached_hold(self):
        import anyio
        from unittest.mock import MagicMock
        from switchyard.mcp_server import REMOTE_TOOLS, create_mcp
        server = create_mcp(self.catalog, state_dir=self.state, origin_host="source", agent_id="test-agent-b-0001",
                            origin_user="tester")
        manager = MagicMock()
        manager.hold.return_value = {"lease_id": "fixture"}

        async def exercise():
            names = {tool.name for tool in await server.list_tools()}
            self.assertEqual(names, set(REMOTE_TOOLS))
            for forbidden in ("shell", "execute_operation", "collect_host", "update_host_description",
                              "save_workload_definition", "plan_operation", "inspect_workload", "observe_local"):
                self.assertNotIn(forbidden, names)
            await server.call_tool("lease_hold", {"device": "TESTHANDHELD", "scope": "remote fixture", "ttl_minutes": 5})
            with self.assertRaises(Exception):
                await server.call_tool("shell", {"host_id": "source", "script": "true", "request_id": "x"})
        with patch.object(server._service, "agent_leases", return_value=manager):
            anyio.run(exercise)
        manager.hold.assert_called_once_with("TESTHANDHELD", scope="remote fixture", ttl=300, owner=None, detached=True,
                                             worktree="source:mcp", origin_host="source",
                                             agent_id="test-agent-b-0001", origin_user="tester")

    def test_remote_mode_validates_origin_and_main_requires_it(self):
        from switchyard import mcp_server
        for kwargs, message in (({"origin_host": "elsewhere"}, "registry host"),
                                ({"origin_host": "source", "agent_id": "bad id!"}, "Paseo agent ID"),
                                ({"agent_id": "test-agent-b-0001"}, "require remote mode")):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ValueError, message):
                mcp_server.create_mcp(self.catalog, state_dir=self.state, **kwargs)
        with patch.object(sys, "argv", ["switchyard-mcp", "--catalog", str(self.catalog), "--remote"]), \
                redirect_stderr(io.StringIO()) as stderr, self.assertRaises(SystemExit) as error:
            mcp_server.main()
        self.assertEqual(error.exception.code, 2)
        self.assertIn("--remote requires --origin-host", stderr.getvalue())


class RemoteInstallerTests(unittest.TestCase):
    """tools/install-remote-client.sh --render, then the rendered program in a temporary remote HOME."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name).resolve()
        control, self.home = root / "control", root / "remote"
        (control / ".omp/agent").mkdir(parents=True)
        (control / ".omp/agent/mcp.json").write_text(json.dumps({"mcpServers": {"tool": {"type": "stdio", "command": "/bin/tool"}}}))
        rendered = subprocess.run(["sh", str(CLIENT.parent / "install-remote-client.sh"), "--render", "host-b"],
                                  env={**os.environ, "HOME": str(control), "SWITCHYARD_CONTROL_TARGET": "tester@control.invalid"},
                                  capture_output=True, text=True, check=True)
        self.program = root / "program.py"
        self.program.write_text(rendered.stdout)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        (bin_dir / "ssh").write_text(f"#!{sys.executable}\n{FAKE_SSH}")
        (bin_dir / "ssh").chmod(0o755)
        self.environment = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "HOME": str(self.home),
                            "FAKE_SSH_LOG": str(root / "ssh.log")}
        (self.home / ".omp/agent").mkdir(parents=True)
        (self.home / ".claude").mkdir()
        (self.home / ".local/bin").mkdir(parents=True)
        (self.home / ".local/bin/switchyard").write_text("#!/bin/sh\necho foreign\n")
        (self.home / ".omp/agent/RULES.md").write_text("# Mine\n\nkeep this\n")
        (self.home / ".omp/agent/mcp.json").write_text(json.dumps({"mcpServers": {"other": {"type": "stdio", "command": "/bin/other"}}}))

    def install(self, **environment):
        result = subprocess.run([sys.executable, str(self.program)], env={**self.environment, **environment},
                                capture_output=True, text=True, timeout=60)
        return result.returncode, json.loads(result.stdout)

    def backups(self):
        return sorted(path.name for path in self.home.rglob("*.bak-*"))

    def test_install_is_idempotent_marked_and_backs_up_changed_files(self):
        code, report = self.install()
        self.assertEqual(code, 0, report)
        self.assertEqual(report["control_ssh"], "ok")
        client = self.home / ".local/bin/switchyard"
        self.assertEqual(client.read_text(), CLIENT.read_text())
        self.assertEqual(client.stat().st_mode & 0o777, 0o755)
        config = self.home / ".config/switchyard/remote.json"
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(config.read_text())["host_id"], "host-b")
        self.assertEqual(json.loads(config.read_text())["control"], "tester@control.invalid")
        skill = (self.home / ".omp/agent/managed-skills/switchyard-device-lease/SKILL.md").read_text()
        self.assertTrue(skill.startswith("---\nname: switchyard-device-lease\n"))
        self.assertIn("76", skill)
        rules = (self.home / ".omp/agent/RULES.md").read_text()
        self.assertTrue(rules.startswith("# Mine\n\nkeep this\n"))
        self.assertEqual(rules.count("BEGIN switchyard-remote-device-locks"), 1)
        self.assertIn("from host-b with another Switchyard registry host", rules)
        self.assertIn("BEGIN switchyard-remote-device-locks", (self.home / ".claude/CLAUDE.md").read_text())
        servers = json.loads((self.home / ".omp/agent/mcp.json").read_text())["mcpServers"]
        self.assertEqual(servers["other"]["command"], "/bin/other")
        self.assertEqual(servers["switchyard"], {"type": "stdio", "command": str(client), "args": ["mcp"]})
        backups = self.backups()
        self.assertEqual(sorted(name.split(".bak-")[0] for name in backups), ["RULES.md", "mcp.json", "switchyard"])
        # Second run: nothing changes, no new backups; an edited managed block is restored in place.
        code, report = self.install()
        self.assertEqual(code, 0)
        self.assertEqual(set(report["files"].values()), {"unchanged"})
        self.assertEqual(self.backups(), backups)
        rules_path = self.home / ".omp/agent/RULES.md"
        rules_path.write_text(rules.replace("TTL-only", "edited") + "\n## After\n")
        self.install()
        self.assertEqual(rules_path.read_text(), rules + "\n## After\n")

    def test_unreachable_control_host_is_reported_with_exit_3(self):
        for stderr, status in (("Permission denied (publickey).", "key not authorized"),
                               ("Host key verification failed.", "missing known_hosts entry")):
            with self.subTest(status=status):
                code, report = self.install(FAKE_SSH_EXIT="255", FAKE_SSH_STDERR=stderr)
                self.assertEqual(code, 3)
                self.assertEqual(report["control_ssh"], status)
                self.assertTrue(report["problems"])
                # Files are still installed; the guidance tells agents to stop when switchyard fails.
                self.assertTrue((self.home / ".local/bin/switchyard").exists())


if __name__ == "__main__":
    unittest.main()
