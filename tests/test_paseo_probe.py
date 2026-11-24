"""Paseo metadata-only HTTP/CLI fixtures; no daemon or fleet access."""
from contextlib import ExitStack
import copy
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
import urllib.error

from pydantic import ValidationError
from switchyard import collector, probe
from switchyard.models import Paseo


PASEO = {"listen": "127.0.0.1:6767", "cli": "/opt/node/bin/paseo"}
STATUS = {"status": "server_info", "serverId": "server-1", "hostname": "fixture", "version": "0.10.3", "listen": "127.0.0.1:6767", "secret": "discard"}
CLI_STATUS = {"home": "/secret", "logPath": "/secret/log", "daemonNode": "/node", "daemonVersion": "ignored",
              "startedAt": "2026-11-22T00:00:00Z", "providers": [{"provider": "codex", "available": True, "error": "secret"}],
              "relay": {"enabled": True, "endpoint": "https://secret", "token": "secret"}}
AGENT = {"id": "agent-1", "shortId": "a1", "name": "Fixture", "provider": "codex", "status": "running", "cwd": "/work",
         "created": "2026-11-22T00:00:00Z", "thinking": "secret", "messages": ["secret"], "prompt": "secret"}


def config():
    return {"host_id": "fixture", "transport": "local", "expected_hostname": "fixture", "user_units": [], "system_units": [], "paseo": PASEO}


def snapshot():
    return {"schema_version": 1, "host_id": "fixture", "observed_at": "2026-11-22T00:00:00Z", "collector": "linux-v1",
            "host": {"hostname": "fixture", "os": "Linux", "distribution": None, "architecture": "x86_64"},
            "cpu": {"model": None, "logical_count": None, "utilization_percent": None, "sample_seconds": None, "load_1m": None},
            "memory": dict.fromkeys(("total_bytes", "available_bytes", "swap_total_bytes", "swap_free_bytes")),
            "gpus": [], "storage": {"devices": [], "filesystems": []}, "workloads": [], "warnings": [],
            "coverage": [{"scope": scope, "status": "complete", "message": "fixture"} for scope in
                         ("cpu", "memory", "gpus", "storage", "systemd:user:1000", "systemd:system")]}


class PaseoTests(unittest.TestCase):
    def read(self, cfg=PASEO, commands=None):
        with patch.object(probe, "paseo_http", side_effect=[STATUS, {"status": "ok"}]), \
             patch.object(probe, "paseo_command", side_effect=commands or [CLI_STATUS, [AGENT]]) as command:
            result, coverage = probe.observe_paseo(cfg)
        return result, coverage, command

    def test_only_loopback_listen_and_absolute_optional_cli(self):
        for listen in ("192.168.50.69:6767", "example.test:6767", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:65536",
                       "user@127.0.0.1:6767", "127.0.0.1:6767/path", "127.0.0.1:6767?token=x", "127.0.0.1:6767\n"):
            with self.subTest(listen=listen), self.assertRaises(ValueError):
                collector._validate_config({**config(), "paseo": {"listen": listen, "cli": None}})
        for listen in ("127.0.0.1:6767", "localhost:6767", "[::1]:6767"):
            self.assertEqual(probe.validate_paseo({"listen": listen, "cli": None})["listen"], listen)
        with self.assertRaises(ValueError):
            probe.validate_paseo({"listen": "127.0.0.1:6767", "cli": "paseo"})

    def test_metadata_allowlist_and_fixed_cli_subcommands(self):
        value, coverage, command = self.read(commands=[CLI_STATUS, [AGENT, {**AGENT, "id": "old", "status": "archived"}]])
        self.assertEqual(coverage["status"], "complete")
        self.assertEqual([call.args[1] for call in command.call_args_list], ["status", "ls"])
        self.assertEqual(len(value["agents"]), 1)
        self.assertEqual(value["daemon"]["providers"], [{"provider": "codex", "available": True}])
        self.assertEqual(value["daemon"]["version"], "0.10.3")
        self.assertNotIn("secret", json.dumps(value))
        self.assertNotIn("thinking", json.dumps(value))
        self.assertEqual(Paseo.model_validate(value, strict=True).model_dump(), value)

    def test_http_only_is_partial_and_never_runs_cli(self):
        value, coverage, command = self.read({**PASEO, "cli": None})
        command.assert_not_called()
        self.assertEqual(coverage["status"], "partial")
        self.assertIsNone(value["agents"])
        self.assertEqual(value["daemon"]["providers"], [])
        self.assertIsNone(value["daemon"]["started_at"])
        self.assertIsNone(value["daemon"]["relay_enabled"])

    def test_refused_is_stopped_other_failures_are_unknown(self):
        for error, state in ((urllib.error.URLError(ConnectionRefusedError(errno.ECONNREFUSED, "refused")), "stopped"),
                             (TimeoutError("secret"), "unknown"), (ValueError("secret"), "unknown")):
            with self.subTest(state=state), patch.object(probe, "paseo_http", side_effect=error), \
                 patch.object(probe, "paseo_command", side_effect=AssertionError("No CLI without HTTP")):
                value, coverage = probe.observe_paseo(PASEO)
            self.assertEqual(value["daemon"]["state"], state)
            self.assertEqual(coverage["status"], "unavailable")
            self.assertNotIn("secret", json.dumps([value, coverage]))

    def test_cli_failures_preserve_daemon_and_other_cli_scope(self):
        for commands in ([TimeoutError("secret"), [AGENT]], [CLI_STATUS, subprocess.TimeoutExpired("secret", 4)]):
            value, coverage, _ = self.read(commands=commands)
            self.assertEqual(value["daemon"]["state"], "running")
            self.assertEqual(coverage["status"], "partial")
            self.assertNotIn("secret", json.dumps(value))

    def test_agent_limits_and_control_characters(self):
        agents = [{**AGENT, "id": str(i)} for i in range(140)]
        value, coverage, _ = self.read(commands=[CLI_STATUS, agents])
        self.assertEqual(len(value["agents"]), 128)
        self.assertEqual(coverage["status"], "partial")
        for change in ({"name": "x" * 257}, {"cwd": "/" + "x" * 1024}, {"name": "hidden\ntext"}, {"status": "x\u0085y"}):
            value, coverage, _ = self.read(commands=[CLI_STATUS, [{**AGENT, **change}]])
            self.assertEqual(value["agents"], [])
            self.assertEqual(coverage["status"], "partial")
        large = [{**AGENT, "id": str(i), "cwd": "/" + "x" * 1023} for i in range(128)]
        value, coverage, _ = self.read(commands=[CLI_STATUS, large])
        self.assertLessEqual(len(json.dumps(value["agents"]).encode()), 65536)
        self.assertEqual(coverage["status"], "partial")

    def test_strict_snapshot_rejects_extra_secret_fields_and_bad_daemon_workload(self):
        value, coverage, _ = self.read()
        base = snapshot()
        base["paseo"] = value
        base["coverage"].append(coverage)
        base["workloads"].append(probe.paseo_workload("fixture", "user:1000", value["daemon"], base["observed_at"]))
        self.assertEqual(collector._validate_snapshot(json.dumps(base), config())["paseo"], value)
        for mutate in (lambda s: s["paseo"]["daemon"].update(token="secret"),
                       lambda s: s["paseo"]["agents"][0].update(name="x\nsecret"),
                       lambda s: s["workloads"][0].update(native_id="different"),
                       lambda s: s["workloads"].clear()):
            bad = copy.deepcopy(base)
            mutate(bad)
            with self.assertRaises(collector.CollectionError):
                collector._validate_snapshot(json.dumps(bad), config())
        with self.assertRaises(collector.CollectionError):
            collector._validate_snapshot(json.dumps(base), {k: v for k, v in config().items() if k != "paseo"})
        with self.assertRaises(ValidationError):
            Paseo.model_validate({**value, "agents": [value["agents"][0]] * 129})

    def test_discovery_only_in_full_lane_and_failures_keep_other_scopes(self):
        with ExitStack() as stack:
            for attr, result in (("system", "Linux"), ("node", "fixture"), ("machine", "x86_64")):
                stack.enter_context(patch.object(probe.platform, attr, return_value=result))
            stack.enter_context(patch.object(probe.os, "geteuid", return_value=1000))
            stack.enter_context(patch.object(probe.os, "getuid", return_value=1000))
            stack.enter_context(patch.object(probe, "text", side_effect=OSError))
            for reader in ("cpu", "cpu_fast", "memory", "gpus"):
                stack.enter_context(patch.object(probe, reader, side_effect=OSError))
            stack.enter_context(patch.object(probe, "storage", return_value=({"devices": [], "filesystems": []}, False)))
            stack.enter_context(patch.object(probe.container_probe, "observe_containers", return_value=([], [], [])))
            with patch.object(probe, "observe_paseo", side_effect=AssertionError("Not opted into full Paseo")), \
                 patch.object(probe, "discover_paseo", return_value=(
                     {"configured": False, "daemon": None, "agents": None, "cli_candidates": []},
                     {"scope": "paseo", "status": "complete", "message": "No Paseo daemon on the default port"})) as discover:
                for mode in ("fast", "storage"):
                    self.assertNotIn("paseo", probe.observe({**config(), "mode": mode}))
                discover.assert_not_called()
                value = probe.observe({k: v for k, v in config().items() if k != "paseo"})
                self.assertFalse(value["paseo"]["configured"])
                discover.assert_called_once()
            with patch.object(probe, "paseo_http", side_effect=TimeoutError):
                value = probe.observe(config())
            scopes = {c["scope"]: c["status"] for c in value["coverage"]}
            self.assertEqual(scopes["storage"], "complete")
            self.assertEqual(scopes["paseo"], "unavailable")
            collector._validate_snapshot(json.dumps(value), config())

    def test_http_disables_proxies_redirects_and_bounds_output(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read1.side_effect = [json.dumps(STATUS).encode(), b""]
        opener = Mock()
        opener.open.return_value = response
        with patch.object(probe.urllib.request, "build_opener", return_value=opener) as build:
            self.assertEqual(probe.paseo_http(PASEO["listen"], "/api/status", time.monotonic() + 3), STATUS)
            self.assertEqual(build.call_args.args[0].proxies, {})
            self.assertIsNone(build.call_args.args[1].redirect_request(None, None, 302, "", {}, "http://remote/"))
            self.assertLessEqual(opener.open.call_args.kwargs["timeout"], 3)
            response.read1.side_effect = [b"x" * 8192] * 9
            with self.assertRaisesRegex(ValueError, "output limit"):
                probe.paseo_http(PASEO["listen"], "/api/status", time.monotonic() + 3)

    def test_cli_environment_fixed_arguments_bounds_and_kills_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cli = root / "paseo"
            pidfile = root / "pid"
            cli.write_text("#!" + sys.executable + "\nimport json, os, sys\nprint(json.dumps({'args':sys.argv[1:],'path':os.environ['PATH'],'home':os.environ.get('HOME')}))\n")
            cli.chmod(0o700)
            value = probe.paseo_command(str(cli), "status", time.monotonic() + 3)
            self.assertEqual(value["args"], ["status", "--json"])
            self.assertEqual(value["path"], directory + ":/usr/bin:/bin")
            self.assertEqual(value["home"], os.environ.get("HOME"))
            with self.assertRaises(ValueError):
                probe.paseo_command(str(cli), "logs", time.monotonic() + 3)
            cli.write_text("#!" + sys.executable + "\nimport os, time\nopen(" + repr(str(pidfile)) + ",'w').write(str(os.getpid()))\ntime.sleep(30)\n")
            with self.assertRaisesRegex(ValueError, "deadline"):
                probe.paseo_command(str(cli), "ls", time.monotonic() + 0.3)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pidfile.read_text()), 0)
            cli.write_text("#!" + sys.executable + "\nprint('x'*262145)\n")
            with self.assertRaisesRegex(ValueError, "output limit"):
                probe.paseo_command(str(cli), "ls", time.monotonic() + 3)
