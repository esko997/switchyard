"""Unconfigured Paseo discovery never executes an installed CLI."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from pydantic import ValidationError
from switchyard import collector, probe
from switchyard.models import Paseo
from tests.test_paseo_probe import AGENT, CLI_STATUS, PASEO, STATUS, config, snapshot


class PaseoDiscoveryTests(unittest.TestCase):
    def test_found_unconfigured_has_only_http_metadata_and_never_executes_cli(self):
        with patch.object(probe, "paseo_http", return_value=STATUS) as http, \
             patch.object(probe, "paseo_cli_candidates", return_value=["/home/fixture/.local/bin/paseo"]), \
             patch.object(probe.subprocess, "Popen", side_effect=AssertionError("Discovery cannot execute")):
            deadline = time.monotonic() + 30
            value, coverage = probe.discover_paseo(deadline=deadline)
        self.assertFalse(value["configured"])
        self.assertEqual(value["cli_candidates"], ["/home/fixture/.local/bin/paseo"])
        self.assertIsNone(value["agents"])
        self.assertEqual(value["daemon"]["state"], "running")
        self.assertEqual(value["daemon"]["providers"], [])
        self.assertIsNone(value["daemon"]["started_at"])
        self.assertIsNone(value["daemon"]["relay_enabled"])
        self.assertEqual(coverage["status"], "partial")
        self.assertEqual(http.call_args.args[:2], ("127.0.0.1:6767", "/api/status"))
        self.assertLessEqual(http.call_args.args[2], time.monotonic() + 2)
        self.assertNotIn("secret", json.dumps(value))
        self.assertEqual(Paseo.model_validate(value, strict=True).model_dump(), value)
        base = snapshot()
        base["paseo"] = value
        base["coverage"].append(coverage)
        base["workloads"].append(probe.paseo_workload("fixture", "user:1000", value["daemon"], base["observed_at"]))
        self.assertEqual(collector._validate_snapshot(json.dumps(base), {k: v for k, v in config().items() if k != "paseo"})["paseo"], value)

    def test_missing_or_invalid_daemon_is_complete_not_found(self):
        for failure in (ConnectionRefusedError(), TimeoutError(), {"status": "invalid"}):
            with self.subTest(failure=type(failure).__name__), \
                 patch.object(probe, "paseo_http", **({"side_effect": failure} if isinstance(failure, Exception)
                                                     else {"return_value": failure})), \
                 patch.object(probe, "paseo_cli_candidates", return_value=[]), \
                 patch.object(probe.subprocess, "Popen", side_effect=AssertionError("Discovery cannot execute")):
                value, coverage = probe.discover_paseo(deadline=time.monotonic() + 3)
            self.assertIsNone(value["daemon"])
            self.assertEqual(coverage["status"], "complete")
            self.assertEqual(coverage["message"], "No Paseo daemon on the default port")
            base = snapshot()
            base["paseo"] = value
            base["coverage"].append(coverage)
            self.assertEqual(collector._validate_snapshot(json.dumps(base), {k: v for k, v in config().items() if k != "paseo"})["paseo"], value)

    def test_candidate_paths_home_only_executable_and_at_most_eight_nvm_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            for index in range(12):
                path = home / f".nvm/versions/node/v{index}/bin/paseo"
                path.parent.mkdir(parents=True)
                path.write_text("not executed")
                path.chmod(0o755)
            local = home / ".local/bin/paseo"
            local.parent.mkdir(parents=True)
            local.write_text("not executed")
            local.chmod(0o755)
            original_is_file = Path.is_file
            with patch.dict(os.environ, {"HOME": str(home), "PATH": "/untrusted/path", "NVM_DIR": "/untrusted/nvm"}), \
                 patch.object(Path, "is_file", lambda path: path.is_relative_to(home) and original_is_file(path)), \
                 patch.object(probe.subprocess, "Popen", side_effect=AssertionError("No subprocess")):
                candidates = probe.paseo_cli_candidates(time.monotonic() + 3)
            self.assertEqual(len(candidates), 9)
            self.assertEqual(sum("/.nvm/" in path for path in candidates), 8)
            self.assertIn(str(local), candidates)
            self.assertTrue(all(Path(path).is_absolute() for path in candidates))
            local.chmod(0o644)
            with patch.dict(os.environ, {"HOME": str(home)}), \
                 patch.object(Path, "is_file", lambda path: path.is_relative_to(home) and original_is_file(path)):
                self.assertNotIn(str(local), probe.paseo_cli_candidates(time.monotonic() + 3))

    def test_exact_system_candidates_and_no_other_home_expansion(self):
        with patch.dict(os.environ, {"HOME": "~someone", "PATH": "/arbitrary"}), \
             patch.object(Path, "is_file", return_value=True) as exists, \
             patch.object(probe.os, "access", return_value=True):
            self.assertEqual(probe.paseo_cli_candidates(time.monotonic() + 3),
                             ["/usr/local/bin/paseo", "/usr/bin/paseo"])
        self.assertEqual(exists.call_count, 2)

    def test_probe_deadline_prevents_discovery_io(self):
        with patch.object(probe, "paseo_http", side_effect=AssertionError("Expired budget")), \
             patch.object(Path, "is_file", side_effect=AssertionError("Expired budget")):
            value, coverage = probe.discover_paseo(deadline=time.monotonic() - 1)
        self.assertIsNone(value["daemon"])
        self.assertEqual(coverage["status"], "unavailable")

    def test_configured_hosts_keep_supported_cli_behavior(self):
        with patch.object(probe, "paseo_http", side_effect=[STATUS, {"status": "ok"}]), \
             patch.object(probe, "paseo_command", side_effect=[CLI_STATUS, [AGENT]]) as command, \
             patch.object(probe, "paseo_cli_candidates", side_effect=AssertionError("Configured hosts not discovered")):
            value, coverage = probe.observe_paseo(PASEO)
        self.assertTrue(value["configured"])
        self.assertEqual(value["cli_candidates"], [])
        self.assertEqual(coverage["status"], "complete")
        self.assertEqual([call.args[1] for call in command.call_args_list], ["status", "ls"])
        self.assertEqual(len(value["agents"]), 1)

    def test_model_bounds_and_discovery_metadata_invariants(self):
        value = {"configured": False, "daemon": None, "agents": None, "cli_candidates": []}
        for change in ({"cli_candidates": ["/paseo"] * 12}, {"cli_candidates": ["relative/paseo"]},
                       {"agents": []}, {"configured": True}, {"configured": "false"}):
            with self.subTest(change=change), self.assertRaises(ValidationError):
                Paseo.model_validate({**value, **change}, strict=True)
