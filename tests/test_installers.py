"""The service and agent-CLI installers against a temporary HOME and a copied checkout; uv, systemctl and loginctl
are stand-ins on PATH, so nothing on this machine is installed, enabled or started."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FLEET = ("home-lab.json", "home-lab.collectors.json", "home-lab.operations.json")
STANDIN = """#!/bin/sh
echo "$(basename "$0") $*" >> "$STANDIN_LOG"
case "$*" in *"tls show"*) echo '{"initialized": true}' ;; esac
exit 0
"""


class InstallerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.project = self.root / "checkout"
        (self.project / "catalogs").mkdir(parents=True)
        shutil.copytree(ROOT / "tools", self.project / "tools", ignore=shutil.ignore_patterns("__pycache__"))
        self.home = self.root / "home"
        self.home.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("uv", "systemctl", "loginctl"):
            path = self.bin / name
            path.write_text(STANDIN)
            path.chmod(0o755)
        self.log = self.root / "standin.log"
        self.env = {"HOME": str(self.home), "PATH": f"{self.bin}:/usr/bin:/bin", "STANDIN_LOG": str(self.log),
                    "SWITCHYARD_UV": str(self.bin / "uv")}

    def run_tool(self, name, *args):
        return subprocess.run(["sh", str(self.project / "tools" / name), *args], env=self.env,
                              capture_output=True, text=True, timeout=60)

    def configure(self):
        for name in FLEET:
            (self.project / "catalogs" / name).write_text("{}")

    def test_missing_configuration_names_the_copies_and_installs_nothing(self):
        (self.project / "catalogs" / "home-lab.json").write_text("{}")
        for tool, args in (("install-services.sh", ["--lan-address", "192.0.2.5"]), ("install-agent-cli.sh", [])):
            with self.subTest(tool=tool):
                result = self.run_tool(tool, *args)
                self.assertEqual(result.returncode, 2)
                self.assertIn("Copy the examples and edit them", result.stderr)
                catalogs = self.project / "catalogs"
                self.assertIn(f"cp {catalogs}/collectors.example.json {catalogs}/home-lab.collectors.json", result.stderr)
                self.assertIn(f"cp {catalogs}/operations.example.json {catalogs}/home-lab.operations.json", result.stderr)
                self.assertNotIn("home-lab.json\n", result.stderr)
        self.assertFalse((self.home / ".config").exists())
        self.assertFalse((self.home / ".local").exists())
        self.assertFalse(self.log.exists())

    def test_services_use_the_fleet_files_and_reinstall_identically(self):
        self.configure()
        self.assertEqual(self.run_tool("install-services.sh").returncode, 2)  # no --lan-address
        first = self.run_tool("install-services.sh", "--lan-address", "192.168.50.5")
        self.assertEqual(first.returncode, 0, first.stderr)
        units = self.home / ".config/systemd/user"
        written = {path.name: path.read_text() for path in sorted(units.iterdir())}
        self.assertEqual(set(written), {"switchyard-desk.service", "switchyard-monitor.service",
                                        "switchyard-lan-view.service", "switchyard-lan.service"})
        catalogs = self.project / "catalogs"
        desk = written["switchyard-desk.service"]
        self.assertIn(f"--catalog {catalogs}/home-lab.json --collectors {catalogs}/home-lab.collectors.json "
                      f"--operations {catalogs}/home-lab.operations.json web", desk)
        self.assertIn("--host 192.168.50.5 --port 8711", written["switchyard-lan-view.service"])
        self.assertNotIn("example", "".join(written.values()))
        second = self.run_tool("install-services.sh", "--lan-address", "192.168.50.5")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual({path.name: path.read_text() for path in sorted(units.iterdir())}, written)
        self.assertIn("systemctl --user enable --now switchyard-desk.service", self.log.read_text())
        loopback = self.run_tool("install-services.sh", "--no-lan", "--no-secure-lan")
        self.assertEqual(loopback.returncode, 0, loopback.stderr)

    def test_explicit_client_network_is_passed_to_both_lan_listeners(self):
        self.configure()
        result = self.run_tool("install-services.sh", "--lan-address", "192.168.50.5",
                               "--allowed-clients", "192.168.50.0/25")
        self.assertEqual(result.returncode, 0, result.stderr)
        units = self.home / ".config/systemd/user"
        for name in ("switchyard-lan-view.service", "switchyard-lan.service"):
            self.assertIn("--allowed-clients 192.168.50.0/25", (units / name).read_text())
        invalid = self.run_tool("install-services.sh", "--lan-address", "192.168.50.5",
                                "--allowed-clients", "192.168.50.0/24\nExecStart=unsafe")
        self.assertEqual(invalid.returncode, 2)

    def test_lan_routes_config_enables_the_dns_timer_without_enabling_lan_listeners(self):
        self.configure()
        (self.project / "catalogs/home-lab.lan-routes.json").write_text("{}")
        result = self.run_tool("install-services.sh", "--no-lan", "--no-secure-lan")
        self.assertEqual(result.returncode, 0, result.stderr)
        units = self.home / ".config/systemd/user"
        self.assertFalse((units / "switchyard-lan.service").exists())
        self.assertIn("lan-dns-sync", (units / "switchyard-lan-dns-sync.service").read_text())
        self.assertIn("OnUnitInactiveSec=60s", (units / "switchyard-lan-dns-sync.timer").read_text())
        self.assertIn("enable --now switchyard-desk.service switchyard-monitor.service switchyard-lan-dns-sync.timer",
                      self.log.read_text())

    def test_agent_wrappers_use_the_fleet_files_and_reinstall_identically(self):
        self.configure()
        first = self.run_tool("install-agent-cli.sh")
        self.assertEqual(first.returncode, 0, first.stderr)
        wrappers = {name: (self.home / ".local/bin" / name).read_text() for name in ("switchyard", "switchyard-mcp", "switchyard-mcp-remote")}
        catalogs = self.project / "catalogs"
        self.assertIn(f'--project "{self.project}"', wrappers["switchyard"])
        self.assertIn(f'--catalog "{catalogs}/home-lab.json" --collectors "{catalogs}/home-lab.collectors.json" '
                      f'"--operations" "{catalogs}/home-lab.operations.json"', wrappers["switchyard"])
        self.assertNotIn("--operations", wrappers["switchyard-mcp-remote"])
        self.assertEqual(self.run_tool("install-agent-cli.sh").returncode, 0)
        self.assertEqual({name: (self.home / ".local/bin" / name).read_text() for name in wrappers}, wrappers)

    def test_a_linked_worktree_is_refused(self):
        self.configure()
        git = ["git", "-c", "user.name=t", "-c", "user.email=t@invalid", "-C", str(self.project)]
        subprocess.run([*git, "init", "-q"], check=True)
        subprocess.run([*git, "add", "tools"], check=True)
        subprocess.run([*git, "commit", "-qm", "fixture"], check=True)
        linked = self.root / "linked"
        subprocess.run([*git, "worktree", "add", "-q", str(linked)], check=True, capture_output=True)
        (linked / "catalogs").mkdir()
        for name in FLEET:
            (linked / "catalogs" / name).write_text("{}")
        result = subprocess.run(["sh", str(linked / "tools" / "install-agent-cli.sh")], env=self.env,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 2)
        self.assertIn("linked git worktree", result.stderr)
        self.assertEqual(self.run_tool("install-agent-cli.sh").returncode, 0)


if __name__ == "__main__":
    unittest.main()
