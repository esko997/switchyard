"""Byte preservation, unsafe-file rejection and on-host recovery without devices."""
import base64
import hashlib
import fcntl
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from switchyard.fleet_keys_remote import BEGIN, END, Conflict, Files, managed, public_key

def key(seed):
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + hashlib.sha256(seed.encode()).digest()
    return "ssh-ed25519 " + base64.b64encode(blob).decode()



class FixtureFiles(Files):
    def inspect(self):
        with patch("switchyard.fleet_keys_remote.client_supported", return_value=True):
            result = super().inspect()
        return {**result, "supported": True, "server_key": key("fixture-server")}


class RemoteKeyFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.files = FixtureFiles(self.home)
        self.generation = "a" * 32
        self.other = "b" * 32

    def identity(self, generation=None):
        self.files.directories(create=True)
        generation = generation or self.generation
        path = self.files.identity(generation)
        path.write_bytes(b"fixture-private-bytes-never-returned")
        path.chmod(0o600)
        path.with_name(path.name + ".pub").write_text(key(generation) + " fixture-comment\n")
        return path

    def configure(self, *, grants=None, peers=None, revoked=None):
        return self.files.apply({"action": "configure", "expected_revision": self.files.inspect()["revision"],
                                 "generation": self.generation, "grants": grants or [], "peers": peers or [],
                                 "revoked_keys": revoked or []})

    def test_inspect_does_not_create_ssh_directory_or_read_private_bytes(self):
        self.files.inspect()
        self.assertFalse(self.files.ssh.exists())
        private = self.identity()
        original = self.files.read

        def no_private(path):
            self.assertNotEqual(path, private)
            return original(path)

        with patch.object(self.files, "read", side_effect=no_private):
            result = self.files.inspect()
        self.assertNotIn("fixture-private", str(result))
        self.assertEqual(result["keys"][self.generation], key(self.generation))

    def test_managed_block_preserves_every_unmanaged_byte_including_missing_newline(self):
        original = b'command="manual",no-agent-forwarding ssh-rsa AAAA untouched\r\n# non-UTF8 \xff no newline'
        addition = managed(original, (key("grant") + "\n").encode())
        self.assertTrue(addition.endswith(original))
        self.assertEqual(managed(addition, b""), original)
        replacement = managed(addition, b"replacement\n")
        self.assertEqual(managed(replacement, b""), original)
        for bad in (BEGIN + b"missing end", END + BEGIN, BEGIN + END + BEGIN + END,
                    b"# BEGIN SWITCHYARD FLEET KEYS v2\n"):
            with self.assertRaises(Conflict):
                managed(bad, b"new\n")

    def test_configure_and_remove_preserve_manual_access_and_main_config_byte_exact(self):
        self.identity()
        main = self.files.ssh / "config"
        main.write_bytes(b"Host personal\n  HostName personal.example\n# untouched \xff")
        manual = b"# manual key without newline"
        self.files.paths["authorized_keys"].write_bytes(manual)
        peer = {"host_id": "beta", "target": "fixture@192.168.50.2", "server_key": key("server-beta")}
        self.configure(grants=[key("grant")], peers=[peer])
        self.assertTrue(self.files.paths["authorized_keys"].read_bytes().endswith(manual))
        self.assertEqual(self.files.paths["authorized_keys"].with_name("authorized_keys.switchyard-prior").read_bytes(), manual)
        config = self.files.paths["config"].read_text()
        self.assertIn("Host switchyard-beta", config)
        self.assertIn("StrictHostKeyChecking yes", config)
        self.assertIn("IdentityAgent none", config)
        self.assertIn("HostKeyAlgorithms ssh-ed25519", config)
        self.configure()
        self.assertEqual(self.files.paths["authorized_keys"].read_bytes(), manual)
        self.assertEqual(main.read_bytes(), b"Host personal\n  HostName personal.example\n# untouched \xff")
        self.assertEqual(self.files.paths["config"].read_bytes(), b"")
        self.assertEqual(self.files.paths["known_hosts"].read_bytes(), b"")

    def test_symlink_hardlink_and_unsafe_permissions_are_rejected(self):
        self.files.directories(create=True)
        target = self.home / "manual"
        target.write_text("do not touch")
        path = self.files.paths["authorized_keys"]
        path.symlink_to(target)
        with self.assertRaises(Conflict):
            self.files.inspect()
        path.unlink()
        os.link(target, path)
        with self.assertRaises(Conflict):
            self.files.inspect()
        path.unlink()
        path.write_text("manual")
        path.chmod(0o666)
        with self.assertRaises(Conflict):
            self.files.inspect()
        path.chmod(0o600)
        self.files.root.chmod(0o777)
        with self.assertRaises(Conflict):
            self.files.inspect()
        self.assertEqual(target.read_text(), "do not touch")

    def test_stale_revision_does_not_change_keys_or_create_identity(self):
        before = self.files.inspect()["revision"]
        self.files.directories(create=True)
        self.files.paths["authorized_keys"].write_text("concurrent manual edit")
        with self.assertRaises(Conflict):
            self.files.apply({"action": "identity", "generation": self.generation, "expected_revision": before})
        self.assertFalse(self.files.identity(self.generation).exists())
        self.assertEqual(self.files.paths["authorized_keys"].read_text(), "concurrent manual edit")

    def test_compare_and_swap_keeps_concurrent_manual_bytes(self):
        self.files.directories(create=True)
        path = self.files.paths["authorized_keys"]
        path.write_bytes(b"concurrent manual value")
        with self.assertRaises(Conflict):
            self.files.atomic(path, b"managed replacement", b"stale prior value")
        self.assertEqual(path.read_bytes(), b"concurrent manual value")
        self.assertEqual(list(self.files.ssh.glob(".switchyard-*")), [])

    def test_remote_lock_busy_fails_before_creation_or_grants(self):
        self.files.directories(create=True)
        lock = self.files.root / "lock"
        with lock.open("a") as stream:
            lock.chmod(0o600)
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(Conflict):
                self.files.apply({"action": "identity", "generation": self.generation,
                                  "expected_revision": self.files.inspect()["revision"]})
        self.assertFalse(self.files.identity(self.generation).exists())

    def test_manual_duplicate_with_options_or_tabs_reports_residual_access(self):
        self.identity()
        duplicate = key("retired").replace(" ", "\t")
        manual = ('from="192.168.50.0/24",no-agent-forwarding ' + duplicate + " manual\n").encode()
        self.files.paths["authorized_keys"].write_bytes(manual)
        result = self.configure(revoked=[key("retired")])
        self.assertEqual(len(result["residual_access"]), 1)
        self.assertEqual(self.files.paths["authorized_keys"].read_bytes(), manual)

    def test_dedicated_client_files_refuse_unmanaged_configuration(self):
        self.files.directories(create=True)
        self.files.paths["config"].write_text("Host *\n  StrictHostKeyChecking no\n")
        with self.assertRaises(Conflict):
            self.files.inspect()

    def test_identity_creation_uses_host_local_keygen_and_reuses_generation(self):
        def keygen(command, **kwargs):
            self.assertEqual(command[:5], ["ssh-keygen", "-q", "-t", "ed25519", "-N"])
            self.assertEqual(command[5], "")
            private = self.identity()
            self.assertEqual(command[-1], str(private))

        with patch("switchyard.fleet_keys_remote.subprocess.run", side_effect=keygen) as generate:
            result = self.files.apply({"action": "identity", "generation": self.generation,
                                       "expected_revision": self.files.inspect()["revision"]})
            result = self.files.apply({"action": "identity", "generation": self.generation,
                                       "expected_revision": result["revision"]})
        self.assertEqual(generate.call_count, 1)
        self.assertNotIn("fixture-private", str(result))
        self.assertEqual(result["keys"][self.generation], key(self.generation))

    def test_orphan_public_file_is_recovered_without_replacing_private_identity(self):
        private = self.identity()
        public = private.with_name(private.name + ".pub")
        public.unlink()
        before = private.read_bytes()
        response = type("KeygenResult", (), {"stdout": (key(self.generation) + "\n").encode()})()
        with patch("switchyard.fleet_keys_remote.subprocess.run", return_value=response) as derive:
            result = self.files.apply({"action": "identity", "generation": self.generation,
                                       "expected_revision": self.files.inspect()["revision"]})
        self.assertEqual(derive.call_args.args[0], ["ssh-keygen", "-y", "-f", str(private)])
        self.assertEqual(private.read_bytes(), before)
        self.assertEqual(result["keys"][self.generation], key(self.generation))

    def test_public_key_parser_rejects_legacy_malformed_and_oversized_material(self):
        for value in ("ssh-rsa AAAA", "ssh-ed25519 not-base64", "ssh-ed25519 AAAA", "x" * 513, None):
            with self.assertRaises(Conflict):
                public_key(value)
        self.assertEqual(public_key(key("valid") + " comment"), key("valid"))


if __name__ == "__main__":
    unittest.main()
