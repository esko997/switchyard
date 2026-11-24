"""Operator password, sessions, throttling, enrollment rules, keys and the auth CLI; temp state only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from switchyard import auth_store
from switchyard.auth import (Auth, AuthError, Identity, enrollment_code, handle_cli, read_new_password,
                             register_cli)
from switchyard.auth_store import hash_password, verify_password

FAST = 2 ** 10
PASSWORD = "correct horse battery staple"
LEAF = "0" * 64


class Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def __call__(self):
        return self.now


def bearer(seed):
    return "sy1_" + (seed * 43)[:43]


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


class AuthTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.clock = Clock()
        self.auth = Auth(self.root, clock=self.clock, registry_hosts=lambda: ["host-a", "host-b"])
        self.operator = Identity("operator", username="operator")
        self.local = Identity("local")

    def request(self, scope="read", hosts=None, seed="A"):
        data = {"name": "agent", "user": "operator", "scope": scope, "key_sha256": sha(bearer(seed))}
        if hosts is not None:
            data["hosts"] = hosts
        return self.auth.create_enrollment(data, source_address="192.168.50.233", leaf_sha256=LEAF,
                                           base_url="https://192.168.50.68:8712")

    def test_code_vectors_published_in_docs(self):
        # Same vectors as docs/auth.md; checked independently with openssl dgst + base32.
        self.assertEqual(enrollment_code("0" * 64, sha("sy1_" + "A" * 43), "0" * 32), "A2C6-HYKT")
        self.assertEqual(enrollment_code(sha("leaf"), sha("sy1_" + "B" * 43), "0123456789abcdef0123456789abcdef"), "4ZNE-XSZW")
        docs = (Path(__file__).resolve().parents[1] / "docs/auth.md").read_text()
        self.assertIn("A2C6-HYKT", docs)
        self.assertIn("4ZNE-XSZW", docs)

    def test_password_hash_is_salted_scrypt_with_stored_parameters(self):
        first, second = json.loads(hash_password(PASSWORD, n=FAST)), json.loads(hash_password(PASSWORD, n=FAST))
        self.assertEqual((first["alg"], first["n"], first["r"], first["p"]), ("scrypt", FAST, 8, 1))
        self.assertNotEqual(first["salt"], second["salt"])
        self.assertTrue(verify_password(PASSWORD, json.dumps(first)))
        self.assertFalse(verify_password(PASSWORD + "x", json.dumps(first)))
        self.assertEqual(auth_store.SCRYPT_N, 2 ** 17)  # Production default.
        with self.assertRaises(ValueError):
            self.auth.set_password("operator", "short")
        with self.assertRaises(ValueError):
            self.auth.set_password("bad name", PASSWORD)

    def test_state_is_private_and_holds_no_secrets(self):
        self.auth.set_password("operator", PASSWORD, scrypt_n=FAST)
        session = self.auth.login("operator", PASSWORD, client="127.0.0.1", listener="lan")
        self.request()
        directory = self.root / "auth"
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((directory / "auth.sqlite3").stat().st_mode), 0o600)
        raw = (directory / "auth.sqlite3").read_bytes()
        for secret in (PASSWORD, session["token"], bearer("A")):
            self.assertNotIn(secret.encode(), raw)

    def test_login_generic_failure_unknown_user_and_throttle(self):
        self.auth.set_password("operator", PASSWORD, scrypt_n=FAST)
        self.auth._dummy = hash_password("dummy", n=FAST)
        messages = set()
        for username, password in (("operator", "wrong password"), ("nobody", PASSWORD)):
            with self.assertRaises(AuthError) as raised:
                self.auth.login(username, password, client="a", listener="lan")
            messages.add((raised.exception.status, str(raised.exception)))
        self.assertEqual(messages, {(401, "Sign-in failed")})
        for _ in range(3):
            with self.assertRaises(AuthError):
                self.auth.login("operator", "wrong", client="a", listener="lan")
        with self.assertRaises(AuthError) as raised:
            self.auth.login("operator", PASSWORD, client="a", listener="lan")  # Even the right password.
        self.assertEqual(raised.exception.status, 429)
        self.assertGreater(raised.exception.retry_after, 0)
        self.auth.login("operator", PASSWORD, client="b", listener="lan")  # Another address is unaffected.
        self.clock.now += 15 * 60 + 1
        self.auth.login("operator", PASSWORD, client="a", listener="lan")
        # Global cap across addresses.
        for index in range(50):
            try:
                self.auth.login("operator", "wrong", client=f"c{index}", listener="lan")
            except AuthError:
                pass
        with self.assertRaises(AuthError) as raised:
            self.auth.login("operator", PASSWORD, client="fresh", listener="lan")
        self.assertEqual(raised.exception.status, 429)
        audit = json.dumps(self.auth.store.audit_tail(200))
        self.assertNotIn(PASSWORD, audit)
        self.assertNotIn("wrong", audit)

    def test_flooding_the_bounded_audit_log_does_not_reset_the_throttle(self):
        self.auth.set_password("operator", PASSWORD, scrypt_n=FAST)
        for _ in range(5):
            with self.assertRaises(AuthError):
                self.auth.login("operator", "wrong", client="a", listener="lan")
        with patch.object(auth_store, "AUDIT_ROWS", 20):
            for _ in range(60):  # Three times the (patched) audit bound, each a throttled attempt.
                with self.assertRaises(AuthError) as raised:
                    self.auth.login("operator", PASSWORD, client="a", listener="lan")
                self.assertEqual(raised.exception.status, 429)
            with self.assertRaises(AuthError) as raised:
                self.auth.login("operator", PASSWORD, client="a", listener="lan")
            self.assertEqual(raised.exception.status, 429)
            rows = self.auth.store.audit_tail(1000)
            self.assertEqual(sum(1 for row in rows if row["outcome"] == "failure"), 5)
            self.assertLessEqual(len(rows), 20 + 5)  # Still bounded: only unexpired failures are kept beyond it.
        self.clock.now += 15 * 60 + 1
        self.auth.login("operator", PASSWORD, client="a", listener="lan")

    def test_session_idle_absolute_rotation_and_logout_all(self):
        self.auth.set_password("operator", PASSWORD, scrypt_n=FAST)
        session = self.auth.login("operator", PASSWORD, client="a", listener="lan")
        token = session["token"]
        self.assertEqual(self.auth.session(token, "lan")["csrf_token"], session["csrf_token"])
        self.assertIsNone(self.auth.session(token, "loopback"))  # Bound to its listener.
        # Idle: refreshed by use (at most once a minute), expired after 12 hours without use.
        self.clock.now += 11 * 3600
        self.assertIsNotNone(self.auth.session(token, "lan"))
        self.clock.now += 11 * 3600
        self.assertIsNotNone(self.auth.session(token, "lan"))
        self.clock.now += 12 * 3600 + 1
        self.assertIsNone(self.auth.session(token, "lan"))
        # Absolute: 7 days even with steady use.
        token = self.auth.login("operator", PASSWORD, client="a", listener="lan")["token"]
        for _ in range(16):  # 176 hours of steady use > 7 days.
            self.clock.now += 11 * 3600
            self.auth.session(token, "lan")
        self.assertIsNone(self.auth.session(token, "lan"))
        # Rotation: a new login with the old token replaces it.
        old = self.auth.login("operator", PASSWORD, client="a", listener="lan")["token"]
        new = self.auth.login("operator", PASSWORD, client="a", listener="lan", replace=old)
        self.assertIsNone(self.auth.session(old, "lan"))
        self.assertNotEqual(new["csrf_token"], self.auth.login("operator", PASSWORD, client="a", listener="lan")["csrf_token"])
        self.assertEqual(self.auth.logout_all()["sessions_ended"], 2)
        self.assertIsNone(self.auth.session(new["token"], "lan"))
        # Changing the password ends every session.
        token = self.auth.login("operator", PASSWORD, client="a", listener="lan")["token"]
        self.auth.set_password("operator", PASSWORD + "!", scrypt_n=FAST)
        self.assertIsNone(self.auth.session(token, "lan"))

    def test_enrollment_rules(self):
        request = self.request("operate", ["host-a", "host-b"])
        self.assertEqual(request["code"], enrollment_code(LEAF, sha(bearer("A")), request["id"]))
        self.assertEqual(request["approve_url"], f"https://192.168.50.68:8712/#access/{request['id']}")
        with self.assertRaises(AuthError) as raised:
            self.auth.poll_enrollment(request["id"], bearer("B"))
        self.assertEqual(raised.exception.status, 404)
        self.assertEqual(self.auth.poll_enrollment(request["id"], bearer("A")), {"status": "pending"})
        for identity, grant in ((self.local, {"scope": "lease"}), (self.local, {})):
            with self.assertRaises(AuthError) as raised:
                self.auth.approve(request["id"], identity, **grant)
            self.assertEqual(raised.exception.status, 403)
        with self.assertRaises(ValueError):
            self.auth.approve(request["id"], self.operator, hosts=["unknown"])
        with self.assertRaises(ValueError):
            self.auth.approve(request["id"], self.operator, scope="lease", hosts=[])
        key = self.auth.approve(request["id"], self.operator, scope="lease", hosts=["host-a"])
        self.assertEqual((key["scope"], key["hosts"]), ("lease", ["host-a"]))
        self.assertEqual(self.auth.poll_enrollment(request["id"], bearer("A"))["key"]["id"], key["id"])
        with self.assertRaises(AuthError) as raised:
            self.auth.deny(request["id"], self.operator)
        self.assertEqual(raised.exception.status, 409)
        # Read: local may approve; never widened; no hosts.
        read = self.request("read", seed="C")
        with self.assertRaises(ValueError):
            self.auth.approve(read["id"], self.operator, scope="operate", hosts=["host-a"])
        self.assertEqual(self.auth.approve(read["id"], self.local)["hosts"], [])
        # Deny is operator only.
        denied = self.request(seed="D")
        with self.assertRaises(AuthError):
            self.auth.deny(denied["id"], self.local)
        self.auth.deny(denied["id"], self.operator)
        self.assertEqual(self.auth.poll_enrollment(denied["id"], bearer("D")), {"status": "denied"})
        # Expiry after 15 minutes.
        late = self.request(seed="E")
        self.clock.now += 15 * 60
        self.assertEqual(self.auth.poll_enrollment(late["id"], bearer("E")), {"status": "expired"})
        with self.assertRaises(AuthError):
            self.auth.approve(late["id"], self.operator)

    def test_keys_expire_revoke_and_record_use(self):
        key = self.auth.approve(self.request()["id"], self.local, expires_in_days=1)
        self.assertEqual(self.auth.key_for_bearer(bearer("A"), "192.168.50.233")["id"], key["id"])
        used = self.auth.keys()[0]
        self.assertEqual(used["last_used_from"], "192.168.50.233")
        self.clock.now += 30
        self.auth.key_for_bearer(bearer("A"), "192.168.50.234")
        self.assertEqual(self.auth.keys()[0]["last_used_at"], used["last_used_at"])  # At most once a minute.
        self.clock.now += 31
        self.auth.key_for_bearer(bearer("A"), "192.168.50.234")
        self.assertEqual(self.auth.keys()[0]["last_used_from"], "192.168.50.234")
        self.clock.now += 86400
        with self.assertRaises(AuthError) as raised:
            self.auth.key_for_bearer(bearer("A"), "x")
        self.assertEqual(raised.exception.status, 401)
        other = self.auth.approve(self.request(seed="F")["id"], self.local)
        with self.assertRaises(AuthError):
            self.auth.revoke(other["id"], self.local)
        self.auth.revoke(other["id"], self.operator)
        with self.assertRaises(AuthError):
            self.auth.key_for_bearer(bearer("F"), "x")
        for malformed in ("sy1_short", "Bearer", bearer("A") + "x"):
            with self.assertRaises(AuthError):
                self.auth.key_for_bearer(malformed, "x")

    def test_enrollment_input_and_caps(self):
        for change in ({"scope": "admin"}, {"user": "two words"}, {"key_sha256": "A" * 64}, {"hosts": "host-a"},
                       {"agent_id": "-bad"}, {"extra": 1}, {"name": "x\n"}, {"scope": "read", "hosts": ["host-a"]}):
            data = {"name": "a", "user": "u", "scope": "lease", "key_sha256": sha("x"), **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.auth.create_enrollment(data, source_address="a", leaf_sha256=LEAF, base_url="https://x")
        for index in range(16):
            self.request(seed=chr(ord("a") + index))
        with self.assertRaises(AuthError) as raised:
            self.request(seed="z")
        self.assertEqual(raised.exception.status, 429)


class AuthCLITests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.service = type("Service", (), {"_state_dir": Path(temp.name),
                                            "hosts": lambda self: {"hosts": [{"id": "host-a"}]}})()
        parser = argparse.ArgumentParser()
        commands = parser.add_subparsers(dest="command")
        register_cli(commands)
        self.parse = parser.parse_args

    def run_cli(self, *argv, agent=None, password=PASSWORD):
        with patch.object(auth_store, "SCRYPT_N", FAST):
            return handle_cli(self.parse(list(argv)), self.service, agent_check=lambda: agent,
                              password_reader=lambda: password)

    def test_set_password_refuses_agents_and_pipes(self):
        with self.assertRaisesRegex(ValueError, "agents"):
            self.run_cli("auth", "set-password", agent="ancestor omp:1 is an agent session")
        self.assertFalse(self.run_cli("auth", "status")["operator_configured"])
        with self.assertRaisesRegex(ValueError, "terminal"):
            with open(os.devnull) as stream:
                read_new_password(stdin=stream)
        answers = iter(["one password here", "another one here"])
        tty = type("TTY", (), {"isatty": lambda self: True})()
        with self.assertRaisesRegex(ValueError, "do not match"):
            read_new_password(stdin=tty, prompt=lambda _: next(answers))
        self.assertEqual(self.run_cli("auth", "set-password", "--username", "operator")["username"], "operator")
        self.assertTrue(self.run_cli("auth", "status")["operator_configured"])

    def test_agents_may_approve_read_only(self):
        auth = Auth(self.service._state_dir, registry_hosts=lambda: ["host-a"])
        made = [auth.create_enrollment({"name": "a", "user": "u", "scope": scope, "key_sha256": sha(seed)},
                                       source_address="a", leaf_sha256=LEAF, base_url="https://x")
                for scope, seed in (("lease", "1"), ("lease", "2"), ("read", "3"))]
        agent = "PASEO_AGENT_ID=x in the environment"
        with self.assertRaisesRegex(ValueError, "operator"):
            self.run_cli("auth", "approve", made[0]["id"], "--hosts", "host-a", agent=agent)
        self.assertEqual(self.run_cli("auth", "approve", made[0]["id"], "--scope", "read", agent=agent)["scope"], "read")
        for command in (("auth", "deny", made[1]["id"]), ("auth", "revoke", "0123456789abcdef"), ("auth", "logout-all")):
            with self.subTest(command=command), self.assertRaisesRegex(ValueError, "agents"):
                self.run_cli(*command, agent=agent)
        key = self.run_cli("auth", "approve", made[1]["id"], "--hosts", "host-a", "--days", "30", "--label", "pop")
        self.assertEqual((key["scope"], key["hosts"], key["label"]), ("lease", ["host-a"], "pop"))
        self.assertEqual(len(self.run_cli("auth", "keys")), 2)
        self.assertEqual([item["id"] for item in self.run_cli("auth", "requests")["pending"]], [made[2]["id"]])
        self.assertEqual(self.run_cli("auth", "revoke", key["id"]), {"revoked": key["id"]})


if __name__ == "__main__":
    unittest.main()
