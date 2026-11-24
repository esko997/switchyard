"""Local CA and server certificate for the HTTPS LAN listener, made with the `openssl` CLI.

Layout under `<state_dir>/tls/` (directory 0700): `ca.key` (0600, EC P-256), `ca.pem` (10 years),
`server.key` (0600, EC P-256), `server.pem` (leaf, 397 days), `server-chain.pem` (leaf + CA, what the
listener serves) and `server.json` (the SAN list). The CA key is read only by `openssl` while issuing
(`tls init`, `tls renew`, or automatic renewal when a listener starts); no Switchyard process loads it.
Key material never appears on a command line: openssl reads and writes files in a private temp directory.
"""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import stat
import subprocess
import tempfile

CA_DAYS = 3650
SERVER_DAYS = 397
RENEW_BEFORE_SECONDS = 30 * 86400
DNS_NAME = re.compile(r"(?=.{1,253}\Z)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z")
OPENSSL_CANDIDATES = ("/usr/bin/openssl", "/usr/local/bin/openssl", str(Path.home() / ".local/bin/openssl"))


class TLSNotInitialized(ValueError):
    pass


def find_openssl():
    """Absolute path of an executable openssl: SWITCHYARD_OPENSSL, PATH, then fixed locations."""
    candidates = [os.environ.get("SWITCHYARD_OPENSSL"), shutil.which("openssl"), *OPENSSL_CANDIDATES]
    for candidate in candidates:
        if candidate and os.path.isabs(candidate) and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise ValueError("openssl not found: install it or set SWITCHYARD_OPENSSL to its absolute path")


def normalize_name(value):
    """A SAN entry: a literal IP address (normalized) or a DNS name (lowercase)."""
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError("Certificate names must be IP addresses or DNS names")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if not DNS_NAME.fullmatch(value):
        raise ValueError(f"Not an IP address or DNS name: {value!r}")
    return value.lower()


def san_entry(name):
    try:
        ipaddress.ip_address(name)
        return "IP:" + name
    except ValueError:
        return "DNS:" + name


def der_sha256(pem_text):
    """Lowercase hex SHA-256 of the DER encoding of the first certificate in a PEM text."""
    match = re.search(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", pem_text, re.S)
    if not match:
        raise ValueError("No certificate in PEM data")
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(match.group(0))).hexdigest()


def colon_hex(value):
    return ":".join(value[i:i + 2] for i in range(0, len(value), 2)).upper()


class TLSStore:
    def __init__(self, state_dir, *, openssl=None, clock=None):
        self.directory = Path(state_dir) / "tls"
        self._openssl = openssl
        self.clock = clock or (lambda: datetime.now(timezone.utc).timestamp())
        self.ca_key, self.ca_cert = self.directory / "ca.key", self.directory / "ca.pem"
        self.server_key, self.server_cert = self.directory / "server.key", self.directory / "server.pem"
        self.chain = self.directory / "server-chain.pem"
        self.meta = self.directory / "server.json"

    # ---- files -----------------------------------------------------------------------------

    def _private_dir(self):
        # The state root too: Switchyard's registry refuses a root that is not 0700.
        self.directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.mkdir(mode=0o700, exist_ok=True)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("TLS state must be an owned directory")
        self.directory.chmod(0o700)

    def _install(self, source, target, mode):
        """Atomically move a file from the private temp dir into place with an exact mode."""
        os.chmod(source, mode)
        os.replace(source, target)

    def openssl(self, *arguments, cwd):
        command = [self._openssl or find_openssl(), *arguments]
        result = subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True, timeout=60,
                                env={"PATH": "/usr/bin:/bin", "LANG": "C"}, check=False)
        if result.returncode != 0:
            raise ValueError("openssl " + arguments[0] + " failed: " + result.stderr.decode("utf-8", "replace").strip()[-300:])
        return result.stdout.decode("utf-8", "replace")

    def initialized(self):
        return self.ca_cert.is_file() and self.ca_key.is_file()

    def ca_pem(self):
        if not self.ca_cert.is_file():
            raise TLSNotInitialized("TLS is not initialized: run `switchyard tls init` on the control host")
        return self.ca_cert.read_text()

    def ca_fingerprint(self):
        return der_sha256(self.ca_pem())

    def names(self):
        try:
            return json.loads(self.meta.read_text())["names"]
        except (OSError, ValueError, KeyError):
            return []

    # ---- issuing ---------------------------------------------------------------------------

    def init(self, names=()):
        """Create the CA if missing (never replaced), then issue a server certificate when names are given."""
        names = [normalize_name(name) for name in names]
        self._private_dir()
        created = False
        if not self.initialized():
            if self.ca_key.exists() or self.ca_cert.exists():
                raise ValueError(f"Incomplete CA in {self.directory}: inspect it; Switchyard never replaces a CA")
            with tempfile.TemporaryDirectory(prefix=".issue-", dir=self.directory) as work:
                config = Path(work) / "ca.cnf"
                config.write_text("[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=Switchyard local CA\n"
                                  "[v3_ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\n"
                                  "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n")
                self.openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                             "-out", "ca.key", cwd=work)
                self.openssl("req", "-x509", "-new", "-key", "ca.key", "-sha256", "-days", str(CA_DAYS),
                             "-config", "ca.cnf", "-extensions", "v3_ca",
                             "-set_serial", "0x" + secrets.token_hex(16), "-out", "ca.pem", cwd=work)
                self._install(Path(work) / "ca.key", self.ca_key, 0o600)
                self._install(Path(work) / "ca.pem", self.ca_cert, 0o644)
            created = True
        if names:
            self.issue(names)
        return {"ca_created": created, **self.show()}

    def issue(self, names):
        """Issue a new server key and certificate for exactly `names` (IP/DNS SANs)."""
        names = sorted(dict.fromkeys(normalize_name(name) for name in names))
        if not names or len(names) > 32:
            raise ValueError("A server certificate needs 1-32 names")
        if not self.initialized():
            raise TLSNotInitialized("TLS is not initialized: run `switchyard tls init` on the control host")
        self._private_dir()
        with tempfile.TemporaryDirectory(prefix=".issue-", dir=self.directory) as work:
            extensions = Path(work) / "server.ext"
            extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                                  "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\n"
                                  "authorityKeyIdentifier=keyid\n"
                                  "subjectAltName=" + ",".join(san_entry(name) for name in names) + "\n")
            self.openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                         "-out", "server.key", cwd=work)
            self.openssl("req", "-new", "-key", "server.key", "-subj", "/CN=switchyard", "-out", "server.csr", cwd=work)
            self.openssl("x509", "-req", "-in", "server.csr", "-CA", str(self.ca_cert), "-CAkey", str(self.ca_key),
                         "-set_serial", "0x" + secrets.token_hex(16), "-days", str(SERVER_DAYS), "-sha256",
                         "-extfile", "server.ext", "-out", "server.pem", cwd=work)
            leaf = (Path(work) / "server.pem").read_text()
            (Path(work) / "server-chain.pem").write_text(leaf + self.ca_cert.read_text())
            (Path(work) / "server.json").write_text(json.dumps({"names": names}) + "\n")
            # Key first: a listener reading a new certificate with the old key fails closed, never mixes chains.
            self._install(Path(work) / "server.key", self.server_key, 0o600)
            self._install(Path(work) / "server.pem", self.server_cert, 0o644)
            self._install(Path(work) / "server-chain.pem", self.chain, 0o644)
            self._install(Path(work) / "server.json", self.meta, 0o600)
        return self.show()

    def renew(self, names=()):
        current = self.names()
        names = [*current, *names]
        if not names:
            raise ValueError("No server certificate yet: give at least one --name")
        return self.issue(names)

    def not_after(self):
        """Server certificate expiry as epoch seconds, or None without a certificate."""
        if not self.server_cert.is_file():
            return None
        output = self.openssl("x509", "-in", str(self.server_cert), "-noout", "-enddate", cwd=self.directory)
        value = output.strip().partition("=")[2]
        return ssl.cert_time_to_seconds(value)

    def ensure_server(self, names):
        """At listener start: (re)issue unless a certificate covers every name with >30 days left."""
        wanted = [normalize_name(name) for name in names]
        if not self.initialized():
            raise TLSNotInitialized("TLS is not initialized: run `switchyard tls init --name <address>` on the control host")
        expiry = self.not_after()
        current = self.names()
        missing = [name for name in wanted if name not in current]
        if expiry is None or missing or expiry - self.clock() < RENEW_BEFORE_SECONDS or not self.chain.is_file():
            self.issue([*current, *wanted])
            return True
        return False

    def server_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(self.chain), str(self.server_key))
        return context

    def leaf_sha256(self):
        return der_sha256(self.server_cert.read_text())

    def show(self):
        result = {"directory": str(self.directory), "initialized": self.initialized()}
        if self.ca_cert.is_file():
            fingerprint = self.ca_fingerprint()
            result["ca"] = {"path": str(self.ca_cert), "fingerprint_sha256": fingerprint,
                            "fingerprint": "sha256:" + fingerprint, "fingerprint_colons": colon_hex(fingerprint)}
        if self.server_cert.is_file():
            expiry = self.not_after()
            result["server"] = {"names": self.names(), "leaf_sha256": self.leaf_sha256(),
                                "not_after": datetime.fromtimestamp(expiry, timezone.utc).isoformat(),
                                "renews_within_days": RENEW_BEFORE_SECONDS // 86400}
        return result

    def export_ca(self, path):
        target = Path(path)
        target.write_text(self.ca_pem())
        return {"path": str(target), "fingerprint": "sha256:" + self.ca_fingerprint()}
