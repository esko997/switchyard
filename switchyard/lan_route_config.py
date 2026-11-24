"""LAN routes: the private route configuration, endpoint candidates and the gateway Caddyfile renderer.

Pure functions, no host access. Endpoints are declared by an application and claimed by its placement; offering
one as a candidate does not publish it. Legacy observed_endpoints retain their exact configured targets and
policies. Optional upstream_policies configure only a declared endpoint's proxy profile, allowed hostnames and
HTTPS CA file, never its address or port.

Candidates require an exact private IPv4 TCP claim. Adopted placements must match the host registry when it is
provided; ambiguous endpoints on multiple current placements are excluded. Older applications may infer the
scheme from an unambiguous declared HTTP health check (no health-result requirement). HTTPS needs an explicitly
configured verified-https policy and CA file; TLS verification is never bypassed.

A route is a resolved snapshot under one hostname. The renderer owns the whole Caddyfile, including the baseline
listeners and a gateway-answered route marker, so configuration remains verifiable while its backend is stopped.
Profiles are plain HTTP, rewrite-redirect HTTP (rewriting exact upstream/plain-route Location headers), or
verified-https (trusting only the configured CA file mounted under /etc/caddy). Hostname restrictions apply to
every profile.
"""
import hashlib
from ipaddress import IPv4Address, IPv4Network
import json
import os
import re
import stat

from . import spec
from .deploy_config import registry_addresses

RENDER_VERSION = "switchyard-lan-route/v1"
PROBE_PATH = "/.well-known/switchyard-route"
CA_DIRECTORY = "/etc/caddy/"  # where the gateway mounts its configuration files
MAX_ROUTES = 64
MAX_ENDPOINTS = 64
MAX_HOSTNAMES = 8
CONFIG_LIMIT = 65536
PROFILES = {"plain": "http", "rewrite-redirect": "http", "verified-https": "https"}
ROUTE_KEYS = ("hostname", "workload_id", "endpoint_id", "address", "port", "scheme", "profile")
# Placed instances: running, stopped by its operator, or fenced while an exclusive resource (a GPU) serves another
# instance. The route marker is answered by the gateway itself, so it never depends on the backend running.
DEPLOYED_STATES = ("active", "staged", "fenced")

_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_CA_FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}(?:\.[A-Za-z0-9_-]{1,32})*\.(?:crt|pem)\Z")
_LAN = (IPv4Network("10.0.0.0/8"), IPv4Network("172.16.0.0/12"), IPv4Network("192.168.0.0/16"))
_CONFIG_KEYS = {"gateway_id", "dns_id", "zone", "ca_sha256"}
_CONFIG_OPTIONAL = {"gateway_ip", "adopt_caddy_sha256", "adopt_routes", "observed_endpoints", "upstream_policies"}
_OBSERVED_KEYS = {"workload_id", "endpoint_id", "host_id", "address", "port", "scheme", "profile"}


# ----------------------------------------------------------------------------------------------- validation
def _identifier(value, label):
    if not isinstance(value, str) or not _ID.match(value):
        raise ValueError("Invalid " + label + ": expected a lowercase ID (a-z, 0-9, hyphens, at most 64)")
    return value


def _digest(value, label):
    if not isinstance(value, str) or not _DIGEST.match(value):
        raise ValueError("Invalid " + label + ": expected 64 lowercase hexadecimal digits")
    return value


def _port(value, label="port"):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("Invalid " + label + ": expected an integer 1-65535")
    return value


def lan_address(value, label="address"):
    """A canonical private (RFC 1918) unicast IPv4 address; loopback, public, wildcard and IPv6 are refused."""
    try:
        address = IPv4Address(value) if isinstance(value, str) else None
    except ValueError:
        address = None
    if address is None or str(address) != value or not any(address in net for net in _LAN):
        raise ValueError("Invalid " + label + " " + repr(value)[:80] + ": expected a canonical private LAN IPv4 address")
    return value


def dns_name(value, label="name"):
    if not isinstance(value, str) or not 0 < len(value) <= 253 or not all(_LABEL.match(part) for part in value.split(".")):
        raise ValueError("Invalid " + label + " " + repr(value)[:80] + ": expected lowercase DNS labels (a-z, 0-9, inner hyphens)")
    return value


def hostname_in(zone, name):
    """A route hostname, fully qualified and lowercase, given relative to the zone or as a name inside it."""
    if not isinstance(name, str) or len(name) > 300:
        raise ValueError("Hostname must be text")
    name = name.strip().rstrip(".").lower()
    if name.endswith("." + zone):
        pass
    elif "." in name or name == zone or not name:
        raise ValueError("Hostname " + repr(name)[:80] + " is outside zone " + zone + " (give one label or name." + zone + ")")
    else:
        name = name + "." + zone
    _zone_name(zone, name, "hostname")
    return name


def relative_name(name, zone):
    """The hostname relative to the zone (the DNS record name)."""
    if not isinstance(name, str) or not name.endswith("." + zone) or len(name) <= len(zone) + 1:
        raise ValueError("Hostname " + repr(name)[:80] + " is not inside zone " + zone)
    return name[:-len(zone) - 1]


def _exact_keys(value, required, optional, label):
    if not isinstance(value, dict) or not required <= set(value) <= required | optional:
        missing = sorted(required - set(value)) if isinstance(value, dict) else sorted(required)
        unknown = sorted(set(value) - required - optional) if isinstance(value, dict) else []
        raise ValueError("Invalid " + label + " fields" + (": missing " + ", ".join(missing) if missing else "")
                         + (": unknown " + ", ".join(unknown) if unknown else ""))
    return value


def _check_target(profile, scheme, label):
    if not isinstance(profile, str) or profile not in PROFILES:
        raise ValueError("Invalid " + label + " profile " + repr(profile)[:40] + "; known: " + ", ".join(sorted(PROFILES)))
    if scheme != PROFILES[profile]:
        raise ValueError("The " + profile + " profile proxies to " + PROFILES[profile] + ", not " + repr(scheme)[:40])


# ----------------------------------------------------------------------------------------------- configuration
def normalize(data):
    """Validate the configuration document and return its normalized form (every optional key present)."""
    _exact_keys(data, _CONFIG_KEYS, _CONFIG_OPTIONAL, "LAN route configuration")
    gateway_id = _identifier(data["gateway_id"], "gateway_id")
    dns_id = _identifier(data["dns_id"], "dns_id")
    if gateway_id == dns_id:
        raise ValueError("gateway_id and dns_id must name different instances")
    zone = dns_name(data["zone"], "zone")
    if len(zone) > 200:
        raise ValueError("Zone is too long")
    gateway_ip = data.get("gateway_ip")
    if gateway_ip is not None:
        lan_address(gateway_ip, "gateway_ip")
    adopt_sha = data.get("adopt_caddy_sha256")
    if adopt_sha is not None:
        _digest(adopt_sha, "adopt_caddy_sha256")
    config = {"gateway_id": gateway_id, "dns_id": dns_id, "zone": zone, "gateway_ip": gateway_ip,
              "ca_sha256": _digest(data["ca_sha256"], "ca_sha256"), "adopt_caddy_sha256": adopt_sha}

    observed, targets, keys = [], set(), set()
    items = data.get("observed_endpoints", [])
    if not isinstance(items, list) or len(items) > MAX_ENDPOINTS:
        raise ValueError("observed_endpoints must be a list of at most " + str(MAX_ENDPOINTS))
    for item in items:
        _exact_keys(item, _OBSERVED_KEYS, {"hostnames", "ca_file"}, "observed endpoint")
        entry = {"workload_id": _identifier(item["workload_id"], "observed endpoint workload_id"),
                 "endpoint_id": _identifier(item["endpoint_id"], "observed endpoint endpoint_id"),
                 "host_id": _identifier(item["host_id"], "observed endpoint host_id"),
                 "address": lan_address(item["address"]), "port": _port(item["port"]),
                 "scheme": item["scheme"], "profile": item["profile"]}
        label = entry["workload_id"] + "/" + entry["endpoint_id"]
        _check_target(entry["profile"], entry["scheme"], "observed endpoint " + label)
        if entry["workload_id"] in (gateway_id, dns_id):
            raise ValueError("Observed endpoint " + label + " names the gateway or DNS instance")
        if (entry["workload_id"], entry["endpoint_id"]) in keys:
            raise ValueError("Duplicate observed endpoint " + label)
        if (entry["address"], entry["port"]) in targets:
            raise ValueError("Observed endpoints " + label + " and another share " + entry["address"] + ":" + str(entry["port"]))
        keys.add((entry["workload_id"], entry["endpoint_id"]))
        targets.add((entry["address"], entry["port"]))
        hostnames = item.get("hostnames")
        if hostnames is not None:
            if not isinstance(hostnames, list) or not 0 < len(hostnames) <= MAX_HOSTNAMES:
                raise ValueError("Observed endpoint " + label + " hostnames must be a list of 1-" + str(MAX_HOSTNAMES))
            hostnames = [_zone_name(zone, name, "observed endpoint " + label + " hostname") for name in hostnames]
            if len(set(hostnames)) != len(hostnames):
                raise ValueError("Duplicate hostname for observed endpoint " + label)
            hostnames = sorted(hostnames)
        entry["hostnames"] = hostnames
        ca_file = item.get("ca_file")
        if (ca_file is not None) != (entry["profile"] == "verified-https"):
            raise ValueError("Observed endpoint " + label + ": ca_file is required for verified-https and only there")
        if ca_file is not None and (not isinstance(ca_file, str) or not _CA_FILE.match(ca_file)):
            raise ValueError("Observed endpoint " + label + ": ca_file must be a plain .crt or .pem file name")
        entry["ca_file"] = ca_file
        observed.append(entry)
    config["observed_endpoints"] = sorted(observed, key=lambda e: (e["workload_id"], e["endpoint_id"]))

    policies, policy_keys = [], set()
    items = data.get("upstream_policies", [])
    if not isinstance(items, list) or len(items) > MAX_ENDPOINTS:
        raise ValueError("upstream_policies must be a list of at most " + str(MAX_ENDPOINTS))
    for item in items:
        _exact_keys(item, {"workload_id", "endpoint_id", "profile"}, {"hostnames", "ca_file"}, "upstream policy")
        entry = {"workload_id": _identifier(item["workload_id"], "upstream policy workload_id"),
                 "endpoint_id": _identifier(item["endpoint_id"], "upstream policy endpoint_id"),
                 "profile": item["profile"]}
        label = entry["workload_id"] + "/" + entry["endpoint_id"]
        key = (entry["workload_id"], entry["endpoint_id"])
        if key in policy_keys:
            raise ValueError("Duplicate upstream policy " + label)
        if key in keys:
            raise ValueError("Upstream policy " + label + " overlaps a legacy observed endpoint policy")
        if entry["workload_id"] in (gateway_id, dns_id):
            raise ValueError("Upstream policy " + label + " names the gateway or DNS instance")
        policy_keys.add(key)
        if not isinstance(entry["profile"], str) or entry["profile"] not in PROFILES:
            raise ValueError("Invalid upstream policy " + label + " profile")
        hostnames = item.get("hostnames")
        if hostnames is not None:
            if not isinstance(hostnames, list) or not 0 < len(hostnames) <= MAX_HOSTNAMES:
                raise ValueError("Upstream policy " + label + " hostnames must be a list of 1-" + str(MAX_HOSTNAMES))
            hostnames = [_zone_name(zone, name, "upstream policy " + label + " hostname") for name in hostnames]
            if len(set(hostnames)) != len(hostnames):
                raise ValueError("Duplicate hostname for upstream policy " + label)
            hostnames = sorted(hostnames)
        entry["hostnames"] = hostnames
        ca_file = item.get("ca_file")
        if (ca_file is not None) != (entry["profile"] == "verified-https"):
            raise ValueError("Upstream policy " + label + ": ca_file is required for verified-https and only there")
        if ca_file is not None and (not isinstance(ca_file, str) or not _CA_FILE.match(ca_file)):
            raise ValueError("Upstream policy " + label + ": ca_file must be a plain .crt or .pem file name")
        entry["ca_file"] = ca_file
        policies.append(entry)
    config["upstream_policies"] = sorted(policies, key=lambda e: (e["workload_id"], e["endpoint_id"]))

    adopt, names = [], set()
    items = data.get("adopt_routes", [])
    if not isinstance(items, list) or len(items) > MAX_ROUTES:
        raise ValueError("adopt_routes must be a list of at most " + str(MAX_ROUTES))
    for item in items:
        _exact_keys(item, {"hostname", "workload_id", "endpoint_id"}, set(), "adopted route")
        hostname = _zone_name(zone, item["hostname"], "adopted route hostname")
        if hostname in names:
            raise ValueError("Duplicate adopted route " + hostname)
        names.add(hostname)
        adopt.append({"hostname": hostname, "workload_id": _identifier(item["workload_id"], "adopted route workload_id"),
                      "endpoint_id": _identifier(item["endpoint_id"], "adopted route endpoint_id")})
    config["adopt_routes"] = sorted(adopt, key=lambda r: r["hostname"])
    if config["adopt_routes"] and adopt_sha is None:
        raise ValueError("adopt_routes need adopt_caddy_sha256 (the exact Caddyfile they were read from)")
    return config


def _zone_name(zone, name, label):
    """A fully qualified lowercase name strictly inside the zone, exactly as written (configuration is canonical)."""
    if not isinstance(name, str) or not name.endswith("." + zone) or len(name) <= len(zone) + 1:
        raise ValueError("Invalid " + label + " " + repr(name)[:80] + ": expected a lowercase name inside " + zone)
    return dns_name(name, label)


def load(path):
    """Read and normalize the private configuration file: an owned regular file (no symlink), not writable by group
    or others, at most 64 KiB of strict JSON. A missing file raises FileNotFoundError (routes are not configured);
    anything else wrong raises ValueError."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        raise
    except OSError as error:
        raise ValueError("Cannot open LAN route configuration " + str(path) + ": " + error.strerror) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("LAN route configuration must be a regular file owned by this account")
        if info.st_mode & 0o022:
            raise ValueError("LAN route configuration must not be writable by group or others")
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, 16384)
            if not chunk:
                break
            size += len(chunk)
            if size > CONFIG_LIMIT:
                raise ValueError("LAN route configuration is larger than " + str(CONFIG_LIMIT) + " bytes")
            chunks.append(chunk)
    finally:
        os.close(fd)

    def constant(name):
        raise ValueError("Invalid JSON constant " + name)

    try:
        data = json.loads(b"".join(chunks).decode("utf-8"), parse_constant=constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("LAN route configuration is not valid JSON: " + str(error)[:200]) from None
    return normalize(data)


# ----------------------------------------------------------------------------------------------- candidates
def _blocked(claims):
    """(host, address, port) the gateway and DNS instances hold over TCP (a wildcard holds every address of its host)."""
    return {(row["host_id"], row["address"], row["port"]) for row in claims if row.get("protocol") == "tcp"}


def _overlaps(blocked, host_id, address, port):
    return any(port == held and (held_address == address or held_host == host_id and held_address in ("0.0.0.0", "::"))
               for held_host, held_address, held in blocked)


def endpoint_scan(store, config, *, hosts=None):
    """Candidates and exclusions from one read-only store snapshot; no probes or health results are needed.

    When `hosts` is provided, adopted endpoints must match their bound host's registry SSH address."""
    rows, skipped, declared = [], [], {}
    registry = None if hosts is None else {entry["host_id"]: entry["address"] for entry in registry_addresses(hosts)[0]}
    policies = {(e["workload_id"], e["endpoint_id"]): e for e in config.get("upstream_policies", [])}
    with store.reading() as db:
        blocked = set()
        for instance_id in (config["gateway_id"], config["dns_id"]):
            blocked |= _blocked(row for row in store.claims_for(db, instance_id) if row.get("owner_kind") == "placement")
        observed = {record["id"]: record for record in store.records(db, "observed")}
        for record in list(observed.values()) + store.records(db, "registered"):
            if record["id"] not in (config["gateway_id"], config["dns_id"]):
                for row, reason in _bundle_rows(record, registry):
                    declared.setdefault((row["workload_id"], row["endpoint_id"]), []).append((row, reason))
        for record in store.records(db, "deployed"):
            if record["id"] in (config["gateway_id"], config["dns_id"]):
                continue
            for row, reason in _deployed_rows(store.instance_row(db, record["id"]), store.placement_row(db, record["id"])):
                declared.setdefault((row["workload_id"], row["endpoint_id"]), []).append((row, reason))
        legacy = {(e["workload_id"], e["endpoint_id"]): e for e in config["observed_endpoints"]}
        for key in sorted(set(declared) | set(legacy)):
            entries = declared.get(key, [])
            entry = legacy.get(key)
            if len(entries) > 1:
                row, reason = entries[0][0], "endpoint is ambiguous across multiple current placements"
            elif entries:
                row, reason = entries[0]
                if entry is not None and any(row[k] != entry[k] for k in ("address", "port", "scheme")):
                    reason = "declared endpoint conflicts with legacy observed endpoint address, port or scheme"
            else:
                row = {k: entry[k] for k in ("workload_id", "endpoint_id", "address", "port", "scheme", "profile",
                                             "host_id", "hostnames", "ca_file")} | {"relation": "observed"}
                reason = _observed_refusal(entry, observed.get(key[0]), registry, store.relation_of(db, key[0]))
            policy = entry if entry is not None else policies.get(key)
            if policy is not None:
                row = {**row, **{k: policy[k] for k in ("profile", "hostnames", "ca_file")}}
                if reason is None and PROFILES[row["profile"]] != row["scheme"]:
                    reason = "upstream policy profile does not match the declared endpoint scheme"
            elif reason is None and row["scheme"] == "https":
                reason = "HTTPS endpoint needs a verified-https upstream policy with a CA file"
            if reason is None and _overlaps(blocked, row["host_id"], row["address"], row["port"]):
                reason = "the gateway or DNS instance holds " + row["address"] + ":" + str(row["port"])
            if reason:
                skipped.append({"workload_id": key[0], "endpoint_id": key[1], "reason": reason})
            else:
                rows.append(row)
    return rows, skipped


def endpoint_candidates(store, config, *, hosts=None):
    """Rows `{workload_id, endpoint_id, address, port, scheme, profile, host_id, relation, hostnames, ca_file}`,
    sorted; `hostnames` (None or the exact allowed names) and `ca_file` come from the configuration."""
    return endpoint_scan(store, config, hosts=hosts)[0]


def _observed_refusal(entry, record, registry, relation):
    if record is None:
        return "no observed workload " + entry["workload_id"] + (" (it is " + relation + ")" if relation else "")
    try:
        application = record["data"]["applications"][0]
        placement = record["data"]["placements"][0]
        native = application["components"][0]["native"]
    except (KeyError, IndexError, TypeError):
        return "observed workload record has no application and placement"
    if native.get("kind") != "observed" or native.get("resource_kind", "service") != "service":
        return "observed workload " + entry["workload_id"] + " is not a service"
    if placement.get("host_id") != entry["host_id"]:
        return "observed workload " + entry["workload_id"] + " is bound on " + str(placement.get("host_id")) + ", not " + entry["host_id"]
    if registry is not None:
        address = registry.get(entry["host_id"])
        if address is None:
            return "host " + entry["host_id"] + " has no LAN address in the registry"
        if address != entry["address"]:
            return "host " + entry["host_id"] + " has registry address " + address + ", not " + entry["address"]
    return None


def _endpoint_rows(workload_id, relation, app, placement, *, registry=None, refusal=None):
    """Resolve declarations against exact claims, leaving policy selection to endpoint_scan."""
    claims = {claim["endpoint"]: claim for claim in placement.get("endpoints", [])}
    components = {component["id"]: component["native"] for component in app.get("components", [])}
    result = []
    for endpoint in app.get("endpoints", []):
        claim = claims.get(endpoint["id"])
        if claim is None:
            continue
        schemes = {check.get("scheme", "http") for check in app.get("health_checks", [])
                   if check.get("type") == "http" and check.get("endpoint") == endpoint["id"]}
        scheme = endpoint.get("scheme") or (next(iter(schemes)) if len(schemes) == 1 else None)
        row = {"workload_id": workload_id, "endpoint_id": endpoint["id"], "address": claim["address"],
               "port": claim["host_port"], "scheme": scheme, "profile": "plain", "host_id": placement["host_id"],
               "relation": relation, "hostnames": None, "ca_file": None}
        native = components.get(endpoint.get("component"), {})
        reason = refusal
        if reason is None and endpoint["protocol"] != "tcp":
            reason = "not a TCP endpoint"
        if reason is None and scheme not in ("http", "https"):
            reason = "no HTTP scheme or unambiguous HTTP health check declared on this endpoint"
        if reason is None and native.get("kind") == "observed" and native.get("resource_kind", "service") != "service":
            reason = "observed endpoint is not a service"
        if reason is None:
            try:
                lan_address(claim["address"], "claim address")
            except ValueError:
                reason = "claimed on " + str(claim["address"]) + ", not an exact private LAN IPv4 address"
        if reason is None and registry is not None:
            address = registry.get(placement["host_id"])
            if address is None:
                reason = "host " + placement["host_id"] + " has no LAN address in the registry"
            elif address != claim["address"]:
                reason = "host " + placement["host_id"] + " has registry address " + address + ", not " + claim["address"]
        result.append((row, reason))
    return result


def _bundle_rows(record, registry):
    bundle = record["data"]
    applications = {(app["id"], app.get("revision")): app for app in bundle.get("applications", [])}
    result = []
    for placement in bundle.get("placements", []):
        if placement.get("state") == "retired":
            continue
        app = applications.get((placement.get("application_id"), placement.get("revision")))
        if app is None:
            continue
        refusal = None if placement.get("ownership") == "adopted" else "placement is not adopted"
        result.extend(_endpoint_rows(record["id"], record["relation"], app, placement, registry=registry, refusal=refusal))
    return result


def _deployed_rows(instance, placement):
    """Declared endpoints of the current placed generation, including stopped/fenced backends."""
    if instance is None or placement is None or placement["state"] not in DEPLOYED_STATES:
        return []
    refusal = "its placement's effects are uncertain; inspect it first" if placement["meta"].get("uncertain") else None
    return _endpoint_rows(instance["id"], "deployed", instance["application"],
                          {**placement["placement"], "host_id": placement["host_id"]}, refusal=refusal)


# ----------------------------------------------------------------------------------------------- routes
def route(config, candidates, hostname, workload_id, endpoint_id):
    """The route snapshot for one hostname (relative or inside the zone) and one exact candidate endpoint."""
    name = hostname_in(config["zone"], hostname)
    if workload_id in (config["gateway_id"], config["dns_id"]):
        raise ValueError("The gateway and DNS instances cannot be published")
    matches = [row for row in candidates if row["workload_id"] == workload_id and row["endpoint_id"] == endpoint_id]
    if len(matches) != 1:
        raise ValueError("No publishable endpoint " + str(workload_id)[:64] + "/" + str(endpoint_id)[:64])
    row = matches[0]
    if row.get("hostnames") is not None and name not in row["hostnames"]:
        raise ValueError("Endpoint " + workload_id + "/" + endpoint_id + " may only be published as "
                         + ", ".join(row["hostnames"]) + " (its application allows only these hostnames)")
    result = {"hostname": name, **{key: row[key] for key in ROUTE_KEYS[1:]}}
    check_route(config, result)
    return result


def _resolve(config, item, gateway_ip=None):
    """(snapshot, configured endpoint policy or None) of one validated route."""
    if not isinstance(item, dict) or not set(ROUTE_KEYS) <= set(item):
        raise ValueError("Route needs " + ", ".join(ROUTE_KEYS))
    snapshot = {key: item[key] for key in ROUTE_KEYS}
    _zone_name(config["zone"], snapshot["hostname"], "route hostname")
    label = snapshot["hostname"]
    _identifier(snapshot["workload_id"], "route workload_id")
    _identifier(snapshot["endpoint_id"], "route endpoint_id")
    if snapshot["workload_id"] in (config["gateway_id"], config["dns_id"]):
        raise ValueError("Route " + label + " targets the gateway or DNS instance")
    lan_address(snapshot["address"], "route " + label + " address")
    _port(snapshot["port"], "route " + label + " port")
    _check_target(snapshot["profile"], snapshot["scheme"], "route " + label)
    key = (snapshot["workload_id"], snapshot["endpoint_id"])
    legacy = next((e for e in config["observed_endpoints"] if (e["workload_id"], e["endpoint_id"]) == key), None)
    trusted = legacy or next((e for e in config.get("upstream_policies", [])
                              if (e["workload_id"], e["endpoint_id"]) == key), None)
    if trusted is None and snapshot["profile"] != "plain":
        raise ValueError("Route " + label + ": profile " + snapshot["profile"] + " needs a configured upstream policy")
    if trusted is not None:
        fields = ("address", "port", "scheme", "profile") if legacy is not None else ("profile",)
        if any(trusted[k] != snapshot[k] for k in fields):
            raise ValueError("Route " + label + " no longer matches its configured endpoint policy")
        if trusted["hostnames"] is not None and label not in trusted["hostnames"]:
            raise ValueError("Route " + label + " is not an allowed hostname of its endpoint")
    if gateway_ip is not None and snapshot["address"] == gateway_ip and snapshot["port"] in (80, 443):
        raise ValueError("Route " + label + " points at the gateway's own listener")
    return snapshot, trusted


def check_route(config, item, gateway_ip=None):
    """Validate one stored route snapshot (extra keys such as `url` are ignored); returns its exact snapshot."""
    return _resolve(config, item, gateway_ip)[0]


def probe_value(item):
    """The marker the gateway answers on PROBE_PATH for this route: SHA-256 over the renderer version and the
    route snapshot (only its seven snapshot keys)."""
    snapshot = {key: item[key] for key in ROUTE_KEYS}
    text = RENDER_VERSION + "\n" + json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode()).hexdigest()


def ca_files(config, routes):
    """Sorted CA file names (gateway configuration files, mounted in CA_DIRECTORY) the routes' upstreams need."""
    return sorted({trusted["ca_file"] for _, trusted in (_resolve(config, item) for item in routes)
                   if trusted is not None and trusted["ca_file"] is not None})


# ----------------------------------------------------------------------------------------------- render
_BASELINE = """{
    admin off
    persist_config off
    skip_install_trust
    auto_https disable_redirects
    https_port 8443
    servers {
        protocols h1 h2
    }
}

(lan_tls) {
    tls internal
}

http://:8081 {
    @ca {
        host GATEWAY_IP
        path /caddy-root.crt
        method GET HEAD
    }
    handle @ca {
        root * /data/caddy/pki/authorities/local
        rewrite * /root.crt
        header Content-Type application/x-x509-ca-cert
        header Content-Disposition "attachment; filename=CA_FILENAME"
        header Cache-Control "no-store"
        file_server
    }
KNOWN    handle {
        respond 404
    }
}

http://:9090 {
    respond /healthz 200
}
"""


def _upstream(item, trusted):
    target = item["address"] + ":" + str(item["port"])
    if item["profile"] == "verified-https":
        return ["reverse_proxy https://" + target + " {", "    transport http {",
                "        tls_trust_pool file " + CA_DIRECTORY + trusted["ca_file"], "    }", "}"]
    if item["profile"] == "rewrite-redirect":
        # Validated names and addresses hold only [a-z0-9.-]; escaping the dots makes the pattern exact.
        pattern = "^http://(?:" + target.replace(".", "\\.") + "|" + item["hostname"].replace(".", "\\.") + ")(/.*)$"
        return ["reverse_proxy " + target + " {",
                "    header_down Location \"" + pattern + "\" \"https://" + item["hostname"] + "$1\"", "}"]
    return ["reverse_proxy " + target]


def _site(item, trusted):
    lines = [item["hostname"] + " {", "    import lan_tls", "    @switchyard_route {", "        method GET",
             "        path " + PROBE_PATH, "    }", "    handle @switchyard_route {",
             "        respond \"" + probe_value(item) + "\" 200", "    }", "    handle {"]
    lines += ["        " + line for line in _upstream(item, trusted)]
    return "\n".join(lines + ["    }", "}"]) + "\n"


def render(config, gateway_ip, routes):
    """The gateway's complete Caddyfile for these routes (deterministic: sites sorted by hostname)."""
    lan_address(gateway_ip, "gateway address")
    if config.get("gateway_ip") is not None and gateway_ip != config["gateway_ip"]:
        raise ValueError("Gateway address " + gateway_ip + " differs from the configured " + config["gateway_ip"])
    if not isinstance(routes, list) or len(routes) > MAX_ROUTES:
        raise ValueError("Routes must be a list of at most " + str(MAX_ROUTES))
    resolved = sorted((_resolve(config, item, gateway_ip) for item in routes), key=lambda pair: pair[0]["hostname"])
    names = [snapshot["hostname"] for snapshot, _ in resolved]
    if len(set(names)) != len(names):
        raise ValueError("Duplicate route hostname")
    known = ""
    if names:
        known = ("    @known host " + " ".join(names) + "\n    handle @known {\n        redir https://{host}{uri} 308\n    }\n")
    text = (_BASELINE.replace("GATEWAY_IP", gateway_ip)
            .replace("CA_FILENAME", config["zone"].replace(".", "-") + "-caddy-ca.crt")
            .replace("KNOWN", known))
    text += "".join("\n" + _site(snapshot, trusted) for snapshot, trusted in resolved)
    if len(text.encode()) > spec.CONFIG_BYTES_LIMIT:
        raise ValueError("Rendered Caddyfile exceeds " + str(spec.CONFIG_BYTES_LIMIT) + " bytes")
    if spec.parameter_references(text):  # the deploy renderer would substitute `{{id}}`; never emit one
        raise ValueError("Rendered Caddyfile contains a parameter reference")
    return text
