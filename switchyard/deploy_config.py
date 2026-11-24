"""Configuration files of deployed applications: parameters, `{{parameter}}` substitution, generators.

Pure functions, no host access. Files are rendered at plan time from the instance application
(parameter values, operator records) and, for the `registry-hosts` generator, the host registry as it is
at that moment; the plan carries every file's text, size and SHA-256. There is no template language:
`{{parameter-id}}` is replaced by the parameter's value (instance `value`, else template `default`),
nothing else is interpreted. Secret references are refused (no secret values in configuration files).
"""
from copy import deepcopy
import difflib
import hashlib
from ipaddress import ip_address
import re

from . import spec

LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
DIFF_LIMIT = 16384
# All files of one application together: they travel in one remote payload (transport input bound 2 MiB,
# JSON escaping can double them) and must be refused at plan time, never as a transport error after intent.
TOTAL_BYTES_LIMIT = 524288


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def parameter_values(app):
    """Effective values: the instance's `value`, else the template `default`; None when neither is set."""
    return {p["id"]: p.get("value") if p.get("value") is not None else p.get("default") for p in app.get("parameters", [])}


def set_parameters(app, values):
    """A copy of the instance application with operator parameter values recorded (validated by format)."""
    app = deepcopy(app)
    declared = {p["id"]: p for p in app.get("parameters", [])}
    unknown = sorted(set(values) - set(declared))
    if unknown:
        raise ValueError("Unknown parameter(s): " + ", ".join(unknown) + "; declared: " + (", ".join(sorted(declared)) or "none"))
    for key, value in values.items():
        try:
            spec.check_parameter_value(declared[key].get("format", "text"), value)
            spec.Parameter.model_validate({**declared[key], "value": value})
        except ValueError as error:
            raise ValueError("Invalid value for parameter " + key + ": " + str(error).splitlines()[-1].strip()) from None
        declared[key]["value"] = value
    return app


def substitute(text, values):
    """Replace every `{{id}}` by its value; a referenced parameter without a value is an error."""
    names = spec.parameter_references(text)
    missing = sorted({name for name in names if values.get(name) is None})
    if missing:
        raise ValueError("Parameter(s) without a value: " + ", ".join(missing) + " (pass --param NAME=VALUE)")
    return spec.PARAMETER_REFERENCE.sub(lambda match: values[match.group(1)], text)


def parameter_formats(app):
    return {p["id"]: p.get("format", "text") for p in app.get("parameters", [])}


def expand_args(args, values, formats):
    """Container args with `{{parameter}}` substituted; an element that is exactly `{{list}}` of an
    `argument-list` parameter becomes one arg per token (no shell is involved anywhere)."""
    result = []
    for arg in args:
        names = spec.parameter_references(arg)
        if len(names) == 1 and arg == "{{" + names[0] + "}}" and formats.get(names[0]) == "argument-list":
            result += substitute(arg, values).split(" ")
        else:
            result.append(substitute(arg, values))
    return result


def substitute_path(text, values):
    """A volume subPath after substitution: a relative path without `.`/`..`/empty segments (it cannot leave its
    dataset; the host additionally refuses symlinks on the way)."""
    path = substitute(text, values)
    try:
        spec.check_parameter_value("relative-path", path)
    except ValueError as error:
        raise ValueError("subPath " + repr(path) + ": " + str(error)) from None
    return path


def zone_of(generator, values):
    zone = substitute(generator["zone"], values)
    try:
        return spec.check_parameter_value("dns-name", zone)
    except ValueError as error:
        raise ValueError("Generator zone " + repr(zone) + ": " + str(error)) from None


def registry_addresses(hosts):
    """Registry hosts with a LAN address the registry knows (the SSH target's IP literal) and the skipped ones."""
    entries, skipped = [], []
    for record in sorted(hosts or [], key=lambda item: item["id"]):
        config = record.get("collector")
        host_id = record["id"]
        if not config:
            skipped.append({"host_id": host_id, "reason": "no connection in the registry"})
            continue
        if config.get("transport") != "ssh":
            skipped.append({"host_id": host_id, "reason": str(config.get("transport")) + " transport: the registry stores no LAN address"})
            continue
        target = str(config.get("target", "")).rsplit("@", 1)[-1]
        try:
            address = ip_address(target)
        except ValueError:
            skipped.append({"host_id": host_id, "reason": "SSH target " + target + " is a name, not an address"})
            continue
        if getattr(address, "scope_id", None):
            skipped.append({"host_id": host_id, "reason": "SSH target " + target + " has an IPv6 scope ID"})
            continue
        if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
            skipped.append({"host_id": host_id, "reason": "SSH target " + target + " is not a LAN unicast address"})
            continue
        if not LABEL.match(host_id):
            skipped.append({"host_id": host_id, "reason": "host ID is not a DNS label"})
            continue
        entries.append({"host_id": host_id, "address": str(address)})
    return entries, skipped


def _registry_dns_entries(hosts):
    """Keep stable ID aliases; add the verified SSH hostname, never a display name."""
    entries, skipped = registry_addresses(hosts)
    by_id = {item["id"]: item for item in hosts or []}
    for entry in list(entries):
        host = by_id[entry["host_id"]]
        if (host.get("verification") or {}).get("state") != "verified":
            continue
        name = host["collector"]["expected_hostname"].split(".", 1)[0].lower()
        if name == entry["host_id"]:
            continue
        if not LABEL.fullmatch(name):
            skipped.append({"host_id": host["id"], "reason": "verified hostname is not a DNS label"})
            continue
        entries.append({**entry, "label": name})
    return entries, skipped


def registry_dns_names(hosts):
    """Relative names reserved by the host registry, including verified hostname aliases."""
    return {entry.get("label", entry["host_id"]) for entry in _registry_dns_entries(hosts)[0]}


def render_registry_hosts(generator, values, hosts):
    """Hosts-format text (`address name.zone`) and a summary of records and skipped hosts."""
    if hosts is None:  # never render an empty list silently
        raise ValueError("The registry-hosts generator needs the host registry; this deploy manager was built without it")
    zone = zone_of(generator, values)
    entries, skipped = _registry_dns_entries(hosts)
    records = []
    claims = {}
    explicit = {record["name"] + "." + zone for record in generator.get("records", [])}
    for entry in entries:
        name = entry.get("label", entry["host_id"]) + "." + zone
        claims.setdefault(name, []).append(entry)
    for name, owners in claims.items():
        # A verified hostname cannot take over an existing ID alias.
        ids = [entry for entry in owners if "label" not in entry]
        preferred = ids or owners
        if name in explicit or len(preferred) > 1 or len(name) > 253:
            reason = (name + " is already an explicit DNS record" if name in explicit else
                      name + " is claimed by more than one registry host" if len(preferred) > 1 else
                      "name longer than 253 characters")
            skipped.extend({"host_id": entry["host_id"], "reason": reason} for entry in owners)
            continue
        entry = preferred[0]
        if len(owners) > 1:
            skipped.extend({"host_id": other["host_id"], "reason": name + " is reserved by registry host " + entry["host_id"]}
                           for other in owners if other != entry)
        records.append({"name": name, "address": entry["address"], "source": "registry:" + entry["host_id"]})
    for record in sorted(generator.get("records", []), key=lambda item: item["name"]):
        name = record["name"] + "." + zone
        if len(name) > 253:
            raise ValueError("Record name " + name + " is longer than 253 characters")
        records.append({"name": name, "address": record["address"], "source": "operator"})
    lines = ["# Generated by Switchyard (generator registry-hosts, zone " + zone + "); do not edit:",
             "# changes are made with `switchyard deploy refresh-plan`."]
    lines += [record["address"] + " " + record["name"] for record in records]
    return "\n".join(lines) + "\n", {"kind": "registry-hosts", "zone": zone, "records": records,
                                      "skipped": sorted(skipped, key=lambda item: item["host_id"])}


def render_files(app, hosts):
    """Every configuration file of the (instance) application, rendered: list of dicts with text and hashes."""
    values = parameter_values(app)
    result = []
    for item in app.get("config_files", []):
        generated = None
        if item.get("content") is not None:
            text = substitute(item["content"], values)
        elif item["generator"]["kind"] == "registry-hosts":
            text, generated = render_registry_hosts(item["generator"], values, hosts)
        else:  # the spec admits no other generator
            raise ValueError("Unknown configuration generator")
        size = len(text.encode())
        if size > spec.CONFIG_BYTES_LIMIT:
            raise ValueError("Configuration file " + item["id"] + " renders to " + str(size) + " bytes (limit "
                             + str(spec.CONFIG_BYTES_LIMIT) + ")")
        result.append({"id": item["id"], "component": item["component"], "name": item["path"], "text": text,
                       "size": size, "sha256": sha(text), "mode": "0644", "on_change": item.get("on_change", "restart"),
                       "generator": generated})
    total = sum(item["size"] for item in result)
    if total > TOTAL_BYTES_LIMIT:
        raise ValueError("Configuration files render to " + str(total) + " bytes together (limit " + str(TOTAL_BYTES_LIMIT) + ")")
    return result


def generator_file(app):
    files = [f for f in app.get("config_files", []) if f.get("generator", {}) and f["generator"].get("kind") == "registry-hosts"]
    if len(files) != 1:
        raise ValueError("Records need exactly one registry-hosts configuration file (found " + str(len(files)) + ")")
    return files[0]


def relative_name(name, zone):
    """An operator record name: one label (relative) or a name inside the zone; stored relative to the zone."""
    name = name.strip().rstrip(".").lower() if isinstance(name, str) else ""
    if name.endswith("." + zone):
        name = name[:-len(zone) - 1]
    elif "." in name:
        raise ValueError("Record " + repr(name) + " is outside zone " + zone + " (give one label or name." + zone + ")")
    if not name or not all(LABEL.match(label) for label in name.split(".")):
        raise ValueError("Record names are lowercase LDH labels (a-z, 0-9, inner hyphens): " + repr(name))
    return name


def change_records(app, *, add=None, remove=(), hosts=None):
    """A copy of the instance application with operator records added/removed (the registry part regenerates)."""
    app = deepcopy(app)
    if not add and not remove:
        return app
    item = generator_file(app)
    zone = zone_of(item["generator"], parameter_values(app))
    records = {r["name"]: r for r in item["generator"].get("records", [])}
    reserved = {entry.get("label", entry["host_id"]): entry["host_id"]
                for entry in _registry_dns_entries(hosts)[0]} if add else {}
    for name in remove:
        key = relative_name(name, zone)
        if key not in records:
            raise ValueError("No operator record named " + key + "." + zone)
        records.pop(key)
    for name, address in (add or {}).items():
        key = relative_name(name, zone)
        if key in reserved:
            raise ValueError("Duplicate name " + key + "." + zone + ": operator record collides with registry host "
                             + reserved[key])
        if key in records:
            raise ValueError("Duplicate name " + key + "." + zone + ": an operator record already has it (remove it first)")
        try:
            spec.HostRecord.model_validate({"name": key, "address": address})
        except ValueError:
            raise ValueError("Record " + key + " needs a canonical IPv4/IPv6 address, got " + repr(address)) from None
        records[key] = {"name": key, "address": address}
    item["generator"]["records"] = [records[key] for key in sorted(records)]
    return app


def diff(old, new, name):
    """Bounded unified diff of one file (old is None for a file that does not exist yet)."""
    lines = list(difflib.unified_diff((old or "").splitlines(keepends=True), new.splitlines(keepends=True),
                                      fromfile="host/" + name if old is not None else "/dev/null", tofile="plan/" + name))
    text = "".join(lines)
    if len(text) > DIFF_LIMIT:
        text = text[:DIFF_LIMIT] + "\n... diff truncated at " + str(DIFF_LIMIT) + " characters\n"
    return text
