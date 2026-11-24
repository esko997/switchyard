"""Read-only inspection of an Ansible repository: path safety, playbooks, inventories, roles and the variables a
playbook exposes, without running a playbook. See docs/ansible.md, "Variables".

YAML is parsed by `ansible_yaml.py` under the pinned runner's own Python (it has PyYAML; Switchyard adds no
dependency). Merged inventory values come from the pinned `ansible-inventory --list`. Both run locally and never
contact a host. Templates are never evaluated: a Jinja expression is shown as its text.
"""
import json
import math
import os
from pathlib import Path
import re

from .ansible_runner import run_process

HELPER = Path(__file__).with_name("ansible_yaml.py")
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox", "collections"}
YAML_SUFFIXES = (".yml", ".yaml")
INVENTORY_DIRS = {"inventory", "inventories"}
INVENTORY_NAMES = {"hosts", "inventory", "hosts.ini", "inventory.ini", "hosts.yml", "hosts.yaml",
                   "inventory.yml", "inventory.yaml"}
MAX_FILES = 1500
MAX_DEPTH = 8
MAX_PLAYBOOKS = 16
MAX_INVENTORIES = 6
RESERVED_PREFIXES = ("ansible_", "switchyard_")
TOP_KEY = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*:(\s|$)")
VAR_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
ROLE_ACTIONS = {prefix + action for prefix in ("", "ansible.builtin.", "ansible.legacy.")
                for action in ("include_role", "import_role")}
# Ansible variable precedence, lowest first, for the layers discovery can see. Extra vars beat all of them.
LAYERS = ("role_default", "inventory", "play_vars", "vars_prompt", "vars_files", "role_vars")
LAYER_LABELS = {"role_default": "role default", "inventory": "repository inventory", "play_vars": "play vars",
                "vars_prompt": "play vars_prompt", "vars_files": "play vars_files", "role_vars": "role vars"}
TYPES = {"str", "path", "bool", "int", "float", "list", "dict", "raw"}
SPEC_TYPES = {"str": "str", "path": "path", "bool": "bool", "int": "int", "float": "float", "list": "list",
              "dict": "dict", "raw": "raw", "jsonarg": "raw", "json": "raw", "bytes": "str", "bits": "str"}
MAX_TEXT = 4096
MAX_VALUE_BYTES = 16384


# ---- paths -------------------------------------------------------------------------------------

def _owned(path, what):
    info = path.stat()
    if info.st_uid != os.getuid():
        raise ValueError(f"{what} is not the operator's own file")
    if info.st_mode & 0o002:
        raise ValueError(f"{what} is writable by every user")


def owned_root(path, home):
    """An operator-given directory: absolute (~ allowed), inside the operator's home after resolving every
    symlink, a directory owned by the operator and not world-writable."""
    if not isinstance(path, str) or not path.strip() or len(path) > 1024 or "\0" in path:
        raise ValueError("Give the repository directory as an absolute path")
    raw = Path(path.strip()).expanduser()
    if not raw.is_absolute():
        raise ValueError("Give the repository directory as an absolute path (~ allowed)")
    home = Path(home).resolve()
    try:
        resolved = raw.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError("No such directory") from None
    if home not in resolved.parents:
        raise ValueError("Repositories must be inside the operator's home directory "
                         + ("(a symlink leads outside it)" if raw != resolved else ""))
    if not resolved.is_dir():
        raise ValueError("Not a directory")
    _owned(resolved, "The repository directory")
    return resolved


def owned_file(repo, relative, what):
    """A file inside the repo, after resolving symlinks, owned by the operator."""
    try:
        path = (repo / relative).resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError(f"{what} {relative} does not exist") from None
    if repo not in path.parents:
        raise ValueError(f"{what} {relative} leads outside the repository")
    if not path.is_file():
        raise ValueError(f"{what} {relative} is not a file")
    _owned(path, f"{what} {relative}")
    return path


def scan(repo):
    """YAML files and inventory candidates in the repo, skipping hidden, virtualenv and dependency trees.
    Symlinks that lead outside the repo and files owned by someone else are skipped and reported."""
    yaml_files, inventory_files, skipped = [], [], []
    truncated = False
    uid = os.getuid()
    for directory, dirnames, filenames in os.walk(repo, followlinks=False):
        relative = Path(directory).relative_to(repo)
        dirnames[:] = sorted(name for name in dirnames if name not in SKIP_DIRS and not name.startswith(".")
                             and len(relative.parts) < MAX_DEPTH)
        for name in sorted(filenames):
            rel = relative / name
            in_inventory_dir = bool(INVENTORY_DIRS & set(rel.parts[:-1]))
            is_yaml = name.endswith(YAML_SUFFIXES)
            if not is_yaml and not (in_inventory_dir or (len(rel.parts) == 1 and name in INVENTORY_NAMES)):
                continue
            path = repo / rel
            try:
                if path.is_symlink() and repo not in path.resolve().parents:
                    skipped.append({"path": str(rel), "reason": "symlink leading outside the repository"})
                    continue
                if path.stat().st_uid != uid:
                    skipped.append({"path": str(rel), "reason": "not owned by the operator"})
                    continue
            except OSError:
                skipped.append({"path": str(rel), "reason": "unreadable"})
                continue
            if len(yaml_files) + len(inventory_files) >= MAX_FILES:
                truncated = True
                break
            (yaml_files if is_yaml else inventory_files).append(str(rel))
            if is_yaml and in_inventory_dir:
                inventory_files.append(str(rel))
    return {"yaml": yaml_files, "inventory": inventory_files, "skipped": skipped[:50], "truncated": truncated}


# ---- runner calls (local only) -----------------------------------------------------------------

def load_yaml(runner, repo, files):
    """Parse files with the pinned runner's PyYAML; {relative path: {"data"|"error": ...}}."""
    if not files:
        return {}
    request = json.dumps({"root": str(repo), "files": list(files)}).encode()
    result = run_process(runner.command("python", "-I", str(HELPER)), cwd=str(runner.root), env=runner.environment(),
                         timeout=300, stdout_limit=32 * 1048576, stdin_data=request)
    if result.exit_code != 0 or result.stdout_overflow:
        raise ValueError("Could not read the repository's YAML with the pinned runner")
    try:
        loaded = json.loads(result.stdout)
    except ValueError as error:
        raise ValueError("The YAML reader returned invalid output") from error
    if not isinstance(loaded, dict):
        raise ValueError("The YAML reader returned invalid output")
    return loaded


def inventory_listing(runner, repo, inventory, playbook_dir):
    """The pinned `ansible-inventory --list` of a repo inventory (local; vaulted values stay encrypted)."""
    result = run_process(runner.command("ansible-inventory", "-i", str(inventory), "--playbook-dir", str(playbook_dir),
                                        "--list"),
                         cwd=str(repo), env=runner.environment(), timeout=300, stdout_limit=4 * 1048576)
    if result.exit_code != 0 or result.stdout_overflow:
        raise ValueError("Could not read the playbook repo inventory with the pinned runner")
    try:
        data = json.loads(result.stdout)
        if not isinstance(data, dict):
            raise ValueError
    except ValueError as error:
        raise ValueError("Repo inventory output is not valid JSON") from error
    return data


def membership(listing, names):
    """(matched inventory host name, its groups including ancestors, its merged vars) or (None, set(), {})."""
    hostvars = (listing.get("_meta") or {}).get("hostvars") or {}
    groups = {name: value for name, value in listing.items() if name != "_meta" and isinstance(value, dict)}

    def member(name):
        return name in hostvars or any(name in (value.get("hosts") or []) for value in groups.values())

    match = next((name for name in names if name and member(name)), None)
    if match is None:
        return None, set(), {}
    parents = {}
    for name, value in groups.items():
        for child in value.get("children") or []:
            parents.setdefault(child, set()).add(name)
    found = {name for name, value in groups.items() if match in (value.get("hosts") or [])}
    pending = list(found)
    while pending:
        for parent in parents.get(pending.pop(), ()):
            if parent not in found:
                found.add(parent)
                pending.append(parent)
    variables = hostvars.get(match) or {}
    return match, found - {"all", "ungrouped"}, variables if isinstance(variables, dict) else {}


def inventory_summary(listing):
    groups = sorted(name for name, value in listing.items()
                    if name not in {"_meta", "all", "ungrouped"} and isinstance(value, dict))
    hosts = set((listing.get("_meta") or {}).get("hostvars") or {})
    for name, value in listing.items():
        if name != "_meta" and isinstance(value, dict):
            hosts.update(item for item in value.get("hosts") or [] if isinstance(item, str))
    return groups, sorted(hosts)


# ---- values -------------------------------------------------------------------------------------

def vaulted(value):
    if isinstance(value, dict):
        return value.get("__vault__") is True or "__ansible_vault" in value or any(vaulted(item) for item in value.values())
    if isinstance(value, list):
        return any(vaulted(item) for item in value)
    return False


def templated(value):
    if isinstance(value, str):
        return "{{" in value or "{%" in value
    if isinstance(value, dict):
        return any(templated(item) for item in value.values())
    if isinstance(value, list):
        return any(templated(item) for item in value)
    return False


def infer(value):
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "dict"
    return "raw"


def _elements(value):
    kinds = {infer(item) for item in value} if isinstance(value, list) else set()
    return kinds.pop() if len(kinds) == 1 and kinds <= {"str", "int", "float", "bool"} else None


def comment_blocks(text):
    """Top-level key -> the comment lines directly above it (no blank line between)."""
    result, block = {}, []
    for line in text.splitlines():
        if line.startswith("#"):
            block.append(line[1:].strip())
            continue
        found = TOP_KEY.match(line)
        if found and block:
            result[found[1]] = " ".join(part for part in block if part)[:MAX_TEXT]
        block = []
    return result


def _description(value):
    if isinstance(value, list):
        value = " ".join(str(item) for item in value if isinstance(item, (str, int, float)))
    return value[:MAX_TEXT] if isinstance(value, str) and value.strip() else None


# ---- the playbook model -------------------------------------------------------------------------

class _Model:
    def __init__(self, loaded, repo):
        self.loaded = loaded
        self.repo = repo
        self.paths = set(loaded)
        self.problems = []
        self.variables = {}
        self.roles = []
        self._seen_roles = set()

    def data(self, relative):
        entry = self.loaded.get(str(relative))
        if not isinstance(entry, dict):
            return None
        if "error" in entry:
            self.problems.append(f"{relative}: {entry['error']}")
            return None
        return entry.get("data")

    def first(self, *candidates):
        for candidate in candidates:
            if str(candidate) in self.paths:
                return str(candidate)
        return None

    def under(self, directory):
        prefix = str(directory) + "/"
        return sorted(path for path in self.paths if path.startswith(prefix) and path.endswith(YAML_SUFFIXES))

    def var(self, name):
        return self.variables.setdefault(name, {
            "name": name, "type": None, "declared": False, "choices": None, "elements": None, "required": False,
            "description": None, "documented_default": None, "secret": False, "secret_reasons": [],
            "templated": False, "sources": []})

    def add(self, name, layer, origin, value, *, description=None):
        if not isinstance(name, str) or not VAR_NAME.fullmatch(name) or name.startswith(RESERVED_PREFIXES):
            return
        var = self.var(name)
        source = {"layer": layer, "label": LAYER_LABELS[layer], "origin": origin, "value": value}
        var["sources"].append(source)
        if vaulted(value):
            var["secret"] = True
            var["secret_reasons"].append(f"vaulted in {origin}")
        if templated(value):
            var["templated"] = True
        if description and not var["description"]:
            var["description"] = description
        if not var["declared"] and var["type"] is None and value is not None and not vaulted(value):
            var["type"] = infer(value)
            var["elements"] = _elements(value)

    def argument_specs(self, specs, origin):
        main = (specs or {}).get("main") if isinstance(specs, dict) else None
        options = main.get("options") if isinstance(main, dict) else None
        if not isinstance(options, dict):
            return
        for name, option in options.items():
            if not isinstance(name, str) or not VAR_NAME.fullmatch(name) or not isinstance(option, dict):
                continue
            var = self.var(name)
            var["declared"] = True
            var["type"] = SPEC_TYPES.get(option.get("type", "str"), "raw")
            choices = option.get("choices")
            var["choices"] = choices if isinstance(choices, list) and len(choices) <= 256 else None
            elements = option.get("elements")
            var["elements"] = SPEC_TYPES.get(elements) if isinstance(elements, str) else None
            var["required"] = option.get("required") is True
            var["description"] = _description(option.get("description")) or var["description"]
            if "default" in option:
                var["documented_default"] = option["default"]
            if option.get("no_log") is True:
                var["secret"] = True
                var["secret_reasons"].append(f"no_log in {origin}")

    def role(self, name, playbook_dir, depth=0):
        if not isinstance(name, str) or not name.strip():
            return
        if templated(name):
            self.problems.append(f"Role name {name!r} is a template; its variables are not shown")
            return
        if name in self._seen_roles or depth > 8:
            return
        self._seen_roles.add(name)
        found = None
        if "/" not in name and "." not in name:
            for base in (playbook_dir / "roles" / name, Path("roles") / name):
                if any(path.startswith(str(base) + "/") for path in self.paths):
                    found = base
                    break
        entry = {"name": name, "path": str(found) if found else None,
                 "note": None if found else ("collection role, not inspected" if "." in name
                                             else "not found in the repository's roles directories")}
        self.roles.append(entry)
        if found is None:
            return
        meta_path = self.first(found / "meta/main.yml", found / "meta/main.yaml")
        meta = self.data(meta_path) if meta_path else None
        spec_path = self.first(found / "meta/argument_specs.yml", found / "meta/argument_specs.yaml")
        specs = self.data(spec_path) if spec_path else None
        if isinstance(specs, dict) and "argument_specs" in specs:
            self.argument_specs(specs["argument_specs"], spec_path)
        elif isinstance(meta, dict) and "argument_specs" in meta:
            self.argument_specs(meta["argument_specs"], meta_path)
        for layer, folder in (("role_default", "defaults"), ("role_vars", "vars")):
            files = [path for path in (self.first(found / folder / "main.yml", found / folder / "main.yaml"),) if path]
            files += self.under(found / folder / "main")
            for path in files:
                data = self.data(path)
                if data is None:
                    continue
                if not isinstance(data, dict):
                    self.problems.append(f"{path}: not a mapping of variables")
                    continue
                comments = comment_blocks(self._text(path)) if layer == "role_default" else {}
                for key, value in data.items():
                    self.add(key, layer, path, value, description=comments.get(key))
        for dependency in (meta or {}).get("dependencies") or [] if isinstance(meta, dict) else []:
            self.role(dependency if isinstance(dependency, str) else
                      (dependency.get("role") or dependency.get("name")) if isinstance(dependency, dict) else None,
                      playbook_dir, depth + 1)
        for path in self.under(found / "tasks") + self.under(found / "handlers"):
            for name_ in self.task_roles(self.data(path)):
                self.role(name_, playbook_dir, depth + 1)

    def _text(self, relative):
        try:
            with open(self.repo / relative, "rb") as stream:
                return stream.read(1048576).decode("utf-8", "replace")
        except OSError:
            return ""

    def task_roles(self, tasks, depth=0):
        names = []
        if not isinstance(tasks, list) or depth > 20:
            return names
        for task in tasks:
            if not isinstance(task, dict):
                continue
            for action in ROLE_ACTIONS & set(task):
                value = task[action]
                if isinstance(value, dict) and isinstance(value.get("name"), str):
                    names.append(value["name"])
            for key in ("block", "rescue", "always"):
                names += self.task_roles(task.get(key), depth + 1)
        return names


def looks_like_playbook(data):
    return (isinstance(data, list) and bool(data) and all(isinstance(play, dict) for play in data)
            and all(("hosts" in play or "import_playbook" in play or "ansible.builtin.import_playbook" in play)
                    for play in data))


def model(loaded, repo, playbook, depth=0, _model=None):
    """Plays, roles and variables of one playbook from already loaded YAML."""
    current = _model or _Model(loaded, repo)
    playbook_dir = Path(playbook).parent
    data = current.data(playbook)
    plays = []
    if not looks_like_playbook(data):
        current.problems.append(f"{playbook} is not a playbook (a list of plays)")
        data = []
    for index, play in enumerate(data):
        imported = play.get("import_playbook") or play.get("ansible.builtin.import_playbook")
        if imported:
            target = str((playbook_dir / str(imported))) if not templated(imported) else None
            plays.append({"import_playbook": str(imported)})
            if target and target in current.paths and depth < 4:
                plays += model(loaded, repo, target, depth + 1, current)["plays"]
            continue
        name = play.get("name")
        origin = f"{playbook} play {index + 1}"
        variables = play.get("vars")
        if isinstance(variables, dict):
            for key, value in variables.items():
                current.add(key, "play_vars", origin, value)
        for item in play.get("vars_files") or [] if isinstance(play.get("vars_files"), list) else []:
            path = str(playbook_dir / item) if isinstance(item, str) and not templated(item) else None
            values = current.data(path) if path in current.paths else None
            if isinstance(values, dict):
                for key, value in values.items():
                    current.add(key, "vars_files", path, value)
            else:
                current.problems.append(f"{origin}: vars_files entry {item!r} was not read")
        for prompt in play.get("vars_prompt") or [] if isinstance(play.get("vars_prompt"), list) else []:
            if not isinstance(prompt, dict) or not isinstance(prompt.get("name"), str):
                continue
            current.add(prompt["name"], "vars_prompt", origin, prompt.get("default"),
                        description=_description(prompt.get("prompt")))
            var = current.variables.get(prompt["name"])
            if var is not None:
                var["prompted"] = True
                if prompt.get("private", True) is not False:
                    var["secret"] = True
                    var["secret_reasons"].append(f"private vars_prompt in {origin}")
        role_names = []
        for role in play.get("roles") or [] if isinstance(play.get("roles"), list) else []:
            role_names.append(role if isinstance(role, str) else
                              (role.get("role") or role.get("name")) if isinstance(role, dict) else None)
        for key in ("pre_tasks", "tasks", "post_tasks", "handlers"):
            role_names += current.task_roles(play.get(key))
        role_names = [name for name in role_names if isinstance(name, str)]
        for role_name in role_names:
            current.role(role_name, playbook_dir)
        hosts = play.get("hosts")
        plays.append({"name": name if isinstance(name, str) else None,
                      "hosts": hosts if isinstance(hosts, str) else ", ".join(str(item) for item in hosts)
                      if isinstance(hosts, list) else None,
                      "become": play.get("become") is True, "roles": role_names})
    return {"plays": plays, "roles": current.roles, "variables": current.variables, "problems": current.problems}


def host_files(paths, directory, kind, name):
    base = (Path(directory) / kind / name) if str(directory) not in {"", "."} else Path(kind) / name
    found = [str(base) + suffix for suffix in YAML_SUFFIXES if str(base) + suffix in paths]
    prefix = str(base) + "/"
    return found + sorted(path for path in paths if path.startswith(prefix) and path.endswith(YAML_SUFFIXES))


def host_values(listing, loaded, record, *, inventory, playbook):
    """What the repo inventory sets for one registry host, each value attributed to its likely file."""
    names = [record["id"], (record.get("collector") or {}).get("expected_hostname")]
    match, groups, variables = membership(listing, names)
    if match is None:
        return {"inventory_host": None, "values": {},
                "error": f"not in the repository inventory as {' or '.join(dict.fromkeys(name for name in names if name))}"}
    paths = set(loaded)
    directories = list(dict.fromkeys([str(Path(inventory).parent), str(Path(playbook).parent)]))
    host_sources = [path for directory in directories for path in host_files(paths, directory, "host_vars", match)]
    group_sources = [path for directory in directories for group in sorted(groups) + ["all"]
                     for path in host_files(paths, directory, "group_vars", group)]

    def origin(key):
        for path in host_sources + group_sources:
            data = (loaded.get(path) or {}).get("data")
            if isinstance(data, dict) and key in data:
                return path
        return inventory

    values = {}
    for key, value in variables.items():
        if not isinstance(key, str) or key.startswith(RESERVED_PREFIXES):
            continue
        values[key] = {"value": value, "origin": origin(key), "vaulted": vaulted(value), "templated": templated(value)}
    return {"inventory_host": match, "groups": sorted(groups), "values": values}


def finish(variables, *, allowed, secret_flags, host_layers):
    """Public variable list: type, sources, per-host effective value; secret values never leave this function."""
    result = []
    for name in sorted(set(variables) | set(allowed)):
        var = variables.get(name) or {"name": name, "type": None, "declared": False, "choices": None, "elements": None,
                                      "required": False, "description": None, "documented_default": None,
                                      "secret": False, "secret_reasons": [], "templated": False, "sources": [],
                                      "undiscovered": True}
        var = dict(var)
        if name in secret_flags:
            var["secret"] = True
            var["secret_reasons"] = var["secret_reasons"] + ["flagged secret in the registration"]
        for host_id, layer in host_layers.items():
            entry = (layer.get("values") or {}).get(name)
            if entry and entry["vaulted"]:
                var["secret"] = True
                var["secret_reasons"] = var["secret_reasons"] + [f"vaulted in {entry['origin']} for {host_id}"]
        var["type"] = var["type"] or "str"
        var["overridable"] = name in allowed
        sources = sorted(var["sources"], key=lambda item: LAYERS.index(item["layer"]))
        effective = {}
        for host_id, layer in host_layers.items():
            stack = [item for item in sources if item["layer"] == "role_default"]
            entry = (layer.get("values") or {}).get(name)
            if entry:
                stack.append({"layer": "inventory", "label": LAYER_LABELS["inventory"], "origin": entry["origin"],
                              "value": entry["value"]})
            stack += [item for item in sources if item["layer"] != "role_default"]
            top = stack[-1] if stack else None
            effective[host_id] = None if top is None else {
                "source": top["label"], "origin": top["origin"],
                **({"hidden": True} if var["secret"] else {"value": top["value"], "templated": templated(top["value"])})}
        if var["secret"]:
            sources = [{key: value for key, value in item.items() if key != "value"} | {"hidden": True} for item in sources]
            var["documented_default"] = None
        var["sources"] = sources
        top = sources[-1] if sources else None
        var["default"] = None if top is None or var["secret"] else {"value": top["value"], "source": top["label"],
                                                                     "origin": top["origin"]}
        var["effective"] = effective
        result.append(var)
    return result


# ---- validation of operator-supplied values ------------------------------------------------------

def _check(value, kind, choices, elements, name, depth=0):
    if kind in {"str", "path"}:
        if not isinstance(value, str) or len(value) > MAX_TEXT or "\0" in value:
            raise ValueError(f"{name} must be text of at most {MAX_TEXT} characters")
    elif kind == "bool":
        if type(value) is not bool:
            raise ValueError(f"{name} must be true or false")
    elif kind == "int":
        if type(value) is not int:
            raise ValueError(f"{name} must be a whole number")
    elif kind == "float":
        if type(value) not in {int, float} or not math.isfinite(value):
            raise ValueError(f"{name} must be a number")
    elif kind == "list":
        if not isinstance(value, list) or len(value) > 256:
            raise ValueError(f"{name} must be a list of at most 256 items")
        for item in value:
            if elements:
                _check(item, elements, choices, None, f"{name} item", depth + 1)
            elif choices is not None and item not in choices:
                raise ValueError(f"{name} items must be among the declared choices")
        return
    elif kind == "dict":
        if not isinstance(value, dict):
            raise ValueError(f"{name} must be a mapping")
    if choices is not None and kind != "list" and value not in choices:
        raise ValueError(f"{name} must be one of the declared choices")


def validate_values(variables, values):
    """Type-check operator overrides against the declared or inferred type; only overridable names pass."""
    if not isinstance(values, dict) or len(values) > 32:
        raise ValueError("Overrides must be a mapping of at most 32 variables")
    known = {var["name"]: var for var in variables}
    result = {}
    for name, value in values.items():
        var = known.get(name)
        if var is None or not var["overridable"]:
            raise ValueError(f"Variable {name!r} may not be overridden for this playbook")
        if len(json.dumps(value, allow_nan=False)) > MAX_VALUE_BYTES:
            raise ValueError(f"{name} is larger than {MAX_VALUE_BYTES} bytes")
        _check(value, var["type"], var.get("choices"), var.get("elements"), name)
        result[name] = value
    return result


def parse_text(var, text):
    """A CLI NAME=VALUE: text for str/path variables, otherwise JSON (true/false/yes/no for booleans)."""
    if var["type"] in {"str", "path"}:
        return text
    if var["type"] == "bool" and text.lower() in {"true", "false", "yes", "no"}:
        return text.lower() in {"true", "yes"}
    try:
        return json.loads(text)
    except ValueError:
        raise ValueError(f"{var['name']} is {var['type']}: give it as JSON") from None
