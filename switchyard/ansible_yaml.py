"""YAML-to-JSON bridge for Ansible variable discovery. Not imported by Switchyard.

Switchyard has no YAML parser of its own and adds no dependency for one. This script runs under the pinned
runner's own Python (`uvx --from ansible-core==<pin> python -I`), whose environment always has PyYAML because
ansible-core needs it. It reads `{"root": ..., "files": [...]}` as JSON on stdin and writes, for each file,
`{"data": ...}` or `{"error": ...}`. It only parses: `yaml.SafeLoader` builds plain data, Ansible's `!vault`
becomes `{"__vault__": true}` (the ciphertext is dropped), `!unsafe` keeps its text, and Jinja expressions
stay text. It opens no network connection and never contacts a host.
"""
import json
import os
import sys

import yaml

MAX_FILE = 1048576
MAX_TOTAL = 16 * 1048576


class Loader(yaml.SafeLoader):
    pass


def _vault(loader, node):
    return {"__vault__": True}


def _unsafe(loader, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_mapping(node, deep=True)


def _other(loader, suffix, node):
    return {"__tag__": "!" + suffix}


Loader.add_constructor("!vault", _vault)
Loader.add_constructor("!unsafe", _unsafe)
Loader.add_multi_constructor("!", _other)


def main():
    request = json.loads(sys.stdin.read(1048576))
    root = os.path.realpath(request["root"])
    result, total = {}, 0
    for relative in request["files"][:2000]:
        path = os.path.realpath(os.path.join(root, relative))
        if os.path.commonpath([root, path]) != root:
            result[relative] = {"error": "outside the repository"}
            continue
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            with os.fdopen(fd, "rb") as stream:
                raw = stream.read(MAX_FILE + 1)
        except OSError as error:
            result[relative] = {"error": f"unreadable ({error.strerror})"}
            continue
        if len(raw) > MAX_FILE or total + len(raw) > MAX_TOTAL:
            result[relative] = {"error": "too large to inspect"}
            continue
        total += len(raw)
        try:
            result[relative] = {"data": yaml.load(raw.decode("utf-8"), Loader=Loader)}
        except (yaml.YAMLError, UnicodeDecodeError, RecursionError) as error:
            mark = getattr(error, "problem_mark", None)
            where = f" at line {mark.line + 1}" if mark is not None else ""
            result[relative] = {"error": f"not valid YAML{where}"}
    sys.stdout.write(json.dumps(result, default=str))


if __name__ == "__main__":
    main()
