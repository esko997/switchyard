#!/bin/sh
# Install the shared agent CLI and MCP wrappers on the control host; no daemon/device access or project changes.
#   ~/.local/bin/switchyard             CLI (leases, reads, operations)
#   ~/.local/bin/switchyard-mcp         stdio MCP for local agents (with the operations configuration)
#   ~/.local/bin/switchyard-mcp-remote  stdio MCP for agents on other hosts via `switchyard mcp`
#                                       (--remote: cache reads and leases only, detached holds attributed
#                                       to the --origin-host/--agent-id the client passes; no operations)
# uv is resolved to an absolute path now, because non-interactive SSH may have a minimal PATH.
# The wrappers run this checkout (never a linked git worktree) with your fleet's configuration, which is not
# tracked: catalogs/home-lab.json, home-lab.collectors.json, home-lab.operations.json (copy the examples first).
# Idempotent: rerunning rewrites the same three files.
set -eu
PROJECT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
CATALOG="$PROJECT/catalogs/home-lab.json"
COLLECTORS="$PROJECT/catalogs/home-lab.collectors.json"
OPERATIONS="$PROJECT/catalogs/home-lab.operations.json"
BIN="$HOME/.local/bin"
# shellcheck source=tools/fleet-config.sh
. "$PROJECT/tools/fleet-config.sh"
require_fleet_config install-agent-cli "$CATALOG" "$COLLECTORS" "$OPERATIONS"
refuse_linked_worktree install-agent-cli "$PROJECT"

UV=${SWITCHYARD_UV:-}
if [ -z "$UV" ]; then
    UV=$(command -v uv 2>/dev/null || true)
fi
for candidate in "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv" /home/linuxbrew/.linuxbrew/bin/uv; do
    [ -n "$UV" ] && break
    [ -x "$candidate" ] && UV=$candidate
done
case $UV in
    /*) ;;
    *) echo "install-agent-cli: uv not found (set SWITCHYARD_UV=/absolute/path/to/uv)" >&2; exit 1 ;;
esac
if [ ! -x "$UV" ]; then
    echo "install-agent-cli: $UV is not executable" >&2
    exit 1
fi

mkdir -p "$BIN"
temporary=""
trap 'rm -f "$temporary"' EXIT HUP INT TERM

# install NAME ENTRY-POINT [EXTRA-ARGS...]: one wrapper, written to a temporary file and renamed into place.
install_wrapper() {
    name=$1 entry=$2
    shift 2
    temporary=$(mktemp "$BIN/.$name.XXXXXX")
    {
        echo '#!/bin/sh'
        printf 'exec "%s" run --project "%s" --locked --quiet %s --catalog "%s" --collectors "%s"' \
            "$UV" "$PROJECT" "$entry" "$CATALOG" "$COLLECTORS"
        for argument in "$@"; do
            printf ' "%s"' "$argument"
        done
        echo ' "$@"'
    } > "$temporary"
    chmod 0755 "$temporary"
    mv -f "$temporary" "$BIN/$name"
    temporary=""
    echo "installed $BIN/$name"
}

install_wrapper switchyard switchyard --operations "$OPERATIONS"
install_wrapper switchyard-mcp switchyard-mcp --operations "$OPERATIONS"
install_wrapper switchyard-mcp-remote switchyard-mcp --remote
