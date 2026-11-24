# Sourced by the installers. Your fleet's configuration files are not tracked (README: "Your fleet's
# configuration"); each starts as a copy of a tracked example beside it.

# require_fleet_config INSTALLER FILE...: exit 2 naming every missing file and the copy that creates it.
require_fleet_config() {
    installer=$1
    shift
    missing=""
    for file in "$@"; do
        [ -f "$file" ] || missing="$missing $file"
    done
    [ -z "$missing" ] && return 0
    echo "$installer: your fleet's configuration is missing. Copy the examples and edit them for your hosts:" >&2
    for file in $missing; do
        name=$(basename "$file")
        case $name in
            home-lab.json) example=example.json ;;
            home-lab.*.json) example=${name#home-lab.}; example=${example%.json}.example.json ;;
            *) example="(no example)" ;;
        esac
        echo "  cp $(dirname "$file")/$example $file" >&2
    done
    echo "These files are untracked (.gitignore: catalogs/home-lab*.json); see README, \"Your fleet's configuration\"." >&2
    exit 2
}

# refuse_linked_worktree INSTALLER PROJECT: wrappers and units must run the main checkout, never a git worktree
# an agent works in (it may be merged and deleted under them).
refuse_linked_worktree() {
    git_dir=$(git -C "$2" rev-parse --absolute-git-dir 2>/dev/null) || return 0
    common=$(git -C "$2" rev-parse --path-format=absolute --git-common-dir 2>/dev/null) || return 0
    if [ "$git_dir" != "$common" ]; then
        echo "$1: $2 is a linked git worktree; install from the main checkout" >&2
        exit 2
    fi
}
