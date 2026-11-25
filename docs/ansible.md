# Ansible host initialization

Switchyard runs operator-owned Ansible playbooks as a host-onboarding backend. The inventory comes from the host registry, check mode is the plan, and apply is an approved operation under the host's canonical lease. The receipt records the playbook commit, the overrides and the changed tasks. The desk's **Playbooks** tab browses, registers, plans and applies; the CLI does the same; MCP reads.

Code:

| File | What it holds |
|---|---|
| `switchyard/ansible_ops.py` | Registrations, inventory, plans, applies, runs, receipts, background jobs, CLI |
| `switchyard/ansible_discovery.py` | Read-only repository inspection: path safety, playbooks, inventories, roles, variables |
| `switchyard/ansible_yaml.py` | YAML-to-JSON bridge run under the pinned runner's own Python; never imported |
| `switchyard/ansible_runner.py` | Pinned runner, bounded execution (stdin pipe, progress tick, cancel), event parsing |
| `switchyard/ansible_callback.py` | The Ansible callback plugin; copied into a private plugin directory, never imported |
| `switchyard/web.py`, `switchyard/static/app.js` | The `/api/ansible/*` routes and the Playbooks tab |

Tests: `tests/test_ansible_ops.py` (runner, plans, applies, callback) and `tests/test_ansible_desk.py` (registrations, discovery, typed overrides, background runs, the become password, HTTP routes).

## Configuration file and registrations

**The database is the authority for registrations.** Playbook registrations live in the table `playbooks` of `<state>/ansible/ansible.sqlite3` (0600), beside plans, runs and receipts. The desk, the CLI and MCP all read them there; the desk and the CLI write them there.

**The configuration file configures the tool only.** It is `<catalog name>.ansible.json` beside `--catalog` (`catalogs/home-lab.ansible.json`, untracked; start from `catalogs/ansible.example.json`), else `SWITCHYARD_ANSIBLE`, else `switchyard ansible --config PATH`. What stays authoritative in it is `runner`: the exact ansible-core version and pinned collections. That is the tool's own supply chain, chosen when Switchyard is installed and reviewed like code; it is not something to change per playbook from a browser.

```json
{
  "schema_version": 1,
  "runner": {"ansible_core": "2.19.15", "collections": [{"name": "ansible.posix", "version": "1.6.2"}]},
  "playbooks": {"<id>": {"...": "one-time seed only, see below"}}
}
```

`playbooks` is optional. **Seeding** happens the first time any Switchyard process opens the Ansible store (CLI, desk or MCP): every playbook in the file is inserted at revision 1 with `updated_by: seed from <file>`, and the store records the seed's time, source path, SHA-256 and IDs (`switchyard ansible playbooks` shows them under `registry.seed`). Seeding is idempotent and loses nothing: it runs once (later edits to the file are never read into the database), uses `INSERT OR IGNORE` (an existing row is never overwritten), and leaves the file in place. `registry.config_playbooks_not_in_database` lists file entries that differ from or are missing in the database, so a stale file is visible. A file with only `runner` is valid.

### Registration schema

| Field | Meaning |
|---|---|
| ID | `[a-z0-9][a-z0-9-]{0,63}`; fixed once registered |
| `description` | Free text |
| `repo` | Absolute path of the repository root (stored resolved) |
| `playbook` | Playbook file, relative to `repo`, `.yml`/`.yaml` |
| `inventory` | Optional repo inventory, relative to `repo` (see "Layering") |
| `groups` | 1-16 groups the generated host joins, so the play's `hosts:` pattern matches. A registry host has no Ansible groups of its own |
| `allowed_hosts` | Explicit registry SSH host IDs, or `"all-linux"` to include current and future verified Linux SSH hosts |
| `become` | The operator's declaration that the playbook escalates. Discovery shows whether its plays say `become: true` |
| `check_mode` | `full`, `partial` or `unsupported`: how far a plan can be trusted. `unsupported` runs only the preflight |
| `extra_vars_allowed` | Variables the operator may override per run. `ansible_*` and `switchyard_*` are refused, so overrides cannot redirect the connection or the privilege settings |
| `secret_vars` | Variables the operator flags as secret (in addition to discovered ones) |

Each row also has `revision` (an integer, incremented by every edit), `created_at`, `updated_at` and `updated_by`. Edit and remove are compare-and-swap: they name the revision they were made from, and a stale revision is refused with the current one.

Registering and editing check more than the seed does:

- The directory must resolve, after every symlink, inside the operator's home directory; a symlink that leads outside is refused.
- The repository root, the playbook and the inventory must be owned by the operator and not writable by every user; the playbook and inventory must resolve inside the repository.
- The repository must be the root of a Git work tree.
- An explicit host list names SSH hosts in the registry. The all-Linux option instead checks host OS, pinned SSH keys and verified connection at target selection and again at apply.

The same path and ownership checks run again before every discovery, plan and apply.

### Register an operator-owned playbook

Start with `catalogs/ansible.example.json` or register a repository in the Playbooks tab. Choose a real Git checkout inside your home, a relative playbook path, groups matching its `hosts:` pattern, and explicit registry host IDs such as `host-a`. Set `become` and check-mode trust from the playbook, not from the example. A registration is not permission to apply it.

For a playbook intended to run on new Linux hosts without editing its registration, choose **All verified Linux SSH hosts** in the desk (CLI: `--all-linux-hosts`). Existing playbooks keep their explicit lists. If you register a repository inventory, the target must also be present there for its host and group variables. Eligibility never starts a run: planning and approved apply still target one leased host at a time.

Inspect task behavior before relying on check mode: skipped commands and first-run package/configuration effects may be unpredicted, while `check_mode: false` probes actually run during planning. Mark sensitive variables and permit only reviewed overrides.

## Variables

Discovery reads the repository and runs nothing of the playbook. It never contacts a host and never evaluates a template: a Jinja expression is shown as its text and flagged `templated`.

**Parsing.** Switchyard has no YAML parser and adds no dependency for one. A correct parser for "this subset" would still have to handle block scalars, anchors, flow collections, tags and quoting, so YAML is parsed by `ansible_yaml.py` under the pinned runner's own Python (`uvx --from ansible-core==<pin> python -I ansible_yaml.py`), whose environment always has PyYAML because ansible-core depends on it. It reads `{"root", "files"}` as JSON on stdin and writes JSON. It uses `yaml.SafeLoader`; `!vault` becomes `{"__vault__": true}` (the ciphertext is dropped), `!unsafe` keeps its text, other tags become markers. Files are opened with `O_NOFOLLOW` and must resolve inside the repository; at most 1 MiB each and 16 MiB in total. Merged per-host inventory values come from the pinned `ansible-inventory --list`, as for runs. Comments, which YAML parsers drop, are read from the raw text by Switchyard itself.

**What is read.** The repository is scanned for YAML files (up to 1500 files, depth 8), skipping hidden directories, `.venv`, `venv`, `node_modules`, `__pycache__`, `.tox` and `collections`. Symlinks that lead outside the repository and files not owned by the operator are skipped and listed. From the registered playbook (following `import_playbook` inside the repository):

| Source | Gives |
|---|---|
| role `meta/argument_specs.yml` (or `argument_specs` in `meta/main.yml`), entry point `main` | Authoritative type (`str` default), `choices`, `required`, `elements`, `description`; `no_log: true` makes the variable secret. The spec's `default` is shown as documentation only: Ansible does not apply it |
| role `defaults/main.yml`, `defaults/main.yaml`, `defaults/main/*.yml` | Name, default value, type inferred from the value; the comment lines directly above a top-level key (no blank line between) as its description |
| play `vars` | Play-level values |
| play `vars_files` | Values from files inside the repository |
| play `vars_prompt` | Name, `prompt` as description, `default`; `private` (the default) makes it secret |
| role `vars/main.yml` | Values that only extra vars can override |
| repository inventory, per allowed host | The merged value from `ansible-inventory --list`, attributed to `host_vars/<host>`, `group_vars/<group>` (beside the inventory or the playbook) or the inventory file itself |

Roles are found in `roles/` beside the playbook or at the repository root, from play `roles`, `include_role`/`import_role` in play and role tasks, and `meta/main.yml` dependencies. Collection roles (`ns.coll.role`) and roles named by a template are listed but not read.

**Effective value per host.** Ansible's precedence among the layers discovery sees, lowest first: role defaults, repository inventory, play vars, play `vars_prompt`, play `vars_files`, role vars. The desk shows, for each allowed host, which layer wins and from which file. Overrides are extra vars and beat all of them.

**Secret variables.** A variable is secret if its argument spec says `no_log`, it is a private `vars_prompt`, any of its values (in the repository or the inventory for an allowed host) is vaulted, or the registration lists it in `secret_vars`. Discovery never returns a secret variable's values, in the repository or per host.

**Limits.** Variables defined only in templates, `set_fact`, `include_vars` at run time, task-level `vars`, collection roles, `group_vars` of groups the host joins only through Switchyard's `groups`, and roles named by templates are not discovered. Such names can still be allowed for override; they are typed as text. If the repository cannot be read at all, a plan treats every allowed name as secret text. Discovery results are cached in the process per repository content (commit plus working-tree fingerprint), registration and pin.

## Overrides

At run time only the variables in `extra_vars_allowed` can be set. The desk shows a typed input for each (a checkbox for booleans, a choice list where choices are known, a number field, a list editor for lists of text or numbers, JSON for mappings and anything else), filled in with the chosen host's effective value, and sends only what the operator changed. The CLI takes `--extra-var NAME=VALUE`: text for `str`/`path` variables, JSON otherwise (`true`/`false`/`yes`/`no` for booleans).

The server validates every value against the declared or inferred type and `choices` (list elements against `elements`), bounds it (text 4096 characters, 16 KiB per value, 32 overrides), and refuses names that are not allowed. Values reach Ansible as extra variables in a private 0600 file in the run's scratch directory, deleted after the run; never on a command line.

**Recorded.** The plan stores `extra_vars.values` (non-secret overrides, in full) and `extra_vars.secret_names`; the receipt copies both. An apply uses the plan's recorded values; only the secret ones are typed again (`--extra-var` on the CLI apply, `secret_vars` over HTTP). Nothing derived from a secret value is stored, so the apply cannot prove it was given the same secret as the plan; that is the price of storing nothing. Secret values, wherever they appear in task names, failure messages, progress or the stderr tail, are replaced with `***` before anything is stored or returned.

## Runner

```
uvx --from ansible-core==<pin> ansible-playbook ...
```

Set `SWITCHYARD_UVX` to an executable path or ensure `uvx` is on `PATH`. The first use downloads ansible-core into uv's cache. That download happens in a version check (`ansible-playbook --version`, which must report the pin) before any lease is taken. Discovery uses the same cached environment.

The environment is rebuilt for every run. Only `PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_ALL`, `SSH_AUTH_SOCK`, `UV_CACHE_DIR` and `XDG_CACHE_HOME` pass through, so no inherited `ANSIBLE_*` variable applies. Switchyard sets:

- `ANSIBLE_CONFIG=<state>/ansible/ansible.cfg` (`interpreter_python = auto_silent`). The repo's own `ansible.cfg` is never loaded, so it cannot change trust, privilege or callbacks.
- `ANSIBLE_HOME=<state>/ansible/home`, `ANSIBLE_COLLECTIONS_PATH=<state>/ansible/collections` (no system-path scan) and in-memory fact cache only.
- Scratch on disk: `ANSIBLE_LOCAL_TEMP` and `TMPDIR` set to `~/.cache/switchyard/ansible/tmp`. Per-run scratch goes in `~/.cache/switchyard/ansible/runs/run-*`, which is removed after each run.
- `ANSIBLE_FORKS=1`, `ANSIBLE_SSH_RETRIES=0`, `ANSIBLE_TIMEOUT=10`, host key checking on, no retry files, `become_ask_pass` off.
- The `switchyard_events` callback, which writes JSON lines to `SWITCHYARD_ANSIBLE_EVENTS`: task starts (name only), results (task name, status, diff size, short failure message), stats. Never results or diff contents; `no_log` results record only that they were hidden. For Switchyard's own runs that path is a FIFO in the run scratch directory: a reader thread parses each line and replaces every secret override value and the sudo password with `***` before keeping it, in memory only, so nothing the callback writes reaches the disk. Stdout (which shows diffs) is discarded. Only a 1 KiB stderr tail is kept, scrubbed the same way. Values that are not secret (for example repo inventory vars echoed in a failure message) are not redacted; mark such tasks `no_log`. The operator's own terminal runs write a regular events file under `<state>/ansible/manual/` for `record-manual`; Switchyard never has the password for those.

Deadlines kill the runner's whole process group: check runs at 15 min and applies at 60 min. In the CLI, SIGTERM or SIGHUP during a run raises `SystemExit`, so the group is reaped, the receipt is finished and the lease is released. In the desk, SIGTERM first stops every background run the same way (see "Runs"). Nothing retries.

## Inventory

`switchyard ansible inventory [--host H] [--playbook ID]` prints the generated inventory and contacts no host. It covers SSH registry hosts that have pinned keys. Unpinned SSH hosts are listed under `refused`, and asking for one with `--host` is an error. Each host is named by its registry ID and gets:

- `ansible_host`, `ansible_user` and `ansible_port` from the registry `target`/`port`, with `ansible_connection: ssh`.
- `ansible_ssh_args` carrying Switchyard's own trust: `UserKnownHostsFile=<registry pin file>`, `GlobalKnownHostsFile=/dev/null`, `HostKeyAlias=switchyard-<id>`, `StrictHostKeyChecking=yes`, `BatchMode=yes` and `UpdateHostKeys=no`, plus no forwarding, no proxy and no control master. Ansible therefore trusts exactly the keys `switchyard host-pin-key` pinned.
- Empty `ansible_ssh_common_args`/`ansible_ssh_extra_args`, plus `switchyard_host_id` and `switchyard_expected_hostname`.

During runs the same connection vars are also passed as an extra-vars file (`-e @<plan>.connection.json`). Extra vars have the highest precedence, so no repo, group or play variable can redirect SSH.

### Layering with the repo's inventory

When the registration has `inventory`, the pinned `ansible-inventory -i <repo inventory> --playbook-dir <playbook dir> --list` runs locally. It finds the host by registry ID first, then by `expected_hostname` (for example registry ID `host-a` with reported hostname `source`). The layering works as follows:

1. Generated connection vars always win. Repo vars named `ansible_*` or `switchyard_*` are dropped; the plan lists them as `repo_vars_replaced`.
2. The host's other vars are copied in as host vars. `ansible-inventory --list` has already merged the repo's inventory `group_vars`/`host_vars` and the playbook-adjacent ones.
3. The host joins the registration's `groups` and every repo group it belongs to, including ancestors. Playbook-adjacent `group_vars/<group>.yml` therefore still apply at run time.
4. A host missing from the repo inventory is refused. So are vault-encrypted vars (discovery shows them as hidden; a run refuses them).

One caveat: the repo's group vars become inventory host vars, which have higher precedence than playbook `group_vars/*`. That only matters if the same name is set in both places. Review the inventory layering when the same variable appears in several places.

## Plan, apply, receipts

```sh
switchyard ansible playbooks                                   # registrations, repo HEAD/dirty, per-host eligibility, sudo state
switchyard ansible show ID                                     # one registration: variables, roles, recent plans, runs, receipts
switchyard ansible variables ID [--host H]                     # discovery; with --host, that host's effective values
switchyard ansible inspect PATH                                # what a directory offers for registration (read-only)
switchyard ansible add ID --repo P --playbook F [--inventory I] --group G --host H [--become] --check-mode M \
    --description D [--var NAME]... [--secret-var NAME]...     # operator only
switchyard ansible edit ID ... --expected-revision N           # same options; replaces the registration
switchyard ansible remove ID --expected-revision N             # plans and receipts stay
switchyard ansible probe --host host-a                       # leased read-only proof: identity, sudo -n, setup facts
switchyard ansible plan ID --host host-a [--extra-var k=v] [--allow-dirty] [--ask-become-pass] [--wait 30]
switchyard ansible plans [PLAN_ID]
switchyard ansible runs [RUN_ID]                               # plan and apply runs with progress, from the desk or the CLI
switchyard ansible apply PLAN_ID --approve --request-id ID [--extra-var secret=v] [--ask-become-pass]
switchyard ansible receipts [RECEIPT_ID|REQUEST_ID]
switchyard ansible record-manual PLAN_ID --request-id ID       # the operator's own terminal run (below)
```

`add`, `edit` and `remove` are refused under agent process ancestry (the best-effort check `lease break` uses).

**Plan.** Steps before the lease, all local:

1. Registration, host eligibility, overrides (typed, allowed) and the sudo password's shape are checked. These are refused at once, before any run is recorded.
2. The repo must be a clean Git work tree. The plan records HEAD and a fingerprint of the tracked diff and untracked files. A dirty tree is refused unless `--allow-dirty` (in the desk: "Plan the uncommitted working tree") is given, which is recorded in the plan and the receipt.
3. Runner and version check.
4. The inventory is generated and written to `<state>/ansible/inventories/<plan>.yml` (mode 0600).

Then, under the host's canonical lease (`LedgerBroker` on the registry ledger; the CLI waits at most `--wait` seconds up to 60, the desk 5; a busy ledger is reported as `<DEVICE> busy: <holder>; <scope>; <age>`, exit 75 on the CLI):

1. Preflight over the pinned SSH runs under `/bin/sh` regardless of the account's login shell. `uname -n` must equal `expected_hostname`, the account must not be root, and `sudo -n true` is probed. The result is remembered per host (shown as "passwordless sudo" or "sudo needs a password").
2. `ansible-playbook --check --diff --limit <host>` runs.

The stored plan contains:

- ID, a 30-minute expiry, host, playbook ID and the run ID.
- Commit, inventory SHA-256, registry-entry SHA-256 and registration SHA-256.
- Overrides: non-secret values in full, secret names only.
- ansible-core version, and `become_password: password supplied by the operator for this run` when one was used.
- Per-task results with diff sizes, and the task-name lists `changed_tasks`, `failed_tasks`, `unreachable_tasks`, `not_predicted` and `forced_run`.

Only a check run that exits 0 makes the plan applicable. The status values are:

- `planned`: the check run succeeded.
- `needs-operator-privilege`: the playbook uses become, passwordless sudo is unavailable and no password was given.
- `failed`: unreachable host, identity mismatch, sudo refused the password, failed or timed-out check, or Switchyard stopped during the check.

**Apply.** Apply requires approval and a request ID, and refuses any of these:

- an expired or already-used plan;
- a changed registration or host registry entry;
- a moved HEAD or changed repo content;
- a regenerated inventory with a different hash;
- missing or extra secret variables (exactly the plan's `secret_names` are typed again);
- a host without passwordless sudo when no password is given (refused before the plan is consumed);
- a different ansible-core version.

The checks run before the lease and again under it. Then the plan is consumed and a `running` receipt is written in one transaction. The preflight runs again, and the playbook runs without `--check`. The lease is held for the whole run and released in `finally`. Receipt status is one of:

- `succeeded`: exit 0 with a final summary.
- `failed`: task failures, sudo refused the password, or unreachable before any task ran (no changes made); changed tasks before the failure are listed. Also used when the preflight failed and the playbook was not started.
- `needs-inspection`: timeout, missing final summary, the host became unreachable mid-run, Switchyard was stopped, or the process died. A `running` receipt whose process died is converted when it is next read.

Receipts record commit, dirty/allow-dirty flags, ansible-core version, inventory hash, overrides (as in the plan), whether a sudo password was supplied, lease ID, start/end, exit code, stats, and changed, failed and unreachable task names. They appear in the desk's Audit log (`GET /api/operations` and `/api/operations/<receipt id>`), next to brokered operations.

Repeating a request ID returns the same receipt (`replayed: true`) without running anything. A different request ID on a consumed plan is refused: make a new plan. Plans, runs, receipts and registrations live in `<state>/ansible/ansible.sqlite3` (0600). This is a private store because `operation_store.Store` has no generic way to insert a new receipt kind.

## Runs

Every plan and apply, from the desk or the CLI, is a run record (table `runs`): kind, playbook, host, status, phase (`waiting for the lease`, `preflight`, `check-mode run`, `applying`), the plan and receipt it produced, the error, and live progress: the current play and task, counts by status and the last 120 task results, scrubbed of secrets, updated about once a second from the callback events.

- **One run per host.** A second plan or apply for a host with an active run is refused, naming the active run. This holds across the desk and the CLI. The lease is still the authority between Switchyard and everything else.
- **Background.** Desk requests return at once (HTTP 202) with the run; the run continues in a thread of the desk process. The page polls `/api/ansible/runs` every 1.5 s while a run is active and the tab or run panel is visible, and `#playbooks/<run id>` reopens a run after a reload.
- **Stopped desk.** SIGTERM to the desk first stops every active run's runner group (like a deadline), finishes its receipt (`needs-inspection` for an apply that started) and releases its lease, then exits as before; with no run active the signal behaves exactly as before. If the desk dies without that (SIGKILL, power loss), runs and receipts whose process is gone become `interrupted` (plan) or `needs-inspection` (apply) when next read.

## Privilege (become)

Switchyard never stores, logs or prints a sudo (become) password. It passes a password the operator types to Ansible for that single run, and nowhere else. Without one, a plan that needs privilege stops before the check run and gives the operator the exact leased terminal commands instead. Both paths stay available.

- **Passwordless sudo works** (`sudo -n true` succeeds under the lease): plan and apply run normally; a typed password is not used.
- **The operator types the password for one run.** In the desk the password field appears when the playbook uses become and the host has no passwordless sudo, or it is not yet known; it is asked again in the approval for every apply and never carried from the plan. On the CLI, `--ask-become-pass` prompts with `getpass` (refused without a terminal). The path the password takes:
  1. The browser sends it once, in the JSON body of `POST /api/ansible/plan` or `/apply`, only over the loopback desk or the HTTPS listener (any other listener refuses it), with the operator's session and CSRF token. The input is a `type="password"`, `autocomplete="off"` field, cleared from the page as soon as the request is built (so also after any failure); it is never in page state, storage or the address.
  2. The handler pops it from the parsed body at once into a `BecomePassword` holder (`repr` shows nothing) and hands it to the run. No log line, exception, run record, plan or receipt contains it; they record only `become_password: password supplied by the operator for this run`.
  3. The background run holds that one reference until the runner exits. Just before starting `ansible-playbook`, Switchyard writes it into an anonymous pipe (`os.pipe`), closes the write end, and makes the read end the runner's stdin; the runner gets `--become-password-file -`, so ansible-core reads it from stdin to EOF. `uvx` passes stdin through. It is never in argv, the environment or any file.
  4. The callback's events pass through a FIFO into memory and are scrubbed line by line before anything keeps them, so neither progress, the final summary, nor any file holds the password; the stderr tail is scrubbed too (`redact`). Then the reference is dropped. CPython cannot zero a string's memory; the object is freed, not wiped.
- **Wrong password.** sudo gets one attempt: ansible-core's own failure ("Incorrect sudo password", "Missing sudo password") makes the plan `failed` (`become_refused: true`) or the receipt `failed`, with "sudo refused the password; nothing past that point ran, and it was not retried". Nothing is retried, because repeated failures can lock the account on some hosts.
- **Your own terminal.** A plan without the password is `needs-operator-privilege`, and nothing past the preflight runs. Its `operator_commands` (shown in the desk with copy buttons) use the same generated inventory, connection-vars file, recorded overrides (secret ones as `<value>` placeholders) and pinned runner, each wrapped in a lease:

  ```sh
  switchyard lease run host-a --scope 'ansible host-init apply on host-a (operator, become; plan PLAN_ID)' --wait 60 -- \
    env -C <repo> ANSIBLE_CONFIG=... ANSIBLE_HOME=... SWITCHYARD_ANSIBLE_EVENTS=<state>/ansible/manual/<plan>-apply.jsonl ... \
    <uvx> --from ansible-core==2.19.15 ansible-playbook -i <state>/ansible/inventories/<plan>.yml --limit host-a \
    -e @<state>/ansible/inventories/<plan>.connection.json --ask-become-pass --diff <repo>/site.yml
  ```

  The `check` command is the same with `--check --diff` and without the events file. After the apply command, "Record my terminal run" in the desk (or `switchyard ansible record-manual <plan> --request-id ID`) turns the events into a receipt with `executor: operator`. Switchyard neither ran the command nor held the lease, so the ledger's CLAIM/RELEASE from `lease run` is the lease record.

`lease run` starts its command in a new session that inherits terminal stdin. If your terminal cannot provide the password prompt there, use a multi-step `switchyard lease hold host-a --scope ...`, run the displayed Ansible command directly, and release the lease in a finally path. Keep passwords out of scripts, arguments and receipts.

## The desk

The **Playbooks** tab lists each registration: description, repository path, commit and whether the working tree is dirty, playbook file, inventory, groups, the hosts it may run on (by hostname, with their last known sudo state), whether it needs sudo, and how far its check mode can be trusted. Opening one reads the repository: its variables (type, playbook value and source, whether it may be overridden, description, secret and required flags), what each allowed host starts with and from which file, plays and roles, recent runs and applies. The Runs list shows every recent run with live state.

As the operator: **Add playbook…** reads a directory (inspection: Git state, playbook files at the top or in `playbooks/`, inventories with their groups and the registry hosts they contain, roles and variables) and fills the form; choose the file, inventory, groups, hosts, sudo, check-mode trust, description, and tick the variables that may be overridden or are secret. **Edit…** re-reads the repository and saves with the revision it was opened at; **Remove…** asks first. **Plan a run…** opens the run panel (host, typed variables, sudo password when needed); the plan's progress, result, caveats and commit appear there; **Approve** applies exactly that plan with a new request ID; the receipt appears in the panel, the run history and the Audit log.

### Routes

| Route | Authority |
|---|---|
| `GET /api/ansible/playbooks`, `GET /api/ansible/playbooks/<id>`, `GET /api/ansible/runs`, `GET /api/ansible/runs/<id>` | read |
| `POST /api/ansible/inspect`, `POST /api/ansible/playbooks` (add), `POST /api/ansible/playbooks/<id>/update`, `POST /api/ansible/playbooks/<id>/remove` | operator |
| `POST /api/ansible/plan`, `POST /api/ansible/apply`, `POST /api/ansible/plans/<id>/record-manual` | operator |

Registering, planning and applying need the operator's session on every listener, the loopback desk included: a playbook with become is root on its host, and agents on the control host can reach loopback. Keys cannot run playbooks. Reads of a registration run discovery (the pinned runner locally); they contact no host.

## Agents

MCP is read-only for Ansible and contacts no host: `ansible_playbooks`, `ansible_playbook` (one registration with discovery and history), `ansible_variables` (discovery; secret values never returned), `ansible_plans`, `ansible_receipts`. Registering, planning and applying are not available over MCP, and MCP takes no sudo password. Opening the store from MCP can perform the one-time seed. `AnsibleOps.inventory(host_id)` (registry only) is also safe; `inventory(host, playbook)` runs the repo inventory through the pinned runner locally. `probe`, `plan` and `apply` take a lease and contact the host.
