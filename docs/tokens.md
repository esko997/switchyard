# Start tokens for registered applications

Registration ([workload.md](spec/workload.md#registration-of-adopted-applications)) stays
metadata-only. Start tokens are its first, narrow host write: **one small file per
component** that the application's own start gates read. The application owner installs
and maintains those gates; Switchyard does not. Code: `switchyard/tokens.py`, fixed remote program `switchyard/tokens_remote.py`,
journal table `tokens` in `deploy.sqlite3`. Tests: `tests/test_tokens.py`.

## Contract

- Path on the host: `~/.local/state/switchyard/tokens/<application>/<component>.token`;
  directories 0700, file 0600, written atomically (temp file + rename in the same
  directory), never through a symlink (a symlinked file or directory is refused).
- **Line 1 is the token and the only thing a gate compares:**

  ```
  switchyard-generation-token/v1 application=<app> component=<component> host=<host_id> generation=<N>
  ```

  `host=` makes a token copied or restored onto another host never match. The component
  ID carries the role (hub vs station), so a station cannot start as a hub.
- Revoked, line 1:
  `switchyard-generation-token/v1 revoked application=<app> component=<component> host=<host_id> generation=<N>`.
- Later lines are metadata (`issued_at=`, `revoked_at=`, `operation=`), ignored by gates.
- A gate checks line 1 exactly and nothing else:

  ```sh
  [ "$(head -n 1 -- "/home/<user>/.local/state/switchyard/tokens/<app>/<component>.token")" = "<line>" ]
  ```

  A whole-file `grep -x` passes when a valid line is appended beside a revoked first line;
  never use one. (Switchyard's own deployed units used to; fixed, see [deploy.md](deploy.md).)
- `~/.local/state/switchyard/tokens/` holds a `.nobackup` marker and a `README`: **exclude
  this directory from backups and restores**. A home restore brings back old tokens.

## Authority and journal

- Operations policy key `token_hosts` (enrolled SSH hosts or local targets; default
  empty). It is separate from `deploy_hosts`, lifecycle and shell authority.
- Issue/revoke require: the application is registered; its latest registration has a
  placement on that host listing the component; the host is in `token_hosts`. The worker
  rechecks this from the live operations file and the registration revision under the lease.
- Journal record per (application, component, host): generation, state
  (`valid`|`revoked`|`unknown`), issue/revoke times, the last 16 operations, the read-back
  evidence (path, line 1, SHA-256, mode, state before), and the last verification.
- **Generations only move forward.** The first issue is generation 1; issuing the current
  valid generation again rewrites the same line (a verified no-op); issuing after a revoke,
  or after an uncertain write, uses N+1. Revoke rewrites line 1 of the current generation.
- Intent (target generation, operation ID) is journaled before the host write. A
  refused write (nothing replaced) withdraws it; a lost result leaves the record `unknown`
  (`uncertain: true`), and the next issue bumps the generation.

## Commands

```sh
switchyard token issue APP COMPONENT --host HOST                         # preview: path, exact line, change
switchyard token issue APP COMPONENT --host HOST --approve --request-id ID
switchyard token revoke APP COMPONENT --host HOST [--approve --request-id ID]
switchyard token show APP [COMPONENT] [--host HOST]                      # journal only
switchyard token verify APP [COMPONENT] [--host HOST] [--request-id ID]  # leased, read-only
switchyard token gate APP COMPONENT --host HOST                          # no host contact
```

Issue and revoke run through the broker under the host's canonical lease (receipt kind
`token`, action `issue`/`revoke`), honour `lease break` device blocks (reported `busy`),
write the file, read it back and record the evidence. The same request ID returns the same
receipt; a different action under the same ID is refused.

**Revocation stops nothing that is running.** A component already started keeps running
until it stops by itself or its owner stops it; the token only makes the gates refuse the
next start. Stopping adopted units is a separate, later capability (a stop grant).

`token gate` prints the recorded path, the exact expected line for the current generation,
the shell check above and the systemd form
`ExecStartPre=/bin/sh -c '[ "$$(head -n 1 -- "PATH")" = "LINE" ]'`. The line names the
generation: after a revoke and a new issue (N+1), gates embedding the old line refuse until
they are regenerated. Launchers map a refusal to their own documented exit code.
It needs a prior issue (the path is the one the host reported).

## Verify findings

`token verify` reads line 1 on the host (it never creates the directory) and compares it
with the journal; the result is stored beside the token without changing it.

| Code | Severity | Meaning |
|---|---|---|
| `token-missing` | drift | no token file |
| `token-valid-while-revoked` | drift | line 1 is the valid token, the journal revoked it (restored/rolled back) |
| `token-revoked-while-valid` | drift | line 1 is revoked, the journal issued it |
| `token-generation-mismatch` | drift | line 1 names another generation |
| `token-foreign-host` | drift | line 1 names another host (copied or restored from elsewhere) |
| `token-malformed` | drift | line 1 is not this component's token at all |
| `token-journal-uncertain` | drift | the journal's last write is unknown; issue or revoke to settle it |
| `extra-valid-line` | info | a later line looks like a valid token: harmless for line-1 gates, evidence of tampering |
| `unreachable` | unknown | host not observed (receipt `needs-inspection`, or `busy` for a lease) |

## Limits

- No stop: revocation never stops a running component.
- No gate installation: Switchyard writes token files only; the application installs and
  owns its gates.
- Detection on contact, not prevention: a restored or hand-copied token opens the gates
  until the next `token verify` notices it.
