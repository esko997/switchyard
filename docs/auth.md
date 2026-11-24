# Operator login, TLS, enrollment and scoped keys

Switchyard has one operator, who signs in with a username and password. Hosts and agents get scoped API keys by asking for access and waiting for the operator to approve. The client generates the key, and the server stores only its SHA-256. The LAN listener speaks HTTPS with a certificate from a local CA.

Code:

| File | What it holds |
|---|---|
| `switchyard/auth.py` | Rules, enrollment, keys, the `auth`/`tls` CLI |
| `switchyard/auth_store.py` | Private SQLite store |
| `switchyard/tls.py` | Local CA and server certificate, made with the `openssl` CLI |
| `switchyard/web.py` | Identity resolution and the route table |

Tests: `tests/test_auth.py`, `tests/test_tls.py`, and `AccessHTTPTests` in `tests/test_interfaces.py`.

## Model

**Operator.** There is one account. The password is hashed with salted `scrypt` (n=2^17, r=8, p=1, 32-byte output, 16-byte salt). The parameters are stored with the hash, so they can be raised later.

- Minimum length is 12 characters. There are no composition rules.
- An unknown username is checked against a dummy hash, so timing does not reveal whether the name exists.
- At most two password checks run at once.
- The password can only be set on the control host: `switchyard auth set-password`.

**Sessions.**

- The token is 32 random bytes, sent as a cookie. The store keeps only its SHA-256.
- Sessions end after 12 hours idle or 7 days in total.
- A new session is issued at every login, and the session the browser presented is deleted.
- A session works only on the listener that issued it (loopback or LAN).
- Each session has its own random CSRF token.
- Setting the password or running `auth logout-all` ends every session.

**Login throttle.** 5 failures per client address in 15 minutes return 429, with `Retry-After`. A global cap of 50 failures in 15 minutes also returns 429. Every attempt goes into a bounded audit table (5000 rows): time, kind, client address, username attempted and outcome. Passwords and tokens are never recorded. Pruning never removes a failure that is still inside the 15-minute window, so flooding the log (for example with throttled attempts) cannot reset the throttle. The throttle itself caps how many such rows exist, so the table stays bounded.

**Keys.**

- Bearer format is `sy1_` plus 43 base64url characters (32 random bytes). The client generates the key.
- The server stores the SHA-256 of the whole bearer string and nothing else of it.
- Every key has a scope: `read`, `lease` or `operate`.
- `lease` and `operate` keys carry a non-empty list of registry host IDs. Amendment 1: the list bounds leases as well as operations. A `read` key has no host list.
- Keys expire after 1–365 days (default 90) and can be revoked.
- `last_used_at`/`last_used_from` are updated at most once a minute.

**State.** `<state_dir>/auth/auth.sqlite3` (mode 0600, directory 0700). It is separate from the operations and deploy stores. The loopback and LAN listener processes share it.

## Listeners and identities

| Listener | Transport | A caller without credentials is |
|---|---|---|
| Loopback desk `127.0.0.1:8710` | plain HTTP | `local` |
| LAN `switchyard web --lan --host 192.168.50.5 --port 8712 --allowed-clients 192.168.50.0/24` | HTTPS only | unauthenticated (401) |
| Legacy read-only LAN view (`--lan-read-only`, 8711) | plain HTTP | `view` (unchanged: GET only, receipts redacted) |

Every request is resolved to one identity before routing:

1. An `Authorization: Bearer` header resolves to `key`. An expired, revoked or unknown key returns 401 on any non-public route. A request with both a bearer and a session cookie returns 400.
2. Otherwise a valid session cookie resolves to `operator`. The cookie is `__Host-switchyard-session` on HTTPS (Secure; HttpOnly; SameSite=Strict; Path=/) and `switchyard-session` on loopback HTTP.
3. Otherwise the listener's anonymous kind applies: `local` on loopback, none on the LAN listener.

A POST authenticated by a session must carry `X-Switchyard-CSRF: <csrf_token>`. Login is the only exception. Bearer requests need no CSRF token. The existing Host, Origin and Sec-Fetch-Site checks still run. On the LAN listener the only accepted origin is `https://<listener authority>`.

### What each identity may do

| Authority | operator | local | key `read` | key `lease` | key `operate` |
|---|---|---|---|---|---|
| `public` | yes | yes | yes | yes | yes |
| `read` | yes | yes | yes (receipt scripts redacted) | yes (redacted) | yes (redacted) |
| `lease` | yes | no (use `switchyard lease` on the host) | no | own hosts only | own hosts only |
| `operate` | yes | yes | no | no | only when every touched host is in the key's hosts |
| `desk` | yes | yes | no | no | no |
| `operator` | yes | no | no | no | no |
| `self` | – | – | own key | own key | own key |

### Route table

The table is `ROUTES` in `switchyard/web.py`. A path without an entry does not exist (404, or 405 for a known path with another method). A test fails if a handler exists without an entry.

**Public**

- Page and static assets: `/` and files directly in `switchyard/static/`.
- `GET /api/auth/session`, `POST /api/auth/login`, `POST /api/auth/logout`.
- `GET /api/tls/ca`.
- `POST /api/enroll`: HTTPS listener only. On loopback it returns 404, because the enrollment code needs the served certificate.
- `GET /api/enroll/<id>`: the bearer proves the request; otherwise 404.

**Read**

- `GET /api/inventory`, `/api/fleet`, `/api/events`, `/api/hosts`, `/api/locks`, `/api/agents`, `/api/fleet-keys`, `/api/definitions`, `/api/store`, `/api/operations`, `/api/operations/<id>`.
- `GET /api/ansible/playbooks`, `/api/ansible/playbooks/<id>`, `/api/ansible/runs`, `/api/ansible/runs/<id>` (registrations, discovered variables, plans, runs and receipts; reading a registration runs discovery locally and contacts no host).
- `GET /api/lan-urls`: published LAN names, eligible workload endpoints and any unfinished publication. It contacts no host.
- For keys, receipts in these responses lose `script`/`script_preview` and gain `script_redacted: true`. That covers `operations` inside fleet snapshots and live events.

**Lease**

- `GET /api/leases`, `POST /api/leases`, `POST /api/leases/<id>/renew`, `POST /api/leases/<id>/release`.
- A key may lease only a device whose registry host IDs are all in its `hosts`. Anything else returns 403 before any lock is attempted.
- Renew and release are allowed only for the key that took the lease, or the operator.

**Operate**

- `POST /api/operations/shell`: hosts are `host_id` plus `extra_host_ids`.
- `POST /api/observations/host`: the host is `host_id`.

**Desk** (operator or loopback `local`; refused for keys because the hosts cannot be determined before execution, or because the action is not for keys)

- `POST /api/operations/inspect`, `/plan`, `/execute`.
- `POST /api/plans/migration`, `/api/observations/local`.
- `POST /api/fleet-keys/inspect`, `/api/definitions/propose`, `/api/hosts/scan-key`.
- `GET /api/enrollments`, `GET /api/keys`.
- `POST /api/enrollments/<id>/approve`: `local` may grant `read` only. `lease`/`operate` grants need the operator.

**Operator**

- `POST /api/enrollments/<id>/deny`, `POST /api/keys/<id>/revoke`.
- `POST /api/hosts/update`, `/api/hosts/pin-key`, `/api/hosts/paseo`.
- `POST /api/fleet-keys/plan`, `/api/fleet-keys/execute`.
- `POST /api/definitions/save`, `/api/definitions/update`.
- `POST /api/ansible/inspect`, `POST /api/ansible/playbooks`, `/api/ansible/playbooks/<id>/update`, `/api/ansible/playbooks/<id>/remove`: Ansible registrations.
- `POST /api/ansible/plan`, `/api/ansible/apply`, `/api/ansible/plans/<id>/record-manual`: a playbook with become is root on its host, so planning and applying need the operator even on loopback. Keys cannot run playbooks.
- `POST /api/lan-urls/plan`, `/api/lan-urls/apply`: preview and explicitly approve LAN publication, edit, removal or recovery. Keys and unsigned loopback callers cannot change ingress.

**Self**

- `POST /api/keys/self/revoke`.

On the loopback desk, operator-only routes therefore need a sign-in. Agents on the control host can reach loopback, and before this change they could edit the registry, fleet keys and definitions there.

### Sudo passwords

Switchyard never stores or logs a sudo (become) password. `POST /api/ansible/plan` and `/api/ansible/apply` accept one optional `become_password` for that single run, from the operator's session only, and only on the loopback desk or the HTTPS listener; any other listener refuses it with 400. The handler takes it out of the request body at once and passes it to `ansible-playbook` through a pipe on its stdin (`--become-password-file -`); plans, runs and receipts record only that a password was supplied. It is asked again for every apply. The full path is in [ansible.md](ansible.md#privilege-become).

## Enrollment

1. The client `POST`s `/api/enroll` with `{name, user, host_id?, agent_id?, scope, hosts?, key_sha256, client?}`. The body may be at most 4 KiB.
   - The server records the source address and returns `{id, code, approve_url, expires_at, poll_after_seconds}`.
   - At most 16 requests can be pending; beyond that the server returns 429. A request expires after 15 minutes.
   - A `key_sha256` that was already submitted is refused.
   - A request grants nothing.
2. The client prints `approve_url` (`https://<listener authority>/#access/<id>`) and the code it computed itself.
3. The operator opens the URL on any device, signs in, and compares the code shown in the Access tab with the one the client printed. Then the operator approves, optionally narrowing:
   - The scope can only narrow, never widen.
   - `lease`/`operate` need a non-empty host list; the approver must choose hosts if the request had none.
   - Expiry is 1–365 days.
   - The label is free text.

   Alternatively: `switchyard auth approve ID [--scope S] [--hosts a,b] [--days N] [--label L]`.
4. The client polls `GET /api/enroll/<id>` with `Authorization: Bearer <key>` until the status is `approved`, `denied` or `expired`.

### Enrollment code

`XXXX-XXXX` is the first 40 bits of `SHA-256(leaf_sha256_hex + ":" + key_sha256 + ":" + id)`, written in RFC 4648 base32 (uppercase), with a dash after four characters. The inputs are:

- `leaf_sha256_hex`: the lowercase hex SHA-256 of the DER-encoded server (leaf) certificate.
- `key_sha256`: the lowercase hex SHA-256 of the bearer string.

The server stores the code it computed from the certificate it served. The client computes the code from the certificate it actually received. Under interception the two codes differ.

Test vectors (checked independently with `openssl dgst -sha256 -binary | head -c 5 | base32`):

| leaf_sha256_hex | key_sha256 | id | code |
|---|---|---|---|
| `0000000000000000000000000000000000000000000000000000000000000000` | `157491a8f4d95ae6e23c1e4c4726d6a221b4051c9e0484ca95dbf9c73a8950e8` (SHA-256 of `sy1_` + 43 × `A`) | `00000000000000000000000000000000` | `A2C6-HYKT` |
| `9f91161f43433e49a6de6db680d79f60159f2e4ac9172621a12846428158440b` (SHA-256 of `leaf`) | `eea34f4ed040a522440b8c060c33c0fc1cb5890b80e8607f332ba00b0478fa19` (SHA-256 of `sy1_` + 43 × `B`) | `0123456789abcdef0123456789abcdef` | `4ZNE-XSZW` |

## Leases over HTTP

`POST /api/leases {device, scope, ttl_minutes?}` takes a detached hold through the existing `lease hold --detached` machinery (`Service.agent_leases().hold(..., detached=True)`). The TTL is 1–120 minutes, default 60. The hold is attributed as follows:

- The owner reads `<name> (<user>, paseo:<agent8>; key <id8>)`.
- If the key's claimed `host_id` is a registry host, `@<host>` is appended and the origin host and agent ID are recorded.

The result is `{lease_id, device, expires_at}`. A busy ledger or a blocked device returns 409 naming the holder. Detached holds are TTL-only: the client must release, or let the TTL end the hold. SSH `switchyard lease` remains preferred wherever it works, because it holds the lease for a command's lifetime and fails closed.

## TLS

```sh
switchyard tls init --name 192.168.50.5 [--name desk.home.arpa]
switchyard tls show
switchyard tls export-ca PATH
switchyard tls renew [--name EXTRA]
```

Everything lives under `<state_dir>/tls/` (directory 0700):

| File | Contents |
|---|---|
| `ca.key` | CA private key, 0600, EC P-256. Never replaced. |
| `ca.pem` | CA certificate, 10 years, `CA:TRUE, pathlen:0` |
| `server.key` | Server private key, 0600 |
| `server.pem` | Server certificate, EC P-256, 397 days, serverAuth, SANs = listener address plus `--name` values |
| `server-chain.pem` | Leaf plus CA, which is what the listener serves |
| `server.json` | The SAN list |

The listener serves TLS 1.2 or newer (`ssl.SSLContext`). When it starts, it reissues the server certificate if the certificate does not cover the bound address and names or has fewer than 30 days left. That reissue runs `openssl`, which reads the CA key. No Switchyard process loads the CA key into memory, and the listener's TLS context never holds it.

Keys are generated by `openssl genpkey` into a 0700 scratch directory under `tls/`. Key material never appears on a command line. `openssl` is found through `SWITCHYARD_OPENSSL`, then `PATH`, then `/usr/bin/openssl`. No new Python dependency is needed.

Clients must trust or pin the CA: fetch `GET /api/tls/ca`, compare its SHA-256 with `switchyard tls show` (or the Access tab), and verify every later connection against it, including hostname/IP checks.

## Setup

Replace the example address with a private literal assigned to the control host. `--allowed-clients CIDR` explicitly selects the admitted network; otherwise the bind address derives an IPv4 /24 or IPv6 /64. This network boundary is additional to authentication, not a substitute.

```sh
switchyard tls init --name 192.168.50.5
switchyard auth set-password                 # at the operator's terminal; refuses pipes and agents
switchyard web --lan --host 192.168.50.5 --port 8712 --allowed-clients 192.168.50.0/24
# On the new host:  switchyard enroll --server https://192.168.50.5:8712 --scope read
# Open the printed URL on any device, sign in, compare the code, approve.
```

Other commands:

- `switchyard auth status|requests|keys` shows the account, sessions, pending requests, keys and recent sign-in events.
- `switchyard auth approve ID --scope read` works from an agent.
- `deny`, `revoke KEY_ID`, `logout-all`, `set-password`, and approvals of `lease`/`operate` refuse callers with agent ancestry, using the same check as `lease break`.

## Revocation

- Operator: `switchyard auth revoke KEY_ID`, or Revoke in the Access tab (`POST /api/keys/<id>/revoke`).
- The key itself: `POST /api/keys/self/revoke` (`switchyard unenroll` on the client).
- A revoked or expired key gets 401 on its next request. Leases the key already took run until their TTL ends or someone releases them.
- `switchyard auth logout-all` ends every browser session.

## Limits

- **Loopback `local` is trusted.** Any process on the control host can use the loopback desk as before, except operator-only routes. That includes reading pending enrollment codes and approving `read` keys.
- **The CLI operator check is best effort.** It looks for agent process ancestry and `PASEO_AGENT_ID`, as `lease break` does. A determined local process can evade it. `set-password` additionally requires a terminal.
- **The CA is self-signed.** Clients must pin it on first use or check its fingerprint out of band. Browsers show a warning until the CA is installed.
- **A key is as trusted as its host.** A key holder on an approved host can do everything its scope allows on its hosts, until the key expires or is revoked.
- **Key-held leases are TTL-only.** The server cannot see the key holder's processes.
- **Workload operations are desk-only for keys.** Inspect, plan and execute are refused for keys because their hosts are not known before execution.
- **Concurrent issuers.** Renewing the certificate while a LAN listener runs does not affect that listener until it restarts. It keeps serving, and computing codes from, the certificate it loaded.
