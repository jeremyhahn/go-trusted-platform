# Platform Authentication — CLI

> **Status: NORMATIVE** · Scope: `pkg/auth/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every verb and flag below was read out of `pkg/cli/commands/canonical_auth.go`
> on 2026-08-18.

---

## 1. Two command groups

```
platformctl auth          User authentication and N-factor management
platformctl credential    Post-init credential operations (submit, list, rotate)
platformctl admin         System administrator identity claim (see §3b)
```

Both are part of the portfolio's **locked CLI surface**, which fixes them as
`auth login | factor list|add|remove|rotate|relabel` and
`credential submit | list | rotate | retrieve | versions | delete | gc`.
`auth` matches. `credential` does not — see §5.

`pkg/auth` itself has **no CLI**: it is a library called by the daemon and the
proxy, not a command.

### Global flags

The `platformctl` persistent flags (`pkg/cli/commands/root.go`) apply. Precedence
is **flag > environment > config file > built-in default**.

| Flag | Short | Default | Environment | Meaning |
|---|---|---|---|---|
| `--config` | `-c` | platform default config path | `PLATFORMCTL_CONFIG` | Config file |
| `--context` | | current-context | `PLATFORMCTL_CONTEXT` | Named context to use |
| `--transport` | | from context | `PLATFORMCTL_TRANSPORT` | `unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded` |
| `--server` | | from context | `PLATFORMCTL_SERVER` | Server address; implies a remote context |
| `--server-name` | | | `PLATFORMCTL_SERVER_NAME` | TLS SNI / certificate verification hostname |
| `--output` | `-o` | `table` | `PLATFORMCTL_OUTPUT` | `table`, `json`, `yaml` |
| `--verbose` | `-v` | `false` | | Verbose output |
| `--no-color` | | `false` | `NO_COLOR` | Disable coloured output |

**`--output` does not apply to `auth`.** These handlers print tab-separated or
key-value text to stdout directly; they do not route through the `platformctl`
printer. Verified 2026-08-18.

### Which verbs work without a server

**None.** Every `auth` verb dials **go-quicbaas**, not platformd. The address is
resolved as:

1. `PLATFORMCTL_QUICBAAS_ADDR` if set — highest precedence.
2. Otherwise from the active CLI context:
   - **local** → `/run/quicbaas.sock` over Unix
   - **remote** → the context's configured server (REST when it starts
     `http://` or `https://`, gRPC otherwise). A remote context with no server
     is an error.
   - **embedded** → an error: *"auth: embedded context cannot dial quicbaas
     (set PLATFORMCTL_QUICBAAS_ADDR)"*

That is not the usual `--transport embedded` story. `auth` has no in-process
path.

---

## 2. `platformctl auth login`

Authenticate using one of the enrolled factors and obtain a session token.

Takes no positional arguments (`cobra.NoArgs`).

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--method` | string | `""` (auto-discover) | `mtls`, `fido2`, or `piv` |
| `--factor` | string | `""` | Pin the login to a specific enrolled factor id |
| `--username` | string | `""` | Username (subject) for login |
| `--client-cert` | string | `""` (env `PLATFORMCTL_CLIENT_CERT`) | Client certificate PEM path (`--method mtls`) |
| `--device` | string | `""` | FIDO2 device id (`--method fido2`) |
| `--rp-id` | string | `""` | WebAuthn relying-party id (`--method fido2`) |
| `--reader` | string | `""` | PC/SC reader name (`--method piv`) |
| `--slot` | string | `9a` | PIV slot id (`--method piv`) |
| `--pin` | string | `""` (env `PLATFORMCTL_USER_PIN`) | PIV User PIN |
| `--save-token` | bool | `false` | Persist the issued token to `--token-path` |
| `--token-path` | string | `""` (env `PLATFORMCTL_TOKEN_PATH`) | Where to write the token; defaults to `~/.platformctl/session.token` |

Auto-discovery order when `--method` is omitted: a client certificate at the
default path, then attached FIDO2 devices, then PC/SC readers.

```bash
# mTLS with an explicit certificate
platformctl auth login --method mtls --client-cert ./client.pem --save-token

# FIDO2, pinned to one enrolled factor
platformctl auth login --method fido2 --factor 01HQ8RJ4 --rp-id platform.example.com

# PIV, PIN from the environment rather than the command line
PLATFORMCTL_USER_PIN=REPLACE_WITH_PIN \
  platformctl auth login --method piv --reader "Example Reader 00 00" --slot 9a
```

Output (stdout, plain text):

```
User:       alice (01HQ8RJ4XYZ)
Token:      <session token>
Issued At:  2026-08-18T12:00:00Z
Expires At: 2026-08-18T20:00:00Z
Token saved to /home/<user>/.platformctl/session.token
```

**The token is printed to stdout.** Redirect it, or use `--save-token` and read
the file — do not leave it in a scrollback buffer on a shared terminal.

**Do not pass `--pin` as a literal argument in an interactive shell.** It lands
in the process table and in shell history. Use `PLATFORMCTL_USER_PIN`.

The login is vendor-agnostic: one code path authenticates a YubiKey, a SoloKey,
a Nitrokey, TouchID, Windows Hello, and any other CTAP2 / PIV-compliant device.

---

## 3. `platformctl auth factor`

N-factor management. Five verbs.

### `auth factor list`

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--user` | string | `""` | Filter by user/subject (admin) |

```bash
platformctl auth factor list
platformctl auth factor list --user alice
```

Output is tab-separated with a header row:
`ID  TYPE  USER  TENANT  ENROLLED  REVOKED`. Timestamps are RFC 3339; an
un-revoked factor shows `-`. With no enrolments it prints
`(no enrolled factors)`.

### `auth factor add`

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--type` | string | `""` | `mtls`, `fido2`, or `piv` |
| `--label` | string | `""` | Human-readable label (**required**) |
| `--user` | string | `""` | Subject/user; defaults to the current authenticated user |
| `--tenant` | string | `""` | Tenant ID (optional) |
| `--cert` | string | `""` | Certificate PEM path (`--type mtls`) |
| `--device` | string | `""` | FIDO2 device id (`--type fido2`); defaults to the first connected |
| `--reader` | string | `""` | PC/SC reader name (`--type piv`) |
| `--slot` | string | `9a` | PIV slot id (`--type piv`) |

```bash
platformctl auth factor add --type fido2 --label "yubikey-5c-desk"
platformctl auth factor add --type mtls  --label "laptop-cert" --cert ./client.pem
platformctl auth factor add --type piv   --label "piv-badge" --reader "Example Reader 00 00" --slot 9a
```

`--label` is required by the service, not by cobra: omitting it fails at the
server with an SDK error rather than at flag parsing.

### `auth factor remove <factor-id>`

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--force` | bool | `false` | Allow removing the **last** factor (admin) |

```bash
platformctl auth factor remove 01HQ8RJ4XYZ
```

Prints `OK`. Omitting the positional id returns
`authsvc.ErrMissingFactorID{Op: "auth factor remove"}`.

**Removing your last factor locks you out.** That is why `--force` exists and
why it is not the default.

### `auth factor rotate <factor-id>`

Takes the same flag set as `add` — the flags describe the **new** factor.

```bash
platformctl auth factor rotate 01HQ8RJ4XYZ --type fido2 --label "yubikey-5c-desk-v2"
```

Output names both ids:

```
Old factor revoked: 01HQ8RJ4XYZ
New enrollment ID:  01HQ9ABCDEF
Type:               fido2
```

Rotation revokes the old factor. If the new enrolment fails after the
revocation, you are down one factor.

### `auth factor relabel <factor-id>`

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--label` | string | `""` | New human-readable label |

```bash
platformctl auth factor relabel 01HQ8RJ4XYZ --label "yubikey-5c-drawer"
```

Prints `OK`.

---

## 3b. `platformctl admin`

> Code: `pkg/cli/commands/admin/` · Architecture:
> [architecture.md §6b](architecture.md) · API: [api.md §2b](api.md).

Unlike `auth`, this group dials **platformd's REST API**, not go-quicbaas: the
claim ceremony is a platform-owned trust boundary (architecture.md §6b.4).
Neither verb needs a session — that is the point of the ceremony.

```
platformctl admin claim          Prove possession of the first-boot admin credential
platformctl admin claim-status   Report whether this node's admin identity is claimed
```

### Flags (both verbs)

| Flag | Default | Meaning |
|---|---|---|
| `--api` | active context's server, else `https://127.0.0.1:8443` | Platform REST endpoint serving the ceremony |
| `--bundle` | `/var/lib/trusted-platform/quicbaas/admin` | Directory holding `admin.crt` and `admin.key` |
| `--ca` | active context's CA, else the host trust store | PEM bundle the platform's TLS certificate must chain to |

`claim` additionally takes `--console <url>` to control the URL printed in the
finish instructions; it defaults to `--api`.

**The endpoint and its TLS settings come from the active context when the
flags are unset**, so `platformctl admin claim` reaches the node every other
`platformctl` command reaches — including the context's `server_name`
override, which is applied as the SNI and certificate-verification hostname.
An explicit flag always wins, so the ceremony can be run against a node the
operator has no context for without creating one first.

The context contributes its **address and TLS settings, not its transport**.
The ceremony is REST-only by construction: its routes run before any session
exists, so there is nothing for the session-bearing SDK client to carry
([api.md §2b](api.md)). A local context — whose daemon is on this host —
resolves to the loopback default.

A remote context whose `server` is **not** an `http://` or `https://` URL is
**refused, not guessed at**:

```
admin: the active context's server "cp.example.com:10443" is not an http://
or https:// endpoint, and the claim ceremony is REST-only; pass --api with
the node's REST endpoint
```

This is the common shape rather than an exotic one — remote contexts default
to gRPC, and `Context.ResolveProtocol` treats any server that does not begin
`http://` or `https://` as gRPC. Bolting a scheme and an assumed REST port
onto such an address could reach a *different service* on that host, and the
ceremony hands a claim token to whatever answers. That is the same reason
there is no `--insecure`. Pass `--api` explicitly; the context still supplies
the CA and server-name settings it holds.

There is deliberately **no `--insecure`**. The ceremony hands a claim token to
whatever answers, so an unauthenticated server would be handed the operator's
proof.

### `platformctl admin claim`

Run it on the node, as a user who can read the bundle (mode 0600, root):

```console
# platformctl admin claim
Possession of the first-boot admin credential confirmed.

  identity:    admin (subject admin)
  tenant:      system
  claim token: 9ir7Yb...
  expires:     2026-09-01 18:12:00 UTC

Finish the ceremony in the console within the window above:

  1. open https://127.0.0.1:8443/setup/admin-claim
  2. paste the claim token
  3. register your passkey when the browser prompts
...
```

It checks status first, so an operator on an already-claimed node gets a clear
answer instead of a rejected proof.

### `platformctl admin claim-status`

```console
$ platformctl admin claim-status --api https://cp.example.com:8443
admin identity: admin
tenant:         system
state:          unclaimed
```

### Exit conditions

| Condition | Error |
|---|---|
| `admin.crt` / `admin.key` missing or unparseable | `admin: cannot read "<path>"` |
| Platform API unreachable | `admin: cannot reach the platform API at <endpoint>` |
| Proof rejected, or ceremony already closed | `admin: the platform refused the claim (HTTP 403)` |
| Node already claimed | `admin: "admin" has already been claimed; recovering it requires removing the enrolled factor through an authenticated admin session` |

---

## 4. `platformctl credential`

```
platformctl credential submit
platformctl credential list
platformctl credential rotate
```

**All three are unimplemented stubs.** Each accepts arbitrary arguments and
returns `PendingCredentialBackendError`:

```
<verb> is not yet wired to the SDK CredentialService
```

for example `credential submit is not yet wired to the SDK CredentialService`.

They exist so the command tree matches the locked surface and so an operator
gets a clear refusal instead of `unknown command`. Verified 2026-08-18.

---

## 5. Exit codes and output

| Situation | Behaviour |
|---|---|
| Success | Exit `0`, plain text on stdout |
| Any handler error | Exit non-zero, cobra renders the error; `SilenceUsage` is **not** set on these commands, so usage is printed too |
| Missing positional factor id | `authsvc.ErrMissingFactorID` |
| Unimplemented `credential` verb | `PendingCredentialBackendError` |

`--output json` / `--output yaml` are accepted as persistent flags and **ignored
by every verb in this group** — the handlers write directly to `os.Stdout`.
Scripts must parse the text, or use the SDK.

---

## 6. Divergences from the locked surface

Both are defects raised against the locked-surface document, per
`conventions/feature-docs.md` §4 — recorded, not resolved by writing the local
variant down as the standard.

1. **`credential` is missing four verbs.** The locked surface defines
   `submit | list | rotate | retrieve | versions | delete | gc`; the code
   registers only `submit | list | rotate`, and all three are stubs.

2. **CLI parity suite.** Every verb here should have a matching
   `CommandDefinition`. **This repository defines no `CommandDefinition` type**
   (grepped repo-wide, 2026-08-18), so the requirement is unmet repo-wide, not
   only for `auth`.

Not a divergence, worth stating: `auth` matches the locked surface exactly
(`login`, `factor list|add|remove|rotate|relabel`).

---

## 7. Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/cli/global-flags.md`](../cli/global-flags.md) — the persistent flag set
- [`docs/iam/cli.md`](../iam/cli.md) — user, group, role and policy verbs
