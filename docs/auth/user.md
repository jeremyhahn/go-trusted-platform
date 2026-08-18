# Platform Authentication — Using It

> **Status: NORMATIVE** · Scope: `pkg/auth/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## What this covers

**Proving who you are** to the platform, and how machines prove who they are.

It does **not** cover what you are then allowed to do. Users, groups, roles and
policies live in [`docs/iam/`](../iam/); certificates live in
[`docs/ca/`](../ca/).

---

## Four ways to authenticate

| You are | You present | Where |
|---|---|---|
| A person at a terminal | A security key, a smart card, or a client certificate | `platformctl auth login` |
| A person in a browser | A passkey (WebAuthn) | `/api/v1/webauthn/...` |
| A script or service on this machine | Nothing — the kernel vouches for you | The platformd Unix socket |
| A machine or service across the network | A client certificate, or a bearer token | mTLS or `Authorization: Bearer` |

---

## Logging in

```bash
platformctl auth login --save-token
```

With no `--method`, the CLI probes in order: a client certificate at the default
path, then attached FIDO2 devices, then PC/SC readers. Be explicit when it
matters:

```bash
platformctl auth login --method fido2
platformctl auth login --method piv --reader "Example Reader 00 00" --slot 9a
platformctl auth login --method mtls --client-cert ./client.pem
```

`--save-token` writes the token to `~/.platformctl/session.token`, mode `0600`.
Without it the token is printed to stdout and nothing else — capture it or lose
it.

**Two things to get right:**

**Do not type your PIN as an argument.** `--pin 123456` lands in the process
table, where every other user on the box can read it, and in your shell history.
Use the environment instead:

```bash
read -rs PLATFORMCTL_USER_PIN; export PLATFORMCTL_USER_PIN
platformctl auth login --method piv
```

**`auth` talks to go-quicbaas, not to platformd.** If your CLI context is
`embedded` the command fails outright:

```
auth: embedded context cannot dial quicbaas (set PLATFORMCTL_QUICBAAS_ADDR)
```

Set `PLATFORMCTL_QUICBAAS_ADDR` or switch to a local/remote context.

---

## Managing your factors

A **factor** is one enrolled way of authenticating: a specific security key, a
specific smart card, a specific certificate. You can have several.

```bash
platformctl auth factor list
```

```
ID           TYPE   USER   TENANT    ENROLLED              REVOKED
01HQ8RJ4XYZ  fido2  alice  platform  2026-06-01T09:12:00Z  -
01HQ9ABCDEF  piv    alice  platform  2026-07-14T16:40:00Z  -
```

Enrol another before you need it:

```bash
platformctl auth factor add --type fido2 --label "yubikey-5c-backup"
platformctl auth factor add --type piv   --label "piv-badge" --reader "Example Reader 00 00"
platformctl auth factor add --type mtls  --label "laptop-cert" --cert ./client.pem
```

`--label` is required and should say something a future you will recognise —
`"yubikey-5c-desk"`, not `"key2"`.

Replace one:

```bash
platformctl auth factor rotate 01HQ8RJ4XYZ --type fido2 --label "yubikey-5c-desk-v2"
```

Remove one:

```bash
platformctl auth factor remove 01HQ8RJ4XYZ
```

**Enrol a second factor before you remove your first.** Removing your last
factor locks you out, which is why it needs `--force` and why you should not
reach for `--force`.

**Rotation revokes the old factor.** If the new enrolment then fails you are
down one factor. On a single-factor account, rotate only when you can recover.

Rename without touching key material:

```bash
platformctl auth factor relabel 01HQ9ABCDEF --label "piv-badge-drawer"
```

---

## Vendor-independence

One code path handles a YubiKey, a SoloKey, a Nitrokey, TouchID, Windows Hello
and any other CTAP2 or PIV-compliant device. If your key speaks the standard,
it works; there is no per-vendor support list to check.

---

## Machines and services

You will not run `auth login` on a machine being provisioned. Machines
authenticate with a certificate:

- A **TPM-issued IDevID** on hardware with a TPM — the strongest device
  identity available, because the private key never leaves the chip.
- A **platform-issued client certificate** for services like `gatewayd`.

The platform reads the certificate and derives:

- an **identity** — by default the email SAN, falling back to Common Name, then
  the subject serial number, then the first DNS SAN;
- a **tenant** — by default the Organization field.

That default matters: **whatever a certificate says in its Organization field is
the tenant it gets**, so a CA that will issue arbitrary Organizations is a CA
that will issue arbitrary tenants. Keep certificate issuance policy and tenancy
policy in the same conversation.

---

## Local scripts

Anything on the same host talking to the platformd Unix socket needs **no
token and no certificate**. The kernel reports the calling process's UID, GID
and PID, and the platform trusts that — it cannot be forged.

The trade-off: a local caller has a UID, not a tenant. Do not expect
tenant-scoped behaviour from a Unix-socket call.

---

## Browsers

Passkey registration and login:

```
POST /api/v1/webauthn/registration/begin
POST /api/v1/webauthn/registration/finish
POST /api/v1/webauthn/login/begin
POST /api/v1/webauthn/login/finish
GET  /api/v1/webauthn/registration/status
```

Successful login yields a JWT. `/api/v1/login/refresh` extends it.

---

## AI and MCP clients

The MCP server advertises OAuth 2.1 protected-resource metadata:

```bash
curl -s https://platform.example.com:8000/.well-known/oauth-protected-resource
```

It returns the resource identifier, the authorization servers, and a list of
supported scopes. Note that **the advertised scope list is broader than what is
actually enforced** — requesting `ca:write` will be accepted and no `ca_*` tool
checks it. See [api.md](api.md) §5.

---

## Troubleshooting

**`auth: embedded context cannot dial quicbaas`.**
The `auth` group has no in-process path. Set `PLATFORMCTL_QUICBAAS_ADDR` or use
a local or remote context.

**`auth: remote context "<name>" has no server configured`.**
The named context is remote and its server field is empty. Fix the context, or
override with `PLATFORMCTL_QUICBAAS_ADDR`.

**`mtls: no client certificates presented`.**
The TLS handshake completed without a client certificate. Either the client did
not offer one, or the server is not requesting one.

**`mtls: certificate chain validation failed`.**
Three usual causes: the certificate was not issued by a CA in the server's trust
bundle; it lacks the **client authentication** extended key usage (a
server-auth-only certificate fails here even though its chain is sound); or the
intermediates were not sent.

**`mtls: certificate expired` / `certificate not yet valid`.**
Check the certificate dates *and* the clock on both ends. A machine whose clock
has not synchronised yet reports "not yet valid" for a perfectly good
certificate.

**`mtls: tenant not found in certificate`.**
No Organization field and no other configured tenant source. Either reissue with
one, or the deployment needs a default tenant configured.

**`mtls: identity not found in certificate`.**
No email SAN, no CN, no subject serial, no DNS SAN. The certificate carries
nothing to name the holder.

**Authentication succeeds for a certificate you expected to be rejected.**
Check three things in order:
1. **Is a trust bundle configured?** With no root pool, chain verification is
   **skipped** — dates, revocation and identity extraction still run, the chain
   does not.
2. **Is revocation checking on?** It is **off by default**, and even when on,
   only a CA error whose text mentions revocation counts as revoked.
3. **Did you expect the IDevID check to reject it?** Inside the general
   authentication path an IDevID failure is logged and ignored, because not
   every client certificate is a device certificate. Paths that must have a
   device certificate check it explicitly.

All three are documented in [architecture.md](architecture.md) §6.

**A token works on one transport and not another.**
Authorization coverage is uneven: 185 of 461 gRPC RPCs and 71 of 449 MCP tools
carry a required scope, and anything uncatalogued is allowed once the token
validates. A call that "works" may simply be uncatalogued.

**You lost your session token.**
Log in again. There is no recovery path and no token store to read from.

---

## One thing to be aware of

`platformctl credential submit`, `list` and `rotate` **exist and do nothing**.
Each returns:

```
credential submit is not yet wired to the SDK CredentialService
```

They are placeholders matching the locked CLI surface. Do not build a workflow
on them yet. [cli.md](cli.md) §4.

---

## Where to go next

- [cli.md](cli.md) — every verb and flag
- [api.md](api.md) — every capability on every transport (**session endpoints are REST-only**)
- [architecture.md](architecture.md) — trust boundaries and the fail-open paths
- [`docs/iam/`](../iam/) — who you are allowed to be, and what you may do
- [`docs/ca/`](../ca/) — getting a certificate in the first place
