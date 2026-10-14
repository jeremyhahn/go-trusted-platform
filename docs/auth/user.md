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

## First: claim the system administrator

A brand-new node has an administrator already — but nobody owns it yet.

qrdb first-boot creates a passwordless, certificate-based `admin` user in the
system tenant on every node, and writes its credential bundle to
`/var/lib/trusted-platform/quicbaas/admin/` (mode 0600, root). Until you claim
it, no one can sign in to the console as the system administrator.

**Claiming is the certificate's job.** There is no invitation email, no setup
link mailed to you, and no default password. The certificate on the node *is*
the bootstrap anchor for this identity — a mailed token would not be an
acceptable one for a principal that guards barrier material.

### Step 1 — prove possession, on the node

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
```

You need shell access to the node and the ability to read the bundle. That is
the point: possession of the machine is what bootstraps its administrator.

To claim a node you are not sitting on, point the command at it and give it
the CA to trust:

```bash
platformctl admin claim \
  --api https://cp.example.com:8443 \
  --bundle ./admin-bundle \
  --ca /etc/trusted-platform/ca.crt
```

### Step 2 — register your passkey, in the console

Open the printed URL, paste the token, and touch your security key when the
browser prompts. Your passkey becomes an **additional** auth factor on the
existing certificate-based admin identity — the certificate stays the
bootstrap anchor; this is ordinary factor enrollment, the same thing any user
does when adding a second factor.

### Step 3 — sign in

From then on, sign in to the console as `admin` with that passkey. Your token
carries the `admin` role, which is what the administration surfaces check.

### Checking whether a node is already claimed

```console
$ platformctl admin claim-status
admin identity: admin
tenant:         system
state:          unclaimed
```

### Things to know

- **The window is short.** The nonce lives two minutes, the claim token ten.
  Start the ceremony when you are ready to touch your key.
- **It closes while your passkey is enrolled.** Someone who later copies the
  bootstrap certificate cannot displace your authenticator with it. If you
  lose the authenticator, the recovery path is to remove its factor through
  an authenticated admin session — that re-opens the ceremony so you can
  claim again with the certificate. There is deliberately no permanent
  lock-out marker: losing a security key should not brick the deployment.
- **A re-claim is announced.** Claiming an admin whose passkey was revoked
  raises a high-severity security event (`adminclaim.reclaim`) naming the
  revoked factor it replaces, the time and the new credential. If you did
  not just recover a lost key yourself, treat it as an intrusion. A claim the
  node cannot classify raises `adminclaim.reclaim_status_unknown` at the
  same severity. A first claim is logged as routine. In the console, open
  **Platform → Logs** and pick the **SECURITY** level to see these events.
- **Every rejection looks the same.** A wrong certificate, an expired nonce and
  a bad signature all answer "proof rejected". That is deliberate; the message
  is not a diagnostic.

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

**Login asks for no username, and the sign-in form no longer has a field for
one.** The ceremony uses discoverable credentials, so your authenticator
identifies you and the platform resolves your account from the credential it
presents. If you hold passkeys for more than one account, your authenticator
asks which — the platform cannot narrow that down for you, and a username box
that looked as though it did would be telling you something untrue.
Registration asks for your email address, because that is when the account is
named. It must be a full address (`name@example.com`): the platform refuses
anything else before it creates the account, rather than leaving behind a user
and workspace that cannot sign in.

Successful login yields a session:

```json
{
  "bearer": "...",
  "expiresAt": "2026-09-12T02:15:00Z"
}
```

Present the bearer on subsequent requests, in `Authorization: Bearer <token>`
or the `jwt` cookie. When it expires, authenticate with your key again — a
WebAuthn login is one touch, and this release issues no renewal credential
(see `docs/auth/architecture.md` §Why the platform still mints the bearer).

`POST /api/v1/login` is the certificate (mTLS) equivalent, and it is currently
**closed** — it answers 403. The platform has no supported way to tie the
certificate you presented to the login ceremony, and opening one regardless
could authenticate you as the daemon rather than as you. Use your security key.
The technical detail is in `docs/auth/architecture.md` §The mTLS factor is
declined.

---

## AI and MCP clients

The MCP server advertises OAuth 2.1 protected-resource metadata:

```bash
curl -s https://platform.example.com:9445/.well-known/oauth-protected-resource
```

It returns the resource identifier, the authorization servers, and a list of
supported scopes. Note that **the advertised scope list is broader than what is
actually enforced** — requesting `container:write` will be accepted and no
`container_*` tool checks it. See [api.md](api.md) §5.

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
Each transport has its own scope catalog, and both the gRPC and MCP catalogs
refuse anything uncatalogued. Every gRPC RPC carries a required scope, but only
370 of 469 MCP tools are classified; an unclassified tool fails with
`AuthErrorToolNotClassified` whatever scopes the token holds. A tool that fails
that way needs classifying, not a broader token. The catalogs are listed in
[`docs/daemon/api.md`](../daemon/api.md) §5.

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
