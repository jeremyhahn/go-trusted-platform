# Trusted Reverse Proxy — Using It

> **Status: REFERENCE** · Scope: `pkg/proxy/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Task-oriented, in the order you do things. Internals are in
> [engineering.md](engineering.md).

---

## What this is

A reverse proxy that puts an application behind the platform's own identity
system. Callers arrive with a platform-issued client certificate or a
broker-issued access token; the proxy checks the credential, the caller's
network zone, optionally whether the caller's machine is freshly attested, and
optionally a policy — then forwards the request with the caller's identity in
headers the backend can trust.

It exists so that an application which understands none of that can still sit
behind all of it, without you configuring reachability twice.

**Two moving parts:**

- **platformd** holds the routes and pools. This is what you edit.
- **gatewayd** runs the proxy and polls platformd. This is what serves traffic.

You never edit a gateway's routes directly. You change platformd, and every
gateway converges on its next sync tick (default 15 seconds).

---

## Prerequisites

1. **A gateway with the proxy service enabled** — `proxy.enabled: true` in its
   configuration, with `proxy.tls.cert-file` / `key-file` and at least one
   listener. Any route that is not `public` also needs a client CA source:
   `proxy.tls.client-ca-file`, or a `trust:` section the platform's
   `internal`-class pool can be read from.
2. **`platformctl` pointed at your platformd** — `--server`, or a configured
   context.
3. **Zones, if you plan to use them.** `allowed-zones` and `backend-zone` are
   validated against the SDN zone matrix. `platformctl proxy zone-matrix` shows
   you what exists.
4. **`token-auth:` configured on the gateway** before any `token` or
   `mtls-or-token` route — issuer and JWKS URL are required and have no
   discoverable default.
5. **`attestation:` configured** before any `require-attestation` route, and
   **`opa:` configured** before any `opa-policy` route.

Points 4 and 5 are not advisory. A gateway whose configuration demands a
capability it was not built with **refuses to start** with a typed error. That
is deliberate: the alternative is a gateway that starts happily and denies
every request.

---

## First route

A pool, then a route pointing at it:

```bash
platformctl proxy pool add --id web-pool \
    --backend https://web-1.internal.example.com:8443 \
    --backend https://web-2.internal.example.com:8443

platformctl proxy route add --id web \
    --host app.example.com \
    --path-prefix / \
    --pool web-pool \
    --auth-mode public
```

```bash
platformctl proxy status          # version went up
platformctl proxy route list      # your route is there
```

Then wait one sync interval, and the gateway is serving it.

**`--auth-mode` is required.** There is no default. `public` means exactly
that — no authentication — so type it deliberately.

---

## Requiring a client certificate

```bash
platformctl proxy pool add --id api-pool \
    --backend https://api-1.internal.example.com:8443 \
    --trust-class platform --mtls-client-cert

platformctl proxy route add --id api \
    --host api.example.com --path-prefix /api --pool api-pool \
    --auth-mode mtls \
    --allowed-zone control-plane --backend-zone services \
    --strip-prefix
```

What each piece buys you:

- **`--auth-mode mtls`** — a platform-issued client certificate, verified
  against the platform CA. No bearer token substitutes for it.
- **`--allowed-zone control-plane`** — the zone in the caller's certificate must be
  `control-plane`. A certificate with no zone extension is denied, not
  defaulted. Zones are those of the
  [reference network](../architecture/reference-network.md).
- **`--backend-zone services`** — the zone matrix must permit
  `control-plane → services`. This is the same table that programs the network's flow
  rules, so route reachability and network reachability cannot drift apart.
- **`--trust-class platform`** on the pool — the proxy verifies the
  *backend's* certificate against the platform CA (the gateway's platform
  anchor, `platform-ca-file:`), and presents its own. A BMC backend uses
  `--trust-class bmc` instead, verified through the `trust: bmc:` class.
- **`--strip-prefix`** — the backend sees `/` where the caller sent `/api`.

---

## Requiring an attested machine

```bash
platformctl proxy route add --id console \
    --host console.example.com --path-prefix / --pool console-pool \
    --auth-mode mtls --require-idevid \
    --require-attestation --attestation-max-age 5m
```

`--require-idevid` means the certificate must be a valid TCG IDevID — an
identity the machine's TPM holds, not a file someone copied.

`--require-attestation` means the platform must hold a manifest for that
machine that is younger than `--attestation-max-age` **and** that platformd
verifies. Anything else denies. Three things to understand before you turn it
on:

- **The age is measured on the manifest's signed collection timestamp**, not on
  when the proxy asked. A machine that stopped pushing manifests goes stale on
  schedule.
- **Token callers can never pass.** They have no device identity, so an
  attestation-gated route denies them `attestation_unavailable`. Do not put
  `--require-attestation` on a `token` route expecting it to be ignored.
- **If platformd is unreachable, the route denies.** Bounded by a 5-second
  negative cache, so it recovers quickly — but it denies. That is the intended
  behavior for an attestation gate.

Leave `--attestation-max-age` off and the route inherits
`defaults.attestation-max-age` from the gateway's file, and failing that 24
hours.

---

## Accepting tokens instead

```bash
platformctl proxy route add --id metrics \
    --path-prefix /metrics --pool metrics-pool \
    --auth-mode token --required-scope proxy:read
```

- **A DPoP proof is required on every request by default.** The gateway's
  `token-auth.allow-bearer` is `false` unless you change it; a plain bearer
  token is rejected. That is what makes a stolen token useless without the
  sender's private key.
- **`--required-scope` is token-only.** Putting it on an `mtls` or `public`
  route is rejected at validation, because it could never be enforced there.
  Certificates carry roles and zones, not OAuth scopes.
- **`mtls-or-token` prefers the certificate.** If a caller presents both, the
  certificate wins and the bearer token is ignored entirely — and never
  forwarded.

**Zones and tokens.** A token caller has no certificate and therefore no zone.
On a route that enforces zones, the operator must assign one explicitly, and
without it the route denies with `zone_requires_mtls`. **There is no
`--token-zone` flag** — set `auth.token-zone` in the gateway's configuration
file, or use another transport. See [cli.md](cli.md) §2.

---

## Adding a policy

```bash
platformctl proxy route add --id partner \
    --host partner.example.com --path-prefix / --pool partner-pool \
    --auth-mode mtls --allowed-zone lab --opa-policy proxy_authz
```

The policy runs **after** authentication, so it decides what an already-known
caller may do. It sees the caller's id, zone, device id, whether the machine is
attested, the auth method and the roles; plus the route and the request method
and path.

`proxy_authz` ships with the platform. It denies by default, denies anything
from the `quarantine` zone, and requires a non-empty client zone — which means
**a token caller with no assigned zone cannot pass `proxy_authz`**, even on a
route that does not otherwise enforce zones. Point `opa.policy-dir` at your own
directory to overlay policies; a file with the same name wins.

If a policy denies, the caller sees `opa_denied` and nothing else. The reasons
are in the gateway's logs and the audit trail, deliberately — a policy that
explains itself to the client is a policy that helps the client route around
it.

---

## Changing things

```bash
platformctl proxy route update --id api --pool api-pool-v2 --auth-mode mtls --path-prefix /api
platformctl proxy route delete api
platformctl proxy pool delete api-pool
```

**`update` replaces the whole route.** Any flag you leave out reverts to its
zero value — a route updated without `--allowed-zone` loses its zone
restriction. Always re-state the full route.

**A pool in use cannot be deleted.** The error names the routes still pointing
at it. Delete or repoint them first.

**Forcing convergence:**

```bash
platformctl proxy reload
```

That bumps the version without changing anything, so every gateway re-fetches
on its next tick.

---

## What the backend sees

After an allow, the backend receives:

| Header | Contents |
|---|---|
| `X-TP-Client-ID` | the caller's identity |
| `X-TP-Device-ID` | the device serial (mTLS callers only) |
| `X-TP-Client-Zone` | the caller's network zone |
| `X-TP-Auth-Method` | `mtls` or `token` |
| `X-TP-Attested` | `true` or `false` — always present |
| `X-TP-Cert-Fingerprint` | SHA-256 of the client certificate |
| `X-Forwarded-Client-Cert` | Envoy-compatible certificate summary |

**Your backend can trust these** — every inbound `X-TP-*` header is stripped
before routing, so a client cannot supply its own. It should authenticate the
*proxy* by its mTLS platform identity and then read these values.

**The caller's `Authorization` header is never forwarded** on an authenticated
route. If your backend needs a credential of its own, it must obtain one
itself; the proxy will not mint, exchange or pass one through.

---

## Troubleshooting

Every denial is a **403** whose body carries a stable `reason`. Find it in the
response body or the audit trail and match it here.

**`client_cert_required`** — an `mtls` route and the client sent no
certificate. Check that the client is actually configured to present one and
that the gateway's listener is the one you think.

**`mtls_authentication_failed`** — a certificate arrived and did not verify.
Wrong CA, expired, or not yet valid.

**`idevid_required`** — `--require-idevid` and the certificate is not a valid
TCG IDevID. Also produced when an `mtls-or-token` route with
`--require-idevid` is reached over the token path, because a token caller can
never present one.

**`zone_missing`** — the certificate has no `OIDTPNetworkZone` extension and
the route enforces zones. Reissue the certificate with a zone; the proxy will
not guess one.

**`zone_not_allowed`** — the caller's zone is not in `--allowed-zone`.

**`zone_matrix_denied`** — the zone matrix does not permit
caller-zone → `--backend-zone`. Run `platformctl proxy zone-matrix`. If the
matrix looks empty on a freshly started gateway, it has not completed its first
sync — the zero state denies everything on purpose.

**`zone_requires_mtls`** — a token caller on a zone-enforcing route with no
`auth.token-zone` assigned.

**`role_required`** — the identity lacks a `--required-role`. On the mTLS path
roles come from the certificate's `roles` attribute, or failing that its OU.

**`token_missing`** — no `Authorization: Bearer` header.

**`token_invalid`** — signature, issuer, audience, expiry, DPoP proof or
liveness check failed. If everything looks right, check whether the gateway
requires a DPoP proof (it does by default) and whether the client is sending
one.

**`token_scope_denied`** — the token is valid and was not granted a
`--required-scope`. This is a broker problem, not a proxy problem: the scope is
minted upstream.

**`attestation_stale`** — no manifest, too old, or platformd rejected it. Check
the machine is still pushing manifests.

**`attestation_unavailable`** — the state could not be established: either the
caller has no device identity (a token caller), or platformd could not be
reached.

**`opa_denied` / `opa_error`** — the policy said no, or failed to evaluate.
The detail is server-side only.

**404 `{"error":"no route"}`** — no route matched. Remember that exact-host
routes are tried before wildcards, that the longest path prefix wins, and that
matching is on segment boundaries: a `/api` route does not match `/apiary`.

**502 `{"error":"bad gateway"}`** — the backend failed. The proxy does no
health checking and no retries; a dead backend in a pool keeps getting its
turn until you remove it.

**A change did not take effect.** Compare `platformctl proxy status` against
the gateway's logs. A gateway that failed to apply a configuration keeps
serving the previous one, logs it, and retries next tick — it does not go
down and does not half-apply.

**Everything disappeared after a platformd restart.** Not expected any more on a
control plane with a database: routes and pools authored over `platformctl proxy`
are persisted through the platform's DAO seam and reload on start (#570). If they
did vanish, the daemon logged `proxy store is in-memory` at startup — it had no
DAO factory — and the fix is the database, not the proxy. Routes you want in
version control belong in the control plane's `proxy:` section, which seeds the
store on every start without overwriting what the API changed.

---

## Things worth knowing before you design around them

- **Backend weights are ignored.** You can set them; round-robin does not read
  them.
- **No health checks, no retries, no circuit breaking, no rate limiting.**
- **No HTTP/3 on the proxy listener** — `h1` and `h2` only.
- **No TCP passthrough.**
- **You cannot query a running gateway's proxy state over any API** — listener
  addresses, live counters and sync health are in-process only.
- **An audit outage does not stop traffic.** Audit emission fails open; the
  authorization decisions do not.

---

## Where to go next

- [cli.md](cli.md) — every verb and flag
- [api.md](api.md) — every capability on all six transports
- [architecture.md](architecture.md) — the design, and what it deliberately
  does not do
- [`docs/gateway/user.md`](../gateway/user.md) — running the gateway that hosts
  this
- [`docs/sdn/`](../sdn/) — zones and the matrix ·
  [`docs/attestation/`](../attestation/) — manifests
