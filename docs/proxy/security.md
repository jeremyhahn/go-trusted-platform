# Proxy Security Model

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md) §6 and [engineering.md](engineering.md) §4 and §5.5.

## Threat model

| Threat | Defense |
|--------|---------|
| Header spoofing (client injects `X-TP-Client-Zone`, `X-TP-Attested`, ...) | Every inbound `X-TP-*` header is stripped before forwarding; identity headers are set exclusively from the authenticated TLS state. Verified end-to-end by the integration suite. |
| Stolen bearer credential | mTLS-mode routes accept no bearer substitute; identity is the private key bound to a platform-issued certificate (optionally a TPM-resident IDevID key via `require-idevid`). On the token path, `allow-bearer: false` (the default) requires an RFC 9449 DPoP proof on every request, and `cnf.jkt`-bound tokens are useless without the sender's DPoP private key (proof signature, htm/htu binding, jti replay cache). |
| DPoP proof replay / cross-origin replay | The proof's `jti` is tracked in a replay cache and its `htu` must match `scheme://host/path` as reconstructed from the proxy's OWN TLS state and `Host` — inbound `X-Forwarded-Proto`/`X-Forwarded-Host` are deliberately ignored (the proxy is the front door; those headers arrive unauthenticated from the client). |
| Token forwarded to backends | On every authenticated route the caller's inbound `Authorization` value is stripped before forwarding — a backend can never replay the client's platform token. The proxy never mints or forwards credentials toward backends; backends authenticate the proxy through its mTLS platform identity and read the caller's identity from the trusted `X-TP-Client-*` headers. |
| Compromised-but-enrolled device | `require-attestation` routes admit only devices whose newest platformd attestation manifest (AK-signed collection timestamp, keyed by IDevID CN) is younger than `attestation-max-age` AND passes platformd verification; verification outcomes feed the platform event trail and quarantine loop. platformd unreachable = deny (`attestation_unavailable`), bounded by a 5s negative cache. |
| Revoked token accepted | `authz-mode: hybrid` (default) / `online` enforce RFC 7662 introspection liveness through the broker (hybrid caches positives for 15s); a liveness-requiring mode without an introspection endpoint is a startup error, never a silent downgrade to offline. |
| Certificate from a foreign CA | Client chains verify against the platform CA pool only (explicit `client-ca-file` or the [platform anchor](../trust/architecture.md#21-platform-anchor)). No system-store fallback for client auth. |
| Lateral movement across zones | `allowed-zones` / `backend-zone` are enforced against the compiled SDN zone matrix — the same deny-by-default table that programs OVS L2/L3 flow rules. A certificate without the zone extension is denied on zone-scoped routes (`zone_missing`), never defaulted. |
| Misconfiguration opening a hole | Fail-closed composition: `proxy.New`/`Reload` reject any configuration demanding a capability the injected chain lacks (token auth, attestation gating, OPA, zones) with typed errors. There is no "warn and serve" mode. |
| Config tampering in transit | gatewayd syncs from platformd over the sdk/go client: gRPC over the local Unix socket by default, or TCP gRPC with TLS anchored by the platform trust resolver. `InsecureSkipVerify` is never used, anywhere. |
| Downgrade attacks | Front door and platformd gRPC connections are TLS 1.3 minimum. |
| Stale policy after zone change | The zone matrix refreshes on every sync tick (independent of the proxy config version) and swaps atomically; the deny-all matrix is the zero state before the first successful sync. |
| Backend impersonation | Backend pools with `tls.trust-class` verify backend TLS through the platform anchor (`platform`) or the `bmc` strategy chain ([`docs/trust/`](../trust/architecture.md)); unknown trust classes are a typed error, not default trust. |
| Slowloris / connection exhaustion | 30s read-header timeout on every listener; graceful drain bounded by the shutdown context. |

## Denial reasons (auditable)

Every deny produces a `403` with a stable machine-readable reason and an
audit event: `client_cert_required`, `mtls_authentication_failed`,
`idevid_required`, `zone_missing`, `zone_not_allowed`,
`zone_matrix_denied`, `role_required`, `token_auth_not_configured`,
`token_missing`, `token_invalid`, `token_scope_denied`,
`zone_requires_mtls`, `attestation_stale`, `attestation_unavailable`,
`opa_denied`, `opa_error`.

OPA violation detail is logged and audited server-side only — the client
sees the bare `opa_denied` reason, never the policy's reasoning.

## Fail-closed capability gaps (current)

- **Token-only deployments without a client CA**: the auth chain is
  mTLS-anchored; `token` routes require the mTLS chain (client CA pool)
  to be constructible even when every caller uses tokens.
- **Scopes on mTLS identities**: certificates carry roles/zones, not
  OAuth scopes, so `required-scopes` binds the token path only and is
  rejected at validation on `mtls`/`public` routes. On `mtls-or-token`
  routes, certificate callers are authorized by roles/zones and token
  callers additionally by scopes.
