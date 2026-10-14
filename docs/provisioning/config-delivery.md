# Config Delivery (Post-Bootstrap / Production)

> **Scope:** This doc covers **post-bootstrap (production) config delivery** —
> how already-installed devices fetch updated config from a running control
> plane over authenticated HTTPS with DANE / Noise / SPKI trust bootstrap
> and EAB authentication.
>
> For **bootstrap-time config delivery** (during `platformctl bootstrap run`,
> before the target has any TLS trust store, uses plain HTTP on a private
> deployer network, keyed by MAC address), see
> [`docs/architecture/bootstrap-flow.md`](../architecture/bootstrap-flow.md).
>
> For the architectural overview that ties both flows together, see
> [`docs/architecture/bootstrap-flow.md`](../architecture/bootstrap-flow.md).

The config delivery system enables devices to fetch their platform configuration from a server at boot time, before ACME enrollment or IDevID issuance.

## Trust Model

At boot time, the device has no TLS trust store and no client certificate. Trust is established in two steps:

1. **Trust Bootstrap**: `platformctl-static bootstrap trust` dispatches through the canonical `xkms/pkg/trust/bootstrap` library (reached via the `go-quicbaas/sdk/go/xkms/trust/bootstrap` type-alias re-export) to verify the server via DANE (TLSA DNS records), Noise_NK protocol, or SPKI pinning. That library composes [go-truststrap](https://github.com/jeremyhahn/go-truststrap) internally; the platform repo does not import `go-truststrap` directly
2. **Config Fetch**: Once CA trust is established, the device fetches its config over verified HTTPS, authenticated via EAB credentials

## Authentication

Config delivery uses EAB (External Account Binding) credentials for authentication. The device sends its EAB key ID and HMAC key, which the server validates against the EAB credential store.

A nonce mechanism prevents replay attacks:
1. Device requests nonce: `GET /api/v1/provisioning/config/nonce`
2. Device includes nonce in config request
3. Server validates nonce (single-use, 5-minute TTL)

## Device Identification

The server identifies which config to deliver using:

| Priority | Method | Field | Use Case |
|----------|--------|-------|----------|
| 1 | TPM EK Serial | `ek_serial` | Hardware TPM devices, vTPM bundles |
| 2 | Exact MAC | `mac_address` | Non-TPM devices, virtual machines |
| 3 | Prefix Match | `match_rules` | Fleet provisioning with common prefixes |

### EAB Credential Binding

An EAB credential is issued for one device profile in one tenant, and it only
works for that device. After the profile is resolved, config delivery and
remote signing require the validated credential's `ProfileID` to be the
resolved profile's, and — when the profile names a tenant — its `TenantID` to
be the profile's. A credential presented by a device that resolves to another
profile, or to no profile at all, is refused with HTTP 403
(`eab credential is not bound to this device's profile`); it never opens a
pending session and never gets a digest signed.

### EK Certificate Binding

After a profile is matched, the delivered config is cryptographically bound to
the device's hardware Endorsement Key. When the matched profile carries a
prestaged EK certificate (`DeviceProfile.EKCert`, PEM), the device MUST present
its EK certificate in `ek_cert` (standard-base64-encoded DER); the server parses
both certificates and compares their **public keys** (`PublicKey.Equal`, covering
RSA / ECDSA / Ed25519). A missing presented certificate is rejected with HTTP
403 (`ek certificate required`), a public-key mismatch with HTTP 403
(`ek certificate public key mismatch`), and an undecodable presented certificate
with HTTP 400.

EK matching is **enforced by default** (`RequireEKMatch`, default true). With
enforcement on, a matched profile with no prestaged EK certificate is rejected
(there is nothing to verify against). Setting `RequireEKMatch` to false (the
private-repo escape hatch) falls back to EK-serial / MAC matching when the
matched profile has no prestaged EK certificate; a prestaged certificate is
still binding even with enforcement off.

### Prestaging the EK Certificate

The device profile is the pre-boot record (findable by EK serial / MAC), and
its `ek_cert` field (PEM) is the prestaged certificate the EK-binding gate
verifies against. It can be set through every transport surface:

- **gRPC / Unix**: `DeviceService.CreateProfile` / `UpdateProfile` with
  `DeviceProfile.ek_cert` (PEM). A non-empty value that does not parse as a
  PEM X.509 certificate is rejected with `INVALID_ARGUMENT`.
- **REST**: `POST/PUT /api/v1/device/profiles` (webservice) and
  `POST/PUT /api/v1/devices/profiles` (daemon REST) accept `ek_cert` in the
  profile JSON body; malformed certificates are rejected with 400.
- **QUIC**: `OpDeviceCreateProfile` (0x38) / `OpDeviceSetProfile` carry
  `ek_cert` on the profile wire structs.
- **MCP**: the `profile_create` / `profile_update_by_id` tools accept
  `ek_cert`.
- **CLI**: `platformctl device profile create|update --ek-cert <path|PEM>`
  (plus `--ek-serial`, `--mac`, and `--config-file` for the rest of the
  pre-boot record).
- **In-process**: `ProfileService.AssignToDeviceWithEK` (the vTPM generator
  binds the generated EK certificate automatically) and the bootstrap seeder
  (`DiscoveredNode.EKCert`).

The certificate is public key material (it carries no secrets), so profile
reads echo it back on every transport for operator auditability.

Typical hardware prestage flow: capture the EK certificate from the node's
TPM (or the manufacturer's EK certificate bundle), then:

```bash
platformctl device profile update <profile-id> \
  --ek-serial <ek-cert-serial> \
  --mac 00:25:90:FF:AA:02 \
  --ek-cert /path/to/ek-cert.pem
```

With the certificate prestaged, the EK-bound delivered path
(`POST /api/v1/provisioning/config`) and the remote UKI signing path
(`POST /api/v1/provisioning/sign`) complete for that node with
`RequireEKMatch` enforced.

## Multi-Protocol API

Config delivery is exposed with full parity on every platform transport —
REST, gRPC, QUIC (opcode `0xCF`), MCP (`provision_*` tools), and Unix socket —
plus the `sdk/go/services/provision` SDK client and the `platformctl
provision` CLI. REST is the pre-identity install-time path; the other
transports sit behind daemon transport auth for operators and services. See
[api-reference.md](api-reference.md) for the complete per-protocol reference,
including the shared authentication model, the delivered-vs-pending tri-state,
and the cross-transport error mapping.

## API Endpoints (REST)

All endpoints are on the standard HTTPS port but excluded from mTLS middleware (devices have no client cert at this stage). Full details with the response envelope: [api-reference-rest.md](api-reference-rest.md).

### Get Nonce

```
GET /api/v1/provisioning/config/nonce

Response: { "nonce": "a1b2c3d4..." }
```

### Fetch Config

```
POST /api/v1/provisioning/config

Request:
{
  "ek_serial": "ABC123",
  "mac_address": "52:54:00:12:34:56",
  "ek_cert": "<base64-encoded DER EK certificate>",
  "eab_key_id": "kid-1234",
  "eab_hmac": "<base64-encoded-hmac-key>",
  "nonce": "a1b2c3d4..."
}

Response (config found):
{
  "config": { ... },   // Full app.App config
  "status": "ok"
}

Response (no match — enter QR mode):
{
  "session_id": "sess-uuid",
  "provision_url": "https://platform:8443/api/v1/provisioning/sessions/sess-uuid",
  "poll_interval_seconds": 5
}
```

### Sign Digest (remote Secure Boot resign)

A bare-metal node configured with `secure-boot.resign-mode: remote` (see
[Secure Boot](../firmware/secure-boot.md)) sends its UKI / kernel-module digest
to the control plane to be signed by the CP-KMS Secure Boot **DB** key. The DB
private key never leaves the control plane — only the digest crosses the wire.
The request is authenticated exactly like Fetch Config (EAB + nonce + EK
certificate), and EAB and EK verification are enforced *before* any signing.

```
POST /api/v1/provisioning/sign

Request:
{
  "ek_serial": "ABC123",
  "mac_address": "52:54:00:12:34:56",
  "ek_cert": "<base64-encoded DER EK certificate>",
  "eab_key_id": "kid-1234",
  "eab_hmac": "<base64-encoded-hmac-key>",
  "nonce": "a1b2c3d4...",
  "digest": "<base64-encoded digest>",
  "key_ref": "db"
}

Response:
{
  "signature": "<base64-encoded signature>",
  "cert_pem": "<base64-encoded DB certificate PEM>"
}
```

The control plane resolves the device profile, reads the DB key URI from the
profile's `secure-boot.db` block, signs the supplied digest via the platform KMS
(pre-hashed), and returns the signature together with the DB certificate so the
node can embed it in the UKI Authenticode signature and enroll it into the
firmware signature database.

Status codes: `400` malformed request or unusable digest, `403` EAB or EK
verification failure, `409` the device profile is not provisioned for remote
signing (secure boot disabled, `resign-mode` not `remote`, or no DB key URI),
`503` no DB key signer is configured on the control plane.

### Poll Session

```
GET /api/v1/provisioning/sessions/{sessionID}/poll

Response (pending):
{ "status": "pending" }

Response (fulfilled):
{
  "config": { ... },
  "status": "ok"
}
```

### Fulfill Session (operator action)

```
POST /api/v1/provisioning/sessions/{sessionID}/fulfill

Request:
{
  "session_id": "sess-uuid",
  "profile_id": 5
}

Response:
{ "status": "fulfilled" }
```

Sessions are also listed and inspected via
`GET /api/v1/provisioning/sessions` and
`GET /api/v1/provisioning/sessions/{sessionID}`.

## Session Management CLI

Operators manage pending provisioning sessions with `platformctl provision
session`, which drives the `ConfigDeliveryService` over any SDK transport
(Unix socket by default):

```bash
# List all active provisioning sessions
platformctl provision session list

# Get a session by ID
platformctl provision session get 6f1c2b3a

# Link device profile 42 to a pending session (uint64 ID as decimal string)
platformctl provision session fulfill 6f1c2b3a --profile-id 42

# Poll a session once; write the delivered config JSON when fulfilled
platformctl provision session poll 6f1c2b3a --output /tmp/config.json
```

`session poll` prints `{"status": "pending"}` while the session is
unfulfilled; once fulfilled it prints (or writes with `--output`, mode 0600)
the delivered config JSON. In JSON output, uint64 profile IDs serialize as
decimal strings per the repo-wide convention.

The pre-identity flows used on the booting device itself remain
`platformctl provision fetch-config` (EAB + nonce over raw HTTPS) and
`platformctl provision interactive` (QR mode) — see below and
[interactive.md](interactive.md).

## Boot-Time Flow

The `autoinstall.sh` script resolves config using this priority chain:

```
1. Kernel param platform_config=<server_url>
   → platformctl-static bootstrap trust (DANE/Noise/SPKI)
   → platformctl-static provision fetch-config (EAB + EK/MAC)
   → if pending → platformctl-static provision interactive (QR)

2. USB/removable media /platform/config.yaml

3. Embedded in ISO /media/cdrom/configs/config.yaml

4. Interactive QR (if platform_server kernel param set)

5. Fatal error with diagnostics
```

## Kernel Command Line Parameters

| Parameter | Example | Purpose |
|-----------|---------|---------|
| `platform_config` | `https://server:8443` | Server URL for config fetch |
| `platform_server` | `https://server:8443` | Server URL for interactive mode only |
| `bootstrap_strategy` | `auto` | Trust strategy: dane, noise, spki, auto |
| `bootstrap_dns` | `8.8.8.8` | DNS server for DANE lookups |
| `bootstrap_noise_key` | `<hex>` | Noise server public key |
| `bootstrap_spki_pin` | `<sha256>` | SPKI certificate pin |
| `eab_kid` | `kid-1234` | EAB key ID for authentication |
| `eab_hmac` | `<base64>` | EAB HMAC key |
