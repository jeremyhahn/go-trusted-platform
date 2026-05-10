# Config Delivery (Post-Bootstrap / Production)

> **Scope:** This doc covers **post-bootstrap (production) config delivery** —
> how already-installed devices fetch updated config from a running control
> plane over authenticated HTTPS with DANE / Noise / SPKI trust bootstrap
> and EAB authentication.
>
> For **bootstrap-time config delivery** (during `platformctl bootstrap run`,
> before the target has any TLS trust store, uses plain HTTP on a private
> deployer network, keyed by MAC address), see
> [`docs/bootstrap/config-delivery.md`](../bootstrap/config-delivery.md).
>
> For the architectural overview that ties both flows together, see
> [`docs/architecture/bootstrap-flow.md`](../architecture/bootstrap-flow.md).

The config delivery system enables devices to fetch their platform configuration from a server at boot time, before ACME enrollment or IDevID issuance.

## Trust Model

At boot time, the device has no TLS trust store and no client certificate. Trust is established in two steps:

1. **Trust Bootstrap**: `platformctl-static bootstrap trust` uses [go-truststrap](https://github.com/jeremyhahn/go-truststrap) to verify the server via DANE (TLSA DNS records), Noise_NK protocol, or SPKI pinning
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

## API Endpoints

All endpoints are on the standard HTTPS port but excluded from mTLS middleware (devices have no client cert at this stage).

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
  "provision_url": "https://platform:8443/provisioning/sessions/sess-uuid",
  "poll_interval_seconds": 5
}
```

### Poll Session

```
GET /api/v1/provisioning/config/poll/{sessionID}

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
POST /api/v1/provisioning/config/fulfill

Request:
{
  "session_id": "sess-uuid",
  "profile_id": 5
}
```

This endpoint requires full authentication (WebAuthn/FIDO2 session or bearer token).

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
