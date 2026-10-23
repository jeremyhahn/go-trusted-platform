# Config Delivery REST API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> The config-delivery REST routes, as handled by
> `pkg/provisioning/configdelivery/handler.go`.

Base path: `/api/v1/provisioning`

Two routers register these paths:

| Router | Authentication |
|--------|----------------|
| Webservice (`pkg/webservice/v1/router/device.go`) | `config/nonce`, `config`, `sign` and `sessions/{sessionID}/poll` are unauthenticated: a booting device has no client certificate, so the service authenticates it by EAB and a single-use nonce ([api-reference.md](api-reference.md#authentication-model)). `sessions`, `sessions/{sessionID}` and `fulfill` need the `provisioning:read` or `provisioning:write` scope |
| Daemon REST (`pkg/api/daemon/rest_service.go`, port 8443) | All seven, behind the listener's mTLS: every connection needs a client certificate, so a device without one cannot reach them here |

## Response Envelope

All responses use the platform webservice envelope; the payloads shown below
are the `payload` field:

```json
{ "code": 200, "success": true, "payload": { ... } }
{ "code": 400, "success": false, "error": "configdelivery: nonce expired or already used" }
```

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/config/nonce` | Issue a single-use nonce |
| POST | `/config` | Fetch config (EAB + nonce + optional EK cert) |
| POST | `/sign` | Remote Secure Boot DB digest signing |
| GET | `/sessions` | List active provisioning sessions |
| GET | `/sessions/{sessionID}` | Get a session by ID |
| GET | `/sessions/{sessionID}/poll` | Poll a session for fulfillment |
| POST | `/sessions/{sessionID}/fulfill` | Fulfill a session (operator) |

### Get Nonce

```http
GET /api/v1/provisioning/config/nonce
```

```json
{ "nonce": "3f8a...64-hex-chars...b1" }
```

The nonce is 32 random bytes in hex, valid for 5 minutes and spent on first
use.

### Fetch Config

```http
POST /api/v1/provisioning/config
Content-Type: application/json

{
  "ek_serial": "ABC123",
  "mac_address": "52:54:00:12:34:56",
  "ek_cert": "<standard-base64 DER EK certificate>",
  "eab_key_id": "kid-1234",
  "eab_hmac": "<base64url HMAC key>",
  "nonce": "3f8a...b1"
}
```

`eab_key_id`, `eab_hmac`, `nonce`, and at least one of `ek_serial` /
`mac_address` are required.

**Delivered** (profile matched, EK binding passed):

```json
{ "config": { "...merged device config..." }, "status": "ok" }
```

**Pending** (no profile matched — enter interactive QR mode):

```json
{
  "session_id": "0b6f9c7e-8f3e-4b2a-9c1d-2f4a5b6c7d8e",
  "provision_url": "https://platform:8443/api/v1/provisioning/sessions/0b6f9c7e-8f3e-4b2a-9c1d-2f4a5b6c7d8e",
  "poll_interval_seconds": 5
}
```

**Errors:** 400 malformed or missing fields, spent nonce, or an EK
certificate that does not parse; 401 EAB validation failure; 403 EK
certificate required or mismatched, or the EAB key bound to another profile;
500 internal.

### Sign Digest

```http
POST /api/v1/provisioning/sign
Content-Type: application/json

{
  "ek_serial": "ABC123",
  "mac_address": "52:54:00:12:34:56",
  "ek_cert": "<standard-base64 DER EK certificate>",
  "eab_key_id": "kid-1234",
  "eab_hmac": "<base64url HMAC key>",
  "nonce": "3f8a...b1",
  "digest": "<standard-base64 digest>",
  "key_ref": "db"
}
```

```json
{ "signature": "<base64 signature>", "cert_pem": "<base64 DB certificate PEM>" }
```

**Errors:** 400 bad input/spent nonce, 403 EAB or EK failure, 409 profile not
provisioned for remote signing, 503 no DB key signer configured.

### List Sessions

```http
GET /api/v1/provisioning/sessions
```

```json
[
  {
    "id": "0b6f9c7e-8f3e-4b2a-9c1d-2f4a5b6c7d8e",
    "ek_serial": "ABC123",
    "mac_address": "52:54:00:12:34:56",
    "fulfilled": false,
    "created_at": "2026-08-02T17:04:05Z",
    "expires_at": "2026-08-02T17:34:05Z"
  }
]
```

### Get Session

```http
GET /api/v1/provisioning/sessions/{sessionID}
```

Returns the session object above (plus `tenant_id` when the session has one, `profile_id`, as a JSON string, and
`profile` once fulfilled). Sessions expire 30 minutes after creation. **404**
when the session does not exist.

### Poll Session

```http
GET /api/v1/provisioning/sessions/{sessionID}/poll
```

**Pending:** `{ "status": "pending" }`

**Fulfilled:** `{ "config": { ... }, "status": "ok" }`

**Errors:** 404 unknown session, 400 expired session, 500 session fulfilled
without a resolved profile (profile-less fulfillment).

### Fulfill Session

```http
POST /api/v1/provisioning/sessions/{sessionID}/fulfill
Content-Type: application/json

{ "session_id": "0b6f9c7e-...", "profile_id": "42" }
```

`profile_id` is accepted as a JSON string or number. The path's
`{sessionID}` wins over `session_id` in the body.

```json
{ "status": "fulfilled" }
```

**Errors:** 404 unknown session or profile, 400 expired or already-fulfilled
session, 400 missing or zero `profile_id`
(`configdelivery: profile_id is required and must be non-zero`, the same typed
error every transport returns).
