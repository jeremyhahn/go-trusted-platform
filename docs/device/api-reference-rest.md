# Device REST API Reference

> **Status: REFERENCE** · Last verified: 2026-10-13
> The device, profile, template and diskless-boot REST routes, their scopes and bodies.

Base URL: `https://localhost:8443/api/v1`

The daemon REST listener serves the operator routes below behind its scope guard,
with the scope listed for each path ([`docs/daemon/api.md`](../daemon/api.md) §1, #997).

## Device Endpoints

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| POST | `/devices` | `device:write` | Register a new device |
| GET | `/devices/{id}` | `device:read` | Get device by ID |
| PUT | `/devices/{id}` | `device:write` | Update device |
| DELETE | `/devices/{id}` | `device:delete` | Delete device |
| GET | `/devices` | `device:read` | List devices |
| GET | `/devices/count` | `device:read` | Count devices |
| GET | `/devices/serial/{serial}` | `device:read` | Find by serial |
| POST | `/devices/{id}/attest` | `device:write` | Verify submitted quote evidence (see below) |
| POST | `/devices/{id}/attest-cert/record` | `device:write` | Record the device's attestation certificate without re-enrolling (admin; fail-closed on `tcg-cap-verifiedTPMRestricted`; body `{"reissue": bool, "clear_on_refusal": bool}` optional; `409` when a clear loses its compare-and-clear) — [api.md §4.5](api.md#45-recording-the-attestation-certificate-without-re-enrolling-473) |
| POST | `/devices/{id}/disable` | `device:write` | Block the device's switch port and record it `suspended` (admin; body `{"reason": "<text>"}` optional, at most 256 bytes; `400` when nothing can enforce it) — [api.md §4.7](api.md#47-operator-disable-and-enable-250) |
| POST | `/devices/{id}/enable` | `device:write` | Re-admit a `suspended` device to the quarantine zone and request re-attestation (admin; no body; `400` when the device is not suspended) — [api.md §4.7](api.md#47-operator-disable-and-enable-250) |

Every operator route on this page takes the scope in its table, which is the
scope its gRPC twin takes: behind the platform-token middleware it is required
on top of the admin role gate, and a token without it gets `403`. The legacy JWT
handler carries no scopes, so there the role gate alone applies
([api.md §7](api.md#7-authorization)).

### POST `/devices/{id}/attest`

Request:

```json
{"evidence": "<base64 JSON DeviceQuoteEvidence>"}
```

where the decoded evidence is
`{"quote": "<base64 TPMS_ATTEST>", "signature": "<base64>", "nonce": "<base64>", "pcrs": {"0": "<base64>"}}`.
The same document is carried by gRPC, Unix, QUIC and MCP, so the shape does
not fork per transport.

Response — the verdict, reporting each check rather than a single flag:

```json
{
  "device_id": 12345,
  "serial": "SN-12345",
  "verified": false,
  "signature_valid": false,
  "nonce_valid": true,
  "pcrs_valid": false,
  "ak_certificate_verified": true,
  "attestation_status": "failed",
  "message": "RSA signature verification failed",
  "attested_at": "2026-09-05T19:31:33Z",
  "pcr_baseline_source": "tofu",
  "pcr_baseline_captured": false
}
```

A quote that fails verification is `200` with `verified: false` — the caller
asked whether the device attests and "no" is a successful answer. `400`,
`404` and `503` are reserved for requests that could not be evaluated:
evidence that is not JSON or lacks `quote`, `signature`, `nonce` or `pcrs` is
`400` (`INVALID_ARGUMENT` on gRPC), never `500`. The
route is registered only when the daemon has a verifier wired, so a `404`
means attestation is not configured on this node, never that it silently
passed.

## Diskless Boot Endpoints

Machine-facing, called by a diskless node's platformd during startup — not an
operator API, so REST only. Request/response shapes, refusal rules and status
codes: [api.md §4.6](api.md#46-diskless-boot-delivery-690).

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/device/boot/certificate` | IDevID key proof over the connection (no client certificate) | The IDevID chain recorded at enrollment; body `{"identity": "<name>", "signature": "<base64>"}`. Every unproven request gets one identical 403 |
| POST | `/device/boot` | mTLS (IDevID) | Attested, channel-bound delivery of the node's IDevID chain, IAK certificate, CA bundle and profile; body `{"evidence": "<base64 DeviceQuoteEvidence>"}` |

## Profile Endpoints

Profiles live under the singular `/device/` prefix and device records under
the plural `/devices/`; no path is served under both (#266,
[api.md §3.1](api.md#31-one-name-per-resource)).

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| POST | `/device/profiles` | `device:write` | Create profile |
| GET | `/device/profiles/{id}` | `device:read` | Get profile by ID |
| PUT | `/device/profiles/{id}` | `device:write` | Update profile |
| DELETE | `/device/profiles/{id}` | `device:delete` | Delete profile |
| GET | `/device/profiles` | `device:read` | List profiles |
| GET | `/device/profiles/count` | `device:read` | Count profiles |
| POST | `/device/profiles/match` | `device:read` | Find matching profile |
| GET | `/device/profiles/mac/{mac}` | `device:read` | Find by MAC address |
| GET | `/device/profiles/serial/{serial}` | `device:read` | Find by serial |
| GET | `/device/profiles/find-config` | `device:read` | Find the config for a device (EK serial / MAC) |
| POST | `/device/activate-json` | `device:write` | Activate a device (JSON body) |
| POST | `/device/profiles/{id}/assign` | `device:write` | Bind profile to a device identity (EK serial / MAC), optionally prestaging the EK certificate |
| POST | `/device/profiles/{id}/unassign` | `device:write` | Clear a profile's device binding |

## Template Endpoints

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| GET | `/device/templates` | `device:read` | List templates |
| GET | `/device/templates/{id}` | `device:read` | Get template by ID |
| GET | `/device/templates/name/{name}` | `device:read` | Find template by name |
| PUT | `/device/templates/{id}` | `device:write` | Update template |
| DELETE | `/device/templates/{id}` | `device:delete` | Delete template |
| POST | `/device/templates` | `device:write` | Create a device template (singular path only — the plural `POST` is the bootstrap seeder's, [api.md §4.1](api.md#41-post-apiv1devicestemplates-belongs-to-the-bootstrap-seeder)) |
| POST | `/device/templates/{id}/create-profile` | `device:write` | Build and save a profile from a stored template |

### POST `/device/templates`

```json
{
  "tenant_id": "acme",
  "name": "edge",
  "role": "load-balancer",
  "config": "aG9zdG5hbWU6IGVkZ2UtMDEK",
  "match_rules": {"mac_prefix": "00:25:90"}
}
```

`config` is bytes, so it travels as **base64** in both directions. `name` is
required; an omitted id is assigned by the server. The reply is `201` with the
stored template in the `{code, success, payload}` envelope, `payload.id` a
JSON string. Behind the platform-token middleware the route requires
`device:write`, as `CreateTemplate` does on gRPC, QUIC and MCP; a token without
it gets `403` ([api.md §7](api.md#7-authorization)).

### POST `/device/templates/{id}/create-profile`

```json
{"overrides": {"name": "edge-01", "ek_serial": "1234567890"}}
```

`overrides` is a full profile request
([api.md §3](api.md)); the template id comes from the path. An empty body
means no overrides; a body that does not decode is `400`
(`ErrInvalidRequestBody`) and nothing is stored. The reply is `201` with the
saved profile in the envelope.

The Go SDK reaches both routes as `DeviceService/CreateTemplate` and
`DeviceService/CreateProfileFromTemplate` through the REST adapter
(`sdk/go/transport/rest/device_template.go`), which renders the pb messages
in this shape and refuses the fields it has no place for
([api.md §4](api.md#4-device-templates)).

It reaches `GET`, `PUT` and `DELETE /device/templates/{id}` and
`GET /device/templates` as `DeviceService/GetTemplate`, `UpdateTemplate`,
`DeleteTemplate` and `ListTemplates`. Get and update answer the bare
template; delete answers `204`; the list takes `page` and `page_size` query
parameters and answers `{"templates": [...], "pagination": {page, page_size,
total, total_pages, has_more}}`.

## Device Operations

### Register Device

```http
POST /api/v1/devices
Content-Type: application/json

{
  "serial": "SRV-2024-001",
  "model": "TrustedServer-v2",
  "ek_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "attest_pub": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "attest_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "signing_pub": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "hash_algo_id": 11
}
```

`attest_cert` is the PEM IAK/AK certificate the platform CA issued at
enrollment; enrollment records it automatically (`api.md` §4.4), and it is the
only trust anchor `POST /devices/{id}/attest` accepts. Omitting it on an update
leaves the stored value in place.

Response `201 Created`:
```json
{
  "id": 1234567890,
  "serial": "SRV-2024-001",
  "model": "TrustedServer-v2",
  "hash_algo_id": 11
}
```

### Get Device

```http
GET /api/v1/devices/1234567890
```

Response `200 OK`:
```json
{
  "id": 1234567890,
  "serial": "SRV-2024-001",
  "model": "TrustedServer-v2",
  "ek_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "attest_pub": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "attest_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "signing_pub": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "hash_algo_id": 11
}
```

### Update Device

```http
PUT /api/v1/devices/1234567890
Content-Type: application/json

{
  "id": 1234567890,
  "serial": "SRV-2024-001",
  "model": "TrustedServer-v3"
}
```

Response `200 OK`:
```json
{
  "id": 1234567890,
  "serial": "SRV-2024-001",
  "model": "TrustedServer-v3"
}
```

### Delete Device

```http
DELETE /api/v1/devices/1234567890
```

Response `204 No Content`

### List Devices

```http
GET /api/v1/devices?page=1&page_size=10&sort_order=asc
```

Query Parameters:
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | int | 1 | Page number |
| page_size | int | 10 | Items per page |
| sort_order | string | asc | Sort order (asc/desc) |

Response `200 OK`:
```json
{
  "devices": [
    {"id": 1234567890, "serial": "SRV-2024-001", "model": "TrustedServer-v2"},
    {"id": 1234567891, "serial": "SRV-2024-002", "model": "TrustedServer-v2"}
  ],
  "page": 1,
  "page_size": 10,
  "total_count": 50,
  "total_pages": 5
}
```

### Find by Serial

```http
GET /api/v1/devices/serial/SRV-2024-001
```

Response `200 OK`:
```json
{
  "id": 1234567890,
  "serial": "SRV-2024-001",
  "model": "TrustedServer-v2"
}
```

### Attest Device

```http
POST /api/v1/devices/1234567890/attest
Content-Type: application/json

{
  "nonce": "base64-encoded-nonce",
  "quote": "base64-encoded-quote",
  "signature": "base64-encoded-signature",
  "pcrs": {
    "0": "base64-encoded-pcr0",
    "7": "base64-encoded-pcr7"
  }
}
```

Response `200 OK`:
```json
{
  "verified": true,
  "device_id": 1234567890,
  "attestation_time": "2024-01-15T10:30:00Z"
}
```

## Profile Operations

### Create Profile

```http
POST /api/v1/profiles
Content-Type: application/json

{
  "name": "IoT Sensor Profile",
  "model": "IoT-Sensor-v1",
  "role": "iot",
  "match_rules": {
    "mac_prefix": "52:54:00",
    "serial_prefix": "IOT-"
  },
  "provisioning_network": {
    "vlan": 998,
    "auth_method": "none",
    "dhcp_pool": {
      "network": "10.99.98.0/24",
      "range_start": "10.99.98.100",
      "range_end": "10.99.98.200",
      "lease_time": 3600
    },
    "gateway": "10.99.98.1",
    "dns": ["10.99.98.1"]
  },
  "production_network": {
    "vlan": 100,
    "auth_method": "802.1x",
    "gateway": "10.100.0.1",
    "dns": ["10.100.0.1", "8.8.8.8"]
  },
  "quarantine_network": {
    "vlan": 666,
    "auth_method": "none",
    "gateway": "10.66.6.1"
  }
}
```

Response `201 Created`:
```json
{
  "id": 1,
  "name": "IoT Sensor Profile",
  "model": "IoT-Sensor-v1",
  "role": "iot"
}
```

Profile create and update additionally accept the pre-boot record fields
used by EK-bound config delivery and remote UKI signing:

```json
{
  "ek_serial": "1234567890",
  "ek_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "mac_address": "00:25:90:FF:AA:02",
  "config": {"hostname": "node-02"},
  "assigned": false,
  "assigned_at": "2026-08-01T09:00:00Z"
}
```

`ek_cert` prestages the PEM-encoded hardware EK certificate; a non-empty
value that does not parse as a PEM X.509 certificate is rejected with
`400 Bad Request`. The certificate is public key material, so profile
reads echo it back for operator auditability. See
`docs/provisioning/config-delivery.md` for the EK-binding contract.

Both routes also accept `tls_server_name`: the certificate name the
attestation collector verifies a node of this profile against when it dials
it for a quote (e.g. `compute.example.internal`); omitted means the
device's own FQDN. On `PUT` an omitted or `null` `tls_server_name` keeps the
stored value (`api.md` §3.3), and an explicit `"tls_server_name": ""` clears
it (`api.md` §3.2). The operator path is
`platformctl device profile update <id> --tls-server-name <name>` (or
`--clear-tls-server-name`).

### Get Profile

```http
GET /api/v1/profiles/1
```

Response `200 OK`:
```json
{
  "id": 1,
  "name": "IoT Sensor Profile",
  "model": "IoT-Sensor-v1",
  "role": "iot",
  "match_rules": {
    "mac_prefix": "52:54:00",
    "serial_prefix": "IOT-"
  },
  "provisioning_network": {"vlan": 998, "auth_method": "none"},
  "production_network": {"vlan": 100, "auth_method": "802.1x"},
  "quarantine_network": {"vlan": 666, "auth_method": "none"},
  "tls_server_name": "compute.example.internal",
  "pcr_baseline": {
    "values": {"0": "a1b2...", "7": "c3d4..."},
    "source": "tofu",
    "recorded_at": "2026-09-01T12:00:00Z",
    "recorded_from_device_id": "9007199254740993"
  }
}
```

`pcr_baseline` is present once a baseline is recorded and is read-only: the
request body has no such field (`api.md` §3.6). `tls_server_name` is present
when set (§ Create Profile).

### Update Profile

```http
PUT /api/v1/profiles/1
Content-Type: application/json

{
  "id": 1,
  "name": "IoT Sensor Profile v2",
  "model": "IoT-Sensor-v2",
  "role": "iot"
}
```

Response `200 OK`:
```json
{
  "id": 1,
  "name": "IoT Sensor Profile v2",
  "model": "IoT-Sensor-v2",
  "role": "iot"
}
```

### Delete Profile

```http
DELETE /api/v1/profiles/1
```

Response `204 No Content`

### List Profiles

```http
GET /api/v1/profiles?page=1&page_size=10
```

Response `200 OK`:
```json
{
  "profiles": [
    {"id": 1, "name": "IoT Sensor Profile", "role": "iot"},
    {"id": 2, "name": "Server Profile", "role": "server"}
  ],
  "page": 1,
  "page_size": 10,
  "total_count": 5,
  "total_pages": 1
}
```

### Find Matching Profile

```http
GET /api/v1/profiles/match?mac=52:54:00:aa:bb:cc&serial=IOT-001&model=IoT-Sensor-v1
```

Query Parameters:
| Parameter | Required | Description |
|-----------|----------|-------------|
| mac | No | Device MAC address |
| serial | No | Device serial number |
| model | No | Device model |

At least one parameter required.

Response `200 OK`:
```json
{
  "id": 1,
  "name": "IoT Sensor Profile",
  "model": "IoT-Sensor-v1",
  "role": "iot"
}
```

### Find by MAC Prefix

```http
GET /api/v1/profiles/mac/52:54:00
```

Response `200 OK`:
```json
{
  "id": 1,
  "name": "IoT Sensor Profile",
  "match_rules": {"mac_prefix": "52:54:00"}
}
```

### Find by Serial Prefix

```http
GET /api/v1/profiles/serial/IOT-
```

Response `200 OK`:
```json
{
  "id": 1,
  "name": "IoT Sensor Profile",
  "match_rules": {"serial_prefix": "IOT-"}
}
```

### Assign Profile to Device

Binds a profile to a specific device identity and marks it assigned. At
least one of `device_id`, `ek_serial` or `mac_address` is required. With
`device_id` (a registered device; JSON string or number, `api.md` §3.4) the
server derives `ek_serial` from the device's stored EK certificate and
prestages that certificate; explicit values win over derived ones, a device
with no EK certificate and no explicit identity is `400`, an unknown device
is `404` (#463). `ek_cert` optionally prestages the device's PEM-encoded TPM
EK certificate; the certificate is source-agnostic (swtpm-backed vTPM or
physical hardware TPM) and must parse as a PEM X.509 certificate. An empty
`ek_cert` leaves any previously prestaged certificate untouched.

```http
POST /api/v1/device/profiles/1/assign
Content-Type: application/json

{"device_id": "970392025956353"}
```

```http
POST /api/v1/device/profiles/1/assign
Content-Type: application/json

{
  "ek_serial": "1234567890",
  "mac_address": "00:25:90:ff:aa:02",
  "ek_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
}
```

Response `200 OK`: the updated profile (with `assigned: true`,
`assigned_at`, and the bound identity fields).

### Unassign Profile from Device

Clears the profile's device binding: the EK serial, MAC address,
prestaged EK certificate, and assignment state are all reset.

```http
POST /api/v1/device/profiles/1/unassign
```

Response `200 OK`: the updated profile (with `assigned: false` and the
identity fields cleared).

## Error Responses

Errors use the platform response envelope (`restwire.WebServiceResponse`):

```json
{
  "code": 404,
  "error": "<service error text>",
  "success": false,
  "payload": null
}
```

The CRUD handlers (`handleServiceError` in
`pkg/webservice/v1/device/rest_handlers.go`) answer `400` for an invalid id
or a profile whose networks share a VLAN, `409` for a duplicate serial, `404`
when the device or profile is not found, and `500` otherwise.
