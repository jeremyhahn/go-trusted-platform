# Device REST API Reference

Base URL: `https://localhost:8443/api/v1`

## Device Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/devices` | Register a new device |
| GET | `/devices/{id}` | Get device by ID |
| PUT | `/devices/{id}` | Update device |
| DELETE | `/devices/{id}` | Delete device |
| GET | `/devices` | List devices |
| GET | `/devices/serial/{serial}` | Find by serial |
| POST | `/devices/{id}/attest` | Attest device |

## Profile Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/profiles` | Create profile |
| GET | `/profiles/{id}` | Get profile by ID |
| PUT | `/profiles/{id}` | Update profile |
| DELETE | `/profiles/{id}` | Delete profile |
| GET | `/profiles` | List profiles |
| GET | `/profiles/match` | Find matching profile |
| GET | `/profiles/mac/{prefix}` | Find by MAC prefix |
| GET | `/profiles/serial/{prefix}` | Find by serial prefix |
| POST | `/devices/profiles/{id}/assign` | Bind profile to a device identity (EK serial / MAC), optionally prestaging the EK certificate |
| POST | `/devices/profiles/{id}/unassign` | Clear a profile's device binding |

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
  "config": {"hostname": "lab-node-2"},
  "assigned": false,
  "assigned_at": "2026-08-01T09:00:00Z"
}
```

`ek_cert` prestages the PEM-encoded hardware EK certificate; a non-empty
value that does not parse as a PEM X.509 certificate is rejected with
`400 Bad Request`. The certificate is public key material, so profile
reads echo it back for operator auditability. See
`docs/provisioning/config-delivery.md` for the EK-binding contract.

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
  "pcr_baseline": {
    "values": {"0": "a1b2...", "7": "c3d4..."},
    "source": "tofu",
    "recorded_at": "2026-09-01T12:00:00Z",
    "recorded_from_device_id": "9007199254740993"
  }
}
```

`pcr_baseline` is present once a baseline is recorded and is read-only: the
request body has no such field (`api.md` §3.6).

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
least one of `ek_serial` or `mac_address` is required. `ek_cert`
optionally prestages the device's PEM-encoded TPM EK certificate; the
certificate is source-agnostic (swtpm-backed vTPM or physical hardware
TPM) and must parse as a PEM X.509 certificate. An empty `ek_cert`
leaves any previously prestaged certificate untouched.

```http
POST /api/v1/devices/profiles/1/assign
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
POST /api/v1/devices/profiles/1/unassign
```

Response `200 OK`: the updated profile (with `assigned: false` and the
identity fields cleared).

## Error Responses

```json
{
  "error": {
    "code": "DEVICE_NOT_FOUND",
    "message": "Device with ID 999 not found"
  }
}
```

See [api-reference.md](api-reference.md) for complete error code list.
