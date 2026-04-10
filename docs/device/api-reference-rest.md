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
  "signing_pub": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "hash_algo_id": 11
}
```

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
  "quarantine_network": {"vlan": 666, "auth_method": "none"}
}
```

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
