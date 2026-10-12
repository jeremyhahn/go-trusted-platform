# TPM REST API Reference

Base URL: `https://localhost:8443/api/v1/tpm`

All endpoints require mTLS client certificate authentication unless `--skip-iam-validation` is used.

## TPM Information and Management

### Get TPM Info

```
GET /api/v1/tpm/info
```

**Response:** `200 OK`. The payload is the flat proto `TPMInfoResponse` in the
standard envelope, with camelCase keys and enums spelled as their proto names.
Every field is always present: `manufacturer` is `null` when the TPM's fixed
properties could not be read (the text report in `properties.info` is still
returned), and empty lists and maps are `[]` and `{}`.
```json
{
  "code": 200,
  "error": "",
  "success": true,
  "payload": {
    "version": "TPM_VERSION_2_0",
    "manufacturer": {
      "name": "Infineon",
      "id": 1229346816,
      "model": "SLB9670",
      "firmwareVersion": "7.85"
    },
    "capabilities": [
      { "name": "SHA256", "supported": true, "value": "supported" }
    ],
    "pcrBanks": ["PCR_BANK_SHA256"],
    "maxNvramSize": 2048,
    "isSimulator": false,
    "fipsMode": true,
    "properties": { "info": "..." },
    "nvIndexes": [
      { "handle": 29360130, "type": "ordinary", "size": 1024, "authRead": true, "authWrite": false }
    ]
  }
}
```

There is no availability flag. A TPM is available exactly when this call
succeeds; without one the daemon answers `503 Service Unavailable` with
`success: false`. The JavaScript SDK's `client.tpm.getInfo()` and
`client.platform.getTPMInfo()` both call this endpoint and return the payload
typed as `TPMInfoResponse`.

### Provision TPM

```
POST /api/v1/tpm/provision
```

**Request:**
```json
{
  "owner_password": "secure-password"
}
```

**Response:** `200 OK`
```json
{
  "success": true,
  "message": "TPM provisioned successfully",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Clear TPM

```
POST /api/v1/tpm/clear
```

**Request:**
```json
{
  "owner_password": "secure-password"
}
```

**Response:** `200 OK`
```json
{
  "success": true,
  "message": "TPM cleared successfully",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Endorsement Key Operations

### Get Endorsement Key

```
GET /api/v1/tpm/ek
```

**Response:** `200 OK`
```json
{
  "handle": 2147483655,
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "algorithm": "RSA_2048",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Create Endorsement Key

```
POST /api/v1/tpm/ek
```

**Request:**
```json
{
  "persistent": true
}
```

**Response:** `201 Created`
```json
{
  "success": true,
  "handle": 2147483655,
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Delete Endorsement Key

```
DELETE /api/v1/tpm/ek
```

**Response:** `204 No Content`

### Get EK Certificate

```
GET /api/v1/tpm/ek/certificate
```

**Response:** `200 OK`
```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Import EK Certificate

```
POST /api/v1/tpm/ek/certificate
```

**Request:**
```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
}
```

**Response:** `201 Created`
```json
{
  "success": true,
  "message": "EK certificate imported",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Storage Root Key Operations

### Get Storage Root Key

```
GET /api/v1/tpm/srk
```

**Response:** `200 OK`
```json
{
  "handle": 2147483656,
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "algorithm": "RSA_2048",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Create Storage Root Key

```
POST /api/v1/tpm/srk
```

**Response:** `201 Created`
```json
{
  "success": true,
  "handle": 2147483656,
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Delete Storage Root Key

```
DELETE /api/v1/tpm/srk
```

**Response:** `204 No Content`

## Initial Attestation Key Operations

### Get Initial Attestation Key

```
GET /api/v1/tpm/iak
```

**Response:** `200 OK`
```json
{
  "handle": 2147483657,
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "algorithm": "RSA_2048",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Create Initial Attestation Key

```
POST /api/v1/tpm/iak
```

**Response:** `201 Created`
```json
{
  "success": true,
  "handle": 2147483657,
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Delete Initial Attestation Key

```
DELETE /api/v1/tpm/iak
```

**Response:** `204 No Content`

### Get Initial Device ID

```
GET /api/v1/tpm/idevid
```

**Response:** `200 OK`
```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Attestation Operations

### Quote PCRs

```
POST /api/v1/tpm/quote
```

**Request:**
```json
{
  "nonce": "base64-encoded-nonce",
  "pcr_indices": [0, 1, 2, 3, 7, 8, 9]
}
```

**Response:** `200 OK`
```json
{
  "quote": "base64-encoded-quote",
  "signature": "base64-encoded-signature",
  "event_log": "base64-encoded-event-log",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Verify Quote

```
POST /api/v1/tpm/verify-quote
```

**Request:**
```json
{
  "quote": "base64-encoded-quote",
  "signature": "base64-encoded-signature",
  "ak_public": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "nonce": "base64-encoded-nonce"
}
```

**Response:** `200 OK`
```json
{
  "verified": true,
  "message": "Quote verified successfully",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Certify Key

```
POST /api/v1/tpm/certify
```

**Request:**
```json
{
  "handle": 2147483657,
  "nonce": "base64-encoded-nonce"
}
```

**Response:** `200 OK`
```json
{
  "certify_info": "base64-encoded-certify-info",
  "signature": "base64-encoded-signature",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Platform Configuration Register Operations

### Read PCRs

```
GET /api/v1/tpm/pcrs?indices=0,1,2,3,7,8,9&bank=SHA256
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `indices` | string | Comma-separated PCR indices |
| `bank` | string | Hash bank (SHA1, SHA256, SHA384, SHA512) |

**Response:** `200 OK`
```json
{
  "pcr_values": [
    {
      "index": 0,
      "bank": "SHA256",
      "value": "base64-encoded-pcr-value"
    }
  ],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Extend PCR

```
POST /api/v1/tpm/pcrs/extend
```

**Request:**
```json
{
  "pcr_index": 9,
  "hash_alg": "SHA256",
  "data": "base64-encoded-data"
}
```

**Response:** `200 OK`
```json
{
  "success": true,
  "message": "PCR extended",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Event Log

### Get Event Log

```
GET /api/v1/tpm/eventlog?format=json
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `format` | string | Output format (json, binary, text) |

**Response:** `200 OK`
```json
{
  "event_log": "base64-encoded-event-log",
  "format": "json",
  "event_count": 42,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Capabilities

### Get TPM Capabilities

```
GET /api/v1/tpm/capabilities
```

**Response:** `200 OK`
```json
{
  "capabilities": [
    {
      "name": "SHA256",
      "value": "supported",
      "supported": true
    },
    {
      "name": "HMAC",
      "value": "supported",
      "supported": true
    }
  ],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Random Number Generation

### Get Random Bytes

```
POST /api/v1/tpm/random
```

**Request:**
```json
{
  "num_bytes": 32
}
```

**Response:** `200 OK`
```json
{
  "random_bytes": "base64-encoded-random-bytes",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Seal and Unseal Operations

### Seal Data

```
POST /api/v1/tpm/seal
```

**Request:**
```json
{
  "data": "base64-encoded-plaintext"
}
```

**Response:** `200 OK`
```json
{
  "sealed_data": "base64-encoded-sealed-data",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Unseal Data

```
POST /api/v1/tpm/unseal
```

**Request:**
```json
{
  "cn": "object-common-name"
}
```

**Response:** `200 OK`
```json
{
  "data": "base64-encoded-plaintext",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## NVRAM Operations

### Define NVRAM Index

```
POST /api/v1/tpm/nv/define
```

**Request:**
```json
{
  "index": 2148007936,
  "size": 256,
  "password": "index-password"
}
```

**Response:** `201 Created`
```json
{
  "success": true,
  "message": "NV index defined",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Write NVRAM

```
POST /api/v1/tpm/nv/write
```

**Request:**
```json
{
  "index": 2148007936,
  "data": "base64-encoded-data",
  "password": "index-password"
}
```

**Response:** `200 OK`
```json
{
  "success": true,
  "message": "NVRAM write complete",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Read NVRAM

```
POST /api/v1/tpm/nv/read
```

**Request:**
```json
{
  "index": 2148007936,
  "data_size": 256
}
```

**Response:** `200 OK`
```json
{
  "data": "base64-encoded-data",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Delete NVRAM Index

```
DELETE /api/v1/tpm/nv?index=2148007936
```

**Response:** `204 No Content`

## Certificate Signing Request Operations

### Create IDevID CSR

```
POST /api/v1/tpm/csr/idevid
```

**Request:**
```json
{}
```

**Response:** `201 Created`
```json
{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Create LDevID CSR

```
POST /api/v1/tpm/csr/ldevid
```

**Request:**
```json
{}
```

**Response:** `201 Created`
```json
{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Platform Attributes

### Get Platform Attributes

```
GET /api/v1/tpm/platform
```

**Response:** `200 OK`
```json
{
  "attributes": {
    "manufacturer": "Infineon",
    "model": "SLB9670",
    "firmware_version": "7.85",
    "tpm_version": "2.0"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Error Responses

| Status | Description |
|--------|-------------|
| `400 Bad Request` | Invalid request body or parameters |
| `401 Unauthorized` | Missing or invalid authentication |
| `404 Not Found` | Key or object not found |
| `409 Conflict` | Object already exists |
| `500 Internal Server Error` | TPM operation failed |
| `503 Service Unavailable` | TPM service not available |

**Error Response Format:**
```json
{
  "error": "invalid pcr index",
  "code": "INVALID_ARGUMENT"
}
```

## cURL Examples

```bash
# Get TPM info
curl -X GET https://localhost:8443/api/v1/tpm/info \
  --cacert ca.crt --cert client.crt --key client.key

# Provision TPM
curl -X POST https://localhost:8443/api/v1/tpm/provision \
  --cacert ca.crt --cert client.crt --key client.key \
  -H "Content-Type: application/json" \
  -d '{"owner_password":"secure-password"}'

# Get Endorsement Key
curl -X GET https://localhost:8443/api/v1/tpm/ek \
  --cacert ca.crt --cert client.crt --key client.key

# Read PCRs
curl -X GET "https://localhost:8443/api/v1/tpm/pcrs?indices=0,1,2,3,7&bank=SHA256" \
  --cacert ca.crt --cert client.crt --key client.key

# Generate quote
curl -X POST https://localhost:8443/api/v1/tpm/quote \
  --cacert ca.crt --cert client.crt --key client.key \
  -H "Content-Type: application/json" \
  -d '{"nonce":"dGVzdG5vbmNl","pcr_indices":[0,1,2,3,7,8,9]}'

# Get random bytes
curl -X POST https://localhost:8443/api/v1/tpm/random \
  --cacert ca.crt --cert client.crt --key client.key \
  -H "Content-Type: application/json" \
  -d '{"num_bytes":32}'
```
