# CA API Reference

This document provides the API reference for Certificate Authority operations
including ACME endpoints and certificate management.

## ACME Endpoints

### Directory

Returns server capabilities and endpoint URLs.

**Endpoint:** `GET /directory`

**Response:**
```json
{
  "newNonce": "https://acme.example.com/acme/new-nonce",
  "newAccount": "https://acme.example.com/acme/new-account",
  "newOrder": "https://acme.example.com/acme/new-order",
  "revokeCert": "https://acme.example.com/acme/revoke-cert",
  "keyChange": "https://acme.example.com/acme/key-change",
  "meta": {
    "termsOfService": "https://example.com/tos",
    "website": "https://example.com",
    "caaIdentities": ["example.com"],
    "externalAccountRequired": false
  }
}
```

### New Nonce

Requests a fresh nonce for JWS signatures.

**Endpoint:** `HEAD /acme/new-nonce` or `GET /acme/new-nonce`

**Response Headers:**
```
Replay-Nonce: abc123...
Cache-Control: no-store
```

### New Account

Registers a new ACME account.

**Endpoint:** `POST /acme/new-account`

**Request:**
```json
{
  "protected": "base64url(JWS protected header)",
  "payload": "base64url({
    \"termsOfServiceAgreed\": true,
    \"contact\": [\"mailto:admin@example.com\"]
  })",
  "signature": "base64url(signature)"
}
```

**Response:**
```json
{
  "status": "valid",
  "contact": ["mailto:admin@example.com"],
  "orders": "https://acme.example.com/acme/acct/123/orders"
}
```

### New Order

Requests a new certificate order.

**Endpoint:** `POST /acme/new-order`

**Request (TLS Certificate):**
```json
{
  "protected": "base64url(JWS header with kid)",
  "payload": "base64url({
    \"identifiers\": [
      {\"type\": \"dns\", \"value\": \"example.com\"},
      {\"type\": \"dns\", \"value\": \"www.example.com\"}
    ],
    \"notBefore\": \"2024-01-01T00:00:00Z\",
    \"notAfter\": \"2025-01-01T00:00:00Z\"
  })",
  "signature": "base64url(signature)"
}
```

**Request (IDevID - enroll-01):**
```json
{
  "protected": "base64url(JWS header)",
  "payload": "base64url({
    \"identifiers\": [
      {\"type\": \"device\", \"value\": \"device-serial-12345\"}
    ]
  })",
  "signature": "base64url(signature)"
}
```

**Response:**
```json
{
  "status": "pending",
  "expires": "2024-01-08T00:00:00Z",
  "identifiers": [
    {"type": "dns", "value": "example.com"}
  ],
  "authorizations": [
    "https://acme.example.com/acme/authz/123"
  ],
  "finalize": "https://acme.example.com/acme/order/456/finalize"
}
```

### Authorization

Retrieves authorization object with challenges.

**Endpoint:** `GET /acme/authz/{id}`

**Response:**
```json
{
  "status": "pending",
  "expires": "2024-01-08T00:00:00Z",
  "identifier": {
    "type": "dns",
    "value": "example.com"
  },
  "challenges": [
    {
      "type": "http-01",
      "url": "https://acme.example.com/acme/chall/abc",
      "status": "pending",
      "token": "xyz789..."
    },
    {
      "type": "dns-01",
      "url": "https://acme.example.com/acme/chall/def",
      "status": "pending",
      "token": "xyz789..."
    }
  ]
}
```

### Challenge

Responds to a challenge.

**Endpoint:** `POST /acme/chall/{id}`

**Request:**
```json
{
  "protected": "base64url(JWS header)",
  "payload": "base64url({})",
  "signature": "base64url(signature)"
}
```

**Response:**
```json
{
  "type": "http-01",
  "url": "https://acme.example.com/acme/chall/abc",
  "status": "valid",
  "token": "xyz789...",
  "validated": "2024-01-02T12:00:00Z"
}
```

### Finalize Order

Submits CSR to finalize order.

**Endpoint:** `POST /acme/order/{id}/finalize`

**Request:**
```json
{
  "protected": "base64url(JWS header)",
  "payload": "base64url({
    \"csr\": \"base64url(DER-encoded CSR)\"
  })",
  "signature": "base64url(signature)"
}
```

**Response:**
```json
{
  "status": "valid",
  "certificate": "https://acme.example.com/acme/cert/789"
}
```

### Download Certificate

Downloads issued certificate.

**Endpoint:** `GET /acme/cert/{id}`

**Response:**
```
-----BEGIN CERTIFICATE-----
MIIDxTCCAq2gAwIBAgIUdQlKHjJ8...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDxTCCAq2gAwIBAgIUdQlKHjJ8...
-----END CERTIFICATE-----
```

### Revoke Certificate

Revokes a certificate.

**Endpoint:** `POST /acme/revoke-cert`

**Request:**
```json
{
  "protected": "base64url(JWS header)",
  "payload": "base64url({
    \"certificate\": \"base64url(DER certificate)\",
    \"reason\": 1
  })",
  "signature": "base64url(signature)"
}
```

**Revocation Reason Codes:**
| Code | Reason                |
|------|-----------------------|
| 0    | unspecified           |
| 1    | keyCompromise         |
| 2    | cACompromise          |
| 3    | affiliationChanged    |
| 4    | superseded            |
| 5    | cessationOfOperation  |

## enroll-01 Challenge Endpoints

### Submit TCG-CSR-IDEVID

**Endpoint:** `POST /.well-known/acme-challenge/{token}`

**Request:**
```json
{
  "version": 1,
  "attestationType": "TPM20",
  "identityObject": {
    "iakPublic": "base64(TPM2B_PUBLIC)",
    "iakName": "base64(TPM2B_NAME)",
    "idevidCsr": "base64(PKCS#10 CSR)"
  },
  "endorsementObject": {
    "ekCertificate": "base64(X.509 certificate)",
    "ekPublic": "base64(TPM2B_PUBLIC)"
  }
}
```

**Response:**
```json
{
  "status": "processing",
  "activationUrl": "https://acme.example.com/.well-known/acme-activation/{token}"
}
```

### Get Credential Blob

**Endpoint:** `GET /.well-known/acme-activation/{token}`

**Response:**
```json
{
  "credentialBlob": "base64(encrypted credential)",
  "secret": "base64(encrypted secret bound to IAK)"
}
```

### Submit Activated Credential

**Endpoint:** `POST /.well-known/acme-activation/{token}`

**Request:**
```json
{
  "decryptedSecret": "base64(decrypted secret from TPM)"
}
```

**Response:**
```json
{
  "status": "valid"
}
```

## Certificate Management API

### List Certificates

**Endpoint:** `GET /api/v1/certificates`

**Query Parameters:**
| Parameter   | Type   | Description                    |
|-------------|--------|--------------------------------|
| status      | string | Filter by status (active/revoked/expired) |
| issuer      | string | Filter by issuing CA CN        |
| page        | int    | Page number                    |
| limit       | int    | Results per page               |

**Response:**
```json
{
  "certificates": [
    {
      "serialNumber": "1234567890",
      "subjectCn": "server.example.com",
      "issuerCn": "Trusted Platform TLS CA",
      "notBefore": "2024-01-01T00:00:00Z",
      "notAfter": "2025-01-01T00:00:00Z",
      "status": "active",
      "keyAlgorithm": "ECDSA-P256"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 150
  }
}
```

### Get Certificate

**Endpoint:** `GET /api/v1/certificates/{serial}`

**Response:**
```json
{
  "serialNumber": "1234567890",
  "subjectCn": "server.example.com",
  "subject": {
    "cn": "server.example.com",
    "o": "Example Corp",
    "c": "US"
  },
  "issuer": {
    "cn": "Trusted Platform TLS CA"
  },
  "notBefore": "2024-01-01T00:00:00Z",
  "notAfter": "2025-01-01T00:00:00Z",
  "status": "active",
  "keyAlgorithm": "ECDSA-P256",
  "keyUsage": ["digitalSignature", "keyEncipherment"],
  "extKeyUsage": ["serverAuth"],
  "san": {
    "dns": ["server.example.com", "www.example.com"],
    "ip": ["192.168.1.100"]
  },
  "certificatePem": "-----BEGIN CERTIFICATE-----\n..."
}
```

### Issue Certificate (Direct)

**Endpoint:** `POST /api/v1/certificates`

**Request:**
```json
{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "validityDays": 365,
  "issuer": "Trusted Platform TLS CA"
}
```

**Response:**
```json
{
  "serialNumber": "1234567890",
  "certificatePem": "-----BEGIN CERTIFICATE-----\n...",
  "chainPem": "-----BEGIN CERTIFICATE-----\n..."
}
```

### Revoke Certificate (Direct)

**Endpoint:** `POST /api/v1/certificates/{serial}/revoke`

**Request:**
```json
{
  "reason": 1,
  "reasonText": "Key compromised"
}
```

**Response:**
```json
{
  "serialNumber": "1234567890",
  "status": "revoked",
  "revokedAt": "2024-06-15T12:00:00Z",
  "revocationReason": 1
}
```

## CA Information API

### Get CA Info

**Endpoint:** `GET /api/v1/ca`

**Response:**
```json
{
  "cas": [
    {
      "cn": "Trusted Platform Root CA",
      "type": "root",
      "algorithm": "ECDSA-P384",
      "notBefore": "2020-01-01T00:00:00Z",
      "notAfter": "2040-01-01T00:00:00Z",
      "certificateCount": 3
    },
    {
      "cn": "Trusted Platform TLS CA",
      "type": "intermediate",
      "issuer": "Trusted Platform Root CA",
      "algorithm": "RSA-4096",
      "notBefore": "2020-01-02T00:00:00Z",
      "notAfter": "2030-01-02T00:00:00Z",
      "certificateCount": 1500
    }
  ]
}
```

### Get CA Certificate

**Endpoint:** `GET /api/v1/ca/{cn}/certificate`

**Response:**
```
-----BEGIN CERTIFICATE-----
MIIDxTCCAq2gAwIBAgIUdQlKHjJ8...
-----END CERTIFICATE-----
```

### Get CA Bundle

**Endpoint:** `GET /api/v1/ca/bundle`

**Query Parameters:**
| Parameter | Type   | Description                      |
|-----------|--------|----------------------------------|
| format    | string | pem (default) or der             |
| include   | string | Comma-separated CA CNs           |

**Response:**
```
-----BEGIN CERTIFICATE-----
... (Intermediate CA)
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
... (Root CA)
-----END CERTIFICATE-----
```

## CRL/OCSP Endpoints

### Get CRL

**Endpoint:** `GET /crl/{ca}.crl`

**Response:** DER-encoded CRL

### OCSP Request

**Endpoint:** `POST /ocsp`

**Request:** DER-encoded OCSP request

**Response:** DER-encoded OCSP response

## Error Responses

### ACME Errors

```json
{
  "type": "urn:ietf:params:acme:error:badCSR",
  "detail": "The CSR is unacceptable (e.g., due to a short key)",
  "status": 400
}
```

### API Errors

```json
{
  "error": {
    "code": "CERTIFICATE_NOT_FOUND",
    "message": "Certificate with serial 123456 not found",
    "details": {}
  }
}
```

## Authentication

### ACME

ACME endpoints use JWS (JSON Web Signature) for authentication with account keys.

### REST API

```bash
# mTLS authentication
curl --cert client.crt --key client.key \
  https://api.example.com/api/v1/certificates

# Bearer token
curl -H "Authorization: Bearer <token>" \
  https://api.example.com/api/v1/certificates
```

## Related Documentation

- [README](README.md) - CA overview
- [ACME](acme.md) - ACME server details
- [Configuration](configuration.md) - Configuration reference
- [CLI Usage](cli-usage.md) - Command-line interface
