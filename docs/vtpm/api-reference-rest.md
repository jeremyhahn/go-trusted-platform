# vTPM REST API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [api.md](api.md) §2-§4 and §6, which also carries the REST authorization rule this file omits.

Base URL: `https://localhost:8443/api/v1/vtpm`

## Bundle Endpoints

### Create Bundle

```
POST /api/v1/vtpm/bundles
```

**Request:**
```json
{
  "mode": "pre-assigned",
  "hostname": "vm001.example.com",
  "ek_algorithm": "RSA",
  "secure_boot_enabled": true,
  "labels": {
    "environment": "production"
  }
}
```

**Response:** `201 Created`
```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "mode": "pre-assigned",
  "manifest": {
    "version": "1.0",
    "hostname": "vm001.example.com",
    "ek_algorithm": "RSA",
    "secure_boot_enabled": true
  },
  "created_at": "2024-01-15T10:30:00Z"
}
```

### Get Bundle

```
GET /api/v1/vtpm/bundles/{id}
```

**Response:** `200 OK`
```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "mode": "pre-assigned",
  "manifest": {
    "hostname": "vm001.example.com"
  }
}
```

### Delete Bundle

```
DELETE /api/v1/vtpm/bundles/{id}
```

**Response:** `204 No Content`

### List Bundles

```
GET /api/v1/vtpm/bundles?mode=pre-assigned&limit=50&offset=0
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `mode` | string | Filter by `template` or `pre-assigned` |
| `limit` | int | Maximum results (default: 100) |
| `offset` | int | Skip first N results |
| `labels` | string | Label filter (key=value) |

**Response:** `200 OK`
```json
{
  "bundles": [
    {"id": "...", "mode": "pre-assigned", "manifest": {...}}
  ],
  "total": 1
}
```

## Template Endpoints

### Create Template

```
POST /api/v1/vtpm/templates
```

**Request:**
```json
{
  "id": "base-server",
  "description": "Base template for production servers",
  "ek_algorithm": "RSA",
  "secure_boot_enabled": true
}
```

**Response:** `201 Created`
```json
{
  "id": "base-server",
  "description": "Base template for production servers",
  "ek_algorithm": "RSA",
  "secure_boot_enabled": true,
  "created_at": "2024-01-15T10:30:00Z"
}
```

### Get Template

```
GET /api/v1/vtpm/templates/{id}
```

**Response:** `200 OK`

### Delete Template

```
DELETE /api/v1/vtpm/templates/{id}
```

**Response:** `204 No Content`

### List Templates

```
GET /api/v1/vtpm/templates
```

**Response:** `200 OK`
```json
{
  "templates": [
    {"id": "base-server", "description": "...", "ek_algorithm": "RSA"}
  ]
}
```

### Clone Template

```
POST /api/v1/vtpm/templates/{id}/clone
```

**Request:**
```json
{
  "hostname": "vm002.example.com",
  "labels": {
    "cloned": "true"
  }
}
```

**Response:** `201 Created`
```json
{
  "id": "new-bundle-uuid",
  "mode": "pre-assigned",
  "cloned_from": "base-server"
}
```

## Export/Import Endpoints

### Export Bundle

```
GET /api/v1/vtpm/bundles/{id}/export
```

**Response:** `200 OK`
- Content-Type: `application/gzip`
- Returns tar.gz archive

### Import Bundle

```
POST /api/v1/vtpm/bundles/import
```

**Request:**
- Content-Type: `multipart/form-data`
- Body: tar.gz archive file

**Response:** `201 Created`
```json
{
  "id": "imported-bundle-uuid",
  "mode": "pre-assigned"
}
```

## Validation Endpoint

### Validate Bundle

```
POST /api/v1/vtpm/bundles/{id}/validate
```

**Response:** `200 OK`
```json
{
  "valid": true,
  "errors": []
}
```

**Response (invalid):** `200 OK`
```json
{
  "valid": false,
  "errors": ["checksum mismatch for tpm-state.bin"]
}
```

## Path Helper Endpoints

### Get Bundle Path

```
GET /api/v1/vtpm/bundles/{id}/path
```

**Response:** `200 OK`
```json
{
  "path": "/var/lib/trusted-platform/vtpm/bundles/f47ac10b-..."
}
```

### Get TPM Socket Path

```
GET /api/v1/vtpm/bundles/{id}/tpm-socket
```

**Response:** `200 OK`
```json
{
  "path": "/var/lib/trusted-platform/vtpm/bundles/f47ac10b-.../tpm/swtpm.sock"
}
```

### Get NVRAM Path

```
GET /api/v1/vtpm/bundles/{id}/nvram
```

**Response:** `200 OK`
```json
{
  "path": "/var/lib/trusted-platform/vtpm/bundles/f47ac10b-.../ovmf/OVMF_VARS.fd"
}
```

## Error Responses

| Status | Description |
|--------|-------------|
| `400 Bad Request` | Invalid request body or parameters |
| `404 Not Found` | Bundle or template not found |
| `409 Conflict` | Bundle or template already exists |
| `500 Internal Server Error` | Server error |

**Error Response Format:**
```json
{
  "error": "bundle not found",
  "code": "BUNDLE_NOT_FOUND"
}
```

## cURL Examples

```bash
# Create bundle
curl -X POST https://localhost:8443/api/v1/vtpm/bundles \
  -H "Content-Type: application/json" \
  -d '{"mode":"pre-assigned","hostname":"vm001.example.com"}'

# List bundles
curl https://localhost:8443/api/v1/vtpm/bundles

# Export bundle
curl https://localhost:8443/api/v1/vtpm/bundles/{id}/export -o bundle.tar.gz

# Import bundle
curl -X POST https://localhost:8443/api/v1/vtpm/bundles/import \
  -F "file=@bundle.tar.gz"
```
