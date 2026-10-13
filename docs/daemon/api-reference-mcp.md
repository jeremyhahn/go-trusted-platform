# MCP API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [api.md](api.md), the canonical six-transport reference and QUIC category-opcode table.

Model Context Protocol (MCP) API documentation for AI/LLM integration with the Trusted Platform daemon.

## Connection

```
HTTPS: https://127.0.0.1:9445  (TLS 1.3 only; no plaintext listener)
stdio: stdin/stdout
```

The HTTP transport presents the daemon's TLS certificate under the same mTLS
policy as REST and gRPC, and the daemon refuses to start it without one. See
[`api.md`](api.md) §5.

## Protocol Overview

MCP enables AI assistants and LLMs to interact with the Trusted Platform through a standardized tool interface. The daemon exposes platform operations as MCP tools that can be called by AI clients.

## Authentication (OAuth 2.1)

The MCP server implements OAuth 2.1 for Protected Resources per RFC 9728.

### Protected Resource Metadata

```
GET /.well-known/oauth-protected-resource
```

**Response:**
```json
{
  "resource": "https://platformd.example.com:9445",
  "authorization_servers": ["https://auth.example.com"],
  "scopes_supported": [
    "attestation:read", "attestation:write",
    "bmc:admin", "bmc:media", "bmc:power", "bmc:read", "bmc:write",
    "ca:read", "ca:sign-csr",
    "certs:generate", "certs:list", "certs:read", "certs:revoke",
    "ceremony:read", "ceremony:write",
    "device:delete", "device:read", "device:write",
    "..."
  ],
  "bearer_methods_supported": ["header"]
}
```

`scopes_supported` is derived from the tool permission catalog — exactly the
scopes some MCP tool requires, sorted — so it always matches what tool
authorization enforces. The full list is in
[docs/auth/api.md §5](../auth/api.md#5-oauth-21-protected-resource-metadata).

### Authentication Flow

1. Client requests MCP tool/resource
2. Server checks for `Authorization` header
3. If missing: 401 with `WWW-Authenticate` header
4. If present: Validate token via QuicBaaS OIDC provider
5. Extract claims (subject, roles, groups, tenant)
6. Check permission via QuicBaaS PEP (Policy Enforcement Point)
7. Allow or deny access

### Making Authenticated Requests

Include a Bearer token in the Authorization header:

```bash
curl --tlsv1.3 --cacert platform-ca.pem -X POST https://127.0.0.1:9445/mcp \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{"method": "tools/call", "params": {"name": "vtpm_list"}}'
```

### Scope Requirements

| Tool Category | Required Scope |
|---------------|----------------|
| vtpm_* tools | vtpm:read or vtpm:write |
| dns_* tools | dns:read, dns:write, or dns:delete |
| device_* tools | device:read, device:write, or device:delete |
| sdn_* tools | sdn:read, sdn:write, or sdn:delete |
| ca_* tools | certs:generate, certs:revoke, certs:read, certs:list, ca:read, or ca:sign-csr (`ca_sign_csr` only); see docs/ca/api.md §4 |
| platform_health | No scope required (public) |

### Authentication Errors

| Code | Description |
|------|-------------|
| -32001 | Authentication required (no token provided) |
| -32002 | Invalid token (validation failed) |
| -32003 | Permission denied (insufficient scope) |
| -32004 | Authorization service unavailable |

### Tool Errors

A failed tool call answers the code for its error class. `-32004` is also a
service the tool needs being unavailable. See [api.md](api.md) §1 for the table
and how a failure is classified.

| Code | Class |
|------|-------|
| -32602 | Invalid argument (also an unknown tool or a malformed resource URI) |
| -32005 | Not found |
| -32006 | Already exists |
| -32007 | Failed precondition |
| -32603 | Unclassified failure |

See [Authentication Architecture](../auth/README.md) for complete details.

## Transport Modes

### HTTP Transport

`platformd serve` runs MCP over HTTPS, TLS 1.3 only, with the daemon
certificate, on `daemon.mcp.bind-host` / `daemon.mcp.port` (default
`127.0.0.1:9445`, see [Configuration](configuration.md)); `--enable-mcp=false`
turns it off. There is no setting for a plaintext listener.

### stdio Transport

The `stdio` transport communicates via standard input/output for direct CLI
integration. It is a `daemon.Config` value for in-process callers;
`platformd serve` has no key or flag that selects it.

## Available Tools

### Health Tools

#### platform_health

Get overall platform health status.

**Parameters:** None

**Returns:**
```json
{
  "status": "HEALTH_STATUS_HEALTHY",
  "components": [
    {"name": "ca", "status": "HEALTH_STATUS_HEALTHY"},
    {"name": "kms", "status": "HEALTH_STATUS_HEALTHY"}
  ]
}
```

---

#### platform_liveness

Check if platform is alive.

**Parameters:** None

**Returns:**
```json
{
  "live": true,
  "status": "HEALTH_STATUS_HEALTHY"
}
```

---

#### platform_readiness

Check if platform is ready to serve requests.

**Parameters:** None

**Returns:**
```json
{
  "ready": true,
  "status": "HEALTH_STATUS_HEALTHY"
}
```

### vTPM Tools

#### vtpm_create

Create a new vTPM bundle.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| name | string | Yes | Bundle hostname |
| algorithm | string | No | EK algorithm: RSA or ECC, any case (default: the daemon's configured `ek-algorithm`); anything else is InvalidArgument |

**Returns:**
```json
{
  "id": "bundle-123",
  "hostname": "device-001",
  "mode": "pre-assigned",
  "created_at": "2025-01-05T12:00:00Z"
}
```

---

#### vtpm_delete

Delete a vTPM bundle.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| name | string | Yes | Bundle ID or hostname |

**Returns:**
```json
{
  "success": true
}
```

---

#### vtpm_list

List all vTPM bundles.

**Parameters:** None

**Returns:**
```json
[
  {
    "id": "bundle-123",
    "hostname": "device-001",
    "mode": "pre-assigned"
  }
]
```

---

#### vtpm_start

Start a vTPM instance.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| name | string | Yes | Bundle ID or hostname |

---

#### vtpm_stop

Stop a vTPM instance.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| name | string | Yes | Bundle ID or hostname |

### CA Tools

#### ca_info

Get Certificate Authority information.

**Parameters:** None

**Returns:**
```json
{
  "subject": "CN=Platform Root CA",
  "serial": "123456",
  "not_before": "2025-01-01T00:00:00Z",
  "not_after": "2035-01-01T00:00:00Z",
  "algorithm": "ECDSA-P256"
}
```

---

#### ca_sign_csr

Certify an existing KMS key for code signing from a CSR the KMS signed.
Requires a platform token granting `ca:sign-csr` (`certs:generate` does not). The
CSR's subject must be one common name naming a KMS key, with that key's
public key and no SANs; the certificate's extended key usage is
`codeSigning` only. See `docs/ca/api.md`.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| csr_pem | string | Yes | PEM PKCS#10 request signed by the KMS key it names |
| valid_days | int | No | Validity in days; omitted or 0 selects the CA's configured default, as on every other transport |

---

#### ca_issue

Issue a new certificate.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| common_name | string | Yes | Certificate CN |
| organization | string | No | Organization name |
| organizational_unit | string | No | Organizational unit |
| country | string | No | Country code |
| province | string | No | State/province |
| locality | string | No | City/locality |
| address | string | No | Street address |
| postal_code | string | No | Postal code |
| valid_days | int | No | Validity in days |
| algorithm | string | No | Key algorithm: `RSA-2048`/`3072`/`4096`, `ECDSA-P256`/`P384`/`P521`, `ED25519`; an unknown name is refused |
| store_type | string | No | Key store type |
| dns_names | []string | No | SAN DNS names |
| ip_addresses | []string | No | SAN IP addresses |
| email_addresses | []string | No | SAN emails |
| uris | []string | No | SAN URIs |
| key_usage | []string | No | Key usage flags |
| ext_key_usage | []string | No | Extended key usage |
| is_ca | bool | No | CA certificate flag |
| max_path_len | int | No | CA max path length |

**Returns:** the gRPC `IssueCertificateResponse` as JSON — `status`,
`certificate` and `timestamp`. The CA keeps the key; no private key is
returned.

---

#### ca_get

Get certificate by serial number.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| serial | string | Yes | Certificate serial |
| include_pem | bool | No | Include PEM data |
| include_der | bool | No | Include DER data |

---

#### ca_list

List certificates.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| limit | int | No | Maximum results |
| cursor | string | No | Pagination cursor |
| status | string | No | Filter by status |

---

#### ca_revoke

Revoke a certificate.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| serial | string | Yes | Certificate serial |
| reason | int | No | Revocation reason code |
| delete_keys | bool | No | Delete associated keys |

---

#### ca_renew

Renew a certificate.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| serial | string | Yes | Certificate serial |
| extend_days | int | No | Days to extend |
| preserve_attrs | bool | No | Preserve attributes |

---

#### ca_verify

Verify a certificate.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| certificate_pem | string | No | PEM certificate |
| certificate_der | bytes | No | DER certificate |
| check_revoked | bool | No | Check revocation |

---

#### ca_crl

Get Certificate Revocation List.

**Parameters:** None

---

#### ca_bundle

Get CA certificate bundle.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| store_type | string | No | Key store type |
| algorithm | string | No | Key algorithm |

### Device Tools

The full device and profile tool set, with schemas, is in
[`docs/device/api-reference-mcp.md`](../device/api-reference-mcp.md).

#### device_register

Register a new device; the server assigns its id and the result is the created
device.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| serial | string | Yes | Device serial number |
| model | string | No | Device model |
| ek_cert | string | No | PEM TPM endorsement key certificate |
| attest_pub | string | No | Attestation public key |
| attest_cert | string | No | PEM attestation key certificate issued by the platform CA |
| signing_pub | string | No | Signing public key |
| hash_algo_id | integer | No | TPM hash algorithm identifier |

---

#### device_get

Get device by ID.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| device_id | string | Yes | Device ID |

---

#### device_find_by_serial

Find a device by its serial number.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| serial | string | Yes | Device serial number |

---

#### device_list

List devices.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| device_type | string | No | Filter by device type |
| status | string | No | Filter by status |

---

#### device_delete

Delete a device.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| device_id | string | Yes | Device ID |

---

#### device_update

Update a device's model or serial and return the stored device; omitted fields
are kept.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| device_id | string | Yes | Device ID |
| model | string | No | New device model |
| serial | string | No | New device serial number |

### SDN Tools

#### sdn_list_bridges

List SDN bridges.

**Parameters:** None

---

#### sdn_create_bridge

Create an SDN bridge.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| bridge_name | string | Yes | Bridge name |

---

#### sdn_delete_bridge

Delete an SDN bridge.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| bridge_name | string | Yes | Bridge name |

---

#### sdn_get_port_state

Get port state.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| bridge_name | string | Yes | Bridge name |
| port_name | string | Yes | Port name |

---

#### sdn_add_port

Add port to bridge.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| bridge_name | string | Yes | Bridge name |
| port_name | string | Yes | Port name |
| port_type | string | No | Port type |

---

#### sdn_delete_port

Delete port from bridge.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| bridge_name | string | Yes | Bridge name |
| port_name | string | Yes | Port name |

---

#### sdn_list_vlans

List VLANs on bridge.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| bridge_name | string | Yes | Bridge name |

---

#### sdn_create_vlan

Create VLAN.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| bridge_name | string | Yes | Bridge name |
| vlan_id | int | Yes | VLAN ID |
| name | string | No | VLAN name |

---

#### sdn_delete_vlan

Delete VLAN.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| bridge_name | string | Yes | Bridge name |
| vlan_id | int | Yes | VLAN ID |

---

#### sdn_list_flows

List flows on bridge.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| bridge_name | string | Yes | Bridge name |

---

#### sdn_add_flow

Add flow to bridge.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| bridge_name | string | Yes | Bridge name |
| flow | map | Yes | Flow configuration |

---

#### sdn_delete_flow

Delete flow from bridge.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| bridge_name | string | Yes | Bridge name |
| flow_id | string | Yes | Flow ID |

---

#### sdn_flush_flows

Flush all flows from bridge.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| bridge_name | string | Yes | Bridge name |

## Error Handling

MCP errors are returned with error codes and messages:

```json
{
  "error": {
    "code": "service_unavailable",
    "message": "vtpm service is not available"
  }
}
```

### Error Codes

| Code | Description |
|------|-------------|
| `service_unavailable` | Service not configured |
| `not_found` | Resource not found |
| `invalid_argument` | Invalid parameter |
| `operation_not_implemented` | Feature not implemented |

## Usage with AI Assistants

### Claude

```
Human: Create a vTPM bundle for device-001

Claude: I'll create a vTPM bundle using the platform tools.

<tool_use>
{
  "name": "vtpm_create",
  "parameters": {
    "name": "device-001",
    "algorithm": "RSA"
  }
}
</tool_use>
```

### Configuration for AI Clients

Add the MCP server to your AI client configuration:

```json
{
  "mcpServers": {
    "trusted-platform": {
      "command": "platformctl",
      "args": ["mcp", "serve"],
      "env": {}
    }
  }
}
```

Or for the HTTPS transport (the client must trust the platform CA):

```json
{
  "mcpServers": {
    "trusted-platform": {
      "url": "https://127.0.0.1:9445"
    }
  }
}
```

## See Also

- [API Reference](api-reference.md)
- [Configuration](configuration.md)
- [Architecture](architecture.md)
