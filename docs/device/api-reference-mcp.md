# Device MCP API Reference

Endpoint: `localhost:9445` (HTTP) or `stdio`

## Overview

The Device API is exposed via the Model Context Protocol (MCP) for AI/LLM integration. MCP enables LLMs to query device inventory, manage profiles, and perform attestation operations.

## Tools

### device_register

Register a new device with TPM credentials.

```json
{
  "name": "device_register",
  "description": "Register a new device with TPM credentials",
  "inputSchema": {
    "type": "object",
    "properties": {
      "serial": {"type": "string", "description": "Device serial number"},
      "model": {"type": "string", "description": "Device model"},
      "ek_cert": {"type": "string", "description": "PEM-encoded EK certificate"},
      "attest_pub": {"type": "string", "description": "PEM-encoded attestation public key"},
      "attest_cert": {"type": "string", "description": "PEM-encoded attestation (IAK/AK) certificate issued by the platform CA"},
      "signing_pub": {"type": "string", "description": "PEM-encoded signing public key"},
      "hash_algo_id": {"type": "integer", "description": "Hash algorithm ID (11=SHA256)"}
    },
    "required": ["serial", "model"]
  }
}
```

### device_get

Get device by ID.

```json
{
  "name": "device_get",
  "description": "Get device by ID",
  "inputSchema": {
    "type": "object",
    "properties": {
      "id": {"type": "integer", "description": "Device ID"}
    },
    "required": ["id"]
  }
}
```

### device_update

Update device information.

```json
{
  "name": "device_update",
  "description": "Update device information",
  "inputSchema": {
    "type": "object",
    "properties": {
      "id": {"type": "integer", "description": "Device ID"},
      "serial": {"type": "string"},
      "model": {"type": "string"}
    },
    "required": ["id"]
  }
}
```

### device_delete

Delete device from registry.

```json
{
  "name": "device_delete",
  "description": "Delete device from registry",
  "inputSchema": {
    "type": "object",
    "properties": {
      "id": {"type": "integer", "description": "Device ID"}
    },
    "required": ["id"]
  }
}
```

### device_list

List devices with pagination.

```json
{
  "name": "device_list",
  "description": "List devices with pagination",
  "inputSchema": {
    "type": "object",
    "properties": {
      "page": {"type": "integer", "default": 1},
      "page_size": {"type": "integer", "default": 10},
      "sort_order": {"type": "string", "enum": ["asc", "desc"]}
    }
  }
}
```

### device_find_by_serial

Find device by serial number.

```json
{
  "name": "device_find_by_serial",
  "description": "Find device by serial number",
  "inputSchema": {
    "type": "object",
    "properties": {
      "serial": {"type": "string", "description": "Device serial number"}
    },
    "required": ["serial"]
  }
}
```

### device_attest

Perform TPM-based attestation.

```json
{
  "name": "device_attest",
  "description": "Perform TPM-based device attestation",
  "inputSchema": {
    "type": "object",
    "properties": {
      "device_id": {"type": "integer", "description": "Device ID"},
      "nonce": {"type": "string", "description": "Base64-encoded nonce"},
      "quote": {"type": "string", "description": "Base64-encoded quote"},
      "signature": {"type": "string", "description": "Base64-encoded signature"},
      "pcrs": {"type": "object", "description": "PCR values by index"}
    },
    "required": ["device_id", "nonce", "quote", "signature"]
  }
}
```

### profile_create

Create a new device profile. In addition to the base fields, the tool
accepts the pre-boot record fields used by EK-bound config delivery and
remote UKI signing: `ek_serial`, `ek_cert` (PEM; must parse as an X.509
certificate), `mac_address`, `config` (full merged platform config
object), `assigned`, and `assigned_at` (RFC3339), plus `tls_server_name`
(the certificate name the attestation collector verifies a node of this
profile against; empty means the device FQDN).

```json
{
  "name": "profile_create",
  "description": "Create a new device profile with network configuration and matching rules",
  "inputSchema": {
    "type": "object",
    "properties": {
      "name": {"type": "string"},
      "model": {"type": "string"},
      "role": {"type": "string"},
      "zone": {"type": "string"},
      "networks": {"type": "object"},
      "match_rules": {"type": "object"},
      "ek_serial": {"type": "string"},
      "ek_cert": {"type": "string", "description": "Prestaged PEM EK certificate"},
      "mac_address": {"type": "string"},
      "config": {"type": "object"},
      "assigned": {"type": "boolean"},
      "assigned_at": {"type": "string"},
      "tls_server_name": {"type": "string"}
    },
    "required": ["name"]
  }
}
```

Results render the profile in its domain JSON shape with the uint64 `id`
as a decimal string (JSON numbers lose precision past 2^53). The
prestaged `ek_cert` is echoed back — it is public key material — so
operators can audit what is prestaged. The result also carries the
read-only `pcr_baseline` when one is recorded; a `pcr_baseline` argument
is not part of either write tool's schema and is dropped by the typed
decode, never stored (`docs/device/api.md` §3.6).

### profile_get_by_id

Get profile by ID.

```json
{
  "name": "profile_get_by_id",
  "description": "Get profile details by ID",
  "inputSchema": {
    "type": "object",
    "properties": {
      "id": {"type": "integer", "description": "Profile ID"}
    },
    "required": ["id"]
  }
}
```

### profile_update_by_id

Update profile properties by ID. Partial update: only supplied fields
replace stored values. Accepts the same pre-boot record fields as
`profile_create` (`ek_serial`, `ek_cert`, `mac_address`, `config`,
`assigned`, `assigned_at`, `tls_server_name`); an unparseable `ek_cert` is
rejected with a typed validation error, and an omitted `tls_server_name`
keeps the stored name.

```json
{
  "name": "profile_update_by_id",
  "description": "Update profile properties by ID",
  "inputSchema": {
    "type": "object",
    "properties": {
      "id": {"type": "integer"},
      "name": {"type": "string"},
      "model": {"type": "string"},
      "role": {"type": "string"},
      "ek_serial": {"type": "string"},
      "ek_cert": {"type": "string"},
      "mac_address": {"type": "string"},
      "config": {"type": "object"},
      "assigned": {"type": "boolean"},
      "assigned_at": {"type": "string"},
      "tls_server_name": {"type": "string"}
    },
    "required": ["id"]
  }
}
```

### profile_delete_by_id

Delete profile.

```json
{
  "name": "profile_delete_by_id",
  "description": "Delete a profile by ID",
  "inputSchema": {
    "type": "object",
    "properties": {
      "id": {"type": "integer", "description": "Profile ID"}
    },
    "required": ["id"]
  }
}
```

### profile_list_all

List profiles with pagination.

```json
{
  "name": "profile_list_all",
  "description": "List all profiles with optional pagination",
  "inputSchema": {
    "type": "object",
    "properties": {
      "page": {"type": "integer", "default": 1},
      "page_size": {"type": "integer", "default": 50}
    }
  }
}
```

### profile_find_matching

Find profile matching device attributes.

```json
{
  "name": "profile_find_matching",
  "description": "Find profile matching device attributes",
  "inputSchema": {
    "type": "object",
    "properties": {
      "mac_address": {"type": "string"},
      "serial": {"type": "string"},
      "model": {"type": "string"}
    }
  }
}
```

### profile_find_by_mac

Find profile by MAC address prefix.

```json
{
  "name": "profile_find_by_mac",
  "description": "Find profile by MAC address prefix",
  "inputSchema": {
    "type": "object",
    "properties": {
      "mac_prefix": {"type": "string", "description": "MAC address prefix"}
    },
    "required": ["mac_prefix"]
  }
}
```

### profile_find_by_serial

Find profile by serial prefix.

```json
{
  "name": "profile_find_by_serial",
  "description": "Find profile by serial prefix",
  "inputSchema": {
    "type": "object",
    "properties": {
      "serial_prefix": {"type": "string", "description": "Serial number prefix"}
    },
    "required": ["serial_prefix"]
  }
}
```

### profile_assign_to_device

Binds a profile to a specific device identity (TPM EK certificate serial
and/or MAC address), optionally prestaging the device's PEM-encoded EK
certificate, and marks the profile assigned. The EK certificate is
source-agnostic: it may come from a swtpm-backed vTPM or a physical
hardware TPM. `profile_id` is required, plus at least one of `ek_serial`
or `mac_address`.

```json
{
  "name": "profile_assign_to_device",
  "arguments": {
    "profile_id": 12345,
    "ek_serial": "1234567890",
    "mac_address": "00:25:90:ff:aa:02",
    "ek_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  }
}
```

Returns the updated profile with the uint64 `id` rendered as a decimal
string.

### profile_unassign_from_device

Clears a profile's device binding: the EK serial, MAC address,
prestaged EK certificate, and assignment state are all reset.

```json
{
  "name": "profile_unassign_from_device",
  "arguments": {
    "profile_id": 12345
  }
}
```

Returns the updated (now unassigned) profile.

## Resources

### device://inventory

Read-only access to device inventory.

```json
{
  "uri": "device://inventory",
  "name": "Device Inventory",
  "description": "Complete device inventory with status",
  "mimeType": "application/json"
}
```

### device://profiles

Read-only access to device profiles.

```json
{
  "uri": "device://profiles",
  "name": "Device Profiles",
  "description": "All configured device profiles",
  "mimeType": "application/json"
}
```

### device://{id}

Individual device resource.

```json
{
  "uri": "device://{id}",
  "name": "Device Details",
  "description": "Device details by ID",
  "mimeType": "application/json"
}
```

## Usage Examples

### stdio Mode

```bash
# Start MCP server
platformctl mcp serve --transport stdio

# Example tool call (sent via stdin)
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "device_list",
    "arguments": {"page": 1, "page_size": 10}
  }
}
```

### HTTP Mode

```bash
# Start MCP server
platformctl mcp serve --transport http --port 9445

# Tool call via HTTP
curl -X POST http://localhost:9445/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "device_get",
      "arguments": {"id": 1234567890}
    }
  }'
```

### Response Format

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"id\":1234567890,\"serial\":\"SRV-2024-001\",\"model\":\"TrustedServer-v2\"}"
      }
    ]
  }
}
```

## Error Handling

MCP errors follow JSON-RPC 2.0:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32000,
    "message": "Device not found",
    "data": {"device_id": 999}
  }
}
```

| Code | Description |
|------|-------------|
| -32700 | Parse error |
| -32600 | Invalid request |
| -32601 | Method not found |
| -32602 | Invalid params |
| -32603 | Internal error |
| -32000 | Application error |

See [api-reference.md](api-reference.md) for complete error code mapping.
