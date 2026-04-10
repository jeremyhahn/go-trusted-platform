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

Create a new device profile.

```json
{
  "name": "profile_create",
  "description": "Create a new device profile",
  "inputSchema": {
    "type": "object",
    "properties": {
      "name": {"type": "string"},
      "model": {"type": "string"},
      "role": {"type": "string", "enum": ["server", "client", "iot", "gateway"]},
      "mac_prefix": {"type": "string", "description": "MAC address prefix for matching"},
      "serial_prefix": {"type": "string", "description": "Serial prefix for matching"}
    },
    "required": ["name"]
  }
}
```

### profile_get

Get profile by ID.

```json
{
  "name": "profile_get",
  "description": "Get profile by ID",
  "inputSchema": {
    "type": "object",
    "properties": {
      "id": {"type": "integer", "description": "Profile ID"}
    },
    "required": ["id"]
  }
}
```

### profile_update

Update profile configuration.

```json
{
  "name": "profile_update",
  "description": "Update profile configuration",
  "inputSchema": {
    "type": "object",
    "properties": {
      "id": {"type": "integer"},
      "name": {"type": "string"},
      "model": {"type": "string"},
      "role": {"type": "string"}
    },
    "required": ["id"]
  }
}
```

### profile_delete

Delete profile.

```json
{
  "name": "profile_delete",
  "description": "Delete profile",
  "inputSchema": {
    "type": "object",
    "properties": {
      "id": {"type": "integer", "description": "Profile ID"}
    },
    "required": ["id"]
  }
}
```

### profile_list

List profiles with pagination.

```json
{
  "name": "profile_list",
  "description": "List profiles with pagination",
  "inputSchema": {
    "type": "object",
    "properties": {
      "page": {"type": "integer", "default": 1},
      "page_size": {"type": "integer", "default": 10}
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
