# DNS MCP API Reference

Model Context Protocol (MCP) tools for AI/LLM integration with the DNS service.

| Property | Value |
|----------|-------|
| Transport | stdio or HTTP |
| Port | 9445 (HTTPS mode) |
| Protocol | JSON-RPC 2.0 |

## Overview

MCP enables AI assistants to manage DNS zones and records through structured tool calls.

## Tools

### dns_create_zone

Create a new DNS zone.

**Parameters:**
```json
{
  "name": "string (required) - Zone FQDN with trailing dot",
  "ttl": "number (required) - Default TTL in seconds",
  "description": "string (optional) - Zone description",
  "internal": "boolean (required) - True for internal zones"
}
```

**Example:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "dns_create_zone",
    "arguments": {
      "name": "myzone.internal.",
      "ttl": 3600,
      "description": "My internal zone",
      "internal": true
    }
  },
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [{
      "type": "text",
      "text": "Zone myzone.internal. created successfully with ID 1234567890"
    }]
  },
  "id": 1
}
```

### dns_get_zone

Retrieve zone details.

**Parameters:**
```json
{
  "name": "string (required) - Zone name"
}
```

**Example:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "dns_get_zone",
    "arguments": {
      "name": "example.internal."
    }
  }
}
```

### dns_update_zone

Update zone configuration.

**Parameters:**
```json
{
  "name": "string (required) - Zone name",
  "ttl": "number (optional) - New TTL",
  "description": "string (optional) - New description"
}
```

### dns_delete_zone

Delete a zone and all its records.

**Parameters:**
```json
{
  "name": "string (required) - Zone name"
}
```

### dns_list_zones

List all zones.

**Parameters:**
```json
{
  "internal": "boolean (optional) - Filter by internal/public",
  "limit": "number (optional) - Max results",
  "offset": "number (optional) - Pagination offset"
}
```

### dns_add_record

Add a DNS record to a zone.

**Parameters:**
```json
{
  "zone_name": "string (required) - Zone name",
  "type": "string (required) - Record type (A, AAAA, CNAME, MX, NS, SRV, TXT)",
  "name": "string (required) - Record name",
  "value": "string (required) - Record value",
  "ttl": "number (required) - TTL in seconds",
  "priority": "number (optional) - Priority for MX/SRV",
  "weight": "number (optional) - Weight for SRV",
  "port": "number (optional) - Port for SRV"
}
```

**Example:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "dns_add_record",
    "arguments": {
      "zone_name": "example.internal.",
      "type": "A",
      "name": "server01",
      "value": "192.168.1.100",
      "ttl": 3600
    }
  }
}
```

### dns_get_record

Get a specific DNS record.

**Parameters:**
```json
{
  "zone_name": "string (required) - Zone name",
  "type": "string (required) - Record type",
  "name": "string (required) - Record name"
}
```

### dns_update_record

Update an existing DNS record.

**Parameters:**
```json
{
  "zone_name": "string (required) - Zone name",
  "type": "string (required) - Record type",
  "name": "string (required) - Record name",
  "value": "string (optional) - New value",
  "ttl": "number (optional) - New TTL"
}
```

### dns_delete_record

Delete a DNS record.

**Parameters:**
```json
{
  "zone_name": "string (required) - Zone name",
  "type": "string (required) - Record type",
  "name": "string (required) - Record name"
}
```

### dns_list_records

List records in a zone.

**Parameters:**
```json
{
  "zone_name": "string (required) - Zone name",
  "type": "string (optional) - Filter by record type"
}
```

### dns_add_tlsa_record

Add a TLSA record for DANE.

**Parameters:**
```json
{
  "zone_name": "string (required) - Zone name",
  "name": "string (required) - Record name (e.g., _443._tcp.www)",
  "usage": "number (required) - TLSA usage (0-3)",
  "selector": "number (required) - Selector (0-1)",
  "matching_type": "number (required) - Matching type (0-2)",
  "certificate": "string (required) - Base64-encoded certificate data",
  "ttl": "number (required) - TTL in seconds"
}
```

### dns_resolve

Resolve a name from the managed zones: the longest managed zone suffix of
`name` answers with only the records `name` owns
([resolution.md](resolution.md#api-resolve)). A name with no such records is an
error ("no records found").

**Parameters:**
```json
{
  "name": "string (required) - FQDN to resolve",
  "record_type": "string (optional, default A) - A, AAAA, CNAME, MX, NS or TXT"
}
```

**Example:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "dns_resolve",
    "arguments": {
      "name": "ns1.example.internal.",
      "record_type": "A"
    }
  }
}
```

**Response:**
```json
{
  "result": {
    "content": [{
      "type": "text",
      "text": "Resolved ns1.example.internal. A: 192.168.1.10 (TTL: 3600)"
    }]
  }
}
```

## Resources

MCP resources provide read-only access to DNS data.

### dns://zones

List all zones.

```json
{
  "method": "resources/read",
  "params": {
    "uri": "dns://zones"
  }
}
```

### dns://zones/{zoneName}

Get zone details.

```json
{
  "method": "resources/read",
  "params": {
    "uri": "dns://zones/example.internal."
  }
}
```

### dns://zones/{zoneName}/records

List zone records.

```json
{
  "method": "resources/read",
  "params": {
    "uri": "dns://zones/example.internal./records"
  }
}
```

## Server Configuration

**stdio mode (default):**
```bash
platformctl mcp serve --transport stdio
```

**HTTP mode:**
```bash
platformctl mcp serve --transport http --port 9445
```

## Client Example

```python
import json
import subprocess

def call_mcp_tool(tool_name, arguments):
    request = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        },
        "id": 1
    }

    proc = subprocess.Popen(
        ["platformctl", "mcp", "serve", "--transport", "stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE
    )

    stdout, _ = proc.communicate(json.dumps(request).encode())
    return json.loads(stdout)

# Create zone
result = call_mcp_tool("dns_create_zone", {
    "name": "myzone.internal.",
    "ttl": 3600,
    "internal": True
})

# Add record
result = call_mcp_tool("dns_add_record", {
    "zone_name": "myzone.internal.",
    "type": "A",
    "name": "server01",
    "value": "192.168.1.100",
    "ttl": 3600
})

# Resolve
result = call_mcp_tool("dns_resolve", {
    "name": "server01.myzone.internal.",
    "record_type": "A"
})
```

## Error Responses

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32000,
    "message": "Zone not found",
    "data": {
      "error": "zone_not_found",
      "zone_name": "nonexistent.internal."
    }
  },
  "id": 1
}
```

| Code | Meaning |
|------|---------|
| -32700 | Parse error |
| -32600 | Invalid request |
| -32601 | Method not found |
| -32602 | Invalid params |
| -32000 | Application error |
