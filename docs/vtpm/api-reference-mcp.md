# vTPM MCP API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [api.md](api.md) §2-§5. `vtpm_bundle_validate`, `vtpm_bundle_export` and `vtpm_bundle_import` do not exist (the tools are `vtpm_validate`, `vtpm_export`, `vtpm_import`, `pkg/api/mcp/tools.go:308-332`), and every `vtpm_bundle_*` tool is refused by the default-deny `AuthorizeTool` (`pkg/api/mcp/authz.go:50-59`).

Port: `9445` (HTTPS) or stdio
Protocol: Model Context Protocol (MCP) via JSON-RPC 2.0

## Overview

The MCP interface exposes vTPM operations as tools for AI/LLM integration.

## Available Tools

### Bundle Tools

| Tool | Description |
|------|-------------|
| `vtpm_bundle_create` | Create new vTPM bundle |
| `vtpm_bundle_get` | Get bundle by ID |
| `vtpm_bundle_delete` | Delete bundle |
| `vtpm_bundle_list` | List bundles |
| `vtpm_bundle_validate` | Validate bundle integrity |
| `vtpm_bundle_export` | Export bundle as tar.gz |
| `vtpm_bundle_import` | Import bundle from tar.gz |

### Template Tools

| Tool | Description |
|------|-------------|
| `vtpm_template_create` | Create new template |
| `vtpm_template_get` | Get template by ID |
| `vtpm_template_delete` | Delete template |
| `vtpm_template_list` | List templates |
| `vtpm_template_clone` | Clone template to bundle |

### Path Tools

| Tool | Description |
|------|-------------|
| `vtpm_get_bundle_path` | Get bundle filesystem path |
| `vtpm_get_tpm_socket_path` | Get TPM socket path |
| `vtpm_get_nvram_path` | Get NVRAM path |

## Tool Definitions

### vtpm_bundle_create

```json
{
  "name": "vtpm_bundle_create",
  "description": "Create a new vTPM bundle with CA-issued EK certificate",
  "inputSchema": {
    "type": "object",
    "properties": {
      "mode": {
        "type": "string",
        "enum": ["template", "pre-assigned"],
        "description": "Bundle mode"
      },
      "hostname": {
        "type": "string",
        "description": "VM hostname (required for pre-assigned)"
      },
      "ek_algorithm": {
        "type": "string",
        "enum": ["RSA", "ECC"],
        "default": "RSA"
      },
      "secure_boot_enabled": {
        "type": "boolean",
        "default": false
      },
      "labels": {
        "type": "object",
        "additionalProperties": {"type": "string"}
      }
    },
    "required": ["mode"]
  }
}
```

### vtpm_bundle_get

```json
{
  "name": "vtpm_bundle_get",
  "description": "Retrieve a vTPM bundle by ID",
  "inputSchema": {
    "type": "object",
    "properties": {
      "id": {
        "type": "string",
        "description": "Bundle UUID"
      }
    },
    "required": ["id"]
  }
}
```

### vtpm_bundle_list

```json
{
  "name": "vtpm_bundle_list",
  "description": "List vTPM bundles with optional filtering",
  "inputSchema": {
    "type": "object",
    "properties": {
      "mode": {
        "type": "string",
        "enum": ["template", "pre-assigned"]
      },
      "limit": {
        "type": "integer",
        "default": 100
      },
      "offset": {
        "type": "integer",
        "default": 0
      }
    }
  }
}
```

### vtpm_template_clone

```json
{
  "name": "vtpm_template_clone",
  "description": "Clone a template to create a bundle with unique identity",
  "inputSchema": {
    "type": "object",
    "properties": {
      "template_id": {
        "type": "string",
        "description": "Template ID to clone"
      },
      "hostname": {
        "type": "string",
        "description": "Hostname for new bundle"
      },
      "labels": {
        "type": "object",
        "additionalProperties": {"type": "string"}
      }
    },
    "required": ["template_id", "hostname"]
  }
}
```

### vtpm_bundle_validate

```json
{
  "name": "vtpm_bundle_validate",
  "description": "Validate bundle integrity by checking checksums",
  "inputSchema": {
    "type": "object",
    "properties": {
      "id": {
        "type": "string",
        "description": "Bundle UUID"
      }
    },
    "required": ["id"]
  }
}
```

## JSON-RPC Examples

### Initialize Connection

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "clientInfo": {
      "name": "vtpm-client",
      "version": "1.0.0"
    }
  }
}
```

### Call Tool

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "vtpm_bundle_create",
    "arguments": {
      "mode": "pre-assigned",
      "hostname": "vm001.example.com",
      "ek_algorithm": "RSA",
      "secure_boot_enabled": true
    }
  }
}
```

### Tool Response

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"id\":\"f47ac10b-...\",\"mode\":\"pre-assigned\"}"
      }
    ],
    "isError": false
  }
}
```

### Error Response

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "error": {
    "code": -32602,
    "message": "bundle not found"
  }
}
```

## Connection Modes

### stdio Mode

```bash
platformctl mcp --stdio
```

The MCP server reads JSON-RPC from stdin and writes responses to stdout.

### HTTP Mode

```bash
platformctl mcp --http --port 9445
```

Connect via HTTP POST to `https://localhost:9445/mcp`. The listener serves TLS
1.3 only, with the daemon certificate; plain `http://` is not served.

## Go Client Example

```go
type mcpRequest struct {
    JSONRPC string      `json:"jsonrpc"`
    ID      int64       `json:"id"`
    Method  string      `json:"method"`
    Params  interface{} `json:"params,omitempty"`
}

type mcpResponse struct {
    JSONRPC string          `json:"jsonrpc"`
    ID      int64           `json:"id"`
    Result  json.RawMessage `json:"result,omitempty"`
    Error   *mcpError       `json:"error,omitempty"`
}

// Call vtpm_bundle_create
req := mcpRequest{
    JSONRPC: "2.0",
    ID:      1,
    Method:  "tools/call",
    Params: map[string]interface{}{
        "name": "vtpm_bundle_create",
        "arguments": map[string]interface{}{
            "mode":     "pre-assigned",
            "hostname": "vm001.example.com",
        },
    },
}
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VTPM_MCP_ENDPOINT` | MCP server address | `localhost:9445` |
