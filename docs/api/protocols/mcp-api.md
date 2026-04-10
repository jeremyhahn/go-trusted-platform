# MCP API Reference

The MCP (Model Context Protocol) API enables AI assistants like Claude and GPT to interact with the Trusted Platform through tool-based invocation using JSON-RPC 2.0.

## Connection Configuration

### Transports

MCP supports two transport modes:

| Transport | Use Case | Port |
|-----------|----------|------|
| stdio | Local CLI integration | N/A |
| HTTP | Remote AI services | 9445 |

Default port: **9445**

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PLATFORM_MCP_ADDR` | Full address | `https://localhost:9445` |
| `PLATFORM_MCP_PORT` | Port number | `9445` |
| `PLATFORM_MCP_TRANSPORT` | Transport type | `http` |

### Go SDK Configuration

```go
import _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"

client, err := platform.NewClient(ctx,
    platform.WithMCPAddr("https://platform.example.com:9445"),
    platform.WithOnlyProtocol(platform.ProtocolMCP),
    platform.WithTimeout(30*time.Second),
)
```

### Direct MCP Client

```go
import mcpapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"

clientConfig := mcpapi.DefaultClientConfig("https://platform.example.com:9445")
clientConfig.Timeout = 30 * time.Second

client, err := mcpapi.NewClient(clientConfig)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// Initialize connection
serverInfo, err := client.Initialize(ctx)
if err != nil {
    log.Fatal(err)
}
log.Printf("Connected to: %s v%s", serverInfo.Name, serverInfo.Version)
```

## JSON-RPC 2.0 Format

### Request Format

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "tool.name",
    "arguments": {
      "param1": "value1",
      "param2": "value2"
    }
  },
  "id": 1
}
```

### Success Response

```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Operation completed successfully"
      }
    ],
    "data": {
      "field": "value"
    }
  },
  "id": 1
}
```

### Error Response

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": {
      "field": "commonName",
      "reason": "required"
    }
  },
  "id": 1
}
```

## Tool Mapping

MCP exposes platform services as tools that AI assistants can discover and invoke.

### Tool Discovery

```json
{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "params": {},
  "id": 1
}
```

Response:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "tools": [
      {
        "name": "ca.issue",
        "description": "Issue a new X.509 certificate",
        "inputSchema": {
          "type": "object",
          "properties": {
            "commonName": {"type": "string", "description": "Certificate common name"},
            "validDays": {"type": "integer", "description": "Validity period in days"}
          },
          "required": ["commonName"]
        }
      }
    ]
  },
  "id": 1
}
```

### Platform Tools

| Tool Name | Description |
|-----------|-------------|
| `platform.health` | Check platform health |
| `platform.liveness` | Liveness probe |
| `platform.readiness` | Readiness probe |
| `platform.status` | Get platform status |

### CA Tools

| Tool Name | Description |
|-----------|-------------|
| `ca.info` | Get CA information |
| `ca.issue` | Issue certificate |
| `ca.get` | Get certificate by serial |
| `ca.list` | List certificates |
| `ca.revoke` | Revoke certificate |
| `ca.renew` | Renew certificate |
| `ca.verify` | Verify certificate |
| `ca.crl` | Get certificate revocation list |
| `ca.bundle` | Get CA certificate bundle |

### IAM Tools

| Tool Name | Description |
|-----------|-------------|
| `iam.user.create` | Create user |
| `iam.user.delete` | Delete user |
| `iam.user.get` | Get user |
| `iam.user.list` | List users |
| `iam.role.create` | Create role |
| `iam.role.delete` | Delete role |
| `iam.role.get` | Get role |
| `iam.role.list` | List roles |
| `iam.role.assign` | Assign role to user |
| `iam.role.revoke` | Revoke role from user |
| `iam.authenticate` | Authenticate user |
| `iam.check_permission` | Check permission |
| `iam.token.create` | Create access token |
| `iam.token.revoke` | Revoke token |
| `iam.token.verify` | Verify token |

### KMS Tools

| Tool Name | Description |
|-----------|-------------|
| `kms.key.create` | Create encryption key |
| `kms.key.delete` | Delete key |
| `kms.key.get` | Get key metadata |
| `kms.key.list` | List keys |
| `kms.key.rotate` | Rotate key |
| `kms.encrypt` | Encrypt data |
| `kms.decrypt` | Decrypt data |
| `kms.sign` | Sign data |
| `kms.verify` | Verify signature |
| `kms.random` | Generate random bytes |
| `kms.datakey.generate` | Generate data key |

### vTPM Tools

| Tool Name | Description |
|-----------|-------------|
| `vtpm.create` | Create vTPM instance |
| `vtpm.delete` | Delete vTPM |
| `vtpm.start` | Start vTPM |
| `vtpm.stop` | Stop vTPM |
| `vtpm.list` | List vTPM instances |
| `vtpm.state` | Get vTPM state |
| `vtpm.quote` | Get attestation quote |
| `vtpm.seal` | Seal data to PCRs |
| `vtpm.unseal` | Unseal data |
| `vtpm.pcr.extend` | Extend PCR |
| `vtpm.pcr.read` | Read PCR value |

### Device Tools

| Tool Name | Description |
|-----------|-------------|
| `device.register` | Register device |
| `device.delete` | Delete device |
| `device.get` | Get device |
| `device.list` | List devices |
| `device.update` | Update device |
| `device.attest` | Attest device |

### Attestation Tools

| Tool Name | Description |
|-----------|-------------|
| `attestation.quote` | Get attestation quote |
| `attestation.verify` | Verify quote |
| `attestation.ek` | Get endorsement key |
| `attestation.ak` | Get attestation key |
| `attestation.ak.create` | Create attestation key |
| `attestation.challenge` | Create challenge |
| `attestation.challenge.verify` | Verify challenge response |

### SDN Tools

| Tool Name | Description |
|-----------|-------------|
| `sdn.bridge.create` | Create bridge |
| `sdn.bridge.delete` | Delete bridge |
| `sdn.bridge.list` | List bridges |
| `sdn.port.add` | Add port to bridge |
| `sdn.port.delete` | Delete port |
| `sdn.port.get_state` | Get port state |
| `sdn.port.set_state` | Set port state |
| `sdn.flow.add` | Add flow rule |
| `sdn.flow.delete` | Delete flow |
| `sdn.flow.list` | List flows |
| `sdn.policy.apply` | Apply policy |
| `sdn.policy.get` | Get policy |

### DNS Tools

| Tool Name | Description |
|-----------|-------------|
| `dns.record.add` | Add DNS record |
| `dns.record.delete` | Delete record |
| `dns.record.get` | Get record |
| `dns.record.list` | List records |
| `dns.resolve` | Resolve hostname |
| `dns.zone.create` | Create zone |
| `dns.zone.delete` | Delete zone |
| `dns.zone.list` | List zones |

## AI/LLM Integration Use Cases

### Certificate Management Assistant

```
User: "Issue a TLS certificate for api.example.com valid for 90 days"

AI Assistant uses tool: ca.issue
Arguments: {
  "commonName": "api.example.com",
  "dnsNames": ["api.example.com"],
  "validDays": 90
}

Result: Certificate issued with serial 01:23:45:67:89:AB
```

### Security Operations

```
User: "Check the health of all platform services and report any issues"

AI Assistant uses tool: platform.status
Arguments: { "includeServices": true }

Result: All services healthy except DNS (degraded performance)
```

### Device Attestation

```
User: "Verify that device DEV-001 has not been tampered with"

AI Assistant uses tools:
1. device.get - Get device information
2. attestation.quote - Request attestation quote
3. attestation.verify - Verify the quote

Result: Device attestation successful, PCR values match expected policy
```

## MCP Protocol Methods

### Initialization

```json
// Client -> Server
{
  "jsonrpc": "2.0",
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "tools": {}
    },
    "clientInfo": {
      "name": "claude",
      "version": "1.0"
    }
  },
  "id": 1
}

// Server -> Client
{
  "jsonrpc": "2.0",
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "tools": { "listChanged": true }
    },
    "serverInfo": {
      "name": "go-trusted-platform",
      "version": "1.0.0"
    }
  },
  "id": 1
}
```

### Tool Invocation

```json
// Client -> Server
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "ca.issue",
    "arguments": {
      "commonName": "server.example.com",
      "organization": ["Example Corp"],
      "validDays": 365
    }
  },
  "id": 2
}

// Server -> Client
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Certificate issued successfully"
      }
    ],
    "data": {
      "serial": "01:23:45:67:89:AB:CD:EF",
      "subject": "CN=server.example.com,O=Example Corp",
      "notAfter": "2026-01-20T00:00:00Z"
    }
  },
  "id": 2
}
```

### Resource Access

```json
// List available resources
{
  "jsonrpc": "2.0",
  "method": "resources/list",
  "params": {},
  "id": 3
}

// Read resource
{
  "jsonrpc": "2.0",
  "method": "resources/read",
  "params": {
    "uri": "certificate://01:23:45:67:89:AB"
  },
  "id": 4
}
```

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| `-32700` | Parse Error | Invalid JSON |
| `-32600` | Invalid Request | Invalid JSON-RPC |
| `-32601` | Method Not Found | Unknown method |
| `-32602` | Invalid Params | Invalid parameters |
| `-32603` | Internal Error | Server error |
| `-32000` | Authentication Required | Auth needed |
| `-32001` | Invalid Token | Invalid auth token |
| `-32002` | Permission Denied | Access denied |
| `-32003` | Service Unavailable | Service down |

## Authentication

### Token Authentication

```go
// Set token on MCP adapter
adapter := client.(*mcpAdapter)
adapter.SetToken(jwtToken)

// Or with direct client
mcpClient.SetToken(jwtToken)
```

### Request with Authentication

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "ca.issue",
    "arguments": {...}
  },
  "id": 1,
  "_meta": {
    "authorization": "Bearer eyJhbGciOiJSUzI1NiIs..."
  }
}
```

## Complete Example

```go
package main

import (
    "context"
    "log"
    "time"

    mcpapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
    "github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
    _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
)

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    // Create MCP client via SDK
    client, err := platform.NewClient(ctx,
        platform.WithMCPAddr("https://platform.example.com:9445"),
        platform.WithOnlyProtocol(platform.ProtocolMCP),
    )
    if err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    defer client.Close()

    // Use services - MCP maps to JSON-RPC tool calls
    version, err := client.Daemon().GetVersion(ctx, &platformv1.GetVersionRequest{})
    if err != nil {
        log.Fatalf("Failed to get version: %v", err)
    }
    log.Printf("Platform version: %s", version.Version)

    // Or use direct MCP client for tool calls
    directClient := client.(*mcpAdapter).Client()

    // List available tools
    tools, err := directClient.ListTools(ctx)
    if err != nil {
        log.Fatal(err)
    }
    for _, tool := range tools {
        log.Printf("Tool: %s - %s", tool.Name, tool.Description)
    }

    // Call tool directly
    result, err := directClient.CallTool(ctx, "ca.info", nil)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("CA Info: %v", result)
}
```

## Claude/AI Integration Example

When Claude uses the MCP connection to manage certificates:

```
User: Can you issue a certificate for my new API server at api.mycompany.com?

Claude: I'll issue a TLS certificate for your API server.

[Claude calls tool: ca.issue]
{
  "commonName": "api.mycompany.com",
  "dnsNames": ["api.mycompany.com"],
  "validDays": 90
}

Certificate issued successfully!

- Serial: 01:23:45:67:89:AB:CD:EF
- Subject: CN=api.mycompany.com
- Valid Until: April 20, 2025

The certificate is now ready for deployment. Would you like me to help
configure your server to use this certificate?
```
