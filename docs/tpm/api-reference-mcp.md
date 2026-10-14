# TPM MCP API Reference

Port: `9445` (HTTPS) or stdio
Protocol: Model Context Protocol (MCP) via JSON-RPC 2.0

## Overview

The MCP interface exposes TPM operations as tools for AI/LLM integration. All tools follow the MCP JSON-RPC 2.0 specification.

## Authorization

Each tool needs the scope of its gRPC twin, and fails with that method's error
class (#304). A tool absent from `pkg/api/mcp/authz.go` is refused for every
caller.

| Tools | Scope |
|---|---|
| `info`, `ek`, `ek_cert`, `srk`, `iak`, `pcrs`, `eventlog`, `random`, `nv_list`, `nv_read`, `make_credential`, `quote`, `verify_quote`, `certify` | `tpm:read` |
| `provision`, `ek_create`, `ek_import_cert`, `srk_create`, `iak_create`, `nv_write`, `activate_credential`, `seal`, `unseal`, `pcr_extend` | `tpm:write` |
| `clear`, `nv_delete` | `tpm:delete` |
| `ek_delete`, `srk_delete`, `iak_delete` | **refused** — they flush a persistent handle, which deletes nothing; gRPC `Delete*` does the same |
| `capabilities`, `platform` | **refused** — no gRPC or REST twin to take a scope from |

Names are `platform_tpm_<tool>`. `unseal` is the one tool stricter than its
gRPC twin: an unseal tool never takes a read scope on MCP. `nv_list` takes the
scope of gRPC `Info`, and `pcr_extend`, which has no gRPC twin, takes the scope
of QUIC's `SubOpTPM2ExtendPCR`.

## Available Tools

### Device Information and Management

| Tool | Description |
|------|-------------|
| `platform_tpm_info` | Get TPM device information |
| `platform_tpm_provision` | Provision TPM with owner authorization |
| `platform_tpm_clear` | Clear TPM and reset owner authorization |
| `platform_tpm_capabilities` | Get TPM fixed properties and capabilities |

### Endorsement Key Tools

| Tool | Description |
|------|-------------|
| `platform_tpm_ek` | Get Endorsement Key public key and handle |
| `platform_tpm_ek_create` | Create Endorsement Key |
| `platform_tpm_ek_delete` | Flush EK handle from TPM (refused, see Authorization) |
| `platform_tpm_ek_cert` | Get EK certificate |
| `platform_tpm_ek_import_cert` | Import EK certificate |

### Storage Root Key Tools

| Tool | Description |
|------|-------------|
| `platform_tpm_srk` | Get Storage Root Key |
| `platform_tpm_srk_create` | Create Storage Root Key |
| `platform_tpm_srk_delete` | Flush SRK handle (refused, see Authorization) |

### Initial Attestation Key Tools

| Tool | Description |
|------|-------------|
| `platform_tpm_iak` | Get Initial Attestation Key |
| `platform_tpm_iak_create` | Create Initial Attestation Key |
| `platform_tpm_iak_delete` | Flush IAK handle (refused, see Authorization) |
| `platform_tpm_idevid` | Get Initial Device ID |

### Attestation Tools

| Tool | Description |
|------|-------------|
| `platform_tpm_quote` | Generate TPM quote for remote attestation |
| `platform_tpm_verify_quote` | Verify quote signature and freshness |
| `platform_tpm_certify` | IAK certifies a persistent key is resident in this TPM |
| `platform_tpm_pcrs` | Read Platform Configuration Registers |
| `platform_tpm_eventlog` | Retrieve TPM event log |

### Cryptographic Tools

| Tool | Description |
|------|-------------|
| `platform_tpm_seal` | Seal data to TPM (PCR binding refused until go-quicbaas #1171) |
| `platform_tpm_unseal` | Unseal TPM-sealed data |
| `platform_tpm_random` | Generate random bytes from TPM RNG |

### Device Identifier Tools

| Tool | Description |
|------|-------------|
| `platform_tpm_idevid_csr` | Create Initial DevID Certificate Signing Request |
| `platform_tpm_ldevid_csr` | Create Local DevID Certificate Signing Request |

### NVRAM Tools

| Tool | Description | Scope |
|------|-------------|-------|
| `platform_tpm_nv_list` | List defined NVRAM indexes | `tpm:read` |
| `platform_tpm_nv_read` | Read NVRAM index | `tpm:read` |
| `platform_tpm_nv_write` | Write NVRAM index | `tpm:write` |
| `platform_tpm_nv_delete` | Undefine NVRAM index | `tpm:delete` |

The NV tools call `pkg/api/tpmnv`, the code gRPC and QUIC run, so they apply
the same bounds before the TPM is touched: the index must be an NV handle in
`0x01000000`-`0x01FFFFFF`, and a write's offset plus data length must fit the
65535-byte NV offset space (see [api.md](api.md)). The scopes are those of the
gRPC twins (`Info`, `ReadNVRAM`, `WriteNVRAM`, `UndefineNVRAM`).

## Tool Definitions

### platform_tpm_info

Get TPM device information and capabilities.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

**Example Response:**
```json
{
  "manufacturer": "Infineon",
  "model": "SLB9670",
  "firmware_version": "7.85",
  "tpm_version": "2.0",
  "fips_mode": true,
  "is_simulator": false
}
```

### platform_tpm_provision

Provision the TPM with owner authorization and create required keys.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "owner_password": {
      "type": "string",
      "description": "Owner password (optional, uses default if empty)"
    }
  }
}
```

### platform_tpm_clear

Clear the TPM, removing all keys and resetting owner authorization.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "owner_password": {
      "type": "string",
      "description": "Owner password for authorization (optional)"
    }
  }
}
```

### platform_tpm_ek

Get the Endorsement Key (EK) public key and handle.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

### platform_tpm_ek_cert

Get the Endorsement Key (EK) certificate in DER format (base64-encoded).

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

### platform_tpm_ek_import_cert

Import an EK certificate into the TPM NV storage.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "certificate": {
      "type": "string",
      "description": "Base64-encoded DER certificate to import"
    }
  },
  "required": ["certificate"]
}
```

### platform_tpm_ek_create

Create an Endorsement Key (EK) using the platform's configured algorithm.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

### platform_tpm_ek_delete

Flush the Endorsement Key (EK) handle from the TPM.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

### platform_tpm_srk

Get the Storage Root Key (SRK) public key and handle.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

### platform_tpm_srk_create

Create a Storage Root Key (SRK) under the Endorsement Key.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

### platform_tpm_srk_delete

Flush the Storage Root Key (SRK) handle from the TPM.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

### platform_tpm_iak

Get the Initial Attestation Key (IAK) public key and handle.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

### platform_tpm_iak_create

Create an Initial Attestation Key (IAK) under the Endorsement Key hierarchy.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

### platform_tpm_iak_delete

Flush the Initial Attestation Key (IAK) handle from the TPM.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

### platform_tpm_idevid

Get the Initial Device ID certificate.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

### platform_tpm_quote

Generate a TPM quote for remote attestation, signed by the attestation key.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "nonce": {
      "type": "string",
      "description": "Base64-encoded nonce for freshness guarantee"
    },
    "pcrs": {
      "type": "array",
      "items": {"type": "integer"},
      "description": "PCR indices to include in the quote (0-23)"
    }
  },
  "required": ["nonce"]
}
```

### platform_tpm_verify_quote

Verify a TPM quote against the attestation key that signed it — `ak_public`,
or the platform IAK when it is omitted — under the scheme the quote declares.
Requires scope `tpm:read`, as does `platform_tpm_quote`. The result is
`{"verified": bool, "message": string}`; a wrong scheme or key answers
`verified: false` with `signature_verification_failed: …`.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "quote": {
      "type": "string",
      "description": "Base64-encoded quote data"
    },
    "signature": {
      "type": "string",
      "description": "Base64-encoded quote signature"
    },
    "nonce": {
      "type": "string",
      "description": "Base64-encoded nonce used during quoting"
    },
    "channel_binding": {
      "type": "string",
      "description": "Base64-encoded channel binding the quote was produced under; the quote must then carry SHA-256(nonce || channel_binding)"
    },
    "ak_public": {
      "type": "string",
      "description": "Base64-encoded PKIX DER public key of the attestation key that signed the quote; omit it to verify against the platform IAK"
    },
    "signature_algorithm": {
      "type": "string",
      "description": "Signature scheme platform_tpm_quote declared, e.g. SHA256-RSAPSS; the signature is checked under it"
    }
  },
  "required": ["quote", "signature", "nonce", "signature_algorithm"]
}
```

### platform_tpm_certify

Have the IAK certify that the key at a persistent handle is resident in this
TPM (TPM2_Certify). Requires scope `tpm:read`. It calls the same
`pkg/api/tpmcertify` layer as every other transport, so a zero or transient
handle, or a nonce over 64 bytes, is refused before the TPM is called
([api.md](api.md) §5). The result carries the `CertifyResponse` fields
(`certify_info`, `signature`, `signature_algorithm`, `certify_info_signature`,
`attesting_key_public`, `attested_key_public`, `attesting_key_public_area`,
`attested_key_public_area`, `nonce`), byte fields base64-encoded.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "key_handle": {
      "type": "integer",
      "description": "Persistent handle of the key to certify (0x81000000-0x81FFFFFF)"
    },
    "key_password": {
      "type": "string",
      "description": "Authorization value of the key, when it has one"
    },
    "nonce": {
      "type": "string",
      "description": "Base64-encoded qualifying data (at most 64 bytes) echoed in the attestation"
    }
  },
  "required": ["key_handle"]
}
```

### platform_tpm_pcrs

Read Platform Configuration Register (PCR) values from the TPM.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "indices": {
      "type": "array",
      "items": {"type": "integer"},
      "description": "PCR indices to read (0-23). If empty, reads all 24 PCRs."
    }
  }
}
```

### platform_tpm_pcr_extend

Extend a PCR with measurement data (hash is computed by the TPM).

Scope `tpm:write`, the scope of QUIC's `SubOpTPM2ExtendPCR`; there is no gRPC
twin. The tool calls `pkg/api/tpmpcr`, the code QUIC runs.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "pcr_index": {
      "type": "integer",
      "description": "PCR index to extend (0-23)"
    },
    "data": {
      "type": "string",
      "description": "Base64-encoded data to extend into the PCR"
    },
    "hash_alg": {
      "type": "string",
      "description": "PCR bank to extend: sha1, sha256, sha384 or sha512 (default sha256)"
    }
  },
  "required": ["pcr_index", "data"]
}
```

### platform_tpm_eventlog

Retrieve the TPM event log (TCG PC Client format).

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

### platform_tpm_capabilities

Get TPM fixed properties and capabilities (manufacturer, algorithms, key sizes).

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

### platform_tpm_random

Generate cryptographically secure random bytes from the TPM hardware RNG.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "num_bytes": {
      "type": "integer",
      "description": "Number of random bytes to generate (1-1024, default: 32)",
      "default": 32
    }
  }
}
```

### platform_tpm_seal

Seal data to the TPM.

**PCR-bound sealing is unavailable.** A call that passes `pcrs` fails with
`ErrPCRBoundSealUnavailable`, and the message names go-quicbaas #1171. Binding
the object to PCRs needs the TPM PolicyPCR primitives, which go-quicbaas does
not re-export yet. Without them the object would be sealed in a way the PCRs do
not protect, so the tool refuses before the TPM is reached.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "data": {
      "type": "string",
      "description": "Base64-encoded data to seal"
    },
    "pcrs": {
      "type": "array",
      "items": {"type": "integer"},
      "description": "PCR indices to bind to (0-23); refused until go-quicbaas #1171"
    },
    "cn": {
      "type": "string",
      "description": "Common name (key ID) of the sealed object; default platform-sealing-key"
    },
    "password": {
      "type": "string",
      "description": "Authorization value the unseal must present"
    }
  },
  "required": ["data"]
}
```

Runs gRPC `Seal` and returns its `sealed_data`. A PCR index outside 0-23 is
`-32602` (invalid params).

### platform_tpm_unseal

Unseal TPM-sealed data.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "cn": {
      "type": "string",
      "description": "Common name of the sealed object"
    },
    "password": {
      "type": "string",
      "description": "Authorization value given at seal time"
    }
  },
  "required": ["cn"]
}
```

Runs gRPC `Unseal`: an unknown `cn` is not-found, an empty one invalid
params. Requires `tpm:write`, where gRPC `Unseal` takes `tpm:read`.

### platform_tpm_idevid_csr

Create Initial DevID Certificate Signing Request.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

### platform_tpm_ldevid_csr

Create Local DevID Certificate Signing Request.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

### platform_tpm_nv_list

List the defined NVRAM indexes. The result is `{"indexes": [{"handle",
"type", "size", "auth_read", "auth_write"}]}`, read from the TPM's fixed
properties.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {}
}
```

### platform_tpm_nv_read

Read data from an NVRAM index. The result is `{"index", "data", "size"}` with
`data` base64-encoded. A `size` that runs past the end of the index reads to
the end.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "index": {
      "type": "integer",
      "description": "NVRAM index to read from (0x01000000-0x01FFFFFF)"
    },
    "size": {
      "type": "integer",
      "description": "Number of bytes to read (optional, reads entire index if omitted)"
    },
    "offset": {
      "type": "integer",
      "description": "Byte offset to read from (default 0)"
    },
    "password": {
      "type": "string",
      "description": "Authorization password for the index or hierarchy its attributes select (optional)"
    }
  },
  "required": ["index"]
}
```

### platform_tpm_nv_write

Write data to an NVRAM index. The result is `{"success", "message"}`. Data
that would run past offset 65535 is refused before any chunk is written.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "index": {
      "type": "integer",
      "description": "NVRAM index to write to (0x01000000-0x01FFFFFF)"
    },
    "data": {
      "type": "string",
      "description": "Base64-encoded data to write"
    },
    "offset": {
      "type": "integer",
      "description": "Byte offset to write at (default 0)"
    },
    "password": {
      "type": "string",
      "description": "Authorization password for the index or hierarchy its attributes select (optional)"
    }
  },
  "required": ["index", "data"]
}
```

### platform_tpm_nv_delete

Undefine (delete) an NVRAM index. The result is `{"success", "message"}`.

**Input Schema:**
```json
{
  "type": "object",
  "properties": {
    "index": {
      "type": "integer",
      "description": "NVRAM index to undefine (0x01000000-0x01FFFFFF)"
    },
    "parent_password": {
      "type": "string",
      "description": "Owner hierarchy password (optional)"
    }
  },
  "required": ["index"]
}
```

`index` must fit in 32 bits, and `size` and `offset` in 16 bits. The values
are whole decimal numbers; anything else is refused with `-32602` (invalid params)
before the TPM is touched. Index 0 and empty `data` are refused the same way.
An index outside `0x01000000`-`0x01FFFFFF`, or a write past the NV offset space,
is refused by `pkg/api/tpmnv` before the TPM is touched.

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
      "name": "tpm-client",
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
    "name": "platform_tpm_info",
    "arguments": {}
  }
}
```

### Tool Response (Success)

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"manufacturer\":\"Infineon\",\"model\":\"SLB9670\",\"firmware_version\":\"7.85\",\"tpm_version\":\"2.0\"}"
      }
    ],
    "isError": false
  }
}
```

### Tool Response (Error)

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "error": {
    "code": -32602,
    "message": "TPM service not available"
  }
}
```

### Quote Example

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "platform_tpm_quote",
    "arguments": {
      "nonce": "dGVzdG5vbmNl",
      "pcrs": [0, 1, 2, 3, 7, 8, 9]
    }
  }
}
```

### Random Bytes Example

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "platform_tpm_random",
    "arguments": {
      "num_bytes": 64
    }
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

// Call platform_tpm_info
req := mcpRequest{
    JSONRPC: "2.0",
    ID:      1,
    Method:  "tools/call",
    Params: map[string]interface{}{
        "name": "platform_tpm_info",
        "arguments": map[string]interface{}{},
    },
}

// The listener serves TLS 1.3 only; trust the platform CA.
client := &http.Client{Transport: &http.Transport{
    TLSClientConfig: &tls.Config{RootCAs: platformCAPool, MinVersion: tls.VersionTLS13},
}}

jsonReq, _ := json.Marshal(req)
httpReq, _ := http.NewRequest(http.MethodPost, "https://localhost:9445/mcp", bytes.NewReader(jsonReq))
httpReq.Header.Set("Content-Type", "application/json")
httpReq.Header.Set("Authorization", "Bearer "+token)
resp, _ := client.Do(httpReq)

var mcpResp mcpResponse
json.NewDecoder(resp.Body).Decode(&mcpResp)
```

## Error Responses

Common error codes and messages:

| Code | Message | Description |
|------|---------|-------------|
| `-32602` | Invalid params | Missing or invalid parameters |
| `-32700` | Parse error | JSON parse error |
| `-32600` | Invalid request | Malformed JSON-RPC request |
| `-32603` | Internal error | Server error |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TPM_MCP_ENDPOINT` | MCP server address | `localhost:9445` |
| `TPM_MCP_STDIO` | Use stdio mode | false |

## Notes

- All timestamps are RFC 3339 format
- Binary data must be base64-encoded in JSON
- Nonce must be at least 8 bytes
- PCR indices must be in range 0-23
- Random byte count is limited to 1024 bytes per request
- NV index numbers are TPM-specific (typically 0x01C00000 and above)
