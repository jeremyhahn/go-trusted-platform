# Config Delivery MCP API Reference

| Property | Value |
|----------|-------|
| Protocol | MCP (JSON-RPC 2.0) |
| Endpoint | `http://host:9445/mcp` |
| Tools | 7 `provision_*` tools |
| Implementation | `pkg/api/mcp/provision_tools.go` |

The `provision_*` tools mirror the `platform.v1 ConfigDeliveryService` gRPC
surface and delegate to the same backing service, so authentication
(EAB + nonce + EK binding) and error semantics are identical. Tool errors
carry the typed service error text verbatim.

## Tools

### provision_get_nonce

No arguments.

```json
{ "nonce": "3f8a...64-hex-chars...b1" }
```

### provision_fetch_config

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `eab_key_id` | string | yes | EAB key identifier |
| `eab_hmac` | string | yes | base64url EAB HMAC key |
| `nonce` | string | yes | Single-use nonce from `provision_get_nonce` |
| `ek_serial` | string | one of | TPM EK certificate serial |
| `mac_address` | string | one of | Primary NIC MAC address |
| `ek_cert` | string | conditional | standard-base64 DER EK certificate (required for EK-bound profiles) |

**Delivered:** `{ "config": { ... }, "status": "ok" }`

**Pending:** `{ "session_id": "...", "provision_url": "...", "poll_interval_seconds": 5 }`

**Pending detection rule:** the result is pending **iff** it has no `config`
key (a delivered result always carries `config` + `status: "ok"`).

### provision_sign_digest

The `provision_fetch_config` arguments plus:

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `digest` | string | yes | standard-base64 pre-computed message digest |
| `key_ref` | string | no | Secure Boot key selector (default `"db"`; only `db` signs remotely) |

**Returns:** `{ "signature": "<base64>", "cert_pem": "<base64 PEM>" }`

### provision_poll_session

| Argument | Type | Required |
|----------|------|----------|
| `session_id` | string | yes |

**Pending:** `{ "status": "pending" }` — pending **iff** `status == "pending"`
and no `config` key.

**Fulfilled:** `{ "config": { ... }, "status": "ok" }`

### provision_fulfill_session

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `session_id` | string | yes | Session to fulfill |
| `profile_id` | string **or** integer | yes | Device profile ID (uint64) |

**`profile_id` as string:** pass uint64 IDs as decimal strings (e.g.
`"18446744073709551615"`) to avoid JSON number precision loss past 2^53. The
tool accepts both; the SDK MCP transport always sends a string.

**Returns:** `{ "status": "fulfilled" }`

### provision_list_sessions

No arguments. Returns the domain session objects wrapped under `sessions`:

```json
{ "sessions": [ { "id": "...", "ek_serial": "...", "fulfilled": false,
                  "created_at": "2026-08-02T17:04:05Z",
                  "expires_at": "2026-08-02T17:34:05Z" } ] }
```

### provision_get_session

| Argument | Type | Required |
|----------|------|----------|
| `session_id` | string | yes |

Returns the session object wrapped under `session`.

## Errors

| Condition | Tool error text contains |
|-----------|--------------------------|
| Missing/empty `session_id` | `provision: session_id is required` |
| Missing/zero/unparseable `profile_id` | `provision: profile_id ...` |
| Missing/undecodable `digest` | `provision: digest ...` |
| EAB failure | `configdelivery: eab validation failed` |
| Spent nonce | `configdelivery: nonce expired or already used` |
| Unknown session | `configdelivery: session not found` |
| Backend not wired | `provision: config delivery service not configured` |

## SDK Usage

```go
client, err := platform.NewClient(ctx,
    platform.WithOnlyProtocol(platform.ProtocolMCP),
    platform.WithMCPAddr("http://localhost:9445"))
prov := provision.NewClientFromGRPC(client.ConfigDelivery())
```

The SDK MCP transport maps the gRPC method names onto the tools above and
rebuilds the pb oneof replies from the domain JSON shapes
(`sdk/go/transport/mcp/provisioning.go`).
