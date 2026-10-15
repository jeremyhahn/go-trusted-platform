# Config Delivery MCP API Reference

| Property | Value |
|----------|-------|
| Protocol | MCP (JSON-RPC 2.0) |
| Endpoint | `https://host:9445/mcp` |
| Tools | 7 `provision_*` tools |
| Implementation | `pkg/api/mcp/provision_tools.go` |

The `provision_*` tools mirror the `platform.v1 ConfigDeliveryService` gRPC
surface and delegate to the same backing service, so authentication
(EAB + nonce + EK binding) and error classes are identical (see
[Errors](#errors)). Tool errors carry the typed service error text verbatim.

## Authorization

Each tool takes the scope of its gRPC twin (`toolPermissionCatalog`,
`pkg/api/mcp/authz.go`). A caller without it is refused with
`PermissionDenied` before the tool runs.

| Tool | Scope |
|------|-------|
| `provision_list_sessions`, `provision_get_session` | `provisioning:read` |
| `provision_fulfill_session` | `provisioning:write` |
| `provision_get_nonce`, `provision_fetch_config`, `provision_sign_digest`, `provision_poll_session` | open — no token, as on gRPC; fetch and sign check the single-use nonce, EAB HMAC and EK binding, and poll needs the random session ID |

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

Each tool error carries the JSON-RPC code of the gRPC status
`ConfigDeliveryService` answers the same failure with: the bridge
(`pkg/api/daemon/mcp_provision.go`) wraps the typed service error in
`ErrConfigDeliveryClassified`, using the gRPC handler's own matcher table.

| Condition | gRPC status | MCP code | Tool error text contains |
|-----------|-------------|----------|--------------------------|
| Missing/empty `session_id` | `InvalidArgument` | `InvalidParams` | `provision: session_id is required` |
| Missing or zero `profile_id` | `InvalidArgument` | `InvalidParams` | `configdelivery: profile_id is required and must be non-zero` |
| Negative or unparseable `profile_id` | `InvalidArgument` | `InvalidParams` | `provision: profile_id ... is not a valid uint64` |
| Missing/undecodable `digest` | `InvalidArgument` | `InvalidParams` | `provision: digest ...` |
| Invalid request fields | `InvalidArgument` | `InvalidParams` | `configdelivery: invalid request` |
| EAB failure (`provision_fetch_config`) | `Unauthenticated` | `AuthenticationRequired` | `configdelivery: eab validation failed` |
| EAB failure (`provision_sign_digest`) | `PermissionDenied` | `PermissionDenied` | `configdelivery: eab validation failed` |
| Spent nonce | `InvalidArgument` | `InvalidParams` | `configdelivery: nonce expired or already used` |
| Unknown session | `NotFound` | `NotFound` | `configdelivery: session not found` |
| Session expired or already fulfilled | `InvalidArgument` | `InvalidParams` | `configdelivery: session ...` |
| No DB signer wired (`provision_sign_digest`) | `Unavailable` | `ServiceUnavailable` | `configdelivery: remote signing is unavailable` |
| Backend not wired | `Unavailable` | `ServiceUnavailable` | `config delivery service is not available` or `provision: config delivery service not configured` |

`provision_fulfill_session` hands a missing or zero `profile_id` to the
service, which refuses it with `configdelivery.ErrProfileIDRequired` before
it looks the session up — the same typed error gRPC, QUIC, REST and the Unix
socket return (#304).

## SDK Usage

```go
client, err := platform.NewClient(ctx,
    platform.WithOnlyProtocol(platform.ProtocolMCP),
    platform.WithMCPAddr("https://localhost:9445"))
prov := provision.NewClientFromGRPC(client.ConfigDelivery())
```

The SDK MCP transport maps the gRPC method names onto the tools above and
rebuilds the pb oneof replies from the domain JSON shapes
(`sdk/go/transport/mcp/provisioning.go`).
