# EAB MCP API Reference

> **Status: REFERENCE** · Last verified: 2026-10-14
> The `platform_eab_*` MCP tools, their arguments, scopes and wire conventions.

| Property | Value |
|----------|-------|
| Tools | `platform_eab_*` (`pkg/api/mcp/eab_tools.go`) |
| Bridge | `MCPServiceProvider` (`pkg/api/daemon/mcp_eab.go`) |
| Backend | same `eab.Service` as the gRPC / QUIC / REST surfaces |
| Scopes | `toolPermissionCatalog` (`pkg/api/mcp/authz.go`), the gRPC `EABService` pairs |

## Tools

| Tool | Scope | Arguments |
|------|-------|-----------|
| `platform_eab_create_credential` | `eab:write` | `profile_id` (required), `tenant_id` (required), `expires_in_seconds` (negative is `InvalidArgument`), `hmac_key_length` |
| `platform_eab_get_credential` | `eab:read` | `credential_id` (required) |
| `platform_eab_get_credential_by_key_id` | `eab:read` | `key_id` (required) |
| `platform_eab_list_credentials` | `eab:read` | `tenant_id`, `profile_id`, `active_only`, `status`, `page`, `page_size` — all optional; empty tenant + zero profile lists the full store (same cascade as gRPC) |
| `platform_eab_revoke_credential` | `eab:write` | `credential_id` (required), `revoker_id` |
| `platform_eab_validate_credential` | `eab:read` | `key_id` (required), `hmac_key` (required; base64url; raw/padded, std/url variants accepted) |
| `platform_eab_delete_credential` | `eab:delete` | `credential_id` (required) |
| `platform_eab_mark_credential_used` | `eab:write` | `credential_id` (required) |
| `platform_eab_cleanup_expired_credentials` | `eab:write` | `tenant_id` (optional; empty = all tenants, named = that tenant only) |
| `platform_eab_get_credential_qr_code` | `eab:read` | `credential_id` (required), `size` (negative is `InvalidArgument`) |
| `platform_eab_get_enrollment_url` | `eab:read` | `credential_id` (required), `path` |

A caller without the tool's scope is refused with `AuthErrorPermissionDenied`
before the tool runs. No tool binds the caller to a tenant: like gRPC, each
serves the `tenant_id` it is given.

## Wire conventions

- A tool's result is an MCP `CallToolResult`: the JSON object below is the
  text of its one `text` block ([daemon api.md](../daemon/api.md) §1 "MCP
  tool results").
- uint64 arguments (`credential_id`, `profile_id`, `revoker_id`) may be
  sent as JSON numbers **or decimal strings**; strings are the canonical
  form (JSON numbers lose precision past 2^53) and are what the SDK MCP
  adapter emits. A value that does not parse becomes `0`, so a malformed
  `credential_id` is refused as missing (`eab: credential_id is required and
  must be non-zero`), not as malformed.
- Credential results render `id` / `profile_id` as decimal strings,
  `status` as `active | revoked | expired | used`, and timestamps as
  RFC3339. The HMAC key appears in the create result only — but the QR
  code and the enrollment URL embed it, so `eab:read` is credential-bearing.
- `platform_eab_list_credentials` returns gRPC's default order (`id`
  ascending); an unknown `status` is `InvalidArgument`.
- `platform_eab_validate_credential` reports failures in-band:
  `{"valid": false, "error_message": ...}`; an undecodable `hmac_key` is
  `InvalidArgument`.
- The QR result base64-encodes the PNG under `qr_code`.
- Errors carry the gRPC class (`ErrEABToolFailure`): `NotFound`,
  `InvalidArgument`, `FailedPrecondition`, `Unavailable`, `Internal`. With no
  EAB backend behind the daemon's provider every tool returns `Unavailable`
  (`eab service not configured`, `pkg/api/daemon/mcp_eab.go:47`). The other
  string, `eab: service provider not configured` (`pkg/api/mcp/eab_tools.go:42`),
  appears only when the MCP service provider does not implement `EABProvider`
  at all.

The SDK MCP adapter (`sdk/go/transport/mcp/eab.go`) maps
`platform.v1.EABService` methods onto these tools and rebuilds the pb
responses from the domain JSON shapes.
