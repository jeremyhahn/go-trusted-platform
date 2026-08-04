# EAB MCP API Reference

| Property | Value |
|----------|-------|
| Tools | `platform_eab_*` (`pkg/api/mcp/eab_tools.go`) |
| Bridge | `MCPServiceProvider` (`pkg/api/daemon/mcp_eab.go`) |
| Backend | same `eab.Service` as the gRPC / QUIC / REST surfaces |

## Tools

| Tool | Arguments |
|------|-----------|
| `platform_eab_create_credential` | `profile_id` (required), `tenant_id` (required), `expires_in_seconds`, `hmac_key_length` |
| `platform_eab_get_credential` | `credential_id` (required) |
| `platform_eab_get_credential_by_key_id` | `key_id` (required) |
| `platform_eab_list_credentials` | `tenant_id`, `profile_id`, `active_only`, `status`, `page`, `page_size` — all optional; empty tenant + zero profile lists the full store (same cascade as gRPC) |
| `platform_eab_revoke_credential` | `credential_id` (required), `revoker_id` |
| `platform_eab_validate_credential` | `key_id`, `hmac_key` (base64url; raw/padded, std/url variants accepted) |
| `platform_eab_delete_credential` | `credential_id` (required) |
| `platform_eab_mark_credential_used` | `credential_id` (required) |
| `platform_eab_cleanup_expired_credentials` | `tenant_id` (optional; empty = all tenants) |
| `platform_eab_get_credential_qr_code` | `credential_id` (required), `size` |
| `platform_eab_get_enrollment_url` | `credential_id` (required), `path` |

## Wire conventions

- uint64 arguments (`credential_id`, `profile_id`, `revoker_id`) may be
  sent as JSON numbers **or decimal strings**; strings are the canonical
  form (JSON numbers lose precision past 2^53) and are what the SDK MCP
  adapter emits.
- Credential results render `id` / `profile_id` as decimal strings,
  `status` as `active | revoked | expired | used`, and timestamps as
  RFC3339. The HMAC key appears only in the create result.
- `platform_eab_validate_credential` reports failures in-band:
  `{"valid": false, "error_message": ...}`.
- The QR result base64-encodes the PNG under `qr_code`.
- Without an EAB backend every tool returns the structured
  `eab: service provider not configured` error.

The SDK MCP adapter (`sdk/go/transport/mcp/eab.go`) maps
`platform.v1.EABService` methods onto these tools and rebuilds the pb
responses from the domain JSON shapes.
