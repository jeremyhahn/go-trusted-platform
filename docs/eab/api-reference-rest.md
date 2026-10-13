# EAB REST API Reference

> **Status: REFERENCE** · Last verified: 2026-10-13
> The `/api/v1/eab` routes and list filters.

| Property | Value |
|----------|-------|
| Base path | `/api/v1/eab` (webservice, port 8443) |
| Router | `pkg/webservice/v1/rest/eab/router.go` |
| Backend | in-process `platform.v1.EABService` (`EABGRPCService`) |
| Encoding | protojson inside the standard `WebServiceResponse` envelope |

## Endpoints

| Method | Path | RPC |
|--------|------|-----|
| `POST` | `/eab/credentials` | CreateCredential (body: `profile_id`, `tenant_id`, `expires_in_seconds`, `hmac_key_length`) |
| `GET` | `/eab/credentials` | ListCredentials (query filters below) |
| `GET` | `/eab/credentials/{id}` | GetCredential |
| `DELETE` | `/eab/credentials/{id}` | DeleteCredential |
| `POST` | `/eab/credentials/{id}/revoke` | RevokeCredential (body: `revoker_id`) |
| `POST` | `/eab/credentials/{id}/used` | MarkCredentialUsed |
| `GET` | `/eab/credentials/{id}/qrcode?size=N` | GetCredentialQRCode |
| `GET` | `/eab/credentials/{id}/url?path=P` | GetEnrollmentURL |
| `GET` | `/eab/credentials/key/{key}` | GetCredentialByKeyID |
| `POST` | `/eab/credentials/validate` | ValidateCredential (body: `key_id`, `hmac_key`) |
| `POST` | `/eab/credentials/cleanup` | CleanupExpiredCredentials (body or query: `tenant_id`) |

## List query filters

`GET /api/v1/eab/credentials` accepts:

| Parameter | Meaning |
|-----------|---------|
| `tenant_id` | tenant scope (empty = all tenants) |
| `profile_id` | device profile scope (0 = all profiles) |
| `active_only` | `true` returns only valid (active, unexpired) credentials |
| `status` | `active` \| `revoked` \| `expired` \| `used` (full proto enum names also accepted) |
| `page`, `page_size` | 1-based pagination over the filtered set |

## Notes

- protojson renders uint64 identifiers (`id`, `profile_id`) as decimal
  strings.
- The HMAC key appears only in the `CreateCredential` response.
- When the EAB backend is not configured the handlers return the
  structured 503 "service unavailable" envelope.
- The SDK REST adapter (`sdk/go/transport/rest`) maps
  `platform.v1.EABService` methods onto these routes, substituting
  `credential_id` / `key_id` into the URL and transmitting list filters
  as query parameters.
