# EAB (External Account Binding) API Reference

> **Status: REFERENCE** · Last verified: 2026-10-13
> The EAB transport map, service resolution and security invariants.

EAB credentials (RFC 8555 §7.3.4) pre-authorize ACME device enrollment:
each credential is a `(KeyID, HMAC key)` pair bound to a device profile
and tenant. The pre-enrollment config delivery flow consumes them to
authenticate `FetchConfig` / `SignDigest` requests.

One implementation backs every transport: `EABGRPCService`
(`pkg/api/daemon/eab_grpc_service.go`) wraps the canonical `eab.Service`
(`pkg/eab`) and is registered on gRPC TCP + UDS, wired into the QUIC
category dispatcher, surfaced to the webservice REST router, and shares
its `eab.Service` with the MCP tools — so semantics and error mapping
are identical everywhere.

| Transport | Reference | Entry point |
|-----------|-----------|-------------|
| REST | [api-reference-rest.md](api-reference-rest.md) | `/api/v1/eab/*` (webservice, `pkg/webservice/v1/rest/eab`) |
| gRPC | [api-reference-grpc.md](api-reference-grpc.md) | `platform.v1.EABService` (TCP `:10443`) |
| QUIC | [api-reference-quic.md](api-reference-quic.md) | `0xCF` sub-opcodes `0x10`-`0x1A` |
| MCP | [api-reference-mcp.md](api-reference-mcp.md) | `platform_eab_*` tools |
| Unix | [api-reference-unix.md](api-reference-unix.md) | `platform.v1.EABService` over `/run/platformd.sock` |

## Service resolution

The daemon resolves the `eab.Service` from
`App.ServiceRegistry().EABService()` (QuicBaaS-backed storage). When the
registry or its backing store is absent, every RPC returns a typed
`Unavailable` error ("eab service not configured") — never
`Unimplemented`, never a panic. QR-code / enrollment-URL delivery uses
`eab.Delivery` configured with `https://<FQDN>:<REST port>` as base URL.

## Canonical interface

`eab.Service` (`pkg/eab/types.go`) is the single EAB contract.
`pkg/api/daemon.EABServicer` is a type alias of it.

## Security invariants

- The HMAC key is returned exactly once: in the `CreateCredential`
  response (base64url, no padding).
- `Get`, `GetByKeyID`, `List` and `Validate` never include the HMAC key.
- Listing by profile with a tenant filter never crosses tenant
  boundaries.
- Validation uses a constant-time comparison in `eab.Service.Validate`;
  failures are reported in-band (`valid=false` + `error_message`)
  rather than as transport errors.
- uint64 identifiers travel as decimal strings in every JSON surface
  (MCP results, SDK MCP arguments) to survive the 2^53 JSON number
  precision limit.
