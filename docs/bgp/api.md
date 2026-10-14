# BGP Speaker — API

> **Status: NORMATIVE** · Scope: the BGP capabilities of `GatewayService` on every transport · Last verified: 2026-10-14
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. The six transports

The transport model, the QUIC frame format, the status bytes and the
platform-wide authorization picture are in
[`docs/daemon/api.md`](../daemon/api.md). They are not repeated here. Unix is
gRPC over a Unix domain socket, so gRPC and Unix share a column.

The BGP capabilities are five methods of `platform.v1.GatewayService`
(`pkg/api/grpc/proto/gateway.proto:11`, RPCs at 27–31). They are implemented
by `pkg/api/daemon/gateway_grpc_service.go`.

| Capability | gRPC / Unix | REST (webservice) | REST (daemon) | QUIC (`0x2F`) | MCP | QUIC / MCP permission |
|---|---|---|---|---|---|---|
| Speaker status | `GetBGPStatus` (263) | `GET /api/v1/gateway/bgp/status` | `GET /api/v1/sdn/gateway/bgp/status` | `0x03` | `gateway_bgp_status` | `sdn:read` |
| List peers | `ListBGPPeers` (289) | `GET /api/v1/gateway/bgp/peers` | `GET /api/v1/sdn/gateway/bgp/peers` | `0x04` | `gateway_bgp_peers` | `sdn:read` |
| Announce a prefix | `AnnouncePrefix` (311) | `POST /api/v1/gateway/bgp/prefixes` | `POST /api/v1/sdn/gateway/bgp/prefixes` | `0x05` | `gateway_bgp_announce` | `sdn:write` |
| Withdraw a prefix | `WithdrawPrefix` (359) | `DELETE /api/v1/gateway/bgp/prefixes?prefix=` | `DELETE /api/v1/sdn/gateway/bgp/prefixes/{prefix}` | `0x06` | `gateway_bgp_withdraw` | `sdn:write` |
| List announced prefixes | `ListAnnouncedPrefixes` (393) | `GET /api/v1/gateway/bgp/prefixes` | `GET /api/v1/sdn/gateway/bgp/prefixes` | `0x07` | `gateway_bgp_prefixes` | `sdn:read` |

Where each column is defined:

- **gRPC:** method lines in `gateway_grpc_service.go`.
- **REST (webservice listener):** `pkg/webservice/v1/rest/gateway/router.go:65-69`.
- **REST (daemon listener):** `pkg/api/rest/gateway_handlers.go:527-533`.
- **QUIC:** the opcodes are `sdk/go/wire/quicwire/gateway_opcodes.go:21-25`,
  under `OpGatewayCategory` (`protocol.go:129`). Dispatch is
  `pkg/api/quic/gateway_handlers.go:642-650`. Permissions are
  `pkg/api/quic/opcode_permissions.go:546-550`.
- **MCP:** the tools are `pkg/api/mcp/gateway_tools.go:253-305`. Permissions
  are `pkg/api/mcp/authz.go:132-136`.
- **Embedded:** `registerGatewayHandlers` (`sdk/go/transport/embedded/dispatch.go:1077`).
- **REST authorization:** the `/gateway/bgp/**` routes are gated to `admin`
  ([auth architecture](../auth/architecture.md)).

Request fields (`gateway.proto:407-417`):

- `AnnouncePrefix`: `prefix` (required) and `next_hop` (optional). The MCP tool
  takes the same two arguments (`gateway_tools.go:271`).
- `WithdrawPrefix`: `prefix` (required). Over the webservice REST listener it
  travels as the URL-encoded `prefix` query parameter
  (`DELETE /api/v1/gateway/bgp/prefixes?prefix=203.0.113.0%2F24`): the SDK's
  REST adapter puts it there (`sdk/go/transport/rest/adapter.go:752`) and the
  handler reads only the query (`pkg/webservice/v1/rest/gateway/router.go:170`),
  so a `DELETE` body is ignored. A missing or malformed prefix answers 400 with
  the reason gRPC gives (§2).
- The list requests are empty. QUIC alone pages the two lists with
  `offset` / `limit`: the default limit is 100 and the cap is 1000
  (`pkg/api/quic/gateway_handlers.go:29-30`, used at 977 and 1111). The SDK's
  QUIC client pages until it holds the reply's `total`
  (`sdk/go/transport/quic/gateway_bgp.go:121`, `:170`), so the SDK returns the
  whole list on every transport. The pages are separate reads, so a list that
  changes while it is paged can repeat or miss an entry.
- The QUIC announce frame can also carry `local_pref`, `med`, `communities`
  and `labels`. Each is refused with `ErrBGPAttributeUnsupported`, answered as
  invalid argument (`pkg/api/daemon/gateway_bgp_bindings.go:122-131`,
  `errors.go:1591`).

## 2. Behaviour on main

`platformd` holds no speaker. `SetBGPSpeaker`
(`gateway_grpc_service.go:139`) has no production caller. So every method
answers `serviceNotConfigured` "BGP speaker not configured on this node"
(267, 293, 332, 372, 397). The two write methods validate their arguments
first:

| Method | Checks, in order |
|---|---|
| `AnnouncePrefix` | `prefix` empty → InvalidArgument "prefix is required" (312); unparsable → "invalid prefix" (317); bad `next_hop` → "invalid next_hop" (324); then "not configured" (332) |
| `WithdrawPrefix` | `prefix` empty → InvalidArgument (360); unparsable → "invalid prefix" (365); then "not configured" (372) |

With a speaker attached, a stopped one answers Unavailable "BGP speaker is
not running" (336, 376).

**Planned (#65):** backing these methods with the gateway's transit speaker.
Until then, a gateway's BGP state is read through the gateway snapshot
([cli.md §2](cli.md#2-platformctl-sdn-gateway-snapshot)).

## 3. What the API does not cover

- The overlay EVPN speaker: no method reads its sessions or routes.
- Peer management: there is no add, delete, reset, enable or disable.
- The config sections. They are part of the gateway config
  ([engineering.md §5](engineering.md#5-configuration)).
