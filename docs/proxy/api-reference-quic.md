# Proxy QUIC API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [api.md](api.md). The SDK has no `platform.WithProtocol`; the option is `WithOnlyProtocol`.

QUIC wire protocol for the reverse-proxy configuration service.

| Property | Value |
|----------|-------|
| Port | 9444 (UDP) |
| Category opcode | `0x2F` (gateway category) |
| Sub-opcode range | `0x20`-`0x2D` |
| Handler | `pkg/api/quic/proxy_handlers.go` (ProxyHandler) |
| Opcodes | `sdk/go/wire/quicwire/proxy_opcodes.go` |

The single-byte top-level opcode space (0x00-0xFF) is fully allocated,
so the proxy service multiplexes as sub-opcodes under the gateway
category opcode `0x2F` (`quic.OpProxyCategory` aliases
`quic.OpGatewayCategory`), following the same convention as EAB
(0x10-0x1A) and device-profile assignment (0x20-0x21) under the
provisioning category 0xCF. The daemon's gateway-category dispatcher
routes the proxy sub-range to the ProxyHandler first; gateway's own
sub-opcodes (0x01-0x14) fall through unchanged.

## Wire Format

```
Request:  [opcode=0x2F][payload = [sub-opcode:1][msgpack request]]
Response: [status:1][payloadLen:4][msgpack response]
```

Payloads are the `platform.v1` protobuf messages encoded with the QUIC
payload codec, which keys on exact Go field names (e.g. `Id`, `Hosts`,
`PathPrefix`, `PoolId`, `Auth`, `PassthroughTcp`).

## Sub-Opcode Table (under 0x2F)

| Sub-opcode | Constant | Operation | Request / Response |
|-----------|----------|-----------|--------------------|
| 0x20 | `ProxySubRouteCreate` | Create route | CreateProxyRouteRequest / Response |
| 0x21 | `ProxySubRouteGet` | Get route | GetProxyRouteRequest / Response |
| 0x22 | `ProxySubRouteUpdate` | Update route | UpdateProxyRouteRequest / Response |
| 0x23 | `ProxySubRouteDelete` | Delete route | DeleteProxyRouteRequest / Response |
| 0x24 | `ProxySubRouteList` | List routes | ListProxyRoutesRequest / Response |
| 0x25 | `ProxySubPoolCreate` | Create pool | CreateProxyPoolRequest / Response |
| 0x26 | `ProxySubPoolGet` | Get pool | GetProxyPoolRequest / Response |
| 0x27 | `ProxySubPoolUpdate` | Update pool | UpdateProxyPoolRequest / Response |
| 0x28 | `ProxySubPoolDelete` | Delete pool | DeleteProxyPoolRequest / Response |
| 0x29 | `ProxySubPoolList` | List pools | ListProxyPoolsRequest / Response |
| 0x2A | `ProxySubConfigGet` | Get merged config | GetProxyConfigRequest / Response |
| 0x2B | `ProxySubStatusGet` | Get status | GetProxyStatusRequest / Response |
| 0x2C | `ProxySubReload` | Reload (bump version) | ReloadProxyConfigRequest / Response |
| 0x2D | `ProxySubZoneMatrix` | Zone matrix | GetProxyZoneMatrixRequest / Response |

## Status Bytes

| Status | Value | Condition |
|--------|-------|-----------|
| `StatusOK` | 0x00 | Success |
| `StatusInvalidRequest` | 0x01 | Decode failure; pool-in-use (FailedPrecondition) |
| `StatusNotFound` | 0x02 | Unknown route/pool |
| `StatusAlreadyExists` | 0x06 | Duplicate route/pool |
| `StatusInvalidArgument` | 0x09 | Validation failure |
| `StatusUnavailable` | 0x0A | Proxy handler or zone service not wired |
| `StatusNotImplemented` | 0x0B | Unknown sub-opcode |
| `StatusInternalError` | 0x04 | Unclassified failure |

## SDK Usage

The SDK QUIC transport translates `ProxyService` gRPC methods to this
wire format automatically (`sdk/go/transport/quic/adapter.go`:
`grpcMethodToOpcodeMap` + `categorySubOpcodeMap`):

```go
client, err := platform.NewClient(ctx,
    platform.WithProtocol(platform.ProtocolQUIC),
    platform.WithQUICAddr("platform:9444"))
proxy := proxysvc.NewClientFromGRPC(client.Proxy())
routes, version, err := proxy.ListRoutes(ctx)
```
