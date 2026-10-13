# Proxy gRPC API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [api.md](api.md).

gRPC service definition for the reverse-proxy configuration service.

| Property | Value |
|----------|-------|
| Service | `platform.v1.ProxyService` |
| Proto | `pkg/api/grpc/proto/proxy.proto` |
| Port | 10443 (TCP), also served on the gRPC Unix socket |
| Server | `pkg/api/grpc/proxy_service.go` (ProxyGRPCService) |

## RPCs

| RPC | Request | Response | Scope |
|-----|---------|----------|-------|
| CreateRoute | CreateProxyRouteRequest | CreateProxyRouteResponse | `proxy:write` |
| GetRoute | GetProxyRouteRequest | GetProxyRouteResponse | `proxy:read` |
| UpdateRoute | UpdateProxyRouteRequest | UpdateProxyRouteResponse | `proxy:write` |
| DeleteRoute | DeleteProxyRouteRequest | DeleteProxyRouteResponse | `proxy:delete` |
| ListRoutes | ListProxyRoutesRequest | ListProxyRoutesResponse | `proxy:read` |
| CreatePool | CreateProxyPoolRequest | CreateProxyPoolResponse | `proxy:write` |
| GetPool | GetProxyPoolRequest | GetProxyPoolResponse | `proxy:read` |
| UpdatePool | UpdateProxyPoolRequest | UpdateProxyPoolResponse | `proxy:write` |
| DeletePool | DeleteProxyPoolRequest | DeleteProxyPoolResponse | `proxy:delete` |
| ListPools | ListProxyPoolsRequest | ListProxyPoolsResponse | `proxy:read` |
| GetProxyConfig | GetProxyConfigRequest | GetProxyConfigResponse | `proxy:read` |
| GetProxyStatus | GetProxyStatusRequest | GetProxyStatusResponse | `proxy:read` |
| ReloadProxyConfig | ReloadProxyConfigRequest | ReloadProxyConfigResponse | `proxy:write` |
| GetZoneMatrix | GetProxyZoneMatrixRequest | GetProxyZoneMatrixResponse | `proxy:read` |

Scopes are enforced by the platform-token interceptor
(`pkg/api/grpc/method_permissions.go`).

## SDK Usage

```go
import (
    platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
    proxysvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/proxy"
    platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

client, err := platform.NewClient(ctx, platform.WithGRPCAddr("platform:10443"))
if err != nil {
    return err
}
proxyClient := proxysvc.NewClientFromGRPC(client.Proxy())

pool, version, err := proxyClient.CreatePool(ctx, &platformv1.ProxyPool{
    Id: "web-pool",
    Backends: []*platformv1.ProxyBackend{{Url: "https://10.0.0.10:8443", Weight: 2}},
})
```

gatewayd sync loop (`pkg/sdn/gateway/proxysvc`). The wire-to-engine
converters live with the engine types in `pkg/proxy` (`proto.go`), not in
the SDK, so the SDK module never imports the engine:

```go
cfg, err := proxyClient.Config(ctx) // GetProxyConfig
routes, pools, version := proxy.ConfigFromProto(cfg) // pkg/proxy
// add gatewayd-local listeners, then proxy.Config{...}.Validate() + engine reload
```

## Error Codes

| Code | Condition |
|------|-----------|
| `InvalidArgument` | Missing ID/body, ID mismatch, pkg/proxy validation failure |
| `NotFound` | Unknown route or pool ID |
| `AlreadyExists` | Duplicate route or pool ID |
| `FailedPrecondition` | Pool referenced by routes; service backend not wired |
| `Unavailable` | Zone matrix requested without a zone service |
| `Internal` | Unclassified backend failure |
