# NTP gRPC API Reference

| Property | Value |
|----------|-------|
| Endpoint | `host:10443` (TCP, TLS 1.3) |
| Service | `platform.v1.NTPService` |
| Proto | `pkg/api/grpc/proto/ntp.proto` |
| Implementation | `pkg/api/daemon/ntp_grpc_service.go` |

## Methods

| RPC | Request | Response | Scope |
|-----|---------|----------|-------|
| `GetStatus` | `GetNTPStatusRequest` | `GetNTPStatusResponse` | `ntp:read` |
| `ListSources` | `ListNTPSourcesRequest` | `ListNTPSourcesResponse` | `ntp:read` |
| `Step` | `StepNTPClockRequest` | `StepNTPClockResponse` | `ntp:write` |

All three requests are empty messages.

Scopes are enforced by the platform-token interceptor via the catalog in
`pkg/api/grpc/method_permissions.go`.

## Messages

`NTPStatus`

| Field | Type | Meaning |
|-------|------|---------|
| `synced` | bool | chronyd currently disciplines the clock |
| `stratum` | uint32 | distance from a reference clock; `0` = unsynchronized, `16` = unusable |
| `leap_status` | string | `Normal`, `Insert second`, `Delete second`, `Not synchronised` |
| `offset_seconds` | double | current system time offset; positive = clock ahead |
| `root_dispersion` | double | maximum error bound to the reference, seconds |
| `root_delay` | double | accumulated round-trip delay, seconds |
| `last_sync_unix` | int64 | reference timestamp of the last update; `0` = never |
| `mode` | string | configured role: `serve`, `consume`, or `both` |
| `reference_id` | string | chrony's hex reference identifier |
| `reference_name` | string | readable name or address of the reference |
| `sources_reachable` / `sources_total` | uint32 | reachability counts |
| `anomaly` / `anomaly_reason` | bool / string | a large correction after the first-boot correction |
| `serve_name_findings` | repeated `NTSServeNameFinding` | advertised NTS-KE names clients cannot usefully dial; absent when there is none |

`NTSServeNameFinding`

| Field | Type | Meaning |
|-------|------|---------|
| `kind` | string | `nts-name-unreachable` (resolved onto a segment this node refuses) or `nts-name-unresolvable` (did not resolve here) |
| `name` | string | the `serve.nts.server-names` entry |
| `address` | string | where the name resolved; empty for `nts-name-unresolvable` |
| `listen_networks` | repeated string | the rendered allow list; empty for `nts-name-unresolvable` |
| `error` | string | the resolver's own words, for `nts-name-unresolvable` |


`NTPSource`

| Field | Type | Meaning |
|-------|------|---------|
| `address` | string | source host name or IP |
| `mode` | string | `server`, `peer`, `refclock`, `unknown` |
| `state` | string | `selected`, `combined`, `excluded`, `unreachable`, `falseticker`, `jittery`, `unknown` |
| `stratum` | uint32 | the source's own stratum |
| `poll_seconds` | uint32 | current polling interval |
| `reach` | uint32 | 8-bit reachability register |
| `last_rx_seconds` | int64 | age of the last sample |
| `offset_seconds` | double | last measured offset |
| `reachable` | bool | any bit set in the reachability register |

## Status Codes

The typed `pkg/ntp` errors map to gRPC codes in `ntpErrToGRPC`
(`pkg/api/daemon/ntp_service.go`); every transport reuses this mapping:

| Domain error | Code |
|--------------|------|
| `ErrNoReachableSource` | `Aborted` (REST 409 Conflict) |
| `ErrControlUnavailable`, `ErrDisabled`, no configured backend | `Unavailable` |
| `ErrMalformedControlOutput` | `Internal` |
| `ErrSyncTimeout` | `DeadlineExceeded` |
| anything else | `Internal` |

## SDK Usage

```go
client, err := platform.Connect(ctx, platform.NewOptions(
    platform.WithOnlyProtocol(platform.ProtocolGRPC),
    platform.WithGRPCAddr("cp.example.com:10443"),
    platform.WithTLSConfig(tlsConfig)))

ntpClient := ntp.NewClientFromGRPC(client.NTP())
status, err := ntpClient.Status(ctx)
```

## Regenerating

```sh
make proto     # buf generate (all protos)
```
