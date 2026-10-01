# Tenant Configuration Reference

> Subordinate to the feature files ([architecture.md](architecture.md),
> [engineering.md](engineering.md), [cli.md](cli.md), [api.md](api.md),
> [user.md](user.md)); where this file disagrees with them, they win.

## There is no `tenancy:` configuration section

The platform configuration file has no tenancy section. Earlier revisions of
this page documented one (`tenancy:` with VLAN allocation, per-tenant bridges,
isolation modes and environment variables); none of it was ever read by the
code, and the per-tenant VLAN range and OVS bridge it described were deleted
by #708.

The tenant manager is configured in code with `tenant.Config`
(`pkg/tenant/config.go`), built from `tenant.DefaultConfig()`.

## `tenant.Config`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `DefaultComputeQuota` | `ComputeQuota` | 10 VMs, 50 containers, 32 vCPUs, 65536 MB memory, 1024 GB disk | Compute quota a new tenant gets unless the request carries one |
| `DefaultNetworkQuota` | `NetworkQuota` | 5 bridges, 100 ports, 10000 Mbps | Network quota a new tenant gets unless the request carries one; accounting only, nothing enforces it in the datapath yet |
| `DefaultStorageQuota` | `StorageQuota` | 2048 GB volumes, 100 snapshots | Storage quota a new tenant gets unless the request carries one |
| `EnableDEKIsolation` | `bool` | `true` | Create a per-tenant DEK at tenant creation; `NewManager` refuses to start without a DEK client when it is on |
| `DEKAlgorithm` | `string` | `aes-256-gcm` | Empty means the backend default; otherwise one of `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, `chacha20-poly1305`, `xchacha20-poly1305` |
| `DEKMaxOperations` | `uint64` | `0` (unlimited) | Operations before rotation is due |
| `DEKMaxBytes` | `uint64` | `0` (unlimited) | Bytes encrypted before rotation is due |
| `DEKWarningPercent` | `int32` | `80` | Usage percentage at which DEK status reports a warning |

`Config.Validate` rejects negative quota limits and an unsupported DEK
algorithm with `ErrConfigValidation`.

## How platformd wires it today

`platformd serve` builds the manager from `tenant.DefaultConfig()` with
`EnableDEKIsolation` turned off, over the quicbaas IAM tenant client. Tenant
CRUD, lifecycle and quotas work; per-tenant DEKs are not created on that path.

## Network

A tenant has no network configuration. Tenant networks are EVPN/VXLAN overlays
and a tenant's routing domain becomes a VRF; see
[architecture.md](architecture.md) and the
[reference network](../architecture/reference-network.md).
