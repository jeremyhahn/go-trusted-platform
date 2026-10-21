# Platform Tenancy — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/tenant/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Design and boundaries: [architecture.md](architecture.md). Transport matrix:
> [api.md](api.md).

---

## 1. Package layout

| File / dir | Holds |
|---|---|
| `manager.go` | `Manager` — the service; `NewManager(cfg *ManagerConfig)` |
| `entity.go` | The tenant entity |
| `state.go` | The five-state lifecycle and its transition map |
| `quotas.go`, `quota/` | Quota limits and usage accounting |
| `keyspace.go` | Per-tenant keyspace |
| `dek_client.go` | Per-tenant DEK operations; `NewTenantDEKClient(dek quicbaas.DEKClient) TenantDEKClient` |
| `config.go` | `Config`, `ManagerConfig` |
| `errors.go` | Typed errors |

A tenant is a **keyspace** and a **DEK**, plus a quota and, optionally, a
per-tenant barrier. Each has its own file.

A tenant has **no VLAN range and no OVS bridge**. The former `vlan/` and
`bridge/` sub-packages were deleted by #708: under the
[reference network](../architecture/reference-network.md) switch VLANs are
underlay zones, tenants never create zones, and tenant networks are EVPN/VXLAN
overlays addressed from the IPAM pool. A tenant's network identity becomes a
VRF in the tenancy work that follows the overlay transport (#709); until then
the tenant manager allocates no network resource.

## 2. The lifecycle

`State` is a `string` type (`pkg/tenant/state.go:21`) with five values:

| Constant | Value |
|---|---|
| `StateCreated` | `created` |
| `StateActive` | `active` |
| `StateSuspended` | `suspended` |
| `StateDeleting` | `deleting` |
| `StateDeleted` | `deleted` |

`ValidTransitions` (`state.go:38`) is an explicit allowlist:

```
created   -> active | deleting
active    -> suspended | deleting
suspended -> active | deleting
deleting  -> deleted
deleted   -> (nothing)
```

Three properties that follow, and that callers depend on:

1. **`deleted` is terminal.** No transition leaves it. A deleted tenant is not
   revived; a new one is created.
2. **`deleting` only goes forward.** Deletion cannot be cancelled once entered.
3. **Same-state transitions are allowed for idempotency**
   (`CanTransitionTo`, `state.go:69-73`). Suspending a suspended tenant
   succeeds, and resuming an active tenant succeeds without a change
   (`Manager.ResumeTenant`) on every transport. This is deliberate — retried API calls must not fail — and it means
   `CanTransitionTo(s, s)` is always true, including for `deleted`.

An invalid transition is `ErrInvalidTransition`; an operation against a state
that does not permit it is `ErrInvalidState`.

## 3. Quotas

`ComputeQuota` (`quotas.go:17`) carries **limits and usage in the same struct**:

| Limit | Usage counterpart |
|---|---|
| `MaxVMs` | `UsedVMs` |
| `MaxContainers` | `UsedContainers` |
| `MaxVCPUs` | `UsedVCPUs` |
| `MaxMemoryMB` | `UsedMemoryMB` |
| `MaxDiskGB` | `UsedDiskGB` |

`HasCapacity(vms, containers, vcpus, memoryMB, diskGB int64) bool` checks a
prospective allocation against all five.

**A unit mismatch to watch.** The struct field is `MaxMemoryMB` — **megabytes** —
while the CLI flag is `--max-memory-gb` and the disk field is `MaxDiskGB`
alongside a `--max-volumes-gb` flag. The CLI's quota flag set is also wider than
`ComputeQuota`: it accepts `--max-bridges`, `--max-ports`,
`--max-bandwidth-mbps`, `--max-volumes-gb` and `--max-snapshots`, which have no
counterpart field in `ComputeQuota`. `ComputeQuotaSummary` is the reporting
shape. Check the unit and the field before writing a quota value.

**Partial quota updates are explicit.** `quotas set` uses
`cmd.Flags().Changed("max-vms")` per flag, so an unset flag leaves the existing
limit alone rather than zeroing it. Zero is a real value meaning "no capacity",
which is why the `Changed` check is necessary.

**An update never touches usage.** `Manager.UpdateQuotas` applies each section
through `SetLimits`, which copies the `Max*` fields and leaves the `Used*`
counters alone; usage moves only through `Reserve` and `Release`.
`TenantGRPCServer.UpdateQuotas` starts from `GetQuotas` and overwrites only the
limits the request carries, so an absent section keeps its limits and
`MaxDiskGB`, which the gRPC message cannot carry, keeps its value.

Exceeding a quota is `ErrQuotaExceeded`; hitting a hard resource ceiling is
`ErrResourceLimitReached`.

## 4. Errors

Typed structs, plus two sentinels:

**Sentinels:** `ErrInvalidID` (`errors.New("tenant: invalid id segment")`),
`ErrNilBarrierStatus` (a value of `ErrNilBarrierStatusType`).

**Typed:** `ErrTenantExists`, `ErrTenantNotFound`, `ErrInvalidRequest`,
`ErrInvalidState`, `ErrInvalidTransition`, `ErrStorageFailed`,
`ErrQuotaExceeded`, `ErrResourceLimitReached`, `ErrDEKOperationFailed`,
`ErrConfigValidation`, `ErrBarrierOperationFailed`, `ErrBarrierNotSupported`.

`ErrBarrierNotSupported` is the one to notice: **per-tenant barriers are not
available in every configuration.** Code must handle the capability being absent
rather than assuming a barrier exists.

`ErrNilBarrierStatus` being a *typed* sentinel rather than `errors.New` is
unusual; compare it with `errors.Is` like any other sentinel.

## 5. Invariants

1. **A tenant's IAM record and DEK are created together.** `CreateTenant`
   registers a rollback for each step, so a DEK failure
   (`ErrDEKOperationFailed`) removes the IAM record rather than leaving a
   partially constructed tenant. A per-tenant barrier that fails to initialise
   is logged and can be initialised later.
2. **A tenant owns no network resource.** No VLAN, no OVS bridge; suspension
   and resumption are state changes only. Traffic enforcement for a tenant
   arrives with its VRF.
3. **Quota checks precede allocation.** `CheckQuota` exists as its own RPC so a
   caller can ask before acting. An exceeded quota is an answer
   (`available: false` with the reason); any other failure, such as an unknown
   tenant, is an error on every transport. Without a quota enforcer (the
   IAM-only manager platformd runs) the tenant's own quotas, set by
   `CreateTenant` and `UpdateQuotas`, are the limits; `volumes` is refused
   there because the entity tracks volume capacity in GB, not a count.
   `GetUsage` likewise refuses an unknown tenant.
4. **DEK rotation does not re-encrypt tenant data.** `RotateTenantDEK` returns
   `DEKRotationResult`; the DEK is rewrapped, not the data.
5. **Suspension is reversible; deletion is not.** See §2.
6. **Key material is never handled as a raw byte slice in this package.** DEK
   operations go through `TenantDEKClient`, which delegates to the stack's DEK
   client. This repository is above Layer 3 and uses the stack's owned
   abstractions rather than coding protected memory directly.

## 6. Persistence

Tenant entities are stored through the stack; `ErrStorageFailed` wraps
persistence failures. Per-tenant keyspaces (`keyspace.go`) are how a tenant's
data is separated in the store — the isolation is in the key path, not in a
filter applied at read time.

A tenant's lifecycle state, quotas, labels and annotations live only in the
`Manager`'s in-memory cache; the IAM tenant record holds the ID, the name and
the timestamps. The pinned go-quicbaas `sdk/go` (v0.12.0-alpha) cannot carry
more: its embedded transport's tenant update keeps only `DisplayName`, stores
it as the tenant's new IAM **name**, and drops status and metadata. So a
tenant rebuilt from IAM (after a restart) starts as `created`, and a by-name
lookup that falls back to IAM never replaces a cached record: a name the cached
record does not carry is `ErrTenantNotFound`, since it is the SDK's rewritten
display name.

## 7. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/tenant/**/*_test.go` | State transitions, quota arithmetic, keyspace paths, the DEK adapter |
| Integration | `test/integration/tenant/` | Lifecycle, quotas, DEK and barrier operations against a running daemon, on all six transports |

The transition table and `HasCapacity` are pure functions and are the cheapest
things in the feature to test exhaustively; do so before touching either.

The integration suite tests the one `platformd` the devcontainer runner starts,
through the endpoints it exports (`TENANT_*_ENDPOINT`, `TENANT_SOCKET_PATH`) and
the mTLS trio (`PLATFORM_CLIENT_CERT`, `PLATFORM_CLIENT_KEY`,
`PLATFORM_CA_CERT`). A test never starts a QuicBaaS node of its own: a second
node in the container binds the ports the daemon already holds and tests nothing
the daemon serves (#541). `pkg/arch/integration_daemon_guard_test.go` fails
`make test` on any reference to the SDK's `NewServer` under `test/integration/`.
`TestTenantGRPCService` (`grpc_adapter_test.go`) checks the TenantService
protobuf contract over the gRPC adapter's connection and deletes the tenants it
creates in `t.Cleanup`.

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide.

## 8. Observability

`GetUsage` reports consumption against limits; `GetTenantDEKStatus` reports key
state; `GetTenantBarrierStatus` reports barrier state. All three are read-only
and safe to poll.

Unseal keys pass through `--key-hex` / `--key-base64` on the CLI. **They must not
be logged**, and a shell that records history will record them — prefer piping
or an environment mechanism over typing an unseal key as an argument.

## 9. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/sdn/`](../sdn/) — overlays and, with tenancy VRFs, a tenant's routing domain
- [`docs/compute/`](../compute/) — what consumes a tenant's compute quota
- [`docs/iam/`](../iam/) — tenant-scoped users, groups, roles and policies
