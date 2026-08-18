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
| `vlan/` | Per-tenant VLAN allocation |
| `bridge/` | Per-tenant bridge naming and lifecycle |
| `keyspace.go` | Per-tenant keyspace |
| `dek_client.go` | Per-tenant DEK operations; `NewTenantDEKClient(dek quicbaas.DEKClient) TenantDEKClient` |
| `config.go` | `Config`, `ManagerConfig` |
| `errors.go` | Typed errors |

A tenant is four things at once: a **VLAN**, a **bridge**, a **keyspace** and a
**DEK**, plus a quota. That is the whole model, and each of the four has its own
sub-package or file.

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
   succeeds. This is deliberate — retried API calls must not fail — and it means
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

Exceeding a quota is `ErrQuotaExceeded`; hitting a hard resource ceiling is
`ErrResourceLimitReached`.

## 4. Errors

Typed structs, plus two sentinels:

**Sentinels:** `ErrInvalidID` (`errors.New("tenant: invalid id segment")`),
`ErrNilBarrierStatus` (a value of `ErrNilBarrierStatusType`).

**Typed:** `ErrTenantExists`, `ErrTenantNotFound`, `ErrInvalidRequest`,
`ErrInvalidState`, `ErrInvalidTransition`, `ErrStorageFailed`,
`ErrBridgeOperationFailed`, `ErrVLANAllocationFailed`, `ErrQuotaExceeded`,
`ErrResourceLimitReached`, `ErrInvalidVLANRange`, `ErrDEKOperationFailed`,
`ErrConfigValidation`, `ErrBarrierOperationFailed`, `ErrBarrierNotSupported`.

`ErrBarrierNotSupported` is the one to notice: **per-tenant barriers are not
available in every configuration.** Code must handle the capability being absent
rather than assuming a barrier exists.

`ErrNilBarrierStatus` being a *typed* sentinel rather than `errors.New` is
unusual; compare it with `errors.Is` like any other sentinel.

## 5. Invariants

1. **A tenant's VLAN, bridge, keyspace and DEK are allocated together.** A
   tenant that exists with three of the four is a partially constructed tenant,
   and the failure modes (`ErrVLANAllocationFailed`,
   `ErrBridgeOperationFailed`, `ErrDEKOperationFailed`) exist so the creation
   path can tell which one failed.
2. **VLAN allocation is bounded by a configured range.** Outside it is
   `ErrInvalidVLANRange`, checked before allocation rather than discovered as a
   collision.
3. **Quota checks precede allocation.** `CheckQuota` exists as its own RPC so a
   caller can ask before acting.
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

## 7. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/tenant/**/*_test.go` | State transitions, quota arithmetic, VLAN range validation |
| Integration | `test/integration/` tenant paths | Bridge and DEK operations against a running daemon |

The transition table and `HasCapacity` are pure functions and are the cheapest
things in the feature to test exhaustively; do so before touching either.

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
- [`docs/sdn/`](../sdn/) — VLANs, bridges and zones a tenant is allocated from
- [`docs/compute/`](../compute/) — what consumes a tenant's compute quota
- [`docs/iam/`](../iam/) — tenant-scoped users, groups, roles and policies
