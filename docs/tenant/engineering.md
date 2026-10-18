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

**An update never touches usage.** `Manager.UpdateQuotas` applies each section
through `SetLimits`, which copies the `Max*` fields and leaves the `Used*`
counters alone; usage moves only through `Reserve` and `Release`.
`TenantGRPCServer.UpdateQuotas` starts from `GetQuotas` and overwrites only the
limits the request carries, so an absent section keeps its limits and
`MaxDiskGB`, which the gRPC message cannot carry, keeps its value. Until a
go-quicbaas tag stores quotas, a limit that differs from the default is
`ErrTenantFieldNotPersisted` (§6).

Exceeding a quota is `ErrQuotaExceeded`; hitting a hard resource ceiling is
`ErrResourceLimitReached`.

**Without an enforcer the entity answers.** A manager built with no quota
enforcer or usage tracker (the daemon's IAM-backed wiring) answers `CheckQuota`
and `GetUsage` from the tenant entity's own limits and `Used*` counters. An
unknown tenant is `ErrTenantNotFound` (`NotFound` on every transport), never an
"available" or "not available" answer; only `ErrQuotaExceeded` becomes
`available=false`.

## 4. Errors

Typed structs, plus two sentinels:

**Sentinels:** `ErrInvalidID` (`errors.New("tenant: invalid id segment")`),
`ErrNilBarrierStatus` (a value of `ErrNilBarrierStatusType`).

**Typed:** `ErrTenantExists`, `ErrTenantNotFound`, `ErrInvalidRequest`,
`ErrInvalidState`, `ErrInvalidTransition`, `ErrStorageFailed`,
`ErrQuotaExceeded`, `ErrResourceLimitReached`, `ErrDEKOperationFailed`,
`ErrConfigValidation`, `ErrBarrierOperationFailed`, `ErrBarrierNotSupported`,
`ErrTenantFieldNotPersisted`.

`ErrTenantFieldNotPersisted` is the declared gap of §6: a write that would
change a field the pinned go-quicbaas SDK cannot store.

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
persistence failures. The IAM tenant record (reached through the SDK
`TenantClient`) is the store of record:

- **Identity** — ID, name and timestamps are IAM tenant fields. The name is
  canonical: no write after create changes it.
- **Declared gap: every other field.** Display name, lifecycle state, the
  compute/network/storage quota limits, labels and annotations cannot be
  stored until a go-quicbaas tag persists them. The pinned go-quicbaas
  v0.12.0-alpha embedded `handleIAMTenantUpdate`
  (`sdk/go/transport/embedded/handlers_iam.go:204-208`) passes only
  `DisplayName` to `UpdateTenant`, as the tenant's new *name*, and drops
  `Metadata` and `Status`; `tenantToSDK` returns no metadata, status or
  display name. The display name is no exception: sending it would rename
  `acme` to `Acme Corporation` and lose it from `GetTenantByName("acme")`.

The manager therefore never calls IAM `Update`. Every write (create, update,
quota update, suspend, resume) builds the entity it would store and compares
it with the entity a reload rebuilds from IAM. If they agree, only the cache is
updated and the write succeeds. If any field differs, the write returns
`ErrTenantFieldNotPersisted{TenantID, Fields}`, naming each field
(`display_name`, `state`, `compute_quota`, `network_quota`, `storage_quota`,
`labels`, `annotations`), and the cache is unchanged: no write reports success
for data that is not stored. A create that carries such a field rolls the IAM
tenant and DEK back. The error is `Unimplemented` on gRPC, Unix, QUIC and MCP
and `501 Not Implemented` on REST.

A reload rebuilds: the IAM identity; state `active` (`suspended` when IAM's
status says so); the configured default quotas (`Config.Default*Quota`) with
zero usage; display name = name; no labels or annotations. If a transport does
store the JSON record under the IAM metadata key `platform.tenant`
(`PlatformRecordKey`), reads parse it over that baseline; a record that does
not parse, or names an unknown state, is `ErrStorageFailed`. Usage counters
move only through `Reserve` and `Release` and live in the cache. The
`deleting` step of delete is cache-only, since IAM has no such status.

Reads that miss the cache (`GetTenant`, `GetTenantByName`, `ListTenants`)
rebuild the entity from IAM. `ListTenants` always reads IAM and replaces each
listed tenant's cache entry with the entity it rebuilt.

The DEK path is not stored; it is derived from the tenant ID.

Per-tenant keyspaces (`keyspace.go`) are how a tenant's
data is separated in the store — the isolation is in the key path, not in a
filter applied at read time.

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
