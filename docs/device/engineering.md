# Device Identity, Profiles and Inventory — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/device/`, `pkg/device/entities/`, `pkg/device/dao/`, `pkg/storage/quicbaas/device*.go` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

This is the file an implementing agent works from. Every identifier below was
read out of the source on 2026-08-18.

---

## 1. Package layout

| File | Holds |
|---|---|
| `pkg/device/service.go` | `Service` — device CRUD |
| `pkg/device/profile_service.go` | `ProfileService` — profile CRUD, matching, assignment |
| `pkg/device/template_service.go` | `TemplateService` — template CRUD, template → profile |
| `pkg/device/types.go` | The three service interfaces |
| `pkg/device/datastore.go` | `Datastore` — DAO factory over `quicbaas.Storage` |
| `pkg/device/dao/types.go` | `DeviceDAO`, `DeviceProfileDAO`, `DeviceTemplateDAO` |
| `pkg/device/config.go` | `Config`, `DefaultConfig`, `Configuration`, `DatastorePartition` |
| `pkg/device/errors.go` | Typed errors, `MessageError`, `WrappedError` |
| `pkg/device/id.go` | `NewID()` |
| `pkg/device/sdn_integration.go` | `SDNIntegration` interface and its event types — **contract only** |
| `pkg/device/entities/device.go` | `Device`, `DeviceState`, `allowedTransitions`, `ErrInvalidTransition` |
| `pkg/device/entities/profile.go` | `DeviceProfile`, `NetworkPhaseConfig`, `ProfileMatchRules`, `ACLConfig`, `DHCPPoolConfig`, `PlatformdConfigRef`, `DeviceRole`, `AuthMethod` |
| `pkg/device/entities/template.go` | `DeviceTemplate` |
| `pkg/device/entities/ekcert.go` | `ParseEKCertPEM`, `ValidateEKCertPEM`, `ErrEKCertNotPEM`, `ErrEKCertInvalid` |
| `pkg/device/entities/bmc.go` | `BMCConfig`, `BMCProtocol`, its validation errors |
| `pkg/device/entities/bmc_enrollment.go` | `BMCEnrollment` |
| `pkg/device/entities/violation.go` | `ViolationEvent`, `ViolationSeverity`, `ViolationSource` |
| `pkg/storage/quicbaas/device_profile.go` | `DeviceProfileDAO` implementation |

## 2. Exported surface

### 2.1 Interfaces (`pkg/device/types.go`)

```go
type DeviceService interface {
    Save(ctx, *entities.Device) error
    Get(ctx, id uint64) (*entities.Device, error)
    Delete(ctx, *entities.Device) error
    Update(ctx, *entities.Device) error
    Count(ctx) (int, error)
    Page(ctx, datastore.PageQuery) (datastore.PageResult[*entities.Device], error)
    FindBySerial(ctx, serial string) (*entities.Device, error)
    FindByHostname(ctx, hostname string) (*entities.Device, error)
}
```

`DeviceProfileService` adds `FindByMACAddress`, `FindBySerial`,
`FindMatchingProfile`, `AssignToDeviceWithEK`, `UnassignFromDevice`.

`DeviceTemplateService` adds `FindByName(ctx, tenantID, name)`, `ToProfile`,
`ToProfileWithConfigOverrides`.

**`FindConfigForDevice` and `AssignToDevice` are on the concrete
`*ProfileService` only** — they are not members of the `DeviceProfileService`
interface. Code holding the interface cannot call them; hold `*ProfileService`
or add them to the interface deliberately.

### 2.2 Constructors

| Constructor | Signature |
|---|---|
| `NewDatastore` | `(quicbaas.Storage, *logging.Logger) *Datastore` |
| `NewService` | `(*Datastore) (*Service, error)` |
| `NewProfileService` | `(*Datastore) (*ProfileService, error)` |
| `NewTemplateService` | `(*Datastore) (*TemplateService, error)` |

There are no functional options anywhere in `pkg/device` (grepped
2026-08-18). All three services take exactly one argument.

`Datastore` exposes `DeviceDAO()`, `ProfileDAO()`, `TemplateDAO()`. All three
return `(dao.X, error)` and, in the current implementation, never return a
non-nil error — they construct the quicbaas DAO directly.

`ProfileService.DAO()` returns the underlying `dao.DeviceProfileDAO`; its doc
comment says it exists for *"the SDN enrollment hook constructor which requires
direct DAO access for profile matching during device enrollment."* Do not reach
for it otherwise.

### 2.3 Compile-time interface checks

Only one exists: `var _ DeviceTemplateService = (*TemplateService)(nil)` in
`template_service.go`. `*Service` and `*ProfileService` carry no equivalent
assertion — adding them is a cheap correctness win, not a defect being papered
over here.

## 3. Invariants

1. **A zero ID is always rejected.** `Save`, `Get`, `Delete`, `Update` on all
   three services reject `ID == 0` before touching storage
   (`ErrInvalidDeviceID`, `ErrInvalidProfileID{}`, `ErrInvalidTemplateID{}`).
   `NewID()` guards against minting `0` for exactly this reason.
2. **`Update` reads before it writes.** All three `Update` methods `Get` the
   record first and return a wrapped error if it is absent, so `Update` cannot
   create. `Save` can.
3. **IDs fit in 2^53.** `NewID()` = 21-bit seconds-since-2024 prefix `<<32` |
   32-bit process counter. Monotonic within a process; the time prefix advances
   across restarts. Every internal allocator of a device id must funnel through
   it so the wire format stays consistent.
4. **Template timestamps are service-managed.** `TemplateService.Save` sets
   `CreatedAt` if zero and always sets `UpdatedAt`; `Update` sets `UpdatedAt`.
   The device and profile services do **not** manage timestamps — `Device`
   carries `CreatedAt`/`UpdatedAt` fields that only `Transition()` touches
   (`UpdatedAt` only).
5. **`ToProfile` does not persist.** Its doc comment is explicit: *"It does NOT
   save the profile -- the caller is responsible for saving."* The returned
   profile has no ID unless an override supplied one.
6. **Template config is deep-copied, match rules are deep-copied by YAML
   round-trip** (`deepCopyMatchRules`). Overrides passed to `ToProfile` are
   assigned by reference for `PlatformdConfig` and `MatchRules`, and merged
   key-by-key for `Networks`.
7. **The merged config lands in two places.**
   `ToProfileWithConfigOverrides` writes the merged map to **both**
   `profile.Config` and `profile.PlatformdConfig.Inline`. The duplication is
   intentional and documented in the source — `Config` is what config delivery
   returns, `PlatformdConfig.Inline` is back-compatibility.
8. **Assignment is idempotent in shape, not in time.**
   `AssignToDeviceWithEK` overwrites `EKSerial`, `MACAddress` and `EKCert` only
   when the corresponding argument is non-empty, then unconditionally sets
   `Assigned = true` and `AssignedAt = time.Now().UTC()`. Re-running it moves
   the timestamp.
9. **Unassignment is total.** `UnassignFromDevice` clears `EKSerial`,
   `MACAddress`, `EKCert`, `Assigned` and `AssignedAt` — it is the symmetric
   inverse, not a partial reset.
10. **Lifecycle transitions are table-driven.** `DeviceState.CanTransitionTo`
    consults `allowedTransitions`; `Device.Transition` applies it and stamps
    `UpdatedAt`. `revoked` has an empty target set and is terminal.
11. **Roles resolve in one place.** `entities.ParseDeviceRole` is the only
    string-to-`DeviceRole` mapping (a map of canonical values plus aliases,
    case-insensitive). The bootstrap roles `control-plane`, `gateway` and
    `worker` are canonical members. Empty resolves to `DeviceRoleUnknown`;
    anything else outside the vocabulary is `ErrUnknownDeviceRole` — no caller
    may fall back to `unknown` for an unrecognised string. `IsValid` is true
    only for canonical spellings, so an alias never reaches storage.
12. **Seeded templates are role-keyed.** `device.NewRoleTemplate(role, config)`
    is the single constructor for the bootstrap seeder's upload, whichever
    handler receives it (see `docs/device/api.md` §4.1): `Name` = `Role` =
    the role string, `Config` verbatim, `ID` = `util.NewID(role)`.
13. **Concurrency is not guaranteed by this package.** Neither `Service`,
    `ProfileService` nor `TemplateService` holds a lock. Read-modify-write
    sequences (`Update`, `AssignToDeviceWithEK`, `UnassignFromDevice`) are
    **not atomic** — two concurrent assignments to the same profile race.
    **This corrects the legacy `architecture.md`, which claimed "DAOs use mutex
    protection" and "pagination uses snapshot isolation"; no mutex exists in
    `pkg/device` or in `pkg/storage/quicbaas/device_profile.go`.**

## 4. Error semantics

### 4.1 Package errors (`pkg/device/errors.go`, `profile_service.go`, `service.go`)

| Error | Type | Returned when |
|---|---|---|
| `ErrInvalidDeviceID` | `*MessageError` value | Device id or `device.ID` is zero, or device is nil |
| `ErrInvalidProfileID{}` | struct | Profile id is zero, or profile is nil |
| `ErrInvalidTemplateID{}` | struct | Template id is zero |
| `ErrNilTemplate{}` | struct | A nil `*DeviceTemplate` was passed |
| `ErrTemplateNameRequired{}` | struct | `FindByName` called with an empty name |
| `ErrTemplateNotFound{ID}` | struct | Declared; **not returned by `pkg/device` today** — `TemplateService.Get` wraps the DAO error instead |
| `ErrDuplicateTemplateName{Name}` | struct | Declared; **not returned by `pkg/device` today** |
| `ErrTemplateConfigRequired{}` | struct | Declared; **not returned by `pkg/device` today** |
| `ErrProfileNotAssigned{ID}` | struct | Declared; **not returned by `pkg/device` today** |
| `ErrDeviceIdentityRequired{}` | struct | `FindConfigForDevice` / `AssignToDeviceWithEK` with neither EK serial nor MAC |
| `ErrNoMatchingConfig{EKSerial, MAC}` | struct | `FindConfigForDevice` found nothing |

Three declared-but-unreturned errors are recorded above rather than omitted:
they are the vocabulary a future change should use, and a reader who greps for
them deserves to know they are currently inert.

`MessageError` (message, no cause) and `WrappedError` (message + `Unwrap`) are
the two generic shapes. **Every service method that fails from storage returns
`&WrappedError{Msg: …, Err: err}`**, so `errors.Is`/`errors.As` reach the
underlying DAO error — including `quicbaas.ErrNotFoundByIndex`.

### 4.2 Entity errors

| Error | Package | Meaning |
|---|---|---|
| `ErrInvalidTransition{From, To}` | `entities` | Lifecycle transition not in the table |
| `ErrUnknownDeviceRole{Role}` | `entities` | `ParseDeviceRole` given a non-empty string outside the role vocabulary; REST surfaces it as `400` |
| `ErrEKCertNotPEM{}` | `entities` | `pem.Decode` produced no block |
| `ErrEKCertInvalid{Cause}` | `entities` | PEM decoded but `x509.ParseCertificate` failed; `Unwrap` exposes the parse error |
| `ErrInvalidViolationSeverity{Value}` | `entities` | Severity outside `warning` / `severe` |
| `ErrInvalidViolationSource{Value}` | `entities` | Source outside `attestation` |
| `ErrBMCAddressRequired{}`, `ErrBMCUsernameRequired{}`, `ErrBMCPasswordRequired{}`, `ErrBMCInvalidPort{Port}`, `ErrBMCUnknownProtocol{Protocol}` | `entities` | `BMCConfig.Validate` |

### 4.3 Fail-closed paths

| Path | Behaviour |
|---|---|
| `ValidateEKCertPEM` | Empty string is valid (no prestage). A **non-empty unparseable** value is rejected at every transport boundary — gRPC, REST, QUIC, MCP and CLI all call it. It is never stored unvalidated. |
| `FindConfigForDevice` | No fallback profile, no default. A miss is `ErrNoMatchingConfig`. |
| `AssignToDeviceWithEK` | No identity ⇒ `ErrDeviceIdentityRequired`, before any storage read. |
| `DeviceState.CanTransitionTo` | Unknown source state ⇒ `ErrInvalidTransition`, not "allow". |
| `ViolationEvent.Validate` | Unrecognised severity or source ⇒ error, never the lenient branch. |
| `Handler.Activate` | A switch VLAN move error ⇒ HTTP 500; the SDN policy step does **not** run. |
| `Handler.GetProfile` / `Handler.Activate` | Missing serial in the mTLS-populated context ⇒ 400 `ErrMissingSerial`. The serial is never taken from the request body. |

**One path is deliberately open:** `transitionSwitchPort` returns `nil` when no
switch service is configured or when the context carries no switch name/port.
A deployment without managed switches activates devices without a VLAN move.
That is a documented no-op, not a silent failure — but it means "activation
succeeded" does not imply "the port moved".

## 5. Configuration

`pkg/device/config.go`:

```go
type Config struct {
    QuicBaaS  *quicbaas.Config `yaml:"quicbaas"  json:"quicbaas"  mapstructure:"quicbaas"`
    ShardID   uint64           `yaml:"shard-id"  json:"shard_id"  mapstructure:"shard-id"`
    Partition string           `yaml:"partition" json:"partition" mapstructure:"partition"`
}
```

| Key | Type | Default (`DefaultConfig`) |
|---|---|---|
| `quicbaas.storage-backend` | string | `pebble` |
| `quicbaas.data-dir` | string | `trusted-data/quicbaas` |
| `quicbaas.wal-dir` | string | `trusted-data/quicbaas/wal` |
| `quicbaas.node-id` | uint64 | `1` |
| `quicbaas.cache-size` | int | `64 * 1024 * 1024` |
| `quicbaas.log-level` | string | `warn` |
| `quicbaas.consistency-level` | — | `quicbaas.ConsistencyLinearizable` |
| `shard-id` | uint64 | `0` |
| `partition` | string | `devices` |

Two package-level variables also exist: `DatastorePartition = "devices"` and
`Configuration *Config` (a nil package global, unset by anything in
`pkg/device`).

**There are no device-specific environment variables.** The legacy
`configuration.md` documented `DEVICE_QUICBAAS_BACKEND`,
`DEVICE_QUICBAAS_DATA_DIR`, `DEVICE_QUICBAAS_WAL_DIR`, `DEVICE_SHARD_ID` and
`DEVICE_PARTITION`; **none of those strings appears anywhere in the codebase**
(grepped repo-wide, 2026-08-18). Configuration is file-driven. The `PLATFORMCTL_*`
environment variables in [cli.md](cli.md) are client-side and unrelated.

Profile-level configuration knobs worth knowing:

| Field | Default when unset | Notes |
|---|---|---|
| `DeviceProfile.EnrollmentNetwork` | `DefaultEnrollmentNetwork` = `"provisioning"` | Resolved by `GetEnrollmentNetworkConfig()` |
| `DeviceProfile.PostEnrollmentNetwork` | `DefaultPostEnrollmentNetwork` = `"trusted"` | `GetPostEnrollmentNetworkConfig()` also back-fills `Zone` from the profile-level `Zone` and returns a **copy**, so the stored map entry is not mutated |
| `DeviceProfile.FailureNetwork` | `DefaultFailureNetwork` = `"quarantine"` | `GetFailureNetworkConfig()` |
| `DeviceProfile.WorkloadPCR` | `DefaultWorkloadPCR` = `14` | `GetWorkloadPCR()`; valid 0–23, and 0 means "use the default" |
| `BMCConfig.Port` | `DefaultBMCIPMIPort` = `623` / `DefaultBMCRedfishPort` = `443` | `EffectivePort()` picks by protocol |

## 6. Persistence

- Backend: `quicbaas.Storage`, exclusively. `Datastore` has no backend switch.
- Entity types are addressed by the quicbaas DAO layer; profiles use the entity
  type constant `entityTypeDeviceProfile` in `pkg/storage/quicbaas/`.
- **Every `Find*` on `DeviceProfileDAO` is a full scan.** The implementation
  pages `storage.List(ctx, entityTypeDeviceProfile, 1000, pageToken, shardID)`
  and filters in Go. There is no secondary index. Cost is O(profiles) per
  lookup, per request.
- Normalisation on the scan paths:
  - `FindByMACPrefix` lowercases both the input and the stored `MACPrefix`.
  - `FindBySerialPrefix` uppercases both the input and the stored
    `SerialPrefix`.
  - `FindMatchingProfile` lowercases the MAC and uppercases the serial before
    calling `ProfileMatchRules.Matches`.
  - `FindByEKSerial` and `FindByExactMAC` use `strings.EqualFold`.
  - **`ProfileMatchRules.Matches` itself does no normalisation** — it is a plain
    prefix/equality comparison. Callers that invoke it directly (not through the
    DAO) get case-sensitive behaviour. That asymmetry is real; do not rely on
    `Matches` being case-insensitive.
- `ProfileMatchRules.Matches` is **OR across fields**: any single non-empty
  rule that matches returns true. `Model` and the legacy `ModelPattern` are
  exact equality; `MACPrefix`, `SerialPrefix` and legacy `SerialPattern` are
  prefixes. `ManufacturerMatch`, `TPMVendor` and `CustomAttributes` participate
  in `IsEmpty()` but are **not evaluated** by `Matches`.
- A profile whose stored JSON fails to unmarshal is **skipped with a warning**,
  not fatal (`logger.Warn("Failed to deserialize device profile", …)`). One
  corrupt record does not take out lookup.
- Migration/compatibility: `NetworkPhaseConfig`, `ProfileMatchRules` and
  `PlatformdConfigRef` each carry an explicit *"Legacy fields retained for
  YAML/JSON unmarshalling of existing configs"* block (`Subnet`, `DNSServers`,
  `DHCP`; `ModelPattern`, `SerialPattern`, `ManufacturerMatch`, `TPMVendor`,
  `CustomAttributes`; `ConfigName`, `ConfigPath`, `Version`). Do not remove
  them without a stored-record migration.

## 7. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit — services | `pkg/device/service_test.go`, `profile_service_test.go`, `profile_service_config_test.go`, `template_service_test.go` | CRUD, validation, assignment, template → profile |
| Unit — entities | `pkg/device/entities/*_test.go` | State machine, EK-cert parsing, BMC validation, violations, match rules |
| Unit — DAO | `pkg/device/datastore_test.go` | DAO factory wiring |
| Unit — config | `pkg/device/config_test.go` | Defaults |
| Unit — SDN contract | `pkg/device/sdn_integration_test.go` | Event/phase validation |
| Benchmark | `pkg/device/benchmark_test.go` | Profile matching cost |
| Transport | `pkg/webservice/v1/device/*_test.go`, `pkg/webservice/v1/rest/device/*_test.go`, `pkg/api/daemon/quic_device_*_test.go`, `pkg/api/mcp/device_profile_dispatch_test.go` | REST routing, QUIC wire compatibility, MCP dispatch |

Fault-injection seams: the DAO interfaces in `pkg/device/dao/types.go` (swap a
fake `DeviceProfileDAO`), and `deviceProfileClient` in
`pkg/cli/commands/device/profile_assign.go`, which exists *"so tests can
exercise the derivation logic without a live daemon."*

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide, not only here.

## 8. Observability

- **Logging.** The DAO layer logs deserialisation failures at Warn with the
  entity id. `Handler.Activate` logs at Error for ARP lookup failure, switch
  VLAN transition failure and port-state transition failure, and at Info on
  success (`"Device %s activated on trusted VLAN %d"`). `transitionSwitchPort`
  logs the switch, port and VLAN at Info.
- **Metrics.** `pkg/device` declares none.
- **Audit.** `pkg/device` writes no audit records itself.
- **Redaction.** `pkg/config/snapshot.go` redacts any config key whose name
  contains `password`, `secret`, `token`, `private` and similar substrings,
  substituting `••••`. `BMCConfig.Password` is additionally tagged
  `secret:"true"`. Note that `pkg/bootstrap.SecretStructTag` (the constant
  naming that tag) has **no consumer in non-test code** — the tag is currently
  declarative. Do not assume a resolver walks it.
- **Never log**: `DeviceProfile.BMC.Password`, and the delivered
  `DeviceProfile.Config` (it is a full platform configuration and may embed
  secret references).
- **Do log freely**: `EKCert`. The MCP result formatter says so explicitly —
  *"an EK certificate is public key material carrying no secrets, so echoing it
  back lets operators audit which certificate is prestaged."*

## 9. Related

- [architecture.md](architecture.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — transports, opcodes, authorization
- [`docs/sdn/`](../sdn/) — the implementation side of `SDNIntegration`
- [`docs/switch/`](../switch/) — the switch manager activation calls into
