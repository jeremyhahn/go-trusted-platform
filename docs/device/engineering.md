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
| `pkg/device/registration.go` | `Registrar`, `Registration`, `Register` — the ONE find-or-create used by ACME enrollment and by the control plane; PEM helpers and `IsRecordNotFound` |
| `pkg/device/controlplane.go` | `ControlPlaneTPM`, `ControlPlaneRegistrar` — the control plane's own device record, read from its own TPM (#472) |
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
2. **Enrollment has one registration implementation.** `device.Register` is
   find-or-create by product serial, and both callers reach it: the ACME
   order-finalize hook in `pkg/webservice/v1/registry.go` maps
   `TCGEnrollmentData` onto a `Registration`, and `ControlPlaneRegistrar` maps
   the control plane's own TPM onto the same structure (#472). Two rules live
   inside it and nowhere else. The **serial lookup is verified**: qrdb's
   secondary-index path can return a record whose serial does not match the
   query when the index is incomplete, so a mismatched hit becomes a create
   rather than an overwrite of an unrelated device. And **an empty field is
   never written**: a re-enrollment that omits the event log, the EK
   certificate or a public area must not erase the one already recorded.
   A `FindBySerial` failure that is not a not-found falls through to create —
   abandoning a device the CA has just issued certificates to would leave an
   identity nothing in the fleet can join against.
3. **`Update` reads before it writes.** All three `Update` methods `Get` the
   record first and return a wrapped error if it is absent, so `Update` cannot
   create. `Save` can.

   **`DeviceService.Update` merges rather than replaces.** A zero-valued
   incoming field inherits the stored value, because the REST contract carries
   only what a caller edits and saving the entity verbatim erased everything
   else. Two groups are protected:

   | group | fields |
   |---|---|
   | lifecycle / liveness | `State`, `StateReason`, `Hostname`, `NetworkPortID`, `SwitchName`, `SwitchPort`, `LastHeartbeatAt`, `LastAttestedAt`, `ActivatedAt`, `CreatedAt`, `PriorState`, `PriorZone`, `BMCEnrollment` |
   | identity / enrollment (#252, #404) | `TenantID`, `EKCert`, `AttestPub`, `AttestCert`, `SigningPub`, `EventLog`, `HashAlgoId`, `Model`, `Serial` |

   The second group was missing until #252, so a `PUT /api/v1/devices/{id}`
   that named none of them **erased the device's TPM enrollment material** —
   `EKCert` and `AttestPub` are what let an attested machine prove it is the
   same machine — with no error and no audit trail.

   `TenantID` was the sharpest case: `DeviceRequest` has **no tenant field at
   all**, so `requestToDevice` cannot populate it and *every* update erased it,
   not merely the partial ones.

   Merging does not freeze a field — a caller sending a new value still wins,
   which is what keeps `Model` and `Serial` editable. Clearing one of these is
   deliberately not expressible through `Update`; `Save` is the unrestricted
   server-owned write path, and enrollment uses it.
4. **IDs fit in 2^53.** `NewID()` = 21-bit seconds-since-2024 prefix `<<32` |
   32-bit process counter. Monotonic within a process; the time prefix advances
   across restarts. Every internal allocator of a device id must funnel through
   it so the wire format stays consistent.
5. **Template timestamps are service-managed.** `TemplateService.Save` sets
   `CreatedAt` if zero and always sets `UpdatedAt`; `Update` sets `UpdatedAt`.
   The device and profile services do **not** manage timestamps — `Device`
   carries `CreatedAt`/`UpdatedAt` fields that only `Transition()` touches
   (`UpdatedAt` only).
6. **`ToProfile` does not persist.** Its doc comment is explicit: *"It does NOT
   save the profile -- the caller is responsible for saving."* The returned
   profile has no ID unless an override supplied one.
7. **Template config is deep-copied, match rules are deep-copied by YAML
   round-trip** (`deepCopyMatchRules`). Overrides passed to `ToProfile` are
   assigned by reference for `PlatformdConfig` and `MatchRules`, and merged
   key-by-key for `Networks`.
8. **The merged config lands in two places.**
   `ToProfileWithConfigOverrides` writes the merged map to **both**
   `profile.Config` and `profile.PlatformdConfig.Inline`. The duplication is
   intentional and documented in the source — `Config` is what config delivery
   returns, `PlatformdConfig.Inline` is back-compatibility.
9. **Assignment is idempotent in shape, not in time.**
   `AssignToDeviceWithEK` overwrites `EKSerial`, `MACAddress` and `EKCert` only
   when the corresponding argument is non-empty, then unconditionally sets
   `Assigned = true` and `AssignedAt = time.Now().UTC()`. Re-running it moves
   the timestamp.
10. **Unassignment is total.** `UnassignFromDevice` clears `EKSerial`,
   `MACAddress`, `EKCert`, `Assigned` and `AssignedAt` — it is the symmetric
   inverse, not a partial reset.
11. **Lifecycle transitions are table-driven.** `DeviceState.CanTransitionTo`
    consults `allowedTransitions`; `Device.Transition` applies it and stamps
    `UpdatedAt`. `revoked` has an empty target set and is terminal.
12. **Roles resolve in one place.** `entities.ParseDeviceRole` is the only
    string-to-`DeviceRole` mapping (a map of canonical values plus aliases,
    case-insensitive). The bootstrap roles `control-plane`, `gateway` and
    `worker` are canonical members. Empty resolves to `DeviceRoleUnknown`;
    anything else outside the vocabulary is `ErrUnknownDeviceRole` — no caller
    may fall back to `unknown` for an unrecognised string. `IsValid` is true
    only for canonical spellings, so an alias never reaches storage.
13. **Seeded templates are role-keyed.** `device.NewRoleTemplate(role, config)`
    is the single constructor for the bootstrap seeder's upload, served only
    by the seeder router (see `docs/device/api.md` §4.1): `Name` = `Role` =
    the canonical role string, `Config` verbatim, `ID` = `util.NewID(role)`.
14. **Concurrency is not guaranteed by this package.** Neither `Service`,
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
| `ErrProfileVLANsNotDistinct{VLAN}` | struct | A profile's provisioning and trusted networks share a VLAN, on any path that can introduce it — `Save`, `Update`, `AssignToDeviceWithEK`. Never from `UnassignFromDevice` or `Delete` (see below) |

**`ProfileService.save` is the one call to `profileDAO.Save`**, and
**`saveValidated` is the seam every path that can INTRODUCE invalid network
state goes through** — `Save`, `Update`, and `AssignToDeviceWithEK` (with its
`AssignToDevice` wrapper). To reach the DAO you go through `save`; to
introduce state you go through `saveValidated` first. That is what makes the
enforcement claim checkable rather than aspirational; do not add a second
`profileDAO.Save`.

The assignment path matters precisely because it does *not* touch the network
config: it loads a profile, sets its EK serial / MAC / assignment state, and
writes it back. Before #133 it bypassed the validation, so a profile stored
before the rule existed was silently re-persisted by an operation that never
inspected its networks. Binding such a profile to real hardware is the
direction that must be refused.

**`UnassignFromDevice` deliberately does not validate**, and calls `save`
directly. Validation guards the *introduction* of invalid state; unassign is
the *removal* path. Refusing to unassign a profile whose VLANs are already
invalid strands the operator — the device cannot be detached from a profile
it is trying to stop using until someone repairs a profile nobody wants any
more, which is the wrong constraint during an incident. `Delete` does not
validate either, so refusing here would protect an inconsistency in which
paths validate rather than an invariant. The failure mode this permits (an
invalid profile briefly stays stored) is strictly less bad than the one it
avoids, and activation is independently protected by the runtime guard in
`transitionSwitchPort`. Do not restore "consistency" by routing unassign
through `saveValidated`; `TestProfileService_UnassignDoesNotValidate` exists
to catch that.

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
| `Handler.Activate` | A switch-move validation error ⇒ HTTP 500 before the SDN policy step; a physical-commit error after enforcement ⇒ HTTP 500 with the port fail-closed on the provisioning VLAN. |
| `Handler.GetProfile` / `Handler.Activate` | Missing serial in the mTLS-populated context ⇒ 400 `ErrMissingSerial`. The serial is never taken from the request body. |

**One path is deliberately open:** `prepareSwitchTransition` returns a nil
move when no switch service is configured or when the context carries no
switch name/port.
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
  success (`"Device %s activated on trusted VLAN %d"`). `commitSwitchTransition`
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
