# Device Identity, Profiles and Inventory — Architecture

> **Status: NORMATIVE** · Scope: `pkg/device/`, `pkg/device/entities/`, `pkg/device/dao/`, `pkg/storage/quicbaas/device*.go` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. The problem

A machine that has never booted has no identity, and a machine that has booted
cannot be trusted to tell you what it is. Zero-touch provisioning therefore has
to answer two questions in the wrong order:

1. **Before the machine exists on the network**, what configuration should it
   get, and what is it allowed to reach?
2. **When the machine appears**, is it the machine that record was written for?

The device feature is the answer to both. A **profile** is the pre-boot record
— written by an operator, keyed to a hardware identity that does not exist on
the wire yet. A **device** is the post-enrollment record — what actually
showed up, with its TPM keys and its lifecycle state.

The failure this prevents is the obvious one: matching a booting machine on
something it asserts about itself. A MAC address is asserted. A serial number
is asserted. A TPM endorsement key certificate is not — it was burned in by
the TPM vendor and signed by a CA that neither the machine nor the operator
controls.

## 2. The shape chosen

**Three nouns, three services, one datastore.**

| Noun | Type | What it is |
|---|---|---|
| **Template** | `entities.DeviceTemplate` | A reusable blueprint: a full platform config as raw YAML bytes, plus default match rules and BMC settings. Not bound to any machine. |
| **Profile** | `entities.DeviceProfile` | The pre-boot record for one machine class or one machine: identity keys (`EKSerial`, `EKCert`, `MACAddress`), match rules, per-phase network configuration, and the merged platform config to deliver. |
| **Device** | `entities.Device` | The post-enrollment record: TPM EK certificate, attestation and signing public keys, event log, switch/port placement, and a lifecycle `State`. |

`TemplateService.ToProfile` is the transition from template to profile;
`ProfileService.AssignToDeviceWithEK` is the transition from an unbound
profile to one nailed to a specific hardware identity. Enrollment creates the
`Device`.

**Identity resolution is priority-ordered, not best-effort.**
`DeviceProfileDAO.FindConfigForDevice` tries, in order: exact EK serial, exact
MAC address, then prefix match rules. The order is the security property — the
unforgeable identifier is consulted first, and the guessable ones only after
it misses.

### 2.1 Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Match booting machines on MAC address only** | A MAC is software-settable. Any machine on the provisioning segment could claim any profile, including one carrying a control-plane configuration. EK serial is tried first for exactly this reason, and `EKCert` exists so the match can be verified cryptographically rather than by string equality. |
| **Let the machine declare its own role or profile at boot** | That makes the configuration a request rather than an assignment, and a compromised installer image would ask for the most privileged profile. Roles come from the profile record, which the operator wrote before the machine booted. |
| **Store only the EK serial, not the certificate** | A serial number is a string; comparing strings proves nothing about the key. `DeviceProfile.EKCert` holds the PEM certificate so pre-enrollment config delivery can compare the presented EK's public key against a prestaged certificate. Prestaging is optional and its absence degrades to serial/MAC matching — see the scope fence in §7. |
| **One combined "device record" covering pre-boot and post-boot** | The two records have different authors and different trust levels. A profile is operator-authored and may exist for a machine that never boots; a device is enrollment-authored and only exists because a machine presented keys. Collapsing them would let enrollment data overwrite operator intent. |
| **Free-form device status strings** | Lifecycle transitions gate network placement — quarantine and suspension are enforcement actions. `DeviceState` is a closed set with an explicit transition table (`allowedTransitions`) and `ErrInvalidTransition`, so "revoked → activated" cannot happen by assigning a string. |
| **A pluggable storage backend abstraction** | `Datastore` wraps `quicbaas.Storage` and nothing else; its doc comment states *"QuicBaaS is the implicit and only supported backend."* A second backend would mean a second correctness surface for records that gate network access. **This corrects the legacy `architecture.md`, which listed LOCAL and MEMORY backends — no such selection exists in the code.** |
| **Snowflake IDs for devices** | `device.NewID()` deliberately composes a 21-bit time prefix with a 32-bit process counter so every id fits inside JavaScript's 2^53 safe-integer range. A 64-bit snowflake would round-trip incorrectly through the WebUI's `JSON.parse` and break subsequent GET/PUT/DELETE by id. |
| **An index for profile lookup** | Every `Find*` on `DeviceProfileDAO` pages the whole entity set and filters in Go (`pkg/storage/quicbaas/device_profile.go`). This is O(n) per lookup and is documented as such in [engineering.md](engineering.md) §6 rather than hidden — the profile count is operator-scale, not machine-scale. |

## 3. Component boundaries

| Piece | Package | Owner |
|---|---|---|
| Device service (CRUD, serial/hostname lookup) | `pkg/device/service.go` | this repo |
| Profile service (CRUD, matching, assignment) | `pkg/device/profile_service.go` | this repo |
| Template service (CRUD, template → profile) | `pkg/device/template_service.go` | this repo |
| Entities and lifecycle state machine | `pkg/device/entities/` | this repo |
| DAO interfaces | `pkg/device/dao/types.go` | this repo |
| DAO implementations | `pkg/storage/quicbaas/device*.go` | this repo |
| Datastore factory | `pkg/device/datastore.go` | this repo |
| ID minting | `pkg/device/id.go` | this repo — `NewID()`, called by `Service.Create` and `Register`, not by transport adapters |
| SDN callback contract (`SDNIntegration`) | `pkg/device/sdn_integration.go` | this repo — **interface only, see §7** |
| REST CRUD + mTLS profile/activate handlers | `pkg/webservice/v1/device/`, `pkg/webservice/v1/router/device.go` | this repo |
| Bootstrap-seeder REST handlers | `pkg/webservice/v1/rest/device/` | this repo |
| gRPC `DeviceService` | `pkg/api/grpc/proto/device.proto` | this repo |
| QUIC device opcodes and handlers | `pkg/api/quic/protocol.go`, `pkg/api/daemon/quic_device_handlers.go` | this repo |
| MCP device and profile tools | `pkg/api/mcp/device_tools.go`, `device_profile_tools.go`, `tools.go` | this repo |
| SDK client | `sdk/go/services/device/client.go` | this repo |
| **The storage engine underneath** | `quicbaas.Storage` | **go-quicbaas** — consumed through its SDK |
| **Bridges, ports, flows, VLAN programming, port authentication** | `pkg/sdn/` — [`docs/sdn/`](../sdn/) | this repo, **separate feature** |
| **Physical switch port VLAN moves** | `pkg/switch/` — [`docs/switch/`](../switch/) | this repo, **separate feature** |
| **Attestation verification and quarantine decisions** | `pkg/attestation/` — [`docs/attestation/`](../attestation/) | this repo, separate feature |
| **Pre-enrollment config delivery, nonces, remote Secure Boot signing** | `pkg/provisioning/configdelivery/` | this repo, separate feature |
| **vTPM bundles bound to a profile** | `pkg/vtpm/` — [`docs/vtpm/`](../vtpm/) | this repo, separate feature |
| **BMC enrollment ceremony** | `pkg/bmc/` — [`docs/bmc/`](../bmc/) | this repo, separate feature (its outcome is stamped onto `Device.BMCEnrollment`) |

The `docs/00 §R` capability row is *"Device enrollment, templates/profiles,
IDevID/LDevID, EAB, invitations"*, **Tier 1**, reached through
`services/device` alongside `services/idevid`, `services/eab` and
`services/invitation`.

Transport mechanics — the six-transport model, the QUIC category-opcode table,
status-byte vocabulary and the authorization catalogs — live in
[`docs/daemon/api.md`](../daemon/api.md) and are not repeated here.

## 4. Data flow

### 4.1 Pre-boot: writing the record before the machine exists

```
operator                     control plane
   │
   ├─ device profile create ──▶ CreateProfile
   │    --ek-cert <PEM>          └─ ParseEKCertPEM validates at the boundary
   │    --config-file <yaml>     └─ config stored as JSON bytes on the profile
   │
   └─ device profile assign ──▶ AssignProfileToDevice
        --device <id>            └─ EK serial + EK cert derived from the
        or --ek-serial/--mac        registered Device record, or supplied
                                    explicitly; Assigned = true, AssignedAt set
```

Nothing here touches the machine. The profile is durable operator intent.

### 4.2 Boot: the machine asks who it is

```
booting machine ──▶ GET /api/v1/devices/config?mac=…&ek_serial=…
                       │
                       └─ ProfileService.FindConfigForDevice
                            1. FindByEKSerial   (EqualFold, exact)
                            2. FindByExactMAC   (EqualFold, exact)
                            3. FindMatchingProfile (prefix rules, MAC only)
                            └─ miss ⇒ ErrNoMatchingConfig
```

The resolver searches **across all tenants** — a machine at boot does not know
its tenant, which is stated in the `FindConfigForDevice` doc comment. That is a
deliberate widening and it is why EK-serial precedence matters: the first
lookup is the one that cannot be spoofed.

### 4.3 Enrollment: the device record appears

TPM attestation produces the EK certificate, attestation key and event log; a
`Device` is saved with `State = registered`. The lifecycle from there is a
closed state machine:

```
unknown → registered → installing → installed → activated → attested
                    ↘            ↘           ↘           ↘
                      quarantined ⇄ attested   suspended → revoked (terminal)
```

`registered` may also go straight to `activated` for machines with no install
step. `quarantined` and `suspended` both carry `PriorState`/`PriorZone` on the
`Device` so remediation restores the machine to where it was, rather than to a
guess.

Liveness is orthogonal to the lifecycle: enrolled nodes report a periodic
heartbeat (`POST /api/v1/device/heartbeat`, mTLS with the node's IDevID
identity — see [api.md](api.md) §Device heartbeat) that stamps
`Device.LastHeartbeatAt` and nothing else. The state machine never moves on
a heartbeat, and a silent node keeps its state — staleness is a UI/alerting
signal, not an enforcement action.

### 4.3.1 The control plane is a device too (#472)

The control plane writes its **own** device record, from its own TPM, through
the same `device.Register` the ACME finalize hook uses. Everything else in this
document applies to it unchanged: it has a serial, an EK certificate, an
`attest_cert`, a lifecycle state, and a profile an operator binds to it.

Two facts make that possible without a second code path:

- The control plane already holds what an enrollment produces. Its own CA
  issued its IAK and IDevID certificates from its own TPM at platform identity
  completion, so `ControlPlaneRegistrar` reads them rather than driving ACME at
  a listener that is not up yet.
- Registration is find-or-create by product serial, so it runs on every start
  as a reconcile. A control plane provisioned before this existed acquires its
  record on the next restart; one that already has it is untouched.

The record's author is therefore the machine itself, which is a weaker claim
than an enrollment the CA witnessed — and it is the correct one here, because
what the record asserts is *which TPM this control plane has*, and the platform
is reading that TPM directly rather than being told about it. What the record
does **not** assert is that the control plane is trustworthy; that is the
verdict the collector produces against it, on the same terms as every node.
See [`docs/attestation/architecture.md`](../attestation/architecture.md),
"The control plane is a device in its own registry".

### 4.4 Activation: identity becomes network access

`POST /api/v1/device/activate` is mTLS-authenticated; the device serial comes
from the client certificate, never from the body.

```
POST /api/v1/device/activate  (mTLS, serial from client cert)
   │
   ├─ SDNEnrollmentHook.LockSerial(serial)           SERIALIZE      → docs/sdn/
   │    held across the whole sequence; OnEnrollmentComplete takes the
   │    same lock, so a re-enrollment cannot replace the pending
   │    activation mid-flight
   ├─ SDNEnrollmentHook.PrecheckActivation(serial)   VALIDATE       → docs/sdn/
   │    no side effects: pending activation present, port resolvable
   │    (deferred to the device MAC when enrollment happened before any
   │    fabric attach). Returns an ActivationPlan reserving the EXACT
   │    pending-activation version, the policy built from it, and a
   │    value-copy snapshot of the switch VLANs; a zone mismatch is
   │    recorded on the plan (ExpectQuarantine), not an error
   ├─ prepareSwitchTransition(plan.VLANs())          VALIDATE       → docs/switch/
   │    no side effects: switch mapping, provisioning VLAN present and
   │    distinct (the one fail-closed revert target), manager
   │    resolvable — the switch itself is never touched; skipped for a
   │    quarantine plan
   ├─ SDNEnrollmentHook.ActivateDevice(plan)         COMMIT SDN     → docs/sdn/
   │    atomically consumes the plan's reserved pending-activation
   │    version (a replaced record is refused with
   │    ErrPendingActivationSuperseded — nothing applied), applies the
   │    plan's policy and transitions the port to authorized; the
   │    physical port has NOT been opened yet, so a slow or failed
   │    policy application admits no traffic
   └─ commitSwitchTransition(...)  ⇒ pkg/switch Manager.SetPortVLAN → docs/switch/
        COMMIT the physical port strictly AFTER enforcement — the
        trusted VLAN opens only onto an enforced datapath; every VLAN
        comes from the plan's snapshot, value copies taken at precheck,
        immune to later in-place mutation (the pre-move VLAN is read
        for logging and the already-on-trusted WARN only); a failed
        move actively reverts to the provisioning VLAN and verifies by
        read-back — SDN authorized, physical port closed, activation
        reinstated for retry; on success FinalizeActivation releases the
        reservation
```

The handler holds only the HTTP binding: the SDN enrollment hook is the
single implementation of activation, and the flow is validate-then-commit
on one immutable plan — the outcome cannot diverge from what the precheck
reported, because the plan fixes the policy, and the physical port is
opened only after the SDN policy is applied and enforced, so no fail-open
interval exists. The hook's typed errors map to HTTP statuses — no pending
activation and a still-unregistered port return 404 at the precheck, with
nothing changed anywhere (the client retries after attaching to the
fabric); a plan carrying a zone mismatch means quarantine — the physical
port is never moved to the trusted VLAN and the response reports
`"status":"quarantined"`; a superseded plan is a 500 with the switch never
touched (the device re-enrolled mid-request; a retry prechecks the current
record); an SDN failure is a 500 with the switch never touched; a failed
physical commit after a successful SDN activation is a 500 with the SDN
side authorized, the physical port verified closed on the provisioning
VLAN, and the pending activation REINSTATED — the client retries the whole
activation without re-enrolling; any other failure is a 500, never
swallowed. A quarantine policy always carries the quarantine VLAN —
the profile's failure-network VLAN, or its provisioning VLAN when no
failure network is declared — and none of the production ACLs; a quarantine
that would share the trusted VLAN is a contradiction and a profile with
neither VLAN cannot be quarantined, so both fail activation closed (500) at
the precheck. The engine refuses a quarantine-zone policy outright when it
has no zone flow manager (`ErrZoneEnforcementUnavailable`): the VLAN-direct
fallback cannot enforce isolation, so instead of a silent downgrade the
activation is a hard failure (500, physical port reverted per the contract
above) — never `200 quarantined` with the OVS port open.

The response reports only what happened: `ActivateDevice` returns a typed
`ActivationResult` (status, port, VLAN, zone read from the policy the engine
applied), and the handler builds the response from it — so a quarantined
response carries the quarantine VLAN, never the trusted one. If the
quarantine policy was applied but the port could not be marked
`quarantined` in the state machine, the outcome is
`ErrQuarantineStateIndeterminate` (500, pending activation retained, the
datapath isolation left in place as the safe direction) — not a reported
quarantine.

The physical-switch failure contract is honest about SSH: the manager's
command sequences are not atomic, so a failed `SetPortVLAN` may still have
changed the VLAN. Fail-closed has exactly one meaning here — the
**provisioning VLAN** (`profile.provisioningNetwork.vlan`; a profile
without one refuses the physical move outright, and a profile whose
provisioning and trusted VLANs are equal is rejected at create/update on
every transport — HTTP 400 — and refused at activation — HTTP 500 —
because "closed" would otherwise mean "on the trusted VLAN"). On any switch
failure —
during the move or during a post-failure revert — the handler moves the
port to the provisioning VLAN and then **verifies by reading the port's
VLAN back**. Only a read-back showing the provisioning VLAN lets the plain
transition error (HTTP 500, port confirmed closed) stand. If the revert or
the read-back fails, or the read-back shows any other VLAN, the response is
HTTP 500 with `ErrSwitchPortIndeterminate` — "physical port state
INDETERMINATE — operator action required" — logged at ERROR, because the
port may remain open on the trusted VLAN. A pre-move read that finds the
port already on the trusted VLAN is logged at WARN: the port state machine
and switch reality diverged.

Activations are serialized per device serial by the hook's own lock
(`LockSerial`), which `OnEnrollmentComplete` also takes: a concurrent
activation for the same device cannot pass the precheck mid-sequence and
later revert the winner's VLAN move, and a concurrent re-enrollment waits
instead of replacing the pending activation between the precheck and its
consumption. The plan's atomic consume (`ErrPendingActivationSuperseded`)
backstops the lock: even a caller that skips `LockSerial` can never
activate a pending-activation version it did not validate.

Two details the legacy documentation had wrong and that matter operationally:

- The response field is **`trustedNetwork`**, not `production_network`. There
  are no `ProvisioningNetwork` / `ProductionNetwork` / `QuarantineNetwork`
  fields on `DeviceProfile`. The entity carries a
  `Networks map[string]*NetworkPhaseConfig` plus three name pointers —
  `EnrollmentNetwork` (default `"provisioning"`), `PostEnrollmentNetwork`
  (default `"trusted"`) and `FailureNetwork` (default `"quarantine"`).
- The switch name and port used by `prepareSwitchTransition` are read from the
  **request context**, not from the profile. `Device.SwitchName` and
  `Device.SwitchPort` exist on the device entity, but the activation handler
  does not read them from there. When either context value is absent the VLAN
  move is a deliberate no-op.

**Persistence.** Everything is stored through `quicbaas.Storage` under the
partition named by `device.DatastorePartition` (`"devices"`), sharded by
`Config.ShardID`. Nothing in this feature writes to the local filesystem.

## 5. Trust boundaries

**Device identity is a trust boundary.** Specifically:

1. **The EK certificate is the root of the pre-boot binding.**
   `DeviceProfile.EKCert` is validated once, at every write seam, by
   `entities.ParseEKCertPEM` / `ValidateEKCertPEM` — gRPC, REST, QUIC, MCP and
   CLI all funnel through it, so a malformed certificate is rejected with the
   same typed error everywhere rather than being stored and failing later at
   the one moment it is load-bearing. An unparseable certificate can never
   match a presented one, so it is rejected at the boundary, not at use.
2. **EK serial and MAC are not equivalent.** The serial is a decimal string
   compared case-insensitively; the certificate is a key. A deployment that
   sets only `EKSerial` has string-matched identity, not cryptographic
   identity. That is a supported configuration and it is weaker — say so in
   your threat model rather than assuming the EK path is in force.
3. **IDevID is the runtime credential.** `Device.Hostname` is documented as
   *"the IDevID common name (FQDN) recorded at enrollment"*, and
   `GET /api/v1/device/profile` and `POST /api/v1/device/activate` extract the
   serial from the **verified client certificate** through the mTLS middleware.
   A caller that cannot present an IDevID cannot reach either route. IDevID
   issuance itself is a separate feature.
4. **Boot-time config lookup is cross-tenant by design.** `FindConfigForDevice`
   searches every tenant. Tenant isolation for this one path is provided by the
   uniqueness of the EK serial / MAC, not by a tenant filter.
5. **The provisioning config-fetch routes are unauthenticated at the transport
   layer.** `pkg/webservice/v1/router/device.go` registers
   `/api/v1/provisioning/*` with the comment *"These routes are UNPROTECTED (no
   mTLS) since devices at boot have no client cert"* — they are EAB- and
   EK-authenticated at the application layer instead. Those routes belong to
   the config-delivery feature; they are named here because they sit on the
   same router and an operator reading firewall rules will see them adjacent to
   device routes.
6. **BMC credentials live inside the profile.** `DeviceProfile.BMC` carries
   `Username` and `Password`; the password field is tagged `secret:"true"` and
   the config-snapshot redactor (`pkg/config/snapshot.go`) hides keys
   containing `password`. Anyone who can read a profile in full can read a BMC
   credential — profile read access is BMC access.
7. **Violation severity drives enforcement.** `ViolationSeveritySevere` puts a
   port admin-down and the device in `suspended`; `ViolationSeverityWarning`
   moves it to the quarantine zone in `quarantined`. `ViolationEvent.Validate`
   rejects an unrecognised severity or source rather than defaulting to the
   lenient branch.

## 6. Failure posture

- Profile assignment **fails closed on identity**: `AssignToDeviceWithEK`
  returns `ErrDeviceIdentityRequired` when neither EK serial nor MAC is
  supplied. There is no "assign to whatever turns up".
- Config resolution **fails closed on a miss**: `FindConfigForDevice` returns
  `ErrNoMatchingConfig` rather than a default profile. A machine with no
  matching record gets nothing.
- Lifecycle transitions **fail closed on the table**: `CanTransitionTo` returns
  `ErrInvalidTransition` for any pair not in `allowedTransitions`, and
  `revoked` is terminal with no outgoing edges.
- The activation switch move **fails the request**, not just the log: a
  non-nil error from `prepareSwitchTransition` produces a 500 before the SDN
  policy step runs, and a non-nil error from `commitSwitchTransition` (which
  runs only after enforcement) produces a 500 with the physical port
  fail-closed.

## 7. What this feature deliberately does not do

- **It does not program the network.** `pkg/device/sdn_integration.go` declares
  the `SDNIntegration` interface, `NetworkEvent`, `NetworkPhase` and
  `NetworkEventContext` — the *contract* by which device lifecycle events reach
  a network controller. The device package contains **no implementation** of
  that interface. Bridges, ports, flows, VLANs and 802.1X port authentication
  are [`docs/sdn/`](../sdn/); physical switch ports are
  [`docs/switch/`](../switch/).
- **It does not verify attestation.** It stores `AttestPub`, `AttestCert`,
  `EKCert` and `EventLog` and it consumes a `ViolationEvent`. Deciding whether a quote is
  acceptable is [`docs/attestation/`](../attestation/).
- **It does not issue certificates.** The EK certificate is a vendor or CA
  artefact that is prestaged and compared. IDevID/LDevID issuance is a separate
  feature.
- **It does not deliver configuration to booting machines.** It resolves
  *which* config applies. The nonce, EAB authentication, EK binding and remote
  Secure Boot digest signing are `pkg/provisioning/configdelivery/`.
- **It does not power machines on.** BMC/Redfish/IPMI is
  [`docs/bmc/`](../bmc/); the profile only carries the connection settings.
- **It does not enforce tenancy on the boot-time lookup.** See §5.4.
- **It does not deduplicate profiles.** Two profiles may carry overlapping
  match rules; `FindMatchingProfile` returns the first hit in storage-iteration
  order and that order is not specified. Write disjoint rules.
- **It does not cache.** Every lookup goes to storage. There is no invalidation
  path because there is nothing to invalidate.

## 8. Related

- [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — transports, opcodes, authorization
- [`docs/sdn/`](../sdn/) — bridges, ports, flows, port authentication
- [`docs/switch/`](../switch/) — physical switch port operations
- [`docs/vtpm/`](../vtpm/) — vTPM bundles bound to a device profile
- [`docs/attestation/`](../attestation/) · [`docs/bmc/`](../bmc/)
