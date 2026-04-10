# BMC Remote Attestation Architecture

Status: Draft (Phase 1 scaffolding)
Owner: pkg/bmc/attestation

## Goals

- Provide a single, vendor-neutral Go API for retrieving and verifying
  **BMC-level remote attestation evidence** across the server fleet.
- Produce `Evidence` blobs that higher-level services (compliance, audit,
  onboarding, continuous attestation) can store, compare, and policy-check
  without knowing vendor specifics.
- Ship a functional v0 Supermicro backend that wraps the vendor `sum` binary
  so that real lab-node-1..lab-node-5 hardware can be exercised immediately.
- Leave clean extension points for Dell iDRAC9 and HPE iLO5/6 backends.

## Non-goals

- **Not** host-side TPM attestation. That already lives in go-xkms / go-trusted-tpm2
  and is a different trust layer (runtime OS, not BMC).
- **Not** a full DICE / SPDM stack. DICE certificate chain parsing is a Phase 4+
  concern and will be a separate package once task #20 / task #47 land.
- **Not** Lenovo XCC. Out of scope for this platform.

## Supported vendors

| Vendor     | Phase | Mechanism                                                    |
|------------|-------|--------------------------------------------------------------|
| Supermicro | 1 v0  | Shell out to `sum` binary (SFT-DCMS-SINGLE license required) |
| Supermicro | 4     | Native Go reverse-engineered Attestation wire protocol       |
| Dell       | 2     | Redfish `Oem.Dell.Attestation` + TCG DICE endpoints (iDRAC9 4.40.40.00+) |
| HPE        | 3     | Redfish `Oem.Hpe.SecurityService` Silicon Root of Trust      |

## Package layout

```
pkg/bmc/attestation/
    doc.go
    evidence.go           // Evidence, EvidenceMetadata
    measurement.go        // Parsed Measurement
    policy.go             // Policy, Verifier
    compare.go            // CompareResult
    provider.go           // AttestationProvider interface
    errors.go             // Typed errors
    dispatch.go           // NewProvider(ctx, bmc.Client) -> AttestationProvider
    supermicro/
        doc.go
        sum_backend.go    // v0 shell-out backend
        sum_parse.go      // ANSI strip + table parsing
    dell/
        doc.go
        redfish_backend.go // stub, returns ErrNotImplemented
    hpe/
        doc.go
        ilo_backend.go    // stub, returns ErrNotImplemented
```

The top-level package owns only types and the dispatcher. Each vendor is a
subpackage so that concrete backends can grow without polluting the common
API surface and so that unused vendors can be omitted via build tags later if
desired.

## Core types

### Evidence

```go
type Evidence struct {
    Vendor    string            // "supermicro" | "dell" | "hpe"
    Action    string            // "dump" | "download" | ...
    ID        string            // vendor-specific evidence identifier (if any)
    Nonce     []byte            // caller-supplied freshness nonce
    CreatedAt time.Time
    Raw       []byte            // opaque vendor blob
    Metadata  map[string]string // vendor-specific, free-form
}
```

Evidence is **opaque**. Higher-level code should treat `Raw` as a sealed blob
to be stored verbatim and later fed back into `GetInfo` or `Compare`. The
vendor backend is the only code that understands the bytes.

### AttestationProvider interface

```go
type AttestationProvider interface {
    Dump(ctx context.Context, nonce []byte) (*Evidence, error)
    List(ctx context.Context) ([]EvidenceMetadata, error)
    Download(ctx context.Context, id string) (*Evidence, error)
    Delete(ctx context.Context, id string) error
    GetInfo(ctx context.Context, ev *Evidence) (*Measurement, error)
    Compare(ctx context.Context, live, ref *Evidence) (*CompareResult, error)
}
```

The method names mirror the Supermicro `sum Attestation --action=<verb>`
verbs intentionally: those verbs are a superset of what Dell and HPE expose,
so vendor backends can map their narrower APIs onto the interface without the
interface leaking Supermicro-isms.

### Measurement

Parsed view of an Evidence blob: cert chain (x509), optional PCR digest
bank, timestamp, nonce echo, and vendor-specific key/value pairs. Populated
by `GetInfo`. Not all fields are required for all vendors.

### Policy / Verifier

```go
type Verifier interface {
    Verify(ctx context.Context, ev *Evidence, pol *Policy) (*VerifyResult, error)
}
```

A `Policy` is a simple declarative set of rules (allowed vendors, required
nonce echo, trusted cert issuers, optional reference Evidence for compare).
Verifier is a separate interface from AttestationProvider so that verification
can run offline in a dedicated appraisal service.

## Vendor detection and dispatch

`NewProvider(ctx, bmc.Client)` calls `GetSystemInfo`, reads the
`Manufacturer` string, and returns the matching backend. Detection rules:

- `supermicro`, `super micro` -> Supermicro (SUM backend)
- `dell`                      -> Dell iDRAC stub
- `hpe`, `hewlett`            -> HPE iLO stub
- anything else               -> `ErrUnsupportedVendor`

Manufacturer string matching is case-insensitive and trimmed. This keeps the
dispatcher aligned with `pkg/bmc.SystemInfo.Manufacturer`, which is the
existing source of truth from Redfish/FRU.

## Relationship to existing TPM attestation (go-xkms)

The BMC attestation layer is **complementary** to host-side TPM attestation:

- go-xkms / go-trusted-tpm2: attests the **host runtime** — UEFI, shim, kernel,
  initrd, and userspace measurements bound to a host TPM AK.
- pkg/bmc/attestation: attests the **BMC itself and its silicon root of trust**,
  answering "is this BMC genuine and uncompromised before I trust anything it
  reports about the host?"

Both emit evidence; a higher-level composite attestation service will consume
both and evaluate a combined policy. That composite service is out of scope
here — we only produce the BMC half.

## Relationship to task #47 and future DICE work

Task #47 (vendor quirks abstraction) and task #20 (DICE) will need a place to
plug parsed cert chains and measurement banks. `Measurement` is intentionally
a loose bag today; when task #20 lands, it gains a typed `DICEChain` field and
a `DICEVerifier` is added. No interface changes expected.

## Test strategy

- **Unit tests** (this task): fake `sum` binary as a shell script in a
  temp dir, pointed at via `SUPERMICRO_SUM_BINARY`. Verifies argument
  construction, stdout parsing, ANSI stripping, error propagation. No real
  BMC involvement.
- **Integration tests** (future, `//go:build integration`): under
  `test/integration/bmc_attestation/` against real lab-node-1 hardware in the
  lab, exercising Dump -> Download -> Compare round-trip.
- **Multi-protocol adapter tests** (future): once a `platformctl bmc
  attestation` CLI exists, reuse the standard 6-adapter pattern from
  `test/integration/kms/`.

## Known unknowns

- The Supermicro SUM `Attestation` wire protocol is **not publicly
  documented**. v0 shells out to the proprietary binary. A native Go
  implementation requires packet-capture-based reverse engineering of the
  SUM <-> BMC traffic and is explicitly Phase 4.
- Dell iDRAC9 Attestation requires firmware 4.40.40.00 or newer. Older
  firmware must surface a clear `ErrAttestationFailed` with an upgrade hint.
- HPE iLO5 vs iLO6 expose different SRoT endpoints; the Phase 3 backend
  will need a runtime sub-variant check.
- `sum` exit codes are not fully enumerated in vendor docs — v0 maps known
  codes and wraps unknown non-zero exits in `ErrAttestationFailed`.

## Implementation phases

1. **Phase 1 (this task)**: interfaces + Supermicro v0 SUM shell-out +
   Dell/HPE stubs + unit tests. No CLI.
2. **Phase 2**: Dell iDRAC9 native Redfish backend, integration test on R640.
3. **Phase 3**: HPE iLO5/6 native Redfish backend.
4. **Phase 4**: Supermicro native Go backend (retires SUM dependency).
5. **Phase 5**: Composite attestation service combining BMC + host TPM
   evidence under a single appraisal policy.

## 2026-04-08 status update — DEFERRED

After an empirical hardware survey, all three vendor backends in the
bmc-attestation package are marked **deferred until RoT-capable
hardware is available**. None of the currently-owned lab hardware can
produce real attestation evidence, which makes integration testing —
the only meaningful validation for this code — impossible.

### Hardware survey results

| Vendor | Platform | Result | Evidence |
|---|---|---|---|
| Supermicro | X10SDV-TP8F (lab-node-1..05) | ❌ | `sum ... -c Attestation --action List` returned "Remote Attestation is not supported on this platform" (error 609.100) even with SFT-DCMS-SINGLE + SFT-SDDC-SINGLE activated. Strings in sum 2.14.0 confirm: "Support only on RoT system of X12 and later platforms." |
| Dell | PowerEdge R640 14G, iDRAC9 FW 7.00.00.183 | ❌ | `/redfish/v1/ComponentsIntegrity` returns 404. `DellAttestationService` returns 404. `TrustedComponents` on `Chassis/System.Embedded.1` returns 404. `DellLCService` exposes 30+ actions, none attestation-related. 14G hardware has Silicon Root of Trust at boot verification time but no exposed attestation API; Dell shipped real attestation surface starting 15G and completed the schema in 16G. |
| HPE | none owned | N/A | No hardware to test against. Specs suggest iLO6 (Gen11) is the best-supported target for DMTF Redfish ComponentIntegrity + SPDM when hardware arrives. |

### Scaffold disposition

The package scaffold is preserved:

- `attestation.AttestationProvider` interface, Evidence type, Policy,
  Measurement, CompareResult, typed errors, dispatch registry.
- `attestation/dell/` returns `ErrNotImplemented` per method (the code
  isn't written; hardware gap would be handled at implementation time).
- `attestation/hpe/` returns `ErrNotImplemented` per method.
- `attestation/supermicro/` returns `ErrAttestationUnsupported` per
  method. Semantically stronger than `ErrNotImplemented` because the
  X10 silicon cannot be unblocked by any amount of software work.

No shell-out wrappers exist anywhere in the tree. The interim v0
Supermicro SUM-shell backend was deleted on 2026-04-08 — it couldn't
be tested against our X10 fleet (SUM refuses the platform check) and
the user explicitly rejected the "shell wrapper" approach.

### Revival conditions

This package becomes active again when any of the following happens:

1. The project acquires X12/X13+ Supermicro hardware with a Silicon
   Root of Trust chip. Phase 4 (native Supermicro Go backend) becomes
   first-class work. Start with tcpdump capture against SUM Attestation
   for wire protocol reverse engineering.
2. The project acquires Dell 15G (R650/R750) or 16G (R660/R760)
   hardware with iDRAC9 firmware 5.x+. Phase 2 (Dell Redfish) becomes
   first-class work. Start from Dell's published OEM schemas — no RE
   needed.
3. The project acquires HPE Gen11 (ProLiant DL360/380 Gen11) hardware
   with iLO6. Phase 3 (HPE Redfish) becomes first-class work. HPE has
   the best public DMTF Redfish ComponentIntegrity + SPDM support of
   the three vendors and is the recommended first concrete backend
   once hardware exists to test against.

### What covers the trust gap in the meantime

Host-side TPM 2.0 attestation via go-xkms is already implemented and
works on every box in the fleet (all 5 mini-0x Supermicro units have
an Infineon SLB9665 TPM 2.0, the R640 reports a TPM 2.0 via
`Systems/System.Embedded.1.TrustedModules`). The existing
`pkg/api/daemon/tpm_grpc_service.go` wraps the comprehensive xkms
`TPM2.Info()` report, and sealed LUKS key unlocking uses the
xkms-managed PlatformSRK. This covers the host runtime trust path;
BMC-layer attestation would have added pre-boot + silicon-chain-of-
custody evidence that X10 + R640 14G simply cannot produce.
