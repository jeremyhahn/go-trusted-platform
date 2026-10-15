# Device Identity (IDevID/IAK/LDevID) Design

> **Status: REFERENCE** · Last verified: 2026-10-15
> Design notes for IDevID, IAK and LDevID. The contract is [api.md](api.md) §8.

## Overview

This document describes the architecture and implementation of TPM-based Device Identity using IDevID (Initial Device Identifier) and IAK (Initial Attestation Key) certificates per TCG specifications, plus the CA-issued LDevID (Local Device Identifier) per IEEE 802.1AR. Device identity provides a cryptographically-bound, manufacturer-issued identity for secure device authentication and attestation.

## References

- TCG TPM 2.0 Keys for Device Identity and Attestation
- TCG Infrastructure Working Group - Device Identifier Composition Engine
- RFC 8995 - Bootstrapping Remote Secure Key Infrastructure (BRSKI)
- IETF ACME Device Attestation (draft-acme-device-attest)

## Architecture Overview

```
+------------------------------------------------------------------+
|                        Device Identity Flow                        |
+------------------------------------------------------------------+
|                                                                    |
|  +-------------+     +----------------+     +------------------+  |
|  |   Device    |     |   IDevID/IAK   |     |       CA         |  |
|  |   (TPM)     |     |   Service      |     |   (go-xkms CA)   |  |
|  +------+------+     +-------+--------+     +---------+--------+  |
|         |                    |                        |           |
|         |  1. Generate Keys  |                        |           |
|         |<-------------------|                        |           |
|         |                    |                        |           |
|         |  2. Create CSR     |                        |           |
|         |<-------------------|                        |           |
|         |    (TCG Profile)   |                        |           |
|         |                    |                        |           |
|         |                    |  3. Submit CSR         |           |
|         |                    |----------------------->|           |
|         |                    |                        |           |
|         |                    |  4. Verify TPM         |           |
|         |                    |<-----------------------|           |
|         |                    |  (ActivateCredential)  |           |
|         |                    |                        |           |
|         |  5. Decrypt Secret |                        |           |
|         |<-------------------|                        |           |
|         |                    |                        |           |
|         |                    |  6. Return Secret      |           |
|         |                    |----------------------->|           |
|         |                    |                        |           |
|         |                    |  7. Issue Certificate  |           |
|         |                    |<-----------------------|           |
|         |                    |                        |           |
|         |  8. Install Cert   |                        |           |
|         |<-------------------|                        |           |
|         |                    |                        |           |
+------------------------------------------------------------------+
```

> **Note**: The CA above is the go-xkms CA/ACME engine, consumed by
> go-trusted-platform through the go-quicbaas SDK (`Security().ACME()` /
> `Security().Certificate()`). go-trusted-ca has been decommissioned; the
> platform never imports it directly.

## Key Types and Hierarchy

### TPM Key Hierarchy

The TCG device identity model places the keys as follows:

```
Endorsement Hierarchy (EH)
|
+-- EK (Endorsement Key)
|   +-- Restricted, decrypt-only
|   +-- Unique to each TPM
|   +-- Certified by TPM manufacturer
|
+-- IDevID (Initial Device Identifier)
|   +-- Sign-only, non-restricted
|   +-- Used for device authentication
|
+-- IAK (Initial Attestation Key)
    +-- Restricted signing key
    +-- Used for TPM quotes/attestation

Owner Hierarchy (OH)
|
+-- SSRK / Platform SRK
    +-- Parents for sealed objects and application keys
```

The keys are created by the go-xkms TPM backend, reached through the
go-quicbaas SDK re-exports; the platform supplies the configuration.

### Shipped Key Configuration

From `configs/platform/templates/single-node/default.yaml` (`tpm:`):

| Key | Config | Handle | Algorithm | Signature |
|-----|--------|--------|-----------|-----------|
| IAK | `tpm.iak` | `0x81010002` | RSA-2048 | SHA256-RSA |
| IDevID | `tpm.idevid` | `0x81020000` | RSA-2048 | SHA256-RSA |
| LDevID | request field | `0x81010102` (default) | ECDSA-P256 (default) | - |

The IDevID config also carries the `model` and `serial` used in the device
identity (`control-plane`, `tp-cp-01` in the shipped file). The LDevID default
handle is `defaultLDevIDHandle` in `pkg/api/daemon/idevid_ldevid.go`.

## Key Generation and CSRs

`IDevIDService` (`pkg/api/daemon/idevid_grpc_service.go`) exposes the device
identity operations:

| RPC | CLI |
|-----|-----|
| `GenerateIDevID`, `GenerateIAK` | `platformctl tpm idevid generate`, `platformctl tpm iak generate` |
| `GetIDevIDInfo`, `GetIAKInfo` | `platformctl tpm idevid info`, `platformctl tpm iak info` |
| `CreateIDevIDCSR`, `CreateIAKCSR` | `platformctl tpm idevid csr`, `platformctl tpm iak csr` |
| `InstallIDevIDCertificate`, `InstallIAKCertificate` | `platformctl tpm idevid install`, `platformctl tpm iak install` |
| `GetIDevIDCertificate`, `GetIAKCertificate` | `platformctl tpm idevid certificate`, `platformctl tpm iak certificate` |
| `DeleteIDevID`, `DeleteIAK` | `platformctl tpm idevid delete`, `platformctl tpm iak delete` (refused: the key is not evicted) |
| `GetDeviceAttributes` | `platformctl tpm device attributes` |
| `ActivateCredential` | - |

The TCG-CSR-IDEVID itself (IAK public area, IDevID CSR, EK certificate) is built
in go-xkms; see [Attestation](attestation.md#tcg-csr-idevid-structure).

## Certificate Installation

`InstallIDevIDCertificate` parses the PEM and hands the certificate to the TPM
backend (`ProvisionIDevIDCert`); empty or malformed PEM is `InvalidArgument`.
The shipped `tpm.idevid.cert-handle` (`0x01C90000`) and `tpm.iak.cert-handle`
are not used today: both are cleared at startup
(`applyCertHandleNVInterim`, `pkg/app/tpm_cert_nv.go`); see
[Configuration](configuration.md).

## Integration with the CA

Device identity certificates are issued by the go-xkms CA/ACME engine through
the go-quicbaas SDK (see the note under Architecture Overview). The platform
defines no CA interface of its own for device identity; the TPM binding check
(credential activation) is part of the enroll-01 challenge.

## LDevID (IEEE 802.1AR Local Device Identifier)

### IDevID vs LDevID

IDevID and LDevID are the two halves of the IEEE 802.1AR device identity model:

| Property | IDevID (birth identity) | LDevID (operational identity) |
|----------|-------------------------|-------------------------------|
| Lifetime | Permanent, created once | Rotatable, many over device life |
| Issued by | Manufacturer / enrollment CA via the TCG-CSR ceremony (endorse-01 / enroll-01) | The **platform CA** the device already trusts |
| Wire format | TCG-CSR (TPM-attested) | Standard PKCS#10 CSR |
| TPM key | IDevID key at `0x81010100` (+ IAK `0x81010101`) | Dedicated LDevID key at `0x81010102`, distinct from the birth keys |
| Cardinality | Exactly one | Zero-or-more |
| Precondition | EK attestation | **A proven IDevID** |

An IDevID is the device's cryptographic birth certificate; an LDevID is a
locally significant, CA-issued, rotatable identity layered on top of it (for
example, a per-deployment or per-tenant operational certificate).

### CreateLDevID Flow

`IDevIDService.CreateLDevID` provisions an LDevID in a single call:

1. **Gate on a proven IDevID.** The service refuses issuance
   (`FailedPrecondition`, typed `ErrIDevIDNotEnrolled`) unless the device has a
   currently-valid IDevID certificate installed. That certificate is the
   on-device materialization of a successful enroll-01 / endorse-01 attestation
   — the CA only issues it after verifying the device's attestation manifest —
   so its presence is proof the IDevID was enrolled.
2. **Create the LDevID key.** A dedicated TPM-resident signing key is created as
   a child of the platform key store SRK, using the existing TPM key management
   (`LDevIDAttributesFromConfig` + `CreateECDSA` / `CreateRSA`). It works
   identically on a hardware TPM and swtpm via the `TrustedPlatformModule`
   abstraction. The key is distinct from the IDevID and IAK birth keys.
3. **Build a PKCS#10 CSR.** A standard `x509.CertificateRequest` is signed by the
   TPM-resident LDevID key (the private key never leaves the TPM).
4. **Issue from the platform CA.** The CSR is signed by the same platform CA seam
   used elsewhere (`config.CAService.SignCSR`, reached through the quicbaas SDK),
   honoring the requested profile and validity.

The response carries the PKCS#10 CSR, the issued certificate (PEM), and parsed
certificate metadata (`KeyType = "LDevID"`, TPM handle `0x81010102`).

`CreateLDevIDRequest` fields: `template` (subject / SANs), `algorithm`
(default ECDSA P-256), `handle` (default `0x81010102`), `profile`,
`validity_days`, and `overwrite`.

### Multi-Protocol Surface

`CreateLDevID` is exposed over **every** platform transport. All of them are thin
wire adapters that delegate to the one shared `IDevIDGRPCService.CreateLDevID`
built by the daemon (TPM key + IAK-derived birth gate + CSR + platform-CA
issuance live there exactly once — no transport re-implements the LDevID flow):

| Transport | Entry point | Wiring |
|-----------|-------------|--------|
| gRPC / Unix | `platform.v1.IDevIDService/CreateLDevID` | `IDevIDGRPCService` registered on both servers |
| Embedded | dispatch table method | in-process call into `IDevIDGRPCService` |
| REST | `POST /api/v1/idevid/ldevid` | `RESTServer.handleLDevIDCreate` → shared service |
| QUIC | `OpTPM2Category` (0x99), sub-opcode `SubOpTPM2LDevIDCSR` (0x1D) | `handleTPM2Category` intercepts the LDevID sub-opcode → `handleLDevIDCreate` → shared service |
| MCP | tool `idevid_create_ldevid` | `MCPServiceProvider.CreateLDevID` → shared service |
| CLI | `platformctl tpm idevid ldevid create` | Go SDK `idevid.Client.CreateLDevID` over any transport |

Wire contract:

- **REST** bodies are the JSON encodings of the pb `CreateLDevIDRequest` /
  `CreateLDevIDResponse` messages (snake_case fields; `csr_pem` /
  `certificate_pem` are base64 per pb `bytes`), so a REST-transport SDK client
  and the daemon handler are byte-symmetric.
- **QUIC** reuses the physical-TPM category opcode because the single-byte QUIC
  opcode namespace is fully allocated; the LDevID request/response are the pb
  messages encoded by the protocol codec **by their Go field names**, framed as
  `payload = [0x1D] + codec(CreateLDevIDRequest)`.
- **MCP** arguments mirror the pb field names (`template`, `algorithm`,
  `handle`, `profile`, `validity_days`, `overwrite`); the tool returns the pb
  response as JSON.

The `gRPC → transport` routing tables live in the SDK adapters
(`sdk/go/transport/{rest,quic,mcp}`), so `idevid.Client.CreateLDevID` works
unchanged across every protocol.

CLI (`platformctl tpm idevid ldevid create`) flags:
`--common-name` / `--organization` / `--organizational-unit` / `--country` /
`--state` / `--locality` (subject template), `--algorithm`, `--handle`,
`--profile`, `--validity-days`, `--overwrite`, and `--out` (writes the issued
certificate PEM to the path and the CSR to `<out>.csr`).

## ACME enroll-01 Challenge Flow

enroll-01 is implemented. A device runs it with `platformctl tpm enroll`
(`pkg/cli/commands/tpm/enroll.go`); the daemon registers the `enroll-01`
verifier in `pkg/daemon/commands/serve.go`. The flow, the TCG-CSR-IDEVID
structure and credential activation are described in
[Attestation](attestation.md#idevid-attestation-via-acme-enroll-01).

## Security Considerations

### Key Protection

1. IDevID and IAK keys are generated inside TPM
2. Private keys never leave the TPM
3. Keys are bound to specific TPM instance via FixedTPM attribute
4. Keys are protected by TPM hierarchy authorization

### Certificate Validation

1. CA must verify TPM binding via ActivateCredential
2. EK certificate chain must be validated to TPM manufacturer
3. Platform binding should be verified against SMBIOS data

### Storage Security

1. Certificates are installed through the TPM backend; the NV cert handles are
   not used today (see Certificate Installation)
2. Certificate chain should be validated on use

## Code Locations

```
pkg/api/daemon/idevid_grpc_service.go   - IDevIDService (IDevID, IAK, CSRs, certificates)
pkg/api/daemon/idevid_ldevid.go         - CreateLDevID
pkg/api/daemon/rest_idevid_ldevid.go    - REST POST /api/v1/idevid/ldevid
pkg/api/daemon/quic_idevid_ldevid.go    - QUIC LDevID sub-opcode
pkg/api/mcp/ldevid_tools.go             - MCP idevid_create_ldevid
pkg/cli/commands/tpm/idevid.go          - platformctl tpm idevid
pkg/cli/commands/tpm/iak.go             - platformctl tpm iak
pkg/cli/commands/tpm/ldevid.go          - platformctl tpm idevid ldevid
pkg/cli/commands/tpm/enroll.go          - platformctl tpm enroll
```
