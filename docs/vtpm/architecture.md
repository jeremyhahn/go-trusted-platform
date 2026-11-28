# vTPM Architecture

> **Status: NORMATIVE** · Scope: `pkg/vtpm/`, `pkg/swtpm/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: architecture (this file) · [engineering.md](engineering.md) ·
> [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> **Verification scope.** Package layout, error set, RPC list, CLI flags and the
> transport matrix were checked against code on 2026-08-18. The narrative below
> predates the migration and was carried over.

## The problem

A VM that attests using the host's TPM is not attesting itself — every guest on
the machine produces the same evidence, and any one of them can exercise the
host's root of trust. Per-workload attestation needs per-workload hardware, and
there is no per-workload hardware.

## The shape chosen

**One swtpm instance per attestable VM**, packaged as a *bundle*: its own state
directory, NVRAM store and control socket, with a CA-issued EK certificate and
optionally enrolled UEFI Secure Boot keys.

Two nouns, kept apart throughout the API:

- **Template** — the specification (Secure Boot on/off, EK algorithm).
- **Bundle** — the instance, bound to a hostname.

`CloneTemplate` is the transition. Errors are per noun so a caller learns
immediately which one it named wrong.

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Share the host TPM with guests** | Every guest would produce identical evidence, per-VM attestation would be meaningless, and one compromised guest could use the host's root of trust. |
| **Generate the vTPM identity at first boot inside the guest** | The guest would author its own identity, which is exactly what attestation is supposed to make impossible. The EK and its certificate are created by the platform at bundle generation, before the guest exists. |
| **Bundle without an EK certificate** | An EK alone is a key nobody vouched for. Certificate injection is a distinct, separately-named step (`ErrEKCertInjectionFailed`) precisely because a bundle can otherwise have keys and still fail attestation for an unrelated-looking reason. |
| **Apply Secure Boot enrollment to a running vTPM** | Enrolled keys are part of a TPM's initial state. Doing it later would mean a vTPM whose measured history does not match its configuration. `--secure-boot` acts at generation and defaults to **true**. |
| **A single "TPM" abstraction with the hardware/software distinction hidden** | The failure modes are completely different — a missing character device, a stopped swtpm daemon, a path that is the wrong kind of file. `target.go` resolves explicitly and names each failure. |
| **Unary bundle export/import** | A bundle carries NVRAM and full TPM state; it does not fit a message. Export and import stream. |

## Component boundaries

| Piece | Package | Owner |
|---|---|---|
| Bundle and template service | `pkg/vtpm/service.go` | this repo |
| Bundle generation (EK, SRK, Secure Boot) | `pkg/vtpm/generator.go` | this repo |
| Export / import archives | `pkg/vtpm/archive.go` | this repo |
| NVRAM | `pkg/vtpm/nvram.go` | this repo |
| **TPM target resolution** | `pkg/vtpm/target.go`, `tpm_provider.go` | this repo |
| VM attestor device | `pkg/vtpm/vm_attestor_device.go` | this repo |
| swtpm process wrapper | `pkg/swtpm/` | this repo |
| **EK certificate issuance** | the CA, reached through the stack — [`docs/ca/`](../ca/) | **not this repo** |
| **Attestation verification** | `pkg/attestation/` — [`docs/attestation/`](../attestation/) | this repo, separate feature |
| **The VM a bundle belongs to** | `pkg/compute/` — [`docs/compute/`](../compute/) | this repo, separate feature |
| **Device profiles a bundle can be pre-assigned to** | `pkg/device/` — [`docs/device/`](../device/) | this repo, separate feature |

The §R capability row is the attestation row — *"TPM attestation of nodes and
workloads"*, Tier 1 — reached through `services/vtpm` alongside
`services/attestation` and `services/tpm`.

## Data flow — a VM getting its own root of trust

1. A **template** fixes the specification: EK algorithm, Secure Boot on or off.
2. `CloneTemplate` (or `CreateBundle`) generates a **bundle** for a named
   hostname: EK, SRK, EK certificate injected from the CA, Secure Boot keys
   enrolled.
3. `StartVTPM` runs an swtpm daemon; the bundle now has a live control socket.
4. `compute create --tpm` attaches that socket to the VM.
5. The guest boots and measures into **its own** PCRs.
6. `QuoteVTPM` produces evidence over those PCRs, which
   [`docs/attestation/`](../attestation/) verifies against policy — bound to the
   host's own attestation.

Steps 1–2 happen before the guest exists. That ordering is the security
property: the guest never participates in creating its own identity.

## Trust boundaries

1. **Guest → vTPM.** The guest can extend PCRs and ask for quotes. It cannot
   forge the EK or its certificate, because it did not create them.
2. **Platform → CA.** EK certificates are issued by the CA through the stack.
   A bundle whose certificate injection failed has an unvouched-for key.
3. **Bundle archive.** `ExportBundle` produces a file containing the VM's root
   of trust. Anyone holding it holds that identity — treat archives as key
   material.
4. **Hardware versus software TPM.** A software TPM satisfies the same
   interfaces and **is not equivalent as a trust root**. A deployment whose
   "TPM" resolves to swtpm on the host has software-rooted, not
   hardware-rooted, attestation.
5. **Sealed data.** `SealVTPM` with `--pcrs` binds a secret to measurements.
   The binding is the control; the auth value is a second one.

## What this feature deliberately does not do

- **It does not issue certificates.** The CA does; this feature injects.
- **It does not verify quotes against policy.** It produces them; attestation
  verifies them.
- **It does not create VMs.** Compute does, and attaches the socket.
- **It does not expose every runtime operation on every transport.** Get
  state, verify quote, get EK, get AK, create AK and get random are QUIC-only —
  recorded as a gap in [api.md](api.md) §4, not a decision. Start, stop,
  quote, seal, unseal and PCR access are on every transport.

## Overview

The vTPM service provides virtual TPM bundle management for VM provisioning. It creates complete swtpm state with CA-issued EK certificates and optional UEFI Secure Boot keys.

## Design Goals

1. **Pre-provisioned Identity** - Bundles include EK certificates before VM deployment
2. **Template Cloning** - Rapid provisioning from base images
3. **Secure Boot Integration** - UEFI key generation and enrollment
4. **Portability** - Export/import bundles between systems
5. **Integrity** - Checksum verification of bundle contents

## Unified Model: Bundle IS Instance

There is exactly one vTPM concern, expressed at two layers of the same
package:

| Layer | Type | Responsibility |
|-------|------|----------------|
| Primitive | `vtpm.VTPMService` (`pkg/vtpm/service.go`) | Canonical per-guest-VM swtpm storage and lifecycle: TPM state, OVMF NVRAM, Secure Boot keys, EK-cert injection, and the runtime TPM ops (start/stop/quote/seal/unseal/extend/read). A **Bundle** is the unit. |
| Facade | `vtpm.Generator` (`pkg/vtpm/generator.go`) | A profile-aware view over the same bundles: generate-for-profile, look up by device profile, export the EK certificate, and maintain the profile → bundle index. |

A **bundle** and an **instance** are the same object. Earlier revisions
shipped a separate `VTPMInstanceService` (proto service, REST `/instances/*`
router, JS `/instances/*` client, and Go `instance_client.go`) that was never
wired into the daemon and pointed at endpoints the backend never served. That
parallel surface was **collapsed into `VTPMService`**:

- The proto `service VTPMInstanceService` and its instance request/response
  messages were removed. There is now a single generated client.
- The profile facade is expressed as fields on the bundle surface rather than a
  second service:
  - `CreateBundleOptions.device_profile_id` binds a new bundle to a device
    profile (the profile-binding create path).
  - `ListBundleOptions.device_profile_id` filters bundles by profile (the
    profile-filtered list path), alongside the existing `limit`/`offset`
    pagination.
  - `Manifest.device_profile_id` records the binding at rest.
- All protocols (REST, gRPC, QUIC, MCP, Unix) expose the **same** bundle
  create/list/get plus the runtime TPM ops. The gRPC/Unix server delegates the
  runtime ops (`StartVTPM`/`StopVTPM`/`IsVTPMRunning`/`QuoteVTPM`/`SealVTPM`/
  `UnsealVTPM`/`ExtendVTPMPCR`/`ReadVTPMPCR`) to the same `vtpm.VTPMService`
  the REST/QUIC/MCP handlers use — closing a prior gap where the gRPC server
  returned `codes.Unimplemented` for those methods.

## Bundle Structure

```
/var/lib/trusted-platform/vtpm/
├── bundles/
│   └── {bundle-id}/
│       ├── manifest.json      # Bundle metadata
│       ├── tpm/
│       │   ├── tpm2-00.permall   # Persistent TPM state
│       │   ├── sealed/           # Blobs of the objects SealVTPM created
│       │   └── swtpm.sock        # Runtime socket (when running; see below)
│       ├── ovmf/
│       │   └── OVMF_VARS.fd      # UEFI NVRAM
│       └── secure-boot-keys/     # If Secure Boot enabled
│           ├── PK.key            # Platform Key
│           ├── PK.crt
│           ├── KEK.key           # Key Exchange Key
│           ├── KEK.crt
│           ├── DB.key            # Signature Database
│           └── DB.crt
└── templates/
    └── {template-id}/
        ├── tpm/
        │   └── tpm2-00.permall
        ├── ovmf/
        │   └── OVMF_VARS.fd
        └── secure-boot-keys/
            └── ...
```

## Bundle Modes

### Pre-Assigned Mode

Complete bundles with identity issued at creation time.

```
Create Bundle
     │
     ├─▶ Initialize swtpm
     │        │
     │        ├─▶ Create EK key pair
     │        │
     │        └─▶ Store EK certificate in NV RAM
     │
     ├─▶ Generate Secure Boot keys (if enabled)
     │        │
     │        ├─▶ Create PK, KEK, DB keys
     │        │
     │        └─▶ Enroll in OVMF NVRAM
     │
     └─▶ Create manifest with checksums
```

**Use Case:** Direct VM deployment where each VM needs immediate TPM identity.

### Template Mode

Base images without identity; EK certificate issued at clone time.

```
Create Template                Clone Template
     │                               │
     ├─▶ Initialize swtpm            ├─▶ Copy TPM state
     │   (no EK cert)                │
     │                               ├─▶ Copy OVMF NVRAM
     ├─▶ Generate Secure Boot        │
     │   keys (shared)               ├─▶ Copy Secure Boot keys
     │                               │
     └─▶ Create base state           ├─▶ Generate EK certificate
                                     │
                                     └─▶ Create manifest
```

**Use Case:** Fleet provisioning where VMs share common configuration but need unique identities.

## EK Certificate Provisioning

The service integrates with the platform CA to issue EK certificates.

### Certificate Flow

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   vTPM       │    │  Certificate │    │   swtpm      │
│   Service    │    │   Authority  │    │   State      │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                   │
       │  Initialize       │                   │
       ├───────────────────────────────────────▶
       │                   │                   │
       │  Create EK Key    │                   │
       │◀──────────────────────────────────────┤
       │                   │                   │
       │  Request Cert     │                   │
       ├──────────────────▶│                   │
       │                   │                   │
       │  Issue EK Cert    │                   │
       │◀──────────────────┤                   │
       │                   │                   │
       │  Store in NV RAM  │                   │
       ├───────────────────────────────────────▶
       │                   │                   │
```

"Create EK Key" is the go-xkms TPM provisioning flow on the bundle's fresh
swtpm: it creates and persists the EK, the shared SRK (`0x81000001`) and an
IAK (`0x81020001`). The IAK's common name is the bundle hostname; go-xkms
refuses to create an IAK without one. The EK public key sent to the CA is
read back from the persistent EK handle.

## Runtime: Start, Seal and Restart

- **Lifetime.** `Start` launches swtpm and returns; the daemon runs until
  `Stop`, not until the request that started it ends. swtpm listens in a short
  temporary directory when the bundle path would exceed the Unix socket path
  limit; `GetTPMSocketPath` reports the socket of the running instance.
- **First Start provisions.** A bundle created without EK-certificate
  injection (template mode, or no CA) has no persistent EK. Its first `Start`
  runs the same go-xkms provisioning flow as above (EK, SRK, IAK), because
  quote, seal and PCR extend need those keys. A later `Start` finds the
  persistent EK and does not provision again, so the keys survive a restart.
- **Start loads the IAK.** A `Start` that finds the vTPM provisioned (a bundle
  created with EK-certificate injection, or a restart) loads the IAK from
  `0x81020001`, which quote signs with. A provisioned vTPM with no IAK there
  is refused with `ErrVTPMAttestationKeyMissing` and does not start.
- **Sealed data.** go-xkms keeps the private and public blobs of a sealed
  object in `tpm/sealed/` of the bundle, through the SDK file key backend.
  `UnsealVTPM` after a restart reads them from there, and an exported bundle
  carries them.

### NV Index Locations

| Algorithm | NV Index | TCG Specification |
|-----------|----------|-------------------|
| RSA 2048 | 0x01C00002 | PC Client Platform TPM Profile |
| ECC P-256 | 0x01C0000A | PC Client Platform TPM Profile |

## Secure Boot Key Hierarchy

```
┌─────────────────────────────────────────────────────────────────┐
│                    Platform Key (PK)                            │
│                    Self-signed, top of chain                    │
└─────────────────────────────────┬───────────────────────────────┘
                                  │ signs
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Key Exchange Key (KEK)                         │
│                  Signed by PK                                   │
└─────────────────────────────────┬───────────────────────────────┘
                                  │ signs
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Signature Database (DB)                      │
│                    Signed by KEK                                │
│                    Signs bootloaders and kernels                │
└─────────────────────────────────────────────────────────────────┘
```

### Key Generation

```go
// Default configuration
SecureBootKeySize:      2048     // RSA key size
SecureBootValidYears:   10       // Certificate validity
SecureBootCommonName:   "Trusted Platform"
SecureBootOrganization: "Trusted Platform"
```

## Device-Profile Binding: Bundle → Generator → QEMU

The QEMU orchestrator (`pkg/compute/qemu.go`) provisions a VM from a
`*entities.DeviceProfile`. It reaches the vTPM subsystem **only** through the
`vtpm.Generator` facade so that every VM boots against a profile-bound,
CA-issued-EK bundle instead of an anonymous swtpm.

```
QEMUOrchestrator.Create(ctx, profile)
     │
     ├─▶ Generator.GetByProfile(ctx, profile.ID)
     │        │
     │        ├─ found ──▶ boot the VM against the prestaged bundle
     │        │            (SocketPath / NVRAMPath / bundle TPM state dir)
     │        │
     │        └─ ErrProfileNotAssociated
     │                 │
     │                 └─▶ Generator.GenerateForProfile(ctx, profile, opts)
     │                          ├─▶ CreateBundle(Mode=PreAssigned,
     │                          │        DeviceProfileID=profile.ID)
     │                          ├─▶ (CA configured) issue + inject EK cert
     │                          └─▶ (Secure Boot) enroll PK/KEK/DB in NVRAM
     │
     └─▶ swtpm points at the bundle's tpm/ state dir + swtpm.sock;
         QEMU attaches the socket + the bundle's OVMF_VARS.fd
```

A prestaged bundle is produced out-of-band by `platformctl vtpm create` or the
config-delivery EK-prestaging flow (which also writes the EK serial /
certificate back onto the device profile via the `ProfileAssigner`), so a VM's
identity can exist before the VM does.

### No-CA / attestation-disabled behavior

The generator is injected into the orchestrator via the compute `Deps`
(`pkg/compute/provider.go`) and the local-QEMU factory. Behavior when TPM is
enabled for the instance:

- **Generator present** — always route through it (`GetByProfile` →
  `GenerateForProfile`). This yields a profile-bound bundle in every case, and
  a CA-issued EK certificate whenever the vTPM service was constructed with a
  CA. This is strictly better than the previous anonymous swtpm.
- **Generator absent, and the profile requires a hardware-rooted identity** —
  the orchestrator fails closed with the typed
  `compute.ErrVTPMIdentityRequired`. A profile is treated as requiring a
  CA-issued identity when Secure Boot is enabled for the instance, or the
  profile carries a prestaged `EKCert` / `EKSerial`. The VM is **not** booted
  with an anonymous swtpm — silently degrading a profile's attestation contract
  is forbidden.
- **Generator absent, and the profile does not require an identity** — the
  orchestrator falls back to a local, identity-less swtpm so dev/test VMs stay
  bootable, and logs a loud warning that the VM has no CA-issued EK identity.
  This fallback is explicit and logged, never silent.

## Export Archive Format

Bundles are exported as gzip-compressed tar archives:

```
bundle-{id}.vtpm.tar.gz
├── manifest.json
├── tpm/
│   └── tpm2-00.permall
├── ovmf/
│   └── OVMF_VARS.fd
└── secure-boot-keys/     # If Secure Boot enabled
    ├── PK.key
    ├── PK.crt
    ├── KEK.key
    ├── KEK.crt
    ├── DB.key
    └── DB.crt
```

### Manifest Schema

```json
{
  "version": "1.0",
  "id": "vm001.example.com-1736937000000000000",
  "mode": "pre-assigned",
  "hostname": "vm001.example.com",
  "created_at": "2025-01-15T10:30:00Z",
  "device_profile_id": 4242,
  "ek_certificate": {
    "subject": "CN=vm001.example.com",
    "issuer": "CN=Trusted Platform CA",
    "serial_number": "1234567890",
    "not_before": "2025-01-15T10:30:00Z",
    "not_after": "2026-01-15T10:30:00Z",
    "fingerprint": "SHA256:AB:CD:EF:..."
  },
  "ek_algorithm": "RSA",
  "ek_handle": 29360130,
  "secure_boot_enabled": true,
  "secure_boot_keys": {
    "pk_fingerprint": "SHA256:...",
    "kek_fingerprint": "SHA256:...",
    "db_fingerprint": "SHA256:...",
    "owner_guid": "a0b1c2d3-e4f5-6789-abcd-ef0123456789"
  },
  "checksums": {
    "tpm/tpm2-00.permall": "e3b0c44298fc1c149afbf4c8996fb924...",
    "ovmf/OVMF_VARS.fd": "b94d27b9934d3e08a52e52d7da7dabfa..."
  },
  "labels": {
    "environment": "production"
  }
}
```

## VM Integration

### QEMU/KVM Attachment

```bash
# Start swtpm for bundle
swtpm socket \
  --tpmstate dir=/var/lib/trusted-platform/vtpm/bundles/{id}/tpm \
  --ctrl type=unixio,path=/var/lib/trusted-platform/vtpm/bundles/{id}/tpm/swtpm.sock \
  --tpm2

# Start VM with vTPM
qemu-system-x86_64 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
  -drive if=pflash,format=raw,file=/var/lib/trusted-platform/vtpm/bundles/{id}/ovmf/OVMF_VARS.fd \
  -chardev socket,id=chrtpm,path=/var/lib/trusted-platform/vtpm/bundles/{id}/tpm/swtpm.sock \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 \
  ...
```

### libvirt Integration

```xml
<domain type='kvm'>
  <tpm model='tpm-tis'>
    <backend type='emulator' version='2.0'>
      <source path='/var/lib/trusted-platform/vtpm/bundles/{id}/tpm'/>
    </backend>
  </tpm>
  <os firmware='efi'>
    <loader readonly='yes' type='pflash'>/usr/share/OVMF/OVMF_CODE_4M.secboot.fd</loader>
    <nvram>/var/lib/trusted-platform/vtpm/bundles/{id}/ovmf/OVMF_VARS.fd</nvram>
  </os>
</domain>
```

## Dependencies

| Component | Purpose |
|-----------|---------|
| `swtpm` | Software TPM implementation |
| `swtpm_setup` | TPM initialization tool |
| `OVMF` | UEFI firmware for VMs |
| `openssl` | Key and certificate generation |
| `sbsigntool` | Secure Boot signing (optional) |

## Security Considerations

### Key Protection

- Secure Boot private keys are stored unencrypted on disk
- Access should be restricted via filesystem permissions
- Consider HSM storage for production deployments

### EK Certificate Trust

- EK certificates are signed by the platform CA
- Verifiers must trust the CA chain
- Certificate revocation requires CRL distribution

### Bundle Integrity

- All files are checksummed in manifest
- Import validates checksums before extraction
- Export includes all required files

### Template Security

- Templates share Secure Boot keys across clones
- Each clone gets unique EK certificate
