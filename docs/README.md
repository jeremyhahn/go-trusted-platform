# go-trusted-platform Documentation

> **Status: NORMATIVE** · Scope: go-trusted-platform `docs/` index · Last verified: 2026-10-13
> Conflicts with this document are defects. Fix them here first.

> Complete documentation for the Zero-Trust Trusted Computing Platform

## Feature folders — start here

Documentation uses the five-file feature-folder layout defined by
`../handbook/software/conventions/feature-docs.md` (ratified 2026-08-19). Each
feature has:

```
docs/<feature>/
    architecture.md   design, boundaries, rejected alternatives, trust boundaries
    engineering.md    the implementation contract an agent works from
    cli.md            every verb and flag
    api.md            every capability on all six transports, gaps included
    user.md           task-oriented usage
```

A gap row in an `api.md` is written `MISSING — docs/13 G<n>` (the form the
handbook's `feature-docs.md` mandates). `docs/13` is the portfolio's SDK
exposure-gaps register, which lives in the handbook, not in this repository:
[`../../handbook/software/docs/13-sdk-exposure-gaps.md`](../../handbook/software/docs/13-sdk-exposure-gaps.md)
(`~/sources/handbook/...` on a host, `/workspace/handbook/...` in a container).
`G7` is the go-trusted-platform re-export gap.

**The folder is the requirements contract**, not commentary. Read it before the
code, and change it in the same PR as the behavior.

### Converted — every feature (38)

| Feature | What it covers |
|---|---|
| [attestation/](attestation/) | TPM attestation of hosts, VMs and containers |
| [auth/](auth/) | Platform authentication — mTLS identity extraction and the per-transport auth seams |
| [barrier/](barrier/) | The platform barrier — init, Shamir, unseal, seal, rekey, recovery — and the `platformd` start-up gate |
| [bmc/](bmc/) | Baseboard management — IPMI, Redfish, vendor quirks |
| [bootstrap/](bootstrap/) | Trust bootstrap, day-zero orchestration, first boot |
| [ca/](ca/) | Certificate authority and ACME (re-export frontage) |
| [cluster/](cluster/) | This repo's half of clustering (consensus itself is owned below) |
| [compute/](compute/) | VM and container orchestration |
| [daemon/](daemon/) | The six binaries, the multi-protocol API server — **and the canonical QUIC opcode and authorization reference** |
| [device/](device/) | Device profiles, identity and inventory |
| [dht/](dht/) | **PLANNED** — the P2P/DHT network, design only, no implementation |
| [dns/](dns/) | Authoritative DNS and DNSSEC |
| [eab/](eab/) | ACME External Account Binding |
| [factory-image/](factory-image/) | Factory disk images — Raspberry Pi, QEMU virt, U-Boot (`platformctl diskimage`) |
| [firmware/](firmware/) | UEFI, Secure Boot, UKI, Authenticode, module signing |
| [gateway/](gateway/) | `gatewayd` edge services and the trusted reverse proxy |
| [health/](health/) | Liveness, readiness and component health |
| [iam/](iam/) | Identity and access management (re-export frontage) |
| [ima/](ima/) | Linux IMA measurement and appraisal |
| [installer/](installer/) | Installer, initrd, ISO building, boot-time unlock |
| [ipxe/](ipxe/) | The PXE/iPXE boot server |
| [kms/](kms/) | Key management (re-export frontage) |
| [luks/](luks/) | Runtime LUKS2 key-slot management (`platformctl luks`) |
| [ntp/](ntp/) | Time synchronisation |
| [provisioning/](provisioning/) | Zero-touch provisioning, PXE, installer |
| [proxy/](proxy/) | The trusted reverse proxy engine and proxy authorization |
| [registry/](registry/) | Attestation-gated OCI registry |
| [sdk/](sdk/) | The Go SDK (`sdk/go`) — the client `platformctl` uses to reach `platformd` |
| [sdn/](sdn/) | Bridges, ports, flows, port authentication, overlay |
| [secrets/](secrets/) | Secret-reference resolution |
| [security/](security/) | Rate limiting, input validation, embedded OPA policy |
| [switch/](switch/) | Managed switch provisioning and vendor drivers |
| [tenant/](tenant/) | Platform tenancy |
| [tpm/](tpm/) | This repo's use of TPM 2.0 (the hardware crypto itself is owned below) |
| [trust/](trust/) | Platform trust anchor (the platform CA) and the `trust.bootstrap` / `trust.bmc` resolver |
| [vpn/](vpn/) | **DESIGN** — attested remote-access VPN (identity, attestation, posture, MFA gate; WireGuard / MASQUE), not implemented |
| [vtpm/](vtpm/) | Virtual TPM bundles and templates |
| [web/](web/) | The web server, embedded assets and the control panel |

**[daemon/api.md](daemon/api.md) is the cross-cutting reference**: the six
transports, the QUIC category-opcode table, and the platform-wide authorization
picture. Other feature folders link to it rather than repeating it.

### The remaining directories are not features

`api/`, `architecture/`, `archive/`, `assets/`, `cli/`, `configuration/`,
`man/`, `operations/`, `plans/`, `reference/`, `roadmap/`, `test/` and
`testing/` are cross-cutting sections and collections, not capabilities, so the
five-file layout does not apply to them. They still predate the convention and
their shape is **not a precedent** (feature-docs.md §8): do not add a file in the
old shape, and do not cite them when converting something else.

Legacy files inside a converted feature folder are kept and linked where they
still carry content. The five files are canonical; where a legacy file
contradicts them, the five files win.

Conversion state is derivable — `ls docs/*/architecture.md` — so no scoreboard
is maintained.

## Quick Links

- [Roadmap](../ROADMAP.md) - What is complete and what remains to the release candidate
- [Build Guide](BUILD.md) - Building from source

---

## Getting Started

### Platform Initialization

Initialize the platform on first start:

```bash
# Initialize and provision the platform, then keep running
sudo ./platformd --init --debug --platform-dir trusted-data
```

Configuration options (persistent flags of `platformd`, `pkg/daemon/commands/root.go`):

| Flag | Default | Description |
|------|---------|-------------|
| `--init` | `false` | Initialize and provision the platform |
| `--platform-dir` | `<working dir>/trusted-data` | Platform data directory |
| `--config-dir` | `/etc/trusted-platform` | Configuration file directory |
| `--config`, `-c` | — | Path to a specific config file (overrides `--config-dir`) |
| `--env`, `-e` | `dev` | Runtime environment (dev, staging, prod) |
| `--debug`, `-d` | `false` | Enable debug mode |

### Starting Services

```bash
# Serve every transport, with mutual TLS on REST
sudo ./platformd serve --enable-mtls

# Check the daemon from the CLI
platformctl status
```

### Quick Example: VM with a vTPM

```bash
# Create a VM with a virtual TPM on a bridge and start it
platformctl compute create --name test-vm --cpus 2 --memory 4096 --tpm --network-bridge br0 --start
platformctl compute get test-vm
```

---

## Table of Contents

### Core Platform

| Component | Description |
|-----------|-------------|
| [Architecture](architecture/) | System design, binary separation, security model |
| [Certificate Authority](ca/) | X.509 PKI, ACME server/client, certificate lifecycle |
| [Key Management](kms/) | Multi-backend KMS with TPM, HSM, and cloud support |
| [TPM 2.0](tpm/) | Hardware security with multi-protocol API (REST, gRPC, QUIC, MCP, Unix) |
| [IMA](ima/) | Linux Integrity Measurement Architecture, PCR 10 |
| [IAM](iam/) | Identity, authentication, authorization, WebAuthn |

### Networking & SDN

| Component | Description |
|-----------|-------------|
| [SDN Controller](sdn/) | OVS, OpenFlow, 802.1X port authentication |
| [DNS Server](dns/) | Authoritative DNS with DNSSEC and DANE |
| [Security](security/) | Protected memory (`MemoryEnclave`), rate limiting, input validation, embedded OPA policy |

### Compute & Orchestration

| Component | Description |
|-----------|-------------|
| [Compute](compute/) | VM orchestration with QEMU/KVM and vTPM |
| [Attestation](attestation/) | Workload attestation from bare metal to containers |
| [Firmware](firmware/) | UEFI Secure Boot, UKI, Authenticode, module signing, AVR attestation |
| [Virtual TPM](vtpm/) | Software TPM for development and testing |

### Infrastructure

| Component | Description |
|-----------|-------------|
| [Cluster](cluster/) | High availability with Raft consensus |
| [Tenant](tenant/) | Multi-tenancy: quotas, keyspace and DEK isolation |
| [Health](health/) | Health checks and Prometheus metrics |
| [Provisioning](provisioning/) | Device enrollment and configuration |
| [Device](device/) | Device profiles and network phases |
| [Barrier](barrier/) | The platform barrier lifecycle, the start-up gate and `platformctl barrier` |
| [Secrets Management](secrets/) | Credential and key lifecycle management |
| [Registry](registry/) | Container and artifact registry with attestation |

### Distributed Systems

| Component | Description |
|-----------|-------------|
| [DHT](dht/) | *Planned* - Distributed hash table, cryptocurrency, content sharing |

### Developer Resources

| Component | Description |
|-----------|-------------|
| [JavaScript SDK](api/sdk-javascript.md) | TypeScript SDK for web applications |
| [API Reference](api/) | Multi-protocol API docs: REST, gRPC, QUIC, MCP, Unix Socket |
| [CLI Reference](daemon/cli.md) | `platformctl` global flags and command tree; the six binaries |
| [Man Pages](man/) | Unix manual pages |
| [Operations](operations/) | Monitoring, troubleshooting, and maintenance |
| [Web UI](web/) | Platform management dashboard and admin interface |

### Deployment

| Component | Description |
|-----------|-------------|
| [Installer](installer/) | ISO installer and deployment options |
| [iPXE](ipxe/) | Network boot configuration |

---

## Key Documents

- [802.1X Authentication](sdn/802.1x.md) - Certificate-based network access
- [Reference Architecture](architecture/reference.md) - IoT hybrid cloud reference architecture

---

## Documentation Structure

Each feature has its own directory under `docs/` with the five files shown in
[Feature folders](#feature-folders--start-here):

```
docs/
├── README.md              # This file - main documentation index
├── BUILD.md               # Build instructions
│
├── {feature}/             # Feature documentation
│   ├── architecture.md    # Design, boundaries, rejected alternatives
│   ├── engineering.md     # The implementation contract
│   ├── cli.md             # Every verb and flag
│   ├── api.md             # Every capability on all six transports
│   └── user.md            # Task-oriented usage
```

### Documentation Conventions

All documentation follows these conventions:

| Convention | Description |
|------------|-------------|
| **Tables** | Used for feature lists, configuration options, and API references |
| **Code blocks** | YAML for config, bash for CLI, Go for API examples |
| **Status banners** | Every document opens with a `NORMATIVE`, `REFERENCE` or `ARCHIVE` banner and a `Last verified:` stamp (handbook `software/conventions/documentation.md` §1-§3) |
| **Cross-references** | Relative links between related documentation |

---

## Development Status

### Component Status

Local mode is the only mode with shipping code, and it is roughly 85% complete — see [ROADMAP.md](../ROADMAP.md). The per-component statuses below mean the component's core is in place and usable; they do not mean the platform as a whole is finished. What is complete and what remains to the release candidate is in the repository [ROADMAP.md](../ROADMAP.md), the one roadmap.

| Component | Status | Documentation |
|-----------|--------|---------------|
| Attestation | Complete | [attestation/](attestation/) |
| Barrier | Partial (`BarrierService` is gRPC/Unix only) | [barrier/](barrier/) |
| CA | Complete | [ca/](ca/) |
| Cluster | Complete | [cluster/](cluster/) |
| Compute | Complete | [compute/](compute/) |
| Datastore | Complete | [sdk/](sdk/) |
| Device | Complete | [device/](device/) |
| IAM | Complete | [iam/](iam/) |
| KMS | Complete | [kms/](kms/) |
| SDN | Complete | [sdn/](sdn/) |
| Tenant | Complete | [tenant/](tenant/) |
| TPM | Complete | [tpm/](tpm/) |
| **DHT** | Not Started (design only, no `pkg/dht`) | [dht/](dht/) |
| Firmware | Partial (UEFI Secure Boot, UKI, module signing, `pkg/firmware/avr/attestation`; no OTA) | [firmware/](firmware/) |

See [ROADMAP.md](../ROADMAP.md) for the full picture.

---

## Contributing

We welcome contributions to go-trusted-platform! Here's how you can help:

### Contributing to Documentation

1. **Find an issue** - The issue tracker is the backlog; [ROADMAP.md](../ROADMAP.md) orders it
2. **Pick a task** - Choose an open, unblocked issue
3. **Submit a PR** - Reference the issue and update the feature folder under `docs/`

### Contributing to Code

1. **Review the roadmap** - See [ROADMAP.md](../ROADMAP.md) for planned work
2. **Follow conventions** - See [CLAUDE.md](../CLAUDE.md) for coding standards
3. **Update documentation** - Include doc updates with code changes

### PR Checklist

When submitting a PR, ensure you:

- [ ] Add/update documentation for new features
- [ ] Follow the documentation conventions above
- [ ] Include tests with 90%+ coverage
- [ ] Reference the issue in your PR description

Priorities are in [ROADMAP.md](../ROADMAP.md).

---

## Standards Compliance

This project aims to be FIPS compliant and follows best practices and guidance issued by the TCG and NIST.

### TCG (Trusted Computing Group)

1. [Trusted Platform Module Library - Part 1: Architecture](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.07-2014-03-13.pdf)
2. [Trusted Platform Module Library - Part 2: Structures](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.99.pdf)
3. [Trusted Platform Module Library - Part 3: Commands](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf)
4. [TPM 2.0 Keys for Device Identity and Attestation](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf)
5. [Registry of Reserved TPM 2.0 Handles and Localities](https://trustedcomputinggroup.org/wp-content/uploads/RegistryOfReservedTPM2HandlesAndLocalities_v1p1_pub.pdf)
6. [TCG TPM v2.0 Provisioning Guidance](https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf)
7. [TCG Guidance for Securing Network Equipment Using TCG Technology](https://trustedcomputinggroup.org/wp-content/uploads/TCG_Guidance_for_Securing_NetEq_1_0r29.pdf)
8. [TCG Guidance for Secure Update of Software and Firmware on Embedded Systems](https://trustedcomputinggroup.org/wp-content/uploads/TCG-Secure-Update-of-SW-and-FW-on-Devices-v1r72_pub.pdf)

### NIST (National Institute of Standards and Technology)

1. [SP 800-147: BIOS Protection Guidelines](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-147.pdf)
2. [SP 800-147B: BIOS Protection Guidelines for Servers](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-147b.pdf)
3. [SP 800-57: Recommendation for Key Management](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt1r5.pdf)
4. [SP 800-88: Guidelines for Media Sanitization](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf)

### FIPS (Federal Information Processing Standards)

1. [FIPS 140-3: Security Requirements for Cryptographic Modules](https://csrc.nist.gov/pubs/fips/140-3/final)
2. [FIPS 180-4: Secure Hash Standard (SHS)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
3. [FIPS 186-5: Digital Signature Standard (DSS)](https://csrc.nist.gov/pubs/fips/186-5/finalf)
4. [FIPS 197: Advanced Encryption Standard (AES)](https://csrc.nist.gov/pubs/fips/197/final)
5. [FIPS 198-1: The Keyed-Hash Message Authentication Code (HMAC)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf)
6. [FIPS 199: Standards for Security Categorization](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.199.pdf)
7. [FIPS 200: Minimum Security Requirements](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.200.pdf)
8. [FIPS 201-3: Personal Identity Verification (PIV)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.201-3.pdf)
9. [FIPS 202: SHA-3 Standard](https://csrc.nist.gov/pubs/fips/202/final)
