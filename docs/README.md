# go-trusted-platform Documentation

> Complete documentation for the Zero-Trust Trusted Computing Platform

## Quick Links

- [Features](FEATURES.md) - Complete feature list
- [Roadmap](ROADMAP.md) - Development progress and planned features
- [Build Guide](BUILD.md) - Building from source

---

## Getting Started

### Platform Initialization

Generate a configuration file and initialize the platform:

```bash
# Generate default config and initialize the platform
./platformd config gen \
    --init \
    --debug \
    --fips=false \
    --domain=example.test \
    --platform-dir trusted-data

# Or copy an existing config
cp configs/platform/config.prod.yaml config.yaml
```

Configuration options:

| Flag | Default | Description |
|------|---------|-------------|
| `--domain` | `example.com` | Domain name |
| `--platform-dir` | `trusted-data` | Platform data directory |
| `--fips` | `true` | Enable FIPS mode |
| `--acme-directory-url` | `https://example.com/api/v1/acme/directory` | ACME Directory URL |
| `--type` | `server` | Configuration type (server or client) |

### Starting Services

```bash
# Start the platform daemon (root privileges required)
# Runs as master (root) + worker (deprivileged) processes
sudo ./platformd

# Start the platform (web services auto-start if configured)
./platformd serve

# Navigate to OpenAPI docs
xdg-open https://localhost:8443/swagger/
```

### Quick Example: VM with Network Access

```bash
# Create and start a VM
platformctl vm create --name test-vm --cpus 2 --memory 4096 --disk test.qcow2
platformctl vm start --name test-vm

# Device enrollment via ACME
platformctl device enroll --bridge br0 --port tap0
platformctl device activate --port tap0
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
| [Security](security/) | Rate limiting, audit logging, input validation |

### Compute & Orchestration

| Component | Description |
|-----------|-------------|
| [Compute](compute/) | VM orchestration with QEMU/KVM and vTPM |
| [Attestation](attestation/) | Workload attestation from bare metal to containers |
| [Firmware](firmware/) | *Planned* - AVR, Raspberry Pi, Android firmware and OTA |
| [Virtual TPM](vtpm/) | Software TPM for development and testing |

### Infrastructure

| Component | Description |
|-----------|-------------|
| [Cluster](cluster/) | High availability with Raft consensus |
| [Tenant](tenant/) | Multi-tenancy with VLAN isolation |
| [Health](health/) | Health checks and Prometheus metrics |
| [Provisioning](provisioning/) | Device enrollment and configuration |
| [Device](device/) | Device profiles and network phases |
| [Barrier Storage](cli/barrier.md) | Encrypted secret storage with multi-tier access. There is no `barrier/` component directory; the canonical 9-verb barrier CLI surface is the documentation that exists |
| [Secrets Management](secrets/) | Credential and key lifecycle management |
| [Registry](registry/) | Container and artifact registry with attestation |

### Distributed Systems

| Component | Description |
|-----------|-------------|
| [DHT](dht/) | *Planned* - Distributed hash table, cryptocurrency, content sharing |
| [Datastore](architecture/quicbaas-integration.md) | QuicBaaS embedded database and service layer (KMS, IAM, secrets, storage) |

### Developer Resources

| Component | Description |
|-----------|-------------|
| [SDK Overview](api/sdk-overview.md) | SDK architecture and design |
| [Go SDK](api/sdk-go.md) | Go SDK for `platformctl` and service integration |
| [JavaScript SDK](api/sdk-javascript.md) | TypeScript SDK for web applications |
| [API Reference](api/) | Multi-protocol API docs: REST, gRPC, QUIC, MCP, Unix Socket |
| [CLI Reference](cli/) | Command-line interface documentation |
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

- [Binary Separation](architecture/binary-separation.md) - Three-binary architecture (platform-initrd, platformd, platformctl)
- [Security Model](architecture/security-model.md) - Privilege separation and threat model
- [QuicBaaS Integration](architecture/quicbaas-integration.md) - Service layer architecture
- [802.1X Authentication](sdn/802.1x.md) - Certificate-based network access
- [Reference Architecture](architecture/reference.md) - IoT hybrid cloud reference architecture

---

## Documentation Structure

Each component has its own directory under `docs/` with a consistent structure:

```
docs/
├── README.md              # This file - main documentation index
├── FEATURES.md            # Complete feature list
├── ROADMAP.md             # Top-level development roadmap
├── BUILD.md               # Build instructions
│
├── {component}/           # Component documentation
│   ├── README.md          # Component overview and quick start
│   ├── architecture.md    # System design and data flows
│   ├── configuration.md   # Configuration reference
│   ├── api-reference.md   # REST/gRPC API documentation
│   ├── cli-usage.md       # Command-line interface
│   └── ROADMAP.md         # Component roadmap (if incomplete)
```

### Documentation Conventions

All documentation follows these conventions:

| Convention | Description |
|------------|-------------|
| **README.md** | Entry point with overview, quick start, and links to detailed docs |
| **Tables** | Used for feature lists, configuration options, and API references |
| **Code blocks** | YAML for config, bash for CLI, Go for API examples |
| **Status banners** | Planned features marked with `> **STATUS: PLANNED FEATURE**` |
| **Cross-references** | Relative links between related documentation |

### File Naming

| File | Purpose |
|------|---------|
| `README.md` | Component overview and navigation |
| `architecture.md` | Design decisions, diagrams, data flows |
| `configuration.md` | Complete YAML configuration reference |
| `api-reference.md` | REST and gRPC endpoint documentation |
| `cli-usage.md` | Command-line examples and options |
| `ROADMAP.md` | Development status and planned work |

---

## Development Status

### Component Status

Local mode is the only mode with shipping code, and it is roughly 85% complete — see [architecture/platform-modes.md](architecture/platform-modes.md). The per-component statuses below mean the component's core is in place and usable; they do not mean the platform as a whole is finished. Work outstanding across the whole platform:

- **Phase 4, Device Enrollment Strategies** (TCG Spec Section 6) is entirely unchecked in [ROADMAP.md](ROADMAP.md): Full Pre-Provision, EK-Only, EAB, and Attestation enrollment.
- **Phases 7 and 8** (LAK/LDevID key operations and the certify-01 challenge, both landing in go-xkms) are **deferred**, with Phase 8 blocked on Phase 7.
- **P2P, P2P Federation, and Hosted** modes are Not Started.
- **DHT** and **Firmware** are Not Started; both have design docs but no implementation package.

| Component | Status | Documentation |
|-----------|--------|---------------|
| Attestation | Complete | [attestation/](attestation/) |
| CA | Complete | [ca/](ca/) |
| Cluster | Complete | [cluster/](cluster/) |
| Compute | Complete | [compute/](compute/) |
| Datastore | Complete | [architecture/quicbaas-integration.md](architecture/quicbaas-integration.md) |
| Device | Complete | [device/](device/) |
| IAM | Complete | [iam/](iam/) |
| KMS | Complete | [kms/](kms/) |
| SDN | Complete | [sdn/](sdn/) |
| Tenant | Complete | [tenant/](tenant/) |
| TPM | Complete | [tpm/](tpm/) |
| **DHT** | Not Started (design only, no `pkg/dht`) | [dht/ROADMAP.md](dht/ROADMAP.md) |
| **Firmware** | Not Started (design only, no `pkg/firmware`) | [firmware/ROADMAP.md](firmware/ROADMAP.md) |

See [ROADMAP.md](ROADMAP.md) for the full picture, including the unchecked Phase 4 enrollment strategies and the deferred Phases 7-8.

---

## Contributing

We welcome contributions to go-trusted-platform! Here's how you can help:

### Contributing to Documentation

1. **Find incomplete items** - Check component `ROADMAP.md` files for `- [ ]` items
2. **Pick a task** - Choose an unchecked item to work on
3. **Submit a PR** - Include the updated `ROADMAP.md` with your item checked

### Contributing to Code

1. **Review the roadmap** - See [ROADMAP.md](ROADMAP.md) for planned features
2. **Check component roadmaps** - Each component has specific tasks in its `ROADMAP.md`
3. **Follow conventions** - See [CLAUDE.md](../CLAUDE.md) for coding standards
4. **Update documentation** - Include doc updates with code changes
5. **Mark progress** - Update relevant `ROADMAP.md` checkboxes in your PR

### PR Checklist

When submitting a PR, ensure you:

- [ ] Update relevant `ROADMAP.md` files to mark completed items as `- [x]`
- [ ] Add/update documentation for new features
- [ ] Follow the documentation conventions above
- [ ] Include tests with 90%+ coverage
- [ ] Reference the roadmap item in your PR description

### Priority Areas

These components need work:

| Priority | Component | Roadmap | Description |
|----------|-----------|---------|-------------|
| Next | Device Enrollment | [ROADMAP.md](ROADMAP.md) | Phase 4 strategies (TCG Section 6), all unchecked |
| Future | [DHT](dht/) | [ROADMAP.md](dht/ROADMAP.md) | P2P network, FROST-DKG, distributed services |
| Future | [Firmware](firmware/) | [ROADMAP.md](firmware/ROADMAP.md) | Raspberry Pi, Android, AVR support |

See [ROADMAP.md](ROADMAP.md) for the full development roadmap.

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
