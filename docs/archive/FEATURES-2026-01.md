# Features

This document lists the completed features of the Trusted Platform.

For development progress and planned features, see the [Roadmap](ROADMAP.md).

---

## Certificate Authority

A complete X.509 PKI implementation with support for multiple key storage backends.

### Core Features

- **Root & Intermediate CAs** - Full certificate hierarchy support
- **Multi-Algorithm Support** - RSA, ECDSA, and EdDSA (Ed25519) signing
- **Simultaneous Signing** - Issue and sign using any supported algorithm and key store
- **TLS 1.3** - Modern transport security with opaque private keys
- **Certificate Storage** - Trusted root and intermediate certificate stores
- **Certificate Revocation Lists (CRLs)** - Full CRL lifecycle management
- **Certificate Signing Requests (CSR)** - Create and sign standard CSRs
- **TCG-CSR-IDEVID** - Generate, sign, and verify device identity certificates
- **Encoding Support** - DER and PEM encoding/decoding
- **CA Bundles** - Create and parse certificate bundles
- **Trust Store Integration** - Install/uninstall CA certificates to OS trust store

### ACME Server & Client

RFC 8555 compliant implementation for automated certificate management.

| Challenge Type | Description |
|----------------|-------------|
| http-01 | Standard HTTP challenge |
| dns-01 | DNS TXT record challenge |
| device-attest-01 | Device attestation (draft-acme-device-attest-03) |
| http-x | Custom HTTP challenge with configurable port |
| endorse-01 | Custom EK certificate issuance |
| enroll-01 | Custom TCG-CSR-IDEVID device enrollment |

- **Cross-Signed Certificates** - Integration with Let's Encrypt or any ACME server
- **Automatic Certificate Renewal** - Hands-free certificate lifecycle management

For details, see [ACME documentation](ca/acme.md).

---

## Key Management

### Key Storage Modules

| Module | Description | Documentation |
|--------|-------------|---------------|
| PKCS #8 | Software-based key storage with password protection | [docs/kms](kms/) |
| PKCS #11 | Hardware security module integration | [docs/kms](kms/) |
| TPM 2.0 | Trusted Platform Module key storage | [docs/tpm](tpm/) |
| SoftHSM | Software HSM for development and testing | |

### Key Features

- **Secondary Key Passwords** - Additional password protection for PKCS #8 and TPM keys
- **Platform Key Store** - Central repository for module PINs and secrets
- **XKMS Architecture** - Flexible key management module configuration
- **PCR Policy Sessions** - Automatic password retrieval based on platform state
- **Auto-Generated Passwords** - 256-bit passwords generated from default placeholder

For details, see [KMS Overview](kms/overview.md).

---

## TPM 2.0

Hardware-backed security using Trusted Platform Module 2.0.

### Provisioning

- **TCG Best Practices** - Provisioning per TCG recommended guidelines
- **EK Certificate Retrieval** - From NVRAM, manufacturer download (Intel), or generation
- **Auto-Import Manufacturer CA** - Automatic TPM manufacturer CA chain import
- **Key Generation** - RSA/ECC EK, SRK, AK, and DevID keys with certificates

### Attestation

- **Credential Challenge/Activate** - Full TPM credential workflow
- **Event Log Reading** - TPM event log extraction and parsing
- **PCR Reading** - Platform Configuration Register state capture
- **Quote/Verify** - TPM-based platform attestation

For details, see the [TPM documentation](tpm/).

---

## Web Services

Built-in web server with modern security features.

### Transport

- **HTTP/1, HTTP/2, HTTP/3** - Full HTTP version support
- **TLS 1.3 Only** - Modern encryption with opaque private keys
- **mTLS** - Mutual TLS authentication

### Features

- **REST API** - Complete REST interface with OpenAPI/Swagger documentation
- **Rewrite Rules** - URL rewriting support
- **Reverse Proxy** - Backend service proxying
- **Virtual Hosts** - Multi-domain hosting

For API documentation, see [docs/api](api/).

---

## Authentication

### WebAuthn / FIDO2

- **Registration** - Begin and finish registration workflows
- **Login** - Begin and finish login workflows
- **Passkey Support** - Hardware security key integration

### JSON Web Tokens

- **Token Generation** - Create signed JWTs
- **Token Refresh** - Automatic token renewal
- **Token Validation** - Signature and claims verification
- **Opaque Private Keys** - TPM/HSM-backed signing keys

For details, see [docs/iam](iam/).

---

## Container Orchestrator

Full container lifecycle management with TPM-based attestation.

### Core Features

- **Podman Integration** - Full lifecycle via Podman API (create, start, stop, remove)
- **Event-log Attestation** - PCR 14 aggregate with per-container measurement log
- **OPA Policy Engine** - Builtin + custom + remote bundle policy enforcement
- **Image Verification** - Platform CA signature verification
- **SDN/OpenFlow Network** - Unified network model for host/VM/container
- **Service Mode** - Embedded (platformd-managed) or standalone (systemd/rc)
- **Init Auto-detection** - Alpine→rc, Debian→systemd, with manual override

### Multi-Protocol API

All container operations available via 5 protocols:

| Protocol | Coverage | Notes |
|----------|----------|-------|
| REST | 94.6% | Full CRUD, logs, attestation |
| gRPC | 98.9% | Streaming logs support |
| QUIC | 92.6% | Binary protocol |
| MCP | 95.1% | AI/LLM tool integration |
| Unix | 92.8% | Local IPC for CLI |

For details, see [compute/container-orchestrator.md](compute/container-orchestrator.md).

---

## Trusted Registry

Attestation-gated container registry with hardware-backed encryption.

### Core Features

- **Attestation-Gated Access** - TPM quote required before image pull/push
- **Image Encryption** - All images encrypted with QuicBaaS-managed keys
- **QuicBaaS Storage** - Single storage backend leveraging QuicBaaS
- **OPA Policies** - Customizable access policies via OPA

### Security Model

- No username/password authentication
- TPM attestation is the only authentication method
- PCR values must match expected golden values
- Images encrypted at rest with AES-256-GCM

For details, see [registry/README.md](registry/README.md).

---

## Remote Attestation

gRPC-based remote attestation between platforms.

### Verifier (Service Provider)

- TLS 1.3 with opaque private keys
- mTLS auto-negotiation
- Endorsement Key certificate retrieval
- Attestation Key profile management
- Credential challenge/activate
- AK certificate issuance
- Quote verification
- Automatic device enrollment

### Attestor (Client)

- TLS 1.3 with opaque private keys
- mTLS auto-negotiation
- Credential activation
- Quote generation
- Automatic device enrollment

---

## DNS Server

Authoritative DNS server with zone management.

- **Public Zones** - Internet-facing DNS records
- **Internal Zones** - Private network resolution
- **ACME Integration** - Zone registration via dns-01 challenge

For details, see [docs/dns](dns/).

---

## Platform Security

### Linux IMA (Integrity Measurement Architecture)

- **File Measurement** - Hash files at access time and extend to PCR 10
- **Signature Verification** - Verify file signatures before execution (appraise mode)
- **Policy Engine** - Flexible rules for measurement and appraisal
- **TPM Integration** - Extend measurements to PCR 10 for attestation
- **Audit Logging** - Log IMA events to audit subsystem
- **EVM Support** - Extended Verification Module for metadata protection

For details, see [docs/ima](ima/).

### File Integrity Monitoring

- System measurement capture and signing
- Digest verification on startup
- Platform state validation

### Signed Blob Storage

- Cryptographic signatures for stored data
- Digest and checksum verification

---

## Deployment Options

### Supported Platforms

| Platform | Secure Boot | Notes |
|----------|-------------|-------|
| Bare Metal (ISO) | Yes | Full installer with custom secure boot keys |
| Docker | Yes | Containerized deployment |
| QEMU / KVM | Yes | Virtual machine testing |
| PXE Boot | Yes | Network boot provisioning |
| Raspberry Pi | Yes | Factory SD-card image: Alpine aarch64, U-Boot with preseeded Secure Boot keys and TCG2 measured boot, signed UKI, same TPM-sealed first boot as the ISO (`make image-rpi`, [docs/factory-image/](factory-image/)) |
| AVR | - | Trusted Bootloader & Firmware |

### Hardware Support

- **AMD KR-260 FPGA** - Hardware acceleration support

For installer documentation, see [docs/installer](installer/).

---

## Configuration

### Supported Operating Systems

- Debian (glibc)
- Alpine (musl libc)

### Binary Types

- **Standard** - Dynamically linked with glibc
- **Static** - Statically linked with musl libc
- **Debug** - Includes debug symbols

---

## Related Documentation

- [Roadmap](ROADMAP.md) - Development progress and planned features
- [Architecture](architecture/) - System design and security model
- [Secure Boot](firmware/secure-boot.md) - Secure boot configuration
- [UEFI Secure Boot](firmware/uefi-secure-boot.md) - UEFI integration details
