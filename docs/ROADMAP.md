# go-trusted-platform Development Roadmap

> **Last Updated**: 2026-01-25
> **Source of Truth**: This document tracks remaining development work.

> **Architecture update (CA/ACME)**: `go-trusted-ca` has been
> decommissioned. Its certificate-authority and ACME engines now live in
> **go-xkms** (`pkg/ca` + `pkg/acme`), and go-trusted-platform consumes
> them exclusively through the **go-quicbaas SDK** (`Security().ACME()` /
> `Security().Certificate()`) -- never by importing go-trusted-ca. Where
> package paths below still read `go-trusted-ca/...`, they refer to that
> absorbed code, now at `go-xkms/...`.

## Vision

go-trusted-platform is a **Zero-Trust Trusted Computing Platform** for running sensitive, regulated, and compliance-critical workloads with hardware-rooted security from bare metal to cloud.

### Platform Modes

| Mode | Description | Status |
|------|-------------|--------|
| **Local** | Isolated/enterprise deployments with local CA, IAM, DNS | ~85% (Phases A-L; Phase 4 enrollment open, Phases 7-8 deferred) |
| **P2P** | Distributed deployments with FROST threshold CA, DHT | Not Started |
| **P2P Federation** | Optional federation layer for P2P mode | Not Started |
| **Hosted** | Premium managed control plane with flexible data plane | Not Started |

---

## Remaining Work

### DHT Network (P2P Mode) - [dht/ROADMAP.md](dht/ROADMAP.md)

**Status**: Design Complete - Implementation Pending

**Milestones**:
1. Core Infrastructure (DHT Core, Network Transport, Wire Protocol)
2. Cryptographic Layer (FROST, FROST-DKG Integration)
3. Certificate Authority (CA Pool, Certificate Ops, CT Log)
4. Consensus and Coordination (VRF Selection, PBFT)
5. Currency and Transactions (UTXO/DAG, Sharded Ledger, Economics)
6. Network Architecture (Hierarchical DHT, IPv6, Gateway)
7. Reputation and Defense
8. Content and Storage
9. Operations (Genesis, Partition, Telemetry)
10. Governance (Upgrades, Versioning)
11. Service Discovery and E-Commerce
12. Browser Extension
13. AI Agent Collaboration

---

### Firmware Integration - [firmware/ROADMAP.md](firmware/ROADMAP.md)

**Status**: Not Started

**Milestones**:
1. Core Infrastructure (Device profiles, OTA skeleton, Virtual testing)
2. AVR Bootloader and Crypto (Production C bootloader, Crypto auto-detection)
3. AVR ISP Flashing and Device Management
4. Firmware Encryption and Supply Chain
5. Raspberry Pi Support (Secure boot, OTP, Alpine integration) — the factory SD-card image with Alpine aarch64, U-Boot Secure Boot and TPM-sealed first boot shipped 2026-09 ([docs/factory-image/](factory-image/)); OTP signed boot, A/B and OTA remain planned ([docs/firmware/rpi.md](firmware/rpi.md))
6. Android Support (Fastboot, GrapheneOS, Hardware attestation)
7. Wireless Protocols and CLI
8. Examples, Documentation, and Fleet UI
9. Testing and Hardening

---

### Hosted Control Plane - Phase O

**Status**: Not Started

- [ ] Multi-tenant CA with tenant PKI isolation
- [ ] Multi-tenant IAM with tenant isolation
- [ ] Multi-tenant KMS with tenant isolation
- [ ] Managed HA (multi-region Raft)
- [ ] Tenant onboarding and provisioning
- [ ] SLA monitoring and enforcement
- [ ] Billing integration

---

## Local Mode Enhancement Phases

### Phase 1: User Registration & Tenant Management - COMPLETE

**Focus**: Self-service account creation with automatic tenant provisioning

- [x] Implement WebAuthn registration flow with tenant UUID generation
- [x] Add user invitation flow within tenant
- [x] Integrate with QuicBaaS OIDC provider
- [x] Create tenant management UI/API
- [x] Frontend: AuthContext, invitation admin page, tenant dashboard
- [x] E2E Tests: 182 Playwright tests (auth, invitations, tenant, isolation)
- [x] Go SDK and JavaScript SDK with React hooks

**See**: `docs/ROADMAP-PHASE1.md` for detailed implementation log

---

### Phase 2: Device Profile Management - COMPLETE

**Focus**: Profile-first device definition

- [x] Implement DeviceProfile entity (pkg/device/entities/profile.go)
- [x] Create device profile management API (all protocols: REST, gRPC, QUIC, MCP)
- [x] Create device profile management UI (web/src/app/(dashboard)/devices/profiles/)
- [x] JavaScript SDK integration with React hooks
- [x] Implement vTPM generation service (pkg/vtpm/)
- [x] Implement EAB credential generation and delivery (QR, file, API) (pkg/eab/)
- [x] REST/gRPC APIs for vTPM and EAB services

**Files Completed:**
- `pkg/device/entities/profile.go` - DeviceProfile entity with network phases
- `pkg/device/profile_service.go` - Profile service implementation
- `pkg/storage/quicbaas/device_profile.go` - QuicBaaS DAO
- `pkg/api/daemon/device_grpc_service.go` - gRPC service (16 RPCs)
- `web/src/app/(dashboard)/devices/profiles/page.tsx` - Profile management UI
- `pkg/vtpm/` - vTPM generation service (types, generator, errors, tests)
- `pkg/eab/` - EAB credential management (types, service, dao, delivery, entity, errors)
- `pkg/webservice/v1/vtpm/` - vTPM REST handlers
- `pkg/webservice/v1/rest/eab/` - EAB REST handlers
- `pkg/api/grpc/proto/vtpm.proto` - vTPM gRPC definitions
- `pkg/api/grpc/proto/eab.proto` - EAB gRPC definitions
- `sdk/javascript/src/services/vtpm-service.ts` - JavaScript SDK vTPM service
- `sdk/javascript/src/services/eab-service.ts` - JavaScript SDK EAB service
- `sdk/javascript/src/react/hooks/use-vtpm-instance.ts` - React hooks for vTPM
- `sdk/javascript/src/react/hooks/use-eab.ts` - React hooks for EAB

---

### Phase 3: TCG-CSR Integration - COMPLETE

**Focus**: Integrate TCG-CSR-IDEVID and TCG-CSR-LDEVID from go-xkms

**Architecture Note**: TCG-CSR functionality is provided by go-xkms SDK, NOT implemented in go-trusted-platform. See `pkg/ca/CLAUDE.md` for integration guidelines.

- [x] TCG-CSR-IDEVID creation via XKMS SDK TPM2 operations
- [x] TCG-CSR-IDEVID validation via XKMS SDK TPM2 operations
- [x] CSR marshaling via XKMS SDK serialization helpers
- [x] CA-side verification via Trusted CA SDK

**Provided by XKMS SDK (via `github.com/jeremyhahn/go-xkms/sdk/go`):**
- TPM2 CSR creation - Device-side CSR builder
- TPM2 CSR validation - Server-side stateless validation
- Serialization helpers - CSR marshaling/unmarshaling

**Provided by go-xkms CA/ACME (consumed via the go-quicbaas SDK):**
- TCG-CSR-IDEVID verification - CA method using XKMS TPM operations
- ACME challenges that consume TCG-CSR structures

---

### Phase 4: Device Enrollment Strategies (TCG Spec Section 6)

**Focus**: Multiple enrollment paths per TCG specification via go-xkms (CA/ACME), consumed through the go-quicbaas SDK

**Architecture Note**: ACME challenges are provided by go-xkms (`pkg/acme/challenges`) and consumed via the go-quicbaas SDK, NOT implemented in go-trusted-platform. See `pkg/ca/CLAUDE.md` for integration guidelines.

- [ ] Full Pre-Provision (Section 6.2): OEM IAK + IDevID single pass
- [ ] EK-Only (Section 6.1): endorse-01 + enroll-01 challenges
- [ ] EAB (Section 6.1 + EAB pre-auth): Pre-authorized physical device
- [ ] Attestation (Section 6.6): Platform Certificate based

**Provided by go-xkms/pkg/acme/challenges/ (via the go-quicbaas SDK):**
- `endorse-01/` - EK endorsement challenge handler
- `enroll-01/` - Device enrollment challenge handler
- `device-attest-01/` - Device attestation challenge handler

**Platform Integration (go-trusted-platform):**
- `pkg/device/enrollment/` - Client-side enrollment using the go-xkms ACME client (via the go-quicbaas SDK)

---

### Phase 5: DNS Multi-Tenancy - COMPLETE

**Focus**: Zone ownership with hybrid authorization

- [x] Add `TenantID` to Zone entity
- [x] Add DNSSEC key-per-zone with tenant namespace in KMS
- [x] Add ownership check in service layer
- [x] Ensure middleware checks coarse permissions

**Files Completed:**
- `pkg/dns/entities/zone.go` - TenantID field and IsOwnedBy() method
- `pkg/dns/dnssec_keystore.go` - Tenant-scoped key paths (key IDs include tenant scope)
- `pkg/dns/service.go` - authorizeZoneAccess(), Zone() and ListZones() with tenant filtering

---

### Phase 6: Certificate Extensions & Tenant Binding - COMPLETE

**Focus**: IEEE 802.1AR compliance with tenant identity

**Architecture Note**: Certificate templates and extensions are provided by go-xkms (`pkg/ca`), consumed via the go-quicbaas SDK. See `pkg/ca/CLAUDE.md` for integration guidelines.

- [x] Implement custom OID for TenantID in IDevID certificates
- [x] Implement HardwareModuleName in subjectAltName (TCG MANDATORY)
- [x] Implement proper X.500 DN with unique Subject Name (buildSubject in ca.go)
- [x] Implement certificate chain validation for EK, Platform certs (trust_chain.go)

**Files Completed in go-xkms/pkg/ca/ (formerly go-trusted-ca):**
- `oids.go` - OIDTPTenantID (1.3.6.1.4.1.29377.101.20), TenantID type, CreateTenantIDExtension()
- `types.go` - HardwareModuleInfo struct, SubjectAlternativeNames.HardwareModuleName field
- `ca.go` - addSANs() with HardwareModuleName OtherName support, buildSANExtensionWithOtherName()
- `oids_test.go` - TestCreateTenantIDExtension with comprehensive coverage
- `trust_chain.go` - Complete chain validation via RootCertificate(), TrustedRootCertPool(), Verify()

---

### Phase 7: LAK/LDevID Key Operations (go-xkms) - DEFERRED

**Focus**: TCG Spec Sections 6.3-6.6 support

**Status**: Deferred - to be implemented when full TCG 6.3-6.6 enrollment is needed

- [ ] `CreateLAK(iakAttrs, qualifyingData)` - Local Attestation Key
- [ ] `CreateLDevID(certifyingKeyAttrs, qualifyingData)` - Local Device ID
- [ ] `CertifyCreation(keyAttrs, creationTicket)` - TPM2_CertifyCreation
- [ ] LAK/LDevID templates (RSA/ECC)

---

### Phase 8: certify-01 Challenge (go-xkms) - DEFERRED

**Focus**: ACME challenge for LAK/LDevID issuance

**Status**: Deferred - depends on Phase 7 completion

- [ ] Challenge handler for Sections 6.3-6.6
- [ ] Unit tests

**Files:**
- `/home/jhahn/sources/go-xkms/pkg/acme/challenges/certify-01/`

---

### Phase 9: Audit & Compliance - COMPLETE

**Focus**: Top secret compliance

- [x] Comprehensive audit logging for all auth/authz decisions
- [x] Device enrollment audit trail with TCG-CSR hash
- [x] Hardware attestation requirements (PCR validation)
- [x] Compliance reporting (QuicBaaS query interface)
- [x] Included Attestation support (Section 6.1.4)

**Files Completed:**
- `pkg/security/audit/persistence/quicbaas.go` - QuicBaaS EventPersister with query support
- `pkg/security/audit/events/enrollment.go` - Device enrollment audit events with CSR hash
- `pkg/security/audit/events/attestation.go` - PCR validation and attestation audit events
- `pkg/webservice/v1/middleware/iam/auth.go` - Authentication audit logging integration
- `pkg/webservice/v1/middleware/iam/authz.go` - Authorization audit logging integration

---

## Binary Architecture

| Binary | Purpose | Size | Commands |
|--------|---------|------|----------|
| `platform-initrd` | Initrd boot operations | ~22MB | boot, recovery |
| `platformd` | Daemon only | ~65MB | serve, version |
| `platformctl` | CLI + all operational commands | ~52MB | firstboot + everything else |

---

## Tech Debt - COMPLETE

All tech debt items have been addressed:

- [x] **RFC3161 Timestamp**: Full Verify() implementation with CMS/PKCS#7 parsing in `pkg/image/timestamp.go`
- [x] **LUKS2 Token Metadata**: Token CRUD operations in `pkg/storage/luks/token.go`
- [x] **QuicBaaS SDK Query**: Already implemented via SDKClient wrapper
- [x] **PEP Client Wiring**: Integrated in daemon startup via `SDKPEPClientAdapter`
- [x] **KMS Secrets Migration**: CLI command with env/file to KMS migration in `pkg/cli/commands/bootstrap/secrets_migrate.go`

---

## Multi-Protocol API Architecture

| Protocol | Transport | Port | Use Case |
|----------|-----------|------|----------|
| REST | HTTPS | 8443 | Web clients |
| gRPC | TCP | 10443 | Service-to-service |
| QUIC | UDP | 9444 | Low-latency, mobile |
| MCP | HTTP | 9445 | AI/LLM integration |
| Unix | gRPC UDS | /run/platformd.sock | Local IPC, CLI |

Ports above are the `platformd serve` defaults (`pkg/daemon/commands/serve.go`), overridable with `--rest-port`, `--grpc-port`, `--quic-port`, and `--mcp-port`. MCP binds `127.0.0.1` only; the rest bind `0.0.0.0`.

Two other port numbers show up nearby and are not daemon API ports. `daemon.DefaultConfig()` in `pkg/api/daemon/config.go` carries library-level fallbacks of `11443` for QUIC and `8000` for MCP, but `platformd serve` always overwrites both from the flags above, so they are never what a running daemon listens on. Port `9443` is a webservice TLS port chosen per role in the shipped configs — control-plane webservice uses `8443` and gateway uses `9443` — not a second REST port on a single node.

---

## References

- TCG TPM 2.0 Keys for Device Identity and Attestation v1.10r9
- IEEE 802.1AR - Secure Device Identity
- RFC 8555 - ACME Protocol

---

## Contributing

1. Pick an unchecked item from this roadmap or a component's ROADMAP.md
2. Implement following conventions in [../CLAUDE.md](../CLAUDE.md)
3. Ensure 90%+ test coverage
4. Submit PR with updated roadmap

---

## Revision History

| Date | Changes |
|------|---------|
| 2026-06-27 | CA/ACME architecture: go-trusted-ca decommissioned; CA + ACME absorbed into go-xkms (pkg/ca + pkg/acme), consumed via the go-quicbaas SDK |
| 2026-01-25 | Tech debt complete: RFC3161 Verify, LUKS2 tokens, PEP wiring, KMS secrets migration |
| 2026-01-25 | Phase 9 Audit & Compliance complete: QuicBaaS persister, auth/authz/enrollment/attestation audit events |
| 2026-01-25 | Phase 6 Certificate Extensions complete: TenantID OID, HardwareModuleName SAN, chain validation. Phases 7-8 deferred. |
| 2026-01-25 | Phase 5 DNS Multi-Tenancy complete: Zone entity TenantID, DNSSEC tenant-scoped keys, service layer authorization |
| 2026-01-21 | Corrected Phase 3-6 architecture: use go-xkms/go-trusted-ca, added pkg/ca/CLAUDE.md |
| 2026-01-19 | Cleaned up roadmap - removed completed items, kept only remaining work |
| 2026-01-18 | Complete rewrite with full integrated security architecture |
