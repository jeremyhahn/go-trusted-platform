# CA Architecture

> **Status: NORMATIVE** · Scope: `pkg/ca/`, `pkg/acme/`, the CA transport layer · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: architecture (this file) · [engineering.md](engineering.md) ·
> [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> **Verification scope.** Package contents, RPC list, REST and ACME route
> registration, CLI flags and the transport matrix were checked against code on
> 2026-08-18. The hierarchy and certificate-type narrative below predates the
> migration and was carried over.

## The problem

Everything on this platform is identified by a certificate — nodes, devices,
workloads, service endpoints, agents. At that volume, issuance has to be
automatic, and the thing that authorises issuance cannot be a human or a shared
secret.

## The shape chosen

**Host the stack's CA; do not build one.** go-xkms owns `TrustedCA` and the
ACME implementation; this repository consumes them through
`go-quicbaas/sdk/go` and re-exports the result as the platform product's
certificate surface (docs/00 L5).

What is local is a small set of adapters and the transport frontage:

```
pkg/ca/quicbaas/keystore_adapter.go   pkg/ca/quicbaas/kms_adapter.go
pkg/acme/storage/quicbaas/            pkg/store/certstore/adapter.go
pkg/store/object/objstore_adapter.go
```

There is **no certificate logic in this repository.** `pkg/ca/` is those two
adapters, an errors file, and a scoped instruction file.

Authorization for issuance comes from **ACME challenge types**, and the ones
that matter here are `endorse-01`, `device-01` and `device-attest-01` — a device
proves what it is from hardware rather than proving control of a name.

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Implement a CA in the platform** | Two CA implementations in one portfolio is two sets of certificate-parsing bugs, two audit surfaces and two things to get FIPS-certified. The stack owns it; this repository consumes it (docs/00 L2). |
| **Manual issuance for platform identities** | At the scale of "every node, device, workload and agent", a human in the loop means either long-lived certificates or an outage. ACME with short validity is the only shape that works. |
| **Name-based challenges only (`http-01` / `dns-01`)** | Proving control of a name proves nothing about the machine. The TPM-based challenges let a device prove its hardware identity, which is the platform's whole premise. Name challenges remain available for services. |
| **Unlimited ACME endpoints** | An unrated certificate-issuance endpoint is a denial-of-service surface and an issuance-abuse surface. Every ACME route carries a rate limiter and account registration has its own. |
| **Serving the CA bundle only over authenticated transports** | A client with no trust cannot authenticate. `/ca/bundle`, `/ca/root`, `/ca/intermediate` and `/ca/bootstrap` are deliberately reachable without credentials, and `bundle` is the one ACME route with no rate limiter. |
| **An unrevoke operation** | Revocation is published in a CRL that relying parties may have cached and acted on. Un-publishing it would make the CRL untrustworthy. Issue a new certificate instead. |

## Component boundaries

| Piece | Location | Owner |
|---|---|---|
| **CA implementation, ACME protocol, certificate management** | go-xkms `TrustedCA`, reached through `go-quicbaas/sdk/go` | **not this repo** |
| **Key management for CA keys** | the stack's KMS, via `pkg/ca/quicbaas/kms_adapter.go` | **not this repo** |
| Keystore adapter | `pkg/ca/quicbaas/keystore_adapter.go` | this repo |
| ACME storage adapter | `pkg/acme/storage/quicbaas/` | this repo |
| Certificate store adapter | `pkg/store/certstore/adapter.go` | this repo |
| Object store adapter | `pkg/store/object/objstore_adapter.go` | this repo |
| gRPC `CAService` | `pkg/api/grpc/ca_service.go`, `pkg/api/daemon/ca_grpc_service.go` | this repo |
| REST CA routes | `pkg/webservice/v1/rest/ca/` | this repo |
| **ACME protocol server** | `pkg/webservice/v1/router/acme.go` | this repo hosts it |
| QUIC CA handlers | `pkg/api/quic/ca_handlers.go` | this repo |
| MCP `ca_*` tools | `pkg/api/mcp/ca_tools.go` | this repo |
| **EAB credentials** | `pkg/eab/` — [`docs/eab/`](../eab/) | this repo, separate feature |
| **DNS-01 challenge records** | `pkg/dns/` — [`docs/dns/`](../dns/) | this repo, separate feature |

The §R row is part of *"Re-export frontage of the composed stack (CA, KMS, IAM,
FIDO2/PIV, barrier, ceremony, LUKS, auth, data services)"*, Tier 1, reached
through `services/ca`.

## Trust boundaries

1. **Requester → CA.** Crossed by an ACME challenge or an authenticated platform
   call. With TPM-based challenges the crossing is attested rather than asserted.
2. **CA → its own keys.** CA private keys live in the stack's KMS. The adapters
   exist so the platform layer never holds them.
3. **Public trust material.** `/ca/bundle`, `/ca/root`, `/ca/intermediate`,
   `/ca/bootstrap`, `/ca/crl` and `/ca/info` are intentionally
   unauthenticated — they are how a client with no trust acquires some, and
   how a relying party checks what it already has. Since #165 that is
   enforced structurally rather than by convention: they are the whole of
   `CARouter.RegisterPublicRoutes`, and `/ca/certificates` — issuance,
   revocation and the issued-certificate inventory — is the whole of the
   gated `CARouter.RegisterRoutes`.
4. **The system trust store.** `install-ca-certificates` gives this CA the
   ability to impersonate anything to that host. Routine on a platform node, a
   decision elsewhere.
5. **Revocation.** One-way and published. Relying parties act on the reason
   code.

## What this feature deliberately does not do

- **It does not implement certificate issuance, parsing or the ACME protocol.**
  Adapters and frontage only. One recorded gap: Sign CSR still parses the CSR
  for its pre-sign checks until the CA's template-validator seam is adopted
  ([engineering.md](engineering.md) §1).
- **It does not implement the TPM challenge handlers.** `endorse-01`,
  `enroll-01` and `device-attest-01` are the stack's.
- **It does not hold CA private keys.**
- **It does not offer renew or verify over REST.** That is a gap
  ([api.md](api.md) §2), not a decision.
- **It has no unrevoke.**

## A stale instruction file

`pkg/ca/CLAUDE.md` still names **`go-trusted-ca`** as the owner of CA and ACME
functionality. That repository was **decommissioned on 2026-08-19** — rolled into
go-xkms — and the identifier survives in ten tracked files. That file is an agent
instruction file with an `AGENTS.md` mirror, so it needs its own change rather
than a documentation edit; it is reported in [engineering.md](engineering.md) §2
and in the migration report.

---

This document describes the Certificate Authority architecture, including the
CA hierarchy, certificate types, and key storage integration.

## Architecture Overview

```
┌───────────────────────────────────────────────────────────────────┐
│                        CA Architecture                            │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Application Layer                                                │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ platformctl ca  │ ACME Client │ platformd    │ Web Server  │  │
│  └────────┬────────┴──────┬──────┴──────┬───────┴──────┬──────┘  │
│           │               │             │              │          │
│           └───────────────┴─────────────┴──────────────┘          │
│                                  │                                │
│  Service Layer                   │                                │
│  ┌───────────────────────────┬───┴───┬───────────────────────────┐│
│  │                        CA Service                             ││
│  │  ┌────────────────────────────────────────────────────────┐  ││
│  │  │ Certificate    │ CRL/OCSP    │ ACME       │ Validation │  ││
│  │  │ Management     │ Management  │ Handler    │ Engine     │  ││
│  │  └────────────────────────────────────────────────────────┘  ││
│  └───────────────────────────────────────────────────────────────┘│
│                                  │                                │
│  Crypto Layer                    │                                │
│  ┌───────────────────────────┬───┴───┬───────────────────────────┐│
│  │                    Signer/Verifier                            ││
│  │  ┌────────────────────────────────────────────────────────┐  ││
│  │  │ go-xkms CA Package (pkg/ca, via go-quicbaas SDK)       │  ││
│  │  └────────┬───────────────────┬───────────────────┬───────┘  ││
│  │           │                   │                   │          ││
│  └───────────────────────────────────────────────────────────────┘│
│              │                   │                   │            │
│  Key Storage │                   │                   │            │
│  ┌───────────┼───────────────────┼───────────────────┼──────────┐│
│  │           ▼                   ▼                   ▼          ││
│  │  ┌────────┴──────┐   ┌────────┴──────┐   ┌────────┴──────┐  ││
│  │  │  TPM Backend  │   │ PKCS#11 Backend│   │  SW Backend   │  ││
│  │  │  (go-xkms)│   │  (go-xkms) │   │ (go-xkms) │  ││
│  │  └───────────────┘   └────────────────┘   └───────────────┘  ││
│  └───────────────────────────────────────────────────────────────┘│
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## CA Hierarchy Diagram

```
┌───────────────────────────────────────────────────────────────────┐
│                        Trust Hierarchy                            │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│                        [Trust Anchor]                             │
│                             │                                     │
│                    ┌────────┴────────┐                            │
│                    │    Root CA      │                            │
│                    │  (Offline/HSM)  │                            │
│                    └────────┬────────┘                            │
│                             │                                     │
│         ┌───────────────────┼───────────────────┐                 │
│         │                   │                   │                 │
│         ▼                   ▼                   ▼                 │
│  ┌──────┴──────┐     ┌──────┴──────┐     ┌──────┴──────┐         │
│  │ TLS/Web CA  │     │ Device CA   │     │ Identity CA │         │
│  │ (Online)    │     │ (IDevID)    │     │ (User/Svc)  │         │
│  └──────┬──────┘     └──────┬──────┘     └──────┬──────┘         │
│         │                   │                   │                 │
│    ┌────┴────┐         ┌────┴────┐         ┌────┴────┐           │
│    │         │         │         │         │         │           │
│    ▼         ▼         ▼         ▼         ▼         ▼           │
│  ┌───┐   ┌──────┐   ┌──────┐ ┌──────┐   ┌──────┐ ┌──────┐       │
│  │TLS│   │mTLS  │   │IDevID│ │IAK   │   │User  │ │Service│      │
│  │Srv│   │Client│   │      │ │      │   │      │ │      │       │
│  └───┘   └──────┘   └──────┘ └──────┘   └──────┘ └──────┘       │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Certificate Types

### Root CA Certificate

| Attribute            | Value                                    |
|----------------------|------------------------------------------|
| Subject CN           | Trusted Platform Root CA                 |
| Key Usage            | keyCertSign, cRLSign                     |
| Basic Constraints    | CA:TRUE, pathlen:1                       |
| Validity             | 10-20 years                              |
| Key Algorithm        | RSA-4096 or ECDSA P-384                  |
| Key Storage          | HSM or offline TPM                       |

### Intermediate CA Certificate

| Attribute            | Value                                    |
|----------------------|------------------------------------------|
| Subject CN           | Trusted Platform [Purpose] CA            |
| Key Usage            | keyCertSign, cRLSign                     |
| Basic Constraints    | CA:TRUE, pathlen:0                       |
| Validity             | 5-10 years                               |
| Key Algorithm        | RSA-3072/4096 or ECDSA P-256/384         |
| Key Storage          | TPM or PKCS#11 HSM                       |

### TLS Server Certificate

| Attribute            | Value                                    |
|----------------------|------------------------------------------|
| Subject CN           | server.example.com                       |
| Key Usage            | digitalSignature, keyEncipherment        |
| Extended Key Usage   | serverAuth                               |
| SAN                  | DNS names, IP addresses                  |
| Validity             | 90-365 days                              |
| Key Algorithm        | ECDSA P-256 or RSA-2048                  |

### IDevID Certificate

| Attribute            | Value                                    |
|----------------------|------------------------------------------|
| Subject CN           | Device serial number                     |
| Key Usage            | digitalSignature                         |
| Extended Key Usage   | clientAuth, id-kp-cmcRA                  |
| TCG OIDs             | tcg-at-tpmManufacturer, tcg-at-tpmModel  |
| Validity             | Device lifetime                          |
| Key Algorithm        | ECDSA P-256 (TPM-bound)                  |

## Key Storage Integration

```
┌───────────────────────────────────────────────────────────────────┐
│                      Key Storage Backends                         │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  go-xkms Unified Interface                                    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  KeyStore Interface                                         │  │
│  │  ┌────────────────────────────────────────────────────────┐│  │
│  │  │ Create() │ Get() │ Sign() │ Verify() │ Delete()        ││  │
│  │  └────────────────────────────────────────────────────────┘│  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐ │
│  │   TPM Backend    │  │  PKCS#11 Backend │  │ Software Backend │ │
│  ├──────────────────┤  ├──────────────────┤  ├──────────────────┤ │
│  │                  │  │                  │  │                  │ │
│  │ • Hardware keys  │  │ • HSM keys       │  │ • File-based     │ │
│  │ • PCR binding    │  │ • Smartcards     │  │ • Dev/test       │ │
│  │ • Attestation    │  │ • Enterprise HSM │  │ • Encrypted      │ │
│  │                  │  │                  │  │                  │ │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘ │
│           │                     │                     │           │
│           ▼                     ▼                     ▼           │
│  ┌────────┴─────────┐  ┌────────┴─────────┐  ┌────────┴─────────┐ │
│  │ /dev/tpmrm0      │  │ PKCS#11 Library  │  │ ${platform-dir}/ │ │
│  │ TPM 2.0 Device   │  │ (SoftHSM, Luna)  │  │ keys/            │ │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘ │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### Key Configuration

```yaml
# CA key storage configuration
certificate-authority:
  platform-ca: 1
  identity:
    - # Root CA
      key-algorithm: ECDSA
      key-size: 384
      keystore-type: tpm2           # software, tpm2, pkcs11
      keystores:
        tpm2:
          srk-handle: 0x81000001
          srk-auth: "kms://ca/root/tpm2/srk-auth?ensure=true&len=32&enc=raw"
          platform-policy: true
      keys:
        - algorithm: ECDSA
          ecc:
            curve: P-384
          signature-algorithm: ECDSA-SHA384
          hash: SHA-384
          store: tpm2
          password: "kms://ca/root/keys/0/password?ensure=true&len=32&enc=base64"
          tpm-policy: platform
      valid: 20
      subject:
        cn: root-ca.example.com
        organization: Example Corp
        country: US
      sans:
        dns:
          - root-ca.example.com

    - # TLS CA (Intermediate)
      key-algorithm: RSA
      key-size: 4096
      keystore-type: pkcs11
      keystores:
        pkcs11:
          library: /usr/lib/softhsm/libsofthsm2.so
          slot: 0
          label: TLS-CA-Key
          pin: "kms://ca/tls/pkcs11/pin"
          platform-policy: true
      keys:
        - algorithm: RSA
          rsa:
            size: 4096
          signature-algorithm: SHA256-RSA
          hash: SHA-256
          store: pkcs11
          password: "kms://ca/tls/keys/0/password?ensure=true&len=32&enc=base64"
          tpm-policy: platform
      valid: 10
      subject:
        cn: tls-ca.example.com
        organization: Example Corp
        country: US
      sans:
        dns:
          - tls-ca.example.com

    - # Device CA (Intermediate)
      key-algorithm: ECDSA
      key-size: 256
      keystore-type: tpm2
      keystores:
        tpm2:
          srk-handle: 0x81000001
          srk-auth: "kms://ca/device/tpm2/srk-auth?ensure=true&len=32&enc=raw"
          platform-policy: true
      keys:
        - algorithm: ECDSA
          ecc:
            curve: P-256
          signature-algorithm: ECDSA-SHA256
          hash: SHA-256
          store: tpm2
          password: "kms://ca/device/keys/0/password?ensure=true&len=32&enc=base64"
          tpm-policy: platform
      valid: 10
      subject:
        cn: device-ca.example.com
        organization: Example Corp
        country: US
      sans:
        dns:
          - device-ca.example.com
```

## Certificate Issuance Flow

```
┌───────────────────────────────────────────────────────────────────┐
│                   Certificate Issuance Flow                       │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. Certificate Request                                           │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Client                          CA Service                  │  │
│  │                                                             │  │
│  │ Generate Key    ─────▶                                      │  │
│  │ (TPM/SW)                                                    │  │
│  │                                                             │  │
│  │ Create CSR      ─────▶   Validate Request                   │  │
│  │ (PKCS#10)                • Subject name                     │  │
│  │                          • Key usage                        │  │
│  │                          • Policy compliance                │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  2. Certificate Generation                                        │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ CA Service                                                  │  │
│  │                                                             │  │
│  │ Build TBS Certificate                                       │  │
│  │ • Subject from CSR                                          │  │
│  │ • Issuer from CA cert                                       │  │
│  │ • Serial number                                             │  │
│  │ • Validity period                                           │  │
│  │ • Extensions                                                │  │
│  │                                                             │  │
│  │ Sign TBS        ─────▶   KeyStore.Sign()                    │  │
│  │                          (TPM/PKCS11/SW)                    │  │
│  │                                                             │  │
│  │ Encode Certificate                                          │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  3. Certificate Delivery                                          │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ CA Service                       Client                     │  │
│  │                                                             │  │
│  │ Store in CA DB  ─────▶                                      │  │
│  │                                                             │  │
│  │ Return Cert     ─────▶   Store Certificate                  │  │
│  │ (PEM/DER)                (KeyStore)                         │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Revocation Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                   Revocation Infrastructure                       │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  CRL Distribution                                                 │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ CA Service                                                  │  │
│  │                                                             │  │
│  │ Certificate Revoked                                         │  │
│  │       │                                                     │  │
│  │       ▼                                                     │  │
│  │ Update CRL Database                                         │  │
│  │       │                                                     │  │
│  │       ▼                                                     │  │
│  │ Generate New CRL ───▶ Sign with CA Key                      │  │
│  │       │                                                     │  │
│  │       ▼                                                     │  │
│  │ Publish to CDP (CRL Distribution Point)                     │  │
│  │   • HTTP endpoint                                           │  │
│  │   • File system                                             │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  OCSP Responder                                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Client          OCSP Responder          CA Database         │  │
│  │                                                             │  │
│  │ OCSP Request  ──────▶                                       │  │
│  │ (cert serial)          Query Status  ──────▶               │  │
│  │                                      ◀──────  Status        │  │
│  │ ◀──────  OCSP Response                                      │  │
│  │          (good/revoked/unknown)                             │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Database Schema

```
┌───────────────────────────────────────────────────────────────────┐
│                      CA Database Schema                           │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  certificates                                                     │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ serial_number  │ PRIMARY KEY, unique certificate ID         │  │
│  │ subject_cn     │ Subject common name                        │  │
│  │ issuer_cn      │ Issuing CA common name                     │  │
│  │ not_before     │ Validity start                             │  │
│  │ not_after      │ Validity end                               │  │
│  │ status         │ active, revoked, expired                   │  │
│  │ revoked_at     │ Revocation timestamp                       │  │
│  │ revoke_reason  │ CRL reason code                            │  │
│  │ certificate    │ DER-encoded certificate                    │  │
│  │ key_attrs      │ Key attributes JSON                        │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ca_keys                                                          │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ ca_cn          │ CA common name                             │  │
│  │ algorithm      │ RSA, ECDSA, Ed25519                        │  │
│  │ store_type     │ tpm, pkcs11, software                      │  │
│  │ handle         │ TPM handle or PKCS#11 label                │  │
│  │ certificate    │ CA certificate                             │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Security Considerations

| Concern                | Mitigation                                  |
|------------------------|---------------------------------------------|
| Root CA compromise     | Offline storage, HSM, ceremony procedures   |
| Private key theft      | TPM/HSM storage, no software extraction     |
| Unauthorized issuance  | Policy engine, audit logging                |
| Revocation bypass      | CRL/OCSP required, short validity periods   |
| Name collision         | Strict validation, namespace policies       |

## QuicBaaS KMS Integration

The CA uses QuicBaaS's KMS service for signing key management through the
QuicBaaSKMSAdapter (`pkg/ca/quicbaas/kms_adapter.go`).

### Signing Key Flow

```
┌───────────────────────────────────────────────────────────────────┐
│                   CA Signing Key Access                           │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  CA Service                   QuicBaaSKMSAdapter   go-quicbaas    │
│      │                               │                  │         │
│      │ GetSigningKey(tenant,purpose) │                  │         │
│      │──────────────────────────────▶│                  │         │
│      │                               │                  │         │
│      │                               │ GetKey(keyID)    │         │
│      │                               │─────────────────▶│         │
│      │                               │◀─────────────────│         │
│      │                               │                  │         │
│      │                               │ xkms.SignerByID()      │
│      │                               │─────────────────▶│         │
│      │                               │◀─────────────────│         │
│      │                               │                  │         │
│      │◀──────────────────────────────│ crypto.Signer    │         │
│      │                               │                  │         │
│      │ signer.Sign(digest)           │                  │         │
│      │ (uses TPM/HSM/SW backend)     │                  │         │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### Key ID Convention

Keys are identified by `tenantID/purpose` format:
- `tenant-a/tenant-root-ca` - Tenant A's root CA key
- `tenant-a/ocsp` - Tenant A's OCSP signing key
- `tenant-b/tls-ca` - Tenant B's TLS CA key

### Backend Abstraction

The CA does not interact with backends directly. QuicBaaS's XKMS
abstracts all backend operations:

| Backend | Use Case |
|---------|----------|
| TPM 2.0 | Hardware-bound CA keys, attestation |
| PKCS#11 | Enterprise HSM integration, FIPS compliance |
| Software | Development, testing, cloud deployments |

## Related Documentation

- [README](user.md) - CA module overview
- [ACME](acme.md) - ACME server documentation
- [Configuration](configuration.md) - Configuration reference
- [API Reference](api.md) - Certificate management API
- [TPM Architecture](../tpm/architecture.md) - TPM key storage
- [KMS Architecture](../kms/architecture.md) - Key management service
