# RATS and attestation reference standards

> **Status: REFERENCE** · Last verified: 2026-10-20

The standards in this directory are copied verbatim and never edited; a new revision replaces its file. Pinned drafts have a standards-watch line in [ROADMAP.md](../../../ROADMAP.md) Dependencies.

| File | Title | Status | Implemented in |
|---|---|---|---|
| [rfc9334.txt](rfc9334.txt) | Remote ATtestation procedureS (RATS) Architecture | RFC | `pkg/attestation/`; appraisal policy in `pkg/policy/opa/policies/`; `pkg/sdn/policy/` outcomes |
| [rfc9711.txt](rfc9711.txt) | The Entity Attestation Token (EAT) | RFC | `pkg/attestation/` |
| [rfc9781.txt](rfc9781.txt) | A Concise Binary Object Representation (CBOR) Tag for Unprotected CBOR Web Token Claims Sets (UCCS) | RFC | `pkg/attestation/` |
| [rfc9782.txt](rfc9782.txt) | Entity Attestation Token (EAT) Media Types | RFC | `pkg/attestation/` |
| [rfc9999.txt](rfc9999.txt) | Remote ATtestation procedureS (RATS) Conceptual Message Wrapper (CMW) | RFC | `pkg/attestation/` |
| [rfc10013.txt](rfc10013.txt) | Entity Attestation Token (EAT) Measured Component | RFC | `pkg/attestation/`; `pkg/policy/opa/policies/` |
| [rfc9683.txt](rfc9683.txt) | Remote Integrity Verification of Network Devices Containing Trusted Platform Modules | RFC | `pkg/sdn/policy/` quarantine and remediation; enrollment paths (`pkg/device/`, `pkg/webservice/v1/device/`, `pkg/api/daemon/`, `pkg/installer/`, `pkg/firstboot/`) |
| [draft-ietf-rats-corim-11.txt](draft-ietf-rats-corim-11.txt) | Concise Reference Integrity Manifest (CoRIM) | pinned draft, revision -11 | `pkg/attestation/`; `pkg/policy/opa/policies/` |
| [draft-ietf-lamps-csr-attestation-30.txt](draft-ietf-lamps-csr-attestation-30.txt) | Use of Remote Attestation with Certification Signing Requests | pinned draft, revision -30 | enrollment paths (`pkg/device/`, `pkg/webservice/v1/device/`, `pkg/api/daemon/`, `pkg/installer/`, `pkg/firstboot/`) |
