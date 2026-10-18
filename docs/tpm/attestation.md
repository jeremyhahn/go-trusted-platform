# TPM Attestation

> **Status: REFERENCE** · Last verified: 2026-10-15
> Quote generation, verification and IDevID attestation as built.

This document describes the remote attestation capabilities of the go-trusted-platform,
including quote generation, verification, and IDevID attestation via ACME enroll-01.

## Attestation Overview

Remote attestation proves to a verifier that a platform is in a known, trusted state
by providing cryptographic evidence of boot measurements stored in TPM PCRs.

```
┌───────────────────────────────────────────────────────────────────┐
│                     Remote Attestation Flow                       │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│    Attester (Client)                    Verifier (Server)         │
│    ┌────────────────┐                   ┌────────────────┐        │
│    │                │                   │                │        │
│    │  1. Request  ──────────────────────▶  Generate      │        │
│    │     Nonce                          │  Nonce         │        │
│    │                │                   │                │        │
│    │  2. Receive  ◀──────────────────────  Send Nonce    │        │
│    │     Nonce                          │                │        │
│    │                │                   │                │        │
│    │  3. Generate   │                   │                │        │
│    │     Quote      │                   │                │        │
│    │     (TPM)      │                   │                │        │
│    │                │                   │                │        │
│    │  4. Send     ──────────────────────▶  5. Verify     │        │
│    │     Quote +                        │     Quote      │        │
│    │     PCRs +                         │     Signature  │        │
│    │     EventLog                       │     PCRs       │        │
│    │                │                   │     EventLog   │        │
│    │                │                   │                │        │
│    │  7. Receive  ◀──────────────────────  6. Send       │        │
│    │     Result                         │     Result     │        │
│    │                │                   │                │        │
│    └────────────────┘                   └────────────────┘        │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Quote Generation

A TPM quote is a signed statement of current PCR values:

```
┌───────────────────────────────────────────────────────────────────┐
│                        Quote Structure                            │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  TPMS_ATTEST                                                      │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ magic: TPM_GENERATED_VALUE (0xff544347)                     │  │
│  │ type: TPM_ST_ATTEST_QUOTE                                   │  │
│  │ qualifiedSigner: AK name (hash of public area)              │  │
│  │ extraData: SHA-256(nonce || channel binding)                │  │
│  │ clockInfo: TPM clock values                                 │  │
│  │ firmwareVersion: TPM firmware version                       │  │
│  │ attested:                                                   │  │
│  │   ┌────────────────────────────────────────────────────────┐│  │
│  │   │ pcrSelect: selected PCR indices                        ││  │
│  │   │ pcrDigest: hash of selected PCR values                 ││  │
│  │   └────────────────────────────────────────────────────────┘│  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  Signature (TPMT_SIGNATURE)                                       │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ sigAlg: TPM_ALG_RSASSA or TPM_ALG_ECDSA                     │  │
│  │ signature: signature over TPMS_ATTEST                       │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### Quote Request Example

```go
// gRPC Quote Request
request := &platformv1.QuoteRequest{
    PcrIndices: []uint32{0, 1, 2, 3, 7, 8, 9},
    Nonce:      nonce,
}

response, err := client.Quote(ctx, request)
// response.Quote              - TPMS_ATTEST structure
// response.Signature          - Quote signature
// response.EventLog           - TPM event log
// response.ChannelBinding     - TLS exporter value the nonce was bound to
// response.SignatureAlgorithm - Scheme the quote was signed with
```

`TPMService.Quote` (`pkg/api/daemon/tpm_grpc_service.go`) reads only
`pcr_indices` and `nonce`; `ak_handle`, `ak_password` and `pcr_bank` are not
used, and `pcr_values` is not filled (read them with `GetPCRs`). The TPM never
quotes the nonce as sent: it quotes SHA-256(nonce || channel binding), where the
binding is the TLS exporter of the connection the request arrived on (#482,
`pkg/attestation/channelbind`). A request with no TLS connection is refused.

## Quote Verification

```
┌───────────────────────────────────────────────────────────────────┐
│                      Verification Process                         │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. Verify Signature                                              │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ • Load AK public key                                        │  │
│  │ • Verify signature over quote data                          │  │
│  │ • Check signature algorithm matches AK                      │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  2. Verify Quote Structure                                        │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ • Check magic value (TPM_GENERATED_VALUE)                   │  │
│  │ • Verify type is TPM_ST_ATTEST_QUOTE                        │  │
│  │ • Confirm extraData matches the (bound) nonce               │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  3. Verify PCR Values                                             │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ • Compute hash of provided PCR values                       │  │
│  │ • Compare with pcrDigest in quote                           │  │
│  │ • Validate PCRs match expected policy                       │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  4. Verify Event Log (Optional)                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ • Replay event log to compute expected PCRs                 │  │
│  │ • Compare computed values with attested values              │  │
│  │ • Validate event log entries                                │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### Verification Example

```go
// gRPC Verify Quote Request
verifyRequest := &platformv1.VerifyQuoteRequest{
    Quote:              response.Quote,
    Signature:          response.Signature,
    AkPublic:           akPublicKey, // empty: the node's own IAK
    Nonce:              nonce,
    ChannelBinding:     response.ChannelBinding,
    SignatureAlgorithm: response.SignatureAlgorithm, // required
}

verifyResponse, err := client.VerifyQuote(ctx, verifyRequest)
// verifyResponse.Verified - true if the checks below passed
// verifyResponse.Message  - verification result details
```

`TPMService.VerifyQuote` performs steps 1 and 2 above: it checks the
TPMS_ATTEST magic and type, compares `extraData` with the nonce (or with
SHA-256(nonce || channel_binding) when a binding is given), and verifies the
signature under `signature_algorithm`; an absent or unknown algorithm is
refused. Empty `quote` or `signature` is `InvalidArgument`. It does not compare
`expected_pcrs` and does not fill `actual_pcrs`: steps 3 and 4 are left to the
caller.

## IDevID Attestation via ACME enroll-01

The platform implements device attestation using the ACME enroll-01 challenge
type for IDevID certificate issuance. A device runs it with `platformctl tpm
enroll` (`pkg/cli/commands/tpm/enroll.go`); the daemon registers the `enroll-01`
verifier in `pkg/daemon/commands/serve.go`, and the TCG-CSR handling and
credential activation below run in go-xkms, reached through the go-quicbaas SDK:

```
┌───────────────────────────────────────────────────────────────────┐
│                  ACME enroll-01 Challenge Flow                    │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│    Client (Device)                       ACME Server              │
│    ┌────────────────┐                   ┌────────────────┐        │
│    │                │                   │                │        │
│    │  1. New Order ─────────────────────▶  Create Order │        │
│    │     (IDevID)                       │                │        │
│    │                │                   │                │        │
│    │  2. Get      ◀─────────────────────  Return        │        │
│    │     Challenge                      │  Challenge     │        │
│    │                │                   │  (enroll-01)   │        │
│    │                │                   │                │        │
│    │  3. Prepare    │                   │                │        │
│    │     TCG-CSR    │                   │                │        │
│    │     • IAK pub  │                   │                │        │
│    │     • IDevID   │                   │                │        │
│    │       CSR      │                   │                │        │
│    │     • EK cert  │                   │                │        │
│    │                │                   │                │        │
│    │  4. POST     ──────────────────────▶  5. Validate   │        │
│    │     CSR to                         │     EK Cert    │        │
│    │     challenge                      │     chain      │        │
│    │     endpoint                       │                │        │
│    │                │                   │                │        │
│    │  6. Receive  ◀─────────────────────  Generate      │        │
│    │     Credential                     │  MakeCredential│        │
│    │     Blob                           │  (encrypted    │        │
│    │                │                   │   secret)      │        │
│    │                │                   │                │        │
│    │  7. Activate   │                   │                │        │
│    │     Credential │                   │                │        │
│    │     (TPM)      │                   │                │        │
│    │                │                   │                │        │
│    │  8. POST     ──────────────────────▶  9. Verify     │        │
│    │     Decrypted                      │     Secret     │        │
│    │     Secret                         │     matches    │        │
│    │                │                   │                │        │
│    │  10. Download ◀────────────────────  11. Issue     │        │
│    │      IDevID                        │     IDevID     │        │
│    │      Cert                          │     Cert       │        │
│    │                │                   │                │        │
│    └────────────────┘                   └────────────────┘        │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### TCG-CSR-IDEVID Structure

```
┌───────────────────────────────────────────────────────────────────┐
│                        TCG-CSR-IDEVID                             │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  version: 1                                                       │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ attestation_type: TPM20                                     │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  identity_object:                                                 │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ iak_public: TPM2B_PUBLIC (IAK public key)                   │  │
│  │ iak_name: TPM2B_NAME (hash of IAK public area)              │  │
│  │ idevid_csr: PKCS#10 CSR signed by IAK                       │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  endorsement_object:                                              │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ ek_certificate: X.509 EK certificate (PEM/DER)              │  │
│  │ ek_public: TPM2B_PUBLIC (EK public key)                     │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### Credential Activation

The ActivateCredential operation proves:
1. The EK is on the same TPM as the IAK
2. The device possesses the EK private key

```
┌───────────────────────────────────────────────────────────────────┐
│                      Credential Activation                        │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Server (MakeCredential):                                         │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ 1. Generate random secret                                   │  │
│  │ 2. Encrypt secret with EK public key                        │  │
│  │ 3. Bind to IAK name (credentialBlob)                        │  │
│  │ 4. Send encrypted credential to client                      │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  Client (ActivateCredential):                                     │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ 1. Load EK into TPM                                         │  │
│  │ 2. Load IAK into TPM                                        │  │
│  │ 3. Call TPM2_ActivateCredential                             │  │
│  │    • Uses EK to decrypt                                     │  │
│  │    • Verifies IAK name binding                              │  │
│  │ 4. Return decrypted secret to server                        │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Event Log Verification

The platform verifies boot measurements via the TPM event log:

```
┌───────────────────────────────────────────────────────────────────┐
│                      Event Log Processing                         │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  TCG Event Log Entry (EFI_TCG2_EVENT)                             │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ PCRIndex: target PCR                                        │  │
│  │ EventType: type of measurement                              │  │
│  │ Digests[]: hash values (one per algorithm)                  │  │
│  │ EventSize: size of event data                               │  │
│  │ Event[]: event-specific data                                │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  Verification:                                                    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ 1. Start with PCR initial value (all zeros)                 │  │
│  │ 2. For each event:                                          │  │
│  │    PCR[i] = Hash(PCR[i] || event.digest)                    │  │
│  │ 3. Compare computed PCR with attested value                 │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### Event Log Request

```go
// Get TPM Event Log
request := &platformv1.GetEventLogRequest{}

response, err := client.GetEventLog(ctx, request)
// response.EventLog   - Raw binary event log
// response.Format     - Always "tcg2"
// response.EventCount - Number of parsed events
// response.Entries    - Parsed events (PCR index, type, digests, string)
```

The request's `format` is not read. When the log cannot be parsed, only the
raw blob is returned.

## PCR Reading

```go
// Get specific PCR values
request := &platformv1.GetPCRsRequest{
    Indices: []uint32{0, 1, 2, 3, 7, 8, 9},
    Bank:    platformv1.PCRBank_PCR_BANK_SHA256,
}

response, err := client.GetPCRs(ctx, request)
for _, pcr := range response.PcrValues {
    fmt.Printf("PCR[%d]: %x\n", pcr.Index, pcr.Value)
}
```

With no `indices` the daemon reads PCRs 0-23; with `bank` unset it returns
every bank the TPM supports.

## Attestation Policies

There is no per-policy PCR list in the configuration (`attestation.policies`
does not exist). The `attestation:` section (`config.Attestation`,
`pkg/config/attestation.go`) carries the quote PCR selection and one policy
engine block:

```yaml
attestation:
  quote-pcrs: [0, 7, 9]           # example: PCRs to quote
  policy:
    engine: opa                   # opa or rego
    policy-dir: /etc/trusted-platform/policies
    default-action: deny          # allow or deny
```

The `policy` defaults are `opa`, `/etc/trusted-platform/policies` and `deny`;
validation (`PolicyConfig.Validate`) refuses an `engine` without a
`policy-dir`. Policies themselves are Rego files in `policy-dir`
(`pkg/policy/opa`). The shipped `single-node/default.yaml` has no
`attestation:` block.

## Error Handling

| Error Condition         | Response                                     |
|-------------------------|----------------------------------------------|
| Invalid nonce           | Reject quote, require fresh attestation      |
| Signature verification  | Reject quote, log failure                    |
| PCR mismatch            | Policy-dependent (`default-action` allow/deny) |
| Event log mismatch      | Additional verification required             |
| AK not trusted          | Require AK certification                     |
| EK certificate invalid  | Reject device enrollment                     |

## Related Documentation

- [README](README.md) - TPM module overview
- [Architecture](architecture.md) - TPM integration details
- [Sealing](sealing.md) - PCR-based data protection
- [PCRs](pcrs.md) - Platform Configuration Register reference
- [Security](security.md) - Security considerations and CVEs
- [API Reference](api-reference.md) - gRPC attestation API
- [CA ACME](../ca/acme.md) - ACME server and enroll-01

## References

### TCG Specifications

- [TCG Remote Attestation](https://trustedcomputinggroup.org/resource/tcg-attestation/)
- [TPM 2.0 Keys for Device Identity](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf)
- [TCG TPM 2.0 Provisioning Guidance](https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf)

### Implementation Guides

- [TPM 2.0 Software Stack Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html)
- [Remote Attestation with tpm2-tools](https://tpm2-software.github.io/2020/06/12/Remote-Attestation-With-tpm2-tools.html)
- [TPM Remote Attestation with go-tpm and gRPC](https://github.com/salrashid123/go_tpm_remote_attestation)
- [TPM-based TLS using Attested Keys](https://github.com/salrashid123/tls_ak)
- [Issue CA-signed Certificate using TPM Public Key](https://gist.github.com/salrashid123/10320c153ad6acdc31854c9775c43c0d)

### Standards

- [ACME Device Attestation Draft](https://datatracker.ietf.org/doc/html/draft-acme-device-attest-03)
