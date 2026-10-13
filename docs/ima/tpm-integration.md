# IMA TPM Integration

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md). There is no `platformctl ima` group and no `tpm pcr` verb, and the attestation manifest carries no IMA data ([architecture.md §9](architecture.md)).

IMA extends file measurements to PCR 10 of the TPM, enabling hardware-backed integrity verification.

## PCR 10 Overview

PCR 10 is designated for IMA measurements by the TCG PC Client Platform specification.

```
┌────────────────────────────────────────────────────────────────────┐
│                        PCR 10 Measurement Flow                      │
├────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │ File Access  │───▶│ IMA Measure  │───▶│ PCR 10 Extend        │  │
│  │ (exec/mmap)  │    │ (sha256)     │    │ TPM2_PCR_Extend()    │  │
│  └──────────────┘    └──────────────┘    └──────────────────────┘  │
│                                                                     │
│  PCR_new = Hash(PCR_old || measurement)                             │
│                                                                     │
└────────────────────────────────────────────────────────────────────┘
```

## PCR Extend Operation

Each IMA measurement extends PCR 10 using:

```
PCR_new = SHA256(PCR_old || measurement_hash)
```

This is a one-way operation - PCR values can only be extended, never decreased.

## Measured Boot Chain

IMA integrates with the platform's measured boot chain:

| PCR | Content | Stability |
|-----|---------|-----------|
| 0 | UEFI Firmware | Stable (per firmware version) |
| 7 | Secure Boot State | Stable (per key enrollment) |
| 9 | Kernel Command Line | Stable (per boot config) |
| **10** | **IMA Measurements** | **Changes every boot** |

### Security Implications

```
┌────────────────────────────────────────────────────────────────────┐
│                        PCR Sealing Guidelines                       │
├────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  LUKS Disk Encryption:                                              │
│    ✓ Use PCRs: 0, 7, 9                                              │
│    ✗ Do NOT use PCR 10 (changes every boot)                         │
│                                                                     │
│  Application Keys (post-boot):                                      │
│    ✓ Use PCRs: 0, 7, 9, 10 (after IMA measurements complete)        │
│                                                                     │
│  Remote Attestation:                                                │
│    ✓ Include PCR 10 for runtime integrity verification              │
│                                                                     │
└────────────────────────────────────────────────────────────────────┘
```

## Reading PCR 10

### Via sysfs

```bash
# SHA-256 bank
cat /sys/class/tpm/tpm0/pcr-sha256/10

# SHA-1 bank (legacy)
cat /sys/class/tpm/tpm0/pcr-sha1/10
```

### Via tpm2-tools

```bash
tpm2_pcrread sha256:10
```

### Via Go Package

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/ima"

verifier := ima.NewVerifier()
pcr10, err := verifier.ReadPCR10FromTPM("sha256")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("PCR 10: %x\n", pcr10)
```

## Computing Expected PCR 10

The expected PCR 10 value can be computed from the IMA event log:

```go
reader := ima.NewReader()
log, err := reader.ReadEventLog()
if err != nil {
    return err
}

verifier := ima.NewVerifier()
expectedPCR, err := verifier.ComputePCR10(log, "sha256")
if err != nil {
    return err
}
fmt.Printf("Expected PCR 10: %x\n", expectedPCR)
```

## Verifying PCR 10

Compare computed PCR 10 against actual TPM value:

```go
reader := ima.NewReader()
log, err := reader.ReadEventLog()
if err != nil {
    return err
}

verifier := ima.NewVerifier()
err = verifier.VerifyPCR10AgainstTPM(log, "sha256")
if err != nil {
    log.Fatal("PCR 10 verification failed:", err)
}
fmt.Println("PCR 10 verification passed")
```

## Remote Attestation

IMA measurements are included in remote attestation quotes:

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Remote Attestation Flow                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Attester                              Verifier                      │
│  ────────                              ────────                      │
│     │                                      │                         │
│     │◀──────── Nonce ──────────────────────│                         │
│     │                                      │                         │
│     │  1. Generate Quote                   │                         │
│     │     - Include PCR 10                 │                         │
│     │     - Sign with AK                   │                         │
│     │                                      │                         │
│     │  2. Collect IMA Event Log            │                         │
│     │                                      │                         │
│     │─────── Quote + Event Log ───────────▶│                         │
│     │                                      │                         │
│     │                    3. Verify Quote    │                         │
│     │                    4. Replay Event Log│                         │
│     │                    5. Compare PCR 10  │                         │
│     │                    6. Check Allowlist │                         │
│     │                                      │                         │
│     │◀─────── Attestation Result ─────────│                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Host Manifest PCR 10

```yaml
# Host manifest includes IMA data
pcrs:
  sha256:
    0: "base64:..."   # UEFI firmware
    7: "base64:..."   # Secure Boot state
    9: "base64:..."   # Kernel command line
    10: "base64:..."  # IMA aggregate

ima:
  policy_hash: "sha256:..."
  aggregate_pcr10: "base64:..."
  violations: 0
  event_count: 1234
```

## PCR Banks

IMA supports multiple hash algorithms corresponding to TPM PCR banks:

| Bank | Hash Size | Use Case |
|------|-----------|----------|
| `sha1` | 20 bytes | Legacy compatibility |
| `sha256` | 32 bytes | Recommended |
| `sha384` | 48 bytes | Higher security |
| `sha512` | 64 bytes | Maximum security |

### Checking Available Banks

```go
verifier := ima.NewVerifier()
banks := verifier.GetAvailablePCRBanks()
for _, bank := range banks {
    fmt.Println("Available:", bank)
}
```

### Bank Selection

The `hash-algorithm` in IMA configuration should match the TPM PCR bank used for verification:

```yaml
ima:
  hash-algorithm: sha256  # Use sha256 PCR bank
```

## Event Log Analysis

### Read Event Log

```go
reader := ima.NewReader()
log, err := reader.ReadEventLog()
if err != nil {
    return err
}

fmt.Printf("Total events: %d\n", log.TotalCount)
fmt.Printf("Unique files: %d\n", log.UniqueFiles)
fmt.Printf("Violations: %d\n", log.ViolationCount)
```

### Find Specific File

```go
events := reader.FindEventByPath(log, "/usr/bin/bash")
for _, event := range events {
    fmt.Printf("Hash: %x\n", event.FileHash)
    fmt.Printf("PCR: %d\n", event.PCR)
}
```

### Get Statistics

```go
stats := reader.GetStatistics(log)
fmt.Printf("By hash algorithm:\n")
for alg, count := range stats.FilesByHashAlg {
    fmt.Printf("  %s: %d\n", alg, count)
}
fmt.Printf("By template:\n")
for template, count := range stats.FilesByTemplate {
    fmt.Printf("  %s: %d\n", template, count)
}
```

## Security Considerations

### PCR 10 Volatility

PCR 10 changes on every boot because:
- Files are measured in different order
- Different files may be accessed
- Timing variations affect measurement sequence

**Do NOT** seal long-term secrets (like LUKS keys) to PCR 10.

### Event Log Integrity

The event log (`/sys/kernel/security/ima/ascii_runtime_measurements`) is not protected by the TPM. An attacker with root access could:
- Modify the event log file
- But NOT modify the PCR 10 value in the TPM

Always verify the event log against the actual PCR 10 value.

### Allowlist Verification

For remote attestation, maintain an allowlist of expected measurements:

```go
verifier := ima.NewVerifier(
    ima.WithAllowlist(map[string][]byte{
        "/usr/bin/bash": expectedHash,
        "/usr/bin/ls":   expectedHash,
    }),
)

result := verifier.VerifyEventLog(log)
if !result.Passed {
    for _, unexpected := range result.UnexpectedFiles {
        fmt.Printf("Unexpected: %s\n", unexpected)
    }
}
```

## CLI Commands

### View PCR 10

```bash
platformctl tpm pcr read --pcr 10 --bank sha256
```

### Verify IMA Measurements

```bash
platformctl ima verify
```

### Show IMA Status

```bash
platformctl ima status
```

### Export Event Log

```bash
platformctl ima export --format json > ima-events.json
```

## Related Documentation

- [Configuration](configuration.md) - IMA configuration options
- [Policies](policies.md) - Policy rules and syntax
- [API Reference](api-reference.md) - Go package API
- [TPM Documentation](../tpm/) - TPM 2.0 integration
- [Attestation](../attestation/) - Remote attestation
