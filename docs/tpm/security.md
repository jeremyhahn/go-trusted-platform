# TPM Security Considerations

This document provides security guidance for TPM 2.0 implementations, including known vulnerabilities (CVEs), mitigation strategies, and security best practices.

## Common Vulnerabilities and Exposures (CVEs)

The following CVEs affect TPM 2.0 implementations and should be considered when deploying TPM-based security solutions.

### CVE-2024-29040 - TPM2 TSS Quote Verification Bypass

**Severity:** High

**Affected Component:** TPM2 Software Stack (TSS) - Fapi_Quote/Fapi_VerifyQuote

**Description:**
The JSON Quote Info returned by `Fapi_Quote` must be deserialized by `Fapi_VerifyQuote` to the TPM Structure `TPMS_ATTEST`. For the field `TPM2_GENERATED magic` of this structure, any number can be used in the JSON structure. This allows a malicious device to provide a state that does not represent the actual platform state.

**Impact:**
- Verifier receives falsified attestation state
- Malicious device may gain unauthorized access to data or services
- Remote attestation trust chain is compromised

**Mitigation:**
- Update to tpm2-tss version 4.1.0 or later
- Verify the `magic` field contains exactly `0xff544347` (TPM_GENERATED_VALUE)

**Reference:** [NVD CVE-2024-29040](https://nvd.nist.gov/vuln/detail/cve-2024-29040)

---

### CVE-2024-29039 - TPM2 Tools Quote Verification Bypass

**Severity:** High

**Affected Component:** tpm2-tools - tpm2_checkquote

**Description:**
Attackers can manipulate `tpm2_checkquote` outputs by altering the `TPML_PCR_SELECTION` in the PCR input file. This causes digest values to be incorrectly mapped to PCR slots and banks, providing a misleading picture of the TPM state.

**Impact:**
- PCR verification returns incorrect results
- Attestation can be spoofed by manipulating PCR selection
- Platform integrity verification is unreliable

**Mitigation:**
- Update to tpm2-tools version 5.7 or later
- Validate PCR selection matches expected configuration before verification

**Reference:** [NVD CVE-2024-29039](https://nvd.nist.gov/vuln/detail/cve-2024-29039)

---

### CVE-2023-1017 - TPM 2.0 Out-of-Bounds Write

**Severity:** Critical

**Affected Component:** TPM 2.0 Module Library - CryptParameterDecryption

**Description:**
An out-of-bounds write vulnerability exists in TPM 2.0's Module Library allowing writing of 2-byte data past the end of TPM2.0 command in the `CryptParameterDecryption` routine.

**Impact:**
- Denial of service (crashing the TPM chip/process)
- TPM rendered unusable
- Potential arbitrary code execution in TPM context

**Mitigation:**
- Update TPM firmware to patched version
- Contact TPM manufacturer for firmware updates
- Monitor for abnormal TPM behavior

**Reference:** [NVD CVE-2023-1017](https://nvd.nist.gov/vuln/detail/cve-2023-1017)

---

### CVE-2023-1018 - TPM 2.0 Out-of-Bounds Read

**Severity:** High

**Affected Component:** TPM 2.0 Module Library - CryptParameterDecryption

**Description:**
An out-of-bounds read vulnerability exists in TPM 2.0's Module Library allowing a 2-byte read past the end of a TPM2.0 command in the `CryptParameterDecryption` routine.

**Impact:**
- Sensitive data stored in TPM may be read
- Information disclosure
- Potential for further exploitation

**Mitigation:**
- Update TPM firmware to patched version
- Contact TPM manufacturer for firmware updates

**Reference:** [NVD CVE-2023-1018](https://nvd.nist.gov/vuln/detail/cve-2023-1018)

## Security Best Practices

### TPM Provisioning

1. **Use Strong Authorization Values**
   - Set owner, endorsement, and lockout hierarchy passwords
   - Use high-entropy passwords (minimum 20 characters)
   - Store passwords securely (not in plaintext files)

2. **Verify EK Certificate Chain**
   - Validate EK certificate against manufacturer CA
   - Check certificate revocation status
   - Verify TPM vendor is trusted

3. **Configure Lockout Policy**
   - Set appropriate lockout thresholds
   - Configure recovery interval
   - Document lockout recovery procedures

### Session Security

1. **Enable Encrypted Sessions**
   ```yaml
   tpm:
     sessions:
       encrypt_sessions: true
   ```
   - Protects against CPU-TPM bus snooping attacks
   - Encrypts command parameters and responses

2. **Use HMAC Sessions for Authorization**
   - Prevents replay attacks
   - Provides mutual authentication

3. **Session Audit When Required**
   - Enable for high-security operations
   - Log session activities for forensics

### Key Management

1. **Follow TCG Key Hierarchy Guidance**
   - Use recommended handle allocations
   - Separate keys by purpose (signing vs encryption)
   - NIST SP 800-57: Do not use same key for signing and decryption

2. **Implement Key Rotation**
   - Rotate application keys periodically
   - Re-seal data after key rotation
   - Maintain backup recovery mechanisms

3. **Protect Key Storage**
   - Store sealed key blobs securely
   - Use appropriate file permissions
   - Consider additional encryption layers

### Attestation Security

1. **Validate Quote Responses**
   - Verify `magic` field is `TPM_GENERATED_VALUE`
   - Check nonce matches request
   - Validate signature algorithm

2. **Verify PCR Selection**
   - Confirm expected PCRs are included
   - Validate PCR bank matches policy
   - Check for missing or extra PCRs

3. **Event Log Verification**
   - Replay event log to verify PCR values
   - Check for event log truncation
   - Validate event types

### Access Control

1. **Restrict Device Access**
   ```bash
   # Example udev rule for TPM access control
   KERNEL=="tpmrm*", MODE="0660", GROUP="tss"
   ```

2. **Use Hierarchy Authorization**
   - Set passwords on all hierarchies
   - Use different passwords per hierarchy
   - Consider delegation policies

3. **Implement Audit Logging**
   - Log all TPM operations
   - Monitor for unusual patterns
   - Alert on authorization failures

## FIPS 140-2/3 Compliance

When operating in FIPS mode:

1. **Use Only Approved Algorithms**
   - RSA-2048 or stronger
   - ECDSA P-256 or P-384
   - SHA-256 or stronger
   - AES-128 or AES-256

2. **Disable Non-FIPS Algorithms**
   - SHA-1 for signatures (may be used for legacy PCR banks)
   - RSA key sizes below 2048 bits
   - Weak symmetric ciphers

3. **Verify TPM FIPS Certification**
   - Check NIST CMVP certificate status
   - Verify TPM operates in FIPS mode
   - Document compliance status

## Incident Response

### TPM Lockout Recovery

```bash
# Clear lockout with lockout authorization
platformctl tpm clear --lockout-pin

# Factory reset (requires physical presence or UEFI)
platformctl tpm clear --force
```

### Suspected Compromise

1. **Isolate affected system**
2. **Capture forensic evidence**
   - Export event logs
   - Document PCR values
   - Preserve sealed objects
3. **Assess impact**
   - Identify affected keys and data
   - Determine if re-provisioning required
4. **Re-provision TPM**
   - Clear TPM
   - Generate new keys
   - Re-seal sensitive data

## Related Documentation

- [README](README.md) - TPM module overview
- [Configuration](configuration.md) - Security configuration options
- [Attestation](attestation.md) - Secure attestation practices
- [Architecture](architecture.md) - Security architecture

## References

- [Vulnerabilities in the TPM 2.0 Reference Implementation Code (Quarkslab)](https://blog.quarkslab.com/vulnerabilities-in-the-tpm-20-reference-implementation-code.html)
- [TCG FIPS 140-3 Guidance for TPM 2.0](https://trustedcomputinggroup.org/wp-content/uploads/TCG-FIPS-140-3-Guidance-for-TPM-2.0-Version-1.0-Revision-1_14Feb24.pdf)
- [TCG CPU-TPM Bus Protection Guidance](https://trustedcomputinggroup.org/wp-content/uploads/TCG_-CPU_-TPM_Bus_Protection_Guidance_Active_Attack_Mitigations-V1-R30_PUB-1.pdf)
- [TPM 2.0 Session and Authorization (Springer)](https://link.springer.com/chapter/10.1007/978-1-4302-6584-9_13)
- [NIST SP 800-57 Key Management Recommendations](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt1r5.pdf)
