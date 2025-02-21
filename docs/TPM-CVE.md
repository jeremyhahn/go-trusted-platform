# TPM Common Vulnerabilities and Exposures


## [CVE-2024-29040](https://nvd.nist.gov/vuln/detail/cve-2024-29040)

This repository hosts source code implementing the Trusted Computing Group's (TCG) TPM2 Software Stack (TSS). The JSON Quote Info returned by Fapi_Quote has to be deserialized by Fapi_VerifyQuote to the TPM Structure `TPMS_ATTEST`. For the field `TPM2_GENERATED magic` of this structure any number can be used in the JSON structure. The verifier can receive a state which does not represent the actual, possibly malicious state of the device under test. The malicious device might get access to data it shouldn't, or can use services it shouldn't be able to. This issue has been patched in version 4.1.0.

## [CVE-2024-29039](https://nvd.nist.gov/vuln/detail/cve-2024-29039)

tpm2 is the source repository for the Trusted Platform Module (TPM2.0) tools. This vulnerability allows attackers to manipulate tpm2_checkquote outputs by altering the TPML_PCR_SELECTION in the PCR input file. As a result, digest values are incorrectly mapped to PCR slots and banks, providing a misleading picture of the TPM state. This issue has been patched in version 5.7.

## [CVE-2023-1017](https://nvd.nist.gov/vuln/detail/cve-2023-1017)

An out-of-bounds write vulnerability exists in TPM2.0's Module Library allowing writing of a 2-byte data past the end of TPM2.0 command in the CryptParameterDecryption routine. An attacker who can successfully exploit this vulnerability can lead to denial of service (crashing the TPM chip/process or rendering it unusable) and/or arbitrary code execution in the TPM context.

## [CVE-2023-1018](https://nvd.nist.gov/vuln/detail/cve-2023-1018)

An out-of-bounds read vulnerability exists in TPM2.0's Module Library allowing a 2-byte read past the end of a TPM2.0 command in the CryptParameterDecryption routine. An attacker who can successfully exploit this vulnerability can read or access sensitive data stored in the TPM.


# References

[Vulnerabilities in the TPM 2.0 reference implementation code](https://blog.quarkslab.com/vulnerabilities-in-the-tpm-20-reference-implementation-code.html)
