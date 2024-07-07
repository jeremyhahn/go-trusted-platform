# TPM Keys

The TPM is a Root of Trust for Reporting.

## Key Hierarchies

1. Endorsement - The endorsement hierarchy is the privacy-sensitive tree and is the hierarchy of choice when the user has privacy concerns. TPM and platform vendors certify that primary keys in this hierarchy are constrained to an authentic TPM attached to an authentic platform.

2. Owner - Also called storage hierarchy, this is intended to be used by the platform owner, i.e., the device owner or user

3. Platform - Intended to be under the control of the platform manufacturer. This is used by the BIOS and System Management Mode (SMM).

4. Null

## Key Types

1. Endorsement Key: The key that the TPM uses in its role as Root of Trust for Reporting. Only used directly to certify Identity Keys (AIKs). Trust in all keys in the system come down to trust in the EK.

2. Storage Root Key (SRK): The key that the TPM uses in its role as
Root of Trust for Storage. Used to protect other keys and data via encryption. Users can freely create other keys unless SRK requires authorization

3. Attestation Key: The key that's used as a signing key during Remote Attestation. The process starts with the Verifier obtaining the EK x509 certificate that's issued by the Manufacturer for the EK on the TPM. The verifier sends the Attestor an encrypted secret that only the EK can decrypt. To decrypt the secret, both the AK and the EK must be simultaneously loaded into the TPM (proving the AK is derived from the EK and "that" TPM), using a one-time session that includes a nonce and timestamp (to avoid replay attacks), and proves that it's derived from the EK and a real TPM, by decryting the secret with the EK and sending it back to the Verifier in plain text form for confirmation.


## Privacy Concerns

The EK can not be used to sign. This is for security (encryption and signing keys should be distinct), and because the EK is the identity of the TPM, and therefore it's owner. To prevent using the TPM as a means for tracing, an EK can not be used to sign, and it is fixed to the TPM, meaning it can not be exported or removed.

The root key for the AK is the EK. To enable anonymous attestations, an AK is generated from the EK, and used to sign during the attestation process.


## References

[TPM 2.0 Keys for Device Identity and Attestation](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf)

[NIST SP 800-57](https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p3_r2_pub.pdf)

https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt1r5.pdf

https://dev.to/nandhithakamal/tpm-part-1-4emf

https://ericchiang.github.io/post/tpm-keys/


US NIST SP800-57 in section 5.2 does not allow the same key to be used for both decryption and signing, and recommends that applications not share keys.
