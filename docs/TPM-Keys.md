# TPM Keys

The TPM is a Root of Trust for Reporting.

## Key Hierarchies

1. Endorsement - The endorsement hierarchy is the privacy-sensitive tree and is the hierarchy of choice when the user has privacy concerns. TPM and platform vendors certify that primary keys in this hierarchy are constrained to an authentic TPM attached to an authentic platform.

2. Owner - Also called storage hierarchy, this is intended to be used by the platform owner, i.e., the device owner or user

3. Platform - Intended to be under the control of the platform manufacturer. This is used by the BIOS and System Management Mode (SMM).

4. Null

## Key Types

1. Endorsement Key: The key that the TPM uses in its role as Root of Trust for Reporting. Only used directly to certify Identity Keys (AIKs). Trust in all keys in the system come down to trust in EK.

2. Storage Root Key (SRK): The key that the TPM uses in its role as
Root of Trust for Storage. Used to protect other keys and data via encryption. Users can freely create other keys unless SRK requires authorization


## Administrative Operations

TPM operations which need the EK:

1. Take ownership
2. Clear the TPM
3. Change the SRK
4. Change the Owner(obviously)
5. Allow SRK read using SRK auth (tpm_restrictsrk -a)


## Privacy Concerns

The root key for the AIK is the EK. The goal of the EK is to prove everything comes from a valid TPM. The EK can be use to sign, but there will be a privacy issue, so the intention of the AIK is to prove a valid TPM without exposure of being traced (by the CA issuing certificates or logs along the way).

## References

[TPM 2.0 Keys for Device Identity and Attestation](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf)

[NIST SP 800-57](https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p3_r2_pub.pdf)

https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt1r5.pdf

https://dev.to/nandhithakamal/tpm-part-1-4emf

https://ericchiang.github.io/post/tpm-keys/


## 

US NIST SP800-57 in section 5.2 does not allow the same key to be used for both decryption and signing, and recommends that applications not share keys.
