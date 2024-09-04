# TPM Keys

The following image shows a fully provisioned TPM by the Trusted Platform. 

The Trusted Platform supports an arbitrary number of key chains. Each key chain supports 1 or more supported Key Store Modules. 

Each Certificate Authority has it's own key chain with any number of Key Store Modules supported by the Trusted Platform.

![Trusted Platform Provisioned TPM](assets/tpm-provisioned.drawio.png?raw=true "Trusted Platform Provisioned TPM")


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

4. Initial Device ID: A fundamental aspect of a Device Identity is the ability to use that identity for network authentication, with the
remote entity (the relying party) having confidence that the device is what it is represented to be.


## References

[TPM 2.0 Provisioning Guidance Published](https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf)

[TPM 2.0 Keys for Device Identity and Attestation](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf)

[NIST SP 800-57](https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p3_r2_pub.pdf)

https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt1r5.pdf

https://dev.to/nandhithakamal/tpm-part-1-4emf

https://ericchiang.github.io/post/tpm-keys/

US NIST SP800-57 in section 5.2 does not allow the same key to be used for both decryption and signing, and recommends that applications not share keys.
