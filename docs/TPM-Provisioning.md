# TPM Provisioning

This document describes the provisioning details used by the Trusted Platform to provision a new platform.

# Auhtorization Implementation

The Trusted Platform uses the "less complex" implementation mentioned in Section 7.2.2 - Implementation options - from the TCG TPM 2.0 Keys for Device Identity and Attestation. 

An enterprise may safely configure the TPM per the "most complex" implementation option using a Delegation Policy following provisioning the platform using the TSS command line tools.

Likewise, the "simplest implementation" may also be safely implemented by the Platform Administrator or Owner following provisioning by using the same TSS command line tools.

# References

https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf

https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf

https://trustedcomputinggroup.org/wp-content/uploads/TCG-OID-Registry-Version-1.00-Revision-0.74_10July24.pdf

https://reference.opcfoundation.org/Onboarding/v105/docs/5.1

https://datatracker.ietf.org/doc/html/draft-acme-device-attest-03