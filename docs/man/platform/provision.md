% tpadm provision platform | Trusted Platform Commands Manual

# NAME

**platform provision** - Provisions a new platform

# SYNOPSIS

**platform provision** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**platform provision** - This command provisions a new platform according to the platform configuration file. The Trusted Platform Module is provisioned according to TCG provisioning guidance, with it's Endorsement Key persisted to the recommended handle index, a Shared Storage Root Key persisted to it's recommended handle index, and the EK certificate extracted from it's NV RAM index handle and imported into the configured Certificate Authority. If an EK certificate can not be found, a new certificate is issued from the configured CA. Initial platform measurements are captured and imported to blob storage for future integrity checks. Key stores and configured services are initialized. When this command completes, the platform and configured services are ready to begin servicing requests.

# OPTIONS

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[TCG Provisioning Guidance](https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf)

[TCG EK Credential Profile](https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-V-2.5-R2_published.pdf)

[TCG Platform Attribute Credential Profile](https://trustedcomputinggroup.org/wp-content/uploads/TCG-Platform-Attribute-Credential-Profile-Version-1.0.pdf)

[TPM 2.0 Keys for Identity and Attestation](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf)

[TCG OID Registry](https://trustedcomputinggroup.org/wp-content/uploads/TCG-OID-Registry-Version-1.00-Revision-0.74_10July24.pdf)

[TCG CPU to TPM Bus Protection Guidance](https://trustedcomputinggroup.org/wp-content/uploads/TCG_-CPU_-TPM_Bus_Protection_Guidance_Active_Attack_Mitigations-V1-R30_PUB-1.pdf)


# NOTES

# EXAMPLES

## Provision a new platform per TCG recommended guidance
```bash
tpadm platform provision
```
# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
