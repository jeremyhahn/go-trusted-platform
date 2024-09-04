% tpadm tpm info | Trusted Platform Commands Manual

# NAME

**tpm provision** - Provision a Trusted Platform Module

# SYNOPSIS

**tpm provision** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm provision** - Provision the TPM as outlined in the TCG Provisioning Guidance - Section 11.1 - Provisioning the TPM:

* Clear the TPM
* Set Endorsement, Owner and Lockout authorizations
* Create, verify & persist EK
* Create * persist Shared SRK
* Create & persist IAK
* Create, verify & persist IDevID (if configured)
* Establish baseline PCRs
* Capture Golden Integrity Measurements

This operation requires hierarchy authorization to perform the TPM2_Clear command as the first step outlined in the TCG Provisioning Guidance, and assumes the auth parameter for these hierarchies to be set to an empty password.

The TPM2_ChangeAuth command may be used prior to invoking this operation to set the hierarchy passwords to an empty value so this operation may complete.

After this operation clears the TPM, the provided Security Officer PIN is used to set new Lockout, Endorsement and Owner authorization values. When this operation completes, the Lockout, Endorsement and Owner hierarchies are all owned by the Security Officer, the TPM is fully provisioned and ready for use.

The hierarchy authorization values assigned during this operation may be safely modified to use authorization passwords and/or policies to align the platform with Enterprise or Platform Administrator requirements following this provisioning process.

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

## Retrieve TPM Information
```bash
tpadm tpm provision
```

# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
