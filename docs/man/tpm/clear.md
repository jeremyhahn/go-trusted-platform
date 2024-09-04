% tpadm tpm clear | Trusted Platform Commands Manual

# NAME

**tpm clear** - Display TPM clearrmation

# SYNOPSIS

**tpm clear** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm clear** - This command removes all TPM context associated with a specific Owner.

The clear operation will:

• flush resident objects (persistent and volatile) in the Storage and Endorsement hierarchies;
• delete any NV Index with TPMA_NV_PLATFORMCREATE == CLEAR;
• change the storage primary seed (SPS) to a new value from the TPM’s random number generator
(RNG),
• change shProof and ehProof,
NOTE 1 The proof values are permitted to be set from the RNG or derived from the associated new
Primary Seed. If derived from the Primary Seeds, the derivation of ehProof shall use both the
SPS and EPS. The computation shall use the SPS as an HMAC key and the derived value may
then be a parameter in a second HMAC in which the EPS is the HMAC key. The reference
design uses values from the RNG.
• SET shEnable and ehEnable;
• set ownerAuth, endorsementAuth, and lockoutAuth to the Empty Buffer;
• set ownerPolicy, endorsementPolicy, and lockoutPolicy to the Empty Buffer;
• set Clock to zero;
• set resetCount to zero;
• set restartCount to zero; and
• set Safe to YES.
• increment pcrUpdateCounter

This command requires Platform Authorization or Lockout Authorization. If TPM2_ClearControl() has
disabled this command, the TPM shall return TPM_RC_DISABLED.

If this command is authorized using lockoutAuth, the HMAC in the response shall use the new
lockoutAuth value (that is, the Empty Buffer) when computing the response HMAC.
	
See TPM 2.0 Part 3: Commands - Section 24.6: TPM2_Clear
https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-3-Commands.pdf

# OPTIONS

  
## References

[common options](common/options.md) collection of common options that provide
clearrmation many users may expect.

[Trusted Platform Module Library Part 3: Commands - Section 24.6: TPM2_Clear](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-3-Commands.pdf)

# NOTES

# EXAMPLES

## Clear the Endorsement hierarchy
```bash
tpadm tpm clear -h e
```

# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
