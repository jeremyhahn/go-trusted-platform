% tpadm platform install | Trusted Platform Commands Manual

# NAME

**platform install** - Perform safe, idempotent installation

# SYNOPSIS

**platform install** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**platform install** - Install performs a safe, modified version of the TCG recommended provisioning guidance procedure intended for platforms that have already been provisioned to some extent by the TPM Manufacturer or Owner. Instead of clearing the hierarchies, setting hierarchy authorizations and provisioning new keys and certificates from scratch, this operation will use pre-existing EK, SRK, IAK and IDevID keys and certificates if they already exist. The provided Security Officer PIN is used as the new Endorsement and Storage hierarchy authorizations during installation. 


# OPTIONS


## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

# NOTES

The current hierarchy authorization is expected to be set to an empty password. You can use the included CLI or TPM2 tools to execute the TPM2_HierarchyChangeAuth command to set the password to an empty password.

This operation is idempotent.

# EXAMPLES

## Perform safe installation
```bash
tpadm platform install
```

# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
