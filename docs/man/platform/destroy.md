% platformd platform destroy | Trusted Platform Commands Manual

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> `platformd` has only `serve` and `version`; the CA, TPM and PKCS #11 verbs
> are `platformctl` commands, documented in each feature folder's `cli.md`.

# NAME

**platform destroy** - Destroy the platform data and configurations

# SYNOPSIS

**platform destroy** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**platform destroy** - This command deletes all platform data, including Certificate Authority keys, certifiates, secrets, and blob storage. A TPM2_Clear command is sent to the TPM, restoring it to the manufacturer's factory settings.


# OPTIONS

## References

[common options](../common/options.md) collection of common options that provide
information many users may expect.

# NOTES


# EXAMPLES

## Clear the TPM and destroy all platform data
```bash
platformd platform destroy
```

# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
