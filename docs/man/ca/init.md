% platformd ca init | Trusted Platform Commands Manual

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> `platformd` has only `serve` and `version`; the CA, TPM and PKCS #11 verbs
> are `platformctl` commands, documented in each feature folder's `cli.md`.

# NAME

**ca init** - Initialize the Certificate Authorities

# SYNOPSIS

**ca init** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**ca init** - Initializes the Certificate Authority by creating a Root and
Intermediates as specified in the platform configuration file.

# OPTIONS


## References

[common options](../common/options.md) collection of common options that provide
information many users may expect.

# NOTES

# EXAMPLES

## Initialize the Certificate Authority
```bash
platformd ca init
```

# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
