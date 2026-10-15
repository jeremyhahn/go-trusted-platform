% platformd tpm info | Trusted Platform Commands Manual

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> `platformd` has only `serve` and `version`; the CA, TPM and PKCS #11 verbs
> are `platformctl` commands, documented in each feature folder's `cli.md`.

# NAME

**tpm info** - Display TPM information

# SYNOPSIS

**tpm info** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm info** - Displays information about the TPM such as manufacturer, model number, firmware version, and handle usage.

# OPTIONS

  
## References

[common options](../common/options.md) collection of common options that provide
information many users may expect.

# NOTES

# EXAMPLES

## Retrieve TPM Information
```bash
platformd tpm info
```

# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
