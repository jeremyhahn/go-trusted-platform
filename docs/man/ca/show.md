% platformd ca show | Trusted Platform Commands Manual

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> `platformd` has only `serve` and `version`; the CA, TPM and PKCS #11 verbs
> are `platformctl` commands, documented in each feature folder's `cli.md`.

# NAME

**ca show** - Display an x509 certificate

# SYNOPSIS

**ca show** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**ca show** - Print x509 certificate details in human readable and PEM form.

# OPTIONS


## References

[common options](../common/options.md) collection of common options that provide
showrmation many users may expect.

# NOTES

# EXAMPLES

## Display certificate information
```bash
platformd ca show intermediate-ca.example.com
```

# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
