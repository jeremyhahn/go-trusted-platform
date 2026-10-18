% platformd ca install-ca-certificates | Trusted Platform Commands Manual

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> `platformd` has only `serve` and `version`; the CA, TPM and PKCS #11 verbs
> are `platformctl` commands, documented in each feature folder's `cli.md`.

# NAME

**ca install-ca-certificates** - Install the Root and Intermediate Certificate Authority public keys to the Operating System trust store.

# SYNOPSIS

**ca install-ca-certificates** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**ca install-ca-certificates** - Installing the Certificate Authority public certificates to the Operating System trust store enables system-wide trust for any certificate issued by the Certificate Authority.

# OPTIONS


## References

[common options](../common/options.md) collection of common options that provide
information many users may expect.

# NOTES

This command requires root or sudo privileges.

# EXAMPLES

## Install Certificate Authority certificates to local OS trust store
```bash
sudo platformd ca install-ca-certificates
```

# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
