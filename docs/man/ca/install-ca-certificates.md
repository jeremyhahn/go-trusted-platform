% trusted-platform ca install-ca-certificates | TPM Commands Manual

# NAME

**ca install-ca-certificates** - Install the Root and Intermediate Certificate Authority public keys to the Operating System trust store.

# SYNOPSIS

**ca install-ca-certificates** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**ca install-ca-certificates** - Installing the Certificate Authority public certificates to the Operating System trust store enables system-wide trust for any certificate issued by the Certificate Authority.

# OPTIONS


## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

# NOTES

This command requires root or sudo privileges.

# EXAMPLES

## Import EK certificate from NV Index, local disk, or TPM manufacturer
```bash
sudo trusted-platform ca install-ca-certificates
```

# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
