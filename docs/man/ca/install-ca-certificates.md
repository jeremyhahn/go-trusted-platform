% tpadm ca install-ca-certificates | Trusted Platform Commands Manual

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

## Install Certificate Authority certificates to local OS trust store
```bash
sudo tpadm ca install-ca-certificates
```

# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
