% tpadm ca uninstall-ca-certificates | Trusted Platform Commands Manual

# NAME

**ca uninstall-ca-certificates** - Uninstalls the Certificate Authority Certificates

# SYNOPSIS

**ca uninstall-ca-certificates** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**ca uninstall-ca-certificates** - Deletes the Root and Intermediate Certificate Authority certificates from the operating system trusted certificate store.

# OPTIONS


## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

# NOTES

This command requires root or sudo privileges.

# EXAMPLES

## Uninstall Certificate Authority certificates from local OS trust store
```bash
sudo tpadm ca uninstall-ca-certificates
```

# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
