% tpadm ca init | Trusted Platform Commands Manual

# NAME

**ca init** - Initialize the Certificate Authorities

# SYNOPSIS

**ca init** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**ca init** - Initializes the Certificate Authority by creating a Root and
Intermediates as specified in the platform configuration file.

# OPTIONS


## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

# NOTES

This command requires root or sudo privileges.

# EXAMPLES

## Import EK certificate from NV Index, local disk, or TPM manufacturer
```bash
sudo tpadm ca init
```

# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
