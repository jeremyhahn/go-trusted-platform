% tpadm platform destroy | Trusted Platform Commands Manual

# NAME

**platform destroy** - Destroy the platform data and configurations

# SYNOPSIS

**platform destroy** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**platform destroy** - This command deletes all platform data, including Certificate Authority keys, certifiates, secrets, and blob storage. A TPM2_Clear command is sent to the TPM, restoring it to the manufacturer's factory settings.


# OPTIONS

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

# NOTES


# EXAMPLES

## Clear the TPM and destroy all platform data
```bash
tpadm platform destroy
```

# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
