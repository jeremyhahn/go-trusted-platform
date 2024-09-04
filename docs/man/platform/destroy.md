% tpadm platform destroy | Trusted Platform Commands Manual

# NAME

**platform destroy** - Destroy the platform data and configurations

# SYNOPSIS

**platform destroy** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**platform destroy** - This command deletes all platform data, including Certificate Authority keys, certifiates, secrets, and blob storage. A TPM2_Clear command is sent to the TPM, restoring it to the manufacturer's factory settings.


# OPTIONS

  * **-f**, **\--file**=_FILE_ or _STDOUT_:

    The file containing the Endorsement key certificate. If the option isn't specified all the EK certificates retrieved either from the manufacturer
    web hosting, TPM NV indices, or local disk, are output to stdout.

  * **-p**, **\--ca-password**:

    The Certificate Auhority private key password.

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
