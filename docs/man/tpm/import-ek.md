% trusted-platform tpm import-ek | TPM Commands Manual

# NAME

**tpm import-ek** - Import an Endorsement Public Key & Certificate

# SYNOPSIS

**tpm import-ek** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm import-ek** - Retrieve the endorsement key public key and certificate. The
certificate is present either on the TCG specified TPM NV indices, the TPM
manufacturer's endorsement certificate hosting server OR local disk. Following
are the conditions dictating the certificate location lookup, in the order they
are executed.

1. NV-Index:

    Default search location when **ARGUMENT** is not specified.

2. Local-Disk:

    Search location when EK certificate could not be found in the NV index.

3. Intel-EK-certificate-server:

    Search location when EK certificate could not be found in the NV index AND
    local disk.

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

The local TPM Endorsement Key is automatically imported to the Certificate
Authority during platform initialization & setup. This command is intended
to re-import an EK into a platform that's already been initialized, for
example, migrating the CA to a new host.

Importing from the local file system assumes the use of a tool such as [tpm2_getekcertificate](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_getekcertificate.1.md) to dump the EK certificate to disk. 

# EXAMPLES

## Import EK certificate from NV Index, local disk, or TPM manufacturer
```bash
trusted-platform tpm import-ek -f ECcert.bin -p intermediate-password
```

# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
