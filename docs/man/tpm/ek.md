% tpadm tpm ek | Trusted Platform Commands Manual

# NAME

**tpm ek** - Retrieve the Endorsement Public Key

# SYNOPSIS

**tpm ek** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm ek** - Retrieve's the TPM Endorsement Public Key in PEM form

# OPTIONS

  * **-r**, **\--rsa**:

    Retrieve the RSA Endorsement Key

  * **-e**, **\--ecc**:

    Retrieve the ECC Endorsement Key

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

# NOTES

# EXAMPLES

## Retrieve TPM 2.0 RSA Endorsement Public Key
```bash
tpadm tpm ek -r
```

## Retrieve TPM 2.0 ECC Endorsement Public Key
```bash
tpadm tpm ek -e
```

# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
