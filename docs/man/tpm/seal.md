% tpadm tpm seal | Trusted Platform Commands Manual

# NAME

**tpm seal** - Retrieves a sealed seal from the tpm TPM store.

# SYNOPSIS

**tpm seal** [*ARGUMENT*] [*OPTIONS*]

# DESCRIPTION

**tpm seal** - Retrieves a sealed seal from the tpm TPM 2.0 key store.


# OPTIONS

* **\--cn**:

    The key common name

* **\--store**:

    The key store module to query for the key [ pkcs8 | pkcs11 | tpm2 ]

* **\--algorithm**:

    The key algorithm [ rsa | ecdsa | ed25519 ]

* **\--auth**:

    The parent key seal authorization value

* **\--policy**:

    When true, the a PCR policy session is used to access the sealed seal


## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

# NOTES


# EXAMPLES

## Retrieve the default Root CA seal (PKCS8, RSA)
```bash
tpadm tpm seal --cn root-ca.example.com
```

## Retrieve the Root CA seal using provided store and key algorithm
```bash
tpadm tpm seal --cn root-ca.example.com --algorithm ecdsa --store pkcs11
```

# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
