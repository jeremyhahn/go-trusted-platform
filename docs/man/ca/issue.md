% tpadm ca issue | Trusted Platform Commands Manual

# NAME

**ca issue** - Displays Certificate Authority issuermation

# SYNOPSIS

**ca issue** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**ca issue** - Issue a new TLS certificate

# OPTIONS


## References

[common options](common/options.md) collection of common options that provide
issuermation many users may expect.

# NOTES

# EXAMPLES

## Issue new TPM 2.0 RSA TLS certificate
```bash
sudo tpadm ca issue --cn webserver.mydomain.com --store tpm2 --algorithm rsa
```

## Issue new PKCS #11 ECDSA TLS certificate
```bash
sudo tpadm ca issue --cn webserver.mydomain.com --store pkcs11 --algorithm ecdsa
```

## Issue new PKCS #8 Ed25519 TLS certificate
```bash
sudo tpadm ca issue --cn webserver.mydomain.com --store pkcs8 --algorithm ed25519
```

# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
