% tpadm ca revoke | Trusted Platform Commands Manual

# NAME

**ca revoke** - Revokes an issued certificate

# SYNOPSIS

**ca revoke** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**ca revoke** - Add the certificate to the CA Certificate Revocation List and delete the certificate and keys from the backend stores.

# OPTIONS


## References

[common options](common/options.md) collection of common options that provide
revokermation many users may expect.

# NOTES

# EXAMPLES

## Revoke RSA TPM 2.0 end entity certificate
```bash
sudo tpadm ca revoke --cn webserver.mydomain.com --store tpm2 --algorithm rsa
```

## Revoke ECDSA PKCS #11 end entity certificate
```bash
sudo tpadm ca revoke --cn webserver.mydomain.com --store pkcs11 --algorithm ecdsa
```

## Remove PKCS #8 Ed25519 end entity certificate
```bash
sudo tpadm ca revoke --cn webserver.mydomain.com --store pkcs8 --algorithm ed25519
```

# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
