% platformd ca revoke | Trusted Platform Commands Manual

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> `platformd` has only `serve` and `version`; the CA, TPM and PKCS #11 verbs
> are `platformctl` commands, documented in each feature folder's `cli.md`.

# NAME

**ca revoke** - Revokes an issued certificate

# SYNOPSIS

**ca revoke** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**ca revoke** - Add the certificate to the CA Certificate Revocation List and delete the certificate and keys from the backend stores.

# OPTIONS


## References

[common options](../common/options.md) collection of common options that provide
revokermation many users may expect.

# NOTES

# EXAMPLES

## Revoke RSA TPM 2.0 end entity certificate
```bash
platformd ca revoke webserver.mydomain.com tpm2 rsa
```

## Revoke ECDSA PKCS #11 end entity certificate
```bash
platformd ca revoke webserver.mydomain.com pkcs11 ecdsa
```

## Remove PKCS #8 Ed25519 end entity certificate
```bash
platformd ca revoke webserver.mydomain.com pkcs8 ed25519
```

# AUTHOR
    Jeremy Hahn
    https://github.com/jeremyhahn
    https://www.linkdedin.com/in/jeremyhahn

# COPYRIGHT
    (c) 2024 Jeremy Hahn
    All Rights Reserved
