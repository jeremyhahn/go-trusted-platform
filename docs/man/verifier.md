% platformd verifier | Trusted Platform Commands Manual

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> `platformd` has only `serve` and `version`; the CA, TPM and PKCS #11 verbs
> are `platformctl` commands, documented in each feature folder's `cli.md`.

# NAME

**verifier** - Starts the Verifier gRPC client

# SYNOPSIS

**verifier** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**verifier** - Performs Remote Attestation with the specified Attestor.


# OPTIONS

  * **-a**, **\--attestor**:

    The IP address, host name, or DNS name of the attestor gRPC service


## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

# NOTES


# EXAMPLES

## Start the verifier service
```bash
platformd verifier
```
