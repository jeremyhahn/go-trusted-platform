% tpadm attestor | Trusted Platform Commands Manual

# NAME

**attestor** - Starts the Attestor gRPC service

# SYNOPSIS

**attestor** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**attestor** - Starts the Attestor service to begin listening for inbound
verification requests from the Verifier to begin Remote Attestation.


# OPTIONS

  * **-l**, **\--listen**:

    The IP address, host name, or DNS name to listen for incoming gRPC requests.


## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

# NOTES


# EXAMPLES

## Start the attestor service
```bash
tpadm attestor
```
