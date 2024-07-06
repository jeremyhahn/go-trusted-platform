% trusted-platform webservice | TPM Commands Manual

# NAME

**webservice** - Trusted Platform Web Services

# SYNOPSIS

**tpm import-ek** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**webservice** - Starts the embedded web server on the port specified in
the platform configuration file. The web server hosts the static assets in the public_html directory as well as a REST API.

The Swagger / OpenAPI REST API docs can be accessed by navigating to https://localhost:8443/swagger.


# OPTIONS


## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

# NOTES


# EXAMPLES

## Import EK certificate from NV Index, local disk, or TPM manufacturer
```bash
trusted-platform webservice --debug
```
