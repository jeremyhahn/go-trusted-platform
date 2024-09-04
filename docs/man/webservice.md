% tpadm webservice | Trusted Platform Commands Manual

# NAME

**webservice** - Trusted Platform Web Services

# SYNOPSIS

**webservice** [*OPTIONS*] [*ARGUMENT*]

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

## Start the embedded web server
```bash
tpadm webservice
```
