% platformd serve | Trusted Platform Commands Manual

# NAME

**serve** - Trusted Platform Daemon

# SYNOPSIS

**serve** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**serve** - Starts the platform daemon with all configured services. The behavior
is controlled by the platform configuration file:

- **With webservices configured**: Full web services stack (REST API, ACME, WebAuthn, JWT)
- **Without webservices**: Daemon-only mode (Unix socket, gRPC, QUIC, MCP)

When web services are enabled, the embedded web server hosts the REST API and
static assets in the public_html directory. The Swagger / OpenAPI REST API docs
can be accessed by navigating to https://localhost:8443/swagger.

# OPTIONS

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

# EXAMPLES

## Start the platform daemon

```bash
platformd serve
```

## Start with initialization

```bash
platformd serve --init
```

## Start with PINs for TPM/CA operations

```bash
platformd serve --so-pin --pin
```

## Start in debug mode

```bash
platformd serve --debug
```
