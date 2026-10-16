% platformd serve | Trusted Platform Commands Manual

> **Status: REFERENCE** · Last verified: 2026-10-15
> Manual page source for `platformd serve`. No build target renders it.

# NAME

**serve** - Trusted Platform Daemon

# SYNOPSIS

**platformd serve** [*OPTIONS*]

**platformd** without a subcommand runs **serve**.

# DESCRIPTION

**serve** - Starts the platform daemon with all configured services. The behavior
is controlled by the platform configuration file:

- **With webservices configured**: Full web services stack (REST API, ACME, WebAuthn, JWT)
- **Without webservices**: Daemon-only mode (Unix socket, gRPC, QUIC, MCP;
  REST only with **\--enable-mtls**, its only authentication)

When web services are enabled, the embedded web server hosts the REST API and
static assets in the public_html directory.

If the TPM is not initialized, **serve** provisions the platform before it
starts. Any startup failure exits non-zero.

# OPTIONS

  * **\--socket-path**:
    Unix socket path. Default: `/run/platformd.sock`.

  * **\--enable-rest**, **\--enable-grpc**, **\--enable-quic**, **\--enable-mcp**:
    Enable each transport. Default: `true`.

  * **\--enable-mtls**:
    Enable mutual TLS authentication. Default: `false`. gRPC over TCP needs it
    unless platform tokens are enabled or quicbaas runs remotely.

  * **\--skip-iam-validation**:
    Skip IAM validation (testing only).

  * **\--<transport>-bind-host**, **\--<transport>-port**, **\--raft-address**,
    **\--raft-listen-address**:
    Listener and Raft addresses. Each falls through to the `daemon:` /
    `quicbaas:` config section and the `PLATFORMD_*` environment when unset.

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
