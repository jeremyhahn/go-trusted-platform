# platformctl ca

Certificate Authority operations exposed by `platformctl`. All commands
work against any of the platform's six transports (`unix`, `grpc`, `rest`,
`quic`, `mcp`, `embedded`) — see [global-flags.md](global-flags.md) for
how to select a transport.

## Subcommands

| Command | Description |
|---------|-------------|
| `ca init` | Initialize a Certificate Authority. |
| `ca info` | Display CA configuration, key store status, and trust chain. |
| `ca issue` | Issue a new x509 certificate. |
| `ca certificate` | Retrieve a single certificate by serial or common name. |
| `ca list` | List issued certificates with status filtering and pagination. |
| `ca verify` | Verify a certificate file against the CA chain (and optionally the CRL). |
| `ca renew` | Renew an existing certificate, optionally preserving SANs. |
| `ca revoke` | Revoke a certificate by serial number. |
| `ca crl` | Display the current Certificate Revocation List. |
| `ca crl generate` | Force generation of a new CRL. |
| `ca crl export` | Write the CRL to disk. |
| `ca bundle` | Print or save the CA trust bundle (PEM). |
| `ca install-ca-certificates` | Install the trust bundle into the system trust store. |
| `ca uninstall-ca-certificates` | Remove the trust bundle from the system trust store. |

## ca bundle

`ca bundle` is the single, consolidated command for retrieving the CA
trust bundle as concatenated PEM. It replaces the deprecated
`ca export-bundle` command, which has been removed.

```
platformctl ca bundle [--output <path>] [--intermediates]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--output`, `-o` | _(stdout)_ | Output file path. When omitted, the PEM bundle is written to stdout, making the command pipe-friendly. |
| `--intermediates` | `true` | Include intermediate CA certificates in the bundle. Pass `--intermediates=false` to emit only the root. |

### Examples

```bash
# Print the PEM trust bundle to stdout
platformctl ca bundle

# Save the trust bundle to a file
platformctl ca bundle --output /etc/ssl/platform-ca.pem

# Pipe directly into the system trust store
platformctl ca bundle | sudo tee /usr/local/share/ca-certificates/platform.crt > /dev/null

# Emit only the root certificate (no intermediates)
platformctl ca bundle --intermediates=false --output root.pem
```

When `--output` is set, the command also prints a short success summary
and the certificate count (or, when `--output json|yaml` is selected as
the global format, a structured response).

### Migration from `ca export-bundle`

The old `ca export-bundle` command had a required `--output` flag and a
duplicated implementation. It has been deleted. Migrate as follows:

```bash
# Old
platformctl ca export-bundle --output /etc/ssl/platform-ca.pem

# New (equivalent behavior)
platformctl ca bundle --output /etc/ssl/platform-ca.pem
```

The new `ca bundle` command additionally supports stdout output, which
the old `export-bundle` did not.

## ca info

```
platformctl ca info [--output table|json|yaml]
```

Returns CA metadata: common name, initialization state, default key
algorithm and validity, the root certificate summary, intermediate
certificate summaries, and the configured key stores.

## ca list

```
platformctl ca list [--status valid|revoked|expired|all]
                    [--issuer <name>]
                    [--page-size N]
```

Lists certificates issued by this CA. Supports server-side filtering by
status and issuer. Pagination is performed via `--page` / `--page-size`.

## ca certificate

```
platformctl ca certificate <serial-or-cn> [--pem]
```

Retrieves a single certificate by either serial number (hex) or common
name. Pass `--pem` to include the PEM blob in the JSON/YAML output.

## ca verify

```
platformctl ca verify <cert.pem> [--crl=true]
```

Verifies a PEM-encoded certificate against the CA trust chain. CRL
checking is on by default; pass `--crl=false` to skip it.

## Errors

CA commands return typed errors from `pkg/cli/commands/ca/errors.go`. Of
note for consumers of `ca bundle`:

| Type | Meaning |
|------|---------|
| `ErrDaemonConnectionRequired` | The CLI could not connect to `platformd` — check `--server` / `--context` and that the daemon is running. |
| `ErrCANotInitialized` | The CA has not been initialized; run `ca init` first. |
| `ErrCABundleFailed` | The bundle could not be retrieved or written. The wrapped reason explains the underlying failure. |
| `ErrBundleEmpty` | The CA returned a zero-length bundle (likely a misconfigured CA). |

(`ErrExportBundleFailed` was renamed to `ErrCABundleFailed` when
`export-bundle` was consolidated into `bundle`.)
