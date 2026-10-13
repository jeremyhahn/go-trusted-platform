# CA CLI Usage

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md), [api.md](api.md), [cli.md](cli.md) and [user.md](user.md).

This document provides the command-line reference for Certificate Authority
operations using platformctl.

## Command Overview

```
platformctl ca <command> [options]

Commands:
  init            Initialize Certificate Authority
  info            Display CA information
  issue           Issue a certificate
  revoke          Revoke a certificate
  certificate     Manage certificates
  install         Install CA certificates to system
  uninstall       Remove CA certificates from system
  bundle          Print or save the CA trust bundle (PEM)
```

## Initialize CA

### Full Initialization

```bash
# Initialize CA with interactive prompts
platformctl ca init --so-pin

# Initialize with explicit passwords
platformctl ca init --raw-so-pin "owner-password" --raw-pin "user-password"

# Initialize in non-interactive mode
platformctl ca init --raw-so-pin "${CA_OWNER_PASSWORD}" --init
```

### Initialization Options

| Option          | Description                              |
|-----------------|------------------------------------------|
| `--so-pin`      | Prompt for Security Officer PIN         |
| `--pin`         | Prompt for user PIN                      |
| `--raw-so-pin`  | Provide SO PIN directly                  |
| `--raw-pin`     | Provide user PIN directly                |
| `--init`        | Auto-initialize without prompts          |
| `--config`      | Path to configuration file               |

## CA Information

### Display CA Info

```bash
# Basic CA information
platformctl ca info

# Output:
# Certificate Authority Information
# =================================
#
# Root CA:
#   CN:        Trusted Platform Root CA
#   Algorithm: ECDSA P-384
#   Valid:     2020-01-01 to 2040-01-01
#   Issued:    3 certificates
#
# Intermediate CAs:
#   - Trusted Platform TLS CA
#     Algorithm: RSA-4096
#     Valid:     2020-01-02 to 2030-01-02
#     Issued:    1,500 certificates
```

### Detailed Information

```bash
# Verbose output
platformctl ca info -v

# JSON output
platformctl ca info -o json
```

## Issue Certificate

### Issue TLS Server Certificate

```bash
# Basic TLS certificate
platformctl ca issue server.example.com software rsa2048

# With Subject Alternative Names
platformctl ca issue server.example.com software ecdsa-p256 \
  --sans-dns "www.example.com,api.example.com" \
  --sans-ips "192.168.1.100"

# With specific validity
platformctl ca issue server.example.com tpm rsa4096 \
  --valid 365
```

### Issue Parameters

| Position | Description                                |
|----------|--------------------------------------------|
| 1        | Common Name (CN)                           |
| 2        | Key store: software, tpm, pkcs11           |
| 3        | Algorithm: rsa2048, rsa4096, ecdsa-p256, etc. |

### Issue Options

| Option            | Description                        | Default |
|-------------------|------------------------------------|---------|
| `--sans-dns`      | DNS Subject Alternative Names      | (none)  |
| `--sans-ips`      | IP Subject Alternative Names       | (none)  |
| `--sans-emails`   | Email Subject Alternative Names    | (none)  |
| `--valid`         | Validity in days                   | 365     |
| `--key-size`      | RSA key size                       | 2048    |
| `--curve`         | ECC curve name                     | P-256   |

### Examples

```bash
# RSA certificate with multiple SANs
platformctl ca issue api.example.com software rsa4096 \
  --sans-dns "api.example.com,api-v2.example.com" \
  --sans-ips "10.0.0.100,10.0.0.101" \
  --valid 90

# ECDSA certificate in TPM
platformctl ca issue app.internal tpm ecdsa-p256

# Ed25519 certificate (software only)
platformctl ca issue signing.example.com software ed25519
```

## Certificate Management

### List Certificates

```bash
# List all certificates
platformctl ca certificate list

# Filter by status
platformctl ca certificate list --status active
platformctl ca certificate list --status revoked

# JSON output
platformctl ca certificate list -o json
```

### Show Certificate

```bash
# Show certificate details
platformctl ca certificate show server.example.com

# Show by serial number
platformctl ca certificate show --serial 1234567890

# Export PEM
platformctl ca certificate show server.example.com --format pem > server.crt
```

### Verify Certificate

```bash
# Verify certificate chain
platformctl ca certificate verify server.crt

# Verify against specific CA
platformctl ca certificate verify server.crt --ca "Trusted Platform TLS CA"
```

## Revoke Certificate

### Revoke by CN

```bash
# Revoke certificate
platformctl ca revoke server.example.com

# With reason code
platformctl ca revoke server.example.com --reason keyCompromise

# Force without confirmation
platformctl ca revoke server.example.com --force
```

### Revoke by Serial

```bash
platformctl ca revoke --serial 1234567890 --reason superseded
```

### Revocation Reasons

| Reason               | Code | Description                    |
|----------------------|------|--------------------------------|
| unspecified          | 0    | No specific reason             |
| keyCompromise        | 1    | Private key compromised        |
| caCompromise         | 2    | CA key compromised             |
| affiliationChanged   | 3    | Subject affiliation changed    |
| superseded           | 4    | Certificate superseded         |
| cessationOfOperation | 5    | Certificate no longer needed   |

## Install CA Certificates

### Install to System Trust Store

```bash
# Install CA certificates
platformctl ca install

# Install specific CA
platformctl ca install --ca "Trusted Platform Root CA"

# Verify installation
platformctl ca install --verify
```

### Uninstall from System Trust Store

```bash
# Uninstall CA certificates
platformctl ca uninstall

# Uninstall specific CA
platformctl ca uninstall --ca "Trusted Platform Root CA"
```

## Export CA Bundle

### Export Full Bundle

```bash
# Export PEM bundle
platformctl ca bundle > ca-bundle.crt

# Export specific format
platformctl ca bundle > ca-bundle.pem  # PEM is the only supported format
# DER export is not supported by ca bundle; use openssl to convert PEM
platformctl ca bundle | openssl x509 -outform der > ca-bundle.der

# Export specific CAs
# Per-CA selection is not supported by ca bundle; emit the full chain
platformctl ca bundle
```

### Export Individual Certificates

```bash
# Export Root CA
# Per-CA selection is not supported; root-only output uses --intermediates=false
platformctl ca bundle --intermediates=false > root-ca.crt

# Export Intermediate CA
# Per-CA selection is not supported by ca bundle; full chain shown
platformctl ca bundle > tls-ca.crt
```

## Global Options

| Option            | Short | Description                       |
|-------------------|-------|-----------------------------------|
| `--debug`         | `-d`  | Enable debug output               |
| `--output`        | `-o`  | Output format (table, json, yaml) |
| `--verbose`       | `-v`  | Verbose output                    |
| `--config`        | `-c`  | Config file path                  |
| `--platform-dir`  |       | Platform data directory           |
| `--intermediate`  |       | Target intermediate CA index      |
| `--so-pin`        |       | Prompt for SO PIN                 |
| `--pin`           |       | Prompt for user PIN               |

## Examples

### Example: Complete CA Setup

```bash
# 1. Initialize CA
platformctl ca init --so-pin

# 2. Verify initialization
platformctl ca info

# 3. Install CA certificates
platformctl ca install

# 4. Issue server certificate
platformctl ca issue server.example.com tpm ecdsa-p256 \
  --sans-dns "server.example.com"

# 5. Export for distribution
platformctl ca bundle > ca-bundle.crt
```

### Example: Certificate Lifecycle

```bash
# Issue certificate
platformctl ca issue app.example.com software rsa2048 \
  --valid 90

# Verify certificate
platformctl ca certificate verify app.example.com

# List active certificates
platformctl ca certificate list --status active

# Revoke certificate
platformctl ca revoke app.example.com --reason superseded

# Issue replacement
platformctl ca issue app.example.com software rsa2048 \
  --valid 90
```

### Example: Automation Script

```bash
#!/bin/bash
set -e

# Initialize CA
platformctl ca init \
  --raw-so-pin "${CA_SO_PIN}" \
  --raw-pin "${CA_PIN}" \
  --init

# Issue certificates for all services
for service in api web worker; do
  platformctl ca issue "${service}.internal" software ecdsa-p256 \
    --valid 365 \
    --raw-so-pin "${CA_SO_PIN}"
done

# Export CA bundle
platformctl ca bundle > /etc/ssl/certs/platform-ca.crt

echo "CA setup complete"
```

### Example: OpenSSL Verification

```bash
# Export certificates
# Per-CA selection is not supported; root-only output uses --intermediates=false
platformctl ca bundle --intermediates=false > root-ca.crt
# Per-CA selection is not supported; full chain shown
platformctl ca bundle > intermediate-ca.crt
platformctl ca certificate show server.example.com --format pem > server.crt

# Verify chain
openssl verify \
  -CAfile root-ca.crt \
  -untrusted intermediate-ca.crt \
  server.crt

# Check certificate details
openssl x509 -in server.crt -text -noout
```

## Error Messages

| Error                        | Cause                    | Solution                    |
|------------------------------|--------------------------|------------------------------|
| "CA not initialized"         | CA not provisioned       | Run `platformctl ca init`   |
| "certificate already exists" | CN already issued        | Use different CN or revoke  |
| "invalid algorithm"          | Unsupported algorithm    | Check supported algorithms  |
| "authorization failed"       | Wrong PIN/password       | Verify credentials          |
| "key store not available"    | TPM/HSM not accessible   | Check device/configuration  |

## Related Documentation

- [README](README.md) - CA module overview
- [Architecture](architecture.md) - CA design
- [ACME](acme.md) - ACME server
- [Configuration](configuration.md) - Configuration reference
- [API Reference](api-reference.md) - API documentation

## See Also

- `platformctl --help` - General CLI help
- `platformctl ca --help` - CA command help
- `platformctl ca issue --help` - Issue command help
