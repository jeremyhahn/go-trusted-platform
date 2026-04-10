# OpenSSL FIPS Provider Builder

This Docker container builds the OpenSSL FIPS provider module (`fips.so`) that is required for FIPS 140-3 compliance.

## Why Pre-Build?

Instead of building OpenSSL from source during installation (which is slow and resource-intensive), we pre-build ONLY the FIPS provider module in this Docker container and include it in the ISO. This approach:

- **Faster installation**: No compilation needed during installation
- **Smaller resource requirements**: Installation VM doesn't need build tools or 4GB+ RAM
- **Reproducible builds**: Same FIPS module every time
- **Follows reference architecture**: Matches the proven approach from the reference project

## Architecture

Following the reference project's architecture:

1. **Pre-build FIPS module** in Docker (this container)
2. **Include in ISO** during ISO creation
3. **Copy to system** during installation to `/usr/lib/ossl-modules/fips.so`
4. **Use Alpine's system OpenSSL** package (not custom-built OpenSSL)

## Build Configuration

The FIPS provider is built with:

- OpenSSL 3.4.1 (configurable via `OPENSSL_VERSION`)
- `--prefix=/usr` (NOT `/usr/local`)
- `--libdir=lib` (NOT `lib64`)
- `--openssldir=/etc/ssl`
- `enable-fips`
- Security hardening: `no-ssl3`, `no-weak-ssl-ciphers`, `OPENSSL_TLS_SECURITY_LEVEL=2`

## Usage

Build the FIPS provider module:

```bash
make build
```

This will:
1. Build the Docker image
2. Run the container to build the FIPS provider
3. Extract `fips.so` to `output/`
4. Create SHA256 checksum

Clean build artifacts:

```bash
make clean
```

Test the built module:

```bash
make test
```

## Output

After building, you'll find in `output/`:

- `fips.so` - The FIPS provider module
- `fips.so.sha256` - SHA256 checksum
- `openssl-version.txt` - OpenSSL version used

## Integration

The FIPS provider module is automatically included in the ISO during the build process. See `pkg/iso/alpine/customizer.go` for integration details.
