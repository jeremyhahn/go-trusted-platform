#!/bin/sh
# build-fips-provider.sh - Build OpenSSL FIPS provider module
set -euo pipefail

# Configuration from environment or defaults
# CRITICAL: We MUST use a FIPS 140-3 VALIDATED OpenSSL version to build the FIPS provider
# According to official OpenSSL FIPS documentation:
#   - OpenSSL 3.1.2 is FIPS 140-3 validated (Certificate #4985, valid until March 10, 2030)
#   - The validated FIPS provider is compatible with ANY OpenSSL 3.x version (3.0-3.5+)
#   - Alpine 3.22.2 provides OpenSSL 3.5.4, which will use this validated provider
# References:
#   - https://github.com/openssl/openssl/blob/master/README-FIPS.md
#   - https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985
#   - https://openssl-library.org/post/2025-03-11-fips-140-3/
OPENSSL_FIPS_VERSION="${OPENSSL_FIPS_VERSION:-3.1.2}"
OUTPUT_DIR="${OUTPUT_DIR:-/output}"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $*" >&2
    exit 1
}

log "=========================================="
log "OpenSSL FIPS 140-3 Provider Build"
log "=========================================="
log "FIPS-Validated OpenSSL version: ${OPENSSL_FIPS_VERSION}"
log "FIPS Certificate: #4985 (valid until March 10, 2030)"
log "Compatible with: OpenSSL 3.0.x - 3.5.x+"
log "Output directory: ${OUTPUT_DIR}"
log ""

# Download and verify OpenSSL source
OPENSSL_TARBALL="openssl-${OPENSSL_FIPS_VERSION}.tar.gz"
OPENSSL_URL="https://www.openssl.org/source/${OPENSSL_TARBALL}"
SHA256_URL="${OPENSSL_URL}.sha256"

if [ ! -f "${OPENSSL_TARBALL}" ] || [ ! -f "${OPENSSL_TARBALL}.verified" ]; then
    log "Downloading OpenSSL source..."

    # Download OpenSSL tarball
    if ! wget -q "${OPENSSL_URL}"; then
        error "Failed to download OpenSSL from ${OPENSSL_URL}"
    fi
    log "✓ OpenSSL tarball downloaded"

    # Download SHA256 checksum
    if ! wget -q "${SHA256_URL}"; then
        error "Failed to download SHA256 checksum from ${SHA256_URL}"
    fi
    log "✓ SHA256 checksum downloaded"

    # Read expected checksum
    EXPECTED_SHA256=$(cat "${OPENSSL_TARBALL}.sha256" | awk '{print $1}')
    if [ -z "${EXPECTED_SHA256}" ]; then
        error "Could not read expected SHA256 checksum"
    fi

    log "Expected SHA256: ${EXPECTED_SHA256}"

    # Calculate actual checksum
    ACTUAL_SHA256=$(sha256sum "${OPENSSL_TARBALL}" | awk '{print $1}')
    log "Actual SHA256:   ${ACTUAL_SHA256}"

    # Verify checksums match
    if [ "${EXPECTED_SHA256}" != "${ACTUAL_SHA256}" ]; then
        error "SHA256 checksum verification FAILED!
Expected: ${EXPECTED_SHA256}
Actual:   ${ACTUAL_SHA256}

The downloaded OpenSSL tarball is corrupted or has been tampered with.
Aborting build for security reasons."
    fi

    log "✓ SHA256 checksum verification PASSED"

    # Mark as verified
    touch "${OPENSSL_TARBALL}.verified"

    # Clean up checksum file
    rm -f "${OPENSSL_TARBALL}.sha256"
else
    log "Using cached and verified OpenSSL source: ${OPENSSL_TARBALL}"
fi

# Extract OpenSSL
log "Extracting OpenSSL source..."
tar -xzf "${OPENSSL_TARBALL}" || error "Failed to extract OpenSSL"
cd "openssl-${OPENSSL_FIPS_VERSION}" || error "Failed to enter OpenSSL directory"
log "✓ Extracted OpenSSL source"

# Configure OpenSSL with FIPS support
# Use same configuration as reference project:
# - --prefix=/usr (NOT /usr/local!)
# - --libdir=lib (NOT lib64!)
# - --openssldir=/etc/ssl
log "Configuring OpenSSL with FIPS support..."
./Configure linux-x86_64 \
    --prefix=/usr \
    --libdir=lib \
    --openssldir=/etc/ssl \
    enable-fips \
    shared \
    no-ssl3 \
    no-weak-ssl-ciphers \
    -DOPENSSL_TLS_SECURITY_LEVEL=2 \
    || error "Failed to configure OpenSSL"

log "✓ OpenSSL configured successfully"

# Build ONLY the FIPS provider module
# According to official OpenSSL FIPS documentation:
#   - The FIPS provider module (fips.so) from OpenSSL 3.1.2 is FIPS 140-3 validated
#   - This module is COMPATIBLE with ANY OpenSSL 3.x version (3.0 - 3.5+)
#   - We should NOT replace the system OpenSSL libraries
#   - Instead, we copy ONLY the validated fips.so to the system
#
# This approach:
#   - Maintains FIPS compliance (using validated FIPS provider from 3.1.2)
#   - Ensures symbol compatibility (using Alpine's system OpenSSL 3.5.4 libraries)
#   - Is officially supported per OpenSSL documentation
#
# References:
#   - https://github.com/openssl/openssl/blob/master/README-FIPS.md
#   - "The OpenSSL 3.1.2 FIPS module is compatible with any version of OpenSSL 3.0-3.5+"
#   - "You can build openssl-3.5.0, then build openssl-3.1.2, and simply copy the
#      fips.so module from your openssl-3.1.2 tree into the openssl-3.5.0 tree"
log "Building ONLY the FIPS provider module (not complete OpenSSL)..."
log "Using $(nproc) CPU cores"

# Build only the FIPS provider module
make build_modules -j$(nproc) || error "Failed to build FIPS provider module"
log "✓ FIPS provider module built successfully"

# Install to staging directory
mkdir -p "${OUTPUT_DIR}/usr/lib/ossl-modules"

# Copy ONLY the FIPS provider module
FIPS_MODULE_SRC="providers/fips.so"
FIPS_MODULE_DEST="${OUTPUT_DIR}/usr/lib/ossl-modules/fips.so"

if [ ! -f "${FIPS_MODULE_SRC}" ]; then
    error "FIPS provider module not found after build: ${FIPS_MODULE_SRC}"
fi

cp "${FIPS_MODULE_SRC}" "${FIPS_MODULE_DEST}" || error "Failed to copy FIPS module"
log "✓ FIPS provider module copied to staging directory"

# Verify the FIPS provider module
if [ ! -f "${FIPS_MODULE_DEST}" ]; then
    error "FIPS provider module not found in output: ${FIPS_MODULE_DEST}"
fi

# Get file info for verification
FIPS_SIZE=$(stat -c%s "${FIPS_MODULE_DEST}")
log "FIPS module size: ${FIPS_SIZE} bytes"

# Create version and installation info files
echo "${OPENSSL_FIPS_VERSION}" > "${OUTPUT_DIR}/openssl-fips-version.txt"
cat > "${OUTPUT_DIR}/README.txt" << EOF
OpenSSL FIPS 140-3 Provider Module
===================================

FIPS Validated Version: ${OPENSSL_FIPS_VERSION}
Certificate: #4985
Valid Until: March 10, 2030
Build Date: $(date +'%Y-%m-%d %H:%M:%S')

This package contains ONLY the FIPS provider module (fips.so).

IMPORTANT: This FIPS provider is compatible with ANY OpenSSL 3.x version.
- Built from: OpenSSL ${OPENSSL_FIPS_VERSION} (FIPS 140-3 validated)
- Compatible with: OpenSSL 3.0.x - 3.5.x+
- Use with: Alpine's system OpenSSL package (currently 3.5.4)

Installation:
  1. Install Alpine's system OpenSSL: apk add openssl
  2. Copy fips.so to: /usr/lib/ossl-modules/fips.so
  3. Run: openssl fipsinstall -out /etc/ssl/fipsmodule.cnf -module /usr/lib/ossl-modules/fips.so
  4. Configure OpenSSL to use FIPS provider in /etc/ssl/openssl.cnf

This approach:
  - Maintains FIPS compliance (validated FIPS provider from 3.1.2)
  - Ensures compatibility (uses Alpine's 3.5.4 libraries for system libraries)
  - Follows official OpenSSL documentation

References:
- https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985
- https://github.com/openssl/openssl/blob/master/README-FIPS.md
- https://openssl-library.org/post/2025-03-11-fips-140-3/
EOF

# Create SHA256 checksum for the FIPS module
cd "${OUTPUT_DIR}"
sha256sum usr/lib/ossl-modules/fips.so > fips.so.sha256

log ""
log "=========================================="
log "FIPS 140-3 Provider Module Build Complete!"
log "=========================================="
log "FIPS-Validated OpenSSL version: ${OPENSSL_FIPS_VERSION}"
log "Certificate: #4985 (valid until March 10, 2030)"
log "Output directory: ${OUTPUT_DIR}/usr/lib/ossl-modules"
log ""
log "Built component:"
log "  - FIPS provider module: /usr/lib/ossl-modules/fips.so (${FIPS_SIZE} bytes)"
log ""
log "This FIPS provider module is compatible with OpenSSL 3.0.x - 3.5.x+"
log "Use with Alpine's system OpenSSL package (apk add openssl)"
log ""
