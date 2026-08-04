#!/bin/bash
# build-fips-kernel.sh - Build FIPS-capable Linux kernel
#
# Module-signing key (CONFIG_MODULE_SIG_KEY):
#   Production builds MUST set MODULE_SIGNING_KEY to the stable platform
#   module-signing key — a single PEM bundle (PKCS#8 private key followed by a
#   self-signed certificate) generated ONCE per platform with:
#
#       platformctl iso module-signing-key
#       # default output: ~/.trusted-platform/secure-boot/module-signing-key.pem
#
#   (or `make module-key` in this directory). The Makefile mounts the key
#   read-only into the container and points MODULE_SIGNING_KEY at it:
#
#       make build MODULE_SIGNING_KEY=~/.trusted-platform/secure-boot/module-signing-key.pem
#
#   The certificate is embedded in the kernel's .builtin_trusted_keys, so the
#   SAME key signs every in-tree module (CONFIG_MODULE_SIG_ALL) at build time
#   and every out-of-tree module signed later with pkg/modulesign. The key
#   material never enters the repository, the build context, or an image layer.
#   Back the key up: regenerating it orphans every module signed with the old
#   key on already-built kernels. See docs/firmware/secure-boot.md.
#
#   When MODULE_SIGNING_KEY is unset the kernel auto-generates a per-build
#   ephemeral key — DEV BUILDS ONLY (out-of-tree signing is impossible because
#   the ephemeral private key is discarded with the build tree).
set -euo pipefail

# Configuration from environment or defaults
# Use 6.12.8 to match Alpine 3.22 LTS kernel
KERNEL_VERSION="${KERNEL_VERSION:-6.12.8}"
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
log "FIPS Kernel Build (Docker Container)"
log "=========================================="
log "Kernel version: ${KERNEL_VERSION}"
log "Output directory: ${OUTPUT_DIR}"
log ""

# Download and verify kernel source
cd /build
KERNEL_TARBALL="linux-${KERNEL_VERSION}.tar.xz"
KERNEL_SHA256="${KERNEL_TARBALL}.sha256"

if [ ! -f "${KERNEL_TARBALL}" ] || [ ! -f "${KERNEL_TARBALL}.verified" ]; then
    log "Downloading kernel source..."
    log "Kernel version: ${KERNEL_VERSION}"

    KERNEL_BASE_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x"
    KERNEL_URL="${KERNEL_BASE_URL}/${KERNEL_TARBALL}"
    SHA256_URL="${KERNEL_BASE_URL}/sha256sums.asc"

    # Download kernel tarball
    if ! wget -q "${KERNEL_URL}"; then
        error "Failed to download kernel from ${KERNEL_URL}"
    fi
    log "✓ Kernel tarball downloaded"

    # Download SHA256 checksums file
    if ! wget -q "${SHA256_URL}"; then
        error "Failed to download checksums from ${SHA256_URL}"
    fi
    log "✓ Checksums file downloaded"

    # Extract the checksum for our specific kernel version
    EXPECTED_SHA256=$(grep "${KERNEL_TARBALL}" sha256sums.asc | awk '{print $1}')
    if [ -z "${EXPECTED_SHA256}" ]; then
        error "Could not find checksum for ${KERNEL_TARBALL} in sha256sums.asc"
    fi

    log "Expected SHA256: ${EXPECTED_SHA256}"

    # Calculate actual checksum
    ACTUAL_SHA256=$(sha256sum "${KERNEL_TARBALL}" | awk '{print $1}')
    log "Actual SHA256:   ${ACTUAL_SHA256}"

    # Verify checksums match
    if [ "${EXPECTED_SHA256}" != "${ACTUAL_SHA256}" ]; then
        error "SHA256 checksum verification FAILED!
Expected: ${EXPECTED_SHA256}
Actual:   ${ACTUAL_SHA256}

The downloaded kernel tarball is corrupted or has been tampered with.
Aborting build for security reasons."
    fi

    log "✓ SHA256 checksum verification PASSED"

    # Mark as verified
    touch "${KERNEL_TARBALL}.verified"

    # Clean up checksum file
    rm -f sha256sums.asc
else
    log "Using cached and verified kernel source: ${KERNEL_TARBALL}"
fi

# Extract kernel
log "Extracting kernel source..."
if ! tar -xf "${KERNEL_TARBALL}"; then
    error "Failed to extract kernel tarball: ${KERNEL_TARBALL}"
fi
log "✓ Kernel extracted"

log "Entering kernel source directory: linux-${KERNEL_VERSION}"
if ! cd "linux-${KERNEL_VERSION}"; then
    error "Failed to enter kernel directory: linux-${KERNEL_VERSION}"
fi

# Use kernel's default x86_64 config as base
log "Creating default x86_64 kernel configuration..."
make defconfig > /dev/null 2>&1 || error "Failed to create default config"

# Enable essential features for Alpine/server use
log "Enabling essential kernel features..."
scripts/config --enable CONFIG_EXT4_FS
scripts/config --enable CONFIG_XFS_FS
scripts/config --enable CONFIG_BTRFS_FS
scripts/config --enable CONFIG_OVERLAY_FS
scripts/config --enable CONFIG_VFAT_FS
scripts/config --enable CONFIG_ISO9660_FS
scripts/config --enable CONFIG_UDF_FS
scripts/config --enable CONFIG_SQUASHFS
scripts/config --enable CONFIG_TMPFS
scripts/config --enable CONFIG_PROC_FS
scripts/config --enable CONFIG_SYSFS
scripts/config --enable CONFIG_DEVTMPFS
scripts/config --enable CONFIG_DEVTMPFS_MOUNT

# Enable crypto and FIPS
log "Enabling FIPS kernel configuration..."

# FIPS dependencies (must be enabled BEFORE CONFIG_CRYPTO_FIPS)
# For Linux 6.12, CONFIG_CRYPTO_FIPS depends on:
#   (CRYPTO_ANSI_CPRNG || CRYPTO_DRBG) && !CRYPTO_MANAGER_DISABLE_TESTS && (MODULE_SIG || !MODULES)

log "Enabling FIPS dependencies..."
scripts/config --enable CONFIG_DEBUG_KERNEL
scripts/config --enable CONFIG_CRYPTO_MANAGER2
# DISABLE the tests disable flag (double negative = enable tests)
scripts/config --disable CONFIG_CRYPTO_MANAGER_DISABLE_TESTS
# Enable extra tests for good measure
scripts/config --enable CONFIG_CRYPTO_MANAGER_EXTRA_TESTS
scripts/config --enable CONFIG_CRYPTO_DRBG
scripts/config --enable CONFIG_CRYPTO_DRBG_MENU
scripts/config --enable CONFIG_CRYPTO_DRBG_HMAC
scripts/config --enable CONFIG_CRYPTO_DRBG_HASH
scripts/config --enable CONFIG_CRYPTO_DRBG_CTR

# Enable module signing for FIPS
scripts/config --enable CONFIG_MODULE_SIG
scripts/config --enable CONFIG_MODULE_SIG_ALL
scripts/config --enable CONFIG_MODULE_SIG_SHA256
scripts/config --set-str CONFIG_MODULE_SIG_HASH "sha256"

# Enforce module signatures at load time: the running kernel REJECTS any module
# that is unsigned or signed by a key absent from its trusted keyring. Combined
# with CONFIG_MODULE_SIG_ALL (every in-tree module is signed at build time) the
# production module set is fully signature-enforced. See docs/firmware/secure-boot.md.
scripts/config --enable CONFIG_MODULE_SIG_FORCE

# Module-signing key. Production builds provide a STABLE platform module-signing
# key (MODULE_SIGNING_KEY=/path/to/key+cert.pem) so the public key is embedded in
# the kernel's .builtin_trusted_keys and the same key can re-sign modules across
# kernel rebuilds and out-of-tree builds (pkg/modulesign). When unset (dev builds)
# the kernel auto-generates a per-build ephemeral key; modules still load because
# CONFIG_MODULE_SIG_ALL signs them with that build's key.
if [ -n "${MODULE_SIGNING_KEY:-}" ]; then
    if [ ! -f "${MODULE_SIGNING_KEY}" ]; then
        error "MODULE_SIGNING_KEY is set but '${MODULE_SIGNING_KEY}' does not exist"
    fi
    log "Using stable platform module-signing key: ${MODULE_SIGNING_KEY}"
    scripts/config --set-str CONFIG_MODULE_SIG_KEY "${MODULE_SIGNING_KEY}"
else
    log "WARNING: MODULE_SIGNING_KEY not set -- kernel will auto-generate a per-build ephemeral module-signing key (dev builds only; provide a stable key for production)"
fi

# Now enable FIPS (dependencies are met)
scripts/config --enable CONFIG_CRYPTO_FIPS
scripts/config --enable CONFIG_CRYPTO_FIPS_NAME
scripts/config --set-str CONFIG_CRYPTO_FIPS_NAME "Trusted Platform FIPS 140-3"

# Enable required crypto algorithms for FIPS
scripts/config --enable CONFIG_CRYPTO_SHA256
scripts/config --enable CONFIG_CRYPTO_SHA512
scripts/config --enable CONFIG_CRYPTO_AES
scripts/config --enable CONFIG_CRYPTO_AES_X86_64
scripts/config --enable CONFIG_CRYPTO_AES_NI_INTEL
scripts/config --enable CONFIG_CRYPTO_CBC
scripts/config --enable CONFIG_CRYPTO_ECB
scripts/config --enable CONFIG_CRYPTO_XTS
scripts/config --enable CONFIG_CRYPTO_GCM
scripts/config --enable CONFIG_CRYPTO_HMAC
scripts/config --enable CONFIG_CRYPTO_RSA
scripts/config --enable CONFIG_CRYPTO_USER_API_HASH
scripts/config --enable CONFIG_CRYPTO_USER_API_SKCIPHER

# Enable necessary drivers and features
scripts/config --enable CONFIG_BLK_DEV_SD
scripts/config --enable CONFIG_ATA
scripts/config --enable CONFIG_SATA_AHCI
scripts/config --enable CONFIG_SCSI
scripts/config --enable CONFIG_VIRTIO
scripts/config --enable CONFIG_VIRTIO_PCI
scripts/config --enable CONFIG_VIRTIO_BLK
scripts/config --enable CONFIG_VIRTIO_NET
scripts/config --enable CONFIG_NET
scripts/config --enable CONFIG_INET
scripts/config --enable CONFIG_PACKET

# Enable TPM (Trusted Platform Module) support
# All TPM drivers built-in (not modules) for early boot initramfs support
log "Enabling TPM kernel support (built-in for early boot)..."
scripts/config --enable CONFIG_TCG_TPM
scripts/config --enable CONFIG_TCG_TIS
scripts/config --enable CONFIG_TCG_TIS_CORE
scripts/config --enable CONFIG_TCG_CRB
scripts/config --enable CONFIG_TCG_TIS_I2C
scripts/config --enable CONFIG_TCG_TIS_I2C_CR50
scripts/config --enable CONFIG_TCG_TIS_SPI
scripts/config --enable CONFIG_TCG_TIS_I2C_ATMEL
scripts/config --enable CONFIG_TCG_TIS_I2C_INFINEON
scripts/config --enable CONFIG_TCG_TIS_I2C_NUVOTON
scripts/config --enable CONFIG_TCG_VTPM_PROXY
scripts/config --enable CONFIG_TCG_TPM2_HMAC
scripts/config --enable CONFIG_HW_RANDOM_TPM

# Enable device mapper and crypto for LUKS
scripts/config --enable CONFIG_BLK_DEV_DM
scripts/config --enable CONFIG_DM_CRYPT
scripts/config --enable CONFIG_MD

# Verify configs were set before olddefconfig
log "Verifying FIPS configs were set by scripts/config..."
echo "=== Pre-olddefconfig Status ==="
grep "^CONFIG_CRYPTO_FIPS=\|^# CONFIG_CRYPTO_FIPS " .config || echo "CONFIG_CRYPTO_FIPS not found in .config"
grep "^CONFIG_DEBUG_KERNEL=\|^# CONFIG_DEBUG_KERNEL " .config || echo "CONFIG_DEBUG_KERNEL not found"
grep "^CONFIG_CRYPTO_MANAGER_DISABLE_TESTS=\|^# CONFIG_CRYPTO_MANAGER_DISABLE_TESTS " .config || echo "CONFIG_CRYPTO_MANAGER_DISABLE_TESTS not found"
grep "^CONFIG_MODULE_SIG=\|^# CONFIG_MODULE_SIG " .config || echo "CONFIG_MODULE_SIG not found"
echo "================================="

# Apply config changes
log "Running make olddefconfig to resolve dependencies..."
make olddefconfig > /dev/null 2>&1 || error "Failed to apply config"

# Verify FIPS is enabled in final config
log "Verifying FIPS configuration..."
log "Checking FIPS and dependencies in .config:"
echo "=== FIPS Configuration Status ==="
grep "CONFIG_DEBUG_KERNEL\|CONFIG_CRYPTO_MANAGER_DISABLE_TESTS\|CONFIG_CRYPTO_DRBG\|CONFIG_MODULE_SIG\|CONFIG_CRYPTO_FIPS\|CONFIG_MODULES" .config | grep -E "=y|is not set" || echo "No matches found"
echo "================================="

# Verify module-signature ENFORCEMENT survived olddefconfig. Without FORCE the
# running kernel would silently load unsigned modules, defeating Secure Boot.
if ! grep -q "^CONFIG_MODULE_SIG_FORCE=y" .config; then
    error "CONFIG_MODULE_SIG_FORCE is not enabled in the final kernel configuration -- unsigned modules would be loadable"
fi
if [ -n "${MODULE_SIGNING_KEY:-}" ] && ! grep -q "^CONFIG_MODULE_SIG_KEY=" .config; then
    error "MODULE_SIGNING_KEY was provided but CONFIG_MODULE_SIG_KEY is unset in the final configuration"
fi
log "Module signature enforcement verified (CONFIG_MODULE_SIG_FORCE=y)"

if ! grep -q "^CONFIG_CRYPTO_FIPS=y" .config; then
    log "ERROR: CONFIG_CRYPTO_FIPS is not enabled in final kernel configuration!"
    log "This usually means dependencies are not met. Checking what might be wrong..."

    # Check if modules are enabled (FIPS needs either MODULE_SIG or !MODULES)
    if grep -q "^CONFIG_MODULES=y" .config; then
        log "Modules are enabled, checking MODULE_SIG..."
        if ! grep -q "^CONFIG_MODULE_SIG=y" .config; then
            log "ERROR: CONFIG_MODULE_SIG is not enabled but needed for FIPS with modules!"
        fi
    fi

    # Check CRYPTO_MANAGER_DISABLE_TESTS (should be NOT set for FIPS)
    if grep -q "^CONFIG_CRYPTO_MANAGER_DISABLE_TESTS=y" .config; then
        log "ERROR: CONFIG_CRYPTO_MANAGER_DISABLE_TESTS is enabled but must be disabled for FIPS!"
        log "Crypto self-tests are disabled which prevents FIPS from working"
    fi
    if ! grep -q "^# CONFIG_CRYPTO_MANAGER_DISABLE_TESTS is not set" .config; then
        log "WARNING: CONFIG_CRYPTO_MANAGER_DISABLE_TESTS status unclear"
    fi

    # Check DRBG
    if ! grep -q "^CONFIG_CRYPTO_DRBG=y" .config; then
        log "ERROR: CONFIG_CRYPTO_DRBG is not enabled!"
    fi

    error "Cannot continue without FIPS enabled. Please review above errors."
fi
log "✓ CONFIG_CRYPTO_FIPS=y verified in kernel configuration"

# Build kernel
log "Building FIPS kernel (this may take 15-30 minutes)..."
log "Using $(nproc) CPU cores"
# Write build log to /output so it persists after container exits
BUILD_LOG="${OUTPUT_DIR}/kernel-build.log"
if ! make -j$(nproc) bzImage modules 2>&1 | tee "${BUILD_LOG}"; then
    echo ""
    echo "=========================================="
    echo "KERNEL BUILD FAILED"
    echo "=========================================="
    echo "Last 100 lines of build output:"
    tail -100 "${BUILD_LOG}"
    echo "=========================================="
    error "Kernel compilation failed. See above for details and full log at ${BUILD_LOG}"
fi

# Get kernel version string
KVER=$(make -s kernelversion)
log "Built kernel version: ${KVER}"

# Prepare output
mkdir -p "${OUTPUT_DIR}"

# Copy kernel image
log "Copying kernel image..."
cp arch/x86/boot/bzImage "${OUTPUT_DIR}/vmlinuz-fips" || error "Failed to copy kernel"

# Install modules to temporary location
log "Installing kernel modules..."
MODULES_TEMP="/tmp/modules-fips"
mkdir -p "${MODULES_TEMP}"
make modules_install INSTALL_MOD_PATH="${MODULES_TEMP}" > /dev/null 2>&1 || error "Failed to install modules"

# Create modules tarball
log "Creating modules archive..."
cd "${MODULES_TEMP}"
tar -czf "${OUTPUT_DIR}/modules-fips-${KVER}.tar.gz" lib/modules/${KVER} || error "Failed to create modules archive"

# Copy System.map and config for reference
log "Copying System.map and kernel config..."
cp "/build/linux-${KERNEL_VERSION}/System.map" "${OUTPUT_DIR}/System.map-fips"
cp "/build/linux-${KERNEL_VERSION}/.config" "${OUTPUT_DIR}/config-fips"

# Create version file
echo "${KVER}" > "${OUTPUT_DIR}/kernel-version.txt"

# Create SHA256 checksums
cd "${OUTPUT_DIR}"
sha256sum vmlinuz-fips > vmlinuz-fips.sha256
sha256sum "modules-fips-${KVER}.tar.gz" > "modules-fips-${KVER}.tar.gz.sha256"

log ""
log "=========================================="
log "FIPS Kernel Build Complete!"
log "=========================================="
log "Kernel image: ${OUTPUT_DIR}/vmlinuz-fips"
log "Modules: ${OUTPUT_DIR}/modules-fips-${KVER}.tar.gz"
log "Version: ${KVER}"
log ""
