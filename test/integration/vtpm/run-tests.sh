#!/bin/bash
# vTPM E2E Integration Test
#
# Tests full platform provisioning with vTPM:
# 1. Build platformd binary
# 2. Build custom ISO with platform config
# 3. Install system in QEMU with vTPM
# 4. Boot and verify platformd starts successfully
#
set -e

WORKSPACE="${WORKSPACE:-/workspace}"
# Use a path under workspace so logs are preserved after container exits
WORK_DIR="${WORK_DIR:-$WORKSPACE/build/integration/vtpm}"

# Fix git safe.directory for mounted workspace
git config --global --add safe.directory "$WORKSPACE"

# Set up trap to ensure cleanup happens on exit (success, failure, or interrupt)
# This is important because the test runs as root in the container
trap 'cleanup_on_exit' EXIT

cleanup_on_exit() {
    local exit_code=$?
    # Cleanup build artifacts while we still have root permissions
    if [ -d "$WORK_DIR/iso-build" ]; then
        echo ">>> Cleaning up iso-build directory on exit..."
        rm -rf "$WORK_DIR/iso-build" 2>/dev/null || true
    fi
    # Fix ownership if possible
    if [ -n "$HOST_UID" ] && [ -n "$HOST_GID" ] && [ -d "$WORK_DIR" ]; then
        chown -R "$HOST_UID:$HOST_GID" "$WORK_DIR" 2>/dev/null || true
    fi
    exit $exit_code
}

setup_vtpm() {
    mkdir -p /var/run/swtpm /var/lib/swtpm /var/log/swtpm
}

run_unit_tests() {
    echo ">>> Running vTPM Go unit tests..."
    cd "$WORKSPACE"
    CGO_ENABLED=1 go test -v -tags=integration -timeout=10m ./test/integration/vtpm/...
}

build_platform() {
    echo ">>> Building platform binaries (including static for Alpine/musl)..."
    cd "$WORKSPACE"
    # Build both dynamic and static binaries
    # Static binaries are required for Alpine/musl compatibility in the ISO
    make build
    make build-static
    # Build platform-initrd-static for initramfs boot operations
    make platform-initrd-static

    # Copy/link binaries to workspace root for test execution
    # The ISO builder looks for binaries in the same directory as platformd
    echo ">>> Setting up binaries in workspace..."
    ln -sf bin/platformd "$WORKSPACE/platformd"
    ln -sf bin/platformctl "$WORKSPACE/platformctl"
    ln -sf bin/platformd-static "$WORKSPACE/platformd-static"
    ln -sf bin/platformctl-static "$WORKSPACE/platformctl-static"
    ln -sf bin/platform-initrd-static "$WORKSPACE/platform-initrd-static"
}

# Run full E2E test using the client-server test infrastructure
# This reuses existing code for:
# - Building custom ISO with platform config
# - Setting up swtpm
# - Running installation
# - Booting and verifying platformd starts
run_full_e2e() {
    echo "=== vTPM E2E Integration Test ==="
    setup_vtpm
    build_platform

    # Create work directory (clean previous runs)
    echo ">>> Preparing work directory: $WORK_DIR"
    rm -rf "$WORK_DIR"
    mkdir -p "$WORK_DIR"

    # Clean up any stale disk images from previous runs
    # The disk image may have stale state that prevents platformd from starting
    echo ">>> Cleaning up stale disk images..."
    rm -f "$WORKSPACE/server-installed.qcow2"
    rm -f "$WORKSPACE/client-installed.qcow2"

    echo ">>> Running platform provisioning test with vTPM..."
    cd "$WORKSPACE"

    # Use existing client-server test in server-only mode with user networking
    # This tests the complete provisioning flow:
    # 1. Builds custom ISO with server platform config
    # 2. Installs system with vTPM
    # 3. Boots and waits for platformd to start (verifies provisioning)
    # NOTE: Use platformctl (CLI) not platformd (daemon) for commands
    # Place disk image in work directory to ensure clean state
    # Use 600s (10 min) timeout for firstboot provisioning which includes TPM sealing
    local result=0
    ./platformctl iso test client-server \
        --server-only \
        --user-network \
        --server-work-dir "$WORK_DIR" \
        --server-disk "$WORK_DIR/server-installed.qcow2" \
        --server-timeout 600 \
        --debug || result=$?

    # Always show log locations for debugging
    echo ""
    echo ">>> Test artifacts available at: $WORK_DIR"
    if [ -f "$WORK_DIR/server-install-serial.log" ]; then
        echo "    - Install log: $WORK_DIR/server-install-serial.log"
    fi
    if [ -f "$WORK_DIR/server-boot-serial.log" ]; then
        echo "    - Boot log: $WORK_DIR/server-boot-serial.log"
        echo ""
        echo ">>> Last 50 lines of boot log:"
        tail -50 "$WORK_DIR/server-boot-serial.log" 2>/dev/null || true
    fi

    # Fix ownership of files created during test
    fix_ownership

    if [ $result -ne 0 ]; then
        echo "=== vTPM E2E test FAILED (exit code: $result) ==="
        exit $result
    fi

    echo "=== vTPM E2E test completed successfully ==="
}

# Clean up temporary build artifacts that don't need to persist
# This removes the iso-build directory which contains only build-time files
# (downloaded ISOs, extracted contents, etc.) that aren't needed after the test
cleanup_build_artifacts() {
    echo ">>> Cleaning up temporary build artifacts..."
    # The iso-build directory contains build-time artifacts that don't need to persist
    # Removing it while still running as root ensures we don't leave root-owned files
    rm -rf "$WORK_DIR/iso-build" 2>/dev/null || true
}

# Fix ownership of files created by root in the container
# This prevents the workspace from having root-owned files after tests
fix_ownership() {
    # First clean up build artifacts that don't need to persist
    cleanup_build_artifacts

    if [ -n "$HOST_UID" ] && [ -n "$HOST_GID" ]; then
        echo ">>> Fixing file ownership (UID=$HOST_UID, GID=$HOST_GID)..."
        chown -R "$HOST_UID:$HOST_GID" "$WORK_DIR" 2>/dev/null || true
        chown -R "$HOST_UID:$HOST_GID" "$WORKSPACE/bin" 2>/dev/null || true
    fi
}

# =============================================================================
# Main
# =============================================================================

case "${1:-full}" in
    unit)
        setup_vtpm
        run_unit_tests
        ;;
    build)
        build_platform
        ;;
    full|e2e)
        run_full_e2e
        ;;
    *)
        echo "Usage: $0 {unit|build|full}"
        echo ""
        echo "  unit  - Run Go unit tests only"
        echo "  build - Build platform binary only"
        echo "  full  - Run complete E2E test (default)"
        exit 1
        ;;
esac
