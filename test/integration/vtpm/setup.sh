#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== vtpm Integration Test Environment Setup ==="

# Create necessary directories
mkdir -p /var/run/swtpm /var/lib/swtpm /var/log/swtpm

# Verify swtpm is installed
echo "Checking swtpm installation..."
if ! command -v swtpm &> /dev/null; then
    echo "ERROR: swtpm not found"
    exit 1
fi

if ! command -v swtpm_setup &> /dev/null; then
    echo "ERROR: swtpm_setup not found"
    exit 1
fi

echo "swtpm version: $(swtpm --version 2>&1 | head -1)"
echo "swtpm installation verified successfully"

# Execute the command passed to the container
if [ "$1" = "run-tests" ]; then
    echo "Running integration tests..."
    exec "${SCRIPT_DIR}/run-tests.sh"
elif [ "$1" = "shell" ]; then
    echo "Starting interactive shell..."
    exec /bin/bash
else
    exec "$@"
fi
