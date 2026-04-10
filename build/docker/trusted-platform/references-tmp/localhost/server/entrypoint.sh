#!/bin/bash

# Start TPM simulator in background if enabled
if [ "${TPM_SIMULATOR}" = "true" ]; then
    echo "Starting TPM simulator..."
    mkdir -p /tmp/tpm
    swtpm socket --tpmstate dir=/tmp/tpm --tpm2 --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --flags not-need-init &
    sleep 2
    export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"
fi

# Check if platform is already initialized
if [ ! -f /opt/trusted-platform/trusted-data/.initialized ]; then
    echo "Initializing platform for the first time..."
    # Clean up any partial initialization
    rm -rf /opt/trusted-platform/trusted-data/platform/keystore/hmac-keys/platform.pin
    /usr/local/bin/platformd --init --raw-so-pin "${PASSWORD:-test}" --raw-pin "${PASSWORD:-test}" serve
    touch /opt/trusted-platform/trusted-data/.initialized
else
    echo "Platform already initialized, starting..."
    /usr/local/bin/platformd serve
fi