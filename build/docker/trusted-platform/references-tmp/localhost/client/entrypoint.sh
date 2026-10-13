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
    # Run initialization - allow it to fail on enrollment
    /usr/local/bin/platformd --init --raw-so-pin "${PASSWORD:-test}" --raw-pin "${PASSWORD:-test}" serve 2>&1 | tee /tmp/init.log || true
    
    # Check if core platform files were created
    if [ -d /opt/trusted-platform/trusted-data/platform ]; then
        touch /opt/trusted-platform/trusted-data/.initialized
        echo "Platform initialization complete (enrollment may be pending)."
        
        # Check if enrollment failed
        if grep -q "failed to wait for authorization" /tmp/init.log; then
            echo "NOTE: ACME enrollment failed. This is expected in Docker environment."
            echo "The client will run without TLS certificates."
            echo "In production, use proper DNS or a reverse proxy for ACME validation."
        fi
    else
        echo "Platform initialization failed completely. Exiting."
        exit 1
    fi
fi

# Run the webservice
echo "Starting webservice..."
# Add a small delay to ensure clean startup
sleep 2

# Check if we were successfully initialized
if [ -d /opt/trusted-platform/trusted-data/platform ]; then
    # Run without --init flag
    exec /usr/local/bin/platformd serve --enable-mtls
else
    echo "Platform not properly initialized. Keeping container running for debugging..."
    # Keep container running
    tail -f /dev/null
fi