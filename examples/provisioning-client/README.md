# Device Provisioning Client Example

This example demonstrates how to use the provisioning client to perform device enrollment and network activation using mTLS authentication with IDevID certificates.

## Overview

The provisioning client enables devices to:
1. Fetch their device profile from the provisioning server
2. Signal activation readiness
3. Transition to production network

## Prerequisites

- IDevID certificate (issued via ACME enrollment)
- IDevID private key
- CA certificate bundle (for server verification)
- Running provisioning server

## Building

```bash
go build -o provisioning-client main.go
```

## Usage

### Basic Usage

Fetch profile and activate device:

```bash
./provisioning-client \
  -server https://provisioning.example.com:8443 \
  -cert /path/to/idevid.pem \
  -key /path/to/idevid-key.pem \
  -ca /path/to/ca-bundle.pem
```

### Fetch Profile Only

Fetch device profile without activating:

```bash
./provisioning-client \
  -server https://provisioning.example.com:8443 \
  -cert /path/to/idevid.pem \
  -key /path/to/idevid-key.pem \
  -ca /path/to/ca-bundle.pem \
  -profile-only
```

### Testing with Self-Signed Certificates

For testing only (never use in production):

```bash
./provisioning-client \
  -server https://localhost:8443 \
  -cert /path/to/idevid.pem \
  -key /path/to/idevid-key.pem \
  -insecure
```

### Advanced Options

```bash
./provisioning-client \
  -server https://provisioning.example.com:8443 \
  -cert /path/to/idevid.pem \
  -key /path/to/idevid-key.pem \
  -ca /path/to/ca-bundle.pem \
  -timeout 60s \
  -retries 5 \
  -retry-delay 10s
```

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-server` | Provisioning server URL | `https://localhost:8443` |
| `-cert` | Path to IDevID certificate (PEM) | Required |
| `-key` | Path to IDevID private key (PEM) | Required |
| `-ca` | Path to CA certificate bundle (PEM) | Required (unless -insecure) |
| `-insecure` | Skip TLS certificate verification | `false` |
| `-timeout` | Request timeout | `30s` |
| `-retries` | Number of retry attempts | `3` |
| `-retry-delay` | Delay between retries | `5s` |
| `-profile-only` | Fetch profile only, don't activate | `false` |

## Example Output

```
time=2025-12-21T22:00:00.000Z level=INFO msg="Starting device provisioning" server=https://provisioning.example.com:8443 cert=/path/to/idevid.pem
time=2025-12-21T22:00:00.001Z level=INFO msg="IDevID certificate loaded" subject=device-001 serial=1234567890
time=2025-12-21T22:00:00.002Z level=INFO msg="Private key loaded"
time=2025-12-21T22:00:00.003Z level=INFO msg="CA bundle loaded"
time=2025-12-21T22:00:00.004Z level=INFO msg="Provisioning client created successfully"
time=2025-12-21T22:00:00.005Z level=INFO msg="Attempting provisioning" attempt=1 max=3
time=2025-12-21T22:00:00.100Z level=INFO msg="Fetching device profile via mTLS" url=https://provisioning.example.com:8443/api/v1/device/profile
time=2025-12-21T22:00:00.200Z level=INFO msg="Device profile fetched successfully" serial=device-001 vlan=100 useDHCP=true
time=2025-12-21T22:00:00.201Z level=INFO msg="Signaling device activation via mTLS" url=https://provisioning.example.com:8443/api/v1/device/activate
time=2025-12-21T22:00:00.300Z level=INFO msg="Device activation successful" status=activated vlan=100 transitionedAt=2025-12-21T22:00:00.299Z
time=2025-12-21T22:00:00.301Z level=INFO msg="Provisioning flow complete" serial=device-001 productionVLAN=100 activationStatus=activated
time=2025-12-21T22:00:00.302Z level=INFO msg="========================================"
time=2025-12-21T22:00:00.302Z level=INFO msg="DEVICE PROFILE"
time=2025-12-21T22:00:00.302Z level=INFO msg="========================================"
time=2025-12-21T22:00:00.302Z level=INFO msg="Serial Number" value=device-001
time=2025-12-21T22:00:00.302Z level=INFO msg=""
time=2025-12-21T22:00:00.302Z level=INFO msg="Production Network:"
time=2025-12-21T22:00:00.302Z level=INFO msg="  VLAN" value=100
time=2025-12-21T22:00:00.302Z level=INFO msg="  DHCP" value=true
time=2025-12-21T22:00:00.302Z level=INFO msg=""
time=2025-12-21T22:00:00.302Z level=INFO msg="Access Control Lists:"
time=2025-12-21T22:00:00.302Z level=INFO msg="  ACL 1:"
time=2025-12-21T22:00:00.302Z level=INFO msg="    Name" value=allow-https
time=2025-12-21T22:00:00.302Z level=INFO msg="    Priority" value=100
time=2025-12-21T22:00:00.302Z level=INFO msg="    Action" value=allow
time=2025-12-21T22:00:00.302Z level=INFO msg="    Match" value=map[tcp_dst:443]
time=2025-12-21T22:00:00.302Z level=INFO msg=""
time=2025-12-21T22:00:00.302Z level=INFO msg="========================================"
time=2025-12-21T22:00:00.302Z level=INFO msg="ACTIVATION RESPONSE"
time=2025-12-21T22:00:00.302Z level=INFO msg="========================================"
time=2025-12-21T22:00:00.302Z level=INFO msg="Status" value=activated
time=2025-12-21T22:00:00.302Z level=INFO msg="VLAN" value=100
time=2025-12-21T22:00:00.302Z level=INFO msg="Transitioned At" value=2025-12-21T22:00:00Z
time=2025-12-21T22:00:00.302Z level=INFO msg=""
time=2025-12-21T22:00:00.302Z level=INFO msg="Network transition complete!"
time=2025-12-21T22:00:00.302Z level=INFO msg="Device is now on production VLAN" vlan=100
time=2025-12-21T22:00:00.302Z level=INFO msg="Device provisioning completed successfully"
```

## Error Handling

The example includes automatic retry logic with exponential backoff. If provisioning fails, it will:

1. Log the error
2. Wait (with exponential backoff)
3. Retry up to the specified number of attempts
4. Exit with error if all retries fail

## Integration with Device Startup

This client can be integrated into device startup scripts:

```bash
#!/bin/bash
# /etc/init.d/device-provisioning

CERT_PATH="/etc/pki/idevid.pem"
KEY_PATH="/etc/pki/idevid-key.pem"
CA_PATH="/etc/pki/ca-bundle.pem"
SERVER="https://provisioning.example.com:8443"

# Run provisioning client
/usr/local/bin/provisioning-client \
  -server "$SERVER" \
  -cert "$CERT_PATH" \
  -key "$KEY_PATH" \
  -ca "$CA_PATH" \
  -retries 10 \
  -retry-delay 30s

# Check exit status
if [ $? -eq 0 ]; then
    echo "Device provisioning successful"
    exit 0
else
    echo "Device provisioning failed"
    exit 1
fi
```

## See Also

- [Provisioning Client Documentation](../../docs/PROVISIONING_CLIENT.md)
- [ACME Enrollment](../../docs/CA-ACME.md)
- [Device activation](../../docs/device/architecture.md#44-activation-identity-becomes-network-access)
