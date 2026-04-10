# Client-Side Network Setup

Automated network configuration during device enrollment using systemd and mTLS.

## Overview

The network setup service runs on device boot to:
1. Fetch device profile from platform API using mTLS
2. Parse production network configuration
3. Generate systemd-networkd config files
4. Reload network configuration
5. Activate device on platform

## Architecture

```
System Boot
    │
    ▼
systemd starts multi-user.target
    │
    ├──────────────────┬──────────────────┐
    ▼                  ▼                  ▼
network.target   platform-api     systemd-networkd
    │                  │                  │
    └──────────────────┴──────────────────┘
                       │
                       ▼
         trusted-platform-network.service
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼
   [Acquire lock]           [Check prerequisites]
         │                           │
         ▼                           ▼
   [Fetch profile]          [Validate certificates]
         │                           │
         ▼                           ▼
   [Generate config]        [Reload networkd]
         │                           │
         ▼                           ▼
   [Verify connectivity]    [Call activation]
         │                           │
         ▼                           ▼
   [Save state]             [Release lock]
```

## Components

### Network Setup Script

**Location:** `/usr/local/bin/trusted-platform-network.sh`

**Features:**
- Production-grade error handling with typed exit codes
- Exclusive locking to prevent concurrent execution
- Logging to `/var/log/trusted-platform/network-setup.log`
- Input validation for API responses
- Cleanup handlers for temporary files

### Systemd Service

**Location:** `/lib/systemd/system/trusted-platform-network.service`

**Configuration:**
- `Type=oneshot` for one-time execution
- `RemainAfterExit=yes` to maintain active state
- Security hardening via systemd features
- Capability restrictions (CAP_NET_ADMIN only)

## Data Flow

```
1. Service starts
   │
2. Validate prerequisites (curl, jq, systemd-networkd)
   │
3. Acquire lock on /run/trusted-platform/network-setup.lock
   │
4. Fetch profile from API (mTLS)
   GET /api/v1/device/profile
   │
   Response:
   {
     "id": 1,
     "name": "device-001",
     "production_network": {
       "vlan": 100,
       "static_ip": "192.168.1.100/24",
       "gateway": "192.168.1.1",
       "dns": ["8.8.8.8"]
     }
   }
   │
5. Validate profile JSON structure
   │
6. Generate /etc/systemd/network/10-eth0.network
   [Match]
   Name=eth0
   VLAN=100

   [Network]
   DHCP=no
   DNS=8.8.8.8
   Address=192.168.1.100/24
   Gateway=192.168.1.1
   │
7. Reload systemd-networkd
   │
8. Verify connectivity (ping API with retries)
   │
9. Call POST /api/v1/device/activate
   │
10. Save state to /var/lib/trusted-platform/network-state.json
   │
11. Release lock and exit
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PLATFORM_API_URL` | `https://localhost:8443` | Platform API base URL |
| `CERT_PATH` | `/etc/trusted-platform/certs/idevidcert.pem` | IDevID certificate |
| `KEY_PATH` | `/etc/trusted-platform/certs/idevidkey.pem` | IDevID private key |
| `CA_PATH` | `/etc/trusted-platform/certs/ca.pem` | CA certificate |
| `NETWORK_INTERFACE` | `eth0` | Primary network interface |

### Configuration File

Optional configuration at `/etc/trusted-platform/network.env`:

```bash
PLATFORM_API_URL=https://platform.example.com:8443
NETWORK_INTERFACE=ens192
```

## Error Handling

| Exit Code | Scenario | Action |
|-----------|----------|--------|
| 0 | Success | Device activated |
| 1 | Prerequisites missing | Log error, exit |
| 10 | Certificate missing | Log error, exit |
| 11 | API unavailable | Log error, exit |
| 12 | Invalid profile JSON | Log error, exit |
| 13 | Cannot write network config | Log error, exit |
| 14 | Lock acquisition failed | Log error, exit |
| 15 | Activation failed | Log error, exit |

## Security

### Authentication
- mTLS with IDevID certificate for all API calls
- CA certificate validates platform API server
- No shared secrets transmitted

### Process Isolation
- Minimal capabilities (CAP_NET_ADMIN, CAP_DAC_OVERRIDE)
- System call filtering (@system-service)
- Restricted file access paths

### Credential Protection
- Certificates in `/etc/trusted-platform/certs/` (root-owned)
- State file permissions: 0600
- Temporary files cleaned up with trap handlers

## Performance

| Operation | Duration | Notes |
|-----------|----------|-------|
| Prerequisites check | < 100ms | Command lookups |
| Certificate validation | < 50ms | File stats |
| API profile fetch | 100-500ms | Network dependent |
| Config generation | 100-200ms | File writes |
| systemd reload | 500-1000ms | Daemon operations |
| Connectivity verify | 2-10s | With retries |
| **Total** | **2-15s** | Typical end-to-end |

## Troubleshooting

### View Service Status
```bash
systemctl status trusted-platform-network.service
```

### View Logs
```bash
journalctl -u trusted-platform-network.service
cat /var/log/trusted-platform/network-setup.log
```

### Manual Execution
```bash
/usr/local/bin/trusted-platform-network.sh
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "Certificate missing" | IDevID not provisioned | Run ACME enrollment |
| "API unavailable" | Network not ready | Check provisioning network |
| "Lock failed" | Concurrent execution | Wait for other process |
| "Activation failed" | Server error | Check platform logs |

## ISO Integration

The network setup files are automatically included in Trusted Platform ISOs during the customization phase:

```go
// pkg/iso/customize.go
func (c *Customizer) CopyNetworkSetupFiles(ctx context.Context) error {
    // Copies script to: /usr/local/bin/trusted-platform-network.sh
    // Copies service to: /lib/systemd/system/trusted-platform-network.service
}
```
