# End-to-End Device Provisioning Integration Test

This directory contains comprehensive end-to-end integration tests for the complete device provisioning workflow with network transitions.

## Overview

The E2E test validates the full device provisioning lifecycle:

1. **Network Setup**: Creates isolated OVS bridges for provisioning (VLAN 100) and production (VLAN 200) networks
2. **Server Boot**: Boots platform server VM with CA, ACME, and DNS services
3. **Client Provisioning**: Boots client VM on provisioning network
4. **TPM Attestation**: Client performs TPM-based attestation
5. **ACME Enrollment**: Client requests certificate via ACME enroll-01 challenge
6. **Certificate Issuance**: Server validates attestation and issues certificate with network policy
7. **Network Transition**: Server transitions client port from provisioning to production VLAN
8. **Verification**: Validates client is on production network with correct ACLs

## Test Modes

### 1. Infrastructure Validation Mode (Default)

Validates the test infrastructure without requiring pre-built ISOs:

- OVS bridge creation and configuration
- QEMU VM creation with vTPM
- TAP interface setup
- Policy engine integration

**Run with:**
```bash
make integration-test-e2e
```

### 2. Full Integration Mode

Runs complete provisioning workflow with actual platform ISOs:

**Prerequisites:**
- Build server and client ISOs using `pkg/iso` builder
- ISOs must have platform installed and configured

**Run with:**
```bash
export INTEGRATION_TEST_SERVER_ISO=/path/to/server.iso
export INTEGRATION_TEST_CLIENT_ISO=/path/to/client.iso
make integration-test-e2e
```

## Requirements

### Container-Based Testing (Recommended)

Tests run inside the devcontainer which provides all dependencies. No root required on the host:

```bash
# Build devcontainer (one time)
make devcontainer-build

# Run tests
make integration-test-e2e
```

The container includes:
- QEMU with KVM support (if /dev/kvm available)
- Open vSwitch with ovsdb-server and ovs-vswitchd
- swtpm for TPM emulation
- All network capabilities (CAP_NET_ADMIN)

### Host Requirements

- Docker with BuildKit support
- Linux host (for /dev/kvm access, optional but faster)
- 8GB RAM minimum
- 20GB free disk space

## Network Architecture

### Provisioning Network (VLAN 100)

```
┌─────────────────────────────────────────┐
│         br-prov (10.100.0.1/24)         │
│              VLAN 100                    │
└─────────────┬───────────────────────────┘
              │
    ┌─────────┴─────────┐
    │                   │
┌───▼────┐         ┌────▼────┐
│ Server │         │ Client  │
│  VM    │         │   VM    │
│ .10    │         │  DHCP   │
└────────┘         └─────────┘
```

**Purpose**: Initial device provisioning and enrollment
- Limited ACLs (HTTPS for ACME, DNS only)
- Server runs CA, ACME, and DNS services
- Client performs attestation and enrollment

### Production Network (VLAN 200)

```
┌─────────────────────────────────────────┐
│         br-prod (10.200.0.1/24)         │
│              VLAN 200                    │
└─────────────┬───────────────────────────┘
              │
    ┌─────────┴─────────┐
    │                   │
┌───▼────┐         ┌────▼────┐
│ Server │         │ Client  │
│  VM    │         │   VM    │
│ .10    │         │  DHCP   │
└────────┘         └─────────┘
```

**Purpose**: Production workload network
- Permissive ACLs for production traffic
- Full network connectivity
- Client has validated certificate

## Test Phases

### Phase 1: Infrastructure Validation

Verifies test infrastructure is properly configured:

```go
✓ OVS bridges created (br-prov, br-prod)
✓ OVMF firmware available
✓ Server VM and TPM created
✓ Client VM and TPM created
✓ Policy engine initialized
```

### Phase 2: Server Provisioning

Boots and provisions the platform server:

```go
✓ Server VM boots from ISO (install mode)
✓ Server completes firstboot provisioning
✓ CA initialized and root/intermediate certs created
✓ ACME server listening on port 8443
✓ DNS server listening on port 9053
```

### Phase 3: Client Provisioning

Client boots and performs ACME enrollment:

```go
✓ Client VM boots from ISO (install mode)
✓ Client on provisioning network (VLAN 100)
✓ Provisioning ACLs applied (HTTPS, DNS only)
✓ Client performs TPM attestation
✓ Client requests certificate via ACME enroll-01
✓ Server validates attestation
✓ Certificate issued with network policy metadata
✓ Client transitions to enrolled state
```

### Phase 4: Network Transition

Server transitions client to production network:

```go
✓ Client port removed from br-prov
✓ Client port added to br-prod
✓ Production VLAN tag applied (200)
✓ Production ACLs applied
✓ Port state transitions to authorized
```

### Phase 5: Verification

Validates final state:

```go
✓ Client port on production bridge
✓ Client on production VLAN (200)
✓ Production ACLs active
✓ Client certificate contains policy
✓ DNS resolution works on production network
✓ Network connectivity validated
```

## Test Structure

```
test/integration/e2e/
├── README.md                      # This file
├── config.go                      # Test configuration
├── setup.go                       # Infrastructure setup
├── cleanup.go                     # Resource cleanup
└── e2e_provisioning_test.go       # Main test implementation
```

## Configuration

### Default Configuration

```go
// Network - Provisioning
ProvisioningVLAN     = 100
ProvisioningBridge   = "br-prov"
ProvisioningSubnet   = "10.100.0.0/24"
ProvisioningGateway  = "10.100.0.1"
ProvisioningServerIP = "10.100.0.10"

// Network - Production
ProductionVLAN       = 200
ProductionBridge     = "br-prod"
ProductionSubnet     = "10.200.0.0/24"
ProductionGateway    = "10.200.0.1"
ProductionServerIP   = "10.200.0.10"

// Resources
DiskSize             = "10G"
MemoryMB             = 4096
CPUCores             = 4

// Timeouts
ServerBootTimeout    = 10 * time.Minute
ClientBootTimeout    = 15 * time.Minute
EnrollmentTimeout    = 10 * time.Minute
```

### Customization

Override defaults by modifying `config.go` or through environment variables.

## Debugging

### Failed Test Artifacts

When a test fails, artifacts are preserved for debugging:

```bash
test-integration-e2e/
├── server/
│   ├── serial.log           # Server console output
│   ├── tpm/                 # Server TPM state
│   └── nvram/               # Server UEFI vars
├── client/
│   ├── serial.log           # Client console output
│   ├── tpm/                 # Client TPM state
│   └── nvram/               # Client UEFI vars
├── server-disk.qcow2        # Server disk image
└── client-disk.qcow2        # Client disk image
```

### Check Serial Console Logs

```bash
# Server console output
tail -f test-integration-e2e/server/serial.log

# Client console output
tail -f test-integration-e2e/client/serial.log
```

### Inspect OVS Bridges (inside container)

```bash
# Get a shell in the devcontainer
make devcontainer-shell

# List bridges
ovs-vsctl show

# List flows
ovs-ofctl dump-flows br-prov
ovs-ofctl dump-flows br-prod

# Check port configuration
ovs-vsctl list port tap-server
ovs-vsctl list port tap-client
```

### Inspect TPM State

```bash
# Server TPM
swtpm_ioctl --unix test-integration-e2e/server/tpm/swtpm.sock -s

# Client TPM
swtpm_ioctl --unix test-integration-e2e/client/tpm/swtpm.sock -s
```

### Manual Cleanup (inside container)

If the test crashes and doesn't clean up:

```bash
# Get a shell in the devcontainer
make devcontainer-shell

# Kill VMs
pkill -f qemu-system-x86_64

# Stop TPMs
pkill -f swtpm

# Remove bridges
ovs-vsctl del-br br-prov
ovs-vsctl del-br br-prod

# Remove work directory
rm -rf test-integration-e2e/
```

## Building Test ISOs

To run the full integration test, you need to build platform ISOs:

```bash
# Build server ISO
make iso-server

# Build client ISO
make iso-client

# Set environment variables and run test
export INTEGRATION_TEST_SERVER_ISO=build/iso/server.iso
export INTEGRATION_TEST_CLIENT_ISO=build/iso/client.iso
make integration-test-e2e
```

## CI/CD Integration

### GitHub Actions

```yaml
name: E2E Integration Test

on: [push, pull_request]

jobs:
  e2e-test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build devcontainer
        run: make devcontainer-build

      - name: Run E2E test
        run: make integration-test-e2e
```

## Performance Benchmarks

Expected execution times:

- **Infrastructure validation**: ~2 minutes
- **Full integration (with ISOs)**: ~30-45 minutes
  - Server boot and provision: ~10 minutes
  - Client boot and enroll: ~15 minutes
  - Network transition: <1 minute
  - Verification: ~1 minute

## Troubleshooting

### KVM not available

If `/dev/kvm` doesn't exist, the test runs in TCG mode (slower).
The devcontainer automatically detects and uses KVM when available.

To enable KVM on the host (for faster tests):
```bash
# Check KVM support
lsmod | grep kvm

# Load KVM module (on host)
modprobe kvm
modprobe kvm_intel  # or kvm_amd
```

### OVS issues inside container

The devcontainer automatically starts OVS services. To debug:
```bash
# Get a shell in the container
make devcontainer-shell

# Check OVS status
ovs-vsctl show
ovs-appctl version
```

### QEMU fails to start

```bash
# Check OVMF firmware paths
ls -la /usr/share/OVMF/
ls -la /usr/share/edk2-ovmf/

# Test QEMU manually
qemu-system-x86_64 -version
```

### Test timeout

Increase timeouts in `config.go`:

```go
ServerBootTimeout = 20 * time.Minute
ClientBootTimeout = 30 * time.Minute
```

## Related Documentation

- [QEMU Package](../../../pkg/qemu/README.md)
- [SDN Package](../../../pkg/sdn/README.md)
- [ISO Builder](../../../pkg/iso/README.md)
- [vTPM Package](../../../pkg/vtpm/README.md)
- [Policy Engine](../../../pkg/sdn/policy/README.md)

## License

Copyright (c) 2025 Jeremy Hahn
SPDX-License-Identifier: Apache-2.0
