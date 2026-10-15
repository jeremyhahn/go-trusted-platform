# SDN Integration Tests

Docker-based integration tests for the Software-Defined Networking (SDN) components of go-trusted-platform.

## Overview

These tests verify the OVS (Open vSwitch) integration including:
- OVSDB client connectivity and operations
- Bridge creation, configuration, and deletion
- Port management (standard, TAP, internal, patch, bond)
- TAP device creation and network interface operations
- OpenFlow rule management and flow tables
- Pure Go ARP table reader and lookup

## Architecture

The tests run in a privileged Docker container with:
- Open vSwitch (ovs-vswitchd and ovsdb-server)
- Go toolchain for running tests
- Network capabilities for TAP/TUN device creation
- Access to /dev/net/tun for TAP interfaces
- Access to /proc/net/arp for ARP table operations

## Prerequisites

- Docker with BuildKit support
- Docker Compose (optional, for docker-compose workflow)
- No root/sudo required on host - container runs with necessary capabilities

## Running Tests

### Using Make (Recommended)

Run all SDN integration tests:
```bash
make integration-test-sdn
```

It builds the shared devcontainer image (`make build-devcontainer`) and runs
the suite through `run-integration-tests.sh sdn`, which starts OVS, swtpm and
platformd first.

Open a shell in the devcontainer for SDN debugging:
```bash
make integration-test-sdn-shell
```

Remove the devcontainer image:
```bash
make devcontainer-clean
```

### Using Docker Compose

The compose file builds the devcontainer image and derives the build tags
from `make print-build-tags` (set `BUILD_TAGS` to override):
```bash
cd test/integration/sdn
docker compose up --build
docker compose down -v
```

### Manual Docker Commands

Run ARP tests only, from the repository root:
```bash
docker run --rm --privileged \
  --device /dev/net/tun:/dev/net/tun \
  -e AUTO_START_OVS=true \
  -v $(pwd):/workspace \
  -w /workspace/test/integration/sdn \
  trusted-platform-dev:latest \
  go test -v -timeout 5m -tags "integration $(make -s print-build-tags)" -run TestNativeARP
```

## Test Categories

### OVSDB Tests (`ovsdb_test.go`)
- Client connection and authentication
- Database operations (CRUD)
- Transaction support
- Reconnection handling
- Error handling

### Bridge Tests (`bridge_test.go`)
- Bridge creation and deletion
- Bridge configuration (STP, RSTP, fail mode)
- External IDs and metadata
- Multiple bridge management
- Bridge listing and querying

### Port Tests (`port_test.go`)
- Port creation and deletion
- Port configuration (VLAN tags, trunks)
- External IDs
- Multiple ports per bridge
- Link aggregation (bonding)

### TAP Device Tests (`tap_test.go`)
- TAP device creation
- Interface configuration (IP, MTU, state)
- Internal ports with IP assignment
- Virtual Ethernet (VETH) pairs
- Patch ports for bridge interconnection

### Flow Tests (`flow_test.go`)
- OpenFlow rule creation and deletion
- Flow matching criteria (IP, TCP, MAC, VLAN, ARP)
- Flow actions (output, flood, modify, resubmit)
- Multiple flow tables
- Flow priority ordering
- Flow statistics

### ARP Native Tests (`arp_native_test.go`)
- Reading /proc/net/arp table
- Retrieving all ARP entries
- MAC address lookup by IP
- IP address lookup by MAC (reverse lookup)
- Dynamic ARP entry creation via ping
- Localhost handling
- Error handling (invalid IP, invalid MAC, not found)
- Convenience function testing

## Container Details

### Privileged Mode
Tests require privileged mode for:
- Creating network interfaces
- Managing TAP/TUN devices
- Kernel module loading (tun)
- Network namespace operations
- Reading /proc/net/arp

### Exposed Ports
- 6640: OVSDB TCP port (for external clients)

### Volumes
- `/workspace`: Project source code
- `/var/run/openvswitch`: OVS runtime state
- `/var/log/openvswitch`: OVS logs

### Environment Variables
- `CGO_ENABLED=1`: Enable CGO for Go builds
- `GOCACHE=/tmp/go-cache`: Go build cache location
- `GOPATH=/go`: Go workspace

## Troubleshooting

### OVS Not Starting

Check OVS logs:
```bash
docker exec go-trusted-platform-sdn-test cat /var/log/openvswitch/ovsdb-server.log
docker exec go-trusted-platform-sdn-test cat /var/log/openvswitch/ovs-vswitchd.log
```

Verify OVS is running:
```bash
docker exec go-trusted-platform-sdn-test ovs-vsctl show
```

### TAP Device Creation Fails

Ensure container is running in privileged mode:
```bash
docker inspect go-trusted-platform-sdn-test | grep Privileged
```

Check /dev/net/tun is available:
```bash
docker exec go-trusted-platform-sdn-test ls -la /dev/net/tun
```

### ARP Table Not Accessible

Verify /proc/net/arp exists:
```bash
docker exec go-trusted-platform-sdn-test cat /proc/net/arp
```

Check network interfaces are up:
```bash
docker exec go-trusted-platform-sdn-test ip link show
```

Test connectivity to gateway:
```bash
docker exec go-trusted-platform-sdn-test ping -c 1 $(ip route show default | awk '{print $3}')
```

### Test Timeouts

Increase test timeout:
```bash
go test -v -timeout 30m ./...
```

### Connection Refused (OVSDB)

Verify OVSDB is listening:
```bash
docker exec go-trusted-platform-sdn-test netstat -tlnp | grep 6640
```

Check OVSDB socket:
```bash
docker exec go-trusted-platform-sdn-test ls -la /var/run/openvswitch/db.sock
```

## Development

### Adding New Tests

1. Create a new `*_test.go` file in this directory
2. Import required packages
3. Use the helper functions from existing tests
4. Follow the test naming convention: `Test<Feature><Action>`
5. Always clean up resources in `defer` statements

### Test Patterns

```go
func TestFeature(t *testing.T) {
    bridgeName := "test-br-feature"
    defer cleanupBridge(t, bridgeName)

    // Create bridge
    err := createBridge(bridgeName)
    require.NoError(t, err)

    // Test logic here

    // Assertions
    assert.True(t, condition, "message")
}
```

### Helper Functions

Available helper functions:
- `createBridge(name)`: Create OVS bridge
- `deleteBridge(name)`: Delete OVS bridge
- `bridgeExists(name)`: Check if bridge exists
- `addPort(bridge, port)`: Add port to bridge
- `deletePort(bridge, port)`: Remove port from bridge
- `addFlow(bridge, flow)`: Add OpenFlow rule
- `deleteFlow(bridge, match)`: Remove OpenFlow rule

ARP test helpers:
- `setupTestGateway(t)`: Create a test-owned gateway (a namespace behind a veth pair) and return its IP
- `pingHost(t, host)`: Ping a host to populate ARP cache

## Performance Considerations

- Tests run sequentially to avoid resource conflicts
- Each test creates isolated bridges with unique names
- Cleanup happens in defer statements to prevent resource leaks
- Timeouts are set to prevent hanging tests
- Use `t.Parallel()` cautiously - network operations may conflict
- ARP lookups read /proc/net/arp synchronously

## Security Notes

- Tests run in privileged containers - use only in trusted environments
- Never run on production systems
- Container has full network access
- TAP devices can affect host networking if misconfigured
- ARP table access reveals network topology information

## Future Enhancements

- [ ] Integration with OVN (Open Virtual Network)
- [ ] Distributed virtual switch tests
- [ ] Network performance benchmarks
- [ ] Security group rule testing
- [ ] NAT and routing table tests
- [ ] Quality of Service (QoS) tests
- [ ] DPDK integration tests
- [ ] ARP cache manipulation tests
- [ ] IPv6 neighbor discovery tests
