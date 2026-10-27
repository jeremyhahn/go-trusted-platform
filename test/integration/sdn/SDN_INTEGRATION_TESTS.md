# SDN/OVS Integration Tests

This directory contains comprehensive integration tests for the SDN/OVS network provisioning system. These tests verify the full network provisioning flow from device enrollment through production network access.

## Test Coverage

### 1. Network Provisioning Flow Tests (`network_provisioning_test.go`)

Tests the complete end-to-end network provisioning flow:

- **Bridge Creation**: Creates provisioning and production bridges
- **Port Management**: Creates ports with VLAN tagging
- **Network Phase Transitions**: Tests device lifecycle transitions through network phases
- **Device Profile Translation**: Converts device profiles to network configurations
- **VLAN Assignment**: Verifies VLAN changes during phase transitions
- **ACL Application**: Translates ACL rules to OpenFlow entries

**Key Test Cases**:
- `TestNetworkProvisioningFlow`: Complete provisioning flow from enrollment to production
- `TestDeviceProfileToNetworkConfig`: Device profile to network config translation
- `TestACLRulesAsOpenFlowEntries`: ACL to OpenFlow rule conversion

### 2. Policy Engine Integration Tests (`policy_engine_integration_test.go`)

Tests the policy engine with real OVS backend:

- **State Machine**: Tests port state transitions with real flows
- **Flow Installation**: Verifies OpenFlow rules are installed when policies are applied
- **Flow Removal**: Tests flow cleanup on policy removal
- **Certificate-Based Authentication**: Tests cert-based network authorization
- **Policy Lifecycle**: Tests complete policy application and removal

**Key Test Cases**:
- `TestPolicyEngineIntegration`: Full policy engine workflow
- `TestPolicyEngineWithCertificate`: Certificate-based authentication flow
- Tests all state transitions: Provisioning → Enrolled → Authorized
- Verifies flows are installed/removed correctly

### 3. Bridge and Port Management Tests (`bridge_port_management_test.go`)

Tests OVS bridge and port operations:

- **Bridge Operations**: Create, configure, list, and delete bridges
- **Port Operations**: Add, configure, list, and delete ports
- **VLAN Configuration**: Set and modify VLAN tags on ports
- **Port State Management**: Control port up/down states
- **Trunk VLAN Configuration**: Configure trunk ports with multiple VLANs

**Key Test Cases**:
- `TestBridgeManagement`: Complete bridge lifecycle
- `TestPortManagement`: Complete port lifecycle
- `TestPortStateManagement`: Port state transitions
- `TestVLANConfiguration`: VLAN configuration scenarios

### 4. OpenFlow Rules Tests (`openflow_rules_test.go`)

Tests OpenFlow rule installation for different network phases:

- **Provisioning Phase Rules**: Limited network access (DHCP, DNS, enrollment)
- **Production Phase Rules**: Full network access with ACLs
- **Quarantine Phase Rules**: Isolated/restricted network access
- **ACL Translation**: Convert ACL configs to OpenFlow rules
- **Flow Modification**: Update and remove flows

**Key Test Cases**:
- `TestOpenFlowRulesForNetworkPhases`: Rules for each network phase
- `TestACLToOpenFlowTranslation`: ACL to OpenFlow conversion
- `TestFlowModificationAndRemoval`: Flow lifecycle management
- `TestVLANFlowManipulation`: VLAN-related flow operations

The policy engine's port state-transition tests run in memory and live in
the unit suite, `pkg/sdn/policy/state_transition_test.go` (#964).

## Network Phases

The tests verify three distinct network phases:

### Provisioning Phase
- **VLAN**: 100 (default)
- **Purpose**: Initial enrollment and device registration
- **Network Access**: Restricted to essential services
  - DHCP (UDP 67/68)
  - DNS (UDP 53)
  - HTTPS enrollment (TCP 443)
  - ARP
  - All other traffic dropped

### Production Phase
- **VLAN**: 200 (default)
- **Purpose**: Normal operational network access
- **Network Access**: Full network access with ACLs
  - HTTP (TCP 80)
  - HTTPS (TCP 443)
  - SSH (TCP 22) - restricted to production subnet
  - DNS (UDP 53)
  - ICMP
  - Default allow policy

### Quarantine Phase
- **VLAN**: 999 (default)
- **Purpose**: Isolated network for policy violations
- **Network Access**: Completely restricted
  - All traffic dropped

## Running the Tests

### Prerequisites

- Open vSwitch installed (`openvswitch-switch` on Debian/Ubuntu)
- Root/sudo access for OVS operations
- Go 1.21+ installed

### Run All Tests

```bash
cd test/integration/sdn
./run-tests.sh
```

### Run Specific Test Suites

```bash
# Network provisioning tests
./run-tests.sh provision

# Policy engine tests
./run-tests.sh policy

# Bridge/port management tests
./run-tests.sh bridge

# OpenFlow rules tests
./run-tests.sh flows
```

### Manual OVS Setup

```bash
# Setup OVS environment
./run-tests.sh setup

# Check status
./run-tests.sh status

# Teardown when done
./run-tests.sh teardown
```

### Development Workflow

```bash
# Clean up leftover test bridges
./run-tests.sh cleanup

# Run specific test
go test -v -run TestNetworkProvisioningFlow

# Run with timeout
go test -v -timeout 10m -run TestPolicyEngine

# Run in devcontainer
docker exec -it devcontainer bash
cd /workspace/test/integration/sdn
./run-tests.sh
```

## Test Architecture

### OVS Client Integration

Tests use real OVS client connecting to:
- OVSDB socket: `/var/run/openvswitch/db.sock`
- OpenFlow sockets: `/var/run/openvswitch/<bridge>.mgmt`

### Flow Controller Implementation

`OVSFlowController` provides real OpenFlow rule management:
- Installs flows via native OpenFlow protocol
- Deletes flows by match criteria
- Lists installed flows
- Uses OpenFlow 1.3 for full feature support

### Mock Components

For isolated testing, mocks are provided:
- `MockPolicyExtractor`: Certificate policy extraction
- `MockCertificateValidator`: Certificate validation

## Device Profile Structure

Tests use realistic device profiles:

```go
DeviceProfile{
    ProvisioningNetwork: &NetworkPhaseConfig{
        VLAN: 100,
        ACLs: []ACLConfig{
            // DHCP, DNS, HTTPS enrollment only
        },
    },
    ProductionNetwork: &NetworkPhaseConfig{
        VLAN: 200,
        DHCPPool: &DHCPPoolConfig{...},
        ACLs: []ACLConfig{
            // Full network access with restrictions
        },
    },
    QuarantineNetwork: &NetworkPhaseConfig{
        VLAN: 999,
        ACLs: []ACLConfig{
            // Drop all traffic
        },
    },
}
```

## Integration Test Requirements

These are **integration tests** that:

1. **Modify system state**: Create/delete OVS bridges and flows
2. **Require OVS services**: ovsdb-server and ovs-vswitchd must be running
3. **Need elevated privileges**: Many OVS operations require root/sudo
4. **Are not isolated**: Tests interact with real OVS infrastructure

**Best Practice**: Run in devcontainer or dedicated test environment

## Troubleshooting

### OVS Not Starting

```bash
# Check if services are running
pgrep ovsdb-server
pgrep ovs-vswitchd

# Check logs
tail -f /var/log/openvswitch/ovsdb-server.log
tail -f /var/log/openvswitch/ovs-vswitchd.log

# Restart manually
./run-tests.sh teardown
./run-tests.sh setup
```

### Permission Denied

```bash
# Ensure socket has correct permissions
sudo chmod 666 /var/run/openvswitch/db.sock

# Or run tests with sudo
sudo -E ./run-tests.sh
```

### Leftover Test Bridges

```bash
# Clean up test bridges
./run-tests.sh cleanup

# Or manually
sudo ovs-vsctl list-br | grep -E 'test|prov|prod' | xargs -I {} sudo ovs-vsctl del-br {}
```

### Test Timeouts

```bash
# Increase timeout
go test -v -timeout 20m ./...

# Run specific test with debug output
go test -v -run TestNetworkProvisioningFlow
```

## CI/CD Integration

### GitHub Actions Example

```yaml
- name: Setup OVS
  run: |
    sudo apt-get update
    sudo apt-get install -y openvswitch-switch

- name: Run SDN Integration Tests
  run: |
    cd test/integration/sdn
    sudo -E ./run-tests.sh
```

### Docker-based Testing

```bash
# Run in devcontainer
make integration-test-sdn
```

## Contributing

When adding new tests:

1. Follow existing test patterns (setup, test, cleanup)
2. Use descriptive test names with proper prefixes
3. Clean up resources in defer statements
4. Use testify require/assert for assertions
5. Add timeout contexts to prevent hanging tests
6. Document complex test scenarios
7. Ensure tests are idempotent

## Performance

Typical test execution times:
- Bridge/Port Management: ~2 minutes
- Network Provisioning: ~3 minutes
- Policy Engine: ~4 minutes
- OpenFlow Rules: ~3 minutes
- Full Suite: ~15 minutes

## References

- [OVS Documentation](http://www.openvswitch.org/support/dist-docs/)
- [OpenFlow 1.3 Specification](https://www.opennetworking.org/software-defined-standards/specifications/)
- [Device Provisioning Flow](../../../docs/sdn/DEVICE_PROVISIONING.md)
- [Policy Engine Design](../../../docs/sdn/POLICY_ENGINE.md)
