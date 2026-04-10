# Integration Testing with Enhanced DevContainer

## Overview

The enhanced devcontainer provides a complete, isolated environment for running integration tests that require:
- Software TPM (swtpm)
- QEMU virtual machines with KVM acceleration
- Open vSwitch for SDN/networking
- Full kernel module support

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Host System                                                  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ DevContainer (Privileged)                            │  │
│  │                                                       │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌────────────┐ │  │
│  │  │ OVS         │  │ QEMU/KVM     │  │ swtpm      │ │  │
│  │  │ Services    │  │ VMs          │  │ Instances  │ │  │
│  │  │             │  │              │  │            │ │  │
│  │  │ ovsdb-      │  │ VM1 ───┐     │  │ TPM0       │ │  │
│  │  │  server     │  │        │     │  │ TPM1       │ │  │
│  │  │ ovs-        │  │ VM2 ───┼─────┼──│ TPM2       │ │  │
│  │  │  vswitchd   │  │        │     │  │            │ │  │
│  │  │             │  │ VM3 ───┘     │  │            │ │  │
│  │  └─────────────┘  └──────────────┘  └────────────┘ │  │
│  │                                                       │  │
│  │  ┌──────────────────────────────────────────────┐   │  │
│  │  │ Go Test Harness                              │   │  │
│  │  │  • Creates VMs                               │   │  │
│  │  │  • Manages OVS bridges/ports                 │   │  │
│  │  │  • Coordinates test execution                │   │  │
│  │  │  • Validates state transitions               │   │  │
│  │  └──────────────────────────────────────────────┘   │  │
│  │                                                       │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                              │
│  Devices: /dev/kvm, /dev/net/tun                           │
└─────────────────────────────────────────────────────────────┘
```

## Test Categories

### 1. SDN/OVS Tests (`test/integration/sdn/`)

**Purpose**: Validate network virtualization, OpenFlow rules, and OVS integration

**What's Tested**:
- Bridge creation and deletion
- Port management (tap, internal, veth)
- OpenFlow rule installation and verification
- Flow table management
- ARP handling (native and OpenFlow)
- Network policy enforcement
- State transitions

**Run Command**:
```bash
make integration-test-sdn-full
```

**Requirements**:
- `/dev/net/tun` device
- Privileged mode
- NET_ADMIN capability

**Example Test**:
```go
func TestBridgeCreation(t *testing.T) {
    // Test creates OVS bridge, adds ports, validates connectivity
    bridge := ovs.NewBridge("test-br0")
    bridge.Create()
    defer bridge.Delete()

    port := bridge.AddPort("tap0", ovs.PortTypeTap)
    assert.NotNil(t, port)
}
```

### 2. vTPM Tests (`test/integration/vtpm/`)

**Purpose**: Validate TPM operations in QEMU VMs

**What's Tested**:
- swtpm initialization
- VM boot with vTPM attached
- TPM key generation
- Attestation flows
- Sealed secrets
- PCR measurements

**Run Command**:
```bash
make integration-test-vtpm
```

**Requirements**:
- swtpm binary
- QEMU
- `/dev/kvm` (optional, for speed)

**Example Test**:
```go
func TestVMWithTPM(t *testing.T) {
    // Test boots VM with vTPM, performs attestation
    vm := qemu.NewVM("test-vm")
    vm.WithTPM(swtpm.NewInstance())
    vm.Boot()
    defer vm.Shutdown()

    attestation := vm.Attest()
    assert.NotEmpty(t, attestation.Quote)
}
```

### 3. Device Profile Tests (`test/integration/sdn/state_transition_integration_test.go`)

**Purpose**: Validate network state transitions during device lifecycle

**What's Tested**:
- Provisioning network setup
- Device enrollment flow
- Network transition to production
- Flow rule updates
- Policy enforcement across states

**Run Command**:
```bash
make integration-test-device-profile
```

**Requirements**:
- OVS running
- `/dev/net/tun`
- Privileged mode

**Test Flow**:
```
1. Device boots in "provisioning" network
2. Device enrolls via ACME
3. Network transitions to "production"
4. OVS flows updated automatically
5. Access policies enforced
6. Connectivity validated
```

### 4. E2E Tests (`make integration-test-e2e`)

**Purpose**: Full end-to-end provisioning-to-production workflow

**What's Tested**:
- Complete VM lifecycle
- Network provisioning
- TPM-backed attestation
- Certificate issuance
- Network transition
- Production operation

**Run Command**:
```bash
make integration-test-e2e
```

**Requirements**:
- All of the above
- `/dev/kvm` strongly recommended
- At least 4GB RAM

**Test Duration**: ~5-10 minutes (with KVM), ~30 minutes (without KVM)

## Test Infrastructure Components

### OVS Services

The `run-tests.sh` scripts automatically:
1. Initialize OVSDB
2. Start ovsdb-server
3. Start ovs-vswitchd
4. Verify services are running
5. Clean up on exit

**Manual Control**:
```bash
# Inside container
/usr/local/bin/entrypoint.sh ovs-start
/usr/local/bin/entrypoint.sh ovs-stop
```

### QEMU VM Management

VMs are created programmatically via `pkg/qemu/`:
```go
vm := qemu.NewVM(&qemu.Config{
    Name:   "test-vm",
    Memory: 2048,
    CPUs:   2,
    Disks: []qemu.Disk{
        {Path: "/tmp/test.qcow2", Size: "10G"},
    },
    Network: qemu.NetworkConfig{
        Type:   "tap",
        Bridge: "provisioning-br",
    },
    TPM: qemu.TPMConfig{
        Enabled: true,
        Socket:  "/tmp/swtpm.sock",
    },
})
```

### swtpm Management

Software TPM instances are created per VM:
```go
tpm := swtpm.New(&swtpm.Config{
    TPMVersion: "2.0",
    StateDir:   "/tmp/tpm-state",
    CtrlSocket: "/tmp/swtpm.sock",
})
tpm.Start()
defer tpm.Stop()
```

## Docker Compose Multi-Service Testing

For complex scenarios requiring multiple isolated services:

### Service: devcontainer
Primary development and test execution environment
- All tools pre-installed
- OVS auto-started
- Persistent volumes for caches

### Service: ovs-standalone
Dedicated OVS instance for distributed testing
- Independent OVS database
- Health checks
- Can be used as remote OVSDB target

### Service: qemu-coordinator
Manages QEMU VM pool
- 4GB shared memory
- Connected to OVS network
- Can spawn multiple VM instances

**Usage**:
```bash
# Start all services
make devcontainer-compose-up

# Run tests across services
docker exec devcontainer /workspace/test/integration/sdn/run-tests.sh
docker exec qemu-coordinator /workspace/test/integration/vtpm/run-tests.sh

# Cleanup
make devcontainer-compose-down
```

## Test Execution Patterns

### Pattern 1: Isolated Test (Recommended)

Each test manages its own resources:
```go
func TestIsolated(t *testing.T) {
    bridge := createBridge(t, "test-br")
    defer bridge.Delete()

    // Test logic
}
```

**Pros**: No test interference, reliable cleanup
**Cons**: Slower (setup/teardown per test)

### Pattern 2: Shared Infrastructure

Tests share common setup:
```go
func TestMain(m *testing.M) {
    setupOVS()
    code := m.Run()
    teardownOVS()
    os.Exit(code)
}
```

**Pros**: Faster (single setup)
**Cons**: Test failures can cascade, state pollution

### Pattern 3: Hierarchical (Used in Device Profile Tests)

Parent creates infrastructure, children test scenarios:
```go
func TestDeviceLifecycle(t *testing.T) {
    setup := createTestEnvironment(t)
    defer setup.Cleanup()

    t.Run("Provisioning", func(t *testing.T) { /* ... */ })
    t.Run("Enrollment", func(t *testing.T) { /* ... */ })
    t.Run("Production", func(t *testing.T) { /* ... */ })
}
```

**Pros**: Realistic, tests full flow
**Cons**: Failures can be hard to isolate

## Performance Optimization

### Use KVM Acceleration

**Without KVM**: QEMU uses software emulation (10-50x slower)
**With KVM**: Near-native performance

Verify KVM is available:
```bash
ls -la /dev/kvm
# crw-rw---- 1 root kvm ...
```

Add your user to kvm group:
```bash
sudo usermod -a -G kvm $USER
```

### Cache Go Modules

Persistent volumes cache downloaded modules:
```yaml
volumes:
  - go-mod-cache:/go/pkg/mod
  - go-build-cache:/root/.cache/go-build
```

First run: ~5 minutes (download all modules)
Subsequent runs: ~30 seconds (use cache)

### Parallel Test Execution

Independent tests can run in parallel:
```bash
go test -parallel=4 ./test/integration/sdn/...
```

**Note**: OVS tests often share global state (bridges, ports) so parallelism may cause conflicts. Use unique resource names or run serially.

### Incremental Testing

Test a specific scenario:
```bash
go test -run TestSpecificScenario ./test/integration/sdn/...
```

## Debugging Integration Tests

### Interactive Debugging

```bash
# Start container with full capabilities
make devcontainer-shell-full

# Inside container, manually set up test environment
/usr/local/bin/entrypoint.sh ovs-start

# Run tests with verbose output
go test -v -run TestBridgeCreation ./test/integration/sdn/...

# Inspect OVS state
ovs-vsctl show
ovs-ofctl dump-flows br0
```

### View OVS Logs

```bash
# Inside container
tail -f /var/log/openvswitch/ovs-vswitchd.log
tail -f /var/log/openvswitch/ovsdb-server.log
```

### Attach to Running VM

```bash
# QEMU VMs can have a monitor console
qemu-system-x86_64 -monitor telnet::4444,server,nowait ...

# Connect to monitor
telnet localhost 4444
```

### Inspect TPM State

```bash
# Connect to swtpm control socket
swtpm_ioctl --tcp localhost:2322 -C
swtpm_ioctl --tcp localhost:2322 -l
```

### Debug Network Connectivity

```bash
# Inside container with OVS running
ip link show
ovs-vsctl show
ovs-ofctl dump-ports br0
ovs-ofctl dump-flows br0
tcpdump -i br0
```

## Common Issues

### Issue: OVS fails to start

**Symptom**: Tests fail with "cannot connect to OVSDB"

**Cause**: OVS services not running

**Solution**:
```bash
# Check if services are running
pgrep ovsdb-server
pgrep ovs-vswitchd

# Restart OVS
/usr/local/bin/entrypoint.sh ovs-stop
/usr/local/bin/entrypoint.sh ovs-start
```

### Issue: Tests timeout

**Symptom**: Tests hang indefinitely

**Cause**: Waiting for VM that won't boot, or deadlock

**Solution**:
```bash
# Increase timeout
go test -timeout=30m ...

# Or debug interactively
make devcontainer-shell-full
# Run specific test with verbose output
```

### Issue: "Cannot allocate memory" when starting VM

**Symptom**: QEMU fails to allocate memory for VM

**Cause**: Insufficient shared memory

**Solution**:
```bash
# Increase --shm-size when running container
docker run --shm-size=4g ...
# Or in docker-compose.yml:
#   shm_size: '4gb'
```

### Issue: KVM not available

**Symptom**: `/dev/kvm` permission denied

**Cause**: Device not mounted or permissions issue

**Solution**:
```bash
# Ensure device is mounted
docker run --device /dev/kvm:/dev/kvm ...

# Check host permissions
ls -la /dev/kvm
# Should be accessible to docker user/group
```

### Issue: Tests pass locally but fail in CI

**Symptom**: Integration tests work on developer machine but fail in CI pipeline

**Cause**: CI environment may not have KVM or privileged mode

**Solution**:
```yaml
# CI configuration (GitHub Actions example)
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - name: Enable KVM
      run: |
        sudo apt-get install -y qemu-kvm
        sudo chmod 666 /dev/kvm

    - name: Run Tests
      run: make integration-test-all
```

Or disable KVM requirement:
```go
// In test code
if !kvmAvailable() {
    t.Skip("KVM not available, skipping hardware acceleration test")
}
```

## Best Practices

### 1. Clean Resource Names

Use unique names to avoid conflicts:
```go
testName := fmt.Sprintf("test-%d", time.Now().UnixNano())
bridge := ovs.NewBridge(testName)
```

### 2. Always Cleanup

Use defer for guaranteed cleanup:
```go
func TestExample(t *testing.T) {
    bridge := createBridge(t, "test-br")
    defer bridge.Delete()  // Always cleanup

    // Test logic
}
```

### 3. Validate Assumptions

Check prerequisites before testing:
```go
func TestRequiresKVM(t *testing.T) {
    if !fileExists("/dev/kvm") {
        t.Skip("KVM not available")
    }
    // Test with KVM
}
```

### 4. Use Table-Driven Tests

For multiple scenarios:
```go
func TestNetworkStates(t *testing.T) {
    tests := []struct {
        name  string
        state string
        flows []FlowRule
    }{
        {"Provisioning", "prov", provFlows},
        {"Production", "prod", prodFlows},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test each scenario
        })
    }
}
```

### 5. Comprehensive Error Messages

Provide context in failures:
```go
assert.NotNil(t, result, "Expected VM to boot successfully, but got nil. Check QEMU logs at %s", logPath)
```

## Metrics and Monitoring

### Test Coverage

```bash
# Run with coverage
go test -cover ./test/integration/sdn/...

# Generate HTML report
go test -coverprofile=/tmp/coverage.out ./test/integration/sdn/...
go tool cover -html=/tmp/coverage.out
```

### Test Duration

```bash
# Show test durations
go test -v ./test/integration/... 2>&1 | grep -E "PASS|FAIL"

# Benchmark mode
go test -bench=. ./test/integration/sdn/...
```

### Resource Usage

```bash
# Monitor container resources
docker stats go-trusted-platform-dev

# Inside container, monitor OVS
ovs-appctl memory/show
ovs-appctl coverage/show
```

## Future Enhancements

### Planned Improvements

1. **Distributed Testing**: Run tests across multiple containers in docker-compose
2. **Performance Benchmarks**: Standardized benchmark suite for OVS operations
3. **Chaos Testing**: Inject failures (network drops, OVS crashes) and verify recovery
4. **Visual Testing Reports**: Generate HTML reports with network topology diagrams
5. **CI/CD Optimization**: Pre-built container images for faster CI runs

### Contributing Tests

When adding new integration tests:

1. Place in appropriate directory (`sdn/`, `vtpm/`, etc.)
2. Update corresponding `run-tests.sh` script
3. Add Makefile target if needed
4. Document in this file
5. Ensure cleanup is robust
6. Add to `integration-test-all` target

## References

- OVS Documentation: http://www.openvswitch.org/support/dist-docs/
- QEMU Documentation: https://www.qemu.org/documentation/
- swtpm Documentation: https://github.com/stefanberger/swtpm
- Go Testing: https://pkg.go.dev/testing
