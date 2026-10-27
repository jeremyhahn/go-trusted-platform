# Development Container - Enhanced SDN/OVS/QEMU Integration Testing

This development container provides a complete environment for integration testing with full SDN, OVS, and QEMU capabilities.

## Features

- **Go Development**: Go 1.25.5 with all standard tooling
- **TPM Support**: swtpm (software TPM) for TPM 2.0 simulation
- **QEMU/KVM**: Full virtualization support with KVM acceleration
- **Open vSwitch**: Complete SDN/networking stack for integration tests
- **Secure Boot**: UEFI, OVMF, and secure boot tooling
- **ISO Building**: Tools for creating custom bootable ISO images
- **Node.js**: For web dashboard builds

## Quick Start

### Build the Container

```bash
make build-devcontainer
```

### Verify Installation

```bash
make devcontainer-verify
```

### Interactive Shell

```bash
# Basic shell
make devcontainer-shell

# Shell with full capabilities (OVS auto-started)
make devcontainer-shell-full

# Shell specifically for SDN testing
make integration-test-sdn-shell
```

## Integration Testing

### SDN/OVS Tests

```bash
# Basic SDN tests
make integration-test-sdn

# Full SDN tests with OVS auto-started
make integration-test-sdn-full

# Device profile network transition tests
make integration-test-device-profile
```

### vTPM Tests

```bash
# Run vTPM integration tests
make integration-test-vtpm

# Interactive vTPM test shell
make integration-test-vtpm-shell
```

A swtpm that does not start fails `integration-test-vtpm`; every other target
warns and runs on.

### End-to-End Tests

```bash
# E2E tests with QEMU VMs and OVS networking
make integration-test-e2e
```

### All Tests

```bash
# Run every devcontainer-runnable suite
make integration-test

# Run one suite: <key> is a TARGET_PACKAGES key in run-integration-tests.sh
make integration-test-<key>
```

`docs/test/integration.md` lists the targets and the suites no container runs.

## Docker Compose Environment

For complex multi-service testing scenarios:

```bash
# Start the full compose environment
make devcontainer-compose-up

# Connect to the main devcontainer
make devcontainer-compose-shell

# Run full test suite in compose environment
make integration-test-compose-full

# View logs
make devcontainer-compose-logs

# Stop environment
make devcontainer-compose-down
```

## Manual Docker Usage

### Basic Container

```bash
docker run --rm -it --privileged \
  -v $(pwd):/workspace \
  -w /workspace \
  trusted-platform-dev:latest bash
```

### With OVS and TUN/TAP

```bash
docker run --rm -it --privileged \
  --device /dev/net/tun:/dev/net/tun \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_MODULE \
  -e AUTO_START_OVS=true \
  -v $(pwd):/workspace \
  -w /workspace \
  trusted-platform-dev:latest ovs-shell
```

### With Full Capabilities (KVM + OVS)

```bash
docker run --rm -it --privileged \
  --device /dev/net/tun:/dev/net/tun \
  --device /dev/kvm:/dev/kvm \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_MODULE \
  --cap-add=IPC_LOCK \
  --shm-size=2g \
  -e AUTO_START_OVS=true \
  -v $(pwd):/workspace \
  -w /workspace \
  trusted-platform-dev:latest ovs-shell
```

## Entrypoint Commands

The container entrypoint supports several commands:

- `verify`: Verify all tools and environment
- `ovs-start`: Start OVS services
- `ovs-stop`: Stop OVS services
- `ovs-shell`: Start OVS and drop to shell
- `bash` / `sh`: Interactive shell
- `help`: Show detailed usage information

### Examples

```bash
# Verify environment
docker run --rm trusted-platform-dev:latest verify

# Start OVS and run tests
docker run --rm --privileged \
  --device /dev/net/tun \
  -e AUTO_START_OVS=true \
  -v $(pwd):/workspace \
  -w /workspace \
  trusted-platform-dev:latest \
  go test -v -tags "integration $(make -s print-build-tags)" ./test/integration/sdn/...
```

## Environment Variables

- `AUTO_START_OVS`: Set to "true" to automatically start OVS on container start
- `QEMU_ENABLE_KVM`: Set to "true" to enable KVM acceleration
- `OVS_MANAGER`: OVS manager connection string (default: tcp:127.0.0.1:6640)

## Required Docker Options

For full functionality, the container requires specific Docker options:

### Minimal (Basic Development)

```bash
--privileged
-v $(pwd):/workspace
```

### SDN/Networking Tests

```bash
--privileged
--device /dev/net/tun:/dev/net/tun
--cap-add=NET_ADMIN
--cap-add=SYS_MODULE
-e AUTO_START_OVS=true
```

### Full E2E Tests (QEMU + OVS)

```bash
--privileged
--device /dev/net/tun:/dev/net/tun
--device /dev/kvm:/dev/kvm
--cap-add=NET_ADMIN
--cap-add=SYS_MODULE
--cap-add=IPC_LOCK
--shm-size=2g
-e AUTO_START_OVS=true
-e QEMU_ENABLE_KVM=true
```

## Docker Compose Services

The `docker-compose.yml` defines three services:

### 1. devcontainer (Main Development Service)

- Full capabilities enabled
- OVS auto-started
- Persistent volumes for Go caches and OVS data
- Devices: /dev/net/tun, /dev/kvm (if available)

### 2. ovs-standalone (Dedicated OVS Service)

- Runs OVS independently for distributed testing
- Health checks ensure OVS is ready
- Separate persistent volumes

### 3. qemu-coordinator (QEMU Test Coordinator)

- Manages QEMU VM instances for E2E tests
- Depends on ovs-standalone
- 4GB shared memory for VM operations

### Network

All services are connected to `trusted-platform-net` bridge network (172.28.0.0/16) for inter-service communication.

## Integration Test Structure

Each directory under `test/integration/` holds one suite (`sdn/`, `vtpm/`,
`dns/`, ...). Every `make integration-test-<key>` target runs its suite
through `run-integration-tests.sh` in this container, which:
1. Sets up required services (OVS, swtpm, a shared `platformd` unless the key
   is in `TARGET_NO_DAEMON`)
2. Runs the tests with the tags `make -s print-build-tags` gives, plus `integration`
3. Cleans up resources

The `run-tests.sh` scripts beside some suites are older; no target calls them.

## Troubleshooting

### OVS Not Starting

Check if kernel modules are available:

```bash
# Inside container
modprobe openvswitch
modprobe tun
```

If modules can't load, ensure the container is running with `--privileged` and `--cap-add=SYS_MODULE`.

### KVM Not Available

```bash
# Check on host
ls -la /dev/kvm

# Ensure container has device access
docker run --device /dev/kvm:/dev/kvm ...
```

### Permission Denied on /dev/net/tun

Ensure the container is started with the device mounted:

```bash
--device /dev/net/tun:/dev/net/tun
```

### Tests Failing with "Cannot allocate memory"

Increase shared memory size:

```bash
--shm-size=2g
```

For QEMU tests, you may need even more:

```bash
--shm-size=4g
```

## Development Workflow

### 1. Make Code Changes

Edit code in your local workspace. Changes are immediately visible in the container via volume mount.

### 2. Run Tests Locally

```bash
# Quick unit tests
make test

# Specific integration tests
make integration-test-sdn
make integration-test-vtpm
```

### 3. Full Integration Testing

```bash
# All tests
make integration-test

# Or use compose for complex scenarios
make integration-test-compose-full
```

### 4. Interactive Debugging

```bash
# Start shell with full capabilities
make devcontainer-shell-full

# Inside container
go test -v -tags "integration $(make -s print-build-tags)" -run TestSpecificTest ./test/integration/sdn/...
```

## Performance Considerations

### Go Module Caching

The docker-compose setup uses named volumes for Go caches:
- `go-mod-cache`: Module downloads (~500MB)
- `go-build-cache`: Build artifacts (~1GB)

This significantly speeds up subsequent builds and tests.

### Persistent OVS Configuration

OVS configuration is persisted in named volumes:
- `ovs-db`: OVSDB database
- `ovs-run`: Runtime data
- `ovs-log`: Logs

This allows OVS to maintain state across container restarts.

### KVM Acceleration

When `/dev/kvm` is available, QEMU VMs run with hardware acceleration, providing near-native performance. Without KVM, QEMU uses software emulation (much slower but still functional).

## CI/CD Integration

The devcontainer can be used in CI/CD pipelines:

```yaml
# GitHub Actions example
- name: Run Integration Tests
  run: |
    make build-devcontainer
    make integration-test
```

Without KVM the same targets run; QEMU falls back to software emulation.

## Cleanup

```bash
# Remove devcontainer image
make devcontainer-clean

# Remove compose volumes and networks
make devcontainer-compose-down

# Full cleanup (images + volumes)
make devcontainer-clean
docker volume prune
```

## Advanced Usage

### QEMU

The container carries Debian's `qemu-system-x86_64` and `qemu-system-aarch64`
(with OVMF and AAVMF) for the compute suite's `local-qemu` provider. The custom
CanoKey QEMU build is gone: no suite used it, and its build dependencies (GTK,
SDL, SPICE headers) were most of the image's trivy findings (#933).

### OVS OpenFlow Testing

```bash
# Inside container with OVS running
ovs-vsctl add-br br0
ovs-vsctl add-port br0 veth0 -- set interface veth0 type=internal
ovs-ofctl add-flow br0 priority=100,action=normal
```

### Multiple VM Instances

The qemu-coordinator service can manage multiple VM instances. See `pkg/qemu/` for VM management APIs.

## Support

For issues specific to:
- **OVS/SDN**: See `test/integration/sdn/README.md`
- **QEMU/vTPM**: See `test/integration/vtpm/README.md`
- **General container**: File an issue in the main repository

## Version Information

- Base Image: Debian Bookworm
- Go: 1.25.5
- Node.js: the `NODE_VERSION` in `scripts/tool-pins.sh` (official release archive, digest-checked; npm bundled, no yarn)
- QEMU: Debian Bookworm package
- OVS: Latest from Debian Bookworm repository
- swtpm: Latest from Debian Bookworm repository
