# DevContainer Quick Start Guide

## TL;DR

```bash
# Build container
make devcontainer-build

# Verify everything works
make devcontainer-verify

# Start interactive shell with full capabilities
make devcontainer-shell-full

# Run SDN integration tests
make integration-test-sdn-full

# Run E2E tests with QEMU
make integration-test-e2e

# Run all integration tests
make integration-test-all
```

## Common Tasks

### Development

```bash
# Basic shell for development
make devcontainer-shell

# Shell with OVS pre-started for network testing
make integration-test-sdn-shell

# Show help
make devcontainer-help
```

### Testing

```bash
# Unit tests (fast, no container needed)
make test

# SDN/OVS tests
make integration-test-sdn              # Basic
make integration-test-sdn-full         # With OVS auto-start
make integration-test-device-profile   # Device profile transitions

# vTPM tests
make integration-test-vtpm

# E2E tests
make integration-test-e2e

# All integration tests
make integration-test-all
```

### Docker Compose

```bash
# Start full environment
make devcontainer-compose-up

# Connect to shell
make devcontainer-compose-shell

# Run tests in compose environment
make integration-test-compose-full

# View logs
make devcontainer-compose-logs

# Stop everything
make devcontainer-compose-down
```

### Cleanup

```bash
# Remove dev container image
make devcontainer-clean

# Remove all volumes
docker volume prune
```

## Requirements

### Host Requirements

- Docker with privileged container support
- `/dev/net/tun` for networking tests
- `/dev/kvm` for hardware-accelerated VMs (optional but recommended)
- At least 4GB RAM allocated to Docker
- At least 20GB disk space for container images and volumes

### Kernel Modules

The following kernel modules should be available on the host:
- `tun` (TUN/TAP networking)
- `kvm` / `kvm_intel` / `kvm_amd` (KVM acceleration)
- `openvswitch` (optional, userspace OVS works without it)

Check availability:
```bash
lsmod | grep -E "tun|kvm|openvswitch"
```

## Troubleshooting

### Container Build Fails

```bash
# Clean everything and rebuild
make devcontainer-clean
docker system prune -f
make devcontainer-build
```

### OVS Fails to Start

```bash
# Check if running as privileged
docker run --rm --privileged \
  go-trusted-platform-dev:latest \
  bash -c "modprobe tun && echo OK"

# Manually start OVS
docker run --rm -it --privileged \
  --device /dev/net/tun \
  go-trusted-platform-dev:latest \
  ovs-start
```

### Tests Timeout

```bash
# Increase test timeout
go test -timeout=30m ...

# Or run with verbose output
go test -v -timeout=30m ...
```

### Out of Disk Space

```bash
# Clean Docker cache
docker system prune -a
docker volume prune

# Clean Go caches in volumes
docker volume rm \
  devcontainer_go-mod-cache \
  devcontainer_go-build-cache
```

## What Gets Tested

### Unit Tests (`make test`)
- Fast, in-memory tests
- No external dependencies
- No container required
- Should complete in < 30 seconds

### Integration Tests SDN (`make integration-test-sdn-full`)
- OVS bridge creation and management
- Network interface manipulation
- OpenFlow rule installation
- ARP handling
- TAP device integration
- Network policy enforcement
- Device profile state transitions

### Integration Tests vTPM (`make integration-test-vtpm`)
- Software TPM initialization
- QEMU VM boot with vTPM
- TPM attestation flows
- Sealed secret management
- Device provisioning

### Integration Tests E2E (`make integration-test-e2e`)
- Full provisioning-to-production workflow
- VM creation with QEMU
- Network transitions (provisioning -> production)
- OVS flow rule updates
- Device enrollment and attestation
- Certificate issuance via ACME

## Performance Tips

### Use KVM Acceleration

Ensure `/dev/kvm` is available and mounted:
```bash
ls -la /dev/kvm
# Should show: crw-rw---- 1 root kvm ...

# Make sure your user is in the kvm group
sudo usermod -a -G kvm $USER
```

### Cache Go Modules

Docker compose automatically creates persistent volumes for Go caches. If running containers manually, mount cache directories:

```bash
docker run --rm -it \
  -v go-mod-cache:/go/pkg/mod \
  -v go-build-cache:/root/.cache/go-build \
  go-trusted-platform-dev:latest
```

### Parallel Testing

```bash
# Run tests in parallel (if they're independent)
go test -parallel=4 ./...
```

### Incremental Builds

The devcontainer uses multi-stage builds. To rebuild only changed layers:
```bash
docker build --target=<stage-name> ...
```

## Integration with IDEs

### VS Code

Use the `.devcontainer/devcontainer.json` configuration (if present) or manually:

1. Install "Remote - Containers" extension
2. Open command palette: "Remote-Containers: Attach to Running Container"
3. Select `go-trusted-platform-dev` container

### JetBrains GoLand

1. Preferences -> Build, Execution, Deployment -> Docker
2. Add Docker server
3. Create run configuration with Docker container

## CI/CD Integration

### GitHub Actions

```yaml
name: Integration Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Build Dev Container
      run: make devcontainer-build

    - name: Run Integration Tests
      run: make integration-test-all
```

### GitLab CI

```yaml
integration-tests:
  image: docker:latest
  services:
    - docker:dind
  script:
    - make devcontainer-build
    - make integration-test-all
  only:
    - merge_requests
    - main
```

## Next Steps

1. Read the full [README.md](README.md) for detailed documentation
2. Explore the test structure in `test/integration/`
3. Check the Makefile for all available targets: `make help`
4. Review the docker-compose.yml for service configuration

## Support

- Documentation: `/home/jhahn/sources/go-trusted-platform/docs/`
- Integration tests: `/home/jhahn/sources/go-trusted-platform/test/integration/`
- Issues: File in main repository
