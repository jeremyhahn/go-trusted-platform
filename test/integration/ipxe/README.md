# iPXE Integration Tests

This directory contains integration tests for the iPXE boot server components.

## Overview

The integration tests verify end-to-end functionality of:

- **DHCP Server**: PXE-aware DHCP server with proper options for PXE and iPXE clients
- **TFTP Server**: Serves iPXE firmware files (ipxe.efi, ipxe32.efi)
- **HTTP Server**: Serves boot scripts, menus, and proxies HTTPS resources

## Test Files

| File | Description |
|------|-------------|
| `commands.go` | IPXECommands interface and data structures |
| `helpers.go` | Test helpers, configuration, and utilities |
| `dhcp_test.go` | DHCP protocol tests (DISCOVER/OFFER/REQUEST/ACK) |
| `tftp_test.go` | TFTP download tests for firmware files |
| `http_test.go` | HTTP boot script and menu tests |
| `multiprotocol_test.go` | Full flow and multi-protocol integration tests |

## Prerequisites

### Required Services

1. **iPXE Server Running**: The PXE server must be running before tests execute
2. **Network Access**: Tests require access to the server's network interface
3. **Root Privileges**: DHCP tests require root or CAP_NET_ADMIN capability

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IPXE_SERVER_IP` | `10.99.99.1` | IP address of the PXE server |
| `IPXE_HTTP_PORT` | `8080` | HTTP server port |
| `IPXE_TFTP_PORT` | `69` | TFTP server port |
| `IPXE_DHCP_ENABLED` | `0` | Set to `1` to run DHCP tests |
| `IPXE_NETWORK_INTERFACE` | - | Network interface for DHCP testing |
| `IPXE_TEST_NETWORK` | `10.99.99.0/24` | Test network CIDR |

## Running Tests

### In Devcontainer (Recommended)

The devcontainer provides an isolated environment with proper networking:

```bash
# Start the devcontainer
make devcontainer

# Inside devcontainer, run integration tests
go test -v -tags "$(make -s print-build-tags) integration" ./test/integration/ipxe/...
```

### Using Makefile

```bash
# Run all iPXE integration tests
make integration-test-ipxe

# Run specific test file
go test -v -tags "$(make -s print-build-tags) integration" ./test/integration/ipxe/... -run TestHTTP

# Run DHCP tests (requires root)
sudo IPXE_DHCP_ENABLED=1 go test -v -tags "$(make -s print-build-tags) integration" ./test/integration/ipxe/... -run TestDHCP
```

### Test Categories

#### HTTP Tests (No Root Required)

Test the HTTP boot script server:

```bash
go test -v -tags "$(make -s print-build-tags) integration" ./test/integration/ipxe/... -run TestHTTP
```

#### TFTP Tests (No Root Required)

Test TFTP firmware downloads:

```bash
go test -v -tags "$(make -s print-build-tags) integration" ./test/integration/ipxe/... -run TestTFTP
```

#### DHCP Tests (Root Required)

Test DHCP server functionality:

```bash
sudo IPXE_DHCP_ENABLED=1 go test -v -tags "$(make -s print-build-tags) integration" ./test/integration/ipxe/... -run TestDHCP
```

#### Full Flow Tests

Test complete PXE boot sequence:

```bash
go test -v -tags "$(make -s print-build-tags) integration" ./test/integration/ipxe/... -run TestIPXEFull
```

## Test Architecture

### Protocol Testing Approach

Instead of requiring full QEMU VM boots, these tests use lightweight protocol-level testing:

1. **DHCP Testing**: Uses a DHCP client library to send DISCOVER/REQUEST packets and verify OFFER/ACK responses
2. **TFTP Testing**: Uses a TFTP client to download firmware and verify file integrity
3. **HTTP Testing**: Uses standard HTTP client to fetch scripts and verify content

### Test Isolation

Tests use isolated network configurations to avoid conflicts:

- Default test network: `10.99.99.0/24`
- Server IP: `10.99.99.1`
- DHCP range: `10.99.99.100` - `10.99.99.200`

### Concurrent Testing

Tests verify the server handles concurrent clients:

- Multiple DHCP clients requesting IPs simultaneously
- Parallel TFTP downloads
- Concurrent HTTP requests

## Expected Test Output

### Successful Run

```
=== RUN   TestHTTPBootScript
=== RUN   TestHTTPBootScript/GetBootScript
--- PASS: TestHTTPBootScript/GetBootScript (0.01s)
=== RUN   TestHTTPBootScript/BootScriptContentType
--- PASS: TestHTTPBootScript/BootScriptContentType (0.01s)
--- PASS: TestHTTPBootScript (0.02s)

=== RUN   TestTFTPDownloadFirmware
=== RUN   TestTFTPDownloadFirmware/DownloadIPXEEFI
--- PASS: TestTFTPDownloadFirmware/DownloadIPXEEFI (2.34s)
--- PASS: TestTFTPDownloadFirmware (2.35s)

PASS
ok      github.com/jeremyhahn/go-trusted-platform/test/integration/ipxe  15.234s
```

### Common Failures

#### Server Not Running

```
--- FAIL: TestHTTPBootScript/GetBootScript
    http_test.go:42: HTTP server unreachable: dial tcp 10.99.99.1:8080: connect: connection refused
```

**Solution**: Start the iPXE server before running tests.

#### DHCP Permission Denied

```
--- FAIL: TestDHCPDiscoverOffer/PXEClientDiscover
    dhcp_test.go:56: failed to create UDP connection: listen udp4 0.0.0.0:0: bind: permission denied
```

**Solution**: Run DHCP tests with root privileges.

#### TFTP Timeout

```
--- FAIL: TestTFTPDownloadFirmware/DownloadIPXEEFI
    tftp_test.go:45: TFTP download of ipxe.efi should succeed: timeout
```

**Solution**: Verify TFTP server is running and accessible.

## Extending Tests

### Adding New Tests

1. Create test functions with `Test` prefix
2. Do not gate on the environment: the `integration` build tag selects the
   tests, and a missing prerequisite fails with a typed error (see
   `CheckNetworkPrivileges`)
3. Use appropriate context helpers for timeouts
4. Follow existing patterns for protocol testing

### Adding New Protocol Adapters

Implement the `IPXECommands` interface:

```go
type IPXECommands interface {
    Name() string
    Setup(ctx context.Context) error
    Teardown() error

    // DHCP operations
    SendDHCPDiscover(...) (*DHCPOfferResult, error)
    SendDHCPRequest(...) (*DHCPAckResult, error)

    // TFTP operations
    TFTPDownload(...) (*TFTPDownloadResult, error)

    // HTTP operations
    HTTPGetBootScript(...) (*HTTPBootScriptResult, error)
    // ... etc
}
```

## Related Documentation

- [iPXE Package Documentation](../../../docs/ipxe/)
- [Integration Testing Guide](../README.md)
- [Devcontainer Setup](../../../build/docker/devcontainer/)
