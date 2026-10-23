# iPXE Integration Tests

This directory contains integration tests for the iPXE boot server components.

## Overview

The integration tests verify end-to-end functionality of:

- **DHCP Server**: PXE-aware DHCP server with proper options for PXE and iPXE clients
- **TFTP Server**: Serves iPXE firmware files (ipxe.efi, ipxe32.efi, undionly.kpxe)
- **HTTP Server**: Serves boot scripts, menus, and proxies HTTPS resources

## Test Files

| File | Description |
|------|-------------|
| `commands.go` | Result types the protocol adapters return, and the suite's server config |
| `helpers.go` | Test helpers, typed errors, configuration, and utilities |
| `setup_test.go` | `TestMain`: the in-process server and its local fixture upstreams |
| `dhcp_test.go` | DHCP protocol tests (DISCOVER/OFFER/REQUEST/ACK) |
| `tftp_test.go` | TFTP download tests for firmware files |
| `http_test.go` | HTTP boot script, menu, and proxy tests |
| `multiprotocol_test.go` | Full flow and multi-protocol integration tests |

## What the Suite Starts

`TestMain` starts everything the tests need, in process, on `127.0.0.1`:

- the platform iPXE server (`pkg/ipxe`) with HTTP and TFTP on free ports, and
  DHCP on `lo` at a free UDP port when `IPXE_DHCP_ENABLED=1`;
- a **firmware upstream**: an `httptest` server the TFTP server downloads its
  firmware from (`FirmwareUpstream`) into a temporary `FirmwareDir`. Each file
  is deterministic (`FirmwareFixture`), so a test compares what TFTP served
  byte for byte;
- a **proxy upstream**: an `httptest` TLS server the `/proxy/https/` route
  fetches from, trusted through `ProxyCACertPool`.

No test reaches the outside network. If any of this fails to start, the whole
run fails; nothing in the suite skips.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `IPXE_DHCP_ENABLED` | Set to `1` and `TestMain` starts the DHCP server on loopback; the DHCP tests **fail** without it |
| `IPXE_SERVER_IP`, `IPXE_HTTP_PORT`, `IPXE_TFTP_PORT`, `IPXE_DHCP_PORT` | Set by `TestMain` to the address and free ports it chose; not user inputs |

The DHCP tests' client binds UDP port 68, which needs root or
`CAP_NET_BIND_SERVICE`; the devcontainer runs as root.

## Running Tests

```bash
# Run all iPXE integration tests in the devcontainer
make integration-test-ipxe

# Run one slice
make integration-test-ipxe-dhcp
make integration-test-ipxe-tftp
make integration-test-ipxe-http
```

The runner sets `IPXE_DHCP_ENABLED=1` for `integration-test-ipxe` and
`integration-test-ipxe-dhcp`, and selects each slice with `-run`:
`ipxe-dhcp` runs `.*DHCP.*`, `ipxe-tftp` runs `.*TFTP.*`, `ipxe-http` runs
`^TestHTTP`.

On a host as root, `make integration-test-ipxe-local` runs the whole package
with `IPXE_DHCP_ENABLED=1`. The older `run-tests.sh` beside the suite, which
no target calls, sets the variable the same way on its `all`, `dhcp` and
`multi` paths; `dhcp` runs `.*DHCP.*` and `multi` runs `^TestIPXE`.

## Test Architecture

### Protocol Testing Approach

Instead of requiring full QEMU VM boots, these tests use lightweight protocol-level testing:

1. **DHCP Testing**: Sends DISCOVER/REQUEST from `0.0.0.0:68` to the server's
   port and reads the broadcast reply back on loopback, matched by xid
2. **TFTP Testing**: Downloads firmware and compares it with the fixture the
   upstream served, including the `tsize` the server reports
3. **HTTP Testing**: Fetches scripts and asserts their content

### The DHCP → TFTP / HTTP Chain

`TestIPXEDHCPToHTTPChain` follows what a booting client is told, not URLs the
test builds itself:

- **Non-iPXE client**: the OFFER names `ipxe.efi` and the server address; the
  test downloads that file over TFTP from that address and compares it with the
  fixture.
- **iPXE client**: the OFFER names `http://<ip>:<port>/boot.ipxe`; the test
  fetches it, follows its `chain menu.ipxe?arch=...` to the menu, follows the
  menu's `chain` to `/boot/test-kernel.ipxe`, and asserts that entry's `kernel`
  and `initrd` lines.

### Concurrent Testing

Tests verify the server handles concurrent clients:

- Multiple DHCP clients requesting IPs simultaneously
- Parallel TFTP downloads, each compared with the fixture
- Concurrent HTTP requests

## Common Failures

#### DHCP Server Not Started

```
--- FAIL: TestDHCPDiscoverOffer
    helpers.go:187: DHCP server not running: set IPXE_DHCP_ENABLED=1 so TestMain starts it
```

**Solution**: Run through `make integration-test-ipxe-dhcp`, which sets the
variable.

#### DHCP Permission Denied

```
--- FAIL: TestDHCPDiscoverOffer/PXEClientDiscover
    DHCP listen for OFFER: listen udp4 0.0.0.0:68: bind: permission denied
```

**Solution**: Run DHCP tests as root (the devcontainer does).

#### Suite Setup Failed

```
iPXE suite setup failed: start iPXE server: ...
```

**Solution**: The step named in the message failed before any test ran; the
run exits non-zero.

## Extending Tests

1. Create test functions with `Test` prefix
2. Use `GetTestServerConfig()` for the server address and ports
3. Fail, never skip, when a server the test needs does not answer
4. Compare served firmware with `FirmwareFixture(name)`
5. Use the context helpers (`TFTPTestContext`, `HTTPTestContext`, ...) for timeouts

## Related Documentation

- [iPXE Package Documentation](../../../docs/ipxe/)
- [Integration Testing Guide](../../../docs/test/integration.md)
- [Devcontainer Setup](../../../build/docker/devcontainer/)
