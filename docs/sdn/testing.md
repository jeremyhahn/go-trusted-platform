# SDN Testing Strategy

> **Status: REFERENCE** · Last verified: 2026-10-26
> How the SDN packages are tested.

## Overview

Testing follows TDD principles with distinct unit and integration test layers.
Unit tests run fast in-memory with mocks; integration tests run in the
devcontainer with real OVS infrastructure.

## Test Layers

| Layer | Location | Dependencies | Run by |
|-------|----------|--------------|--------|
| Unit | `pkg/sdn/*/` | None (mocks) | `make test` (CI Gate) |
| Integration | `test/integration/sdn/` | OVS, swtpm and platformd in the devcontainer | `make integration-test-sdn`; CI's full-tier `integration` job |
| Stress | `test/integration/sdn/stress/` | Privileged devcontainer | `make stress-sdn` |
| Benchmark | `pkg/sdn/*/benchmark_test.go` | None | `make bench-sdn` |

`make test` runs every `pkg/sdn/...` package except `pkg/sdn/netlink`, which
`TEST_EXCLUDE` in the Makefile leaves out because it needs root and netlink.
No CI stage runs the netlink tests.

## Unit Tests

### Requirements

- Run in-memory, no system modifications
- Complete quickly
- No skip guards or -short flags
- 90%+ code coverage target
- Test both success and error paths

### Package Layout

Each package keeps its tests beside the code, one `_test.go` file per source
file plus coverage files. The core packages:

| Package | Test files cover |
|---------|------------------|
| `pkg/sdn/arp` | `/proc/net/arp` parsing and lookup (`arp_test.go`), duplicate address detection (`dad_test.go`, `dad_frame_test.go`) |
| `pkg/sdn/openflow` | Client against a mock switch (`client_test.go`, `client_batch_test.go`), message encoding (`messages_test.go`, `protocol_test.go`), groups, meters, conntrack, Nicira extensions, tunnels |
| `pkg/sdn/ovs` | OVSDB client against a mock server (`client_test.go`), bridges, ports, flows and flow grammar, QoS, VXLAN, `ovs-appctl` (`appctl_test.go`), types |
| `pkg/sdn/netlink` | Links and TAP devices, with mock netlink handles (`mock_netlink_test.go`, `tap_mock_test.go`) |
| `pkg/sdn/policy` | Engine, state machine (`state_test.go`), port state transitions across network phases against a recording flow controller (`state_transition_test.go`), certificate extraction, monitor, enrollment hook, quarantine, admission, zone flows |

### Mock Servers

#### Mock OpenFlow Server

`pkg/sdn/openflow/mock_server_test.go` defines `mockOFServer`, a TCP listener
that answers the OpenFlow handshake and records the messages the client sends.

#### Mock OVSDB Server

`pkg/sdn/ovs/mock_server_test.go` defines `mockOVSDBServer`, a JSON-RPC
listener over in-memory `mockDatabase` / `mockTable` contents.

### ARP Test Data

The ARP tests write literal `/proc/net/arp` text to a temp file
(`sampleARPTable` in `pkg/sdn/arp/arp_test.go`):

```
IP address       HW type     Flags       HW address            Mask     Device
192.0.2.1        0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
```

There is no shared `testdata/` directory; certificates for the policy tests
are generated in the tests.

## Integration Tests

### Location

`test/integration/sdn/` holds one package, `sdn`, plus the `stress/`,
`topology/` and `mock_bgp/` sub-packages. Among its files:

| File | Covers |
|------|--------|
| `openflow_native_test.go` | The pure Go OpenFlow client against a real bridge (`TestNativeOpenFlow_*`) |
| `arp_native_test.go` | The pure Go ARP reader against the kernel table (`TestNativeARP_*`) |
| `ovsdb_test.go`, `bridge_test.go`, `port_test.go`, `bridge_port_management_test.go`, `tap_test.go` | OVSDB, bridges, ports, TAP/veth/patch ports |
| `flow_test.go`, `flow_batch_test.go`, `openflow_rules_test.go` | Flow install, removal, priorities, per-phase rules |
| `policy_engine_integration_test.go`, `network_provisioning_test.go` | Policy engine, provisioning |
| `multiprotocol_test.go`, `overlay_multiprotocol_test.go`, `ipam_test.go`, `zone_test.go`, `nat64_surface_test.go`, `perf_cli_test.go` | The SDN, overlay, IPAM, zone, NAT64 and perf surfaces over CLI, REST, gRPC, QUIC, MCP and Unix |
| `gateway_*_test.go`, `ct_firewall_test.go`, `nat_dual_uplink_test.go`, `group_lb_test.go`, `nat64_*_test.go` | The gateway datapath |
| `*_netns_test.go`, `overlay_nd_test.go` | Network-namespace tests: FHRP, host firewall, tunnels, ND suppression |

`run-tests.sh` and `README.md` beside them describe the standalone setup.

### Build Tags

```go
//go:build integration

package sdn
```

### Test Requirements

- Run in the privileged devcontainer, never on the host
- OVS installed and running
- Root permissions for OVS operations

## Makefile Targets

| Target | Runs |
|--------|------|
| `make test` | All unit tests, `pkg/sdn/netlink` excluded |
| `make test-pkg PKG=./pkg/sdn/openflow/` | One package with the derived build tags; add `TESTFLAGS='-run TestFoo -v'` to narrow it |
| `make coverage-sdn` | `./pkg/sdn/...` with a coverage profile and HTML report in the coverage directory |
| `make bench-sdn` | Benchmarks for vxlan, bgp, gateway, ipam, dhcp and openflow |
| `make bench-sdn-<pkg>` | One of those six |
| `make integration-test-sdn` | `./test/integration/sdn/...` through the shared devcontainer runner (OVS, swtpm, platformd) |
| `make integration-test-sdn-full` | The SDN suite with OVS in a privileged devcontainer |
| `make integration-test-sdn-shell` | An interactive shell in the SDN devcontainer |
| `make stress-sdn`, `make stress-sdn-{ipam,bgp,dhcp,overlay,cluster}` | The stress suites |

There are no per-package `test-sdn-*` targets; use `make test-pkg`. Never
hand-write the `-tags` list: derive it with `make -s print-build-tags`.

## Running Tests

### Unit Tests (Fast, Local)

```bash
# One package
make test-pkg PKG=./pkg/sdn/openflow/

# One test
make test-pkg PKG=./pkg/sdn/openflow/ TESTFLAGS='-run TestClient_AddFlow -v'

# Race detector
make test-pkg PKG=./pkg/sdn/policy/ TESTFLAGS='-race'

# Coverage for all SDN packages
make coverage-sdn
```

### Integration Tests (Container)

```bash
make integration-test-sdn
```

The runner and what `make integration-test` leaves out are described in
[docs/test/integration.md](../test/integration.md).

### End-to-End Test

```bash
# Full client-server test with OVS (requires root)
sudo platformctl iso test client-server --use-ovs
```

## Test Conventions

1. **Error Paths** - Every function has at least 2 tests: success and error
2. **Typed Errors** - Never use fmt.Errorf, always typed errors
3. **Table Tests** - Use table-driven tests for multiple inputs
4. **Cleanup** - Always clean up resources in defer or t.Cleanup
5. **Parallel** - Mark independent tests with t.Parallel()
6. **Naming** - TestFunctionName_Scenario for clarity

## CI

The CI Gate runs `make test` on every PR but a docs-only one (every changed
file markdown or under `docs/`), which runs Lint and the Gate only unless it
is labelled `ci:full`. `make test-race` runs in the full tier: pushes to main
and PRs labelled `ci:full`. The full tier's `integration` job runs
`make integration-test`, whose runner targets include `sdn`, so the SDN
suite runs on every push to main, on `workflow_dispatch` and on a `ci:full`
PR. A failed leaf test fails the job unless `.github/foreign-failures.tsv`
lists it (see [docs/test/integration.md](../test/integration.md)). Run
`make integration-test-sdn` in the devcontainer before merging SDN changes;
an unlabelled PR does not run it.

## Performance Testing

### Benchmarks

Benchmark suites live alongside each package (e.g.
`pkg/sdn/openflow/benchmark_test.go` for OpenFlow message
marshal/unmarshal, `pkg/sdn/dhcp/benchmark_test.go` for DHCP). Run them
with `make bench-sdn`, or one package with `make bench-sdn-openflow`.

For live datapath measurements on a running gateway use
`platformctl sdn gateway perf` (see
[gateway/user.md — Measuring the datapath](../gateway/user.md#measuring-the-datapath)).
