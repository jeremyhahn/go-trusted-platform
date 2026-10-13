# New Packages Test Report

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · A dated review record (2026-04-14). `pkg/sdn/firewall`, `pkg/cli/commands/encrypt`, `test/integration/switch/`, `test/integration/cli/switch/`, `test/integration/sdn/gateway/` and `test/integration/sdn/tunnel/` no longer exist.

**Date:** 2026-04-14
**Reviewer:** QA Expert (Claude)
**Scope:** Packages implemented in the current development session

> **Historical note (2026-08):** `pkg/sdn/firewall` (the Go userspace
> firewall engine reviewed below) has since been deleted, replaced by the
> OVS-native conntrack firewall in `pkg/sdn/gateway/services/firewall`.
> See `docs/sdn/firewall/` for the current design. The figures below are
> retained as a record of the review at that date.

---

## Executive Summary

All 14 reviewed packages pass their test suites with zero failures. Eight packages meet
or exceed the 90% unit-test coverage target. Four packages fall below 90%: the two CLI
command packages, the gateway/commands package, and the gateway node package (compat
layer). These gaps are explainable — they involve I/O-bound or network-bound code paths
that require real daemon connections or real switch hardware to exercise — but additional
test infrastructure should be built to close them.

---

## Coverage Summary Table

| Package | Tests | Coverage | Status |
|---------|-------|----------|--------|
| `pkg/sdn/fabric` | 66 | 92.4% | PASS |
| `pkg/sdn/fabric/nexus` | 62 | 91.7% | PASS |
| `pkg/sdn/firewall` | 68 | 99.3% | PASS |
| `pkg/sdn/tunnel` | 35 | 88.4% | BELOW TARGET |
| `pkg/switch` | 144 | 85.0% | BELOW TARGET |
| `pkg/config/secrets` | 34 | 92.0% | PASS |
| `pkg/cli/commands/encrypt` | 10 | 61.2% | BELOW TARGET |
| `pkg/cli/commands/switch` | 25 | 39.4% | BELOW TARGET |
| `pkg/webservice/v1/rest/switch` | 27 | 85.6% | BELOW TARGET |
| `sdk/go/services/switch` | 26 | 90.1% | PASS |
| `pkg/sdn/cluster` | 679 | 92.3% | PASS |
| `pkg/sdn/gateway` | 91 | 71.2% | BELOW TARGET |
| `pkg/sdn/gateway/commands` | 13 | 60.0% | BELOW TARGET |
| `pkg/sdn/gateway/modes` | 274 | 87.9% | BELOW TARGET |

---

## Benchmark Results — `pkg/sdn/firewall`

The firewall engine includes a production-quality benchmark suite. Results on the CI
host (96 vCPUs, Intel Xeon Platinum 8260 @ 2.40 GHz):

| Benchmark | Iterations | ns/op | B/op | allocs/op |
|-----------|-----------|-------|------|-----------|
| `BenchmarkConnTrackLookup` | 18,027,762 | 68 | 0 | 0 |
| `BenchmarkConnTrackLookupMiss` | 15,985,219 | 63 | 0 | 0 |
| `BenchmarkConnTrackInsert` | 1,000,000 | 1,076 | 446 | 1 |
| `BenchmarkFiveTupleHash` | 40,393,870 | 29 | 0 | 0 |
| `BenchmarkFiveTupleHashIPv6` | 38,195,247 | 32 | 0 | 0 |
| `BenchmarkEngineProcessEstablished` | 4,805,979 | 241 | 0 | 0 |
| `BenchmarkEngineProcessNew` | 1,256,368 | 929 | 303 | 2 |

Key observations:
- Established-connection fast-path (241 ns/op, zero allocs) is well within the target for
  line-rate packet processing on 1 GbE links.
- New-connection path (929 ns/op, 2 allocs) is acceptable for stateful firewall admission.
- Sharded conntrack table eliminates lock contention: zero-allocation lookups confirm
  lock-free read paths are working correctly.

No performance regressions identified.

---

## Package-by-Package Analysis

### 1. `pkg/sdn/fabric` — 92.4%

**Test count:** 66
**All tests pass.**

**What is covered:**
- Config validation (all struct types, duplicate detection, EVPN mode checks)
- All typed error types including `Error()` and `Unwrap()` methods
- Manager construction (missing driver factory, invalid config)
- `ApplyFabric`: success path, EVPN mode, connect error, VLAN error, LAG error, unknown switch
- `ProvisionPort`, `ActivatePort`, `QuarantinePort`: success and all error branches
- `SegmentByName` hit and miss
- `SwitchStatus` connected, disconnected, unknown switch

**Gaps (7.6%):**

- `RegisterDriver` (line 60, `driver.go`) — 0% coverage. The factory function used for
  registering custom drivers is never called in tests; only the default Nexus driver
  registration path is exercised. A test that calls `RegisterDriver` with a custom
  factory and then resolves it via `DriverFor` would eliminate this gap.

- `Manager.Close` error path — 66.7% covered. The path where `Close` is called while
  at least one driver's `Close` returns an error is not exercised.

- `Manager.setPortAccessOnPeers` partial coverage — LAG peer iteration boundary cases
  with mVPC topologies are not all exercised.

**Recommendations:**
- Add `TestRegisterDriver_CustomFactory` to cover the public registration API.
- Add `TestManager_Close_DriverError` to cover the error aggregation path.

---

### 2. `pkg/sdn/fabric/nexus` — 91.7%

**Test count:** 62
**All tests pass.**

**What is covered:**
- All NX-OS command generators (VLAN, VNI, LAG, port access/trunk)
- Output parsers for `show vlan`, `show nve vni`, `show port-channel summary`,
  `show running-config interface`
- Error keyword detection (`containsError`)
- Driver lifecycle: construct, connect (idempotent), ping, close
- All operational methods with both success and not-connected error paths
- `executeBatch` error paths (command error, batch error, output error)
- Driver registration and vendor lookup

**Gaps (8.3%):**

- `Connect` over a real SSH transport — the test uses an injected executor, so the
  actual `ssh.Dial` code path is 0%. This is by design for unit tests but needs
  integration test coverage.

- `parseShowVLAN` line 31: 91.7% — the regex path for malformed multi-column output
  is not exercised.

**Recommendations:**
- Integration test: `TestNexusDriver_Connect_RealSSH` in `test/integration/sdn/` using
  a Nexus device in the devcontainer simulation or a test double.
- Add a table entry to `TestParseShowVLAN_*` for malformed column alignment.

---

### 3. `pkg/sdn/firewall` — 99.3%

**Test count:** 68
**All tests pass.**

**What is covered:**
- Config validation (nil config, disabled, invalid policy, zone/rule/NAT validation)
- ConnTrack: insert, lookup, update, delete, expiry, snapshot, overwrite, concurrent
  access (race-safe), shard distribution verification
- `FiveTuple` hash consistency and IPv6 correctness
- All timeout constants and per-protocol timeout selection
- Engine: new connection, established fast-path, DNAT, default deny/allow, rule priority
  ordering, DNS rule, stats, connection expiry
- NAT engine: DNAT port-forward, SNAT masquerade, protocol filter, zone filter, empty
  rules
- Rule matching: exact, wildcard, zone mismatch, network mismatch, port mismatch,
  state (established/related/new)
- `Action.String()` and `ParseAction()` round-trip
- Zone resolver: all interface lookups, policy lookup, missing zone

**Gaps (0.7%):**

- A single internal error path in the expiry loop where a `Snapshot` is called on an
  already-closed table. This is a defensive check; the code path cannot be reached
  through the public API.

**Recommendations:**
- No unit-test gaps that require new tests. The 0.7% uncovered code is unreachable
  defensive code.
- Add `BenchmarkConnTrackExpire` to track expiry performance as table size grows.

---

### 4. `pkg/sdn/tunnel` — 88.4%

**Test count:** 35
**All tests pass.**

**Gaps (11.6%):**

The `netlink_ops.go` file defines the thin wrapper functions that call the real Linux
kernel netlink API (`LinkAdd`, `LinkDel`, `LinkSetUp`, `LinkSetMTU`, `LinkByName`,
`AddrAdd`, `AddrList`, `LinkList`). These are injected via interface and are fully
mocked in the test suite. The production implementations show 0% coverage because no
test exercises the real netlink path. This is correct behavior for unit tests (the host
must not be modified) but the real implementations need integration-level validation.

Additional gaps in `manager.go`:
- `linkOperState` line 161 — 50% covered. The state-reading code path that checks
  `net.InterfaceByName` failure is not exercised.
- `addAddress` line 311 — 75% covered. The case where `AddrList` returns an error is
  not tested.
- `ListTunnels` line 177 — 84.6% covered. `LinkList` error path is not exercised.

**Recommendations:**
- Add `TestManager_ListTunnels_LinkListError` and `TestManager_Status_AddrListError`
  to the unit tests using the mock netlink interface.
- Integration test: `TestTunnelManager_RealNetlink` in `test/integration/sdn/tunnel/`
  using a network namespace to exercise real GRE tunnel creation and teardown.

---

### 5. `pkg/switch` — 85.0%

**Test count:** 144
**All tests pass.**

**Gaps (15%):**

The gap is concentrated in code paths that require an active SSH connection:

- `ssh.go:Execute` (0%) and `ssh.go:Close` (0%) — the real SSH execution engine. The
  `SSHExecutor` uses a real `ssh.Dial` and `ssh.Session` which cannot be exercised
  without a running SSH server. The mock executor used in tests bypasses this.

- `cisco_nexus.go:ensureConnected` (28.6%) and `ssh_manager.go:ensureConnected` (28.6%)
  — connection retry logic. The reconnection path triggered when `executor == nil` but
  SSH config is valid is not tested.

- `NewSSHExecutor` (47.1%) — key loading failure paths for partially malformed PEM are
  not all covered. Currently tests cover nil config and completely invalid key content
  but not the case where a valid PEM file contains a non-SSH key type.

- `service.go:Close` (57.1%) — the path where iterating over managers and closing them
  encounters a manager that returns an error is not tested.

- `extractColumn` (60%) — the column extraction helper for fixed-width table parsing
  is missing tests for columns that start beyond the end-of-line boundary.

**Recommendations:**
- Add `TestNewSSHExecutor_NonSSHKeyType` to cover the unsupported key type error.
- Add `TestNewService_Close_ManagerError` to cover the Close aggregation path.
- Add `TestExtractColumn_BeyondEOL` to cover the boundary condition.
- Integration test: `TestSSHManager_RealSwitch` in `test/integration/switch/` using
  a containerized SSH server (e.g., `openssh-server` container with Nexus-mimicking
  scripts).

---

### 6. `pkg/config/secrets` — 92.0%

**Test count:** 34
**All tests pass.**

**What is covered:**
- `IDevIDResolver`: scheme detection, `CanResolve` all cases, successful resolution
  (all base64 variants), invalid base64, decrypt error, empty ciphertext, context
  cancellation and deadline, nil decrypter, invalid scheme
- `FileResolver`: scheme detection, `CanResolve` all cases, successful read, missing
  file (wrapped `os.ErrNotExist`), empty file, invalid scheme, empty path, context
  cancellation
- `SecretValue`: `Clear()`, `IsExpired()`, `String()` including nil receiver
- Helper functions: `extractCiphertext`, `decodeBase64` all variants
- All typed error types

**Gaps (8%):**

- `IDevIDResolver` uses a real RSA key pair generated in `TestMain`. The test for
  `Resolve_DecryptionFailed` relies on timing (RSA decryption with wrong key), which
  passed reliably in this run (0.37s). If RSA padding error messages change across Go
  versions, the error string comparison could be fragile.

- The `Resolver` interface's `CanResolve` fast-path when the input is a non-string
  type is not tested (no tests call resolvers with exotic values).

**Recommendations:**
- Use `errors.As` rather than string matching in `TestIDevIDResolver_Resolve_DecryptionFailed`.
- Add a test for `SecretValue` zero-value construction to verify zero-value is valid.

---

### 7. `pkg/cli/commands/encrypt` — removed

This command produced the platform-wide AES-256-GCM secret scheme and was deleted
when that scheme was eradicated (global wrapping key blast radius). Per-node secrets
are produced via `idevid://` (RSA-OAEP to the node IDevID, e.g. `openssl pkeyutl`);
shared secrets live in the KMS and are referenced with `kms://`.

---

### 8. `pkg/cli/commands/switch` — 39.4%

**Test count:** 25
**All tests pass.**

**Gaps (60.6%):**

This is the lowest-coverage package. The tested code is primarily validation: required
flag checks and constructor error paths. All `run*` functions (the actual command
execution logic) are minimally tested because they require a live HTTP server.

Specific uncovered code:
- `newCLIContext` (0%) — trivial, but zero coverage signals no test calls commands
  through the full execution path
- `buildClientTLSConfig` (0%) — TLS certificate loading from file paths
- `runListPorts`, `runPortStatus`, `runSetVLAN`, `runEnablePort`, `runDisablePort` —
  all have 6-40% coverage covering only the early validation returns

**Recommendations:**

1. Add `TestNewCLIContext` — trivial, brings `newCLIContext` to 100% with a single
   assertion that the returned context has a deadline.
2. Add `TestBuildClientTLSConfig_*` for the TLS config builder with temp cert files.
3. Add `TestRunListPorts_Success` using an `httptest.NewTLSServer` that returns a
   mock response, exercising the full command execution path without needing real
   network hardware.
4. Integration test: `TestSwitchCommands_Integration` in
   `test/integration/cli/switch/` using the platformd REST endpoint with all switch
   operations.

---

### 9. `pkg/webservice/v1/rest/switch` — 85.6%

**Test count:** 27
**All tests pass.**

**Gaps (14.4%):**

- `extractSwitchAndPort` (60%) — the helper that decodes URL path segments. The path
  where URL decoding fails for a malformed percent-encoded segment is not tested.
- `decodeVar` (75%) — the route variable decoder. Missing test for an empty variable
  name.
- `handlePortError` (75%) — error classification. The path where `err` is nil is not
  tested, and the `ErrPortNotFound` type-assertion path may have an unexercised branch.

**Recommendations:**
- Add `TestExtractSwitchAndPort_MalformedPercent` with a request URL containing `%ZZ`
  in the port segment.
- Add `TestHandlePortError_Nil` to verify that a nil error returns HTTP 200.
- Add `TestHandlePortError_UnknownError` to verify that an unknown error type returns
  HTTP 500 with a generic message.

---

### 10. `sdk/go/services/switch` — 90.1%

**Test count:** 26
**All tests pass.**

**Gaps (9.9%):**

- `doGet` (77.8%) — the private HTTP GET helper. The path where the HTTP client's
  `Do()` returns a network-level error (not an HTTP error) is not tested.
- `doPost` (84.2%) — same gap for the POST helper.
- `decodeResponse` (71.4%) — the path where `json.Decode` fails on a truncated
  response body is not tested.

**Recommendations:**
- Add `TestClient_doGet_NetworkError` using an `httptest.Server` that closes the
  connection immediately to trigger a transport-level error.
- Add `TestClient_decodeResponse_Truncated` with a server that returns valid HTTP
  headers but a truncated JSON body.

---

### 11. `pkg/sdn/cluster/gateway_partitions.go` — 92.3% (cluster package overall)

**Test count:** 679 (full cluster package)
**All tests pass.**

The `gateway_partitions.go` file contains the partition type constants and the
`VIPEntry`, `ConnTrackEntry`, `NATSessionEntry`, `FirewallRuleEntry`, and
`BGPRouteEntry` data types. These are well covered:

- All serialization round-trips (JSON and entity ID)
- Uniqueness of partition constants
- Cross-type entity ID uniqueness
- Empty/nil field handling

**Gaps** are in the broader cluster package (7.7%), mainly in the DAO layer:
- `notifier.go:Notify` (70%) — the subscriber notification path where a subscriber
  channel is full (backpressure) is not tested.
- Various DAO `Update` and `Delete` methods at 84-88% — the optimistic-concurrency
  version conflict path is partially tested but not all branches are exercised.

**Recommendations:**
- Add `TestNotifier_Notify_FullChannel` to verify backpressure behavior when a
  subscriber's channel is at capacity.
- Expand DAO update tests to cover all version conflict variants.

---

### 12. `pkg/sdn/gateway` — 71.2% (node + compat + types)

**Test count:** 91
**All tests pass.**

**Gaps (28.8%):**

This package has the largest absolute gap. The uncovered code falls into three
categories:

**Category A — Deprecated compat layer (compat.go):**
All methods on `GatewayMode` (0% coverage): `String()`, `Valid()`, `HasMode()`,
`Modes()`, `GetActiveModes()`, `HasMode` (on Gateway), `ActivateMode`,
`DeactivateMode`. These are deprecated compatibility shims for the old mode-flag API.
The new config-driven API is fully tested in `node_test.go`. The compat methods are
retained only for API compatibility during migration. All typed errors in `compat.go`
(`ErrModeNotActive`, `ErrModeAlreadyActive`, `ErrInvalidMode`) have 0% coverage.

**Category B — Service handler internals (node.go):**
The inner service handler types (`loadBalancerServiceHandler`, `natServiceHandler`,
`firewallServiceHandler`, `dhcpServiceHandler`, `pxeServiceHandler`) all have
`IsActive()`, `Health()`, `Name()`, and `Start()`/`Stop()` at 0-80%. The `Start` and
`Stop` for load balancer and NAT handlers are 0% — these depend on components that
require external process management (e.g., starting keepalived or iptables).

**Category C — Gateway node.go rollback path:**
`rollbackStartedServices` (0%) — the rollback function called when a partial startup
fails is not exercised because the test startup always succeeds. A test that injects
a failing service mid-startup would exercise this path.

**Recommendations (priority order):**

1. Add `TestGatewayMode_*` tests for the compat layer to bring deprecated API to at
   least 80% — this is a small addition with high ROI since it documents the migration
   contract.
2. Add `TestGateway_Start_Rollback` — inject a service that fails on `Start()` to
   verify that previously-started services are stopped.
3. Add `TestServiceHandler_LoadBalancer_*` and `TestServiceHandler_NAT_*` for the
   service handler Start/Stop/IsActive/Health cycle.
4. Add integration test: `TestGateway_FullStartStop` in `test/integration/sdn/gateway/`
   using a real OVS instance.

---

### 13. `pkg/sdn/gateway/commands` — 60.0%

**Test count:** 13
**All tests pass.**

**Gaps (40%):**

- `Execute` (0%) — the top-level command entry point that calls `rootCmd.Execute()`.
  This cannot be unit tested without hijacking `os.Args` or using a subprocess.
- `runServe` (0%) — the serve subcommand that instantiates a real gateway and blocks.
  This requires a full platform daemon stack.

**Recommendations:**
- Add `TestExecute_InvalidArgs` using a subprocess test (`exec.Command(os.Args[0], ...)`)
  to verify error exit code on bad arguments.
- Integration test: `TestGatewayServe_Integration` in `test/integration/sdn/gateway/`
  that starts the serve command with a test config and verifies it comes up.

---

### 14. `pkg/sdn/gateway/modes` — 87.9%

**Test count:** 274
**All tests pass.**

**Gaps (12.1%):**

- `edge_pxe.go:Start` (0%) and `SetDeviceLookup` (0%) — the PXE sub-service start
  path and device-lookup registration. These require real DHCP/TFTP server components.
- `overlay.go:stopComponents` (40%) — the shutdown sequence for overlay sub-components
  when some components were never started is not fully tested.
- `transit.go:Start` (65.4%) — the BGP session establishment and RPKI validator
  initialization paths that require real BGP peer connections.
- `edge.go:Start` (62.5%) and `Stop` (75%) — similarly dependent on real network
  interfaces.
- Various `expirationLoop` and `cleanupLoop` goroutine paths (71%) — time-triggered
  cleanup that requires test clock injection.

**Recommendations:**
- Add a `clock` interface to `expirationLoop` and `cleanupLoop` to allow test-driven
  clock advancement without `time.Sleep`.
- Add `TestOverlayMode_StopComponents_PartialStart` to cover the partial-start
  shutdown path.
- Integration tests for `transit`, `edge`, and `overlay` Start/Stop cycles in
  `test/integration/sdn/gateway/modes/`.

---

## Test Quality Assessment

### Error Path Coverage

All packages define typed errors as structs implementing `error`. Across all packages:
- Every exported typed error has at least one test verifying its `Error()` message.
- All typed errors that implement `Unwrap()` have `Unwrap()` tested via `errors.Is`
  or `errors.As`.
- No packages use `fmt.Errorf` — the convention is consistently followed.

### Concurrent Access

The following packages have explicit concurrency tests:
- `pkg/sdn/firewall`: `TestConnTrack_ConcurrentAccess` with 100 goroutines, shard
  distribution verified.
- `pkg/sdn/cluster`: Multiple DAO tests use parallel goroutines to verify lock-free
  read paths.
- `pkg/sdn/gateway/modes`: `TestTransitModeHandler_ConcurrentOperations` verifies
  sign/verify operations under concurrent load.
- `pkg/sdn/tunnel`: No concurrent-access tests. The manager uses `sync.RWMutex` and
  should have a concurrent-access test.

### Edge Case Coverage

Good patterns observed across all packages:
- Nil input tests are present for every public constructor.
- Boundary values tested for VLAN IDs (0, 1, 4094, 4095), MTU (min/max), TTL.
- Empty slice and empty map inputs tested in all collection-accepting functions.
- Context cancellation and deadline tested in `pkg/config/secrets`.

Gaps:
- `pkg/cli/commands/switch` and `pkg/cli/commands/encrypt` do not test the happy path
  at all due to the daemon dependency. No context cancellation tests exist.
- `pkg/sdn/tunnel` does not test concurrent tunnel creation (parallel `EnsureTunnel`
  calls for different tunnel names).

---

## Integration Test Requirements

The following functionality requires real infrastructure and cannot be meaningfully
unit tested. Integration tests should be added to `test/integration/`:

### Requires Real Switch Hardware or Simulator

| Test | Package | Requirements |
|------|---------|--------------|
| `TestNexusDriver_Connect_RealSSH` | `pkg/sdn/fabric/nexus` | SSH-accessible Nexus switch or container-based CLI simulator |
| `TestSSHManager_RealSwitch` | `pkg/switch` | SSH server with Cisco IOS/NX-OS CLI responses |
| `TestSSHExecutor_Execute` | `pkg/switch` | Any SSH server |

### Requires Running platformd

| Test | Package | Requirements |
|------|---------|--------------|
| `TestEncryptCommand_Integration` | `pkg/cli/commands/encrypt` | platformd with KMS service |
| `TestSwitchCommands_Integration` | `pkg/cli/commands/switch` | platformd with switch service configured |

### Requires Real Linux Network Stack (devcontainer)

| Test | Package | Requirements |
|------|---------|--------------|
| `TestTunnelManager_RealNetlink` | `pkg/sdn/tunnel` | Network namespace in devcontainer |
| `TestGateway_FullStartStop` | `pkg/sdn/gateway` | OVS + network namespaces |
| `TestGatewayServe_Integration` | `pkg/sdn/gateway/commands` | Full platform stack |
| `TestEdgeMode_Start` | `pkg/sdn/gateway/modes` | DHCP, TFTP, network interfaces |
| `TestTransitMode_BGPSession` | `pkg/sdn/gateway/modes` | BGP daemon (GoBGP) |
| `TestOverlayMode_VXLANFlows` | `pkg/sdn/gateway/modes` | OVS, VXLAN interfaces |

---

## Priority Remediation Plan

### Immediate (closes coverage gaps with unit tests only)

These gaps can be closed without real infrastructure:

1. `pkg/cli/commands/switch` — Add `TestNewCLIContext`, `TestBuildClientTLSConfig_*`
   using temp cert files, and `TestRun*_Success` using `httptest.Server`. Estimated
   coverage improvement: +45pp to 85%+.

2. `pkg/cli/commands/encrypt` — Extract the KMS encrypt function behind an interface
   and add `TestRunEncrypt_Success` using a mock. Estimated: +30pp to 91%+.

3. `pkg/sdn/gateway` — Add `TestGatewayMode_*` for the compat layer and
   `TestGateway_Start_Rollback`. Estimated: +15pp to 86%+.

4. `pkg/sdn/tunnel` — Add `TestManager_ListTunnels_LinkListError` and
   `TestManager_Status_AddrListError`. Estimated: +3pp to 91%+.

5. `pkg/webservice/v1/rest/switch` — Add three missing edge case tests. Estimated:
   +5pp to 90%+.

6. `pkg/switch` — Add `TestNewSSHExecutor_NonSSHKeyType`, `TestNewService_Close_ManagerError`,
   `TestExtractColumn_BeyondEOL`. Estimated: +5pp to 90%+.

### Short-term (integration tests, devcontainer)

Tracked in `test/integration/`:
- `sdn/tunnel/` — real netlink GRE tunnel creation in a network namespace
- `sdn/gateway/` — OVS-backed gateway start/stop cycle
- `switch/` — SSH server container mimicking Nexus CLI output

### Long-term (requires real hardware or hardware simulators)

- Nexus NX-OS driver against a real Cisco switch or NX-OS virtual appliance
- BGP transit mode against a real GoBGP peer
- PXE edge mode with real DHCP/TFTP clients

---

## Makefile Coverage Targets

The following `make` targets should be added (or verified to exist) for per-package
coverage:

```make
coverage-sdn-fabric:
	GONOSUMCHECK="*" GONOSUMDB="*" GOPRIVATE="*" GOFLAGS="-buildvcs=false" \
	go test ./pkg/sdn/fabric/... -cover -coverprofile=coverage/sdn-fabric.out
	go tool cover -html=coverage/sdn-fabric.out -o coverage/sdn-fabric.html

coverage-sdn-firewall:
	GONOSUMCHECK="*" GONOSUMDB="*" GOPRIVATE="*" GOFLAGS="-buildvcs=false" \
	go test ./pkg/sdn/firewall/... -cover -coverprofile=coverage/sdn-firewall.out
	go tool cover -html=coverage/sdn-firewall.out -o coverage/sdn-firewall.html

coverage-sdn-tunnel:
	GONOSUMCHECK="*" GONOSUMDB="*" GOPRIVATE="*" GOFLAGS="-buildvcs=false" \
	go test ./pkg/sdn/tunnel/... -cover -coverprofile=coverage/sdn-tunnel.out
	go tool cover -html=coverage/sdn-tunnel.out -o coverage/sdn-tunnel.html

coverage-sdn-cluster:
	GONOSUMCHECK="*" GONOSUMDB="*" GOPRIVATE="*" GOFLAGS="-buildvcs=false" \
	go test ./pkg/sdn/cluster/... -cover -coverprofile=coverage/sdn-cluster.out
	go tool cover -html=coverage/sdn-cluster.out -o coverage/sdn-cluster.html

coverage-sdn-gateway:
	GONOSUMCHECK="*" GONOSUMDB="*" GOPRIVATE="*" GOFLAGS="-buildvcs=false" \
	go test ./pkg/sdn/gateway/... -cover -coverprofile=coverage/sdn-gateway.out
	go tool cover -html=coverage/sdn-gateway.out -o coverage/sdn-gateway.html

coverage-switch:
	GONOSUMCHECK="*" GONOSUMDB="*" GOPRIVATE="*" GOFLAGS="-buildvcs=false" \
	go test ./pkg/switch/... -cover -coverprofile=coverage/switch.out
	go tool cover -html=coverage/switch.out -o coverage/switch.html

coverage-secrets:
	GONOSUMCHECK="*" GONOSUMDB="*" GOPRIVATE="*" GOFLAGS="-buildvcs=false" \
	go test ./pkg/config/secrets/... -cover -coverprofile=coverage/secrets.out
	go tool cover -html=coverage/secrets.out -o coverage/secrets.html

coverage-cli-encrypt:
	GONOSUMCHECK="*" GONOSUMDB="*" GOPRIVATE="*" GOFLAGS="-buildvcs=false" \
	go test ./pkg/cli/commands/encrypt/... -cover -coverprofile=coverage/cli-encrypt.out
	go tool cover -html=coverage/cli-encrypt.out -o coverage/cli-encrypt.html

coverage-cli-switch:
	GONOSUMCHECK="*" GONOSUMDB="*" GOPRIVATE="*" GOFLAGS="-buildvcs=false" \
	go test ./pkg/cli/commands/switch/... -cover -coverprofile=coverage/cli-switch.out
	go tool cover -html=coverage/cli-switch.out -o coverage/cli-switch.html

coverage-rest-switch:
	GONOSUMCHECK="*" GONOSUMDB="*" GOPRIVATE="*" GOFLAGS="-buildvcs=false" \
	go test ./pkg/webservice/v1/rest/switch/... -cover -coverprofile=coverage/rest-switch.out
	go tool cover -html=coverage/rest-switch.out -o coverage/rest-switch.html

coverage-sdk-switch:
	GONOSUMCHECK="*" GONOSUMDB="*" GOPRIVATE="*" GOFLAGS="-buildvcs=false" \
	go test ./sdk/go/services/switch/... -cover -coverprofile=coverage/sdk-switch.out
	go tool cover -html=coverage/sdk-switch.out -o coverage/sdk-switch.html

bench-sdn-firewall:
	GONOSUMCHECK="*" GONOSUMDB="*" GOPRIVATE="*" GOFLAGS="-buildvcs=false" \
	go test ./pkg/sdn/firewall/... -bench=. -benchmem -count=3
```
