# SDN Testing Strategy

## Overview

Testing follows TDD principles with distinct unit and integration test layers.
Unit tests run fast in-memory with mocks; integration tests run in containers
with real OVS infrastructure.

## Test Summary

| Package | Unit Tests | Integration Tests | Coverage |
|---------|------------|-------------------|----------|
| arp | 15+ | 10 | 95%+ |
| openflow | 20+ | 18 | 90%+ |
| ovs | 25+ | 12 | 90%+ |
| netlink | 20+ | 8 | 85%+ |
| policy | 30+ | 27 | 90%+ |
| **Total** | **110+** | **75+** | **90%+** |

## Test Layers

| Layer | Location | Dependencies | CI |
|-------|----------|--------------|-----|
| Unit | `pkg/sdn/*/` | None (mocks) | Fast |
| Integration | `test/integration/sdn/` | OVS in container | Slow |

## Unit Tests

### Requirements

- Run in-memory, no system modifications
- Complete quickly (< 1 second per test)
- No skip guards or -short flags
- 90%+ code coverage target
- Test both success and error paths

### Package Coverage

#### pkg/sdn/arp

```go
// arp_test.go
func TestTable_ParseValidFile(t *testing.T)       // Valid /proc/net/arp
func TestTable_ParseMalformedFile(t *testing.T)   // Bad format handling
func TestTable_EmptyFile(t *testing.T)            // Empty ARP table
func TestLookupMAC_Found(t *testing.T)            // Successful lookup
func TestLookupMAC_NotFound(t *testing.T)         // IP not in table
func TestLookupMAC_IncompleteEntry(t *testing.T)  // 00:00:00:00:00:00
```

#### pkg/sdn/openflow

```go
// client_test.go - with mock server
func TestClient_Connect(t *testing.T)           // Connection setup
func TestClient_Handshake(t *testing.T)         // Hello/Features exchange
func TestClient_AddFlow(t *testing.T)           // Flow mod add
func TestClient_DeleteFlow(t *testing.T)        // Flow mod delete
func TestClient_ModifyFlow(t *testing.T)        // Flow mod modify
func TestClient_GetFlowStats(t *testing.T)      // Multipart request
func TestClient_Barrier(t *testing.T)           // Barrier sync
func TestClient_Echo(t *testing.T)              // Echo request/reply
func TestClient_Reconnect(t *testing.T)         // Reconnection handling
func TestClient_Timeout(t *testing.T)           // Operation timeout

// messages_test.go
func TestHeader_MarshalBinary(t *testing.T)     // Header encoding
func TestHeader_UnmarshalBinary(t *testing.T)   // Header decoding
func TestMatch_AllFields(t *testing.T)          // All match field types
func TestMatch_Wildcards(t *testing.T)          // Wildcard matching
func TestActions_Output(t *testing.T)           // Output action
func TestActions_SetVLAN(t *testing.T)          // Set VLAN action
func TestActions_PopVLAN(t *testing.T)          // Pop VLAN action
func TestActions_GotoTable(t *testing.T)        // Goto table action
func TestFlowMod_MarshalBinary(t *testing.T)    // Complete flow mod
func TestFlowStats_UnmarshalBinary(t *testing.T) // Stats parsing

// protocol_test.go
func TestConstants(t *testing.T)                // Protocol constants
func TestByteOrder(t *testing.T)                // Big-endian encoding
```

#### pkg/sdn/ovs

```go
// client_test.go - with mock OVSDB server
func TestClient_Connect(t *testing.T)           // Connection setup
func TestClient_Disconnect(t *testing.T)        // Clean disconnect
func TestClient_ListDatabases(t *testing.T)     // list_dbs method
func TestClient_GetSchema(t *testing.T)         // get_schema method
func TestClient_Echo(t *testing.T)              // echo method
func TestClient_Transact(t *testing.T)          // Transaction handling
func TestClient_TransactError(t *testing.T)     // Transaction error

// bridge_test.go
func TestBridge_Create(t *testing.T)            // CreateBridge
func TestBridge_Delete(t *testing.T)            // DeleteBridge
func TestBridge_Get(t *testing.T)               // GetBridge
func TestBridge_List(t *testing.T)              // ListBridges
func TestBridge_AlreadyExists(t *testing.T)     // Duplicate bridge

// port_test.go
func TestPort_Add(t *testing.T)                 // AddPort
func TestPort_Delete(t *testing.T)              // DeletePort
func TestPort_Get(t *testing.T)                 // GetPort
func TestPort_List(t *testing.T)                // ListPorts
func TestPort_SetVLAN(t *testing.T)             // SetPortVLAN
func TestPort_SetTrunks(t *testing.T)           // SetPortTrunks
func TestPort_SetState(t *testing.T)            // SetPortState

// flow_test.go
func TestFlow_Add(t *testing.T)                 // AddFlow via OpenFlow
func TestFlow_Delete(t *testing.T)              // DeleteFlow
func TestFlow_DeleteAll(t *testing.T)           // DeleteAllFlows
func TestFlow_GetStats(t *testing.T)            // GetFlowStats

// types_test.go
func TestUUID_Marshal(t *testing.T)             // UUID serialization
func TestSet_Marshal(t *testing.T)              // Set serialization
func TestMap_Marshal(t *testing.T)              // Map serialization
func TestNamedUUID_Marshal(t *testing.T)        // Named UUID ref
```

#### pkg/sdn/policy

```go
// engine_test.go
func TestEngine_New(t *testing.T)               // Engine creation
func TestEngine_SetPortState(t *testing.T)      // State transitions
func TestEngine_ApplyPolicy(t *testing.T)       // Policy application
func TestEngine_RemovePolicy(t *testing.T)      // Policy removal
func TestEngine_AuthenticatePort(t *testing.T)  // Certificate auth

// state_test.go
func TestStateMachine_Transitions(t *testing.T) // Valid transitions
func TestStateMachine_Invalid(t *testing.T)     // Invalid transitions

// certificate_test.go
func TestX509Extractor_Policy(t *testing.T)     // Policy extraction
func TestX509Extractor_TenantID(t *testing.T)   // Tenant ID extraction

// enrollment_hook_test.go
func TestEnrollmentHook_OnComplete(t *testing.T)    // Enrollment handling
func TestEnrollmentHook_Activate(t *testing.T)      // Device activation
func TestEnrollmentHook_RegisterPort(t *testing.T)  // Port registration
```

### Mock Servers

#### Mock OpenFlow Server

```go
// pkg/sdn/openflow/mock_server_test.go
type mockOFServer struct {
    listener net.Listener
    conn     net.Conn
    handlers map[uint8]func([]byte) []byte
}

func (s *mockOFServer) handleHello(data []byte) []byte
func (s *mockOFServer) handleFeaturesRequest(data []byte) []byte
func (s *mockOFServer) handleFlowMod(data []byte) []byte
func (s *mockOFServer) handleBarrier(data []byte) []byte
```

#### Mock OVSDB Server

```go
// pkg/sdn/ovs/mock_server_test.go
type mockOVSDBServer struct {
    listener  net.Listener
    databases map[string]map[string][]map[string]interface{}
}

func (s *mockOVSDBServer) handleListDbs() []string
func (s *mockOVSDBServer) handleGetSchema(db string) *Schema
func (s *mockOVSDBServer) handleTransact(ops []Operation) []OpResult
```

## Integration Tests

### Location

```
test/integration/sdn/
+-- run-tests.sh              # Test orchestration
+-- openflow_native_test.go   # Pure Go OpenFlow client tests
+-- arp_native_test.go        # Pure Go ARP table reader tests
+-- bridge_test.go            # Bridge operations
+-- port_test.go              # Port operations
+-- flow_test.go              # Flow operations
+-- tap_test.go               # TAP device tests
+-- ovsdb_test.go             # OVSDB client tests
+-- policy_test.go            # Policy engine tests
```

### Build Tags

```go
//go:build integration && linux

package sdn_integration
```

### Test Requirements

- Run in privileged Docker container
- OVS installed and running
- Root permissions for OVS operations
- Clean environment (no pre-existing bridges)

### Native OpenFlow Integration Tests

Tests using the pure Go OpenFlow client (`pkg/sdn/openflow`):

```go
// openflow_native_test.go
func TestNativeOpenFlow_Connection(t *testing.T)     // Connect to real bridge
func TestNativeOpenFlow_Handshake(t *testing.T)      // Hello/Features exchange
func TestNativeOpenFlow_AddFlow(t *testing.T)        // Add flow rule
func TestNativeOpenFlow_DeleteFlow(t *testing.T)     // Delete flow rule
func TestNativeOpenFlow_ModifyFlow(t *testing.T)     // Modify existing flow
func TestNativeOpenFlow_GetFlowStats(t *testing.T)   // Get flow statistics
func TestNativeOpenFlow_Barrier(t *testing.T)        // Barrier sync
func TestNativeOpenFlow_Echo(t *testing.T)           // Echo request/reply
func TestNativeOpenFlow_MultipleFlows(t *testing.T)  // Add multiple flows
func TestNativeOpenFlow_FlowPriority(t *testing.T)   // Priority handling
func TestNativeOpenFlow_Reconnect(t *testing.T)      // Disconnect and reconnect
func TestNativeOpenFlow_VLANFlow(t *testing.T)       // VLAN push/pop
func TestNativeOpenFlow_GotoTableFlow(t *testing.T)  // Goto table instruction
func TestNativeOpenFlow_ComplexMatch(t *testing.T)   // Multi-field matches
func TestNativeOpenFlow_DeleteAllFlows(t *testing.T) // Delete all flows
func TestNativeOpenFlow_ConcurrentOps(t *testing.T)  // Concurrent operations
func TestNativeOpenFlow_ErrorHandling(t *testing.T)  // Error handling
func TestNativeOpenFlow_Timeouts(t *testing.T)       // Operation timeouts
```

### Native ARP Integration Tests

Tests using the pure Go ARP table reader (`pkg/sdn/arp`):

```go
// arp_native_test.go
func TestNativeARP_ReadTable(t *testing.T)         // Read /proc/net/arp
func TestNativeARP_Entries(t *testing.T)           // Get all entries
func TestNativeARP_LookupAfterPing(t *testing.T)   // Ping creates entry, lookup
func TestNativeARP_LookupLocalhost(t *testing.T)   // Localhost handling
func TestNativeARP_LookupNotFound(t *testing.T)    // Non-existent IP
func TestNativeARP_MultipleEntries(t *testing.T)   // Multiple ARP entries
func TestNativeARP_LookupIP(t *testing.T)          // MAC to IP lookup
func TestNativeARP_InvalidIP(t *testing.T)         // Invalid IP error
func TestNativeARP_InvalidMAC(t *testing.T)        // Invalid MAC error
func TestNativeARP_GetMACForIP(t *testing.T)       // Convenience function
```

### Policy Engine Integration Tests

```go
// policy_test.go
func TestPolicyEngine_FullLifecycle(t *testing.T)    // Complete flow
func TestPolicyEngine_CertificateAuth(t *testing.T)  // Certificate-based auth
func TestPolicyEngine_VLANTransition(t *testing.T)   // VLAN transitions
func TestPolicyEngine_FlowRules(t *testing.T)        // OpenFlow rule generation
func TestPolicyEngine_Quarantine(t *testing.T)       // Quarantine handling
func TestPolicyEngine_Block(t *testing.T)            // Port blocking
func TestPolicyEngine_Concurrent(t *testing.T)       // Concurrent access
```

## Makefile Targets

```makefile
# Unit tests
test-sdn:
    go test -v -cover ./pkg/sdn/...

test-sdn-arp:
    go test -v -cover ./pkg/sdn/arp/...

test-sdn-openflow:
    go test -v -cover ./pkg/sdn/openflow/...

test-sdn-ovs:
    go test -v -cover ./pkg/sdn/ovs/...

test-sdn-netlink:
    go test -v -cover ./pkg/sdn/netlink/...

test-sdn-policy:
    go test -v -cover ./pkg/sdn/policy/...

# Integration tests
integration-test-sdn:
    docker run --privileged --rm \
        -v $(PWD):/app \
        -w /app \
        trusted-platform-builder \
        go test -tags=integration ./test/integration/sdn/...

# Coverage
coverage-sdn:
    go test -coverprofile=coverage-sdn.out ./pkg/sdn/...
    go tool cover -html=coverage-sdn.out -o coverage-sdn.html

# Benchmarks
bench-sdn:
    go test -bench=. -benchmem ./pkg/sdn/...
```

## Running Tests

### Unit Tests (Fast, Local)

```bash
# All SDN packages
make test-sdn

# Specific package
go test -v ./pkg/sdn/openflow/...

# With coverage
go test -cover -coverprofile=cover.out ./pkg/sdn/openflow/...
go tool cover -html=cover.out
```

### Integration Tests (Container)

```bash
# All integration tests
make integration-test-sdn

# Specific test
docker run --privileged --rm \
    -v $(PWD):/app \
    -w /app \
    trusted-platform-builder \
    go test -tags=integration ./test/integration/sdn/... -run TestOpenFlow
```

### End-to-End Test

```bash
# Full client-server test with OVS
sudo ./platformctl iso test client-server --use-ovs --debug
```

## Test Conventions

1. **Error Paths** - Every function has at least 2 tests: success and error
2. **Typed Errors** - Never use fmt.Errorf, always typed errors
3. **Table Tests** - Use table-driven tests for multiple inputs
4. **Cleanup** - Always clean up resources in defer or t.Cleanup
5. **Parallel** - Mark independent tests with t.Parallel()
6. **Naming** - TestFunctionName_Scenario for clarity

## Coverage Goals

| Package | Target | Notes |
|---------|--------|-------|
| arp | 95% | Simple, full coverage achievable |
| openflow | 90% | Protocol encoding complete |
| ovs | 90% | Mock OVSDB server coverage |
| netlink | 85% | Some kernel-dependent code |
| policy | 90% | State machine fully testable |

## Debugging

```bash
# Verbose output
go test -v -count=1 ./pkg/sdn/openflow/...

# Run single test
go test -v -run TestClient_AddFlow ./pkg/sdn/openflow/...

# Race detector
go test -race ./pkg/sdn/...

# CPU/memory profiling
go test -cpuprofile=cpu.out -memprofile=mem.out ./pkg/sdn/openflow/...
```

## CI/CD Integration

### GitHub Actions

```yaml
sdn-tests:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4

    - name: Set up Go
      uses: actions/setup-go@v5
      with:
        go-version: '1.21'

    - name: Unit Tests
      run: make test-sdn

    - name: Integration Tests
      run: make integration-test-sdn

    - name: Coverage Report
      run: |
        make coverage-sdn
        go tool cover -func=coverage-sdn.out
```

## Test Data

### Sample Certificates

Test certificates are generated in `testdata/`:

```
testdata/
+-- ca.pem           # Test CA certificate
+-- device.pem       # Test device certificate
+-- device-key.pem   # Test device private key
+-- expired.pem      # Expired certificate for testing
+-- revoked.pem      # Revoked certificate for testing
```

### Mock ARP Table

```go
const mockARPTable = `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.2      0x1         0x2         11:22:33:44:55:66     *        eth0
192.168.1.3      0x1         0x0         00:00:00:00:00:00     *        eth0
`
```

## Performance Testing

### Benchmarks

```go
func BenchmarkOpenFlow_AddFlow(b *testing.B)
func BenchmarkOpenFlow_DeleteFlow(b *testing.B)
func BenchmarkARP_LookupMAC(b *testing.B)
func BenchmarkPolicy_ApplyPolicy(b *testing.B)
```

### Performance Targets

| Operation | Target | Notes |
|-----------|--------|-------|
| Flow add | < 1ms | Single flow rule |
| Flow delete | < 1ms | Single flow rule |
| ARP lookup | < 100us | Single IP lookup |
| Policy apply | < 5ms | Including VLAN and flows |
