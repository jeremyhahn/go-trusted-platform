# ACME Enrollment Integration Tests

## Overview

This directory contains comprehensive integration tests for the ACME enroll-01 challenge flow, which implements device attestation via TPM and certificate-based network access control.

## Test Files

- `acme_enrollment_integration_test.go` - Main integration test suite
- `acme_enrollment_mock_server_test.go` - Mock HTTP server for provisioning endpoints

## Test Coverage

### 1. Device Attestation Flow
Tests the complete device enrollment process:
- Device generates TPM-bound keys (simulated in unit tests, real TPM in integration tests)
- Device creates Certificate Signing Request (CSR) with attestation data
- Server verifies TPM attestation (EK certificate, AK quote, PCR values)
- Server issues IDevID certificate with device identity

**Key Components:**
- TPM key generation and attestation
- CSR creation with TCG extensions
- Server-side attestation verification
- IDevID certificate issuance

### 2. Certificate-Based Network Access
Tests network policy enforcement based on certificate contents:
- Device presents certificate to network (via mTLS)
- Policy engine extracts VLAN and ACL rules from certificate
- Device port transitions through network phases:
  - Provisioning VLAN (limited access for enrollment)
  - Enrolled state (certificate issued, awaiting activation)
  - Production VLAN (full network access after activation)

**Key Components:**
- Enrollment hook processing certificates
- Port state transitions (Provisioning → Enrolled → Authorized)
- VLAN tagging and policy enforcement
- Network segmentation

###  3. End-to-End Enrollment
Tests the complete client-server enrollment workflow:
- Server starts with CA and ACME service
- Client connects to provisioning network
- Client performs enroll-01 challenge with TPM attestation
- Client receives IDevID certificate with network policy extensions
- Client fetches device profile via mTLS (using IDevID)
- Client signals activation readiness
- Server transitions client port to production VLAN
- Client applies production network configuration

**Key Components:**
- Provisioning client (`pkg/provisioning/client.go`)
- Device profile service (`pkg/device/profile_service.go`)
- Network phase transitions
- mTLS authentication with IDevID

### 4. Error Cases
Tests various failure scenarios:
- Invalid TPM attestation rejected
- Revoked certificates blocked from network access
- Expired certificates detected and trigger re-enrollment
- Missing/invalid device profiles prevent enrollment
- Network policy application failures

**Key Components:**
- Certificate revocation checking
- Expiration validation
- Profile lookup failures
- Policy application error handling

## Dependencies

### Required Packages
- `pkg/kms` - Key Management System for certificate operations
- `pkg/device` - Device profile and enrollment management
- `pkg/sdn/policy` - Network policy engine and enrollment hooks
- `pkg/provisioning` - Provisioning client for mTLS profile fetching
- `pkg/store/datastore` - Data persistence layer
- `pkg/swtpm` - Software TPM for integration tests

### Test Infrastructure
- `pkg/testenv` - Isolated test network environments
- Mock policy engine for unit-level integration tests
- In-memory datastore for fast test execution

## Running Tests

### Unit-Level Integration Tests
These tests use mocks and run quickly without modifying the host:

```bash
# Run all ACME enrollment tests
make test-acme-enrollment

# Run with verbose output
go test -v -tags=integration ./test/integration -run TestACMEEnrollmentFlow

# Run specific test case
go test -v -tags=integration ./test/integration -run TestACMEEnrollmentFlow/DeviceAttestationFlow
```

### Full Integration Tests with SWTPM
These tests require swtpm and run with real TPM simulation:

```bash
# Run TPM-based tests (requires swtpm installed)
go test -v -tags=integration ./test/integration -run TestEnrollmentWithRealTPM

# Skip if swtpm not available
SKIP_INTEGRATION=1 go test ./test/integration
```

### Run in Development Container
For complete isolation and reproducibility:

```bash
# Build and enter devcontainer
make devcontainer-build
make devcontainer-shell

# Inside container, run tests
go test -v -tags=integration ./test/integration
```

## Test Architecture

### Test Environment Setup
Each test creates an isolated environment with:
- In-memory KVStore datastore
- Mock CA for certificate issuance
- Mock policy engine for network control
- Device profile with production network configuration
- SDN enrollment hook for processing enrollment events

### Mock Components
- **MockPolicyEngine**: Simulates OpenFlow policy enforcement
- **MockHTTPServer**: Provides provisioning API endpoints
- **MockMACExtractor**: Simulates ARP table lookup for MAC addresses
- **MockCA**: Issues certificates for device testing

### Test Data
- **Provisioning VLAN**: 100
- **Production VLAN**: 200
- **Quarantine VLAN**: 999
- **Test Device**: "TEST-DEVICE-001" (serial), "TPM-TestDevice-v1" (model)
- **Test Network**: 10.99.99.0/28
- **Client IP**: 10.99.99.3
- **Server IP**: 10.99.99.2

## Integration Points

### With Real Platform Components
When integrated with the full platform:

1. **ACME Server** (`go-trusted-ca`)
   - Implements enroll-01 challenge validation
   - Verifies TPM attestation during CSR processing
   - Issues IDevID certificates with device identity

2. **Policy Engine** (`pkg/sdn/policy`)
   - Registers enrollment hook with ACME server
   - Processes enrollment completion events
   - Manages port state transitions
   - Applies network policies based on certificate

3. **Device Service** (`pkg/device`)
   - Stores device profiles with network configuration
   - Matches devices by serial number or MAC address
   - Provides profile API via mTLS

4. **SDN Controller** (`pkg/sdn/ovs`)
   - Manages OpenVSwitch bridges and ports
   - Applies OpenFlow rules for VLAN tagging
   - Enforces ACLs based on device profiles

## Expected Behavior

### Successful Enrollment Flow
1. Device boots on provisioning VLAN (100)
2. Device generates TPM attestation and CSR
3. ACME server verifies attestation and issues IDevID
4. Enrollment hook transitions port to "Enrolled" state
5. Device uses IDevID for mTLS to fetch profile
6. Device signals activation readiness
7. Server transitions port to production VLAN (200)
8. Device applies production network configuration

### Certificate Properties
IDevID certificates contain:
- Subject CN: Device model + serial number
- Subject SN: Device serial number
- Extended Key Usage: Client Authentication
- Extensions: TPM attestation data (TCG OIDs)
- Validity: Configured lifetime (e.g., 90 days)

### Network Phase Transitions
```
Unconnected
    ↓
Provisioning (VLAN 100) - Limited access for enrollment
    ↓ (after ACME enrollment)
Enrolled - Certificate issued, awaiting activation
    ↓ (after activation signal)
Authorized (VLAN 200) - Full production access
```

## Future Enhancements

1. **Real TPM Integration**
   - Integration with hardware TPM 2.0
   - Real EK and AK management
   - Actual PCR quote generation and verification

2. **Certificate Revocation**
   - CRL distribution and checking
   - OCSP responder integration
   - Automatic quarantine on revocation

3. **Advanced Network Policies**
   - Time-based access controls
   - Rate limiting per device
   - Dynamic ACL updates based on threat intelligence

4. **Multi-CA Support**
   - Certificate chain validation
   - Cross-certification between CAs
   - Certificate transparency logging

5. **Metrics and Monitoring**
   - Enrollment success/failure rates
   - Network transition times
   - Certificate lifetime tracking
   - Attestation verification latency

## Troubleshooting

### Common Issues

**Test fails with "TPM not available"**
- Install swtpm: `sudo apt-get install swtpm swtpm-tools`
- Or skip TPM tests: `SKIP_INTEGRATION=1 go test ./test/integration`

**Test fails with "datastore error"**
- Ensure in-memory backend is available
- Check datastore factory initialization

**Test fails with "port not found"**
- Verify mock MAC extractor returns correct MAC
- Check port registration in enrollment hook setup

**Network transition fails**
- Verify policy engine mock is properly initialized
- Check port state before and after transitions
- Review enrollment hook logs for errors

## Related Documentation

- `docs/GRPC_API_DESIGN.md` - API design for device management
- `pkg/provisioning/client.go` - Provisioning client implementation
- `pkg/sdn/policy/enrollment_hook.go` - Enrollment event processing
- `pkg/device/entities/profile.go` - Device profile schema

## Contributing

When adding new test cases:

1. Follow the existing test structure (testDeviceAttestationFlow, etc.)
2. Use table-driven tests for multiple scenarios
3. Add meaningful assertions with clear error messages
4. Clean up resources in test cleanup functions
5. Document expected behavior in test comments
6. Ensure tests can run in parallel where possible
7. Add integration-specific tests to this suite, unit tests to package-level test files
