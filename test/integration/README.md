# Integration Tests

This directory contains integration tests for the Trusted Platform that perform end-to-end testing with real services and VMs.

## Testenv Enrollment Integration Test

The testenv enrollment integration test (`testenv_enrollment_integration_test.go`) validates the full ACME enrollment workflow between server and client VMs with TPM-based attestation.

### What It Tests

1. **Server VM Provisioning**
   - Boots server VM with software TPM (swtpm)
   - Waits for platform services to start (DNS on port 9053, HTTPS on port 8443)
   - Validates server is ready to accept ACME enrollment requests

2. **Client VM Provisioning**
   - Boots client VM with software TPM (swtpm)
   - Embeds server CA bundle for trust
   - Configures client to use server for DNS resolution

3. **ACME enroll-01 Challenge**
   - Client initiates ACME enrollment with `enroll-01` challenge
   - Client generates TPM-backed IDevID certificate request
   - Server validates TPM attestation
   - Server issues IDevID certificate to client

4. **Certificate Verification**
   - Validates client received IDevID certificate
   - Verifies certificate contains TPM attestation extensions
   - Confirms certificate is properly signed and valid

### Requirements

#### System Requirements
- **Root privileges**: Required for network bridge and TAP device creation
- **Disk space**: ~20GB free for VM disk images and ISOs
- **Memory**: 8GB+ RAM recommended (VMs use 4GB each)
- **CPU**: 4+ cores recommended

#### Software Dependencies
- QEMU with KVM support (`qemu-system-x86_64`)
- Software TPM (`swtpm`)
- Network tools: `ip`, `iptables`, `nc`, `dig`, `ping`
- Go 1.21+ with CGO enabled

### Running the Test

#### Quick Start

```bash
# Run the integration test (requires root)
sudo make integration-test-testenv-enrollment
```

#### Manual Execution

```bash
# Navigate to the integration test directory
cd test/integration

# Run with Go test (requires root)
sudo CGO_ENABLED=1 go test -tags=integration -v -timeout=40m \
  -run TestEnrollmentIntegration ./...
```

### Test Workflow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Setup Isolated Network (10.99.99.0/28)                  │
│    - Create bridge: tp-br (10.99.99.1)                     │
│    - Create TAP devices: tap-tp-server, tap-tp-client      │
│    - Configure NAT for internet access                     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Server VM Setup                                          │
│    - IP: 10.99.99.2                                         │
│    - Create 10GB qcow2 disk                                 │
│    - Start software TPM (swtpm)                             │
│    - Build custom ISO with server config                    │
│    - Install OS with encrypted LUKS root                    │
│    - Boot VM (background mode)                              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Wait for Server Ready (up to 10 minutes)                │
│    - Check ping reachability                                │
│    - Check DNS service (port 9053)                          │
│    - Check HTTPS service (port 8443)                        │
│    - Handle automatic reboot after provisioning             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Fetch CA Bundle from Server                             │
│    - GET https://10.99.99.2:8443/api/v1/acme/ca-bundle     │
│    - Save to test-integration-enrollment/ca-bundle.pem      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. Client VM Setup                                          │
│    - IP: 10.99.99.3                                         │
│    - Create 10GB qcow2 disk                                 │
│    - Start software TPM (swtpm)                             │
│    - Build custom ISO with client config + CA bundle        │
│    - Install OS with encrypted LUKS root                    │
│    - Boot VM (background mode)                              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. Wait for Client Enrollment (up to 15 minutes)           │
│    - Check ping reachability                                │
│    - Check enrollment status on server API                  │
│    - Handle automatic reboot after provisioning             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ 7. Verify Enrollment Success                               │
│    - Fetch client certificate from server                   │
│    - Verify certificate properties:                         │
│      * Valid subject CN                                     │
│      * Not expired                                          │
│      * Proper serial number                                 │
│    - Verify TPM attestation extensions present              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ 8. Cleanup                                                  │
│    - Stop client VM and TPM                                 │
│    - Stop server VM and TPM                                 │
│    - Remove network bridge and TAP devices                  │
│    - Remove test artifacts                                  │
└─────────────────────────────────────────────────────────────┘
```

### Network Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ Host System                                                  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Network Bridge: tp-br (10.99.99.1/28)                  │ │
│  │                                                          │ │
│  │  ┌──────────────────┐         ┌──────────────────┐     │ │
│  │  │ TAP: tap-tp-server│         │ TAP: tap-tp-client│     │ │
│  │  │ MAC: 52:54:00:99:│         │ MAC: 52:54:00:99:│     │ │
│  │  │      00:02       │         │      00:03       │     │ │
│  │  └────────┬─────────┘         └────────┬─────────┘     │ │
│  └───────────┼──────────────────────────────┼─────────────┘ │
│              │                              │                │
│              │                              │                │
│         ┌────▼──────┐                 ┌────▼──────┐        │
│         │ Server VM  │                 │ Client VM  │        │
│         │ 10.99.99.2│◄────ACME────────│ 10.99.99.3│        │
│         │           │                 │           │        │
│         │ Services: │                 │ Services: │        │
│         │ - DNS:9053│                 │ - Enroll  │        │
│         │ -HTTPS:8443│                 │   Client  │        │
│         │ - ACME    │                 │           │        │
│         │ - CA      │                 │           │        │
│         └───────────┘                 └───────────┘        │
│                                                              │
│  NAT: iptables -t nat -A POSTROUTING -s 10.99.99.0/28      │
│                        -j MASQUERADE                         │
│                                                              │
│  Internet Access: Via gateway 10.99.99.1                    │
└──────────────────────────────────────────────────────────────┘
```

### Test Artifacts

All test artifacts are created in `test-integration-enrollment/`:

```
test-integration-enrollment/
├── ca-bundle.pem           # Server CA bundle (fetched during test)
├── server/                 # Server VM workspace
│   ├── tpm/               # Software TPM state
│   ├── platform.yaml      # Platform configuration
│   ├── installer.yaml     # Installer configuration
│   ├── server.iso         # Custom installation ISO
│   └── efivars/           # UEFI variables
├── client/                 # Client VM workspace
│   ├── tpm/               # Software TPM state
│   ├── platform.yaml      # Platform configuration
│   ├── installer.yaml     # Installer configuration
│   ├── client.iso         # Custom installation ISO (with CA bundle)
│   └── efivars/           # UEFI variables
├── server-disk.qcow2       # Server VM disk (10GB)
└── client-disk.qcow2       # Client VM disk (10GB)
```

### Cleanup

The test automatically cleans up on completion, but you can manually clean up with:

```bash
# Clean test artifacts (requires root)
sudo make integration-test-testenv-enrollment-clean
```

### Troubleshooting

#### Test Timeout

If the test times out, check:
- VM boot logs in serial console output
- Network connectivity: `ping 10.99.99.2`
- Service status: `nc -z 10.99.99.2 8443`

#### Network Issues

If network setup fails:
```bash
# Check bridge exists
ip link show tp-br

# Check TAP devices
ip link show tap-tp-server
ip link show tap-tp-client

# Check NAT rules
iptables -t nat -L POSTROUTING -n -v
```

#### VM Boot Issues

If VMs fail to boot:
```bash
# Check QEMU processes
ps aux | grep qemu

# Check swtpm processes
ps aux | grep swtpm

# Check available disk space
df -h
```

### Test Duration

Typical test execution times:
- Network setup: ~2 seconds
- Server VM installation: ~2-3 minutes
- Server boot and provisioning: ~3-5 minutes
- Client VM installation: ~2-3 minutes
- Client boot and enrollment: ~5-8 minutes
- Verification: ~5 seconds
- Cleanup: ~5 seconds

**Total: 15-25 minutes** (depending on system performance)

### CI/CD Integration

This test is designed for local development and manual testing. For CI/CD:

1. Requires bare metal or nested virtualization support
2. Must run with root privileges
3. Needs substantial disk space and memory
4. Should run on dedicated test infrastructure

### Related Documentation

- [ACME Protocol](../../docs/ACME.md)
- [TPM Attestation](../../docs/TPM_ATTESTATION.md)
- [Platform Architecture](../../docs/ARCHITECTURE.md)
- [ISO Builder](../../pkg/cmd/iso/README.md)
- [Testenv Package](../../pkg/testenv/README.md)

### Contributing

When modifying this test:

1. Keep timeout values generous (VMs can be slow)
2. Add detailed logging for debugging
3. Ensure proper cleanup in all code paths
4. Test on both fast and slow systems
5. Document any new requirements or dependencies

### License

See [LICENSE](../../LICENSE) for details.
