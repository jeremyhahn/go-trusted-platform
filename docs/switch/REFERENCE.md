# Switch Management Reference

Quick reference guide for the switch management system.

## File Organization

```
docs/switch/
├── README.md                    # Overview & quick start
├── architecture.md              # System design & components
├── configuration.md             # YAML config guide
├── api-reference.md             # REST, gRPC, Go APIs
├── provisioning-workflow.md     # Complete provisioning flow
├── adding-vendors.md            # How to add new vendors
└── REFERENCE.md                 # This file
```

## Key Interfaces

### Manager Interface (Runtime Operations)

```go
type Manager interface {
    SetPortVLAN(ctx context.Context, port string, vlanID uint16) error
    GetPortVLAN(ctx context.Context, port string) (uint16, error)
    GetPortStatus(ctx context.Context, port string) (*switchwire.PortStatus, error)
    ListPorts(ctx context.Context) ([]*switchwire.PortStatus, error)
    EnablePort(ctx context.Context, port string) error
    DisablePort(ctx context.Context, port string) error
    Close() error
}
```

### Service Layer

```go
type Service struct {
    // Unexported
}

func NewService(configs []Config, logger *slog.Logger) (*Service, error)
func (s *Service) Manager(name string) (Manager, error)
func (s *Service) Close() error
```

## Configuration Schema

```yaml
switches:
  - name: string                          # Required: switch identifier
    vendor: cisco-nexus | noop            # Required: switch platform
    host: string                          # Required: IP or hostname
    port: int                             # Optional: SSH port (default: 22)
    user: string                          # Required: SSH username
    password: string                      # Conditional: SSH password or kms://ref
    ssh_key: string                       # Conditional: path to SSH private key
    vlans:
      - id: int                           # Required: VLAN ID (1-4094)
        name: string                      # Required: VLAN name
        subnet: string                    # Optional: IP subnet (informational)
        description: string               # Optional: VLAN description
    ports:
      - port: string                      # Required: port identifier(s)
        mode: access | trunk              # Required: switchport mode
        vlans: [int]                      # For trunk: allowed VLANs
        access_vlan: int                  # For access: VLAN ID
        native_vlan: int                  # For trunk: native VLAN (must be in vlans)
        mtu: int                          # Optional: 1500-9216 (0 = leave as is)
        description: string               # Optional: port description
```

## Error Types

### Connection Errors
- `ErrSSHConnectionFailed{Host, Cause}`
- `ErrSwitchConnectionFailed{Host, Cause}`

### Operation Errors
- `ErrPortVLANSetFailed{Port, VLANID, Cause}`
- `ErrPortNotFound{Port}`
- `ErrVLANNotFound{VLANID}`

### Parsing Errors
- `ErrSSHParseOutputFailed{Command, Output, Reason}`
- `ErrSSHCommandFailed{Command, Output, Cause}`

### Configuration Errors
- `ErrInvalidConfig{Field, Reason}`
- `ErrInvalidPortRange{Port, Reason}`
- `ErrNilConfig{}`
- `ErrUnsupportedVendor{Vendor}`

### Service Errors
- `ErrManagerNotFound{Name}`

## Common Operations

### Move Port to VLAN

```go
mgr, _ := service.Manager("core-switch")
mgr.SetPortVLAN(ctx, "Eth1/3", 200)
```

### Get Port Status

```go
status, _ := mgr.GetPortStatus(ctx, "Eth1/3")
println(status.LinkUp, status.AccessVLAN, status.Enabled)
```

### List All Ports

```go
ports, _ := mgr.ListPorts(ctx)
for _, p := range ports {
    println(p.Port, p.Enabled, p.LinkUp)
}
```

### Enable/Disable Port

```go
mgr.DisablePort(ctx, "Eth1/4")
mgr.EnablePort(ctx, "Eth1/4")
```

## Platform Integration Points

### Daemon Initialization
- File: `pkg/daemon/commands/serve.go`
- Location: Lines 513-525
- Creates switch service if `App.SwitchConfigs` is not empty

### Device Activation Handler
- File: `pkg/webservice/v1/device/handler.go`
- Method: `transitionSwitchPort()`
- Moves port to production VLAN during device activation

### Configuration Loading
- File: `pkg/app/app.go`
- Field: `SwitchConfigs []switchmgmt.Config`
- Loaded from YAML `switches:` section

## Vendor Support Matrix

| Vendor | Status | Port Format | Notes |
|--------|--------|-------------|-------|
| Cisco NX-OS | Production | `Eth1/1` | SSH CLI |
| Cisco IOS/IOS-XE | Planned | `Gi1/0/1` | Same SSH CLI |
| Arista EOS | Planned | `Ethernet1` | Compatible CLI |
| Juniper | Planned | `ge-0/0/0` | Requires NETCONF |
| Mellanox | Planned | TBD | Custom API |
| Testing | Available | N/A | `noop` vendor |

## Startup Behavior

1. Daemon loads config file
2. Platform parses `switches:` section into `App.SwitchConfigs`
3. If configs not empty:
   - Create Service with all switches
   - Service creates one Manager per Config
   - Managers are lazy-initialized (SSH not connected yet)
4. If no configs:
   - Switch Service is not created
   - Device activation skips VLAN transition (no-op)
5. On daemon shutdown:
   - Call `Service.Close()` to close all Managers

## Testing

### Unit Tests
- Location: `pkg/switch/*_test.go`
- Mocked SSHExecutor
- No real switch required

### Integration Tests
- Location: `test/integration/switch/` (planned)
- Real switch or simulator (OVS in devcontainer)
- Full workflow testing

### Manual Testing
```bash
# Start daemon with switch config
platformctl serve --config platform.yaml

# Register device and activate
curl -X POST https://localhost:8443/device/register -d '{...}'
curl -X POST https://localhost:8443/device/activate --cert device.crt --key device.key

# Verify port moved to production VLAN
ssh admin@switch "show interfaces Eth1/3 switchport"
```

## Performance Characteristics

- **SSH Connection**: Lazy-created on first use, reused for all operations
- **Command Execution**: ~200-500ms per command (network dependent)
- **Output Parsing**: <5ms (regex-based, no external parsers)
- **Error Recovery**: Automatic retry not implemented (caller responsibility)
- **Concurrency**: Not thread-safe (one connection per Manager)

## Security Notes

- SSH keys preferred over passwords
- Passwords can use `kms://` secret references
- No credential logging (except in debug mode)
- SSH output not logged (may contain sensitive data)
- Command injection prevention: Input validation on port names and VLAN IDs

## Troubleshooting Flowchart

```
Switch operation failed?
├─ Network error?
│  ├─ Yes: Ping switch, check SSH access
│  └─ No: Continue
├─ Authentication error?
│  ├─ Yes: Verify SSH key/password
│  └─ No: Continue
├─ Port/VLAN not found?
│  ├─ Yes: Check port naming, create VLAN
│  └─ No: Continue
├─ Command output parsing failed?
│  ├─ Yes: Check vendor format, update regex
│  └─ No: Continue
└─ Unknown error?
   └─ Check logs: daemon error level with full context
```

## Design Principles

1. **Interface-based**: Manager interface allows multiple implementations
2. **Factory pattern**: Vendor dispatch via registered factories
3. **Service layer**: Clean separation between API and implementation
4. **Lazy initialization**: Minimize resource usage and startup time
5. **Error handling**: Typed errors for precise error handling
6. **Logging**: Structured logging for debugging
7. **Testing**: Mockable interfaces for unit testing
8. **SSH-centric**: Use SSH CLI for broad vendor support

## Future Enhancements

- [ ] Multi-vendor NETCONF support (for vendors that support it)
- [ ] Batch operations (move multiple ports in one call)
- [ ] Connection pooling (reuse SSH connection across Managers)
- [ ] CLI commands (`platformctl switch`)
- [ ] gRPC service exposure
- [ ] QUIC protocol support
- [ ] MCP tool exposure
- [ ] Port autodiscovery (MAC table lookup)
- [ ] Configuration verification step (verify VLAN after move)
- [ ] Audit logging (who made what change and when)

## Related Documentation

- [PXE Bootstrap Architecture](../bootstrap/README.md)
- [Device Lifecycle](../device/README.md)
- [SDN Policy Engine](../sdn/README.md)
- [REST API](../webservice/README.md)

## Support & Reporting Issues

When reporting switch management issues:

1. Include switch model and OS version
2. Include error message and stack trace
3. Include platform config (sanitized passwords)
4. Include daemon logs (debug level)
5. Describe the operation that failed (SetPortVLAN, GetPortStatus, etc.)

Example:
```
Title: SetPortVLAN fails with Cisco NX-OS 10.2.5
Description: Moving port Eth1/3 to VLAN 200 returns "command failed"
Error: switchmgmt: failed to set port Eth1/3 to vlan 200: 
       ssh command failed "switchport access vlan 200" (output: % Invalid VLAN number)
Details: VLAN 200 exists on switch (verified with "show vlan brief")
Config: cisco-nexus vendor with SSH key auth to 10.0.1.50
```

## License

Same as go-trusted-platform: AGPL-3.0 or Commercial
