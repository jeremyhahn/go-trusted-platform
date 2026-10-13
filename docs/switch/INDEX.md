# Switch Management Documentation Index

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md), [engineering.md](engineering.md), [cli.md](cli.md), [api.md](api.md) and [user.md](user.md). The CLI and gRPC surfaces ship today; the runtime switch service is not wired into the daemon; `kms://` passwords are not resolved; password auth is not implemented.

Complete documentation for the physical switch management feature in go-trusted-platform.

## Documentation Map

### Getting Started
- **[README.md](README.md)** - Overview, architecture diagram, use cases, quick start
  - What the feature does
  - How it fits into provisioning
  - Supported vendors (Cisco, Arista, Juniper, etc.)
  - Quick configuration example

### Architecture & Design
- **[architecture.md](architecture.md)** - System design, packages, data flow, error handling
  - Package organization
  - Manager interface and Service layer
  - SSH Manager implementation
  - Factory pattern for vendor dispatch
  - Configuration types
  - Data flow during device activation
  - Error handling strategy
  - Dependencies
  - Testing strategy
  - Extension points for new vendors
  - Performance considerations
  - Open design questions

### Configuration
- **[configuration.md](configuration.md)** - Complete YAML configuration guide
  - Configuration structure and all fields
  - SSH key and password authentication
  - Encrypted password references
  - Multiple switch examples
  - Port naming conventions
  - Validation rules
  - Startup behavior
  - Troubleshooting common issues
  - Security best practices
  - Performance tuning

### APIs
- **[api-reference.md](api-reference.md)** - REST, Go, gRPC, planned CLI APIs
  - Device activation REST endpoint (POST /device/activate)
  - Manager interface for Go usage
  - Service layer API
  - Data types (PortStatus, Config, VLANConfig)
  - Complete error reference with examples
  - Go usage patterns and examples
  - Planned gRPC and CLI commands
  - Backwards compatibility notes

### Provisioning Workflow
- **[provisioning-workflow.md](provisioning-workflow.md)** - Complete end-to-end workflow
  - Phases: Registration, Provisioning, Activation
  - Detailed sequence diagrams
  - Step-by-step explanations
  - VLAN state transitions
  - Failure scenarios and recovery
  - Workflow customization
  - Monitoring and logging
  - Manual testing procedures
  - Timeline and ASCII diagrams

### Adding Vendors
- **[adding-vendors.md](adding-vendors.md)** - Step-by-step guide to add new vendors
  - 8-step process from creation to testing
  - Full code examples (Arista EOS)
  - Output parsing patterns
  - Unit test examples
  - Integration test setup
  - Documentation checklist
  - Common vendor differences
  - Fallback strategies
  - Troubleshooting

### Reference
- **[REFERENCE.md](REFERENCE.md)** - Quick lookup reference
  - File organization
  - Key interfaces and types
  - Configuration schema
  - Error types
  - Common operations with code examples
  - Platform integration points
  - Vendor support matrix
  - Startup behavior
  - Testing matrix
  - Performance characteristics
  - Security notes
  - Troubleshooting flowchart
  - Design principles
  - Future enhancements

## Quick Navigation by Role

### For Platform Users/Operators
1. Start with [README.md](README.md) - Understanding the feature
2. Read [configuration.md](configuration.md) - How to configure switches
3. Review [provisioning-workflow.md](provisioning-workflow.md) - How provisioning works
4. Check [REFERENCE.md](REFERENCE.md) - Quick troubleshooting

### For Go Developers
1. Read [architecture.md](architecture.md) - System design
2. Study [api-reference.md](api-reference.md) - Go APIs and patterns
3. Review `pkg/switch/*.go` source code
4. Check [REFERENCE.md](REFERENCE.md) - Error types and operations

### For Adding New Vendors
1. Read [architecture.md](architecture.md) - Manager interface
2. Follow [adding-vendors.md](adding-vendors.md) - Step-by-step guide
3. Review existing implementation: `pkg/switch/ssh_manager.go`
4. Test with `pkg/switch/*_test.go` examples

### For REST API Integration
1. Read [api-reference.md](api-reference.md) - REST endpoints
2. Review `pkg/webservice/v1/device/handler.go` - Device handler integration
3. Check [provisioning-workflow.md](provisioning-workflow.md) - When VLAN transition happens

### For DevOps/Infrastructure
1. Read [README.md](README.md) - High-level overview
2. Study [configuration.md](configuration.md) - Switch configuration
3. Review [provisioning-workflow.md](provisioning-workflow.md) - Provisioning flow
4. Monitor logs/errors - See [REFERENCE.md](REFERENCE.md) troubleshooting

## Key Concepts Quick Reference

### Manager
Interface for runtime port operations on a single switch. Implemented by vendors (SSH-based for Cisco, etc.).

### Service
Registry of Managers, one per configured switch. Provides Manager lookup by switch name.

### Config
Switch connection details (host, port, credentials) plus initial setup (VLANs, ports).

### PortStatus
Observable state of a port: mode (access/trunk), VLAN membership, enabled/disabled, link up/down.

### Factory Pattern
Used to dispatch Manager creation by vendor. New vendors register their factory in `managerRegistry`.

### Lazy SSH Connection
SSH connection created on first Manager method call, reused for all subsequent calls, closed on Manager.Close().

## Implementation Status

| Feature | Status | Location |
|---------|--------|----------|
| Cisco NX-OS/IOS-XE support | Production | `pkg/switch/ssh_manager.go` |
| Service layer | Production | `pkg/switch/service.go` |
| Device activation integration | Production | `pkg/webservice/v1/device/handler.go` |
| Error types | Production | `pkg/switch/errors.go` |
| No-op testing support | Production | `pkg/switch/noop_manager.go` |
| Arista EOS | Planned | - |
| Juniper NETCONF | Planned | - |
| gRPC API | Planned | - |
| CLI commands | Planned | - |
| Port autodiscovery | Planned | - |

## File Locations

### Documentation
- All markdown files: `docs/switch/`

### Source Code
- Core package: `pkg/switch/`
- Device handler: `pkg/webservice/v1/device/handler.go`
- Configuration: `pkg/app/app.go`
- Daemon integration: `pkg/daemon/commands/serve.go`

### Tests
- Unit tests: `pkg/switch/*_test.go`
- Integration tests: `test/integration/switch/` (planned)

## Common Questions

**Q: Do I need a physical switch?**
A: No. Use the `noop` vendor for testing, or omit the `switches:` section entirely.

**Q: How are passwords kept secure?**
A: Use SSH keys when possible. For passwords, use `kms://secretname` references to platform secrets.

**Q: Can I use non-Cisco switches?**
A: Yes, if they support SSH CLI similar to Cisco IOS. For others (Juniper, etc.), implement a new vendor (see [adding-vendors.md](adding-vendors.md)).

**Q: How do I troubleshoot connection issues?**
A: Check [configuration.md](configuration.md) troubleshooting section, verify SSH access manually, enable debug logging.

**Q: Can I move multiple ports at once?**
A: Currently, one SetPortVLAN per request. Batch operations are a planned enhancement.

**Q: What happens if switch is down?**
A: Device activation returns HTTP 500. Device stays on provisioning VLAN. Operator fixes switch and device retries.

**Q: Can I autodetect which port a device is on?**
A: Not yet. Current design requires switch/port to be pre-configured per device. Port autodiscovery is planned.

## Next Steps

1. **Configure**: Add `switches:` section to your platform config (see [configuration.md](configuration.md))
2. **Test**: Verify with `noop` vendor first, then real switch
3. **Monitor**: Watch daemon logs during device provisioning
4. **Extend**: Add new vendors if needed (see [adding-vendors.md](adding-vendors.md))

## Support & Feedback

For questions, issues, or contributions:
1. Check [REFERENCE.md](REFERENCE.md) troubleshooting flowchart
2. Review relevant documentation section
3. Check source code comments
4. Report issues with error types, switch model, and logs

---

**Documentation Version**: 1.0  
**Last Updated**: 2025-04-13  
**Status**: Complete for Cisco NX-OS production use  
**Audience**: Operators, Go developers, DevOps engineers, architecture reviewers
