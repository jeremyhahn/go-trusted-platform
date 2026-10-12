# SDN Documentation Index

Complete documentation for the Software-Defined Networking (SDN) components in go-trusted-platform.

## Quick Navigation

### By Component

| Component | Purpose | Documentation |
|-----------|---------|-----------------|
| **Physical Fabric** | Unified switch management (VLAN/EVPN) | [fabric/README.md](./fabric/README.md) |
| **Stateful Firewall** | Zone-based packet filtering + NAT | [firewall/README.md](./firewall/README.md) |
| **Gateway Node** | Multi-service overlay, edge, transit node | [gateway/README.md](./gateway/README.md) |
| **BGP** | Border Gateway Protocol for route announcement | [bgp/README.md](./bgp/README.md) |
| **DHCP** | Dynamic IP allocation | [dhcp/README.md](./dhcp/README.md) |
| **IPAM** | IP address pool management | [ipam/README.md](./ipam/README.md) |
| **Tunnels** | GRE/IPIP tunnel lifecycle | [tunnel/README.md](./tunnel/README.md) |
| **Overlay** | VXLAN-based overlay networking | [overlay/README.md](./overlay/README.md) |

### By Use Case

#### Network Provisioning
1. Read [fabric/README.md](./fabric/README.md) — Understand fabric architecture
2. Configure switches in [fabric/configuration.md](./fabric/configuration.md)
3. Review port lifecycle in [fabric/api-reference.md](./fabric/api-reference.md)

#### Device PXE Provisioning
1. Review provisioning flow in [provisioning.md](./provisioning.md)
2. Understand VLAN transitions in [fabric/README.md](./fabric/README.md) (PXE Provisioning Workflow)
3. Check provisioning segment config in [fabric/configuration.md](./fabric/configuration.md)

#### Firewall and Security
1. Start with [firewall/README.md](./firewall/README.md) for concepts
2. Configure zones and rules in [firewall/configuration.md](./firewall/configuration.md)
3. Understand packet pipeline in [firewall/architecture.md](./firewall/architecture.md)
4. Tune for performance in [firewall/performance.md](./firewall/performance.md)

#### Multi-Tenant Overlay Networking
1. Review [overlay/README.md](./overlay/README.md) for VXLAN concepts
2. Configure segments in [overlay/configuration.md](./overlay/configuration.md)
3. Check API integration in [overlay/api-reference.md](./overlay/api-reference.md)

#### BGP Route Announcement
1. Start with [bgp/README.md](./bgp/README.md)
2. Configure BGP in [bgp/configuration.md](./bgp/configuration.md)
3. Understand EVPN in [bgp/evpn.md](./bgp/evpn.md)

#### Gateway Node Operations
The gateway is its own feature: start with
[docs/gateway/architecture.md](../gateway/architecture.md), then
[user.md](../gateway/user.md) to configure its service sections.

## Complete Documentation Map

### Fabric Management

```
fabric/
├── README.md              # Overview, VLAN vs EVPN, quick start
├── configuration.md       # FabricConfig schema, 3 complete examples
├── api-reference.md       # Driver/Manager interfaces, types, usage patterns
└── adding-drivers.md      # Guide for implementing vendor drivers
```

**When to use:**
- Configuring physical switches
- Managing VLAN or EVPN segments
- Implementing port lifecycle (provision/activate/quarantine)
- Adding support for new switch vendors

### Firewall Engine

```
firewall/
├── README.md              # Features, zones, rules, connection states
├── configuration.md       # Zone/rule/NAT config schema
├── architecture.md        # Packet pipeline, conntrack, design
└── performance.md         # Benchmarks, tuning guide
```

**When to use:**
- Configuring firewall zones and policies
- Creating packet filtering rules
- Setting up SNAT/DNAT rules
- Tuning for high throughput
- Understanding connection tracking

### Gateway Node

Documented in the [docs/gateway/](../gateway/) feature folder
(architecture, engineering, cli, api, user); `gateway/README.md` here is only
a pointer to it.

### BGP Routing

```
bgp/
├── README.md              # BGP overview, concepts
├── configuration.md       # BGP config schema
├── architecture.md        # Implementation design
├── evpn.md               # EVPN overlay mode
├── transit.md            # BGP transit design
├── troubleshooting.md     # Common issues
├── cli-usage.md          # CLI commands
└── api-reference*.md     # REST, gRPC, QUIC, MCP API
```

**When to use:**
- Configuring BGP neighbors
- Setting up EVPN overlay
- Announcing prefixes
- Troubleshooting BGP issues

### DHCP Service

```
dhcp/
├── README.md              # DHCP overview
├── configuration.md       # DHCP pools, options
├── architecture.md        # Packet handling
├── plugins.md            # Plugin extensions
├── cli-usage.md          # CLI commands
└── api-reference*.md     # REST, gRPC, QUIC, MCP API
```

**When to use:**
- Configuring DHCP pools per segment
- Setting DHCP options (DNS, gateway, etc)
- Extending DHCP with plugins
- Querying lease information

### IPAM Service

```
ipam/
├── README.md              # IPAM overview
├── configuration.md       # IP pool configuration
├── architecture.md        # Allocation algorithms
└── api-reference*.md     # REST, gRPC, QUIC, MCP API
```

**When to use:**
- Managing IP address pools
- Reserving/allocating addresses
- Tracking address usage

### Tunnel Management

```
tunnel/
├── README.md              # GRE/IPIP tunnel overview
└── configuration.md       # TunnelConfig schema
```

**When to use:**
- Creating GRE tunnels to VPS nodes
- Configuring IPv6 tunnels
- Setting up BGP peer transport

### Overlay Networking

```
overlay/
├── README.md              # VXLAN overlay overview
├── configuration.md       # Segment/VTEP configuration
├── architecture.md        # VNI mapping, EVPN integration
├── operations.md          # Runtime operations
└── api-reference*.md     # REST, gRPC, QUIC, MCP API
```

**When to use:**
- Configuring overlay segments
- Setting VNI mappings
- EVPN with VXLAN underlays
- Multi-tenant isolation

## Configuration Examples

### Minimal Firewall

```yaml
gateway:
  firewall:
    enabled: true
    default-policy: deny   # verdict for connections no zone-matrix rule matched
  nat:
    enabled: true
    external-ip: 203.0.113.10
    port-range-start: 1024
    port-range-end: 65535
    max-sessions: 65536
    internal-cidr: 10.0.100.0/24
```

Inter-zone policy is not configured on the firewall — it is derived from
the zone declarations and their compiled allow/deny matrix.

See: [firewall/configuration.md](./firewall/configuration.md)

### Minimal Fabric

```yaml
sdn:
  environment:
    id: 4                       # every VLAN and subnet derives from this
  fabric:
    switches:
      - id: switch-01
        vendor: cisco-nexus
        mgmt-ip: 192.0.2.250
    ports:
      - {switch-id: switch-01, port: Ethernet1/25, class: hypervisor}
```

See: [fabric/configuration.md](./fabric/configuration.md)

### Minimal Gateway

```yaml
sdn:
  gateway:
    enabled: true
    node-id: gw-01
    
    overlay:
      enabled: true
      vtep-ip: 10.0.0.1
    
    firewall:
      enabled: true
      # ... firewall config
```

See: [gateway/user.md — Configuring the daemon](../gateway/user.md#configuring-the-daemon)

## API References

Each service exposes APIs via multiple protocols:

| Service | REST | gRPC | QUIC | MCP | Unix |
|---------|------|------|------|-----|------|
| Fabric | [ref](./fabric/api-reference.md) | N/A | N/A | N/A | N/A |
| Firewall | No | No | No | No | No |
| Gateway | [ref](../gateway/api.md) | [ref](../gateway/api.md) | [ref](../gateway/api.md) | [ref](../gateway/api.md) | [ref](../gateway/api.md#1-the-six-transports) |
| BGP | [ref](./bgp/api-reference-rest.md) | [ref](./bgp/api-reference-grpc.md) | [ref](./bgp/api-reference-quic.md) | [ref](./bgp/api-reference-mcp.md) | [ref](./bgp/api-reference-unix.md) |
| DHCP | No | No | No | No | No |
| IPAM | [ref](./ipam/api-reference-rest.md) | [ref](./ipam/api-reference-grpc.md) | [ref](./ipam/api-reference-quic.md) | [ref](./ipam/api-reference-mcp.md) | [ref](./ipam/api-reference-unix.md) |

## CLI Tools

Platform SDN is controlled via CLI:

```bash
# Gateway node status and modes
platformctl sdn gateway status
platformctl sdn gateway mode set --modes overlay,edge,transit

# Query BGP status and peers
platformctl sdn gateway bgp status
platformctl sdn gateway bgp peers

# Check IPAM pools and allocations
platformctl sdn ipam pool list
platformctl sdn ipam allocations

# Manage network policies (firewall policy type)
platformctl sdn policy list
platformctl sdn policy apply --type firewall [options]
```

DHCP has no CLI command group; the DHCP server is configured via the
`sdn.dhcp` YAML section (see [dhcp/configuration.md](./dhcp/configuration.md)).

See: [cli-usage.md](./cli-usage.md) for full command reference

## Architecture Overviews

### System Architecture

See: [architecture.md](./architecture.md)

```
Platform Daemon
├── Gateway (overlay, edge, transit)
├── Firewall (zone-based, stateful)
├── BGP (route announcement)
├── DHCP (address allocation)
├── Tunnel (GRE/IPIP)
├── Fabric (physical switches)
└── Overlay (VXLAN multi-tenant)
```

### Packet Flow

See: [firewall/architecture.md](./firewall/architecture.md)

```
Packet → ConnTrack → Zone Resolver → NAT → Rules → Verdict
```

## Troubleshooting

| Issue | Component | Solution |
|-------|-----------|----------|
| VLAN not created on switch | [Fabric](./fabric/README.md) | Check driver, vendor config, credentials |
| Packets dropped unexpectedly | [Firewall](./firewall/README.md) | Review rules, check zones, verify rules order |
| BGP neighbors not coming up | [BGP](./bgp/troubleshooting.md) | Check tunnel configs, verify ASN, test reachability |
| Devices not getting DHCP | [DHCP](./dhcp/architecture.md) | Verify pool config, check zone reachability |
| Overlay segments isolated | [Overlay](./overlay/architecture.md) | Check VNI mapping, EVPN state |

See: [user.md — Troubleshooting](./user.md#troubleshooting), and for the gateway
[gateway/user.md — Troubleshooting](../gateway/user.md#troubleshooting)

## Testing

### Unit Tests

```bash
make test                          # All tests
make test-sdn-fabric              # Fabric tests
make test-sdn-gateway             # Gateway tests
```

### Integration Tests

```bash
make integration-test              # All integration tests
make integration-test-sdn-gateway  # Gateway integration
```

See: [testing.md](./testing.md) for comprehensive testing guide

## Performance

- **Firewall**: stateful zone filtering in the OVS kernel datapath via conntrack (`ct()`/`ct_state`) flows; no userspace packet path (no published benchmarks yet) — See [firewall/performance.md](./firewall/performance.md)
- **Hardware offload**: OVS tc-flower offload for 100/200/400G NICs — ConnectX/BlueField (mlx5 switchdev) and Broadcom NetXtreme-E (bnxt TruFlow) — See [performance/hw-offload.md](./performance/hw-offload.md)
- **Lab validation runbook**: X10 hardware-offload/400G validation procedure with `platformctl sdn gateway perf` measurement steps and a measured-values-only results template — See [performance/x10-lab-validation.md](./performance/x10-lab-validation.md)
- **BGP**: native Go BGP speaker for EVPN and transit route propagation — See [bgp/architecture.md](./bgp/architecture.md)
- **DHCP**: native Go DHCP server with IPAM-backed lease allocation — See [dhcp/architecture.md](./dhcp/architecture.md)

## Security

### Secrets in Configuration

See: [secrets/config-secret-schemes.md](../secrets/config-secret-schemes.md)

- `kms://` — QuicBaaS KMS-managed secrets (canonical; generate-on-first-boot)
- `idevid://` — Node IDevID key (RSA-OAEP) for per-node secrets
- `file://` — Raw bytes from a local file (airgap/dev escape hatch, opt-in)

### mTLS

All services support mutual TLS for inter-node communication.

## Related Documentation

- [Configuration Guide](../daemon/configuration.md#configuration-structure) — Top-level config structure
- [Security Architecture](../security/architecture.md) — Overall security design
- [Secrets Framework](../secrets/README.md) — Secret management
- [Bootstrap Process](../bootstrap/README.md) — Node initialization
- [TPM/Device Identity](../tpm/device-identity-design.md) — IDevID design

## Contributing

To update SDN documentation:

1. Edit relevant `.md` file in `docs/sdn/{component}/`
2. Keep examples current with code
3. Update cross-references in this INDEX.md
4. Test configuration examples
5. Run spell-check: `make check-docs`

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-04-13 | Initial comprehensive SDN documentation (Phase 7) |

---

**Last Updated**: 2026-04-13
**Documentation Version**: 1.0
**Status**: Production-ready
