# VXLAN Overlay Configuration Reference

## Overview

This document is the reference for configuring the VXLAN overlay
subsystem: the platform YAML surface, runtime-derived settings, and the
Go configuration API.

## Platform Configuration (YAML)

The `sdn.overlay` YAML section is intentionally small; most overlay
settings are derived at runtime (see below).

```yaml
sdn:
  enabled: true

  # OVS connection (shared by all SDN components)
  ovs:
    socket: "/var/run/openvswitch/db.sock"
    bridge: "br-int"
    datapath: "system"

  overlay:
    enabled: true
    vxlan-port: 4789
    underlay-interface: "eth0"
```

### Overlay Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| enabled | bool | false | Enable overlay networking |
| vxlan-port | uint16 | 4789 | UDP port for VXLAN encapsulation |
| underlay-interface | string | "lo" | Physical interface for VXLAN underlay traffic. The loopback default suits single-node and test environments; production deployments should set the uplink interface (e.g., `eth0`, `bond0`) |

### Overlay IPsec (`sdn.overlay.ipsec`)

Host-to-host IPsec between VTEPs, driven through charon over VICI
(`pkg/sdn/ipsec`; design in [architecture.md](architecture.md#overlay-ipsec)).
`sdn.Config.Validate` checks the section; a disabled or absent section is
not checked.

```yaml
sdn:
  overlay:
    enabled: true
    ipsec:
      enabled: true
      fabric-interface: bond0
      local-address: 10.20.0.11
      static-peers: [10.20.0.1, 10.20.0.2]   # route reflectors, gateways
      certificate-file: /etc/platform/ipsec/tunnel.pem   # leaf, then its CA chain
      token:
        slot: 0
        handle: "6970736563"                  # CKA_ID of the IKE key, hex
        pin-file: /etc/platform/ipsec/token.pin
```

| Parameter | Type | Default | Rule |
|-----------|------|---------|------|
| enabled | bool | false | With it on, the fabric interface carries only IKE, ESP, SA-protected traffic and the link ICMPv6 -- received, sent or routed through the node |
| fabric-interface | string | — | Required; a Linux interface name (1–15 characters) |
| local-address | string | — | Required; this VTEP's unicast address, the IKE endpoint and certificate identity |
| static-peers | []string | none | Explicit per-peer connections (route reflectors, gateways); single unicast addresses of the local address's family, no duplicates, never the local address. There is no wildcard peer |
| vici-socket | string | `/run/charon.vici` | Absolute path. platformd refuses the socket unless it is mode 0600 and owned by platformd's user, and served by a process that listened as charon's uid |
| certificate-file | string | none | Absolute path; PEM tunnel certificate followed by its CA chain, read on every attach by `ipsec.FileIdentity`. Required when the identity comes from files |
| token.module | string | `xkms` | The name of the module under charon's `pkcs11 { modules { } }` in strongswan.conf, sent with `load-token`; letters, digits, `-` and `_`, at most 64. The shipped `pkcs11.conf` defines `xkms`, whose path is the p11-kit client that forwards to the node-local xkms token |
| token.slot | uint32 | 0 | Token slot holding the IKE key |
| token.handle | string | — | Required; the key's CKA_ID in hex |
| token.pin-file | string | none | Absolute path; its first line is the token PIN, read once into a memguard enclave. Without it `load-token` sends no PIN |
| cp-outage-tolerance | duration | 24h | Control-plane outage the overlay rides through on the certificate it holds. The CRLs pushed to charon must also outlast it: under `revocation=strict` an expired CRL fails IKE, so issue them with `nextUpdate` further out than this |
| cert-lifetime | duration | 3 × cp-outage-tolerance | At least 3 × cp-outage-tolerance. IKE reauthentication runs at half of it |
| replay-window | uint32 | 1024 | At least 1024 |
| ike-rate | uint32 | 20 | IKE packets per second per source address on UDP 500/4500 |
| ike-burst | uint32 | 2 × ike-rate | At least ike-rate |
| underlay-slaac | bool | false | Also pass ICMPv6 router solicitation and advertisement on an IPv6 fabric, for an underlay addressed by SLAAC. Neighbour discovery and MLD always pass; redirects never do |

A failure is an `*ipsec.ConfigError` naming the field
(`overlay.ipsec.static-peers[1]: ipsec: duplicate peer`) and wrapping one
of the `ipsec.Err*` sentinels.

ESP in transport mode adds up to 40 bytes to each encapsulated frame
(8-byte header, 8-byte IV, 16-byte ICV, padding and trailer), so an
IPsec-protected underlay needs an MTU of at least 9090. Platform switch
ports run 9216.

### Runtime-Derived Settings

The daemon fills in the remaining overlay controller settings when it
builds the configuration:

| Setting | Source | Default |
|---------|--------|---------|
| VTEP IP | Node public IPv4 | 127.0.0.1 when unset (test / loopback nodes) |
| Bridge name | Applied default | `br-int`, the workload integration bridge. Never `sdn.ovs.bridge` (`br-fabric`, which carries the physical trunk) |
| Underlay MTU | Applied default | 9216, the platform switch-port MTU (`netplan.MTU`) |
| Environment | `sdn.environment.id` | none: without an environment every VNI must be explicit |
| State backend | Applied default | `memory` (or `quicbaas` for cluster-shared state) |
| Health check interval | Applied default | 30s |
| MAC expiration | Applied default | 5m |

### Flow Programming

Flows are currently programmed one FlowMod per call; there is no flow
batching configuration. Batched OVS transactions are a planned
optimization.

## Go Configuration API

### Programmatic Configuration

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"

// Create overlay configuration
config := &overlay.Config{
    NodeID:            "node-001",
    VTEPIP:            netip.MustParseAddr("10.0.0.1"),
    UnderlayInterface: "eth0",
    UnderlayMTU:       9000,
    VXLANPort:         4789,
    Environment:       4,          // VNIs 400001-499999
    BridgeName:        "br-int",
    OVSSocketPath:     "/var/run/openvswitch/db.sock",
    StateBackend:      "memory",
    EnableEVPN:        true,
}
config.ApplyDefaults()

// Create the overlay controller
controller, err := overlay.New(config,
    overlay.WithLogger(logger),
    overlay.WithOVSClient(ovsClient),
    overlay.WithOpenFlowClient(ofClient),
)
if err != nil {
    return err
}

// Start the controller
if err := controller.Start(ctx); err != nil {
    return err
}
```

### Configuration Options

```go
// Available options
func WithLogger(logger *slog.Logger) Option
func WithOVSClient(client *ovs.Client) Option
func WithOpenFlowClient(client *openflow.Client) Option
func WithVTEPManager(manager *vxlan.VTEPManager) Option
func WithBGPSpeaker(speaker *bgp.Speaker) Option
func WithEVPNManager(manager *bgp.EVPNManager) Option
func WithGateway(gw *gateway.Gateway) Option
func WithIPAM(allocator ipam.Allocator) Option
func WithStateManager(state *StateManager) Option
```

### Config Fields

| Field | Type | Description |
|-------|------|-------------|
| NodeID | string | Unique identifier for this node (required) |
| VTEPIP | netip.Addr | This node's VTEP IP address (required) |
| UnderlayInterface | string | Physical interface for underlay traffic (required) |
| UnderlayMTU | int | Underlay MTU; must be >= 9050 (`vxlan.MinimumUnderlayMTU`) |
| VXLANPort | uint16 | UDP port for VXLAN (default 4789) |
| Environment | uint16 | Environment number E. A zero VNI in AddVNI is derived as E·100000+n with n the lowest free overlay network number (`netplan.VNI`); an explicit VNI must lie in E's block |
| BridgeName | string | OVS integration bridge for overlay traffic (`br-int`) |
| OVSSocketPath | string | Path to the OVSDB socket |
| BGPConfig | *bgp.BGPConfig | BGP service configuration |
| GatewayConfig | *gateway.GatewayConfig | Gateway node configuration |
| StateBackend | string | State storage: "memory" or "quicbaas" |
| HealthCheckInterval | time.Duration | Health check interval |
| MACExpiration | time.Duration | Expiration for learned remote MACs |
| EnableEVPN | bool | Enable EVPN MAC/IP advertisement and learning |

With `EnableEVPN` and an EVPN manager (`WithEVPNManager`), `AddVNI` with
`VNIConfig.AdvertiseIMET` joins the VNI's EVI, which originates its Type-3
route, and `RemoveVNI` leaves it again (see [../bgp/evpn.md](../bgp/evpn.md)).
A failed join is logged; the VNI is still added, with `IMETAdvertised` false.

## Multi-Host Deployment

Each host sets its own underlay interface; the VTEP IP is derived from
the node's public IPv4 address.

```yaml
# /etc/platformd/config.yaml on each host
sdn:
  enabled: true
  overlay:
    enabled: true
    underlay-interface: "eth0"
```

## MTU Planning

The overlay MTU is fixed at 9000 bytes (`vxlan.OverlayMTU`): workload
(VM) interfaces use 9000. VXLAN encapsulation adds 50 bytes, so the
underlay MTU must be at least 9050 (`vxlan.MinimumUnderlayMTU`); a
smaller one is refused at startup rather than fragmenting. Platform
switch ports run 9216.

### MTU Configuration Checklist

1. Configure physical switches for jumbo frames
2. Set underlay interface MTU on all hosts
3. Verify end-to-end MTU with ping

```bash
# Verify underlay MTU
ip link show eth0 | grep mtu

# Test the underlay carries an encapsulated 9000-byte frame
ping -M do -s 9022 10.0.0.2  # 9022 + 28 = 9050

# Test the VXLAN path at the overlay MTU
ping -M do -s 8972 <vm-on-remote-host>  # 8972 + 28 = 9000
```

## Validation

### Configuration Validation

```bash
# Show the effective SDN configuration section
platformctl config get sdn

# Check overlay status
platformctl sdn overlay status

# Verify VTEP registration
platformctl sdn overlay vtep list
```

### Startup Validation

`Config.Validate()` enforces these invariants when the controller
starts:

| Check | Description |
|-------|-------------|
| Node ID set | NodeID must be non-empty |
| VTEP IP valid | VTEPIP must be a valid, specified address |
| Underlay interface set | UnderlayInterface must be non-empty |
| Underlay MTU | MTU must be >= 9050 (the 9000-byte overlay MTU plus encapsulation) |
| VXLAN port | Port must be non-zero |
| Bridge name set | BridgeName must be non-empty |

## Troubleshooting Configuration

| Issue | Check | Fix |
|-------|-------|-----|
| VTEP not reachable | `ip addr show` | Ensure the node's public IPv4 is bound to the underlay interface |
| MTU too small | `ip link show eth0` | Raise the underlay interface MTU to >= 9050 |
| OVS not found | `ovs-vsctl show` | Install and start Open vSwitch; check `sdn.ovs.socket` |

## See Also

- [Architecture](architecture.md)
- [API Reference](api-reference.md)
- [SDN Configuration](../configuration.md)
