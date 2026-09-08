# SDN Configuration Reference

## Overview

This document provides a comprehensive reference for configuring the SDN subsystem,
including OVSDB client, OpenFlow client, policy engine, and network VLANs.

## OVSDB Client Configuration

### Client Options

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"

// Create client with options
client, err := ovs.NewClient(
    "/var/run/openvswitch/db.sock",
    ovs.WithDatabase("Open_vSwitch"),
    ovs.WithTimeout(30*time.Second),
    ovs.WithOpenFlowSocketDir("/var/run/openvswitch"),
)
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| socketPath | string | Required | Path to OVSDB Unix socket |
| database | string | "Open_vSwitch" | OVSDB database name |
| timeout | time.Duration | 30s | Operation timeout |
| ofSocketDir | string | "/var/run/openvswitch" | Directory for OpenFlow sockets |

### Socket Paths

| Socket | Purpose | Default Path |
|--------|---------|--------------|
| OVSDB | Database operations | /var/run/openvswitch/db.sock |
| OpenFlow | Flow management | /var/run/openvswitch/{bridge}.mgmt |

## OpenFlow Client Configuration

### Client Options

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"

// Create client with options
ofClient, err := openflow.NewClient(
    "br0",
    openflow.WithSocketDir("/var/run/openvswitch"),
    openflow.WithTimeout(30*time.Second),
)
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| bridgeName | string | Required | OVS bridge name |
| socketDir | string | "/var/run/openvswitch" | Directory for management sockets |
| timeout | time.Duration | 30s | Operation timeout |

## Policy Engine Configuration

### Engine Configuration

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"

config := policy.Config{
    // Required: OVS bridge name to manage
    BridgeName: "br0",

    // Required: Flow controller for OpenFlow operations
    FlowController: ovsClient,

    // Required: Port controller for VLAN/state operations
    // If nil, uses FlowController if it implements OVSPortController
    PortController: ovsClient,

    // Optional: Logger (uses slog.Default() if nil)
    Logger: slog.Default(),

    // Optional: Certificate policy extractor
    PolicyExtractor: policy.NewX509PolicyExtractor(),

    // Optional: Certificate validator
    CertificateValidator: certValidator,

    // Optional: Enable certificate lifecycle monitoring
    EnableMonitoring: true,

    // Optional: Monitor configuration
    MonitorConfig: policy.MonitorConfig{
        CheckInterval:    time.Hour,
        ExpiryThreshold:  7 * 24 * time.Hour, // 7 days
    },
}

engine, err := policy.NewEngine(config)
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| BridgeName | string | Required | OVS bridge to manage |
| FlowController | FlowController | Required | OpenFlow operations interface |
| PortController | OVSPortController | nil | OVSDB port operations interface |
| Logger | *slog.Logger | slog.Default() | Structured logger |
| PolicyExtractor | PolicyExtractor | X509PolicyExtractor | Certificate policy extraction |
| CertificateValidator | CertificateValidator | nil | Certificate validation |
| EnableMonitoring | bool | false | Enable certificate monitoring |
| MonitorConfig | MonitorConfig | - | Monitor settings |

### Monitor Configuration

```go
type MonitorConfig struct {
    // How often to check certificate expiry
    CheckInterval time.Duration

    // Threshold before expiry to trigger warning
    ExpiryThreshold time.Duration

    // Callback when certificate is about to expire
    OnExpirySoon func(portID string, expiresIn time.Duration)

    // Callback when certificate has expired
    OnExpired func(portID string)
}
```

## Bridge Configuration

### Creating a Bridge

```go
ctx := context.Background()

// Create bridge with default settings
bridge, err := client.CreateBridge(ctx, "br0")

// Create bridge with OpenFlow protocol
bridge, err := client.CreateBridgeWithProtocol(ctx, "br0", "OpenFlow13")
```

### Bridge Properties

| Property | Type | Description |
|----------|------|-------------|
| name | string | Unique bridge name |
| protocols | []string | Supported OpenFlow protocols |
| fail_mode | string | Behavior on controller disconnect ("secure", "standalone") |
| datapath_type | string | Datapath implementation ("system", "netdev") |

### Default Bridge Configuration

```yaml
bridge:
  name: "br0"
  protocols:
    - "OpenFlow13"
  fail_mode: "secure"
  datapath_type: "system"
```

## Port Configuration

### Adding a Port

```go
ctx := context.Background()

// Add port to bridge
port, err := client.AddPort(ctx, "br0", "eth0")

// Add port with VLAN tag
err = client.SetPortVLAN(ctx, "eth0", 100)

// Add port with trunk VLANs
err = client.SetPortTrunks(ctx, "eth0", []int64{100, 200, 300})
```

### Port Properties

| Property | Type | Description |
|----------|------|-------------|
| name | string | Unique port name |
| tag | int64 | Access VLAN tag (1-4094) |
| trunks | []int64 | Trunk VLAN list |
| vlan_mode | string | VLAN mode ("access", "trunk", "native-tagged") |

### Port State Management

```go
// Set port admin state
err = client.SetPortState(ctx, "eth0", ovs.PortStateUp)
err = client.SetPortState(ctx, "eth0", ovs.PortStateDown)

// Get OpenFlow port number
ofPort, err := client.GetOFPort(ctx, "eth0")
```

## Flow Rule Configuration

### Flow Priorities

| Priority | Use Case |
|----------|----------|
| 65535 | Controller rules (highest) |
| 1000-9999 | User ACL rules |
| 100-999 | System rules (DHCP, DNS, etc.) |
| 1-99 | Default rules |
| 0 | Table-miss (lowest) |

### Match Field Configuration

```go
flow := openflow.NewFlowMod(1000) // priority

// Layer 2 matches
flow.Match.SetInPort(1)
flow.Match.SetEthSrc("aa:bb:cc:dd:ee:ff")
flow.Match.SetEthDst("11:22:33:44:55:66")
flow.Match.SetEthType(0x0800) // IPv4

// VLAN matches
flow.Match.SetVLANVid(100)

// Layer 3 matches (requires EthType)
flow.Match.SetIPProto(6) // TCP
flow.Match.SetIPv4Src("192.168.1.0/24")
flow.Match.SetIPv4Dst("10.0.0.0/8")

// Layer 4 matches (requires IPProto)
flow.Match.SetTCPDst(443)
flow.Match.SetUDPDst(53)
```

### Action Configuration

```go
// Output to port
flow.AddOutputAction(2)

// Output to multiple ports
flow.AddOutputAction(2)
flow.AddOutputAction(3)

// VLAN operations
flow.AddSetVLANAction(100)
flow.AddPopVLANAction()

// Drop (no action = drop)
// flow with no actions drops packets

// Normal L2/L3 processing
flow.AddNormalAction()

// Go to another table
flow.AddGotoTableAction(1)
```

## Zone-Based Network Configuration

VLAN numbers are plain L2 segment identifiers. All network policy is derived
from the **zone** assigned to each network segment, not the VLAN number. See
[Reference Network Architecture](../architecture/reference-network.md) for
the authoritative zone taxonomy, VLAN defaults, and compliance control mapping.

### Default zone segments (reference-network.md defaults)

| Zone | Default VLAN | Default Subnet | Purpose |
|------|:------------:|----------------|---------|
| `trusted` | 200 | 198.18.0.0/24 | Enrolled, attested, internal workloads |
| `provisioning` | 201 | 172.16.201.0/24 | Device onboarding (DHCP/PXE/ACME) |
| `quarantine` | 202 | 172.16.202.0/24 | Non-compliant devices; isolated |
| `storage` | 203 | 172.16.203.0/24 | Attested storage tier |
| `tenant` | 1000+ | 172.17.0.0/16+ | Per-tenant micro-zones |
| `management` | 50 | (deployment OOB net) | IPMI/BMC; never routes to data zones |

All values are configurable. Declare subnets in `sdn.networks` with a `zone:`
field; the platform derives enforcement from the zone, not the VLAN number.

### Per-zone OpenFlow templates

The `pkg/sdn/policy/zoneflows` package generates per-zone OpenFlow rule sets.
Key rules (abbreviated; see package godoc for the complete rule set):

**provisioning zone** — least privilege; DHCP/DNS/TFTP/ACME only, default drop:

```
priority=1900, arp,       dl_vlan=201,                    actions=normal
priority=1850, udp,       dl_vlan=201, tp_src=68,tp_dst=67, actions=normal  # DHCP
priority=1800, udp,       dl_vlan=201, tp_dst=53,          actions=normal  # DNS
priority=1700, tcp,       dl_vlan=201, tp_dst=443,          actions=normal  # ACME
priority=900,             dl_vlan=201,                    actions=drop
```

**quarantine zone** — auth and remediation HTTPS only, default drop:

```
priority=1900, arp,       dl_vlan=202,                         actions=normal
priority=1850, udp,       dl_vlan=202, tp_src=68,tp_dst=67,    actions=normal  # DHCP
priority=1650, tcp,       dl_vlan=202, tp_dst=443,             actions=normal  # remediation
priority=1100,            dl_vlan=202,                         actions=drop
```

**trusted zone** — per-profile ACLs; base east-west allow:

```
priority=100, in_port=<port>, dl_vlan=200, actions=normal
```

### Profile zone configuration

Each device profile declares a target zone for post-enrollment network access.
The zone determines which VLAN the OVS port is tagged with and which OpenFlow
rules apply:

```yaml
# Device profile snippet
post_enrollment_network:
  zone: trusted       # zone name from sdn.zones / built-in zone taxonomy
  vlan: 200           # must match the network declared with zone: trusted
  acls:
    - priority: 1000
      match: {protocol: tcp, destination_port: 443}
      action: allow
    - priority: 1
      action: deny
```

## Environment Variables

Environment variables can override configuration for quick testing or container deployments:

| Variable | Default | Description |
|----------|---------|-------------|
| OVS_DB_SOCK | /var/run/openvswitch/db.sock | OVSDB socket path |
| OVS_RUNDIR | /var/run/openvswitch | OVS runtime directory |
| SDN_LOG_LEVEL | info | Logging level (debug, info, warn, error) |
| SDN_VLAN_DEFAULT | 1 | Default VLAN ID |
| SDN_VLAN_MANAGEMENT | 50 | Management VLAN ID (default; matches reference-network.md) |
| SDN_VLAN_QUARANTINE | 202 | Quarantine VLAN ID (default; matches reference-network.md) |
| SDN_VLAN_PROVISIONING | 201 | Provisioning VLAN ID (default; matches reference-network.md) |
| SDN_VLAN_STORAGE | 203 | Storage VLAN ID (default; matches reference-network.md) |
| SDN_VLAN_CLOUD_TENANT_BASE | 1000 | Base VLAN for cloud tenants |

## Platform Configuration (YAML)

All VLAN assignments are configurable. See [Reference Network Architecture](../architecture/reference-network.md) for the complete configuration schema.

### `networks:` — list form (current)

The `sdn.networks` field is a **list** of `NetworkConfig` entries. The former
map form (`networks: {name: {vlan: N, pool: P}}`) has been removed.

Each entry requires a `zone:` field that classifies the segment within the
platform's trust model. Built-in zone names are `trusted`, `public`,
`provisioning`, `quarantine`, `storage`, `tenant`, and `management`.

```yaml
sdn:
  enabled: true
  controller: true
  ovs:
    socket: /var/run/openvswitch/db.sock
    bridge: trusted0
    datapath: system
    protocols:
      - OpenFlow13
      - OpenFlow15
    # Optional hardware offload (tc-flower):
    # hw-offload: true
    # tc-policy: skip_sw
    # Optional DPDK userspace datapath (requires datapath: netdev):
    # dpdk:
    #   init: true
    #   socket-mem: "1024,1024"
    #   lcore-mask: "0x1"
    #   pmd-cpu-mask: "0x6"

  ipam:
    backend: quicbaas
    pools:
      - name: production
        cidr: 198.18.0.0/24
        gateway: 198.18.0.1
        dhcp: true
      - name: provisioning
        cidr: 172.16.201.0/24
        gateway: 172.16.201.1
        dhcp: true
      - name: quarantine
        cidr: 172.16.202.0/24
        gateway: 172.16.202.1
        dhcp: false
      - name: storage
        cidr: 172.16.203.0/24
        gateway: 172.16.203.1
        dhcp: true

  # networks is a list; every entry requires a zone: field.
  networks:
    - name: production
      vlan: 200
      zone: trusted        # must match a name in the resolved zone set
      pool: production     # optional: IPAM pool reference
      subnet: 198.18.0.0/24  # optional: must match pool CIDR if both set
      subnet6: 2602:f5bb:200::/64  # optional IPv6 prefix for a dual-stack segment (#554)
    - name: provisioning
      vlan: 201
      zone: provisioning
      pool: provisioning
    - name: quarantine
      vlan: 202
      zone: quarantine
      pool: quarantine
    - name: storage
      vlan: 203
      zone: storage
      pool: storage
```

### `ovs:` — datapath, hardware offload, and DPDK

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ovs.datapath` | string | `""` | Bridge `datapath_type`. Empty and `system` both select the default kernel datapath; `netdev` selects the userspace/DPDK datapath. Applied when the bridge is created and reconciled on startup when an existing bridge differs. |
| `ovs.hw-offload` | bool | `false` | Sets `other_config:hw-offload=true` on the global Open_vSwitch row, enabling tc-flower hardware flow offload. |
| `ovs.tc-policy` | string | `""` | Sets `other_config:tc-policy`. One of `none`, `skip_sw`, `skip_hw`. Requires `hw-offload: true`. |
| `ovs.dpdk.init` | bool | `false` | Sets `other_config:dpdk-init=true`, initializing DPDK in ovs-vswitchd. Requires `datapath: netdev`. |
| `ovs.dpdk.socket-mem` | string | `""` | `other_config:dpdk-socket-mem` — hugepage MB per NUMA socket, e.g. `"1024,1024"`. |
| `ovs.dpdk.lcore-mask` | string | `""` | `other_config:dpdk-lcore-mask` — CPU bitmask for DPDK lcore threads. |
| `ovs.dpdk.pmd-cpu-mask` | string | `""` | `other_config:pmd-cpu-mask` — CPU bitmask for poll-mode-driver threads. |
| `ovs.dpdk.n-rxq` | int | `0` | Receive queues for DPDK ports; applied per-interface (`options:n_rxq`) when DPDK ports are created. |
| `ovs.dpdk.extra` | map | `{}` | Additional `other_config` keys merged verbatim after the derived `dpdk-*` keys (extras win on conflict). |

Semantics:

- On startup platformd reconciles the global `other_config` before creating
  the bridge, writing only keys that are missing or different. Keys it does
  not own are never touched or deleted.
- **`hw-offload` and `dpdk-init` are read once by ovs-vswitchd at startup.**
  When platformd changes either value it logs a prominent warning: the
  operator must restart `ovs-vswitchd` for the change to take effect.
  platformd never restarts the daemon itself.
- Changing `ovs.datapath` for an existing bridge updates the bridge's
  `datapath_type` and logs a warning — ovs-vswitchd destroys and recreates
  the datapath, briefly interrupting forwarding on that bridge.
- Validation: `tc-policy` without `hw-offload: true` and a `dpdk:` block
  without `datapath: netdev` are configuration errors that fail startup.
- NIC/kernel requirements, the switchdev bring-up order, and what
  actually offloads: see [performance/hw-offload.md](./performance/hw-offload.md).

### `zones:` — optional zone overrides

The `sdn.zones` list allows operators to override built-in zone attributes or
add custom zones. When absent, all seven built-in zones are used unchanged.
A user entry whose `name` matches a built-in **fully replaces** that built-in.
Setting `omit: true` removes a built-in (requires another zone to cover any
lifecycle role the omitted zone held).

```yaml
sdn:
  # Override the public zone to tighten intra-zone isolation.
  zones:
    - name: public
      internet_ingress: true
      isolate: true
      allow_to:
        - zone: public   # intra-zone only
  networks:
    - name: dmz
      vlan: 210
      zone: public
```

Zone override semantics:

| User entry | Result |
|------------|--------|
| Name matches a built-in, `omit: false` | Built-in fully replaced by user entry |
| Name matches a built-in, `omit: true` | Built-in dropped from resolved set |
| Name does not match any built-in | Appended as a new custom zone |

Validation errors returned by `sdn.Config.Validate()`:

| Error | Cause |
|-------|-------|
| `ErrMissingNetworkZone` | A network entry has no `zone:` field |
| `ErrUnknownNetworkZone` | `zone:` references a name not in the resolved set |
| `ErrDuplicateNetworkName` | Two networks share the same `name:` |
| `ErrDuplicateNetworkVLAN` | Two networks share the same non-zero `vlan:` |
| `ErrInvalidNetworkVLAN` | `vlan:` is outside `[1, 4094]` |
| `ErrDuplicateNetworkSubnet` | Two networks declare identical non-zero `subnet:` or `subnet6:` |
| `ErrNetworkSubnet6NotIPv6` | `subnet6:` is set to something other than an IPv6 prefix |
| `ErrInvalidNetworkPool` | `pool:` references a name not in `ipam.pools` |
| `ErrSubnetPoolMismatch` | Both `subnet:` and `pool:` are set but their CIDRs differ |

## Systemd Configuration

### OVS Service Dependencies

```ini
[Unit]
Description=Trusted Platform SDN Controller
After=openvswitch-switch.service
Requires=openvswitch-switch.service

[Service]
Type=simple
ExecStart=/usr/bin/platformd sdn start
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Troubleshooting

### Verify OVS Connection

```bash
# Check OVSDB socket
ls -la /var/run/openvswitch/db.sock

# Verify OVS service
systemctl status openvswitch-switch

# Test OVSDB connection
ovs-vsctl show
```

### Verify OpenFlow Connection

```bash
# Check management socket
ls -la /var/run/openvswitch/br0.mgmt

# View flows
ovs-ofctl dump-flows br0

# View ports
ovs-ofctl show br0
```

### Debug Logging

```go
// Enable debug logging
logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelDebug,
}))

config := policy.Config{
    Logger: logger,
    // ...
}
```

## Identity Configuration

The `identity` block controls how device-identity certificates are issued by
the platform. It is optional; when absent the defaults below apply.

```yaml
sdn:
  identity:
    encode_zone_in_cert: false
    platform_zone: ""
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `encode_zone_in_cert` | bool | `false` | When `true`, IDevID issuance and ACME device-enrollment paths embed the network zone in the issued certificate using the `OIDTPNetworkZone` extension (`1.3.6.1.4.1.29377.101.21`). |
| `platform_zone` | string | `"management"` | The zone name embedded in the platform's own self-IDevID certificate when `encode_zone_in_cert` is `true`. Defaults to `"management"` when empty. |

### Zone-in-Certificate (Z3) Overview

When `encode_zone_in_cert: true`:

1. **Device enrollment (IDevID / ACME)** — the zone is taken from the device
   profile's `post-enrollment` `NetworkPhaseConfig.Zone`, falling back to
   `DeviceProfile.Zone`. If neither is set, issuance fails with a typed error
   (`ErrEncodeZoneEmpty`).

2. **Platform self-IDevID** — the zone is taken from `platform_zone` (default:
   `"management"`). If `platform_zone` is empty and encoding is enabled, the
   default `"management"` zone is used.

3. **Policy enforcement** — the `X509PolicyExtractor` reads the zone from the
   `OIDTPNetworkZone` extension via the quicbaas SDK re-export
   (`github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca`). A certificate
   carrying a zone that is not present in the resolved zone set triggers
   fail-closed quarantine: the port is placed in the quarantine zone and
   `ErrZoneNotDeclared` is returned for audit logging.

4. **Enrollment hook cross-check** — when a device activates via
   `ActivateDevice`, the `buildPortPolicy` function cross-checks the zone
   embedded in the issued certificate against the profile zone. A mismatch
   places the device in quarantine and returns `ErrZoneMismatch`. Certificates
   without a zone extension fall back to the profile zone (backward-compatible
   with pre-Z3 deployments).

### Example

Enable zone encoding with a custom management zone name:

```yaml
sdn:
  enabled: true
  identity:
    encode_zone_in_cert: true
    platform_zone: "management"
  zones:
    - name: management
      vlan: 10
      role: management
    - name: trusted
      vlan: 200
      role: trusted
    - name: provisioning
      vlan: 201
      role: provisioning
    - name: quarantine
      vlan: 202
      role: quarantine
```


## DNS Zone Subdomains

When `dns.zone-subdomains: true` is set in the DNS configuration, the platform
derives per-network-zone DNS subdomains from the SDN zone list. The resolved
SDN zones (`sdn.zones`, merged with built-in defaults) are passed to the DNS
subsystem at startup.

**How it works:**

- The DNS server pre-creates one sub-zone per resolved network zone under the
  internal domain: `<networkzone>.<domain>` (e.g., `trusted.example.internal.`).
- Device enrollment registers the host as both:
  - `<host>.<domain>` (standard, always)
  - `<host>.<networkzone>.<domain>` (zone-qualified, when enabled and the device
    profile declares a network zone)
- BMC names (`<host>-bmc.<domain>`) are **never** zone-qualified. The management
  zone naming convention (`<host>-bmc.<domain>`) is preserved unchanged.
- DNS **reflects** zone membership for readability and discovery but is **never
  the security boundary**; all enforcement lives in the SDN/identity layer.

**Requirements:**

- `sdn.enabled: true` with zones validated (`sdn.Validate()` called) before DNS
  startup so that `ResolvedZones()` returns the full zone list.
- `dns.zone-subdomains: true` in the DNS configuration.

**Example — resulting DNS names for host `lab-node-1` in zone `trusted`:**

```
lab-node-1.example.internal.          # standard record
lab-node-1.trusted.example.internal.  # zone-qualified record
lab-node-1-bmc.example.internal.      # BMC — not zone-qualified (unchanged)
```

## Transit Configuration (`transit:`)

The `sdn.transit` block configures the point-to-point transit link between the
gateway and its upstream BGP peer or an adjacent gateway node. It is distinct
from the gateway's BGP transit service (see
[Gateway Transit Mode](gateway/transit-mode.md)) — this block defines the L2
VLAN and L3 P2P prefix; the gateway's `transit:` service block controls whether
the transit routing service is active.

When absent, the transit link uses the platform defaults (`vlan: 10`,
`p2p: "172.16.0.0/24"`).

```yaml
sdn:
  transit: {vlan: 10, p2p: "172.16.0.0/24"}
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `vlan` | uint16 | `10` | VLAN tag for the transit link. Must be in `[1, 4094]` when non-zero. Zero means use the default. |
| `p2p` | string | `"172.16.0.0/24"` | P2P subnet for the transit link. /31 or /30 slices are allocated from this block per peer. |

### Validation

`sdn.Config.Validate()` calls `TransitConfig.Validate()`, which returns
`ErrInvalidTransitVLAN{VLAN: n}` when a non-zero VLAN is outside `[1, 4094]`.

| Error | Cause |
|-------|-------|
| `ErrInvalidTransitVLAN` | `vlan:` is non-zero and outside `[1, 4094]` |

### Effective defaults

`TransitConfig.EffectiveVLAN()` returns `vlan.DefaultTransit` (10) when `vlan`
is zero. `TransitConfig.EffectiveP2P()` returns `"172.16.0.0/24"` when `p2p`
is empty. These helpers are safe to call on a nil `*TransitConfig`.

## Management VPN Configuration (`management_vpn:`)

The `sdn.management_vpn` block enables a VPN tunnel that allows traffic from
specified zones to reach the management plane. The WireGuard runtime details
(key generation, peer enrollment, dynamic IP assignment) are handled by the
go-xkms WireGuard support reached through the quicbaas SDK. This block only
controls whether the service is active and which zones are allowed inbound.

```yaml
sdn:
  management_vpn: {enabled: true, type: wireguard, allow_to: [management]}
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Activates the management VPN service. When `false`, the block is accepted but the service is not started and zone validation is skipped. |
| `type` | string | `"wireguard"` | VPN protocol. Currently only `"wireguard"` is supported. |
| `allow_to` | []string | `[]` | Zone names whose traffic is permitted into the management plane. Each name must exist in the resolved zone set. |

### Validation

When `enabled: true`, `sdn.Config.Validate()` checks every name in `allow_to`
against the resolved zone set and returns `ErrManagementVPNUnknownZone{Zone: n}`
for the first unrecognised name.

| Error | Cause |
|-------|-------|
| `ErrManagementVPNUnknownZone` | An `allow_to` entry does not match any resolved zone |

### Runtime-undefined behaviour

The following aspects are intentionally outside this config block and are
managed entirely by the quicbaas SDK at runtime:

- WireGuard private/public key generation and rotation
- Per-peer allowed-IPs assignment and IPAM lease
- Peer enrollment ceremony (IDevID attestation gate)
- Cryptographic handshake timeouts and re-keying intervals

### Example — three-node reference deployment

```yaml
sdn:
  transit: {vlan: 10, p2p: "172.16.0.0/24"}
  management_vpn: {enabled: true, type: wireguard, allow_to: [management]}
  services:
    provisioning: {acme_server: "172.16.201.10", dns_server: "172.16.201.1", dhcp_range: "172.16.201.100-172.16.201.200"}
    quarantine:   {remediation_server: "172.16.202.10", dns_server: "172.16.202.1"}
```

## Zone Services Configuration (`services:`)

The `sdn.services` block is a map keyed by zone name. Each entry provides
per-zone service endpoints that the platform uses when servicing devices that
land in that zone (e.g., which ACME server to direct a provisioning device to,
which DNS server to inject, which DHCP range to advertise).

```yaml
sdn:
  services:
    provisioning: {acme_server: "172.16.201.10", dns_server: "172.16.201.1", dhcp_range: "172.16.201.100-172.16.201.200"}
    quarantine:   {remediation_server: "172.16.202.10", dns_server: "172.16.202.1"}
```

### ZoneServiceConfig fields

| Field | Type | Description |
|-------|------|-------------|
| `acme_server` | string | Address of the ACME server devices in this zone should contact for certificate enrolment. |
| `dns_server` | string | DNS resolver address injected via DHCP option 6 for devices in this zone. |
| `dhcp_range` | string | DHCP address range in `start-end` notation (e.g., `"172.16.201.100-172.16.201.200"`). |
| `remediation_server` | string | Address of the remediation portal served to quarantined devices. |

All fields are optional — supply only the ones relevant to each zone.

### Lookup

Callers read `Config.Services[zoneName]` directly. The map is keyed by the
zone name string (e.g., `"provisioning"`, `"quarantine"`). An absent key is not
an error; it simply means no additional service endpoints are configured for
that zone.


## Runtime Zone CRUD

The zone set declared in the configuration file is the *seed*. At runtime, the
`ZoneService` starts from this seed and allows CRUD operations through every
protocol (REST, gRPC, QUIC, MCP, Unix socket, CLI). Runtime changes overlay the
config-seeded set:

- **Create** adds a new zone and re-validates the full set. Duplicate names are
  rejected.
- **Update** replaces a zone's policy fields. If any policy-relevant field
  (`isolate`, `oob`, `isolate_per_tenant`, `internet_ingress`, `allow_to`,
  `isolate_from`) changes, the response includes `restart_required: true` because
  the flow matrix must be recompiled via daemon restart.
- **Delete** removes a zone. Removing the sole holder of a required lifecycle role
  (`provisioning`, `quarantine`) without a replacement fails validation.
- **Assign** binds a named network segment to a trust zone. Always returns
  `restart_required: true` because flow tables keyed by network→zone must be
  rebuilt.

Runtime mutations are in-memory by default. When a quicbaas KV store is
configured, zones are persisted and survive restarts.
