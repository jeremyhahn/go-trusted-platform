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

The SDN section declares an **environment** and the **zone policy**; every
VLAN ID, subnet, IPAM pool, DHCP range and switch port VLAN list is derived
from them by `pkg/sdn/netplan`, the only place numbering is computed. Nothing
is configured per VLAN. See [Reference Network
Architecture](../architecture/reference-network.md) for the design.

### `environment:` — the numbering inputs

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `environment.id` | int | required | Environment number _E_ (2–40). Its VLAN block is _E_·100–_E_·100+99 |
| `environment.base` | IPv4 prefix | `10.0.0.0/8` | The `/8` the environment's `/16` (`<base>.E.0.0/16`) is taken from |
| `environment.ula` | IPv6 prefix | none | The deployment's RFC 4193 `/48`. Without it no IPv6 subnets are derived |
| `environment.overrides[]` | list | none | Explicit numbering for single zones: `zone`, and any of `vlan`, `subnet` (IPv4 `/16`–`/26`), `subnet6` (`/64`) |

`sdn.enabled: true` without `environment:` fails validation
(`ErrEnvironmentRequired`): nothing can be numbered.

Derived for the zone at offset _n_:

| What | Rule | Example (E=4, control-plane, n=6) |
|------|------|-----------------------------------|
| VLAN | _E_·100+_n_ | 406 |
| IPv4 subnet | `<base>.E.n.0/24` | 10.4.6.0/24 |
| IPv6 subnet | `<ula>:<VLAN digits>::/64` | fd12:3456:789a:406::/64 |
| Gateway | `.1` | 10.4.6.1 |
| IPAM pool | the subnet, `.1` reserved, dynamic range `.50`–last | 10.4.6.50–10.4.6.254 |

And for the environment:

| What | Rule |
|------|------|
| IPAM pool | `<base>.E.128.0/17`, split into tunnel-p2p `/22`, loopbacks `/22`, service-vips `/21`, platform-hosts `/20`, tenant-default `/18` |
| Reserved | `<base>.E.128.0/31` (gateway HA sync), `169.254.169.253`, `<ula>:ffff::/64`, every zone's `.1` |
| Overlay VNI | _E_·100000+_n_ for overlay network _n_ (1–99,999) |

### `zones:` — tune built-in policy, add owner-defined zones

The nine built-in zones need no entry: `transit` (x00), `fabric` (x01),
`management` (x02), `hypervisor` (x03), `quarantine` (x04), `provisioning`
(x05), `control-plane` (x06), `storage` (x07), `backup` (x08).

An entry whose `name` matches a built-in **replaces its policy**
(`internet_ingress`, `isolate_from`, `allow_to`, `services`, `isolate`,
`privileged_access`). Its identity — `offset`, `port_classes`,
`lifecycle_role`, `oob` — is fixed: an entry may restate it but never change
it (`ErrBuiltinIdentity`). `omit: true` drops an optional built-in; `fabric`,
`provisioning`, `quarantine` and `control-plane` cannot be omitted
(`ErrOmitRequired`).

Any other entry is an **owner-defined zone**. It must take a unique `offset`
from 9 to 99 and join the `gateway` and/or `hypervisor` port class; it
cannot carry a lifecycle role or `oob`.

```yaml
sdn:
  environment:
    id: 4
    ula: fd12:3456:789a::/48
  zones:
    - name: lab
      offset: 9                 # VLAN 409, 10.4.9.0/24, fd12:3456:789a:409::/64
      port_classes: [hypervisor]
      isolate: true
      allow_to:
        - {zone: storage, services: [storage]}
        - zone: control-plane
          services: [api]
      privileged_access:        # required: lab → control-plane is beyond the reference
        reason: "lab CI runners reach the platform API"
        approved_by: "platform owner"
```

A path into `control-plane` or `management` that the zone's built-in
defaults do not already open needs `privileged_access` with both fields
(`ErrPrivilegedAccessRequired`). platformd logs every such path as an audit
record (`audit=true`) each time it loads the configuration.

`platform`, `tenant`, `public` and `trusted` cannot name a zone
(`ErrReservedZoneName`): overlays are not zones, and tenants never create
zones.

### Built-in zone policy

| From | Allowed to | Services |
|------|------------|----------|
| fabric | fabric | vxlan, bgp, ipsec |
| hypervisor | hypervisor | migration |
| quarantine | control-plane | dns, auth, remediation |
| provisioning | control-plane | tftp, http, dns, acme |
| control-plane | control-plane | all |
| storage | storage | storage |
| backup | backup | backup |

Every other pair is denied, including traffic inside `transit` and
`management`. `management` is out-of-band and reaches nothing.

### Per-zone OpenFlow templates

The `pkg/sdn/policy/zoneflows` package generates the lifecycle zones' rule
sets from the reference flow templates; every other zone gets the rules the
inter-zone matrix compiles.

Each rule matches the zone's frames **the way they reach the flow tables**.
OVS applies a port's VLAN configuration (`tag`, `trunks`, `vlan_mode`) only in
the `NORMAL` action; the OpenFlow tables see a frame as it was received. So:

- on an **access port**, and for a trunk's **native** zone, the zone's frames
  carry no 802.1Q header and are matched as untagged:
  `in_port=<port>,vlan_tci=0x0000/0x1fff`;
- for a trunk's **tagged** zones, frames are matched by VLAN:
  `in_port=<port>,dl_vlan=<VLAN>`.

The inter-zone matrix rules follow the same split: one shared set keyed on
`dl_vlan=<source VLAN>` covers tagged traffic, and each access port (or trunk
native zone) gets the same verdicts keyed on its own untagged ingress, removed
with the port's other rules.

With environment 4, on a hypervisor trunk (provisioning is the native zone):

**provisioning** (VLAN 405, native, untagged) — DHCP, DNS, TFTP, HTTP and ACME
only, default drop:

```
in_port=<port>,vlan_tci=0x0000/0x1fff,arp,                      actions=normal
in_port=<port>,vlan_tci=0x0000/0x1fff,udp,tp_src=68,tp_dst=67,  actions=normal   # DHCP
in_port=<port>,vlan_tci=0x0000/0x1fff,udp,tp_dst=53,            actions=normal   # DNS
in_port=<port>,vlan_tci=0x0000/0x1fff,udp,tp_dst=69,            actions=normal   # TFTP
in_port=<port>,vlan_tci=0x0000/0x1fff,tcp,tp_dst=443,           actions=normal   # ACME
in_port=<port>,vlan_tci=0x0000/0x1fff,                          actions=drop
```

**quarantine** (VLAN 404, tagged on the trunk) — authentication and
remediation only, default drop:

```
in_port=<port>,dl_vlan=404,arp,                      actions=normal
in_port=<port>,dl_vlan=404,udp,tp_src=68,tp_dst=67,  actions=normal   # DHCP
in_port=<port>,dl_vlan=404,tcp,tp_dst=443,           actions=normal   # remediation
in_port=<port>,dl_vlan=404,                          actions=drop
```

A port placed in quarantine as an access port matches the quarantine rules on
untagged ingress instead.

### Device lifecycle

A device's port moves **provisioning → the zones of its role → quarantine →
down**. Once attested, the port carries the zones of its role's port class
(`gateway` for a gateway, `hypervisor` for control-plane and compute nodes),
with the native VLAN of that class. A blocked port is administratively down,
never in a "blocked zone". The device profile's `zone` names a single zone
when a profile needs exactly one.

## Environment Variables

Environment variables can override configuration for quick testing or container deployments:

| Variable | Default | Description |
|----------|---------|-------------|
| OVS_DB_SOCK | /var/run/openvswitch/db.sock | OVSDB socket path |
| OVS_RUNDIR | /var/run/openvswitch | OVS runtime directory |
| SDN_LOG_LEVEL | info | Logging level (debug, info, warn, error) |

No environment variable sets a VLAN: numbering comes only from
`sdn.environment`.

## Platform Configuration (YAML)

All VLAN assignments are configurable. See [Reference Network Architecture](../architecture/reference-network.md) for the complete configuration schema.

### A complete `sdn:` section

```yaml
sdn:
  enabled: true
  controller: true
  environment:
    id: 4
    base: 10.0.0.0/8
    ula: fd12:3456:789a::/48
  ovs:
    socket: /var/run/openvswitch/db.sock
    bridge: br-fabric          # carries the trunk; workloads use br-int
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
    # The zone pools and IPAM ranges are derived and seeded at startup.
    # `pools:` adds explicit pools beside them.
    pools:
      - name: public
        cidr: 203.0.113.0/24
        gateway: 203.0.113.1
  dhcp:
    enabled: false
  fabric:
    switches:
      - {id: switch-01, vendor: cisco-nexus, mgmt-ip: 192.0.2.250, credentials-ref: "kms://switches/switch-01"}
    ports:
      - {switch-id: switch-01, port: Ethernet1/25, class: hypervisor, description: cp-01}
```

### `ipam.pools:` — explicit pools

The plan's pools are derived: one per zone (named after it) and one per IPAM
range except the tenant default range (`tunnel-p2p`, `loopbacks`,
`service-vips`, `platform-hosts`). An explicit pool may not take one of
those names (`ErrPoolNameReserved`) or overlap a derived pool or a reserved
range (`ErrPoolOverlap`); a pool carved from the tenant default range is
allowed. A pool's `zone`, when set, must be a declared zone
(`ErrPoolZoneUndeclared`); overlay pools carry none.

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
| `platform_zone` | string | `"control-plane"` | The zone name embedded in the platform's own self-IDevID certificate when `encode_zone_in_cert` is `true`. Defaults to `"control-plane"` when empty: the platform lives on the control-plane zone, and management carries BMCs only. |

### Zone-in-Certificate (Z3) Overview

When `encode_zone_in_cert: true`:

1. **Device enrollment (IDevID / ACME)** — the zone is taken from the device
   profile's `post-enrollment` `NetworkPhaseConfig.Zone`, falling back to
   `DeviceProfile.Zone`. If neither is set, issuance fails with a typed error
   (`ErrEncodeZoneEmpty`).

2. **Platform self-IDevID** — the zone is taken from `platform_zone` (default:
   `"control-plane"`). If `platform_zone` is empty and encoding is enabled, the
   default `"control-plane"` zone is used.

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

Enable zone encoding; the platform's own certificate carries `control-plane`:

```yaml
sdn:
  enabled: true
  environment:
    id: 4
  identity:
    encode_zone_in_cert: true
    platform_zone: control-plane
```


## DNS Zone Subdomains

When `dns.zone-subdomains: true` is set in the DNS configuration, the platform
derives per-network-zone DNS subdomains from the SDN zone list. The resolved
SDN zones (`sdn.zones`, merged with built-in defaults) are passed to the DNS
subsystem at startup.

**How it works:**

- The DNS server pre-creates one sub-zone per resolved network zone under the
  internal domain: `<networkzone>.<domain>` (e.g., `control-plane.example.internal.`).
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

**Example — resulting DNS names for host `cp-01` in zone `control-plane`:**

```
cp-01.example.internal.                # standard record
cp-01.control-plane.example.internal.  # zone-qualified record
cp-01-bmc.example.internal.            # BMC — not zone-qualified (unchanged)
```

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
  environment: {id: 4}
  management_vpn: {enabled: true, type: wireguard, allow_to: [management]}
```

The transit zone needs no section of its own: its VLAN and subnet are the
environment's x00, and transit point-to-point links take `/31`s from the
`tunnel-p2p` IPAM range.

## Runtime Zone CRUD

The zone entries in `sdn.zones` are the *seed*. At runtime the `ZoneService`
starts from that seed (resolved onto the built-ins) and allows changes through
every protocol (REST, gRPC, QUIC, MCP, Unix socket, CLI):

- **Create** adds an owner-defined zone (offset 9–99). A built-in name returns
  already-exists.
- **Update** tunes a built-in zone's policy or replaces an owner-defined zone.
- **Delete** removes an owner-defined zone, or omits an optional built-in. The
  required built-ins (`fabric`, `provisioning`, `quarantine`, `control-plane`)
  cannot be removed.

Every change re-runs `zone.Resolve` and `zone.Validate` on the whole set and,
when the daemon has an environment, derives the network plan again; a change
that fails either is refused and leaves the set as it was. A path into
`control-plane` or `management` beyond the reference needs `privileged_access`
and writes an audit record. Every accepted change returns
`restart_required: true`: the network plan and the flow matrix are derived at
startup, so the change takes effect when the daemon restarts.

Runtime changes are held in memory only. To keep a change, put it in
`sdn.zones` in the configuration file.
