# SDN Configuration Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> The `sdn:` configuration section.

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
    ovs.WithAppCtlRunDir("/var/run/openvswitch"),
)
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| socketPath | string | Required | Path to OVSDB Unix socket; empty returns `ErrInvalidSocket` |
| database | string | "Open_vSwitch" | OVSDB database name |
| timeout | time.Duration | 30s | Operation timeout |
| ofSocketDir | string | "/var/run/openvswitch" | Directory for OpenFlow sockets |
| appCtlRunDir | string | "/var/run/openvswitch" | Run directory holding the `ovs-appctl` control sockets (`WithAppCtlRunDir`) |

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
| bridgeName | string | Required | OVS bridge name; empty returns `ErrInvalidBridgeName` |
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

    // Port controller for VLAN/state operations. If nil, FlowController is
    // used when it implements OVSPortController; otherwise NewEngine fails.
    PortController: ovsClient,

    // Optional: Logger (uses slog.Default() if nil)
    Logger: slog.Default(),

    // Optional: Certificate policy extractor (NewX509PolicyExtractor() if nil)
    PolicyExtractor: policy.NewX509PolicyExtractor(),

    // Optional: Certificate validator (revocation checks)
    CertificateValidator: certValidator,

    // Optional: Zone-keyed flow installation; a quarantine policy is
    // refused without it
    ZoneFlowManager: zoneFlows,

    // Optional: How per-port allow rules end: normal, or goto_table:10
    // when a gatewayd pipeline owns the bridge
    Terminal: zoneflows.TerminalNormal,

    // Optional: Resolved zones; identifies the quarantine zone
    Zones: resolvedZones,

    // Optional: Enable certificate lifecycle monitoring
    EnableMonitoring: true,

    // Optional: Monitor configuration
    MonitorConfig: policy.MonitorConfig{
        CheckInterval:   time.Hour,
        ExpiryThreshold: 7 * 24 * time.Hour, // 7 days
    },
}

engine, err := policy.NewEngine(config)
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| BridgeName | string | Required | OVS bridge to manage |
| FlowController | FlowController | Required | OpenFlow operations interface |
| PortController | OVSPortController | FlowController | OVSDB port operations; defaults to FlowController when it implements OVSPortController, otherwise NewEngine returns an error |
| Logger | *slog.Logger | slog.Default() | Structured logger |
| PolicyExtractor | PolicyExtractor | NewX509PolicyExtractor() | Certificate policy extraction |
| CertificateValidator | CertificateValidator | nil | Certificate validation |
| ZoneFlowManager | *ZoneFlowManager | nil | Zone-keyed flow installation; required for a quarantine policy |
| Terminal | zoneflows.Terminal | normal | How per-port allow rules end (`normal` or `goto_table:10`) |
| Zones | []zone.ZoneConfig | nil | Resolved zone set; identifies the quarantine zone |
| EnableMonitoring | bool | false | Enable certificate monitoring; the monitor is created only when true |
| MonitorConfig | MonitorConfig | - | Monitor settings |

### Monitor Configuration

```go
type MonitorConfig struct {
    // How often to check certificate status (default 5m)
    CheckInterval time.Duration

    // Callbacks fire for certificates expiring within this duration (default 24h)
    ExpiryThreshold time.Duration
}
```

Callbacks are registered on the `*CertificateMonitor`, not in the config:

```go
monitor.OnExpiry(func(portID string, cert interface{}, timeUntilExpiry time.Duration) { ... })
monitor.OnRevoked(func(portID string, cert interface{}) { ... })
```

Each callback runs in its own goroutine and is re-invoked on every check while
the condition holds, so it must be safe for concurrent use. An expired or
revoked certificate also blocks the port.

## Bridge Configuration

### Creating a Bridge

```go
ctx := context.Background()

// Create bridge with default settings
bridge, err := client.CreateBridge(ctx, "br0")

// Create bridge with datapath, fail mode and OpenFlow protocols
bridge, err := client.CreateBridgeWithOptions(ctx, "br0", &ovs.BridgeOptions{
    DatapathType: "system",          // "" or "system" = kernel; "netdev" = userspace/DPDK
    FailMode:     "secure",          // "standalone", "secure" or empty
    Protocols:    []string{"OpenFlow13"},
})
```

### Bridge Properties

| Property | Type | Description |
|----------|------|-------------|
| name | string | Unique bridge name |
| protocols | []string | Supported OpenFlow protocols |
| fail_mode | string | Behavior on controller disconnect ("secure", "standalone") |
| datapath_type | string | Datapath implementation ("system", "netdev") |

The platform's own bridge is configured by `sdn.ovs` (`bridge`, `datapath`,
`protocols`); see [`ovs:`](#ovs--datapath-hardware-offload-and-dpdk).

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

The zone templates in `pkg/sdn/policy/zoneflows` install their table-0 rules at
these priorities:

| Priority | Rule |
|----------|------|
| 1900 | ARP and IPv6 neighbour discovery |
| 1850 | DHCP |
| 1800 | DNS |
| 1750 | TFTP |
| 1700 | ACME (provisioning), scanning servers (quarantine) |
| 1650 | Package repositories (provisioning), remediation servers (quarantine) |
| 1600 | Notification portal (quarantine), ICMP (provisioning, when allowed) |
| 1100 | Quarantine default drop |
| 900 | Provisioning default drop |
| 200 | Inter-zone matrix deny |
| 100 | Inter-zone matrix allow, east-west, management |

Conntrack uses table 20 (the gate: IP at 100, neighbour discovery at 200) and
table 21 (the verdict: invalid 400, established/related 300, miss 0);
accepted traffic continues in table 30.

### Building a Flow

A `FlowMod` is built from a match and an instruction list and sent with
`(*openflow.Client).AddFlow`:

```go
fm := openflow.NewFlowMod(xid) // xid is the OpenFlow transaction ID
fm.TableID = 0
fm.Priority = 1000

// Layer 2 matches (fm.Match is created by NewFlowMod)
fm.Match.AddInPort(1)
fm.Match.AddEthSrc(srcMAC)          // net.HardwareAddr
fm.Match.AddEthType(0x0800)         // IPv4
fm.Match.AddVLANVid(100)

// Layer 3 and 4 matches
fm.Match.AddIPProto(6)              // TCP
fm.Match.AddIPv4DstMasked(net.ParseIP("10.0.0.0"), net.CIDRMask(8, 32))
fm.Match.AddTCPDst(443)

fm.Instructions = []openflow.Instruction{
    openflow.NewInstructionApplyActions(
        openflow.NewActionOutput(2, 0),
    ),
}

err = ofClient.AddFlow(ctx, fm)
```

Other matches: `AddEthDst`, `AddIPv4Src`/`AddIPv4Dst` (and `Masked` forms),
`AddTCPSrc`, `AddUDPSrc`/`AddUDPDst`, `AddReg`, `AddCTState`/`AddCTZone`/
`AddCTMark` and the tunnel matches.

### Actions and Instructions

| Need | Call |
|------|------|
| Output to a port | `openflow.NewActionOutput(port, 0)` |
| Normal L2/L3 processing | `openflow.NewActionOutput(openflow.OFPPNormal, 0)` |
| Flood / to controller | `NewActionOutput(openflow.OFPPFlood, 0)`, `NewActionOutput(openflow.OFPPController, maxLen)` |
| VLAN push / pop | `openflow.NewActionPushVLAN(0x8100)`, `openflow.NewActionPopVLAN()` |
| Set a field | `openflow.NewActionSetField(class, field, value)` |
| Decrement TTL | `openflow.NewActionDecNwTTL()` |
| Group, conntrack, register load, resubmit | `NewActionGroup`, `NewActionCT`/`NewActionCTCommit`, `NewActionRegLoad`, `NewActionResubmit` |
| Apply actions | `openflow.NewInstructionApplyActions(actions...)` |
| Go to another table | `openflow.NewInstructionGotoTable(tableID)` |
| Meter | `openflow.NewInstructionMeter(meterID)` |

A flow with no instructions drops the packet.

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

IP rules are shown for IPv4; each has an IPv6 twin (`dl_type=0x86dd`,
`ipv6_dst`, DHCPv6 ports 546/547), and ARP has neighbour-discovery twins.

**provisioning** (VLAN 405, native, untagged) — DHCP, DNS, TFTP, ACME and
package repositories only, default drop. With no server addresses configured
the DNS, ACME and package rules accept any destination; with addresses, one
rule per address (`nw_dst=<ip>`):

```
priority=1900 in_port=<port>,vlan_tci=0x0000/0x1fff,dl_type=0x0806                                  actions=normal  # ARP
priority=1850 in_port=<port>,vlan_tci=0x0000/0x1fff,dl_type=0x0800,nw_proto=17,tp_src=68,tp_dst=67  actions=normal  # DHCP
priority=1800 in_port=<port>,vlan_tci=0x0000/0x1fff,dl_type=0x0800,nw_proto=17,tp_dst=53            actions=normal  # DNS; also 8053, 9053
priority=1750 in_port=<port>,vlan_tci=0x0000/0x1fff,dl_type=0x0800,nw_proto=17,tp_dst=69            actions=normal  # TFTP
priority=1700 in_port=<port>,vlan_tci=0x0000/0x1fff,dl_type=0x0800,nw_proto=6,tp_dst=443            actions=normal  # ACME; also 8443, 9443
priority=1650 in_port=<port>,vlan_tci=0x0000/0x1fff,dl_type=0x0800,nw_proto=6,tp_dst=80             actions=normal  # package repos; also 443
priority=1600 in_port=<port>,vlan_tci=0x0000/0x1fff,dl_type=0x0800,nw_proto=1                       actions=normal  # ICMP, only when AllowICMP
priority=900  in_port=<port>,vlan_tci=0x0000/0x1fff                                                 actions=drop
```

**quarantine** (VLAN 404, tagged on the trunk) — DHCP, DNS, scanning,
remediation and the notification portal only, default drop:

```
priority=1900 in_port=<port>,dl_vlan=404,dl_type=0x0806                                  actions=normal  # ARP
priority=1850 in_port=<port>,dl_vlan=404,dl_type=0x0800,nw_proto=17,tp_src=68,tp_dst=67  actions=normal  # DHCP
priority=1800 in_port=<port>,dl_vlan=404,dl_type=0x0800,nw_proto=17,tp_dst=53            actions=normal  # DNS (nw_dst=<DNS server> when set)
priority=1700 in_port=<port>,dl_vlan=404,dl_type=0x0800,nw_dst=<scanner>                 actions=normal  # per scanning server
priority=1650 in_port=<port>,dl_vlan=404,dl_type=0x0800,nw_proto=6,nw_dst=<rem>,tp_dst=443 actions=normal # per remediation server and allowed port (default 443)
priority=1600 in_port=<port>,dl_vlan=404,dl_type=0x0800,nw_proto=6,nw_dst=<portal>,tp_dst=80 actions=normal # notification portal; also 443
priority=1100 in_port=<port>,dl_vlan=404                                                 actions=drop    # cookie quarantine:<port>
```

When a gatewayd pipeline owns the bridge, every `actions=normal` above is
written as `actions=goto_table:10` instead.

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

No environment variable configures the `sdn:` section: the OVSDB socket,
bridge and every VLAN come only from the configuration file.

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
- Validation fails startup on an empty `socket` (`ErrInvalidOVSSocket`) or
  `bridge` (`ErrInvalidBridge`), an unknown `tc-policy`
  (`ErrInvalidTCPolicy`), `tc-policy` without `hw-offload: true`
  (`ErrTCPolicyWithoutHWOffload`), and a `dpdk:` block without
  `datapath: netdev` (`ErrDPDKRequiresNetdev`).
- If the Open_vSwitch root row is not there yet, platformd retries for up to
  two minutes before it gives up.
- NIC/kernel requirements, the switchdev bring-up order, and what
  actually offloads: see [performance/hw-offload.md](./performance/hw-offload.md).

## Systemd Configuration

The SDN controller runs inside `platformd serve`; there is no separate SDN
command or unit. The shipped unit is `configs/os/platformd.service`:

```ini
[Unit]
After=network-online.target systemd-tmpfiles-setup.service

[Service]
ExecStart=/usr/local/bin/platformd serve --config=/etc/trusted-platform/config.yaml --socket-path=/var/run/platformd.sock --log-dir=/var/log/trusted-platform --enable-mtls ${PLATFORMD_DEBUG}
```

It is not ordered after Open vSwitch; platformd waits for the OVS root row
itself (see [`ovs:`](#ovs--datapath-hardware-offload-and-dpdk)).

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
   with pre-Z3 deployments); an extension that is present but unreadable fails
   closed with `ErrZoneExtensionInvalid`.

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

Startup fails with `ErrZoneSubdomainsNoInternalServer` when zone subdomains
are on without an internal DNS server, and with
`ErrZoneSubdomainsNoNetworkZones` when the zone list is empty.

**Example — resulting DNS names for host `cp-01` in zone `control-plane`:**

```
cp-01.example.internal.                # standard record
cp-01.control-plane.example.internal.  # zone-qualified record
cp-01-bmc.example.internal.            # BMC — not zone-qualified (unchanged)
```

## Management VPN Configuration (`management_vpn:`)

The `sdn.management_vpn` block declares which zones a management VPN may
reach. platformd only validates it; nothing in platformd starts a VPN from it.
The management VPN service itself is gatewayd's: it reads its own
`management_vpn` section (`pkg/sdn/gateway/vpn_service.go`), described in
[Gateway architecture](../gateway/architecture.md).

```yaml
sdn:
  management_vpn: {enabled: true, type: wireguard, allow_to: [management]}
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Turns on validation of `allow_to`. When `false`, the block is accepted and zone validation is skipped. |
| `type` | string | `""` | VPN protocol. Only `"wireguard"` is defined by the reference architecture; the value is not checked. |
| `allow_to` | []string | `[]` | Zone names the VPN admin subnet may reach. Each name must exist in the resolved zone set. |

### Validation

When `enabled: true`, `sdn.Config.Validate()` checks every name in `allow_to`
against the resolved zone set and returns `ErrManagementVPNUnknownZone{Zone: n}`
for the first unrecognised name.

| Error | Cause |
|-------|-------|
| `ErrManagementVPNUnknownZone` | An `allow_to` entry does not match any resolved zone |

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
