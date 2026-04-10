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

## VLAN Configuration

### VLAN Zones

See [Reference Network Architecture](../architecture/reference-network.md) for the complete VLAN scheme.

| Zone | VLANs | Purpose |
|------|-------|---------|
| Infrastructure | 1-8 | Platform operations (DEFAULT, WAN0-2, MANAGEMENT, QUARANTINE, PROVISIONING, STORAGE) |
| Corporate | 10-16 | User/device networks (HOME, OFFICE, WIFI, WIFI_GUEST, IOT, DATA, CCTV) |
| DMZ | 20-22 | Public-facing services (DMZ_PUBLIC, DMZ_PRIVATE, DMZ_DATA) |
| Cloud Tenant | 1000+ | Multi-tenant workloads |

### Provisioning VLAN (7)

Devices in provisioning state have limited network access:

```yaml
provisioning_vlan:
  id: 7
  network: "172.16.7.0/24"
  gateway: "172.16.7.1"
  dhcp_range: "172.16.7.100-172.16.7.200"
  allowed_traffic:
    - protocol: udp
      port: 67-68
      description: "DHCP"
    - protocol: udp
      port: 53
      description: "DNS"
    - protocol: tcp
      port: 53
      description: "DNS over TCP"
    - protocol: udp
      port: 69
      description: "TFTP for PXE"
    - protocol: tcp
      port: 443
      description: "HTTPS to platform"
    - protocol: tcp
      port: 8443
      description: "Platform API"
```

### Quarantine VLAN (6)

Devices with compliance issues are isolated:

```yaml
quarantine_vlan:
  id: 6
  network: "172.16.6.0/24"
  gateway: "172.16.6.1"
  allowed_traffic:
    - protocol: tcp
      port: 443
      destination: "remediation-server"
      description: "Remediation portal"
```

### Production VLANs

Production VLANs are configured per device profile:

```yaml
production_vlan:
  id: 11  # From device profile (OFFICE example)
  acls:
    - priority: 1000
      match:
        protocol: tcp
        destination_port: 443
      action: allow
    - priority: 500
      match:
        protocol: icmp
      action: allow
    - priority: 1
      action: deny  # Default deny
```

## Environment Variables

Environment variables can override configuration for quick testing or container deployments:

| Variable | Default | Description |
|----------|---------|-------------|
| OVS_DB_SOCK | /var/run/openvswitch/db.sock | OVSDB socket path |
| OVS_RUNDIR | /var/run/openvswitch | OVS runtime directory |
| SDN_LOG_LEVEL | info | Logging level (debug, info, warn, error) |
| SDN_VLAN_DEFAULT | 1 | Default VLAN ID |
| SDN_VLAN_MANAGEMENT | 5 | Management VLAN ID |
| SDN_VLAN_QUARANTINE | 6 | Quarantine VLAN ID |
| SDN_VLAN_PROVISIONING | 7 | Provisioning VLAN ID |
| SDN_VLAN_STORAGE | 8 | Storage VLAN ID |
| SDN_VLAN_CLOUD_TENANT_BASE | 1000 | Base VLAN for cloud tenants |

## Platform Configuration (YAML)

All VLAN assignments are configurable. See [Reference Network Architecture](../architecture/reference-network.md) for the complete configuration schema.

```yaml
sdn:
  enabled: true
  bridge_name: "br0"

  ovsdb:
    socket: "/var/run/openvswitch/db.sock"
    database: "Open_vSwitch"
    timeout: 30s

  openflow:
    socket_dir: "/var/run/openvswitch"
    version: "1.3"
    timeout: 30s

  # VLAN assignments (all configurable, defaults shown)
  vlans:
    default: 1
    management: 5
    quarantine: 6
    provisioning: 7
    storage: 8
    cloud_tenant_base: 1000

  # Subnet assignments
  subnets:
    quarantine: "172.16.6.0/24"
    provisioning: "172.16.7.0/24"

  # Service IPs
  services:
    provisioning:
      acme_server: "172.16.7.10"
      dns_server: "172.16.7.1"
    quarantine:
      remediation_server: "172.16.6.10"
      dns_server: "172.16.6.1"

  policy:
    enable_monitoring: true
    certificate_check_interval: 1h
    expiry_warning_threshold: 168h  # 7 days

  logging:
    level: info
    format: json
```

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
