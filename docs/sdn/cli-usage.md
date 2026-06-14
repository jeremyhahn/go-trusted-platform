# SDN CLI Usage

## Overview

The `platformctl sdn` command provides command-line management of the SDN
subsystem, including bridge, port, and flow operations.

## Command Structure

```
platformctl sdn <subcommand> [options]

Subcommands:
  bridge    Manage OVS bridges
  port      Manage OVS ports
  flow      Manage OpenFlow rules
  policy    Manage port policies
  status    Show SDN status
  overlay   Manage VXLAN overlay network (VTEPs, VNIs, tunnels, MACs)
  gateway   Manage multi-mode gateway (modes, BGP, IPAM)
  ipam      Manage IP address pools and allocations
  zone      Manage network trust zones
```

## Bridge Commands

### Create Bridge

Creates a new OVS bridge.

```bash
platformctl sdn bridge create <name> [options]

Options:
  --protocol    OpenFlow protocol version (default: OpenFlow13)
  --fail-mode   Failure mode: secure|standalone (default: secure)
  --datapath    Datapath type: system|netdev (default: system)

Examples:
  platformctl sdn bridge create br0
  platformctl sdn bridge create br1 --protocol OpenFlow13 --fail-mode secure
```

### Delete Bridge

Deletes an OVS bridge.

```bash
platformctl sdn bridge delete <name>

Examples:
  platformctl sdn bridge delete br0
```

### List Bridges

Lists all OVS bridges.

```bash
platformctl sdn bridge list [options]

Options:
  --json        Output in JSON format
  --wide        Show additional details

Examples:
  platformctl sdn bridge list
  platformctl sdn bridge list --json
```

**Output:**
```
NAME    UUID                                  PORTS   PROTOCOL
br0     a1b2c3d4-e5f6-7890-abcd-ef1234567890  3       OpenFlow13
br1     b2c3d4e5-f678-9012-bcde-f12345678901  1       OpenFlow13
```

### Show Bridge

Shows bridge details.

```bash
platformctl sdn bridge show <name> [options]

Options:
  --json        Output in JSON format

Examples:
  platformctl sdn bridge show br0
```

**Output:**
```
Bridge: br0
UUID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
Protocol: OpenFlow13
Fail Mode: secure
Datapath: system
Ports:
  - br0 (internal)
  - eth0 (system)
  - tap-vm1 (system)
```

## Port Commands

### Add Port

Adds a port to a bridge.

```bash
platformctl sdn port add <bridge> <port> [options]

Options:
  --vlan        Access VLAN ID (1-4094)
  --trunks      Trunk VLAN list (comma-separated)
  --type        Port type: system|internal|patch

Examples:
  platformctl sdn port add br0 eth0
  platformctl sdn port add br0 eth1 --vlan 100
  platformctl sdn port add br0 eth2 --trunks 100,200,300
```

### Delete Port

Removes a port from a bridge.

```bash
platformctl sdn port delete <bridge> <port>

Examples:
  platformctl sdn port delete br0 eth0
```

### List Ports

Lists ports on a bridge.

```bash
platformctl sdn port list <bridge> [options]

Options:
  --json        Output in JSON format
  --wide        Show additional details

Examples:
  platformctl sdn port list br0
```

**Output:**
```
PORT      OFPORT  VLAN  TRUNKS      STATE
br0       LOCAL   -     -           up
eth0      1       100   -           up
eth1      2       -     100,200     up
tap-vm1   3       998   -           up
```

### Show Port

Shows port details.

```bash
platformctl sdn port show <port> [options]

Options:
  --json        Output in JSON format

Examples:
  platformctl sdn port show eth0
```

**Output:**
```
Port: eth0
UUID: c3d4e5f6-7890-1234-cdef-012345678901
OpenFlow Port: 1
VLAN Tag: 100
Trunks: []
Admin State: up
Link State: up
MAC Address: aa:bb:cc:dd:ee:ff
```

### Set Port VLAN

Sets access VLAN on a port.

```bash
platformctl sdn port set-vlan <port> <vlan>

Examples:
  platformctl sdn port set-vlan eth0 100
```

### Set Port State

Sets port admin state.

```bash
platformctl sdn port set-state <port> <state>

States:
  up      Enable port
  down    Disable port

Examples:
  platformctl sdn port set-state eth0 down
  platformctl sdn port set-state eth0 up
```

## Flow Commands

### Add Flow

Adds an OpenFlow rule.

```bash
platformctl sdn flow add <bridge> [options]

Options:
  --priority    Flow priority (0-65535)
  --in-port     Match input port
  --eth-src     Match source MAC
  --eth-dst     Match destination MAC
  --eth-type    Match Ethernet type (hex)
  --vlan        Match VLAN ID
  --ip-proto    Match IP protocol (tcp|udp|icmp|number)
  --ip-src      Match source IP (CIDR)
  --ip-dst      Match destination IP (CIDR)
  --tcp-dst     Match TCP destination port
  --udp-dst     Match UDP destination port
  --action      Actions: output:N, drop, normal, set-vlan:N, pop-vlan

Examples:
  # Drop all traffic from port 1
  platformctl sdn flow add br0 --priority 100 --in-port 1 --action drop

  # Allow HTTPS
  platformctl sdn flow add br0 --priority 1000 --ip-proto tcp --tcp-dst 443 --action normal

  # Forward port 1 to port 2
  platformctl sdn flow add br0 --priority 100 --in-port 1 --action output:2

  # Set VLAN tag
  platformctl sdn flow add br0 --priority 100 --in-port 1 --action set-vlan:100,output:2
```

### Delete Flow

Deletes OpenFlow rules.

```bash
platformctl sdn flow delete <bridge> [options]

Options:
  --in-port     Match input port
  --priority    Match priority
  --cookie      Match cookie value
  --all         Delete all flows

Examples:
  platformctl sdn flow delete br0 --in-port 1
  platformctl sdn flow delete br0 --all
```

### List Flows

Lists OpenFlow rules.

```bash
platformctl sdn flow list <bridge> [options]

Options:
  --json        Output in JSON format
  --stats       Show packet/byte counts

Examples:
  platformctl sdn flow list br0
  platformctl sdn flow list br0 --stats
```

**Output:**
```
PRIORITY  MATCH                           ACTIONS          PACKETS  BYTES
65535     in_port=CONTROLLER              output:NORMAL    0        0
1000      tcp,tp_dst=443                  NORMAL           1234     567890
100       in_port=1                       output:2         5678     1234567
0         *                               drop             0        0
```

### Show Flow Stats

Shows flow statistics.

```bash
platformctl sdn flow stats <bridge> [options]

Options:
  --json        Output in JSON format
  --table       Filter by table ID

Examples:
  platformctl sdn flow stats br0
```

## Policy Commands

### Show Port Policy

Shows policy for a port.

```bash
platformctl sdn policy show <port> [options]

Options:
  --json        Output in JSON format

Examples:
  platformctl sdn policy show eth1
```

**Output:**
```
Port: eth1
State: authorized
Tenant: acme-corp
VLAN: 100
Certificate:
  Subject: CN=device-001,O=Acme Corp
  Expires: 2026-01-01T00:00:00Z
  Serial: 1234567890
ACLs:
  1000: tcp,tp_dst=443 -> allow
  1000: tcp,tp_dst=80 -> allow
  500:  icmp -> allow
  1:    * -> deny
```

### Set Port State

Sets port authentication state.

```bash
platformctl sdn policy set-state <port> <state>

States:
  provisioning    Limited access for enrollment
  enrolled        Enrolled, awaiting activation
  authorized      Full production access
  quarantined     Isolated for remediation
  blocked         DROP all traffic

Examples:
  platformctl sdn policy set-state eth1 provisioning
  platformctl sdn policy set-state eth1 blocked
```

### Block Port

Blocks a port (DROP all traffic).

```bash
platformctl sdn policy block <port>

Examples:
  platformctl sdn policy block eth1
```

### Unblock Port

Unblocks a port (returns to provisioning).

```bash
platformctl sdn policy unblock <port>

Examples:
  platformctl sdn policy unblock eth1
```

### List Port States

Lists all port authentication states.

```bash
platformctl sdn policy list [options]

Options:
  --json        Output in JSON format
  --state       Filter by state
  --bridge      Filter by bridge

Examples:
  platformctl sdn policy list
  platformctl sdn policy list --state authorized
```

**Output:**
```
PORT      BRIDGE  STATE         VLAN  TENANT       EXPIRES
eth1      br0     authorized    100   acme-corp    2026-01-01
eth2      br0     provisioning  998   -            -
tap-vm1   br0     enrolled      998   -            -
tap-vm2   br0     blocked       -     -            -
```

## Status Command

### Show SDN Status

Shows overall SDN status.

```bash
platformctl sdn status [options]

Options:
  --json        Output in JSON format

Examples:
  platformctl sdn status
```

**Output:**
```
SDN Status
==========

OVSDB Connection:
  Socket: /var/run/openvswitch/db.sock
  Status: connected
  Database: Open_vSwitch

Bridges:
  br0: 3 ports, OpenFlow13, 15 flows

Port Authentication:
  Authorized:    5
  Provisioning:  2
  Enrolled:      1
  Quarantined:   0
  Blocked:       0

OpenFlow:
  Protocol: 1.3
  Flows: 15
  Tables: 1
```

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| PLATFORM_OVS_SOCKET | OVSDB socket path |
| PLATFORM_OVS_BRIDGE | Default bridge name |
| PLATFORM_LOG_LEVEL | Logging level |

### Config File

```yaml
# ~/.platformctl.yaml or /etc/trusted-platform/platformctl.yaml
sdn:
  ovsdb_socket: /var/run/openvswitch/db.sock
  default_bridge: br0
  log_level: info
```

## Examples

### Complete Port Setup

```bash
# Create bridge
platformctl sdn bridge create br0

# Add port with provisioning VLAN
platformctl sdn port add br0 eth1 --vlan 998

# Add provisioning flows
platformctl sdn flow add br0 --priority 100 --vlan 998 --ip-proto udp --udp-dst 67 --action normal
platformctl sdn flow add br0 --priority 100 --vlan 998 --ip-proto udp --udp-dst 68 --action normal
platformctl sdn flow add br0 --priority 100 --vlan 998 --ip-proto udp --udp-dst 53 --action normal
platformctl sdn flow add br0 --priority 100 --vlan 998 --ip-proto tcp --tcp-dst 443 --action normal
platformctl sdn flow add br0 --priority 0 --vlan 998 --action drop

# After device enrollment, transition to production
platformctl sdn port set-vlan eth1 100
platformctl sdn policy set-state eth1 authorized
```

### Troubleshooting

```bash
# Check connection status
platformctl sdn status

# Verify flows
platformctl sdn flow list br0 --stats

# Check port state
platformctl sdn port show eth1
platformctl sdn policy show eth1

# Debug with verbose output
platformctl --verbose sdn port show eth1
```

### Block Compromised Device

```bash
# Block port immediately
platformctl sdn policy block eth1

# Verify blocked
platformctl sdn policy show eth1
platformctl sdn flow list br0 | grep eth1

# After remediation, unblock
platformctl sdn policy unblock eth1
```

---

## Overlay Commands

The overlay commands manage the VXLAN overlay network infrastructure.

### Get Overlay Status

```bash
platformctl sdn overlay status [options]

Options:
  --json        Output in JSON format

Examples:
  platformctl sdn overlay status
```

### VTEP Commands

```bash
# List all VTEPs
platformctl sdn overlay vtep list [options]

Options:
  --json        Output in JSON format

# Get VTEP details
platformctl sdn overlay vtep get <node-id> [options]

Options:
  --json        Output in JSON format

Examples:
  platformctl sdn overlay vtep list
  platformctl sdn overlay vtep get node-001
```

### VNI Commands

```bash
# List VNIs
platformctl sdn overlay vni list [options]

Options:
  --json        Output in JSON format

# Create VNI
platformctl sdn overlay vni create --vni <VNI> --vlan <VLAN> --name <NAME>

# Delete VNI
platformctl sdn overlay vni delete <vni>

Examples:
  platformctl sdn overlay vni list
  platformctl sdn overlay vni create --vni 1000100 --vlan 100 --name production
  platformctl sdn overlay vni delete 1000100
```

### Tunnel Commands

```bash
platformctl sdn overlay tunnel list [options]

Options:
  --vni         Filter by VNI
  --json        Output in JSON format

Examples:
  platformctl sdn overlay tunnel list
  platformctl sdn overlay tunnel list --vni 1000100
```

### MAC Commands

```bash
# List remote MACs
platformctl sdn overlay mac list [options]

Options:
  --vni         Filter by VNI
  --json        Output in JSON format

# Forget a MAC
platformctl sdn overlay mac forget <mac> --vni <VNI>

Examples:
  platformctl sdn overlay mac list
  platformctl sdn overlay mac list --vni 1000100
  platformctl sdn overlay mac forget aa:bb:cc:dd:ee:ff --vni 1000100
```

---

## Gateway Commands

The gateway commands manage multi-mode gateway nodes (overlay, edge, transit).

### Get Gateway Status

```bash
platformctl sdn gateway status [options]

Options:
  --json        Output in JSON format

Examples:
  platformctl sdn gateway status
```

### Set Gateway Mode

```bash
platformctl sdn gateway mode set --modes <MODES>

Modes (comma-separated):
  overlay       VXLAN overlay mode
  edge          IoT/P2P edge gateway mode
  transit       BGP transit mode

Examples:
  platformctl sdn gateway mode set --modes overlay
  platformctl sdn gateway mode set --modes overlay,edge
  platformctl sdn gateway mode set --modes overlay,edge,transit
```

### BGP Commands

```bash
# Get BGP status
platformctl sdn gateway bgp status [options]

Options:
  --json        Output in JSON format

# List BGP peers
platformctl sdn gateway bgp peers [options]

Options:
  --json        Output in JSON format

# List announced prefixes
platformctl sdn gateway bgp prefixes [options]

Options:
  --json        Output in JSON format

# Announce prefix
platformctl sdn gateway bgp announce --prefix <PREFIX> --next-hop <NEXT-HOP>

# Withdraw prefix
platformctl sdn gateway bgp withdraw --prefix <PREFIX>

Examples:
  platformctl sdn gateway bgp status
  platformctl sdn gateway bgp peers
  platformctl sdn gateway bgp prefixes
  platformctl sdn gateway bgp announce --prefix 2602:F5BB:1234::/48 --next-hop 2602:F5BB::1
  platformctl sdn gateway bgp withdraw --prefix 2602:F5BB:1234::/48
```

### IPAM Commands (via Gateway)

```bash
# List IPAM pools
platformctl sdn gateway ipam pools [options]

Options:
  --json        Output in JSON format

# Allocate IP from pool
platformctl sdn gateway ipam allocate --pool <POOL-ID> --device <DEVICE-ID> --hostname <HOSTNAME>

# Release IP
platformctl sdn gateway ipam release --ip <IP>

# List allocations
platformctl sdn gateway ipam allocations [options]

Options:
  --pool        Filter by pool ID
  --json        Output in JSON format

Examples:
  platformctl sdn gateway ipam pools
  platformctl sdn gateway ipam allocate --pool prod-v6 --device node-001 --hostname web01
  platformctl sdn gateway ipam release --ip 2602:F5BB:1234::100
  platformctl sdn gateway ipam allocations --pool prod-v6
```

---

## IPAM Commands

The IPAM commands provide direct IP Address Management operations.

### Pool Commands

```bash
# List pools
platformctl sdn ipam pool list [options]

Options:
  --json        Output in JSON format

# Create pool
platformctl sdn ipam pool create --name <NAME> --cidr <CIDR> [options]

Options:
  --gateway     Gateway address for the pool
  --dns         DNS server(s) (comma-separated)
  --lease       Lease duration (default: 24h)
  --json        Output in JSON format

# Delete pool
platformctl sdn ipam pool delete <pool-id>

Examples:
  platformctl sdn ipam pool list
  platformctl sdn ipam pool create --name prod-v4 --cidr 10.0.0.0/24 --gateway 10.0.0.1
  platformctl sdn ipam pool create --name prod-v6 --cidr 2602:F5BB:1234::/64 --gateway 2602:F5BB:1234::1
  platformctl sdn ipam pool delete prod-v4
```

### Allocation Commands

```bash
# Allocate IP
platformctl sdn ipam allocate --pool <POOL-ID> --device <DEVICE-ID> --hostname <HOSTNAME>

# Release IP
platformctl sdn ipam release <ip>

# List allocations
platformctl sdn ipam list [options]

Options:
  --pool        Filter by pool ID
  --json        Output in JSON format

Examples:
  platformctl sdn ipam allocate --pool prod-v4 --device vm-001 --hostname webserver
  platformctl sdn ipam release 10.0.0.50
  platformctl sdn ipam list
  platformctl sdn ipam list --pool prod-v4
```

## Zone Commands

`platformctl sdn zone` manages network trust zones — named policy boundaries
that govern isolation, internet ingress, OOB access, and inter-zone routing.

### List Zones

```bash
platformctl sdn zone list [--lifecycle-role <role>] [--json]

Options:
  --lifecycle-role  Filter zones by role: provisioning|quarantine (empty = all)
  --json            Output in JSON format

Examples:
  platformctl sdn zone list
  platformctl sdn zone list --lifecycle-role provisioning
```

### Create Zone

```bash
platformctl sdn zone create --name <name> [options]

Options:
  --name                Zone name (required)
  --isolate             Isolate this zone from all others (default: false)
  --isolate-per-tenant  Isolate traffic per tenant within the zone
  --internet-ingress    Allow inbound internet traffic
  --oob                 Mark zone as out-of-band management
  --lifecycle-role      provisioning|quarantine
  --allow-to            Comma-separated list of zones this zone may reach
  --isolate-from        Comma-separated list of zones this zone is isolated from
  --json                Output in JSON format

Examples:
  platformctl sdn zone create --name dmz --internet-ingress
  platformctl sdn zone create --name quarantine --lifecycle-role quarantine --isolate
```

### Update Zone

```bash
platformctl sdn zone update --name <name> [options]

Options: same policy flags as create (all optional)

Examples:
  platformctl sdn zone update --name dmz --isolate-per-tenant
```

The response includes `restart_required: true` when a policy-relevant field
(Isolate, OOB, IsolatePerTenant, InternetIngress, AllowTo, IsolateFrom) changes.

### Delete Zone

```bash
platformctl sdn zone delete --name <name>

Examples:
  platformctl sdn zone delete dmz
```

Fails when the zone is the sole holder of the `provisioning` or `quarantine`
lifecycle role — the platform requires at least one zone for each special role.

### Assign Network to Zone

```bash
platformctl sdn zone assign --network <cidr-or-name> --zone <zone-name>

Options:
  --network  Network segment identifier (required)
  --zone     Target zone name (required)

Examples:
  platformctl sdn zone assign --network corp-lan --zone trusted
  platformctl sdn zone assign --network 10.0.0.0/24 --zone dmz
```
