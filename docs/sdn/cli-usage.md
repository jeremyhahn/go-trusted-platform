# SDN CLI Usage

> **Status: REFERENCE** · Last verified: 2026-10-15
> The `platformctl sdn` commands, by example.

## Overview

The `platformctl sdn` command provides command-line management of the SDN
subsystem, including bridge, port, flow, VLAN, policy, overlay, gateway,
IPAM, and zone operations.

## Command Structure

```
platformctl sdn <subcommand> [options]

Subcommands:
  bridge    Manage OVS bridges
  port      Manage OVS ports
  flow      Manage OpenFlow rules
  vlan      Manage VLANs
  policy    Manage network policies
  overlay   Manage VXLAN overlay network (VTEPs, VNIs, tunnels, MACs)
  gateway   Manage gateway nodes (status, snapshot, overlay, modes, BGP,
            load balancer, NAT64, perf)
  ipam      Manage IP address pools and allocations
  zone      Manage underlay zones
```

Global flags apply to every command:

```
-o, --output       Output format: table, json, yaml (env PLATFORMCTL_OUTPUT)
    --transport    SDK transport override: unix, grpc, rest, quic, mcp, embedded
                   (env PLATFORMCTL_TRANSPORT)
    --server       Server address override (env PLATFORMCTL_SERVER)
    --server-name  TLS SNI / verification hostname override (env PLATFORMCTL_SERVER_NAME)
    --context      Context to use (env PLATFORMCTL_CONTEXT)
-c, --config       Config file (env PLATFORMCTL_CONFIG)
-v, --verbose      Verbose output
    --no-color     Disable colored output (env NO_COLOR)
```

## Bridge Commands

### Create Bridge

```bash
platformctl sdn bridge create --id <id> --name <name> --type <type> [options]

Options:
  --id            Bridge ID (required)
  --name          Bridge name (required)
  --type          Bridge type: ovs, linux, vxlan (required)
  --description   Bridge description
  --datapath-id   Datapath ID
  --fail-mode     Fail mode: secure, standalone
  --stp           Enable STP
  --rstp          Enable RSTP
  --mtu           MTU size

Examples:
  platformctl sdn bridge create --id br0 --name br0 --type ovs
  platformctl sdn bridge create --id br1 --name br1 --type ovs --fail-mode secure
```

### Get Bridge

```bash
platformctl sdn bridge get <bridge-id>
```

### List Bridges

```bash
platformctl sdn bridge list [options]

Options:
  --type      Filter by bridge type: ovs, linux, vxlan
  --status    Filter by status: up, down, error
  --limit     Maximum number of results
  --cursor    Pagination cursor

Examples:
  platformctl sdn bridge list
  platformctl sdn bridge list -o json
```

### Delete Bridge

```bash
platformctl sdn bridge delete <bridge-id> [options]

Options:
  --force          Force deletion even if bridge has ports
  --delete-ports   Delete all ports on the bridge
  --delete-flows   Delete all flows on the bridge

Examples:
  platformctl sdn bridge delete br0
```

## Port Commands

### Add Port

```bash
platformctl sdn port add --bridge <bridge-id> --id <port-id> --name <name> --type <type> [options]

Options:
  --bridge        Bridge ID (required)
  --id            Port ID (required)
  --name          Port name (required)
  --type          Port type: internal, physical, tap, veth, vxlan, gre (required)
  --tag           VLAN tag for access ports
  --interface     Interface name to attach
  --mac           MAC address
  --mtu           MTU size
  --admin-state   Administrative state: up, down

Examples:
  platformctl sdn port add --bridge br0 --id eth0 --name eth0 --type physical
  platformctl sdn port add --bridge br0 --id eth1 --name eth1 --type physical --tag 100
```

### Delete Port

```bash
platformctl sdn port delete <port-id> --bridge <bridge-id>
```

### Get Port State

```bash
platformctl sdn port state <port-id> --bridge <bridge-id>
```

### Set Port State

```bash
platformctl sdn port set-state <port-id> --bridge <bridge-id> [options]

Options:
  --admin-state    Administrative state: up, down (required)
  --ingress-rate   Ingress policing rate in bps, a whole multiple of 1000 (0 leaves policing unchanged)
  --ingress-burst  Ingress policing burst in bits, a whole multiple of 1000 (needs --ingress-rate)
  --egress-rate    Egress shaping rate in bps (0 leaves shaping unchanged)
  --egress-burst   Egress shaping burst in bits (needs --egress-rate)

Examples:
  platformctl sdn port set-state eth0 --bridge br0 --admin-state down
  platformctl sdn port set-state eth0 --bridge br0 --admin-state up --ingress-rate 10000000 --ingress-burst 1000000
  platformctl sdn port set-state eth0 --bridge br0 --admin-state up --egress-rate 20000000 --egress-burst 2000000
```

### Port Statistics

```bash
platformctl sdn port stats <port-id> --bridge <bridge-id>
```

## Flow Commands

### Add Flow

```bash
platformctl sdn flow add --bridge <bridge-id> --id <flow-id> --table <n> --priority <n> [options]

Options:
  --bridge       Bridge ID (required)
  --id           Required; kept in the flow's metadata only (the flow's
                 ID is the flow-0x<cookie> the add answers)
  --table        Flow table number (required)
  --priority     Flow priority (required)
  --in-port      Match on input port
  --dl-src       Match on source MAC
  --dl-dst       Match on destination MAC
  --dl-type      Match on ethertype
  --nw-src       Match on source IP
  --nw-dst       Match on destination IP
  --action       Action type (can be repeated)
  --action-port  Output port for action

Examples:
  # Drop all traffic from port 1
  platformctl sdn flow add --bridge br0 --id drop-p1 --table 0 --priority 100 --in-port 1 --action drop

  # Forward port 1 to port 2
  platformctl sdn flow add --bridge br0 --id fwd-p1 --table 0 --priority 100 --in-port 1 --action output --action-port 2
```

### Delete Flow

```bash
platformctl sdn flow delete <flow-id> --bridge <bridge-id>

Examples:
  platformctl sdn flow delete flow-0x1a2b3c --bridge br0
```

`<flow-id>` is the `flow-0x<cookie>` ID that `flow add` answers and
`flow list` shows.

### List Flows

```bash
platformctl sdn flow list --bridge <bridge-id> [options]

Options:
  --table     Filter by table number
  --limit     Maximum number of results
  --cursor    Pagination cursor

Examples:
  platformctl sdn flow list --bridge br0
  platformctl sdn flow list --bridge br0 --table 0 -o json
```

## VLAN Commands

```bash
# Create a VLAN
platformctl sdn vlan create --id <1-4094> --name <name> [--description <text>] [--bridge <bridge-id> ...]

# Delete a VLAN
platformctl sdn vlan delete <vlan-id> --bridge <bridge-id>

# List VLANs
platformctl sdn vlan list [--bridge <bridge-id>] [--limit <n>] [--cursor <c>]

Examples:
  platformctl sdn vlan create --id 100 --name production --bridge br0
  platformctl sdn vlan list --bridge br0
  platformctl sdn vlan delete 100 --bridge br0
```

## Policy Commands

### Apply Policy

```bash
platformctl sdn policy apply --id <id> --name <name> --type <type> --priority <n> --bridge <bridge-id> [options]

Options:
  --id            Policy ID (required)
  --name          Policy name (required)
  --type          Policy type: acl, qos, nat, firewall, routing (required)
  --priority      Policy priority (required)
  --bridge        Bridge ID to apply policy to (required)
  --description   Policy description
  --enabled       Enable the policy immediately

Examples:
  platformctl sdn policy apply --id acl-1 --name web-acl --type acl --priority 100 --bridge br0 --enabled
```

### Get Policy

```bash
platformctl sdn policy get <policy-id>
```

### List Policies

```bash
platformctl sdn policy list [options]

Options:
  --type      Filter by policy type
  --target    Filter by target ID
  --limit     Maximum number of results
  --cursor    Pagination cursor

Examples:
  platformctl sdn policy list
  platformctl sdn policy list --type acl
```

## Overlay Commands

The overlay commands manage the VXLAN overlay network infrastructure.

### Get Overlay Status

```bash
platformctl sdn overlay status
platformctl sdn overlay status -o json
```

### VTEP Commands

```bash
# List all VTEPs
platformctl sdn overlay vtep list

# Get VTEP details
platformctl sdn overlay vtep get <node-id>

Examples:
  platformctl sdn overlay vtep list
  platformctl sdn overlay vtep get node-001
```

### VNI Commands

```bash
# List VNIs
platformctl sdn overlay vni list

# Create VNI
platformctl sdn overlay vni create --vni <VNI> --vlan <VLAN> [--name <NAME>]
# (--name is accepted and not stored)

# Delete VNI
platformctl sdn overlay vni delete <vni>

Examples:
  platformctl sdn overlay vni list
  platformctl sdn overlay vni create --vni 1000100 --vlan 100 --name production
  platformctl sdn overlay vni delete 1000100
```

### Tunnel Commands

On platformd the overlay controller holds the local VTEP and the VNIs
only, so `tunnel list` and `mac list` print nothing and `mac forget`
answers not found; see [overlay/operations.md](overlay/operations.md).
The remote VTEPs a gateway admitted are listed with
`platformctl sdn gateway overlay vteps`.


```bash
platformctl sdn overlay tunnel list [--vni <VNI>]

Examples:
  platformctl sdn overlay tunnel list
  platformctl sdn overlay tunnel list --vni 1000100
```

### MAC Commands

```bash
# List remote MACs
platformctl sdn overlay mac list [--vni <VNI>]

# Forget a MAC
platformctl sdn overlay mac forget <mac> --vni <VNI>

Examples:
  platformctl sdn overlay mac list
  platformctl sdn overlay mac list --vni 1000100
  platformctl sdn overlay mac forget aa:bb:cc:dd:ee:ff --vni 1000100
```

## Gateway Commands

The gateway commands manage gateway nodes, which run the service sections
their configuration enables. See the [gateway CLI reference](../gateway/cli.md)
for full details.

### Get Gateway Status

```bash
platformctl sdn gateway status
platformctl sdn gateway status -o json
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
platformctl sdn gateway bgp status

# List BGP peers
platformctl sdn gateway bgp peers

# List announced prefixes
platformctl sdn gateway bgp routes

# Announce prefix
platformctl sdn gateway bgp announce --prefix <PREFIX> [--next-hop <NEXT-HOP>]

# Withdraw prefix
platformctl sdn gateway bgp withdraw --prefix <PREFIX>

Examples:
  platformctl sdn gateway bgp status
  platformctl sdn gateway bgp peers
  platformctl sdn gateway bgp routes
  platformctl sdn gateway bgp announce --prefix 2001:DB8:1234::/48 --next-hop 2001:db8::1
  platformctl sdn gateway bgp withdraw --prefix 2001:DB8:1234::/48
```

### Load Balancer Commands

```bash
# Load balancer health
platformctl sdn gateway lb status

# VIP management (IPv4 VIP; --protocol tcp or udp, default tcp;
# backends as address:port[:weight])
platformctl sdn gateway lb vip add --protocol tcp --address <VIP> --port <PORT> \
  --backend <ADDR:PORT[:WEIGHT]> [--backend ...] [--algorithm hash|round-robin]
platformctl sdn gateway lb vip list
platformctl sdn gateway lb vip get --protocol tcp --address <VIP> --port <PORT>
platformctl sdn gateway lb vip set-backends --protocol tcp --address <VIP> --port <PORT> \
  --backend <ADDR:PORT[:WEIGHT]> [--backend ...]
platformctl sdn gateway lb vip remove --protocol tcp --address <VIP> --port <PORT>
```

### Performance Commands

```bash
# Flow programming throughput (mutates bridge flow tables)
platformctl sdn gateway perf flows --count 1000 --batch

# Live datapath counters (cache hits/misses, hw-offload state)
platformctl sdn gateway perf datapath [--bridge <bridge>]

# Conntrack table summary
platformctl sdn gateway perf conntrack [--zone <zone>]
```

## IPAM Commands

### Pool Commands

```bash
# List pools
platformctl sdn ipam pool list [--zone <zone>]

# Get a pool
platformctl sdn ipam pool get --id <pool-id>

# Create pool
platformctl sdn ipam pool create --name <NAME> --cidr <CIDR> [options]

Options:
  --id             Optional pool ID (generated if omitted)
  --gateway        Gateway IP address within the CIDR
  --zone           Underlay zone, e.g. 'control-plane' or 'provisioning'
  --description    Description of the pool's purpose
  --lease-seconds  Default lease duration in seconds (0 = never expire)
  --reserved       Prefixes (CIDR) that are never allocatable (repeatable)
  --range-start    First address of the dynamic allocation window
  --range-end      Last address of the dynamic allocation window

# Update pool
platformctl sdn ipam pool update --id <pool-id> [--name ...] [--gateway ...] [--zone ...]
  [--description ...] [--lease-seconds ...] [--reserved ...] [--range-start ...] [--range-end ...]

# Delete pool
platformctl sdn ipam pool delete --id <pool-id>

Examples:
  platformctl sdn ipam pool list
  platformctl sdn ipam pool create --name prod-v4 --cidr 10.0.0.0/24 --gateway 10.0.0.1
  platformctl sdn ipam pool create --name prod-v6 --cidr 2001:DB8:1234::/64 --gateway 2001:DB8:1234::1
  platformctl sdn ipam pool delete --id prod-v4
```

### Allocation Commands

```bash
# Allocate IP
platformctl sdn ipam allocate --pool-id <POOL-ID> --device-id <DEVICE-ID> [--hostname <HOSTNAME>]

# Release IP
platformctl sdn ipam release --ip <IP>

# List allocations
platformctl sdn ipam allocations [--pool-id <POOL-ID>]

Examples:
  platformctl sdn ipam allocate --pool-id prod-v4 --device-id vm-001 --hostname webserver
  platformctl sdn ipam release --ip 10.0.0.50
  platformctl sdn ipam allocations
  platformctl sdn ipam allocations --pool-id prod-v4
```

## Zone Commands

`platformctl sdn zone` manages the underlay zones of the reference network:
the nine built-ins at fixed offsets (policy tunable) and owner-defined zones
at offsets 9–99. Overlays (`platform`, `tenant`, `public`) are not zones.

### List Zones

```bash
platformctl sdn zone list [--lifecycle-role <role>]

Options:
  --lifecycle-role  Filter zones by role: provisioning|quarantine (empty = all)

Examples:
  platformctl sdn zone list
  platformctl sdn zone list --lifecycle-role provisioning
```

### Create Zone

Creates an owner-defined zone. Its VLAN, /24 and ULA /64 are derived from
its offset.

```bash
platformctl sdn zone create --name <name> --offset <9-99> --port-class <class> [options]

Options:
  --name               Zone name (required; not platform, tenant, public, trusted)
  --offset             Offset in the environment block, 9-99
  --port-class         gateway or hypervisor (repeatable)
  --isolate            Deny everything except the --allow-to paths
  --isolate-from       Zone this zone never sends to (repeatable)
  --allow-to           zone or zone:service[,service...] (repeatable)
  --service            Service permitted inside the zone (repeatable)
  --internet-ingress   Allow inbound internet traffic
  --reason             privileged_access reason (with --approved-by)
  --approved-by        privileged_access approver (with --reason)

Examples:
  platformctl sdn zone create --name lab --offset 9 --port-class hypervisor --isolate
  platformctl sdn zone create --name lab-dns --offset 10 --port-class gateway \
    --allow-to control-plane:dns --reason "lab resolver" --approved-by owner
```

A path into `control-plane` or `management` beyond the reference defaults
needs `--reason` and `--approved-by`; the daemon writes an audit record for
it.

### Update Zone

```bash
platformctl sdn zone update --name <name> [options]

Options: the policy flags of create; they replace the zone's policy as a whole

Examples:
  platformctl sdn zone update --name storage --isolate --allow-to storage:nvme-tcp
```

A built-in zone keeps its offset, port classes, lifecycle role and OOB flag;
changing them is refused. Every accepted change returns
`restart_required: true`: the network plan is derived at daemon startup.

### Delete Zone

```bash
platformctl sdn zone delete --name <name>

Examples:
  platformctl sdn zone delete --name lab
```

Deleting a built-in omits it from the environment. `fabric`,
`provisioning`, `quarantine` and `control-plane` cannot be removed.

There is no "assign network to zone" command: networks are zones.
