# Cluster CLI Usage

## Overview

The `platformctl cluster` command group provides management operations for go-trusted-platform cluster deployments.

## Commands

```
platformctl cluster <command>

Commands:
  bootstrap    Initialize a new cluster
  join         Join an existing cluster
  leave        Leave the cluster gracefully
  status       Show cluster and node status
  nodes        List all cluster nodes
  remove       Remove a node from the cluster
  transfer     Transfer leadership to another node

Flags:
  -h, --help   Help for cluster commands
```

## Bootstrap

Initialize a new cluster with the current node as the initial leader.

### Usage

```bash
platformctl cluster bootstrap [flags]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--node-id` | uint64 | required | Unique node identifier |
| `--listen-addr` | string | required | Raft listen address (host:port) |
| `--advertise-addr` | string | listen-addr | Raft advertise address |
| `--data-dir` | string | config | QuicBaaS data directory |
| `--metadata` | string | - | Node metadata (key=value,...) |

### Examples

```bash
# Bootstrap with minimal configuration
platformctl cluster bootstrap \
  --node-id 1 \
  --listen-addr 192.168.1.10:63000

# Bootstrap with explicit advertise address
platformctl cluster bootstrap \
  --node-id 1 \
  --listen-addr 0.0.0.0:63000 \
  --advertise-addr 192.168.1.10:63000

# Bootstrap with metadata
platformctl cluster bootstrap \
  --node-id 1 \
  --listen-addr 192.168.1.10:63000 \
  --metadata "datacenter=dc1,rack=rack1"
```

### Output

```
Cluster bootstrapped successfully.

Cluster ID: cluster-abc123
Node ID: 1
State: leader
Address: 192.168.1.10:63000

To add more nodes, run on each node:
  platformctl cluster join --node-id <ID> --listen-addr <ADDR> --join 192.168.1.10:63000
```

## Join

Join an existing cluster via a known member.

### Usage

```bash
platformctl cluster join [flags]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--node-id` | uint64 | required | Unique node identifier |
| `--listen-addr` | string | required | Raft listen address |
| `--advertise-addr` | string | listen-addr | Raft advertise address |
| `--join` | string[] | required | Existing member addresses |
| `--metadata` | string | - | Node metadata |
| `--timeout` | duration | 30s | Join operation timeout |

### Examples

```bash
# Join via single member
platformctl cluster join \
  --node-id 2 \
  --listen-addr 192.168.1.11:63000 \
  --join 192.168.1.10:63000

# Join via multiple members (for redundancy)
platformctl cluster join \
  --node-id 3 \
  --listen-addr 192.168.1.12:63000 \
  --join 192.168.1.10:63000 \
  --join 192.168.1.11:63000

# Join with timeout
platformctl cluster join \
  --node-id 2 \
  --listen-addr 192.168.1.11:63000 \
  --join 192.168.1.10:63000 \
  --timeout 60s
```

### Output

```
Successfully joined cluster.

Cluster ID: cluster-abc123
Node ID: 2
State: follower
Leader: 192.168.1.10:63000
```

## Leave

Gracefully leave the cluster.

### Usage

```bash
platformctl cluster leave [flags]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--force` | bool | false | Force leave without graceful shutdown |
| `--timeout` | duration | 30s | Leave operation timeout |

### Examples

```bash
# Graceful leave
platformctl cluster leave

# Force leave
platformctl cluster leave --force
```

### Output

```
Successfully left cluster.

Node 2 removed from cluster membership.
Local data retained in /var/lib/platform/quicbaas
```

## Status

Display cluster and node status.

### Usage

```bash
platformctl cluster status [flags]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-o, --output` | string | text | Output format (text, json, yaml) |
| `--details` | bool | false | Show detailed status |

### Examples

```bash
# Basic status
platformctl cluster status

# Detailed status in JSON
platformctl cluster status --details -o json

# YAML output
platformctl cluster status -o yaml
```

### Output (Text)

```
Cluster Status: healthy
Nodes: 3/3 healthy

Cluster Information:
  Cluster ID:    cluster-abc123
  Leader:        192.168.1.10:63000 (Node 1)
  Term:          5
  Commit Index:  12345

Local Node:
  Node ID:       1
  Address:       192.168.1.10:63000
  State:         leader
  Health:        healthy
  Uptime:        2h 15m 30s
```

### Output (JSON)

```json
{
  "cluster": {
    "cluster_id": "cluster-abc123",
    "state": "healthy",
    "total_nodes": 3,
    "healthy_nodes": 3,
    "leader_id": 1,
    "leader_addr": "192.168.1.10:63000",
    "current_term": 5,
    "commit_index": 12345
  },
  "local_node": {
    "node_id": 1,
    "address": "192.168.1.10:63000",
    "raft_state": "leader",
    "health": "healthy",
    "uptime": "2h15m30s"
  }
}
```

## Nodes

List all nodes in the cluster.

### Usage

```bash
platformctl cluster nodes [flags]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-o, --output` | string | table | Output format (table, json, yaml, wide) |
| `--healthy` | bool | false | Show only healthy nodes |

### Examples

```bash
# Table output
platformctl cluster nodes

# Wide output with more columns
platformctl cluster nodes -o wide

# JSON output
platformctl cluster nodes -o json

# Only healthy nodes
platformctl cluster nodes --healthy
```

### Output (Table)

```
NODE ID    ADDRESS             STATE      HEALTH     UPTIME
1          192.168.1.10:63000  leader     healthy    2h 15m
2          192.168.1.11:63000  follower   healthy    2h 10m
3          192.168.1.12:63000  follower   healthy    2h 05m
```

### Output (Wide)

```
NODE ID    ADDRESS             STATE      HEALTH     UPTIME     LAST SEEN              APPLIED INDEX
1          192.168.1.10:63000  leader     healthy    2h 15m     2024-01-15T10:30:00Z   12345
2          192.168.1.11:63000  follower   healthy    2h 10m     2024-01-15T10:30:00Z   12343
3          192.168.1.12:63000  follower   healthy    2h 05m     2024-01-15T10:30:00Z   12340
```

## Remove

Remove a node from the cluster (leader only operation).

### Usage

```bash
platformctl cluster remove <node-id> [flags]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--force` | bool | false | Force removal without graceful shutdown |
| `--yes` | bool | false | Skip confirmation prompt |

### Examples

```bash
# Remove with confirmation
platformctl cluster remove 2

# Force remove without confirmation
platformctl cluster remove 2 --force --yes
```

### Output

```
Are you sure you want to remove node 2 from the cluster? [y/N] y

Node 2 removed from cluster successfully.

Remaining nodes:
  Node 1: 192.168.1.10:63000 (leader)
  Node 3: 192.168.1.12:63000 (follower)
```

## Transfer

Transfer leadership to another node.

### Usage

```bash
platformctl cluster transfer <target-node-id> [flags]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--timeout` | duration | 30s | Transfer operation timeout |

### Examples

```bash
# Transfer leadership to node 2
platformctl cluster transfer 2

# Transfer with custom timeout
platformctl cluster transfer 2 --timeout 60s
```

### Output

```
Leadership transferred successfully.

Previous Leader: Node 1 (192.168.1.10:63000)
New Leader:      Node 2 (192.168.1.11:63000)
```

## Global Flags

These flags apply to all cluster commands:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--config` | string | /etc/platformd/config.yaml | Configuration file path |
| `--server` | string | localhost:63001 | API server address |
| `--cert` | string | - | Client certificate path |
| `--key` | string | - | Client key path |
| `--ca` | string | - | CA certificate path |
| `-v, --verbose` | bool | false | Verbose output |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PLATFORM_CONFIG` | Configuration file path |
| `PLATFORM_SERVER` | API server address |
| `PLATFORM_CERT` | Client certificate path |
| `PLATFORM_KEY` | Client key path |
| `PLATFORM_CA` | CA certificate path |

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Connection failed |
| 4 | Authentication failed |
| 5 | Not leader (for leader-only operations) |
| 6 | No quorum |

## Scripting Examples

### Automated Cluster Setup

```bash
#!/bin/bash
set -e

# Bootstrap first node
ssh node1 platformctl cluster bootstrap \
  --node-id 1 \
  --listen-addr 192.168.1.10:63000

# Wait for leader
sleep 5

# Join remaining nodes
for i in 2 3; do
  ssh node$i platformctl cluster join \
    --node-id $i \
    --listen-addr 192.168.1.$((9+i)):63000 \
    --join 192.168.1.10:63000
  sleep 2
done

# Verify cluster
platformctl cluster status
platformctl cluster nodes
```

### Health Check Script

```bash
#!/bin/bash

STATUS=$(platformctl cluster status -o json)
HEALTHY=$(echo "$STATUS" | jq -r '.cluster.state')

if [ "$HEALTHY" != "healthy" ]; then
  echo "Cluster is not healthy: $HEALTHY"
  exit 1
fi

NODES=$(echo "$STATUS" | jq -r '.cluster.healthy_nodes')
TOTAL=$(echo "$STATUS" | jq -r '.cluster.total_nodes')

if [ "$NODES" -lt "$TOTAL" ]; then
  echo "Warning: $NODES/$TOTAL nodes healthy"
  exit 1
fi

echo "Cluster healthy: $NODES/$TOTAL nodes"
exit 0
```

### Backup Before Maintenance

```bash
#!/bin/bash
set -e

NODE_ID=$1

# Check if node is leader
IS_LEADER=$(platformctl cluster status -o json | jq -r '.local_node.raft_state')

if [ "$IS_LEADER" = "leader" ]; then
  # Transfer leadership before maintenance
  OTHER_NODE=$(platformctl cluster nodes -o json | \
    jq -r ".nodes[] | select(.node_id != $NODE_ID) | .node_id" | head -1)
  platformctl cluster transfer $OTHER_NODE
fi

# Now safe to perform maintenance
echo "Node $NODE_ID ready for maintenance"
```

## Related Documentation

- [API Reference](api-reference.md) - REST and gRPC API
- [Configuration](configuration.md) - Cluster configuration
- [Bootstrap](bootstrap.md) - Detailed setup procedures
- [Operations](operations.md) - Operational runbooks
