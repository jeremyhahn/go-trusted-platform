# Cluster Architecture

This document describes the cluster architecture of go-trusted-platform, including Raft consensus via QuicBaaS, node roles, and state replication.

## Overview

The cluster architecture uses QuicBaaS's Raft consensus to provide strongly consistent, distributed state across multiple nodes. All cluster nodes run identical platformd instances with embedded QuicBaaS, forming a single logical cluster.

## Architecture Diagram

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                           CLUSTER ARCHITECTURE                                ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║   ┌─────────────────────────┐     ┌─────────────────────────┐                 ║
║   │       Clients           │     │    External Systems     │                 ║
║   │  (platformctl, API)     │     │   (ACME, SDN devices)   │                 ║
║   └───────────┬─────────────┘     └───────────┬─────────────┘                 ║
║               │                               │                               ║
║               └───────────────┬───────────────┘                               ║
║                               │                                               ║
║   ┌───────────────────────────▼───────────────────────────┐                   ║
║   │                    Load Balancer                      │                   ║
║   │              (optional, for HA access)                │                   ║
║   └───────────────────────────┬───────────────────────────┘                   ║
║                               │                                               ║
║       ┌───────────────────────┼────────────────────────┐                      ║
║       │                       │                        │                      ║
║       ▼                       ▼                        ▼                      ║
║   ┌───────┐               ┌────────┐                ┌────────┐                ║
║   │Node 1 │               │Node 2  │                │Node 3  │                ║
║   │Leader │               │Follower│                │Follower│                ║
║   └───┬───┘               └───┬────┘                └───┬────┘                ║
║       │                       │                        │                      ║
║   ┌───▼───┐               ┌───▼───┐                ┌───▼───┐                  ║
║   │platfmd│               │platfmd│                │platfmd│                  ║
║   │       │               │       │                │       │                  ║
║   │ ┌───┐ │               │ ┌───┐ │                │ ┌───┐ │                  ║
║   │ │API│ │               │ │API│ │                │ │API│ │                  ║
║   │ └───┘ │               │ └───┘ │                │ └───┘ │                  ║
║   │       │               │       │                │       │                  ║
║   │ ┌───┐ │               │ ┌───┐ │                │ ┌───┐ │                  ║
║   │ │SDN│ │               │ │SDN│ │                │ │SDN│ │                  ║
║   │ └───┘ │               │ └───┘ │                │ └───┘ │                  ║
║   │       │               │       │                │       │                  ║
║   │ ┌───┐ │               │ ┌───┐ │                │ ┌───┐ │                  ║
║   │ │CA │ │               │ │CA │ │                │ │CA │ │                  ║
║   │ └───┘ │               │ └───┘ │                │ └───┘ │                  ║
║   └───┬───┘               └───┬───┘                └───┬───┘                  ║
║       │                       │                        │                      ║
║   ┌───▼───────────────────────▼────────────────────────▼───┐                  ║
║   │                     QuicBaaS Raft                      │                  ║
║   │                                                        │                  ║
║   │   Node 1 (Leader)  ◀───▶  Node 2  ◀───▶  Node 3        │                  ║
║   │   • Log replication                                    │                  ║
║   │   • Leader election                                    │                  ║
║   │   • Snapshot management                                │                  ║
║   └────────────────────────────────────────────────────────┘                  ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

## Raft Consensus

### Leader Election

QuicBaaS implements the Raft consensus algorithm for distributed coordination. Key characteristics:

| Property | Description |
|----------|-------------|
| **Election Timeout** | 150-300ms randomized timeout before starting election |
| **Heartbeat Interval** | 50ms between leader heartbeats |
| **Term** | Monotonically increasing logical clock |
| **Log Index** | Sequential position in the replicated log |

Election process:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        LEADER ELECTION                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Follower         Candidate           Leader                       │
│   ┌──────┐         ┌────────┐          ┌──────┐                     │
│   │      │  elect  │        │  wins    │      │                     │
│   │  F   │────────▶│   C    │─────────▶│  L   │                     │
│   │      │         │        │          │      │                     │
│   └──────┘         └────────┘          └──────┘                     │
│      ▲                  │                  │                        │
│      │     loses/       │                  │                        │
│      │     timeout      │   heartbeats     │                        │
│      └──────────────────┴◀─────────────────┘                        │
│                                                                     │
│   States:                                                           │
│   • Follower: Receives heartbeats, forwards writes to leader        │
│   • Candidate: Requesting votes for leadership                      │
│   • Leader: Handles all writes, replicates to followers             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Log Replication

All writes go through the Raft log for consensus:

```
Client              Leader                Followers
   │                   │                      │
   │── Write ─────────▶│                      │
   │                   │                      │
   │                   │── AppendEntries ────▶│
   │                   │                      │
   │                   │◀──── ACK ────────────│
   │                   │     (majority)       │
   │                   │                      │
   │                   │── Commit ───────────▶│
   │                   │                      │
   │◀── Success ───────│                      │
```

Log entry structure:
- **Term**: Election term when entry was created
- **Index**: Sequential position in log
- **Command**: Serialized state machine operation
- **Checksum**: CRC32 for integrity verification

### Quorum Requirements

Raft requires a majority quorum for all operations:

| Cluster Size | Quorum | Fault Tolerance |
|--------------|--------|-----------------|
| 1 node | 1 | 0 failures |
| 3 nodes | 2 | 1 failure |
| 5 nodes | 3 | 2 failures |
| 7 nodes | 4 | 3 failures |

**Recommendation**: Use 3 or 5 nodes for production. Odd numbers prevent split-brain scenarios.

## Node Roles

### Leader Node

The leader handles all write operations and coordinates replication:

- Accepts client write requests
- Appends entries to local log
- Replicates entries to followers via AppendEntries RPC
- Commits entries after quorum acknowledgment
- Sends periodic heartbeats to maintain leadership

### Follower Node

Followers replicate state and can serve reads:

- Receive and apply log entries from leader
- Respond to AppendEntries RPCs
- Participate in leader elections
- Forward write requests to leader
- Serve linearizable reads (with leader confirmation)

### Candidate Node

Temporary state during elections:

- Increments term and votes for self
- Sends RequestVote RPCs to other nodes
- Becomes leader if receives majority votes
- Returns to follower if another leader elected

## State Machine

QuicBaaS's state machine applies committed log entries:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         STATE MACHINE                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Raft Log                 State Machine              Storage       │
│   ┌──────┐                 ┌──────────┐               ┌──────┐      │
│   │Entry1│                 │          │               │      │      │
│   │Entry2│  ──▶ Apply ──▶  │ Executor │  ──▶ Write ─▶ │Pebble│      │
│   │Entry3│                 │          │               │  DB  │      │
│   │...   │                 └──────────┘               │      │      │
│   └──────┘                                            └──────┘      │
│                                                                     │
│   Operations:                                                       │
│   • Put(entityType, id, data)                                       │
│   • Delete(entityType, id)                                          │
│   • BatchPut(entries)                                               │
│   • BatchDelete(ids)                                                │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Cluster-Aware Services

The following services replicate state via QuicBaaS:

### SDN Controller

- OVS bridge configurations
- Port states and policies
- Flow rules and priorities
- VLAN assignments

### Certificate Authority

- CA signing keys (wrapped)
- Issued certificates
- Certificate revocation lists (CRLs)
- ACME account registrations

### DNS Server

- Zone records
- Dynamic DNS updates
- Service discovery entries

### Device Profiles

- Profile definitions
- Attestation policies
- Compliance requirements

### Tenant Manager

- Tenant configurations
- Resource quotas
- DEK key handles

## Consistency Levels

QuicBaaS supports three read consistency levels:

| Level | Latency | Guarantee |
|-------|---------|-----------|
| **Linearizable** | 1-5ms | Reads see most recent committed write |
| **Strong** | 10-50ms | Full Raft consensus per read |
| **Eventual** | <1ms | May return stale data |

**Default**: Linearizable (recommended for most use cases)

Linearizable reads use the ReadIndex optimization:
1. Leader confirms it's still leader via heartbeats
2. Returns local state after confirmation
3. No Raft log append required

## Snapshots

QuicBaaS takes periodic snapshots to compact the log:

```
┌─────────────────────────────────────────────────────────────────────┐
│                          SNAPSHOTS                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Raft Log                 Snapshot                                 │
│   ┌──────┬──────┬──────┐   ┌──────────┐                             │
│   │  1   │  2   │  3   │   │          │                             │
│   ├──────┼──────┼──────┤   │ Snapshot │                             │
│   │  4   │  5   │  6   │   │ @ idx 6  │                             │
│   ├──────┼──────┼──────┤   │          │                             │
│   │  7   │  8   │  9   │   └──────────┘                             │
│   └──────┴──────┴──────┘                                            │
│                                                                     │
│   After snapshot @ index 6:                                         │
│   • Entries 1-6 can be discarded                                    │
│   • Snapshot contains full state at index 6                         │
│   • New nodes bootstrap from snapshot + entries 7+                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

Configuration:
- `snapshot_interval`: Time between snapshots (default: 30s)
- `snapshot_threshold`: Minimum log entries before snapshot (default: 10000)

## Network Topology

### Port Requirements

| Port | Protocol | Purpose |
|------|----------|---------|
| 63000 | TCP | Raft consensus (peer-to-peer) |
| 63001 | TCP | gRPC API (client access) |
| 63002 | TCP | REST API (optional) |

### Firewall Rules

All cluster nodes must allow:
- Inbound TCP 63000 from other cluster nodes
- Inbound TCP 63001 from clients and load balancers

Example iptables:
```bash
# Allow Raft between cluster nodes
iptables -A INPUT -p tcp --dport 63000 -s 192.168.1.10 -j ACCEPT
iptables -A INPUT -p tcp --dport 63000 -s 192.168.1.11 -j ACCEPT
iptables -A INPUT -p tcp --dport 63000 -s 192.168.1.12 -j ACCEPT

# Allow API access
iptables -A INPUT -p tcp --dport 63001 -j ACCEPT
```

## Failure Handling

### Node Failure

When a node fails:

1. Leader detects missing heartbeat acknowledgments
2. If leader fails, followers start election after timeout
3. New leader elected from remaining nodes
4. Operations continue with quorum

Recovery Time Objective (RTO): < 10 seconds

### Network Partition

During network partition:

- Majority partition maintains quorum and continues operating
- Minority partition becomes read-only (stale reads if eventual consistency)
- When partition heals, minority nodes sync from leader

### Data Recovery

QuicBaaS provides durability through:

1. Write-ahead log (WAL) for crash recovery
2. Periodic snapshots for fast recovery
3. Raft log replication across nodes

## Related Documentation

- [Configuration](configuration.md) - Cluster configuration options
- [Bootstrap](bootstrap.md) - Cluster setup procedures
- [Operations](operations.md) - Operational runbooks
- [QuicBaaS Integration](../architecture/quicbaas-integration.md) - Service layer details
