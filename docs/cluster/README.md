# Cluster Overview

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md) and its siblings; describes an API surface and a `platformctl cluster` CLI that do not exist.

The Trusted Platform supports both standalone and clustered deployment modes, with QuicBaaS Raft consensus providing distributed state replication across cluster nodes.

## Key Features

| Feature | Description |
|---------|-------------|
| **Raft Consensus** | QuicBaaS-based Raft consensus for distributed state |
| **Leader Election** | Automatic leader election with failover |
| **State Replication** | Strongly consistent state replication across nodes |
| **Cluster-Aware Services** | SDN, CA, DNS, and Device Profile replication |
| **High Availability** | Automatic failover with < 10 second recovery |
| **Horizontal Scaling** | Add nodes for increased capacity and redundancy |

## Deployment Modes

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                            DEPLOYMENT MODES                                   ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║   STANDALONE MODE                    CLUSTERED MODE                           ║
║   ┌─────────────────┐                ┌───────────────────┐                    ║
║   │                 │                │                   │                    ║
║   │   platformd     │                │   Node 1 (Leader) │                    ║
║   │                 │                │   platformd       │                    ║
║   │   ┌──────────┐  │                │   ┌──────────┐    │                    ║
║   │   │ QuicBaaS │  │                │   │ QuicBaaS │◀───┼────┐               ║
║   │   │ (single) │  │                │   │ (Raft)   │    │    │               ║
║   │   └──────────┘  │                │   └──────────┘    │    │               ║
║   │                 │                │                   │    │               ║
║   │   ┌──────────┐  │                └───────────────────┘    │               ║
║   │   │ OVS      │  │                         │               │               ║
║   │   └──────────┘  │                ┌────────▼──────────┐    │               ║
║   │                 │                │                   │    │               ║
║   └─────────────────┘                │   Node 2          │    │               ║
║                                      │   platformd       │    │               ║
║   • Single node                      │   ┌──────────┐    │    │               ║
║   • Local storage                    │   │ QuicBaaS │◀───┼────┤               ║
║   • No redundancy                    │   │ (Raft)   │    │    │               ║
║                                      │   └──────────┘    │    │               ║
║                                      │                   │    │               ║
║                                      └───────────────────┘    │               ║
║                                               │               │               ║
║                                      ┌────────▼──────────┐    │               ║
║                                      │                   │    │               ║
║                                      │   Node 3          │    │               ║
║                                      │   platformd       │    │               ║
║                                      │   ┌──────────┐    │    │               ║
║                                      │   │ QuicBaaS │◀───┼────┘               ║
║                                      │   │ (Raft)   │    │                    ║
║                                      │   └──────────┘    │                    ║
║                                      │                   │                    ║
║                                      └───────────────────┘                    ║
║                                                                               ║
║                                      • 3 or 5 nodes (odd for quorum)          ║
║                                      • Raft-replicated state                  ║
║                                      • Automatic failover                     ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

## Quick Start

### Standalone Mode (Default)

```bash
# Start platformd in standalone mode (default)
platformctl platform start

# Verify standalone mode
platformctl cluster status

# Output:
# Cluster Status: standalone
# Node ID: 1
# State: leader (single-node)
# QuicBaaS: healthy
```

### Clustered Mode

```bash
# Bootstrap first node (becomes initial leader)
platformctl cluster bootstrap \
  --node-id 1 \
  --listen-addr 192.168.1.10:63000 \
  --advertise-addr 192.168.1.10:63000

# Join additional nodes
platformctl cluster join \
  --node-id 2 \
  --listen-addr 192.168.1.11:63000 \
  --advertise-addr 192.168.1.11:63000 \
  --join 192.168.1.10:63000

platformctl cluster join \
  --node-id 3 \
  --listen-addr 192.168.1.12:63000 \
  --advertise-addr 192.168.1.12:63000 \
  --join 192.168.1.10:63000

# Verify cluster status
platformctl cluster status

# Output:
# Cluster Status: healthy
# Nodes: 3/3 healthy
#
# NODE ID    ADDRESS            STATE      RAFT STATE    UPTIME
# 1          192.168.1.10:63000 healthy    leader        2h 15m
# 2          192.168.1.11:63000 healthy    follower      2h 10m
# 3          192.168.1.12:63000 healthy    follower      2h 05m
```

## Architecture Overview

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                         CLUSTER ARCHITECTURE                                  ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║                              ┌────────────────┐                               ║
║                              │    Clients     │                               ║
║                              │  (platformctl) │                               ║
║                              └───────┬────────┘                               ║
║                                      │                                        ║
║                    ┌─────────────────┼─────────────────┐                      ║
║                    │                 │                 │                      ║
║          ┌─────────▼─────────┐ ┌─────▼───────┐ ┌───────▼───────┐              ║
║          │    Node 1         │ │   Node 2    │ │    Node 3     │              ║
║          │    (Leader)       │ │  (Follower) │ │   (Follower)  │              ║
║          ├───────────────────┤ ├─────────────┤ ├───────────────┤              ║
║          │                   │ │             │ │               │              ║
║          │ ┌───────────────┐ │ │ ┌─────────┐ │ │ ┌───────────┐ │              ║
║          │ │ gRPC/REST API │ │ │ │ gRPC    │ │ │ │ gRPC      │ │              ║
║          │ └───────┬───────┘ │ │ └────┬────┘ │ │ └─────┬─────┘ │              ║
║          │         │         │ │      │      │ │       │       │              ║
║          │ ┌───────▼───────┐ │ │ ┌────▼────┐ │ │ ┌─────▼─────┐ │              ║
║          │ │ Cluster-Aware │ │ │ │ Cluster │ │ │ │ Cluster   │ │              ║
║          │ │ Services      │ │ │ │ Services│ │ │ │ Services  │ │              ║
║          │ │ • SDN         │ │ │ │ (sync)  │ │ │ │ (sync)    │ │              ║
║          │ │ • CA          │ │ │ │         │ │ │ │           │ │              ║
║          │ │ • DNS         │ │ │ │         │ │ │ │           │ │              ║
║          │ └───────┬───────┘ │ │ └────┬────┘ │ │ └─────┬─────┘ │              ║
║          │         │         │ │      │      │ │       │       │              ║
║          │ ┌───────▼───────┐ │ │ ┌────▼────┐ │ │ ┌─────▼─────┐ │              ║
║          │ │ QuicBaaS      │ │ │ │ QuicBaaS│ │ │ │ QuicBaaS  │ │              ║
║          │ │ (Raft Leader) │◀─▶│ │ (Raft)  │◀─▶│ │ (Raft)    │ │              ║
║          │ └───────────────┘ │ │ └─────────┘ │ │ └───────────┘ │              ║
║          │                   │ │             │ │               │              ║
║          └───────────────────┘ └─────────────┘ └───────────────┘              ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

## Documentation Index

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Complete cluster architecture with diagrams |
| [Configuration](configuration.md) | Cluster and node configuration reference |
| [Bootstrap](user.md) | Initial cluster setup and node addition |
| [Operations](user.md) | Operational procedures and maintenance |
| [Cluster-Aware Services](architecture.md) | SDN, CA, DNS clustering details |
| [API Reference](api-reference.md) | Cluster management API |
| [CLI Usage](cli-usage.md) | platformctl cluster commands |
| [Roadmap](../../ROADMAP.md) | Development roadmap and progress tracker |

## Key Concepts

### Raft Consensus

QuicBaaS implements Raft consensus for distributed state:

```
                      Leader Election
┌────────────────────────────────────────────────────────────────────┐
│                                                                    │
│   Initial State       Election           Steady State              │
│   ┌───────────┐       ┌───────────┐      ┌───────────┐             │
│   │ Follower  │──────▶│ Candidate │─────▶│  Leader   │             │
│   └───────────┘       └───────────┘      └───────────┘             │
│        ▲                                       │                   │
│        │                                       │                   │
│        └─────────── (term ends) ───────────────┘                   │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

### Quorum

Raft requires a majority quorum for operations:

| Cluster Size | Quorum | Max Failures |
|--------------|--------|--------------|
| 1 node | 1 | 0 |
| 3 nodes | 2 | 1 |
| 5 nodes | 3 | 2 |
| 7 nodes | 4 | 3 |

### State Replication

All writes go through the leader and are replicated:

```
  Client                Leader                 Followers
    │                     │                       │
    │─── Write Request ──▶│                       │
    │                     │─── AppendEntries ────▶│
    │                     │◀── ACK (majority) ────│
    │                     │                       │
    │                     │─── Commit ───────────▶│
    │◀── Success ─────────│                       │
    │                     │                       │
```

## Cluster-Aware Services

The following services are cluster-aware and replicate state:

| Service | Replicated Data | Sync Mechanism |
|---------|-----------------|----------------|
| **SDN Controller** | OVS bridge configs, port states, flow rules | QuicBaaS + gRPC sync |
| **Certificate Authority** | CA state, issued certs, CRLs | QuicBaaS |
| **DNS Server** | Zone records, DDNS updates | QuicBaaS |
| **Device Profiles** | Profile definitions, attestation policies | QuicBaaS |
| **Tenant Manager** | Tenant configs, quotas, DEK handles | QuicBaaS |

## Failover Behavior

```
                      Failover Timeline
┌────────────────────────────────────────────────────────────────────┐
│                                                                    │
│  0s         2s         5s         10s        15s                   │
│  │          │          │          │          │                     │
│  ▼          ▼          ▼          ▼          ▼                     │
│  Leader     Heartbeat  Election   New        Clients               │
│  Fails      Timeout    Starts     Leader     Reconnect             │
│             (no ack)              Elected                          │
│                                                                    │
│  ┌──────┐  ┌────────┐  ┌─────────┐ ┌────────┐ ┌─────────┐          │
│  │Leader│  │Follower│  │Candidate│ │ Leader │ │ Clients │          │
│  │ dies │  │ detects│  │election │ │ accepts│ │ resume  │          │
│  └──────┘  └────────┘  └─────────┘ └────────┘ └─────────┘          │
│                                                                    │
│  RTO (Recovery Time Objective): < 10 seconds                       │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

## Related Documentation

- [Tenant Architecture](../tenant/architecture.md) - Multi-tenancy with clustering
- [SDN Architecture](../sdn/architecture.md) - SDN clustering details
- [Daemon API](../daemon/api.md) - Platform API design
- [QuicBaaS Client](../../pkg/storage/quicbaas/) - QuicBaaS integration

## Next Steps

1. Review the [Architecture](architecture.md) documentation
2. Plan deployment with [Configuration](configuration.md) reference
3. Bootstrap cluster using [Bootstrap](user.md) guide
4. Set up monitoring per [Operations](user.md) guide
