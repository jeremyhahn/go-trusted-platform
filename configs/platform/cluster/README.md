# Cluster Reference Architecture

High-availability deployment configuration for go-trusted-platform.

## Architecture Overview

```
                        INTERNET
                            │
              ┌─────────────┴─────────────┐
              │         Gateways          │
              │  (Stateless, HA via VIP)  │
              ├─────────────┬─────────────┤
              │  gateway1   │  gateway2   │
              │  10.0.0.10  │  10.0.0.11  │
              │  (VIP: 10.0.0.1)          │
              └─────────────┴─────────────┘
                            │ Port 443
                            ▼
              ┌─────────────────────────────────┐
              │    Server/Controller Cluster    │
              │       (Raft for State HA)       │
              ├───────────┬───────────┬─────────┤
              │  server1  │  server2  │ server3 │
              │ 10.0.1.1  │ 10.0.1.2  │ 10.0.1.3│
              │  NodeID:1 │  NodeID:2 │ NodeID:3│
              │ (Leader)  │(Follower) │(Follower)│
              └───────────┴───────────┴─────────┘
                            │
                            ▼
              ┌─────────────────────────────────┐
              │        Client Cluster           │
              │   (Run custom.example.com)      │
              ├───────────┬───────────┬─────────┤
              │  client1  │  client2  │ client3 │
              │ 10.0.2.1  │ 10.0.2.2  │ 10.0.2.3│
              └───────────┴───────────┴─────────┘
```

## Network Configuration

| Node | IP Address | Role | Raft Port |
|------|-----------|------|-----------|
| gateway1 | 10.0.0.10 | Load Balancer | - |
| gateway2 | 10.0.0.11 | Load Balancer | - |
| VIP | 10.0.0.1 | Anycast Gateway | - |
| server1 | 10.0.1.1 | Controller (Leader) | 63000 |
| server2 | 10.0.1.2 | Controller (Follower) | 63000 |
| server3 | 10.0.1.3 | Controller (Follower) | 63000 |
| client1 | 10.0.2.1 | Application | - |
| client2 | 10.0.2.2 | Application | - |
| client3 | 10.0.2.3 | Application | - |

## Deployment Order

Deploy nodes in this order to ensure proper cluster formation:

### Phase 1: Bootstrap Server Cluster

1. **Deploy server1**
   ```bash
   platformd --config /etc/trusted-platform/server1.example.com.yaml
   ```
   Server1 waits for a quorum of the members it lists.

2. **Deploy server2**
   ```bash
   platformd --config /etc/trusted-platform/server2.example.com.yaml
   ```
   With two of three members up, the cluster has quorum and elects a leader.

3. **Deploy server3**
   ```bash
   platformd --config /etc/trusted-platform/server3.example.com.yaml
   ```
   Server3 catches up as the third member. The servers may start in any
   order (see [Raft Bootstrap Procedure](#raft-bootstrap-procedure)).

### Phase 2: Deploy Gateways

4. **Deploy gateway1**
   ```bash
   gatewayd --config /etc/trusted-platform/gateway1.example.com.yaml
   ```

5. **Deploy gateway2**
   ```bash
   gatewayd --config /etc/trusted-platform/gateway2.example.com.yaml
   ```

Both gateways share the anycast VIP (10.0.0.1). Configure your network to route traffic to both using:
- BGP anycast
- DNS round-robin
- Hardware load balancer
- Keepalived/VRRP

### Phase 3: Deploy Client Cluster

6. **Deploy client1, client2, client3** (any order)
   ```bash
   platformd --config /etc/trusted-platform/client1.example.com.yaml
   platformd --config /etc/trusted-platform/client2.example.com.yaml
   platformd --config /etc/trusted-platform/client3.example.com.yaml
   ```

## Raft Bootstrap Procedure

### Initial Cluster Formation

The three servers bootstrap the cluster together from one static member list.
Each server's `quicbaas:` section carries:

- the same `join-addresses`, every member as `id=host:port`, itself included:
  `["1=10.0.1.1:63000", "2=10.0.1.2:63000", "3=10.0.1.3:63000"]`;
- the same `deployment-id` and `raft-tls-ca-file`;
- its own `node-id`, `raft-address`, `raft-tls-cert-file` and `raft-tls-key-file`.

Start them in any order; a leader is elected once a quorum is up. The storage
backend stays `pebble`: Raft is engaged by `join-addresses`, and
`storage-backend: raft` is refused. Raft between peers is always mutual TLS,
so provision the certificate, key and CA files before the first start (see
[docs/cluster/user.md](../../../docs/cluster/user.md#configuring-a-cluster)).

### Adding New Nodes

Adding a member to a running cluster is not supported from platform config
yet: platformd always bootstraps from the static list and never sets
go-quicbaas's join mode.

### Recovering from Failures

**Single Node Failure:**
- Cluster continues operating (quorum maintained with 2/3 nodes)
- Restart failed node; it will automatically rejoin

**Leader Failure:**
- Remaining followers elect new leader automatically
- No manual intervention required

**Quorum Loss (2+ failures):**
- Cluster becomes read-only
- Restore at least one more node to regain quorum

## Service Routing

### custom.example.com

Traffic flow:
1. Client requests `https://custom.example.com`
2. DNS resolves to VIP (10.0.0.1)
3. Gateway receives request on port 443
4. Gateway proxies to client cluster:
   - `https://client1.example.internal:9443`
   - `https://client2.example.internal:9443`
   - `https://client3.example.internal:9443`

### *.example.com (all other)

Traffic flow:
1. Client requests `https://server.example.com`
2. DNS resolves to VIP (10.0.0.1)
3. Gateway receives request on port 443
4. Gateway proxies to server cluster:
   - `https://server1.example.internal:8443`
   - `https://server2.example.internal:8443`
   - `https://server3.example.internal:8443`

## Health Checks

The gateway performs active health checks on backend servers:
- **Interval:** 5 seconds
- **Timeout:** 3 seconds
- **Protocol:** HTTPS

Failed backends are automatically removed from the load balancer pool until health checks pass.

## Failover Testing

### Test Server Failover

1. Identify current Raft leader:
   ```bash
   platformctl cluster status
   ```

2. Stop the leader node

3. Verify new leader election:
   ```bash
   platformctl cluster status
   ```

4. Verify services continue operating

### Test Gateway Failover

1. Stop gateway1

2. Verify traffic continues via gateway2:
   ```bash
   curl -v https://custom.example.com
   ```

3. Restart gateway1

## Monitoring

### Cluster Health

```bash
# Check Raft cluster status
platformctl cluster status

# Check node health
platformctl node health

# View cluster members
platformctl cluster members
```

### Gateway Status

```bash
# Check gateway health
gatewayd status

# View backend health
gatewayd backends list

# View active connections
gatewayd connections
```

## Configuration Files

| File | Description |
|------|-------------|
| `gateway1.example.com.yaml` | Gateway node 1 (load balancer) |
| `gateway2.example.com.yaml` | Gateway node 2 (load balancer) |
| `server1.example.com.yaml` | Server node 1 (Raft member 1) |
| `server2.example.com.yaml` | Server node 2 (Raft member 2) |
| `server3.example.com.yaml` | Server node 3 (Raft member 3) |
| `client1.example.com.yaml` | Client node 1 (application) |
| `client2.example.com.yaml` | Client node 2 (application) |
| `client3.example.com.yaml` | Client node 3 (application) |
