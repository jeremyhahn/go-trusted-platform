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

1. **Deploy server1** (bootstrap node)
   ```bash
   platformd --config /etc/trusted-platform/server1.example.com.yaml
   ```
   Server1 starts as a single-node Raft cluster (leader).

2. **Deploy server2** (join cluster)
   ```bash
   platformd --config /etc/trusted-platform/server2.example.com.yaml
   ```
   Server2 joins server1's cluster as a follower.

3. **Deploy server3** (join cluster)
   ```bash
   platformd --config /etc/trusted-platform/server3.example.com.yaml
   ```
   Server3 joins as a follower. Cluster now has quorum (3 nodes).

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

Server1 is the bootstrap node:
- `join-addresses: []` (empty - creates new cluster)
- Becomes initial leader

Server2 and Server3 join the existing cluster:
- `join-addresses: ["10.0.1.1:63000"]` (points to server1)
- Automatically discover and join the Raft cluster

### Adding New Nodes

To add a node to an existing cluster:
1. Configure the new node with `join-addresses` pointing to any existing cluster member
2. Start the new node
3. The new node automatically joins and receives replicated state

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
| `server1.example.com.yaml` | Server node 1 (Raft bootstrap) |
| `server2.example.com.yaml` | Server node 2 (Raft follower) |
| `server3.example.com.yaml` | Server node 3 (Raft follower) |
| `client1.example.com.yaml` | Client node 1 (application) |
| `client2.example.com.yaml` | Client node 2 (application) |
| `client3.example.com.yaml` | Client node 3 (application) |
