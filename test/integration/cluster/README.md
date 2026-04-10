# Cluster Integration Tests

This directory contains integration tests for the go-trusted-platform cluster functionality, including multi-node Raft consensus, state replication, and failover testing.

## Overview

The cluster integration tests verify:
- **Cluster Formation**: 3-node Raft cluster formation and leader election
- **Consensus**: Write replication, read consistency, log replication
- **Failover**: Leader failover, follower failure, node restart, partition recovery
- **SDN Replication**: Bridge, port, flow state replication across cluster
- **CA Replication**: Certificate, CRL, ACME state replication

## Test Files

| File | Tests | Description |
|------|-------|-------------|
| `setup_test.go` | - | Test infrastructure helpers |
| `cluster_test.go` | 14 | Core cluster operations |
| `consensus_test.go` | 10 | Raft consensus tests |
| `failover_test.go` | 12 | Failure and recovery tests |
| `sdn_cluster_test.go` | 9 | SDN state replication |
| `ca_cluster_test.go` | 11 | CA state replication |

**Total: 56 tests**

## Running Tests

### Single Container Mode

Run all cluster tests:
```bash
make integration-test-cluster
```

Run specific test suites:
```bash
make integration-test-cluster-consensus   # Consensus tests
make integration-test-cluster-failover    # Failover tests
make integration-test-cluster-sdn         # SDN tests
make integration-test-cluster-ca          # CA tests
```

Interactive shell for debugging:
```bash
make integration-test-cluster-shell
```

### Docker Compose Mode (Multi-Container)

Start full multi-node cluster:
```bash
make integration-test-cluster-compose
```

Start cluster nodes only (for manual testing):
```bash
make integration-test-cluster-compose-up
```

Stop and cleanup:
```bash
make integration-test-cluster-compose-down
```

### Using run-tests.sh

```bash
cd test/integration/cluster

./run-tests.sh           # Run all tests
./run-tests.sh setup     # Setup cluster only
./run-tests.sh status    # Show cluster status
./run-tests.sh consensus # Consensus tests only
./run-tests.sh failover  # Failover tests only
./run-tests.sh sdn       # SDN tests only
./run-tests.sh ca        # CA tests only
./run-tests.sh teardown  # Cleanup cluster
./run-tests.sh help      # Show help
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `INTEGRATION_TEST` | - | Must be set to "1" to run tests |
| `CLUSTER_SIZE` | 3 | Number of cluster nodes |
| `NODE_TIMEOUT` | 30s | Node startup timeout |
| `CLUSTER_TIMEOUT` | 60s | Cluster formation timeout |
| `LOG_LEVEL` | info | Logging level |
| `TEST_TIMEOUT` | 15m | Test execution timeout |

## Docker Compose Services

The `docker-compose.yml` defines:

| Service | IP | Ports | Description |
|---------|-----|-------|-------------|
| `cluster-node-1` | 172.30.0.11 | 7001, 8001 | Bootstrap node |
| `cluster-node-2` | 172.30.0.12 | 7002, 8002 | Follower node |
| `cluster-node-3` | 172.30.0.13 | 7003, 8003 | Follower node |
| `test-runner` | 172.30.0.100 | - | Test execution |

## Test Categories

### Cluster Formation Tests
- Verify 3 nodes can form a cluster
- Verify leader election within timeout
- Verify node discovery
- Verify cluster status reporting

### Consensus Tests
- Write replication to all nodes
- Read consistency across nodes
- Raft log entry replication
- Snapshot creation and recovery

### Failover Tests
- Leader failure and re-election (< 10 seconds)
- Follower failure (cluster continues)
- Node restart and rejoin
- Network partition handling
- Partition recovery and healing

### SDN Cluster Tests
- Bridge state replication
- Port state replication
- Flow rule replication
- State consistency after writes
- Persistence through leader failover

### CA Cluster Tests
- Certificate replication
- CRL update replication
- ACME state replication
- Leader-only CRL generation
- Persistence through leader failover

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Setup failed |
| 2 | Cluster formation failed |
| 3 | Test failed |
| 4 | Cleanup failed |
| 5 | Invalid arguments |

## Debugging

Enable debug logging:
```bash
LOG_LEVEL=debug ./run-tests.sh
```

View container logs:
```bash
docker compose logs -f cluster-node-1
```

Shell into a node:
```bash
docker compose exec cluster-node-1 bash
```

## CI/CD Integration

The tests integrate with CI/CD via exit codes and can be run as:
```bash
make integration-test-cluster || exit 1
```

Typical CI timeout: 30-45 minutes for full test suite.
