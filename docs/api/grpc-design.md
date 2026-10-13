# gRPC API Design - Platform Daemon Internal API

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [daemon/api.md](../daemon/api.md) and each feature's `api.md`.

## 1. Executive Summary

This document presents the comprehensive gRPC API design for the `platformd` daemon, providing a unified interface for privileged platform operations. The design acknowledges that go-trusted-platform is evolving from a standalone certificate authority and TPM management tool into a full-featured trusted computing platform with SDN, compute orchestration, and remote attestation capabilities.

**Key Technology Choices:**
- Protocol Buffers v3 for efficient, type-safe serialization
- gRPC for high-performance, bidirectional streaming RPC
- Unix socket transport for secure local IPC
- Go-native code generation for zero-overhead integration

This internal API serves as the foundation for local CLI tools (platformctl) and future REST API gateways, consolidating root-level operations into a single, well-defined contract.

## 2. Architecture Overview

The platformd daemon exposes five primary gRPC services over a Unix socket (`/var/run/platformd.sock`):

```
┌──────────────────────────────────────────────────────────────────────┐
│                         platformd (daemon)                           │
│                                                                      │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐   │
│  │ PlatformDaemon   │  │   TPMService     │  │   SDNService     │   │
│  │                  │  │                  │  │                  │   │
│  │ - Status/Health  │  │ - Provisioning   │  │ - Bridges        │   │
│  │ - Provisioning   │  │ - EK/SRK/AK      │  │ - Ports/Flows    │   │
│  │ - Services       │  │ - Seal/Unseal    │  │ - VLANs          │   │
│  │ - Events/Logs    │  │ - Attestation    │  │ - x509 Auth      │   │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘   │
│                                                                      │
│  ┌──────────────────┐  ┌──────────────────┐                         │
│  │ ComputeService   │  │  Common Types    │                         │
│  │                  │  │                  │                         │
│  │ - VM Lifecycle   │  │ - Error Codes    │                         │
│  │ - Containers     │  │ - Key Algorithms │                         │
│  │ - Snapshots      │  │ - Pagination     │                         │
│  │ - Attestation    │  │ - Health Status  │                         │
│  └──────────────────┘  └──────────────────┘                         │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
                                 │
                                 │ Unix Socket
                                 │ /var/run/platformd.sock
                                 │
                                 │
                          ┌──────▼──────┐
                          │ platformctl │
                          │   (CLI)     │
                          └─────────────┘
```

**Key Interactions:**
1. Client connects to Unix socket with appropriate permissions
2. Client invokes RPC methods on registered services
3. Daemon performs privileged operations (TPM, networking, VM management)
4. Responses include structured status, errors, and results
5. Streaming RPCs provide real-time events, logs, and console I/O

**Data Flow:**
- Synchronous RPCs for CRUD operations and queries
- Server-streaming for logs, events, and metrics
- Client-streaming for console input
- Bidirectional streaming for interactive sessions (future)

## 3. Service Definitions

### 3.1 PlatformDaemon Service

**Responsibilities:**
- System-wide status and health monitoring
- Platform initialization and provisioning
- Service lifecycle management (start/stop/restart)
- Configuration management with hot-reload
- Event, log, and metric streaming

**Core Operations:**
- `GetStatus()` - Current system state and service inventory
- `Provision()` - Initialize TPM, CA, network, and compute resources
- `StartService()/StopService()` - Control individual platform services
- `StreamEvents()` - Real-time platform event notifications
- `StreamLogs()` - Service log aggregation with filtering

### 3.2 TPMService

**Responsibilities:**
- TPM capability discovery and configuration
- Hierarchical key provisioning (EK → SRK → AK)
- Data sealing with PCR policy enforcement
- Remote attestation quote generation and verification
- NVRAM operations for persistent storage
- Cryptographically secure random number generation

**Core Operations:**
- `Provision()` - Create EK, SRK, and IAK in one transaction
- `Seal()/Unseal()` - Protect secrets with TPM and PCR binding
- `Quote()` - Generate attestation evidence with nonce
- `VerifyQuote()` - Validate quote signature and PCR values
- `GetEventLog()` - Retrieve measured boot event log

### 3.3 SDNService

**Responsibilities:**
- Software-defined network bridge management (OVS, Linux bridge)
- Port lifecycle and statistics
- OpenFlow rule programming (flow tables)
- VLAN isolation and trunk configuration
- x509 certificate-based port authentication
- Network flow logging and monitoring

**Core Operations:**
- `CreateBridge()` - Provision network bridge with datapath ID
- `AddPort()` - Attach physical/virtual interfaces to bridges
- `AddFlow()` - Program OpenFlow rules with match/action criteria
- `AuthenticatePort()` - Validate x509 certificate for network access
- `StreamFlowLogs()` - Real-time network traffic visibility

### 3.4 ComputeService

**Responsibilities:**
- Virtual machine lifecycle (QEMU/KVM)
- Container orchestration (Podman/Docker)
- Console attachment and streaming I/O
- Disk management (attach, resize, snapshot)
- Live migration between hosts
- vTPM attestation for VMs
- Resource metrics and monitoring

**Core Operations:**
- `CreateVM()` - Provision VM with CPU, memory, disk, network, TPM
- `StartVM()/StopVM()` - Control VM power state
- `AttachVMConsole()` - Stream serial console output
- `CreateSnapshot()` - Point-in-time VM state capture
- `AttestVM()` - Generate quote from VM's vTPM
- `CreateContainer()` - Launch container with optional host TPM access

### 3.5 Common Types

**Responsibilities:**
- Shared enumerations and message types
- Error code standardization
- Pagination and filtering primitives
- Key algorithm and hash algorithm definitions
- Health status reporting

## 4. API Contracts

### 4.1 PlatformDaemon.GetStatus

**Endpoint:** `PlatformDaemon/GetStatus`

**Request:**
```json
{}
```

**Success Response (200 OK):**
```json
{
  "status": "SYSTEM_STATUS_READY",
  "info": {
    "hostname": "platform-node-01",
    "platform_id": "550e8400-e29b-41d4-a716-446655440000",
    "version": "1.4.0",
    "build_time": "2025-12-11T10:30:00Z",
    "git_commit": "f003b6d",
    "fips_mode": true,
    "tpm_info": {
      "version": "TPM_VERSION_2_0",
      "manufacturer": "Intel",
      "firmware_version": "7.85",
      "is_simulator": false,
      "fips_mode": true
    },
    "system_info": {
      "os": "linux",
      "arch": "amd64",
      "kernel_version": "6.14.0-36-generic",
      "num_cpus": 16,
      "total_memory_mb": 65536,
      "available_memory_mb": 32768,
      "uptime_seconds": 86400
    }
  },
  "services": [
    {
      "type": "SERVICE_TYPE_TPM",
      "name": "tpm",
      "status": "SERVICE_STATUS_RUNNING",
      "health": "HEALTH_STATUS_HEALTHY",
      "uptime_seconds": 86400
    },
    {
      "type": "SERVICE_TYPE_SDN",
      "name": "sdn",
      "status": "SERVICE_STATUS_RUNNING",
      "health": "HEALTH_STATUS_HEALTHY",
      "uptime_seconds": 86400
    }
  ],
  "timestamp": "2025-12-11T12:00:00Z"
}
```

**Error Responses:**
- `UNAVAILABLE` - Daemon is shutting down or initializing
- `INTERNAL` - Unexpected system error

---

### 4.2 TPMService.Seal

**Endpoint:** `TPMService/Seal`

**Request:**
```json
{
  "data": "c2VjcmV0LXBhc3N3b3Jk",  // base64-encoded secret
  "cn": "database-encryption-key",
  "parent_handle": 2164260866,      // 0x81000002 (SRK)
  "parent_password": "",
  "password": "seal-password",
  "pcr_indices": [0, 1, 2, 3, 7],
  "pcr_bank": "PCR_BANK_SHA256",
  "overwrite": false
}
```

**Success Response (200 OK):**
```json
{
  "status": {
    "success": true,
    "message": "Secret sealed successfully"
  },
  "sealed_data": "AQALAAAGAAABAAu...==",  // base64-encoded TPM2B_PRIVATE
  "public_key": "AQALAAAGAAABAAu...==",   // base64-encoded TPM2B_PUBLIC
  "private_key": "AQALAAAGAAABAAu...=="
}
```

**Error Responses:**
- `INVALID_ARGUMENT` - Invalid PCR indices or password
- `ALREADY_EXISTS` - Sealed object with CN already exists
- `PERMISSION_DENIED` - Incorrect parent password
- `FAILED_PRECONDITION` - TPM not provisioned
- `INTERNAL` - TPM hardware error

---

### 4.3 SDNService.CreateBridge

**Endpoint:** `SDNService/CreateBridge`

**Request:**
```json
{
  "config": {
    "name": "br-compute",
    "type": "BRIDGE_TYPE_OVS",
    "stp_enabled": false,
    "mtu": 9000,
    "controllers": ["tcp:127.0.0.1:6653"],
    "options": {
      "datapath-type": "netdev",
      "stp-enable": "false"
    },
    "labels": {
      "environment": "production",
      "purpose": "compute"
    }
  }
}
```

**Success Response (200 OK):**
```json
{
  "status": {
    "success": true,
    "message": "Bridge created successfully"
  },
  "bridge": {
    "id": "br-compute-550e8400",
    "config": {
      "name": "br-compute",
      "type": "BRIDGE_TYPE_OVS",
      "datapath_id": "0000550e84000000",
      "stp_enabled": false,
      "mtu": 9000
    },
    "status": "BRIDGE_STATUS_UP",
    "created_at": "2025-12-11T12:00:00Z",
    "stats": {
      "total_ports": 0,
      "total_flows": 0
    }
  }
}
```

**Error Responses:**
- `ALREADY_EXISTS` - Bridge with name already exists
- `INVALID_ARGUMENT` - Invalid MTU or controller address
- `PERMISSION_DENIED` - Insufficient privileges
- `RESOURCE_EXHAUSTED` - Maximum bridge limit reached
- `UNAVAILABLE` - OVS daemon not running

---

### 4.4 ComputeService.CreateVM

**Endpoint:** `ComputeService/CreateVM`

**Request:**
```json
{
  "config": {
    "name": "vm-web-01",
    "description": "Web server with TPM attestation",
    "firmware": "FIRMWARE_TYPE_UEFI_SECURE_BOOT",
    "boot_device": "BOOT_DEVICE_DISK",
    "cpu": {
      "cores": 4,
      "sockets": 1,
      "threads": 2,
      "model": "host-passthrough"
    },
    "memory": {
      "size_mb": 8192,
      "hugepages": false
    },
    "disks": [
      {
        "id": "root",
        "path": "/var/lib/vms/vm-web-01/disk.qcow2",
        "type": "DISK_TYPE_QCOW2",
        "bus": "DISK_BUS_VIRTIO",
        "size_gb": 100,
        "bootable": true
      }
    ],
    "networks": [
      {
        "id": "eth0",
        "bridge": "br-compute",
        "model": "NETWORK_MODEL_VIRTIO",
        "vlan": 100
      }
    ],
    "graphics": {
      "type": "GRAPHICS_TYPE_SPICE",
      "listen": "127.0.0.1",
      "port": 5900
    },
    "tpm": {
      "enabled": true,
      "version": "TPM_VERSION_2_0",
      "emulated": true,
      "state_dir": "/var/lib/vms/vm-web-01/tpm"
    },
    "secure_boot": true,
    "labels": {
      "role": "webserver",
      "tier": "frontend"
    }
  },
  "start": true
}
```

**Success Response (200 OK):**
```json
{
  "status": {
    "success": true,
    "message": "VM created and started successfully"
  },
  "vm": {
    "id": "vm-550e8400-e29b-41d4",
    "config": {
      "name": "vm-web-01",
      // ... full config echoed back
    },
    "state": "VM_STATE_RUNNING",
    "created_at": "2025-12-11T12:00:00Z",
    "updated_at": "2025-12-11T12:00:05Z",
    "host_id": "platform-node-01"
  }
}
```

**Error Responses:**
- `ALREADY_EXISTS` - VM with name already exists
- `INVALID_ARGUMENT` - Invalid CPU/memory configuration
- `RESOURCE_EXHAUSTED` - Insufficient host resources
- `NOT_FOUND` - Bridge or disk path not found
- `FAILED_PRECONDITION` - Secure boot keys not available
- `INTERNAL` - QEMU/KVM error

---

### 4.5 ComputeService.AttestVM

**Endpoint:** `ComputeService/AttestVM`

**Request:**
```json
{
  "vm_id": "vm-550e8400-e29b-41d4",
  "nonce": "cmFuZG9tLW5vbmNl",  // base64-encoded 20-byte nonce
  "pcr_indices": [0, 1, 2, 3, 7],
  "pcr_bank": "PCR_BANK_SHA256"
}
```

**Success Response (200 OK):**
```json
{
  "status": {
    "success": true,
    "message": "VM attestation quote generated"
  },
  "quote": "AQALAAAGAAABAAu...==",      // base64-encoded TPMS_ATTEST
  "signature": "AQALAAAGAAABAAu...==",  // base64-encoded signature
  "pcr_values": [
    {
      "index": 0,
      "bank": "PCR_BANK_SHA256",
      "value": "0000000000000000000000000000000000000000000000000000000000000000"
    },
    {
      "index": 1,
      "bank": "PCR_BANK_SHA256",
      "value": "3d458cfe55cc03ea1f443f1562beec8d..."
    }
  ],
  "event_log": "TlRGUyAgICAg..==",     // base64-encoded TCG event log
  "ak_public": "AQALAAAGAAABAAu...=="  // base64-encoded TPM2B_PUBLIC
}
```

**Error Responses:**
- `NOT_FOUND` - VM does not exist
- `FAILED_PRECONDITION` - VM not running or TPM not enabled
- `INVALID_ARGUMENT` - Invalid nonce or PCR indices
- `UNAVAILABLE` - Cannot connect to vTPM socket
- `INTERNAL` - vTPM error

---

### 4.6 PlatformDaemon.StreamEvents

**Endpoint:** `PlatformDaemon/StreamEvents` (Server Streaming)

**Request:**
```json
{
  "types": [
    "EVENT_TYPE_VM_CREATED",
    "EVENT_TYPE_VM_STARTED",
    "EVENT_TYPE_VM_STOPPED",
    "EVENT_TYPE_ATTESTATION_REQUESTED"
  ],
  "min_severity": ["EVENT_SEVERITY_INFO"],
  "sources": ["compute", "tpm"]
}
```

**Streaming Response (multiple messages):**
```json
{
  "id": "evt-550e8400-001",
  "type": "EVENT_TYPE_VM_CREATED",
  "severity": "EVENT_SEVERITY_INFO",
  "timestamp": "2025-12-11T12:00:00Z",
  "source": "compute",
  "message": "VM vm-web-01 created successfully",
  "metadata": {
    "vm_id": "vm-550e8400-e29b-41d4",
    "vm_name": "vm-web-01",
    "host_id": "platform-node-01"
  }
}
```

```json
{
  "id": "evt-550e8400-002",
  "type": "EVENT_TYPE_VM_STARTED",
  "severity": "EVENT_SEVERITY_INFO",
  "timestamp": "2025-12-11T12:00:05Z",
  "source": "compute",
  "message": "VM vm-web-01 started",
  "metadata": {
    "vm_id": "vm-550e8400-e29b-41d4",
    "startup_time_ms": "4567"
  }
}
```

**Error Responses:**
- `CANCELLED` - Client cancelled the stream
- `DEADLINE_EXCEEDED` - Timeout reached

## 5. Data Schema

### 5.1 TPM Sealed Data Storage (BlobStore)

```sql
-- Stored as individual files in blob store
-- Path: /var/lib/platformd/tpm/sealed/{cn}.json

{
  "cn": "database-encryption-key",
  "sealed_data": "AQALAAAGAAABAAu...==",
  "public_key": "AQALAAAGAAABAAu...==",
  "private_key": "AQALAAAGAAABAAu...==",
  "parent_handle": 2164260866,
  "pcr_indices": [0, 1, 2, 3, 7],
  "pcr_bank": "SHA256",
  "created_at": "2025-12-11T12:00:00Z",
  "metadata": {
    "created_by": "admin",
    "purpose": "database-encryption"
  }
}

-- Indexes: cn (primary key), parent_handle, created_at
```

### 5.2 VM State Storage (KVStore)

```sql
-- Key-Value Store (BadgerDB or similar)
-- Key format: vm:{id}

Key: "vm:vm-550e8400-e29b-41d4"
Value: {
  "id": "vm-550e8400-e29b-41d4",
  "name": "vm-web-01",
  "config": {
    // Full VMConfig as JSON
  },
  "state": "VM_STATE_RUNNING",
  "pid": 12345,
  "created_at": "2025-12-11T12:00:00Z",
  "updated_at": "2025-12-11T12:00:05Z",
  "host_id": "platform-node-01",
  "labels": {
    "role": "webserver",
    "tier": "frontend"
  }
}

-- Secondary indexes:
-- Key: "vm_by_name:vm-web-01" → Value: "vm-550e8400-e29b-41d4"
-- Key: "vm_by_state:VM_STATE_RUNNING:vm-550e8400-e29b-41d4" → Value: "1"
-- Key: "vm_by_label:role=webserver:vm-550e8400-e29b-41d4" → Value: "1"
```

### 5.3 SDN Bridge Configuration (KVStore)

```sql
-- Key format: bridge:{id}

Key: "bridge:br-compute-550e8400"
Value: {
  "id": "br-compute-550e8400",
  "name": "br-compute",
  "type": "BRIDGE_TYPE_OVS",
  "datapath_id": "0000550e84000000",
  "stp_enabled": false,
  "mtu": 9000,
  "controllers": ["tcp:127.0.0.1:6653"],
  "ports": [
    "port-550e8400-001",
    "port-550e8400-002"
  ],
  "created_at": "2025-12-11T12:00:00Z",
  "labels": {
    "environment": "production",
    "purpose": "compute"
  }
}

-- Port storage
Key: "port:port-550e8400-001"
Value: {
  "id": "port-550e8400-001",
  "bridge_id": "br-compute-550e8400",
  "name": "vnet0",
  "type": "PORT_TYPE_TAP",
  "vlan": 100,
  "status": "PORT_STATUS_UP",
  "auth": {
    "authenticated": true,
    "certificate_cn": "vm-web-01.platform.local",
    "authorized_vlans": [100, 101]
  }
}
```

### 5.4 Event Log Storage (Time-Series)

```sql
-- Time-series database or append-only log
-- Schema for structured event storage

CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  severity TEXT NOT NULL,
  timestamp DATETIME NOT NULL,
  source TEXT NOT NULL,
  message TEXT NOT NULL,
  metadata JSON,
  INDEX idx_type (type),
  INDEX idx_severity (severity),
  INDEX idx_timestamp (timestamp),
  INDEX idx_source (source)
);

-- Example row:
INSERT INTO events VALUES (
  'evt-550e8400-001',
  'EVENT_TYPE_VM_CREATED',
  'EVENT_SEVERITY_INFO',
  '2025-12-11 12:00:00',
  'compute',
  'VM vm-web-01 created successfully',
  '{"vm_id": "vm-550e8400-e29b-41d4", "vm_name": "vm-web-01"}'
);
```

## 6. Technology Stack Rationale

### 6.1 Protocol Buffers v3

**Justification:**
- **Efficient serialization**: Binary format with ~3-10x smaller payloads than JSON
- **Type safety**: Strongly-typed schema with compiler validation
- **Backward compatibility**: Field deprecation and reserved numbers support evolution
- **Code generation**: Native Go structs with zero-overhead marshaling
- **Wide adoption**: Industry standard for microservices communication

**Trade-offs:**
vs. JSON:
- PRO: Better performance, smaller size, type safety
- CON: Not human-readable in wire format, requires code generation
- DECISION: Performance and type safety outweigh debugging convenience. Use `grpcurl` for testing.

vs. MessagePack:
- PRO: Proto has better schema evolution, wider tooling support
- CON: MessagePack is slightly faster for dynamic types
- DECISION: Schema-first design aligns with platform's long-term stability goals

### 6.2 gRPC

**Justification:**
- **HTTP/2 transport**: Multiplexing, header compression, flow control
- **Bidirectional streaming**: Essential for console I/O and real-time events
- **Language agnostic**: Future clients in Python, Rust, or TypeScript
- **Service mesh ready**: Compatible with Istio, Linkerd for future scaling
- **Native deadlines**: Built-in timeout and cancellation propagation

**Trade-offs:**
vs. REST:
- PRO: Better performance, streaming support, type-safe contracts
- CON: Less accessible for curl-based testing, requires HTTP/2
- DECISION: Internal API prioritizes performance. REST gateway (platformd workers) provides HTTP/1.1 access.

vs. Unix Domain Sockets (raw):
- PRO: gRPC provides service versioning, streaming, error handling
- CON: Unix sockets are simpler for basic RPC
- DECISION: gRPC's advanced features justify the overhead for a long-lived daemon API

### 6.3 Unix Socket Transport

**Justification:**
- **Security**: Filesystem permissions provide access control (no network exposure)
- **Performance**: Lower latency than TCP loopback (no TCP handshake, no congestion control)
- **Simplicity**: No TLS certificate management for local IPC
- **Atomicity**: Socket file existence indicates daemon availability

**Trade-offs:**
vs. TCP loopback:
- PRO: Better security, faster, no port conflicts
- CON: Cannot access remotely, limited to single host
- DECISION: platformd is a local daemon. Remote access via platformd REST/gRPC APIs.

vs. D-Bus:
- PRO: gRPC has better streaming, cross-platform support
- CON: D-Bus has better desktop integration (systemd, polkit)
- DECISION: Platform targets datacenter/edge, not desktop. gRPC better for cloud-native patterns.

### 6.3.1 Unix Domain Socket Transport

The gRPC server listens on both TCP and Unix domain socket transports simultaneously, providing the same API surface with transport-specific authentication.

**Dual Listener Architecture:**

```go
// TCP listener for external/remote access
tcpListener, _ := net.Listen("tcp", ":10443")

// Unix socket listener for local IPC
unixListener, _ := net.Listen("unix", "/run/platformd.sock")
os.Chmod("/run/platformd.sock", 0660)

// Single gRPC server serves both
server := grpc.NewServer(
    grpc.ChainUnaryInterceptor(
        interceptor.UnixCredentialsUnaryInterceptor,
        // ... other interceptors
    ),
)

// Serve on both listeners concurrently
go server.Serve(tcpListener)
server.Serve(unixListener)
```

**SO_PEERCRED Integration:**

The `UnixCredentialsUnaryInterceptor` extracts peer credentials from Unix socket connections:

```go
func UnixCredentialsUnaryInterceptor(ctx context.Context, req interface{},
    info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {

    peer, _ := peer.FromContext(ctx)
    if unixAddr, ok := peer.Addr.(*net.UnixAddr); ok {
        // Extract SO_PEERCRED
        creds := extractPeerCredentials(peer)
        ctx = context.WithValue(ctx, UnixCredentialsKey, creds)
    }
    return handler(ctx, req)
}
```

**Configuration Options:**

```yaml
grpc:
  # TCP transport
  tcp_enabled: true
  tcp_address: ":10443"
  tls_enabled: true
  tls_cert_file: "/etc/platform/certs/grpc.crt"
  tls_key_file: "/etc/platform/certs/grpc.key"

  # Unix socket transport
  unix_enabled: true
  unix_socket: "/run/platformd.sock"
  unix_socket_mode: 0660
  unix_socket_group: "platform"
```

**Client Connection Examples:**

```go
// Unix socket (local, SO_PEERCRED auth)
conn, _ := grpc.NewClient("unix:///run/platformd.sock",
    grpc.WithTransportCredentials(insecure.NewCredentials()))

// TCP with TLS (remote)
conn, _ := grpc.NewClient("localhost:10443",
    grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
```

**Transport Selection:**
- Use Unix socket for CLI tools (`platformctl`) and local services
- Use TCP for service-to-service communication across hosts
- Use TCP with mTLS for external API access

### 6.4 BadgerDB for State Storage

**Justification:**
- **Embeddable**: No external database dependency, simplifies deployment
- **Performance**: LSM-tree optimized for write-heavy workloads (event logs)
- **ACID transactions**: Ensures consistent VM/bridge state
- **Go-native**: Zero CGO dependencies, easy cross-compilation
- **Flexible indexing**: Supports secondary indexes for label queries

**Trade-offs:**
vs. SQLite:
- PRO: Better write performance for event logs, native Go
- CON: SQLite has better SQL query support
- DECISION: Key-value access patterns dominate. SQL not required.

vs. etcd:
- PRO: BadgerDB is embedded, lower operational complexity
- CON: etcd provides distributed consensus for multi-node
- DECISION: Single-daemon architecture. Future: etcd for HA deployments.

### 6.5 Go Code Generation (protoc-gen-go)

**Justification:**
- **Native integration**: Generated structs implement standard Go interfaces
- **Zero reflection overhead**: Compile-time type checking, optimized serialization
- **Versioned packages**: `platform/v1`, `platform/v2` coexist for gradual migration
- **gRPC compatibility**: Official plugin with guaranteed compatibility

**Trade-offs:**
vs. Manual implementation:
- PRO: Automated generation prevents human error, faster iteration
- CON: Build step dependency, larger repository size with generated code
- DECISION: .gitignore generated code, document build process. Benefits outweigh complexity.

## 7. Key Considerations

### 7.1 Scalability

**How will the system handle 10x the initial load?**

**Current Architecture (Single Host):**
- 100 VMs per host
- 10 SDN bridges
- 1000 flows per bridge
- 10 attestation requests/second

**10x Load (1000 VMs, 100 bridges, 10,000 flows, 100 attestations/sec):**

1. **Horizontal Scaling:**
   - Deploy multiple platformd instances across hosts
   - Introduce etcd cluster for distributed state storage
   - Add gRPC load balancer for client distribution
   - Use Raft consensus for leader election

2. **Vertical Optimization:**
   - Connection pooling: Reuse gRPC connections (max 100 concurrent streams per conn)
   - Message batching: Batch VM creation requests (10 VMs/request)
   - Lazy loading: Paginate ListVMs responses (100 VMs/page)
   - Cache warming: Preload frequently accessed VM configs in memory

3. **Database Sharding:**
   - Shard VMs by host_id: `vm:{host_id}:{vm_id}`
   - Shard events by timestamp: `events:{YYYY-MM-DD}:{id}`
   - Use consistent hashing for flow storage across bridges

4. **Resource Limits:**
   - Enforce `max_instances` in VM creation (configurable per tenant)
   - Rate limiting: 1000 RPCs/sec per client
   - Streaming backpressure: 10MB buffer per stream, drop old messages

5. **Monitoring:**
   - Export Prometheus metrics: `platformd_vm_count`, `platformd_rpc_duration_seconds`
   - Alert on gRPC errors > 1% rate
   - Dashboard for VM/container/bridge inventory

**Bottleneck Mitigation:**
- **CPU**: Use worker pools (100 workers) for parallel VM operations
- **Memory**: Stream large responses (event logs) instead of buffering
- **Disk I/O**: Use SSDs for BadgerDB, tune LSM compaction settings
- **Network**: Compress gRPC messages (gzip) for large payloads (> 1MB)

### 7.2 Security

**What are the primary threat vectors and mitigation strategies?**

**Threat Model:**
- Attacker goals: Gain root access, exfiltrate secrets, disrupt VMs
- Attack surface: Unix socket, VM escape, TPM tampering, network sniffing

**1. Unix Socket Security:**
- **Threat**: Unauthorized access to privileged operations
- **Mitigation**:
  - Socket permissions: `0660` (rw-rw----)
  - Owner: `root:platformd`
  - AppArmor/SELinux policy: Restrict socket access to platformd group
  - Peer credential checking: Verify client UID/GID via `SO_PEERCRED`

**2. Input Validation:**
- **Threat**: Injection attacks (command injection, path traversal)
- **Mitigation**:
  - Validate all RPC inputs: VM names (alphanumeric + hyphen), paths (no ../), IPs (CIDR)
  - Sanitize shell commands: Use exec.Command with separate args, never `sh -c`
  - Enforce resource limits: Max 100GB disk, 64GB RAM per VM
  - Reject oversized messages: gRPC max message size 16MB

**3. Secret Management:**
- **Threat**: Plaintext passwords in logs, memory dumps
- **Mitigation**:
  - TPM seal passwords before storage
  - Redact passwords from logs: `logger.Debug("password", "[REDACTED]")`
  - Use secure memory (mlock) for key material in-process
  - Clear sensitive data with explicit zeroing: `explicit_bzero(password, len)`

**4. VM Isolation:**
- **Threat**: VM escape, container breakout
- **Mitigation**:
  - Run QEMU with `-sandbox on` for seccomp filtering
  - Use KVM for hardware-assisted isolation
  - Limit VM capabilities: No privileged containers without approval
  - Separate networks: quarantine (VLAN x04) → control-plane or overlay networks after attestation, per the [reference network](../architecture/reference-network.md)

**5. TPM Security:**
- **Threat**: TPM key extraction, replay attacks
- **Mitigation**:
  - Require TPM 2.0 FIPS-certified chips (no software emulation in production)
  - Use nonces in attestation quotes (20 bytes random from crypto/rand)
  - Verify quote freshness: Reject quotes > 5 minutes old
  - Seal secrets with PCR policy: Unseal only if boot state matches expected PCRs

**6. Attestation Integrity:**
- **Threat**: Quote forgery, PCR manipulation
- **Mitigation**:
  - Validate quote signature with AK public key from trusted CA
  - Compare PCRs against golden values from policy server
  - Require event log consistency: Hash event log, compare to PCR extend operations
  - Use TPM quote instead of PCR read (signed attestation vs. unauthenticated query)

**7. Network Security (SDN):**
- **Threat**: Unauthorized VLAN access, MAC spoofing
- **Mitigation**:
  - x509 port authentication: Validate client certificate before VLAN assignment
  - OpenFlow rules: Drop packets from unauthenticated ports
  - Port security: Limit MAC addresses per port (1 MAC for VMs, 10 for trunks)
  - Flow logging: Audit all traffic for anomaly detection

**8. Audit Logging:**
- **Threat**: Tampering with audit logs to hide attacks
- **Mitigation**:
  - Write-only event log: Append-only SQLite with immutable flag
  - Forward logs to remote syslog server (TLS)
  - Sign events with platform private key (future enhancement)
  - WORM storage: Use write-once media for compliance

### 7.3 Observability

**How will we monitor the system's health and debug issues?**

**1. Metrics (Prometheus Format):**
```
# RPC metrics
platformd_grpc_requests_total{service="TPMService",method="Seal",status="success"} 1500
platformd_grpc_request_duration_seconds{service="TPMService",method="Seal",quantile="0.99"} 0.15

# Resource metrics
platformd_vm_count{state="running"} 85
platformd_vm_memory_used_mb{vm_id="vm-550e8400"} 8192
platformd_bridge_flow_count{bridge_id="br-compute"} 1234

# TPM metrics
platformd_tpm_seal_operations_total{result="success"} 500
platformd_tpm_quote_latency_seconds{quantile="0.95"} 0.05

# System metrics
platformd_uptime_seconds 864000
platformd_service_status{service="compute",status="running"} 1
```

**2. Structured Logging (JSON):**
```json
{
  "timestamp": "2025-12-11T12:00:00Z",
  "level": "info",
  "service": "compute",
  "method": "CreateVM",
  "vm_id": "vm-550e8400-e29b-41d4",
  "vm_name": "vm-web-01",
  "duration_ms": 4567,
  "message": "VM created successfully"
}
```

**Log Levels:**
- `DEBUG`: RPC parameter details, internal state transitions
- `INFO`: VM lifecycle events, attestation results, service starts
- `WARN`: Retry attempts, degraded performance, deprecated API usage
- `ERROR`: Failed operations, TPM errors, quota exceeded
- `CRITICAL`: Daemon crash, TPM lockout, data corruption

**3. Distributed Tracing (OpenTelemetry):**
```
Trace: CreateVM
├─ Span: validate_config (5ms)
├─ Span: allocate_resources (20ms)
├─ Span: create_disk (300ms)
│  └─ Span: qemu-img_create (280ms)
├─ Span: provision_vtpm (150ms)
│  ├─ Span: swtpm_setup (100ms)
│  └─ Span: create_ek (50ms)
├─ Span: configure_network (40ms)
│  └─ Span: attach_port_to_bridge (30ms)
└─ Span: start_qemu (4000ms)
```

**4. Health Checks:**
```bash
# gRPC health check (custom endpoint)
grpcurl -plaintext -unix /var/run/platformd.sock \
  platform.v1.PlatformDaemon/GetHealth

# Returns:
{
  "status": "HEALTH_STATUS_HEALTHY",
  "components": [
    {"name": "tpm", "status": "HEALTH_STATUS_HEALTHY", "message": "TPM 2.0 operational"},
    {"name": "badgerdb", "status": "HEALTH_STATUS_HEALTHY", "message": "DB size: 1.2GB"},
    {"name": "ovs", "status": "HEALTH_STATUS_DEGRADED", "message": "Controller unreachable"}
  ]
}
```

**5. Debugging Tools:**
- `grpcurl`: Interactive RPC testing against Unix socket
- `wireshark`: Capture gRPC traffic (requires HTTP/2 dissector)
- `platformctl debug dump-state`: Export VM/bridge state as JSON
- `platformctl debug replay-events`: Replay event log for root cause analysis

**6. Alerting Rules:**
```yaml
# Prometheus AlertManager rules
- alert: HighVMCreationFailureRate
  expr: rate(platformd_grpc_requests_total{method="CreateVM",status="error"}[5m]) > 0.1
  for: 5m
  annotations:
    summary: "VM creation failures exceed 10% over 5 minutes"

- alert: TPMQuoteLatencyHigh
  expr: platformd_tpm_quote_latency_seconds{quantile="0.99"} > 1.0
  for: 1m
  annotations:
    summary: "TPM quote P99 latency > 1 second"

- alert: ServiceDown
  expr: platformd_service_status{status="running"} == 0
  for: 1m
  annotations:
    summary: "Platform service {{ $labels.service }} is down"
```

### 7.4 Deployment & CI/CD

**How will this architecture be deployed?**

**1. Build Process:**
```bash
# Generate proto code
make proto-gen

# Build daemon binary (static, no CGO)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags="-s -w -X main.Version=1.4.0 -X main.GitCommit=$(git rev-parse HEAD)" \
  -o platformd cmd/platformd/main.go

# Build container image
docker build -t ghcr.io/jeremyhahn/platformd:1.4.0 .
```

**2. Deployment Options:**

**Option A: Systemd Service (Bare Metal)**
```ini
[Unit]
Description=Platform Daemon
After=network.target tpm2-abrmd.service

[Service]
Type=notify
ExecStart=/usr/local/bin/platformd --config /etc/platformd/config.yaml
Restart=on-failure
RestartSec=5s
User=root
Group=platformd
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/platformd /var/run/platformd.sock

[Install]
WantedBy=multi-user.target
```

**Option B: Kubernetes DaemonSet (Edge)**
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: platformd
spec:
  selector:
    matchLabels:
      app: platformd
  template:
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: platformd
        image: ghcr.io/jeremyhahn/platformd:1.4.0
        securityContext:
          privileged: true  # Required for KVM, TPM, OVS
        volumeMounts:
        - name: tpm
          mountPath: /dev/tpm0
        - name: kvm
          mountPath: /dev/kvm
        - name: socket
          mountPath: /var/run/platformd
        - name: data
          mountPath: /var/lib/platformd
      volumes:
      - name: tpm
        hostPath: {path: /dev/tpm0}
      - name: kvm
        hostPath: {path: /dev/kvm}
      - name: socket
        hostPath: {path: /var/run/platformd}
      - name: data
        hostPath: {path: /var/lib/platformd}
```

**3. CI/CD Pipeline (GitHub Actions):**
```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  proto-gen:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with: {go-version: '1.21'}
      - run: make proto-gen
      - run: git diff --exit-code  # Fail if proto gen changes files

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: make test
      - run: make integration-test

  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: make build
      - uses: docker/build-push-action@v4
        with:
          push: true
          tags: ghcr.io/jeremyhahn/platformd:${{ github.sha }}
```

**4. Configuration Management:**
```yaml
# /etc/platformd/config.yaml
daemon:
  socket: /var/run/platformd.sock
  socket_permissions: "0660"
  log_level: info
  metrics_port: 9090

tpm:
  device: /dev/tpm0
  fips_mode: true
  provisioning_strategy: IAK

sdn:
  default_bridge_type: ovs
  ovs_controller: tcp:127.0.0.1:6653

compute:
  vm_storage_path: /var/lib/platformd/vms
  max_vms_per_host: 100
  default_firmware: UEFI_SECURE_BOOT
```

**5. Migration Strategy:**
```bash
# V1.3.0 → V1.4.0 (add gRPC API)
# 1. Deploy V1.4.0 with dual interface (legacy CLI + gRPC)
# 2. Migrate platformctl to gRPC client
# 3. Deprecate legacy CLI after 2 releases
# 4. V1.6.0 removes legacy CLI

# Database migration
platformd migrate --from 1.3.0 --to 1.4.0
# - Converts old YAML-based VM configs to BadgerDB
# - Migrates event logs to time-series database
```

**6. Rollback Plan:**
```bash
# If V1.4.0 fails, rollback to V1.3.0
systemctl stop platformd
cp /usr/local/bin/platformd-v1.3.0 /usr/local/bin/platformd
platformd migrate --from 1.4.0 --to 1.3.0  # Reverse migration
systemctl start platformd
```

---

## Summary

This gRPC API design provides a robust, scalable foundation for the platformd daemon's internal operations. By adopting Protocol Buffers and gRPC, we gain type safety, efficient serialization, and bidirectional streaming while maintaining flexibility for future enhancements. The Unix socket transport ensures security and performance for local IPC, with a clear path to remote access via platformd worker processes serving REST/gRPC APIs.

The architecture scales to 10x load through horizontal scaling (etcd cluster), vertical optimization (connection pooling, caching), and database sharding. Security is enforced through Unix permissions, input validation, TPM-backed secret management, and comprehensive audit logging. Observability is achieved via Prometheus metrics, structured logs, OpenTelemetry tracing, and health checks.

Deployment options range from bare-metal systemd services to Kubernetes DaemonSets, with a well-defined CI/CD pipeline and migration strategy. This design balances immediate project needs with long-term architectural goals, providing a solid foundation for go-trusted-platform's evolution into a full-featured trusted computing platform.

---

**File Locations:**
- Protocol Definitions: `pkg/api/grpc/proto/*.proto`
- Generated Code: `sdk/go/gen/` (gitignored)
- Build Directive: `sdk/go/generate.go`
- Documentation: `pkg/api/grpc/README.md`
