# Compute API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [api.md](api.md), the compute API contract for every transport.

This document provides the API reference for compute orchestration operations.

## Status: 100% Complete

All APIs are fully implemented and production-ready:
- Go API (Orchestrator interface)
- gRPC API (ComputeService)
- REST API (HTTP endpoints)

## Go API

### Orchestrator Interface

The `Orchestrator` interface defines the contract for compute orchestration:

```go
package compute

import (
    "context"

    "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
    "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

type Orchestrator interface {
    // Create creates a new compute instance from a device profile
    Create(ctx context.Context, profile *entities.DeviceProfile) (*Instance, error)

    // Start starts a stopped instance
    Start(ctx context.Context, instanceID string) error

    // Stop stops a running instance
    Stop(ctx context.Context, instanceID string) error

    // Delete deletes an instance and cleans up resources
    Delete(ctx context.Context, instanceID string) error

    // List returns all instances, optionally filtered
    List(ctx context.Context, filter *InstanceFilter) ([]*Instance, error)

    // Get retrieves a specific instance by ID
    Get(ctx context.Context, instanceID string) (*Instance, error)

    // AttachNetwork attaches an instance to an OVS network port
    AttachNetwork(ctx context.Context, instanceID, portName string) error

    // DetachNetwork detaches an instance from an OVS network port
    DetachNetwork(ctx context.Context, instanceID, portName string) error

    // ActivateInstance transitions network port from enrolled to authorized
    ActivateInstance(ctx context.Context, instanceID string, portPolicy *policy.PortPolicy) error

    // Wait waits for an instance to exit (blocks until instance stops)
    Wait(ctx context.Context, instanceID string) error

    // GetState returns the current state of an instance
    GetState(ctx context.Context, instanceID string) (InstanceState, error)

    // Close closes the orchestrator and releases resources
    Close() error
}
```

### Creating an Orchestrator

```go
import (
    "github.com/jeremyhahn/go-trusted-platform/pkg/compute"
    "github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Create configuration
config := compute.DefaultOrchestratorConfig(compute.ComputeTypeVM)

// Create logger
logger := logging.DefaultLogger()

// Create orchestrator
orchestrator, err := compute.NewQEMUOrchestrator(config, logger)
if err != nil {
    return fmt.Errorf("failed to create orchestrator: %w", err)
}
defer orchestrator.Close()
```

### Instance Lifecycle Methods

#### Create

Creates a new compute instance from a device profile.

```go
func (o *Orchestrator) Create(ctx context.Context, profile *entities.DeviceProfile) (*Instance, error)
```

**Parameters:**
- `ctx` - Context for cancellation and timeout
- `profile` - Device profile defining instance configuration

**Returns:**
- `*Instance` - Created instance with ID and initial state
- `error` - Error if creation fails

**Example:**
```go
profile := &entities.DeviceProfile{
    Name:  "web-server-001",
    Model: "Standard VM",
    Role:  entities.DeviceRoleServer,
}

instance, err := orchestrator.Create(ctx, profile)
if err != nil {
    return fmt.Errorf("create failed: %w", err)
}
fmt.Printf("Created instance: %s\n", instance.ID)
```

**Errors:**
- `ErrInvalidProfile` - Profile is nil or invalid
- `ErrResourceExhausted` - MaxInstances limit reached
- `ErrInvalidConfiguration` - Invalid configuration

---

#### Start

Starts a stopped instance.

```go
func (o *Orchestrator) Start(ctx context.Context, instanceID string) error
```

**Parameters:**
- `ctx` - Context for cancellation and timeout
- `instanceID` - Unique instance identifier

**Returns:**
- `error` - Error if start fails

**Example:**
```go
if err := orchestrator.Start(ctx, instance.ID); err != nil {
    return fmt.Errorf("start failed: %w", err)
}
```

**Errors:**
- `ErrInstanceNotFound` - Instance does not exist
- `ErrInstanceAlreadyRunning` - Instance is already running
- `ErrInvalidState` - Instance not in stopped state

---

#### Stop

Stops a running instance.

```go
func (o *Orchestrator) Stop(ctx context.Context, instanceID string) error
```

**Parameters:**
- `ctx` - Context for cancellation and timeout
- `instanceID` - Unique instance identifier

**Returns:**
- `error` - Error if stop fails

**Example:**
```go
if err := orchestrator.Stop(ctx, instance.ID); err != nil {
    return fmt.Errorf("stop failed: %w", err)
}
```

**Errors:**
- `ErrInstanceNotFound` - Instance does not exist
- `ErrInstanceNotRunning` - Instance is not running

---

#### Delete

Deletes an instance and cleans up all resources.

```go
func (o *Orchestrator) Delete(ctx context.Context, instanceID string) error
```

**Parameters:**
- `ctx` - Context for cancellation and timeout
- `instanceID` - Unique instance identifier

**Returns:**
- `error` - Error if deletion fails

**Example:**
```go
if err := orchestrator.Delete(ctx, instance.ID); err != nil {
    return fmt.Errorf("delete failed: %w", err)
}
```

**Errors:**
- `ErrInstanceNotFound` - Instance does not exist
- `ErrInvalidState` - Instance must be stopped

**Cleanup performed:**
- Stops swtpm if running
- Removes TPM state directory
- Removes disk image
- Removes NVRAM copy
- Removes instance from registry

---

### Query Methods

#### List

Returns all instances, optionally filtered.

```go
func (o *Orchestrator) List(ctx context.Context, filter *InstanceFilter) ([]*Instance, error)
```

**Parameters:**
- `ctx` - Context for cancellation and timeout
- `filter` - Optional filter criteria (nil for all instances)

**Returns:**
- `[]*Instance` - Slice of matching instances
- `error` - Error if query fails

**Example:**
```go
// List all instances
instances, err := orchestrator.List(ctx, nil)

// List running VMs
runningState := compute.StateRunning
vmType := compute.ComputeTypeVM
filter := &compute.InstanceFilter{
    State: &runningState,
    Type:  &vmType,
}
instances, err := orchestrator.List(ctx, filter)
```

---

#### Get

Retrieves a specific instance by ID.

```go
func (o *Orchestrator) Get(ctx context.Context, instanceID string) (*Instance, error)
```

**Parameters:**
- `ctx` - Context for cancellation and timeout
- `instanceID` - Unique instance identifier

**Returns:**
- `*Instance` - Instance details
- `error` - Error if not found

**Example:**
```go
instance, err := orchestrator.Get(ctx, instanceID)
if err != nil {
    if errors.Is(err, compute.ErrInstanceNotFound) {
        fmt.Println("Instance not found")
    }
    return err
}
fmt.Printf("Instance: %s, State: %s\n", instance.Name, instance.State)
```

---

#### GetState

Returns the current state of an instance.

```go
func (o *Orchestrator) GetState(ctx context.Context, instanceID string) (InstanceState, error)
```

**Parameters:**
- `ctx` - Context for cancellation and timeout
- `instanceID` - Unique instance identifier

**Returns:**
- `InstanceState` - Current state
- `error` - Error if not found

**Example:**
```go
state, err := orchestrator.GetState(ctx, instanceID)
if err != nil {
    return err
}
fmt.Printf("State: %s\n", state)
```

---

### Network Methods

#### AttachNetwork

Attaches an instance to an OVS network port.

```go
func (o *Orchestrator) AttachNetwork(ctx context.Context, instanceID, portName string) error
```

**Parameters:**
- `ctx` - Context for cancellation and timeout
- `instanceID` - Unique instance identifier
- `portName` - OVS port name to create

**Returns:**
- `error` - Error if attachment fails

**Example:**
```go
portName := fmt.Sprintf("vm-%s", instance.ID[:8])
if err := orchestrator.AttachNetwork(ctx, instance.ID, portName); err != nil {
    return fmt.Errorf("attach network failed: %w", err)
}
```

**Errors:**
- `ErrInstanceNotFound` - Instance does not exist
- `ErrNetworkAttachmentFailed` - OVS operation failed

**With Port Authentication:**
When `PortAuthEnabled` is true, the port enters Provisioning state with limited network access.

---

#### DetachNetwork

Detaches an instance from an OVS network port.

```go
func (o *Orchestrator) DetachNetwork(ctx context.Context, instanceID, portName string) error
```

**Parameters:**
- `ctx` - Context for cancellation and timeout
- `instanceID` - Unique instance identifier
- `portName` - OVS port name to remove

**Returns:**
- `error` - Error if detachment fails

**Example:**
```go
if err := orchestrator.DetachNetwork(ctx, instance.ID, portName); err != nil {
    return fmt.Errorf("detach network failed: %w", err)
}
```

---

#### ActivateInstance

Transitions network port from enrolled to authorized state.

```go
func (o *Orchestrator) ActivateInstance(ctx context.Context, instanceID string, portPolicy *policy.PortPolicy) error
```

**Parameters:**
- `ctx` - Context for cancellation and timeout
- `instanceID` - Unique instance identifier
- `portPolicy` - Production network policy to apply

**Returns:**
- `error` - Error if activation fails

**Example:**
```go
portPolicy := &policy.PortPolicy{
    TenantID:  "tenant-1",
    VLAN:      100,
    ExpiresAt: time.Now().Add(24 * time.Hour),
}

if err := orchestrator.ActivateInstance(ctx, instance.ID, portPolicy); err != nil {
    return fmt.Errorf("activation failed: %w", err)
}
```

---

#### Wait

Waits for an instance to exit.

```go
func (o *Orchestrator) Wait(ctx context.Context, instanceID string) error
```

**Parameters:**
- `ctx` - Context for cancellation and timeout
- `instanceID` - Unique instance identifier

**Returns:**
- `error` - Error if wait fails

**Example:**
```go
// Wait with timeout
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
defer cancel()

if err := orchestrator.Wait(ctx, instance.ID); err != nil {
    if errors.Is(err, context.DeadlineExceeded) {
        fmt.Println("Wait timed out")
    }
    return err
}
fmt.Println("Instance exited")
```

---

### Cleanup Methods

#### Close

Closes the orchestrator and releases resources.

```go
func (o *Orchestrator) Close() error
```

**Returns:**
- `error` - Error if cleanup fails

**Example:**
```go
defer orchestrator.Close()
```

---

## gRPC API

The compute gRPC API is defined in `pkg/api/grpc/proto/compute.proto`.

### Service Definition

```protobuf
service ComputeService {
  // VM operations
  rpc CreateVM(CreateVMRequest) returns (CreateVMResponse);
  rpc StartVM(StartVMRequest) returns (StartVMResponse);
  rpc StopVM(StopVMRequest) returns (StopVMResponse);
  rpc RebootVM(RebootVMRequest) returns (RebootVMResponse);
  rpc DeleteVM(DeleteVMRequest) returns (DeleteVMResponse);
  rpc GetVM(GetVMRequest) returns (GetVMResponse);
  rpc ListVMs(ListVMsRequest) returns (ListVMsResponse);

  // VM console and monitoring
  rpc AttachVMConsole(AttachVMConsoleRequest) returns (stream ConsoleOutput);
  rpc GetVMLogs(GetVMLogsRequest) returns (stream LogEntry);
  rpc GetVMMetrics(GetVMMetricsRequest) returns (VMMetricsResponse);

  // VM disk operations
  rpc AttachDisk(AttachDiskRequest) returns (AttachDiskResponse);
  rpc DetachDisk(DetachDiskRequest) returns (DetachDiskResponse);
  rpc ResizeDisk(ResizeDiskRequest) returns (ResizeDiskResponse);

  // VM snapshot operations
  rpc CreateSnapshot(CreateSnapshotRequest) returns (CreateSnapshotResponse);
  rpc RestoreSnapshot(RestoreSnapshotRequest) returns (RestoreSnapshotResponse);
  rpc DeleteSnapshot(DeleteSnapshotRequest) returns (DeleteSnapshotResponse);
  rpc ListSnapshots(ListSnapshotsRequest) returns (ListSnapshotsResponse);

  // VM migration
  rpc MigrateVM(MigrateVMRequest) returns (MigrateVMResponse);

  // Container operations
  rpc CreateContainer(CreateContainerRequest) returns (CreateContainerResponse);
  rpc StartContainer(StartContainerRequest) returns (StartContainerResponse);
  rpc StopContainer(StopContainerRequest) returns (StopContainerResponse);
  rpc DeleteContainer(DeleteContainerRequest) returns (DeleteContainerResponse);
  rpc GetContainer(GetContainerRequest) returns (GetContainerResponse);
  rpc ListContainers(ListContainersRequest) returns (ListContainersResponse);

  // VM attestation
  rpc AttestVM(AttestVMRequest) returns (AttestVMResponse);
  rpc VerifyVMAttestation(VerifyVMAttestationRequest) returns (VerifyVMAttestationResponse);

  // Container attestation
  rpc AttestContainer(AttestContainerRequest) returns (AttestContainerResponse);
}
```

### Message Types

#### VMConfig

```protobuf
message VMConfig {
  string name = 1;
  string description = 2;
  FirmwareType firmware = 3;
  BootDevice boot_device = 4;
  CPUConfig cpu = 5;
  MemoryConfig memory = 6;
  repeated DiskConfig disks = 7;
  repeated NetworkConfig networks = 8;
  GraphicsConfig graphics = 9;
  TPMConfig tpm = 10;
  bool secure_boot = 11;
  bytes nvram = 12;
  map<string, string> labels = 13;
  map<string, string> metadata = 14;
}
```

#### CPUConfig

```protobuf
message CPUConfig {
  uint32 cores = 1;
  uint32 sockets = 2;
  uint32 threads = 3;
  string model = 4;
  repeated string features = 5;
}
```

#### MemoryConfig

```protobuf
message MemoryConfig {
  uint64 size_mb = 1;
  bool hugepages = 2;
  bool shared = 3;
}
```

#### DiskConfig

```protobuf
message DiskConfig {
  string id = 1;
  string path = 2;
  DiskType type = 3;
  DiskBus bus = 4;
  uint64 size_gb = 5;
  bool readonly = 6;
  bool bootable = 7;
  string backing_file = 8;
}
```

#### NetworkConfig

```protobuf
message NetworkConfig {
  string id = 1;
  string bridge = 2;
  string mac_address = 3;
  NetworkModel model = 4;
  uint32 vlan = 5;
  uint64 bandwidth_limit_mbps = 6;
}
```

#### TPMConfig

```protobuf
message TPMConfig {
  bool enabled = 1;
  TPMVersion version = 2;
  string device_path = 3;
  bool emulated = 4;
  string state_dir = 5;
}
```

### Enums

#### VMState

```protobuf
enum VMState {
  VM_STATE_UNSPECIFIED = 0;
  VM_STATE_STOPPED = 1;
  VM_STATE_STARTING = 2;
  VM_STATE_RUNNING = 3;
  VM_STATE_PAUSED = 4;
  VM_STATE_STOPPING = 5;
  VM_STATE_REBOOTING = 6;
  VM_STATE_MIGRATING = 7;
  VM_STATE_ERROR = 8;
}
```

#### FirmwareType

```protobuf
enum FirmwareType {
  FIRMWARE_TYPE_UNSPECIFIED = 0;
  FIRMWARE_TYPE_BIOS = 1;
  FIRMWARE_TYPE_UEFI = 2;
  FIRMWARE_TYPE_UEFI_SECURE_BOOT = 3;
}
```

#### DiskType

```protobuf
enum DiskType {
  DISK_TYPE_UNSPECIFIED = 0;
  DISK_TYPE_RAW = 1;
  DISK_TYPE_QCOW2 = 2;
  DISK_TYPE_VDI = 3;
  DISK_TYPE_VMDK = 4;
}
```

---

## REST API

platformd's REST listener serves `/api/v1/compute` from
`restapi.ComputeHandlers` (`pkg/api/rest/compute_handlers.go`). Every route
calls one `ComputeService` RPC — the same service gRPC serves — over protobuf
JSON, behind the scope that RPC requires on gRPC. The wire contract (field
names, enums, query parameters, unknown-field refusal, error mapping) is in
[api.md §1](api.md#1-the-six-transports).

### Endpoints

| Method | Endpoint | RPC | Scope |
|--------|----------|-----|-------|
| POST | /api/v1/compute/vms | `CreateVM` | `vm:write` |
| GET | /api/v1/compute/vms | `ListVMs` | `vm:read` |
| GET | /api/v1/compute/vms/{id} | `GetVM` | `vm:read` |
| DELETE | /api/v1/compute/vms/{id} | `DeleteVM` | `vm:delete` |
| POST | /api/v1/compute/vms/{id}/start | `StartVM` | `vm:write` |
| POST | /api/v1/compute/vms/{id}/stop | `StopVM` | `vm:write` |
| POST | /api/v1/compute/vms/{id}/reboot | `RebootVM` | `vm:write` |
| GET | /api/v1/compute/vms/{id}/metrics | `GetVMMetrics` | `vm:read` |
| POST | /api/v1/compute/vms/{vmId}/migrate | `MigrateVM` | `vm:write` |
| POST | /api/v1/compute/vms/{vmId}/disks | `AttachDisk` | `vm:write` |
| DELETE | /api/v1/compute/vms/{vmId}/disks/{diskId} | `DetachDisk` | `vm:write` |
| PATCH | /api/v1/compute/vms/{vmId}/disks/{diskId} | `ResizeDisk` | `vm:write` |
| POST | /api/v1/compute/vms/{vmId}/snapshots | `CreateSnapshot` | `vm:write` |
| GET | /api/v1/compute/vms/{vmId}/snapshots | `ListSnapshots` | `vm:read` |
| DELETE | /api/v1/compute/vms/{vmId}/snapshots/{snapshotId} | `DeleteSnapshot` | `vm:delete` |
| POST | /api/v1/compute/vms/{vmId}/snapshots/{snapshotId}/restore | `RestoreSnapshot` | `vm:write` |
| POST | /api/v1/compute/vms/{vmId}/attest | `AttestVM` | `vm:read` |
| POST | /api/v1/compute/vms/{vmId}/attest/verify | `VerifyVMAttestation` | `vm:read` |
| POST | /api/v1/compute/containers | `CreateContainer` | `container:write` |
| GET | /api/v1/compute/containers | `ListContainers` | `container:read` |
| GET | /api/v1/compute/containers/{id} | `GetContainer` | `container:read` |
| DELETE | /api/v1/compute/containers/{id} | `DeleteContainer` | `container:delete` |
| POST | /api/v1/compute/containers/{id}/start | `StartContainer` | `container:write` |
| POST | /api/v1/compute/containers/{id}/stop | `StopContainer` | `container:write` |
| POST | /api/v1/compute/containers/{id}/exec | `ExecContainer` | `container:write` |
| POST | /api/v1/compute/containers/{id}/attest | `AttestContainer` | `container:read` |
| GET | /api/v1/compute/containers/{id}/metrics | `GetContainerMetrics` | `container:read` |
| DELETE | /api/v1/compute/containers | `DeleteContainer` | `container:delete` |
| POST | /api/v1/compute/containers/start | `StartContainer` | `container:write` |
| POST | /api/v1/compute/containers/stop | `StopContainer` | `container:write` |
| POST | /api/v1/compute/containers/attest | `AttestContainer` | `container:read` |

The last four are the forms the Go SDK sends, with the container `id` in the
body; the JavaScript SDK puts it in the path. A path parameter fills the
request field of the same name, so `{vmId}` is `vmId` and `{id}` is `id`.

Suspend, resume, restart, console and logs have no route: suspend and resume
have no `ComputeService` RPC, and console and logs are gRPC streams.

### Request/Response Examples

#### Create VM

**Request:**
```http
POST /api/v1/compute/vms HTTP/1.1
Authorization: Bearer <token with vm:write>
Content-Type: application/json

{
  "config": {
    "name": "web-server-001",
    "cpu": {
      "cores": 4
    },
    "memory": {
      "sizeMb": 4096
    },
    "disks": [
      {
        "path": "/var/lib/compute/web-server-001/disk.qcow2",
        "type": "DISK_TYPE_QCOW2",
        "sizeGb": 20,
        "bootable": true
      }
    ],
    "networks": [
      {
        "bridge": "br-int",
        "model": "NETWORK_MODEL_VIRTIO"
      }
    ],
    "tpm": {
      "enabled": true,
      "version": "TPM_VERSION_2_0",
      "emulated": true
    },
    "secureBoot": true
  },
  "start": true
}
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": {
    "success": true,
    "message": "VM created successfully"
  },
  "vm": {
    "id": "abc123",
    "config": { ... },
    "state": "VM_STATE_RUNNING",
    "createdAt": "2025-01-15T10:30:00Z"
  }
}
```

#### List VMs

**Request:**
```http
GET /api/v1/compute/vms?states=VM_STATE_RUNNING&pagination.pageSize=20&selector.matchLabels.tier=web HTTP/1.1
Authorization: Bearer <token with vm:read>
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "vms": [
    {
      "id": "abc123",
      "config": {
        "name": "web-server-001"
      },
      "state": "VM_STATE_RUNNING"
    }
  ],
  "pagination": {
    "page": 0,
    "pageSize": 20,
    "totalPages": 1,
    "totalItems": "1"
  }
}
```

`totalItems` is a `uint64`, which protobuf JSON writes as a string.

#### A refused request

```http
POST /api/v1/compute/vms/abc123/stop HTTP/1.1
Authorization: Bearer <token with vm:write>
Content-Type: application/json

{"force": true, "timeout": 30}
```

answers `400` with `ErrInvalidRequestBody` (`unknown field "timeout"`; the
field is `timeoutSeconds`), and `GET /api/v1/compute/vms?state=RUNNING`
answers `400` with `ErrInvalidQueryParameter`. Neither reaches the compute
service.

---

## VM Snapshots and Attestation

### Snapshot semantics

VM snapshots are **internal QEMU snapshots** (savevm / loadvm / delvm /
"info snapshots" over the VM's QMP monitor) implemented by the canonical
`compute.VMSnapshotter` capability interface, which `compute.QEMUOrchestrator`
implements. Protocol surfaces type-assert the capability on the compute
orchestrator; container orchestrators do not implement it and requests are
rejected with a typed capability-not-supported error.

Requirements and typed rejections:

- **qcow2 only** — internal snapshots live inside the qcow2 image. A
  non-qcow2 disk returns `ErrUnsupportedDiskFormat` (gRPC
  `FAILED_PRECONDITION`, REST 409).
- **Running VM only** — savevm/loadvm are QMP commands and require a running
  QEMU process. A stopped VM returns `ErrInstanceNotRunning` (gRPC
  `FAILED_PRECONDITION`).
- **Full snapshots only** — internal snapshots always capture memory + disk.
  A gRPC `SnapshotConfig` requesting exactly one of `memory_snapshot` /
  `disk_snapshot` is rejected with `INVALID_ARGUMENT` (both set or both
  unset means a full snapshot).
- Snapshot names are validated (`ErrInvalidSnapshotName`), and unknown
  snapshots return `ErrSnapshotNotFound` (gRPC `NOT_FOUND`).

### Attestation semantics

VM attestation is implemented by the canonical `compute.VMAttester`
capability interface:

- `AttestVM(ctx, instanceID, nonce, pcrIndices)` generates a TPM quote from
  the instance's per-VM swtpm (socket recorded in
  `Instance.Metadata["tpm_socket"]`) via the go-xkms SDK TPM connected to
  the socket and the `pkg/attestation/vm` attestor. An empty nonce is
  replaced with a platform-generated 32-byte random nonce; an empty PCR
  selection defaults to PCRs 0-7. Only the SHA-256 bank is supported —
  other banks are rejected with `INVALID_ARGUMENT`. Attestation requires a
  running VM (swtpm runs with the VM) and a vTPM-enabled instance
  (`ErrVTPMNotAvailable` otherwise).
- `VerifyVMAttestation(ctx, instanceID, evidence)` verifies submitted quote
  evidence against the instance's **live** vTPM attestation key: the AK
  signature over the marshaled `TPMS_ATTEST` under the scheme the evidence
  declares in `SignatureAlgorithm` (RSASSA-PKCS1-v1_5, RSA-PSS or ECDSA
  ASN.1 over SHA-256/384/512, as `AttestVM` reported it; absent, unknown or
  mismatched fails), the embedded anti-replay nonce, and — when expected
  PCR values are supplied — the quote's PCR digest recomputed from the
  expected values (the expected index set must exactly match the quote's
  PCR selection). Live PCR values for the expected indices are returned as
  diagnostics.

### Protocol surfaces

| Surface | Wiring |
|---------|--------|
| gRPC / Unix | `ComputeService` `CreateSnapshot` / `RestoreSnapshot` / `DeleteSnapshot` / `ListSnapshots` / `AttestVM` / `VerifyVMAttestation` |
| QUIC | Extended VM operations are multiplexed as sub-opcodes in `payload[0]` under `OpVMExtendedCategory` (0x69, inside the VM opcode range) because the direct extended opcodes 0xB6-0xBF collide with the IAM role/group ranges at the top level. Sub-opcodes: `OpVMSnapshot`, `OpVMSnapshotRestore`, `OpVMSnapshotDelete`, `OpVMSnapshotList`, `OpVMAttest`, `OpVMVerifyAttest` |
| MCP | `vm_snapshot_create`, `vm_snapshot_get`, `vm_snapshot_list`, `vm_snapshot_delete`, `vm_snapshot_restore`, `vm_attest`, `vm_attest_verify` (optional `VMProvider` capability on the service provider) |
| REST | platformd's REST listener: `POST`/`GET /api/v1/compute/vms/{vmId}/snapshots`, `DELETE .../snapshots/{snapshotId}`, `POST .../snapshots/{snapshotId}/restore`, `POST /api/v1/compute/vms/{vmId}/attest` and `POST .../attest/verify`, each calling the `ComputeService` RPC above ([REST API](#rest-api)) |

Suspend / resume / restart / console remain honestly unimplemented: no
production orchestrator provides the `VMExtendedLifecycle` capability yet,
so those operations return typed not-supported errors on every surface.

---

## Error Codes

### Go Errors

| Error | HTTP Code | Description |
|-------|-----------|-------------|
| ErrInstanceNotFound | 404 | Instance does not exist |
| ErrInstanceAlreadyExists | 409 | Instance ID already in use |
| ErrInstanceNotRunning | 400 | Instance is not running |
| ErrInstanceAlreadyRunning | 409 | Instance is already running |
| ErrInvalidConfiguration | 400 | Configuration validation failed |
| ErrInvalidInstanceID | 400 | Empty or invalid instance ID |
| ErrInvalidProfile | 400 | Device profile validation failed |
| ErrNetworkAttachmentFailed | 500 | OVS operation failed |
| ErrNetworkDetachmentFailed | 500 | OVS cleanup failed |
| ErrOrchestratorNotInitialized | 500 | Orchestrator not ready |
| ErrUnsupportedOperation | 501 | Operation not supported |
| ErrInvalidState | 400 | Invalid state transition |
| ErrTimeout | 408 | Operation timed out |
| ErrResourceExhausted | 429 | Resource limit reached |
| ErrUnsupportedDiskFormat | 409 | Internal snapshots require qcow2 |
| ErrInvalidSnapshotName | 400 | Snapshot name failed validation |
| ErrSnapshotNotFound | 404 | Snapshot does not exist |
| ErrVTPMNotAvailable | 409 | Instance has no usable vTPM |
| ErrInvalidAttestationEvidence | 400 | Verification evidence missing fields |

### gRPC Status Codes

| Status | Description |
|--------|-------------|
| OK | Success |
| NOT_FOUND | Instance not found |
| ALREADY_EXISTS | Instance already exists |
| INVALID_ARGUMENT | Invalid parameters |
| FAILED_PRECONDITION | Invalid state for operation |
| RESOURCE_EXHAUSTED | Resource limit reached |
| INTERNAL | Internal error |
| UNAVAILABLE | Service unavailable |
| DEADLINE_EXCEEDED | Timeout |

---

## See Also

- [Configuration](configuration.md) - Configuration reference
- [CLI Usage](cli-usage.md) - Command-line interface
- [Architecture](architecture.md) - System design
- [api.md](api.md) - The current compute API contract
