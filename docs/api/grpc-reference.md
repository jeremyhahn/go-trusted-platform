# gRPC API Reference

Package: `platform.v1`

Socket: `/run/platformd/platformd.sock`

## Services

| Service | Description |
|---------|-------------|
| [PlatformDaemon](#platformdaemon-service) | System and service management |
| [TPMService](#tpmservice) | TPM operations |
| [ComputeService](#computeservice) | VM and container lifecycle |
| [SDNService](#sdnservice) | Software-defined networking |

---

## PlatformDaemon Service

Main service for system operations and service management.

### System Operations

#### GetStatus

Returns platform status and information.

```protobuf
rpc GetStatus(GetStatusRequest) returns (GetStatusResponse);
```

**Response:**
- `status` - SystemStatus enum
- `info` - PlatformInfo (hostname, version, TPM info)
- `services` - List of ServiceInfo

#### GetHealth

Returns health status of all components.

```protobuf
rpc GetHealth(GetHealthRequest) returns (GetHealthResponse);
```

**Request:**
- `detailed` (bool) - Include detailed component info

**Response:**
- `status` - HealthStatus enum
- `components` - List of ComponentHealth

#### GetVersion

Returns version information.

```protobuf
rpc GetVersion(GetVersionRequest) returns (GetVersionResponse);
```

**Response:**
- `version` - Version string
- `build_time` - Build timestamp
- `git_commit` - Git commit hash
- `go_version` - Go version

#### Provision

Provisions the platform with TPM, CA, and network.

```protobuf
rpc Provision(ProvisionRequest) returns (ProvisionResponse);
```

**Request:**
- `owner_password` - TPM owner password
- `endorsement_password` - TPM endorsement password
- `provision_tpm` - Provision TPM
- `provision_ca` - Provision CA
- `provision_network` - Provision network

#### Shutdown

Gracefully shuts down the platform.

```protobuf
rpc Shutdown(ShutdownRequest) returns (ShutdownResponse);
```

**Request:**
- `graceful` (bool) - Wait for operations to complete
- `timeout_seconds` - Shutdown timeout

### Configuration Operations

#### GetConfig

Retrieves configuration sections.

```protobuf
rpc GetConfig(GetConfigRequest) returns (GetConfigResponse);
```

**Request:**
- `section` - Section name (empty for all)

#### UpdateConfig

Updates a configuration section.

```protobuf
rpc UpdateConfig(UpdateConfigRequest) returns (UpdateConfigResponse);
```

**Request:**
- `section` - ConfigSection with name and values
- `persist` - Save to disk

#### ReloadConfig

Reloads configuration from disk.

```protobuf
rpc ReloadConfig(ReloadConfigRequest) returns (ReloadConfigResponse);
```

### Service Management

#### StartService

```protobuf
rpc StartService(StartServiceRequest) returns (StartServiceResponse);
```

**Request:**
- `service` - ServiceType enum
- `options` - Key-value options map

#### StopService

```protobuf
rpc StopService(StopServiceRequest) returns (StopServiceResponse);
```

**Request:**
- `service` - ServiceType enum
- `force` - Force stop
- `timeout_seconds` - Stop timeout

#### RestartService

```protobuf
rpc RestartService(RestartServiceRequest) returns (RestartServiceResponse);
```

#### GetServiceStatus

```protobuf
rpc GetServiceStatus(GetServiceStatusRequest) returns (GetServiceStatusResponse);
```

#### ListServices

```protobuf
rpc ListServices(ListServicesRequest) returns (ListServicesResponse);
```

**Request:**
- `types` - Filter by service types
- `statuses` - Filter by statuses

### Streaming

#### StreamEvents

Streams platform events.

```protobuf
rpc StreamEvents(StreamEventsRequest) returns (stream Event);
```

**Request:**
- `types` - Event types to filter
- `min_severity` - Minimum severity
- `sources` - Source filters
- `since` - Events since timestamp

#### StreamLogs

Streams service logs.

```protobuf
rpc StreamLogs(StreamLogsRequest) returns (stream LogEntry);
```

#### StreamMetrics

Streams platform metrics.

```protobuf
rpc StreamMetrics(StreamMetricsRequest) returns (stream MetricData);
```

---

## TPMService

TPM 2.0 operations and attestation.

### Info and Provisioning

#### Info

Returns TPM capabilities and information.

```protobuf
rpc Info(TPMInfoRequest) returns (TPMInfoResponse);
```

**Response:**
- `version` - TPM version (1.2, 2.0)
- `manufacturer` - TPMManufacturer info
- `capabilities` - List of TPMCapability
- `pcr_banks` - Available PCR banks
- `is_simulator` - Using simulator
- `fips_mode` - FIPS mode enabled

#### Provision

Initializes TPM with required keys.

```protobuf
rpc Provision(TPMProvisionRequest) returns (TPMProvisionResponse);
```

**Request:**
- `owner_password` - Owner authorization
- `endorsement_password` - Endorsement authorization
- `create_ek` - Create endorsement key
- `create_srk` - Create storage root key
- `create_ak` - Create attestation key
- `ek_attributes`, `srk_attributes`, `ak_attributes` - Key attributes

#### Clear

Clears the TPM (requires owner auth).

```protobuf
rpc Clear(TPMClearRequest) returns (TPMClearResponse);
```

### Key Operations

#### EK (Endorsement Key)

```protobuf
rpc CreateEK(CreateEKRequest) returns (CreateEKResponse);
rpc GetEK(GetEKRequest) returns (GetEKResponse);
rpc GetEKCertificate(GetEKCertificateRequest) returns (GetEKCertificateResponse);
rpc ImportEKCertificate(ImportEKCertificateRequest) returns (ImportEKCertificateResponse);
rpc DeleteEK(DeleteEKRequest) returns (DeleteEKResponse);
```

#### SRK (Storage Root Key)

```protobuf
rpc CreateSRK(CreateSRKRequest) returns (CreateSRKResponse);
rpc GetSRK(GetSRKRequest) returns (GetSRKResponse);
rpc DeleteSRK(DeleteSRKRequest) returns (DeleteSRKResponse);
```

#### AK (Attestation Key)

```protobuf
rpc CreateAK(CreateAKRequest) returns (CreateAKResponse);
rpc GetAK(GetAKRequest) returns (GetAKResponse);
rpc DeleteAK(DeleteAKRequest) returns (DeleteAKResponse);
```

### Seal/Unseal

#### Seal

Seals data to TPM and PCR state.

```protobuf
rpc Seal(SealRequest) returns (SealResponse);
```

**Request:**
- `data` - Data to seal
- `cn` - Common name for sealed object
- `parent_handle` - SRK handle
- `pcr_indices` - PCRs to bind
- `pcr_bank` - PCR bank (SHA256, etc.)

#### Unseal

Unseals previously sealed data.

```protobuf
rpc Unseal(UnsealRequest) returns (UnsealResponse);
```

### Attestation

#### Quote

Generates a TPM quote.

```protobuf
rpc Quote(QuoteRequest) returns (QuoteResponse);
```

**Request:**
- `ak_handle` - Attestation key handle
- `pcr_indices` - PCRs to quote
- `nonce` - Challenge nonce

**Response:**
- `quote` - TPM quote blob
- `signature` - Quote signature
- `pcr_values` - PCR values
- `event_log` - TPM event log

#### VerifyQuote

Verifies a TPM quote.

```protobuf
rpc VerifyQuote(VerifyQuoteRequest) returns (VerifyQuoteResponse);
```

#### GetPCRs

Reads PCR values.

```protobuf
rpc GetPCRs(GetPCRsRequest) returns (GetPCRsResponse);
```

#### GetEventLog

Returns the TPM event log.

```protobuf
rpc GetEventLog(GetEventLogRequest) returns (GetEventLogResponse);
```

### NVRAM

```protobuf
rpc DefineNVRAM(DefineNVRAMRequest) returns (DefineNVRAMResponse);
rpc WriteNVRAM(WriteNVRAMRequest) returns (WriteNVRAMResponse);
rpc ReadNVRAM(ReadNVRAMRequest) returns (ReadNVRAMResponse);
rpc UndefineNVRAM(UndefineNVRAMRequest) returns (UndefineNVRAMResponse);
```

### Random

#### GetRandom

Returns cryptographically random bytes.

```protobuf
rpc GetRandom(GetRandomRequest) returns (GetRandomResponse);
```

---

## ComputeService

VM and container lifecycle management.

### VM Operations

```protobuf
rpc CreateVM(CreateVMRequest) returns (CreateVMResponse);
rpc StartVM(StartVMRequest) returns (StartVMResponse);
rpc StopVM(StopVMRequest) returns (StopVMResponse);
rpc RebootVM(RebootVMRequest) returns (RebootVMResponse);
rpc DeleteVM(DeleteVMRequest) returns (DeleteVMResponse);
rpc GetVM(GetVMRequest) returns (GetVMResponse);
rpc ListVMs(ListVMsRequest) returns (ListVMsResponse);
```

**CreateVMRequest:**
- `config` - VMConfig (name, cpu, memory, disks, networks, TPM)
- `start` - Start immediately

**VMConfig Fields:**
- `name`, `description`
- `firmware` - BIOS, UEFI, UEFI_SECURE_BOOT
- `cpu` - CPUConfig (cores, sockets, threads, model)
- `memory` - MemoryConfig (size_mb, hugepages)
- `disks` - DiskConfig list
- `networks` - NetworkConfig list
- `tpm` - TPMConfig (enabled, version, emulated)
- `secure_boot` - Enable secure boot

### VM Console and Monitoring

```protobuf
rpc AttachVMConsole(AttachVMConsoleRequest) returns (stream ConsoleOutput);
rpc SendVMConsoleInput(stream ConsoleInput) returns (ConsoleInputResponse);
rpc GetVMLogs(GetVMLogsRequest) returns (stream LogEntry);
rpc GetVMMetrics(GetVMMetricsRequest) returns (VMMetricsResponse);
```

### VM Disk Operations

```protobuf
rpc AttachDisk(AttachDiskRequest) returns (AttachDiskResponse);
rpc DetachDisk(DetachDiskRequest) returns (DetachDiskResponse);
rpc ResizeDisk(ResizeDiskRequest) returns (ResizeDiskResponse);
```

### VM Snapshots

```protobuf
rpc CreateSnapshot(CreateSnapshotRequest) returns (CreateSnapshotResponse);
rpc RestoreSnapshot(RestoreSnapshotRequest) returns (RestoreSnapshotResponse);
rpc DeleteSnapshot(DeleteSnapshotRequest) returns (DeleteSnapshotResponse);
rpc ListSnapshots(ListSnapshotsRequest) returns (ListSnapshotsResponse);
```

### VM Migration

```protobuf
rpc MigrateVM(MigrateVMRequest) returns (MigrateVMResponse);
```

**Request:**
- `vm_id` - VM identifier
- `destination_host` - Target host
- `live_migration` - Live migration
- `bandwidth_limit_mbps` - Bandwidth limit

### Container Operations

```protobuf
rpc CreateContainer(CreateContainerRequest) returns (CreateContainerResponse);
rpc StartContainer(StartContainerRequest) returns (StartContainerResponse);
rpc StopContainer(StopContainerRequest) returns (StopContainerResponse);
rpc DeleteContainer(DeleteContainerRequest) returns (DeleteContainerResponse);
rpc GetContainer(GetContainerRequest) returns (GetContainerResponse);
rpc ListContainers(ListContainersRequest) returns (ListContainersResponse);
```

**ContainerConfig Fields:**
- `name`, `image`, `image_hash`
- `command`, `args`, `env`
- `volumes` - VolumeMount list
- `ports` - PortMapping list
- `resources` - ResourceLimits
- `restart_policy`
- `tpm_access` - Mount host TPM

### Container Console and Exec

```protobuf
rpc AttachContainer(AttachContainerRequest) returns (stream ConsoleOutput);
rpc ExecContainer(ExecContainerRequest) returns (ExecContainerResponse);
rpc GetContainerLogs(GetContainerLogsRequest) returns (stream LogEntry);
rpc GetContainerMetrics(GetContainerMetricsRequest) returns (ContainerMetricsResponse);
```

### VM Attestation

```protobuf
rpc AttestVM(AttestVMRequest) returns (AttestVMResponse);
rpc VerifyVMAttestation(VerifyVMAttestationRequest) returns (VerifyVMAttestationResponse);
```

---

## SDNService

Software-defined networking operations.

### Bridge Operations

```protobuf
rpc CreateBridge(CreateBridgeRequest) returns (CreateBridgeResponse);
rpc DeleteBridge(DeleteBridgeRequest) returns (DeleteBridgeResponse);
rpc GetBridge(GetBridgeRequest) returns (GetBridgeResponse);
rpc ListBridges(ListBridgesRequest) returns (ListBridgesResponse);
```

**BridgeConfig Fields:**
- `name` - Bridge name
- `type` - OVS, LINUX, VXLAN
- `datapath_id` - OpenFlow datapath ID
- `stp_enabled` - Enable STP
- `controllers` - OpenFlow controller URLs

### Port Operations

```protobuf
rpc AddPort(AddPortRequest) returns (AddPortResponse);
rpc DeletePort(DeletePortRequest) returns (DeletePortResponse);
rpc GetPort(GetPortRequest) returns (GetPortResponse);
rpc ListPorts(ListPortsRequest) returns (ListPortsResponse);
```

**PortConfig Fields:**
- `name` - Port name
- `type` - INTERNAL, PHYSICAL, TAP, VETH, VXLAN, GRE
- `vlan` - Access VLAN
- `trunk_vlans` - Trunk VLANs
- `mac_address`

### Flow Operations

```protobuf
rpc AddFlow(AddFlowRequest) returns (AddFlowResponse);
rpc DeleteFlow(DeleteFlowRequest) returns (DeleteFlowResponse);
rpc ListFlows(ListFlowsRequest) returns (ListFlowsResponse);
rpc FlushFlows(FlushFlowsRequest) returns (FlushFlowsResponse);
```

**FlowConfig Fields:**
- `bridge_id` - Bridge ID
- `table` - Flow table (0-3, DROP)
- `priority` - Flow priority
- `match` - FlowMatch criteria
- `actions` - FlowAction list

**FlowMatch Fields:**
- `in_port`, `vlan_id`
- `eth_src`, `eth_dst`, `eth_type`
- `ip_src`, `ip_dst`, `ip_proto`
- `tcp_src`, `tcp_dst`, `udp_src`, `udp_dst`

### VLAN Operations

```protobuf
rpc CreateVLAN(CreateVLANRequest) returns (CreateVLANResponse);
rpc DeleteVLAN(DeleteVLANRequest) returns (DeleteVLANResponse);
rpc ListVLANs(ListVLANsRequest) returns (ListVLANsResponse);
```

### Port Authentication (802.1X)

```protobuf
rpc AuthenticatePort(AuthenticatePortRequest) returns (AuthenticatePortResponse);
rpc RevokePortAuth(RevokePortAuthRequest) returns (RevokePortAuthResponse);
```

**AuthenticatePortRequest:**
- `bridge_id`, `port_id`
- `certificate` - X.509 client certificate
- `format` - PEM or DER

### Statistics

```protobuf
rpc GetPortStats(GetPortStatsRequest) returns (GetPortStatsResponse);
rpc GetFlowStats(GetFlowStatsRequest) returns (GetFlowStatsResponse);
```

### Streaming

```protobuf
rpc StreamFlowLogs(StreamFlowLogsRequest) returns (stream FlowLogEntry);
```

---

## Common Types

### Enums

**ServiceType:**
- `TPM`, `SDN`, `COMPUTE`, `DNS`, `ACME`, `WEBSERVICE`, `ATTESTATION`

**ServiceStatus:**
- `STOPPED`, `STARTING`, `RUNNING`, `STOPPING`, `ERROR`

**HealthStatus:**
- `HEALTHY`, `DEGRADED`, `UNHEALTHY`

**KeyAlgorithm:**
- `RSA_2048`, `RSA_3072`, `RSA_4096`
- `ECDSA_P256`, `ECDSA_P384`, `ECDSA_P521`
- `ED25519`
- `DILITHIUM2`, `DILITHIUM3`, `DILITHIUM5`

**HashAlgorithm:**
- `SHA1`, `SHA256`, `SHA384`, `SHA512`
- `SHA3_256`, `SHA3_384`, `SHA3_512`

**PCRBank:**
- `SHA1`, `SHA256`, `SHA384`, `SHA512`, `SM3_256`

### Messages

**Status:**
```protobuf
message Status {
  bool success = 1;
  string message = 2;
  ErrorDetail error = 3;
}
```

**PaginationRequest:**
```protobuf
message PaginationRequest {
  uint32 page = 1;
  uint32 page_size = 2;
  string sort_by = 3;
  bool ascending = 4;
}
```

**LabelSelector:**
```protobuf
message LabelSelector {
  map<string, string> match_labels = 1;
  repeated string match_expressions = 2;
}
```

---

## Go Client Example

```go
package main

import (
    "context"
    "log"

    "github.com/jeremyhahn/go-trusted-platform/pkg/api/unix"
    platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

func main() {
    // Connect to platformd
    client, err := socket.NewClient("/run/platformd/platformd.sock")
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    conn, _ := client.GetConnection()
    ctx := context.Background()

    // Platform daemon
    daemon := platformv1.NewPlatformDaemonClient(conn)
    status, _ := daemon.GetStatus(ctx, &platformv1.GetStatusRequest{})
    log.Printf("Platform: %s", status.Info.Hostname)

    // TPM service
    tpm := platformv1.NewTPMServiceClient(conn)
    info, _ := tpm.Info(ctx, &platformv1.TPMInfoRequest{})
    log.Printf("TPM: %s", info.Manufacturer.Name)

    // Compute service
    compute := platformv1.NewComputeServiceClient(conn)
    vms, _ := compute.ListVMs(ctx, &platformv1.ListVMsRequest{})
    log.Printf("VMs: %d", len(vms.Vms))

    // SDN service
    sdn := platformv1.NewSDNServiceClient(conn)
    bridges, _ := sdn.ListBridges(ctx, &platformv1.ListBridgesRequest{})
    log.Printf("Bridges: %d", len(bridges.Bridges))
}
```
