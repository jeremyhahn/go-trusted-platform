# Device gRPC API Reference

Endpoint: `localhost:9443`

## Service Definitions

```protobuf
service DeviceService {
  rpc RegisterDevice(RegisterDeviceRequest) returns (RegisterDeviceResponse);
  rpc GetDevice(GetDeviceRequest) returns (GetDeviceResponse);
  rpc UpdateDevice(UpdateDeviceRequest) returns (UpdateDeviceResponse);
  rpc DeleteDevice(DeleteDeviceRequest) returns (DeleteDeviceResponse);
  rpc ListDevices(ListDevicesRequest) returns (ListDevicesResponse);
  rpc FindDeviceBySerial(FindDeviceBySerialRequest) returns (FindDeviceBySerialResponse);
  rpc AttestDevice(AttestDeviceRequest) returns (AttestDeviceResponse);
}

service ProfileService {
  rpc CreateProfile(CreateProfileRequest) returns (CreateProfileResponse);
  rpc GetProfile(GetProfileRequest) returns (GetProfileResponse);
  rpc UpdateProfile(UpdateProfileRequest) returns (UpdateProfileResponse);
  rpc DeleteProfile(DeleteProfileRequest) returns (DeleteProfileResponse);
  rpc ListProfiles(ListProfilesRequest) returns (ListProfilesResponse);
  rpc FindMatchingProfile(FindMatchingProfileRequest) returns (FindMatchingProfileResponse);
  rpc FindProfileByMACAddress(FindProfileByMACRequest) returns (FindProfileByMACResponse);
  rpc FindProfileBySerial(FindProfileBySerialRequest) returns (FindProfileBySerialResponse);
}
```

## Device Messages

```protobuf
message Device {
  uint64 id = 1;
  string serial = 2;
  string model = 3;
  string ek_cert = 4;         // PEM encoded
  string attest_pub = 5;      // PEM encoded
  string signing_pub = 6;     // PEM encoded
  bytes event_log = 7;
  uint32 hash_algo_id = 8;
  string attest_cert = 14;    // PEM IAK/AK certificate issued at enrollment; the quote trust anchor (#404)
}

message RegisterDeviceRequest {
  string serial = 1;
  string model = 2;
  string ek_cert = 3;
  string attest_pub = 4;
  string signing_pub = 5;
  bytes event_log = 6;
  uint32 hash_algo_id = 7;
}

message RegisterDeviceResponse {
  Device device = 1;
}

message GetDeviceRequest {
  uint64 id = 1;
}

message GetDeviceResponse {
  Device device = 1;
}

message UpdateDeviceRequest {
  Device device = 1;
}

message UpdateDeviceResponse {
  Device device = 1;
}

message DeleteDeviceRequest {
  uint64 id = 1;
}

message DeleteDeviceResponse {
  bool success = 1;
}

message ListDevicesRequest {
  int32 page = 1;
  int32 page_size = 2;
  string sort_order = 3;
}

message ListDevicesResponse {
  repeated Device devices = 1;
  int32 page = 2;
  int32 page_size = 3;
  int32 total_count = 4;
  int32 total_pages = 5;
}

message FindDeviceBySerialRequest {
  string serial = 1;
}

message FindDeviceBySerialResponse {
  Device device = 1;
}

message AttestDeviceRequest {
  string device_id = 1;
  // evidence is the JSON-encoded DeviceQuoteEvidence
  // {quote, signature, nonce, pcrs} — the same bytes on every transport.
  bytes evidence = 2;
}

// Each check is reported separately from the overall verdict; see
// docs/device/api.md §4.4 for what each one means and how failures are
// classified.
message AttestDeviceResponse {
  Status status = 1;
  uint64 device_id = 2;
  string serial = 3;
  string model = 4;
  bool verified = 5;
  bool signature_valid = 6;
  bool nonce_valid = 7;
  bool pcrs_valid = 8;
  string attestation_status = 9;
  string message = 10;
  google.protobuf.Timestamp attested_at = 11;
  // TCG DevID v1 r12 §8.2: the enrolled attestation certificate chains to
  // the platform CA and carries tcg-cap-verifiedTPMRestricted.
  bool ak_certificate_verified = 12;
  // "signed" or "tofu"; empty when no baseline was evaluated.
  string pcr_baseline_source = 13;
  google.protobuf.Timestamp pcr_baseline_recorded_at = 14;
  // This verification captured the profile's trust-on-first-use baseline.
  bool pcr_baseline_captured = 15;
}
```

## Profile Messages

```protobuf
message DeviceProfile {
  uint64 id = 1;
  string name = 2;
  string model = 3;
  string role = 4;
  bytes event_log = 5;
  ProfileMatchRules match_rules = 6;
  NetworkPhaseConfig provisioning_network = 7;
  NetworkPhaseConfig production_network = 8;
  NetworkPhaseConfig quarantine_network = 9;
  PlatformdConfigRef platformd_config = 10;
}

message ProfileMatchRules {
  string mac_prefix = 1;
  string serial_prefix = 2;
  string model = 3;
  map<string, string> custom_attributes = 4;
}
```

> The authoritative `DeviceProfile` message lives in
> `pkg/api/grpc/proto/device.proto` and additionally carries the
> device-identity binding (`ek_serial`, `mac_address`), the assignment
> state (`assigned`, `assigned_at`), the full device config as JSON
> bytes (`config`), and the prestaged hardware EK certificate
> (`ek_cert`, PEM). Profile create/update round-trip all of these
> fields; `config` bytes that are not valid JSON and a non-empty
> `ek_cert` that does not parse as a PEM X.509 certificate are rejected
> with `INVALID_ARGUMENT`. `ek_cert` is readable as well as writable by
> design: an EK certificate is public key material (an X.509 certificate
> carrying no secrets), so echoing it back on reads lets operators audit
> which certificate is prestaged. Prestaging `ek_cert` on a profile arms
> the EK-binding gate of pre-enrollment config delivery and remote UKI
> signing (see `docs/provisioning/config-delivery.md`).

```protobuf

message NetworkPhaseConfig {
  uint32 vlan = 1;
  DHCPPoolConfig dhcp_pool = 2;
  string static_ip = 3;
  string gateway = 4;
  repeated string dns = 5;
  string auth_method = 6;
  repeated ACLConfig acls = 7;
}

message CreateProfileRequest {
  string name = 1;
  string model = 2;
  string role = 3;
  ProfileMatchRules match_rules = 4;
  NetworkPhaseConfig provisioning_network = 5;
  NetworkPhaseConfig production_network = 6;
  NetworkPhaseConfig quarantine_network = 7;
}

message CreateProfileResponse {
  DeviceProfile profile = 1;
}

message GetProfileRequest {
  uint64 id = 1;
}

message GetProfileResponse {
  DeviceProfile profile = 1;
}

message UpdateProfileRequest {
  DeviceProfile profile = 1;
}

message UpdateProfileResponse {
  DeviceProfile profile = 1;
}

message DeleteProfileRequest {
  uint64 id = 1;
}

message DeleteProfileResponse {
  bool success = 1;
}

message ListProfilesRequest {
  int32 page = 1;
  int32 page_size = 2;
  string sort_order = 3;
}

message ListProfilesResponse {
  repeated DeviceProfile profiles = 1;
  int32 page = 2;
  int32 page_size = 3;
  int32 total_count = 4;
  int32 total_pages = 5;
}

message FindMatchingProfileRequest {
  string mac_address = 1;
  string serial = 2;
  string model = 3;
}

message FindMatchingProfileResponse {
  DeviceProfile profile = 1;
}

message FindProfileByMACRequest {
  string mac_prefix = 1;
}

message FindProfileByMACResponse {
  DeviceProfile profile = 1;
}

message FindProfileBySerialRequest {
  string serial_prefix = 1;
}

message FindProfileBySerialResponse {
  DeviceProfile profile = 1;
}
```

## Profile Assignment

The `platform.v1.DeviceService` exposes profile-to-device binding
(canonical proto: `pkg/api/grpc/proto/device.proto`):

```protobuf
rpc AssignProfileToDevice(AssignProfileToDeviceRequest) returns (AssignProfileToDeviceResponse);
rpc UnassignProfileFromDevice(UnassignProfileFromDeviceRequest) returns (UnassignProfileFromDeviceResponse);

message AssignProfileToDeviceRequest {
  uint64 profile_id = 1;
  string ek_serial = 2;
  string mac_address = 3;
  // ek_cert optionally prestages the device's PEM-encoded TPM EK
  // certificate. Source-agnostic: swtpm-backed vTPM or physical
  // hardware TPM. Empty leaves any prestaged certificate untouched.
  string ek_cert = 4;
}

message AssignProfileToDeviceResponse {
  DeviceProfile profile = 1;
}

message UnassignProfileFromDeviceRequest {
  uint64 profile_id = 1;
}

message UnassignProfileFromDeviceResponse {
  DeviceProfile profile = 1;
}
```

`AssignProfileToDevice` requires a non-zero `profile_id` plus at least
one of `ek_serial` / `mac_address`; a non-empty `ek_cert` must parse as
a PEM X.509 certificate. `UnassignProfileFromDevice` clears the EK
serial, MAC address, prestaged EK certificate, and assignment state.
Both RPCs return the updated profile. The same RPCs are reachable over
the Unix socket transport (gRPC over UDS).

## Usage Examples

### Go Client

```go
import (
    "context"
    "crypto/tls"
    "crypto/x509"

    pb "github.com/jeremyhahn/go-trusted-platform/api/v1/device"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

func main() {
    // Load TLS credentials
    creds, _ := credentials.NewClientTLSFromFile("ca.crt", "")

    conn, _ := grpc.Dial("localhost:9443", grpc.WithTransportCredentials(creds))
    defer conn.Close()

    client := pb.NewDeviceServiceClient(conn)

    // Register device
    resp, _ := client.RegisterDevice(context.Background(), &pb.RegisterDeviceRequest{
        Serial:    "SRV-2024-001",
        Model:     "TrustedServer-v2",
        EkCert:    "-----BEGIN CERTIFICATE-----\n...",
        HashAlgoId: 11,
    })

    fmt.Printf("Device ID: %d\n", resp.Device.Id)
}
```

### grpcurl

```bash
# List devices
grpcurl -cacert ca.crt \
  -d '{"page": 1, "page_size": 10}' \
  localhost:9443 device.DeviceService/ListDevices

# Get device
grpcurl -cacert ca.crt \
  -d '{"id": 1234567890}' \
  localhost:9443 device.DeviceService/GetDevice

# Register device
grpcurl -cacert ca.crt \
  -d '{"serial": "SRV-2024-001", "model": "TrustedServer-v2"}' \
  localhost:9443 device.DeviceService/RegisterDevice

# Find matching profile
grpcurl -cacert ca.crt \
  -d '{"mac_address": "52:54:00:aa:bb:cc", "serial": "IOT-001"}' \
  localhost:9443 device.ProfileService/FindMatchingProfile

# Attest device
grpcurl -cacert ca.crt \
  -d '{"device_id": 1234567890, "nonce": "...", "quote": "...", "signature": "..."}' \
  localhost:9443 device.DeviceService/AttestDevice
```

## Error Handling

gRPC status codes:

| Status | Description |
|--------|-------------|
| NOT_FOUND | Device or profile not found |
| INVALID_ARGUMENT | Invalid request parameters |
| ALREADY_EXISTS | Duplicate serial number |
| PERMISSION_DENIED | Authentication failed |
| INTERNAL | Server error |

See [api-reference.md](api-reference.md) for complete error code mapping.
