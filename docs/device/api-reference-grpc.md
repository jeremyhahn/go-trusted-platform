# Device gRPC API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [api.md](api.md) and `pkg/api/grpc/proto/device.proto`. There is one `DeviceService` (`CreateDevice`, not `RegisterDevice`; no separate `ProfileService`), served on port 10443, not 9443.

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
  rpc BootCertificate(BootCertificateRequest) returns (BootCertificateResponse);
  rpc BootDelivery(BootDeliveryRequest) returns (BootDeliveryResponse);
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
  string hostname = 15;       // hostname the device registered under; read-only, updates ignore it
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

// RecordAttestationCertificate records (or re-records) the device's
// attestation certificate without re-enrolling the device. Fail-closed:
// the candidate must parse, chain to the platform CA, carry
// tcg-cap-verifiedTPMRestricted and certify the enrolled attestation key,
// or nothing is written and the call returns FAILED_PRECONDITION naming
// every candidate refused -- unless clear_on_refusal is set, which clears
// the refused certificate instead. A clear that loses its compare-and-clear
// returns ABORTED. See docs/device/api.md §4.5.
rpc RecordAttestationCertificate(RecordAttestationCertificateRequest)
    returns (RecordAttestationCertificateResponse);

message RecordAttestationCertificateRequest {
  string device_id = 1;
  // reissue lets the CA issue a fresh certificate over the device's
  // enrolled attestation public key when no stored certificate passes.
  bool reissue = 2;
  // clear_on_refusal clears the certificate on the record when every
  // candidate is refused, so the next quote is an absence (denied) instead
  // of a cryptographic failure (quarantined). Audited as
  // device_attest_cert_cleared. Never clears a compliant certificate.
  bool clear_on_refusal = 3;
}

message RecordAttestationCertificateResponse {
  Status status = 1;
  uint64 device_id = 2;
  string serial = 3;
  string model = 4;
  bool changed = 5;                 // false: the record already held it
  string source = 6;                // "device" | "ca" | "reissued"
  string source_detail = 7;         // CA store name or issued CN
  bool reissued = 8;
  string subject = 9;
  string certificate_serial = 10;
  google.protobuf.Timestamp not_after = 11;
  string attest_cert = 12;          // the recorded certificate, PEM
  bool cleared = 13;                // the refused certificate was cleared;
                                    // subject..not_after describe it
  string refusal = 14;              // why it was refused, on a clear
}

// DisableDevice blocks the device's switch port and records it suspended
// with state_reason "operator: <reason>". EnableDevice moves a suspended
// device to quarantined, re-admits its port to the quarantine zone and
// requests re-attestation. Both enforce before they record, and refuse
// with FAILED_PRECONDITION when nothing can enforce the change. Scope
// device:write. See docs/device/api.md §4.7.
rpc DisableDevice(DisableDeviceRequest) returns (DeviceLifecycleResponse);
rpc EnableDevice(EnableDeviceRequest) returns (DeviceLifecycleResponse);

message DisableDeviceRequest {
  string device_id = 1;
  string reason = 2;                // at most 256 bytes
}

message EnableDeviceRequest {
  string device_id = 1;
}

message DeviceLifecycleResponse {
  Status status = 1;
  uint64 device_id = 2;
  string state = 3;                 // "suspended" | "quarantined"
  string previous_state = 4;
  string state_reason = 5;
  bool reattestation_requested = 6; // enable queued an immediate re-attestation
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
>
> Since #448 it also carries `tls_server_name` (writable: the certificate
> name the attestation collector verifies a node of this profile against;
> empty means the device FQDN; an `UpdateProfile` that omits it keeps the
> stored value, and `UpdateProfileRequest.clear_tls_server_name = true`
> clears it — proto3 cannot tell an unset string from an empty one, so the
> flag is the only clear; with a non-empty name it is `INVALID_ARGUMENT`,
> `docs/device/api.md` §3.2) and `pcr_baseline` (`PCRBaseline` message:
> `map<uint32, bytes> values`, `string source`, `Timestamp recorded_at`,
> `uint64 recorded_from_device_id`). `pcr_baseline` is **read-only**:
> `GetProfile`/`ListProfiles` populate it, `CreateProfile`/`UpdateProfile`
> ignore it, and the stored baseline survives an update that omits or
> tries to replace it (`docs/device/api.md` §3.6).

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
  // device_id names an already-registered device to bind to. The server
  // derives ek_serial from the device's stored EK certificate and
  // prestages it; explicit ek_serial / mac_address / ek_cert win. A
  // device with no EK certificate and no explicit identity is
  // FAILED_PRECONDITION; no identity at all is INVALID_ARGUMENT (#463).
  uint64 device_id = 5;
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

## Diskless Boot

`BootCertificate` and `BootDelivery` are a diskless node's two per-boot
requests ([api.md §4.6](api.md#46-diskless-boot-delivery-690)). They are exempt
from token authentication (a node holds no token); the service authenticates
every request itself and binds the proof and the evidence to a nonce exported
from the connection's TLS 1.3 session.

| RPC | Request | Response |
|-----|---------|----------|
| `BootCertificate` | `identity`, `signature` (proof over the identity and the channel nonce) | `identity`, `idevid_chain` |
| `BootDelivery` | `evidence` (the node's identity is the client certificate) | `serial`, `idevid_chain`, `attest_cert`, `ca_bundle`, `profile`, `pcr_baseline_source`, `pcr_baseline_captured` |

A malformed or unverifiable request is `InvalidArgument`, a request that
fails the identity or channel check is `PermissionDenied`, and an
unconfigured service is `Unavailable`. With mutual TLS enabled the listener
verifies a client certificate only if given; `BootCertificate` may arrive
without one, `BootDelivery` and every other method need a verified one
(`Unauthenticated`). A listener without mutual TLS cannot serve `BootDelivery`.

## Device Templates

`platform.v1.DeviceService` creates device templates and builds profiles
from them ([api.md §4](api.md#4-device-templates)). These are device
templates, not vTPM templates (`VTPMService.CreateTemplate`); the messages
carry the `DeviceTemplate…` prefix so the two cannot collide.

```protobuf
rpc CreateTemplate(DeviceTemplateCreateRequest) returns (DeviceTemplateCreateResponse);
rpc CreateProfileFromTemplate(CreateProfileFromTemplateRequest) returns (CreateProfileResponse);

message DeviceTemplate {
  uint64 id = 1;
  string tenant_id = 2;
  string name = 3;
  string description = 4;
  DeviceRole role = 5;
  bytes config = 6;
  ProfileMatchRules match_rules = 7;
  google.protobuf.Timestamp created_at = 8;
  google.protobuf.Timestamp updated_at = 9;
  BMCConfig bmc = 10;
}

message DeviceTemplateCreateRequest {
  DeviceTemplate template = 1;
}

message DeviceTemplateCreateResponse {
  Status status = 1;
  DeviceTemplate template = 2;
}

message CreateProfileFromTemplateRequest {
  uint64 template_id = 1;
  DeviceProfile overrides = 2;
}
```

`CreateTemplate` assigns an id when the template carries none and refuses
an empty `name` (`InvalidArgument`). `CreateProfileFromTemplate` requires a
non-zero `template_id`; an unknown one is `NotFound`. The profile takes the
template's tenant, role, config and match rules, the non-empty `overrides`
fields replace them (`DEVICE_ROLE_UNSPECIFIED` keeps the template's role),
and the saved profile is returned. A daemon started without the template or
the profile service answers `Unavailable`. Both RPCs require `device:write`.

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
