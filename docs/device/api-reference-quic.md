# Device QUIC API Reference

Endpoint: `localhost:9444` (UDP, TLS 1.3, ALPN `platform-quic`)

## Overview

The device surface is served by the platform QUIC protocol: one opcode
byte per operation, with the payload encoded by the platform codec
(MessagePack by default). The canonical wire contract for every device
request and response is the **`platform.v1` protobuf message itself** —
the SDK QUIC transport adapter encodes the generated pb request structs
directly and decodes daemon replies directly into the pb response
structs. The codec keys on exact Go field names, so the daemon decodes
each payload into the same pb types (`sdk/go/gen`), guaranteeing
SDK/daemon shape parity by construction and giving QUIC identical
semantics to gRPC (every daemon handler delegates to the shared
`DeviceGRPCService`).

Use the platform SDK (`sdk/go` with the QUIC transport) rather than
hand-rolling the framing; the tables below document the wire contract
the SDK implements.

## ALPN

The listener negotiates exactly one protocol, `platform-quic`, exported as
`quic.ALPNProtocol`. A client offering any other name fails the TLS handshake
with `no_application_protocol` **before a stream is opened**, so the symptom
is a connection error rather than a protocol error and reads like an
unreachable daemon. Reference the constant rather than repeating the string.

## Opcodes

| Opcode | Operation | Request message | Response message |
|--------|-----------|-----------------|------------------|
| `0x30` | Register device | `CreateDeviceRequest` | `CreateDeviceResponse` |
| `0x31` | Unregister device | `DeleteDeviceRequest` | `DeleteDeviceResponse` |
| `0x32` | Get device (union) | `GetDeviceRequest` or `FindDeviceBySerialRequest` | `GetDeviceResponse` / `FindDeviceBySerialResponse` |
| `0x33` | List / count devices | `ListDevicesRequest` | `ListDevicesResponse` |
| `0x34` | Update device | `UpdateDeviceRequest` | `UpdateDeviceResponse` |
| `0x35` | Get profile | `GetProfileRequest` | `GetProfileResponse` |
| `0x36` | Update (set) profile | `UpdateProfileRequest` | `UpdateProfileResponse` |
| `0x37` | List / count profiles | `ListProfilesRequest` | `ListProfilesResponse` |
| `0x38` | Create profile | `CreateProfileRequest` | `CreateProfileResponse` |
| `0x39` | Delete profile | `DeleteProfileRequest` | `DeleteProfileResponse` |
| `0x3A` | Attest device | `AttestDeviceRequest` | `AttestDeviceResponse` |
| `0x3B` | Activate device | `ActivateDeviceRequest` | `ActivateDeviceResponse` |
| `0x3D` | Get device state | `{Id}` | daemon-native `DeviceStateResponse` (domain-only state field, no pb counterpart) |

Profile assignment has no opcode of its own; it is multiplexed under
`OpProvisioningCategory` (`0xCF`) and documented under *Profile Assignment*
below.

Union opcodes:

- `0x32` serves both `GetDevice` (by `Id`) and `FindDeviceBySerial` (by
  `Serial`); both responses carry the device under the same `Device`
  field, so either reply type decodes the response.
- `0x33` / `0x37` serve both `List*` and `Count*`: the daemon always
  returns the full list response with `pagination.total_items`
  populated, and the SDK projects `Count*Response.count` from it.

Profile messages are the pb `DeviceProfile` (`docs/device/api-reference-grpc.md`),
so `0x35`–`0x38` carry `tls_server_name` (writable) and the read-only
`pcr_baseline` exactly as gRPC does: a `0x36` / `0x38` payload that names
`pcr_baseline` is ignored, and one that omits `tls_server_name` keeps the
stored value; an `UpdateProfileRequest` clears it only with
`clear_tls_server_name = true` (`docs/device/api.md` §3.2). The
daemon-native dark QUIC handler (`pkg/api/quic`) mirrors this on its own
`ProfileInfo` (`tls_server_name`, `pcr_baseline` with hex digests keyed by
register index and a Unix `recorded_at`); its `ProfileUpdateRequest` carries
`tls_server_name` as a pointer, so an omitted name keeps the stored one and
an explicit `""` clears it.

## Profile Assignment, Attestation Certificate and Templates (sub-opcodes under 0xCF)

The single-byte opcode space is fully allocated, so profile assignment
is multiplexed under the provisioning category opcode `0xCF` (same
precedent as the EAB sub-range): `payload[0]` is the sub-opcode and
`payload[1:]` is the codec-encoded pb request.

| Sub-opcode | Operation | Request message | Response message |
|------------|-----------|-----------------|------------------|
| `0x20` | Assign profile to device | `AssignProfileToDeviceRequest` | `AssignProfileToDeviceResponse` |
| `0x21` | Unassign profile from device | `UnassignProfileFromDeviceRequest` | `UnassignProfileFromDeviceResponse` |
| `0x22` | Record the device's attestation certificate without re-enrolling ([api.md §4.5](api.md#45-recording-the-attestation-certificate-without-re-enrolling-473)); a refusal is status `0x01` with the reason, and a `clear_on_refusal` clear that lost its compare-and-clear is `0x06` | `RecordAttestationCertificateRequest` | `RecordAttestationCertificateResponse` |
| `0x23` | Boot certificate: a diskless node's proof-of-possession request for its recorded IDevID chain ([api.md §4.6](api.md#46-diskless-boot-delivery-690)) | `BootCertificateRequest` | `BootCertificateResponse` |
| `0x24` | Boot delivery: attestation evidence in, network profile and CA bundle out ([api.md §4.6](api.md#46-diskless-boot-delivery-690)) | `BootDeliveryRequest` | `BootDeliveryResponse` |
| `0x25` | Disable the device: block its port, record it `suspended` ([api.md §4.7](api.md#47-operator-disable-and-enable-250)); a refusal is status `0x01` | `DisableDeviceRequest` | `DeviceLifecycleResponse` |
| `0x26` | Enable a `suspended` device into quarantine and request re-attestation; a refusal is status `0x01` | `EnableDeviceRequest` | `DeviceLifecycleResponse` |
| `0x27` | Create a device template ([api.md §4](api.md#4-device-templates)); not a vTPM template | `DeviceTemplateCreateRequest` | `DeviceTemplateCreateResponse` |
| `0x28` | Build and save a profile from a stored device template | `CreateProfileFromTemplateRequest` | `CreateProfileResponse` |
| `0x29` | Find the profile whose match rules fit a MAC, serial or model; no match is status `NotFound` | `FindMatchingProfileRequest` | `FindMatchingProfileResponse` |

Sub-opcodes `0x23` and `0x24` are exempt from token authentication: a
diskless node holds no token, and the service authenticates every request
itself. The proof and the evidence are bound to a nonce exported from the
QUIC connection's TLS 1.3 session, so input computed for another connection
is refused. A refusal of the request is status `0x09` (invalid argument) or
`0x07` (permission denied); a service that is not configured is `Unavailable`.

The template sub-opcodes answer `Unavailable` when the daemon runs without
the template or the profile service, as gRPC and REST do.

`AssignProfileToDeviceRequest` binds the profile to a device identity
(`ek_serial` and/or `mac_address`) and may prestage the device's
PEM-encoded EK certificate in `ek_cert` (source-agnostic: swtpm-backed
vTPM or physical hardware TPM). Unassign clears the EK serial, MAC
address, prestaged EK certificate, and assignment state.

The SDK adapter emits this framing automatically for
`DeviceService/AssignProfileToDevice`,
`DeviceService/UnassignProfileFromDevice`,
`DeviceService/RecordAttestationCertificate`,
`DeviceService/BootCertificate`,
`DeviceService/BootDelivery`,
`DeviceService/DisableDevice`,
`DeviceService/EnableDevice`,
`DeviceService/CreateTemplate`,
`DeviceService/CreateProfileFromTemplate` and
`DeviceService/FindMatchingProfile`.

## Authorization

Behind the platform-token middleware every device opcode and sub-opcode
requires a `device:*` scope, the same scope its gRPC method takes. The
catalogs are `opcodePermissions` (top-level opcodes) and
`categoryPermissions` (sub-opcodes under `0xCF`, keyed by `payload[0]`) in
`pkg/api/quic/opcode_permissions.go`; `AuthMiddleware.GuardRequest`
resolves them through `LookupOperationPermission` after the token
validates. A token without the scope gets `StatusPermissionDenied`; a
request without a token gets `StatusUnauthorized`; an operation absent from
the catalogs is refused, so a new sub-opcode without an entry fails closed.

| Scope | Opcodes |
|-------|---------|
| `device:read` | `0x32`, `0x33`, `0x35`, `0x37`, `0x3D`, `0x3E`; sub-opcode `0x29` |
| `device:write` | `0x30`, `0x34`, `0x36`, `0x38`, `0x3A`, `0x3B`, `0x3C`; sub-opcodes `0x20`–`0x22`, `0x25`–`0x28` |
| `device:delete` | `0x31`, `0x39` |

The boot sub-opcodes `0x23` and `0x24` are pre-auth (above), and the other
`0xCF` sub-ranges carry no scope. Config delivery (`0x01`–`0x07`)
is machine bootstrap: the device has no platform token, which is why its
gRPC `ConfigDeliveryService` is not in the scope catalog either. EAB
credential management (`0x10`–`0x1A`) is unscoped on gRPC and MCP as well;
see [`docs/eab/api.md`](../eab/api.md) §5.

Under mTLS-only QUIC, or with IAM validation skipped, the daemon installs
no token middleware (`selectQUICAuth`), so these scopes are not enforced.

`pkg/api/daemon/quic_device_authz_test.go` sends every device write
opcode and sub-opcode through the daemon's QUIC handler and asserts that a
`device:read` token and a missing token are refused while `device:write`
reaches the handler.

## Go Client Example

```go
import (
    platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
    _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
    "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

client, err := platform.NewClient(ctx,
    platform.WithProtocol(platform.ProtocolQUIC),
    platform.WithQUICAddr("localhost:9444"),
    platform.WithTLSConfig(tlsConfig), // TLS 1.3, trusted CA
)
if err != nil {
    return err
}
defer client.Close()

devices := device.NewClientFromGRPC(client.Device())

// Bind a profile to a hardware EK and prestage its certificate.
profile, err := devices.AssignProfile(ctx, profileID,
    ekSerial, macAddress, ekCertPEM)

// Clear the binding.
profile, err = devices.UnassignProfile(ctx, profileID)
```

## Wire Compatibility Guards

The round-trip compatibility of every device message (encode SDK-side
pb shape, decode daemon-side shape, compare with `proto.Equal`) is
pinned by `pkg/api/daemon/quic_device_wire_compat_test.go`. Changes to
the device wire contract must keep those tests green.

## Error Handling

QUIC status bytes map 1:1 onto the gRPC codes produced by the shared
device service:

| QUIC status | gRPC code |
|-------------|-----------|
| `StatusInvalidArgument` | `INVALID_ARGUMENT` |
| `StatusNotFound` | `NOT_FOUND` |
| `StatusAlreadyExists` | `ALREADY_EXISTS` |
| `StatusUnavailable` | `UNAVAILABLE` (service not configured) |
| `StatusInvalidRequest` | `FAILED_PRECONDITION` / payload decode failure |
| `StatusInternalError` | `INTERNAL` |

See [api-reference.md](api-reference.md) for the transport overview.
