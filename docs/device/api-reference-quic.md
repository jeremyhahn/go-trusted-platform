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
stored value. The daemon-native dark QUIC handler (`pkg/api/quic`) mirrors
this on its own `ProfileInfo` (`tls_server_name`, `pcr_baseline` with hex
digests keyed by register index and a Unix `recorded_at`).

## Profile Assignment and Attestation Certificate (sub-opcodes under 0xCF)

The single-byte opcode space is fully allocated, so profile assignment
is multiplexed under the provisioning category opcode `0xCF` (same
precedent as the EAB sub-range): `payload[0]` is the sub-opcode and
`payload[1:]` is the codec-encoded pb request.

| Sub-opcode | Operation | Request message | Response message |
|------------|-----------|-----------------|------------------|
| `0x20` | Assign profile to device | `AssignProfileToDeviceRequest` | `AssignProfileToDeviceResponse` |
| `0x21` | Unassign profile from device | `UnassignProfileFromDeviceRequest` | `UnassignProfileFromDeviceResponse` |
| `0x22` | Record the device's attestation certificate without re-enrolling ([api.md §4.5](api.md#45-recording-the-attestation-certificate-without-re-enrolling-473)); a refusal is status `0x01` with the reason | `RecordAttestationCertificateRequest` | `RecordAttestationCertificateResponse` |

`AssignProfileToDeviceRequest` binds the profile to a device identity
(`ek_serial` and/or `mac_address`) and may prestage the device's
PEM-encoded EK certificate in `ek_cert` (source-agnostic: swtpm-backed
vTPM or physical hardware TPM). Unassign clears the EK serial, MAC
address, prestaged EK certificate, and assignment state.

The SDK adapter emits this framing automatically for
`DeviceService/AssignProfileToDevice` and
`DeviceService/UnassignProfileFromDevice`.

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
