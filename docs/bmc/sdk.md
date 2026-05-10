# BMC SDK

Go client for the BMC service. The SDK lives at
`sdk/go/services/bmc` and speaks gRPC to platformd. CLI commands
under `pkg/cli/commands/bmc` use this SDK exclusively; consumers
should do the same rather than calling `pkg/bmc` directly.

## Import

```go
import (
    bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
    "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)
```

## Constructing a client

Two constructors are provided:

```go
// From a transport.Adapter (gRPC, QUIC over UDS, or TCP).
client, err := bmcsvc.NewClient(adapter)
if err != nil {
    return err
}

// From an existing platformv1.BMCServiceClient (e.g. when sharing
// a connection with other services).
client := bmcsvc.NewClientFromGRPC(grpcClient)
```

`NewClient` returns `bmc.ErrNilConnection` (re-exported via
`sdk/go/services/common`) when the adapter or its underlying
connection is nil.

## Power management

```go
resp, err := client.PowerOn(ctx, profileID)
resp, err  = client.PowerOff(ctx, profileID)
resp, err  = client.PowerReset(ctx, profileID)
resp, err  = client.PowerCycle(ctx, profileID)
state, err := client.PowerStatus(ctx, profileID)  // bmcsvc.PowerState
```

`PowerResponse` carries `PreviousState` and `CurrentState`.
Internally the four mutators dispatch through a
`map[string]powerAction` so adding a new action means adding an
entry to the map, not a new switch case.

## Boot device

```go
err := client.SetBootDevice(ctx, profileID, bmcsvc.BootDevicePXE, true)
dev, err := client.GetBootDevice(ctx, profileID)
```

`bmcsvc.BootDevice` constants: `BootDevicePXE`, `BootDeviceDisk`,
`BootDeviceCDROM`, `BootDeviceVirtualMedia`, `BootDeviceNone`.

## Virtual media

```go
err := client.MountISO(ctx, profileID, "https://iso.example/os.iso")
err  = client.UnmountISO(ctx, profileID)
info, err := client.VirtualMediaStatus(ctx, profileID)  // *VirtualMediaInfo
```

## Sensors and system info

```go
sensors, err := client.GetSensors(ctx, profileID)        // []SensorReading
sysInfo, err := client.GetSystemInfo(ctx, profileID)     // *SystemInfo
```

## Provisioning

```go
result, err := client.Provision(ctx, profileID, isoURL)         // *ProvisionResult
status, err := client.ProvisionStatus(ctx, profileID)           // *ProvisioningStatus
```

## Certificate management

```go
info, err := client.GetWebCertificate(ctx, profileID)           // *CertificateInfo
msg,  err := client.ReplaceWebCertificate(ctx, profileID, certPEM, keyPEM)
```

`CertificateInfo` includes subject, issuer, serial, validity
window, days remaining, SANs and SHA-256 fingerprint.

## User management

```go
users, err := client.ListUsers(ctx, profileID)                  // []User
slot,  err := client.CreateUser(ctx, profileID, &user, password)
err         = client.DeleteUser(ctx, profileID, slot)
err         = client.SetUserPassword(ctx, profileID, slot, password)
err         = client.SetUserPrivilege(ctx, profileID, slot, channel, bmcsvc.PrivilegeOperator)
```

`Privilege` constants: `PrivilegeAdministrator`,
`PrivilegeOperator`, `PrivilegeUser`, `PrivilegeCallback`,
`PrivilegeNoAccess`.

## Errors

All RPC failures are wrapped in a typed error with `Unwrap()`
support so callers can use `errors.Is` / `errors.As`:

| Type | Returned by |
|---|---|
| `*ErrPowerFailed` | Power* methods |
| `*ErrBootDeviceFailed` | SetBootDevice, GetBootDevice |
| `*ErrVirtualMediaFailed` | MountISO, UnmountISO, VirtualMediaStatus |
| `*ErrSensorsFailed` | GetSensors |
| `*ErrSystemInfoFailed` | GetSystemInfo |
| `*ErrProvisionFailed` | Provision, ProvisionStatus |
| `*ErrCertificateFailed` | GetWebCertificate, ReplaceWebCertificate |
| `*ErrUserFailed` | ListUsers, CreateUser, DeleteUser, SetUserPassword, SetUserPrivilege |

Each error carries `ProfileID` and `Cause`; user/cert/power/media
variants also carry `Action` so the caller knows which sub-op
failed.

## See also

- `docs/bmc/operations.md` -- operator runbook
- `docs/bmc/configuration.md` -- platformd YAML schema
- `pkg/bmc/CLAUDE.md` -- contributor map of the server-side
  package layout
