# BMC — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/bmc/`, `pkg/quirks/`, `pkg/bmc/smc/`, `pkg/bmc/credentials/`, `pkg/app/bmc_*.go` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every identifier below was grepped in the tree on 2026-08-18. Design and
> boundaries: [architecture.md](architecture.md). Transport matrix:
> [api.md](api.md).

---

## 1. Package layout

`pkg/bmc/` — the feature:

| File | Holds |
|---|---|
| `types.go` | `Client`, `ClientFactory`, `ProfileStore`, `PowerState`, `BootDevice`, `Protocol`, `SensorReading`, `SystemInfo`, `VirtualMediaInfo` |
| `config.go` | `Config`, `DefaultConfig`, `DefaultRedfishConfig`, `Validate`, `Endpoint` |
| `factory.go` | `DefaultClientFactory`, `RedfishClientFactory`, the `protocolFactories` dispatch map |
| `service.go` | `Service`, `ServiceParams`, `NewService`, the profile-keyed client cache |
| `service_cert.go`, `service_user.go` | `Service` methods that build per-call cert/user managers |
| `ipmi.go`, `rmcp.go`, `ipmi_sdr.go`, `ipmi_fru.go` | IPMI 2.0 RMCP+ transport, SDR parsing, FRU parsing, `IPMIClientFactory` |
| `rmcp_sol.go`, `rmcp_sol_errors.go` | `SOLSession` and its errors |
| `redfish.go`, `redfish_transport.go`, `redfish_types.go`, `redfish_errors.go` | Redfish client, `peerCertificate`, `ErrRedfishRequest` |
| `vendor.go` | `Vendor`, `VendorProbe`, `RecommendCertBackend`, `ManufacturerString` |
| `cert.go`, `auto_cert.go`, `redfish_cert.go`, `cert_restore.go`, `cert_info.go` | `CertBackend`, `CertificateManager`, `ManagedCertificateManager`, `AutoCertManager`, the backend factory registry, `CertificateInfo` |
| `user.go`, `ipmi_user.go`, `redfish_user.go` | `Privilege`, `User`, `UserManager`, `ManagedUserManager` |
| `credentials.go` | `Credentials`, `CredentialStore`, `MemoryStore`, `CredentialPath` |
| `rotation.go` | `RotationEngine`, `RotationOptions`, `GenerateRandomPassword` |
| `enrollment.go` | `EnrollmentConfig`, `DefaultEnrollmentConfig` |
| `tls.go` | `TLSProvider`, `BuildTLSConfig`, `HTTPSEndpoint`, `ErrTLSProvider` |
| `virtualmedia.go`, `vmedia_*.go` | `MediaSpec`, `MediaProtocol`, the three-backend dispatch chain |
| `vboot_smc_oem_ipmi.go` | Supermicro OEM IPMI boot-override backend (registered in the `bootOverrideBackends` map in `redfish.go`) |
| `discovery.go`, `mac_smc_oem_ipmi.go` | `DiscoverMAC`, `DiscoverMACs`, `DetectProtocol` |
| `errors.go` | The typed error set (§6) |
| `mock.go` | `MockClient`, for consumers' unit tests |

Subpackages: `pkg/bmc/smc/` (Supermicro ATEN CGI cert upload and restore),
`pkg/bmc/credentials/` (`QuicBaaSStore`), `pkg/bmc/attestation/` (**scaffolding
only** — see §12).

`pkg/quirks/` — `quirks.go` (`Quirk`, `MediaType`, `Resolve`, `Default`),
`registry.go` (`buildRegistry`, the only table permitted to hold vendor and
model strings), `errors.go` (`ErrUnknownManufacturer`).

Ceremonies live in `pkg/app/`: `bmc_enroll.go`, `bmc_restore.go`,
`bmc_cert.go`, `bmc_cert_init.go`.

## 2. Exported surface

### Core

```go
type Client interface {
    PowerOn(ctx) error;  PowerOff(ctx) error;  PowerReset(ctx) error
    PowerCycle(ctx) error;  PowerStatus(ctx) (PowerState, error)
    SetBootDevice(ctx, device BootDevice, persistent bool) error
    GetBootDevice(ctx) (BootDevice, error)
    MountISO(ctx, isoURL string) error;  UnmountISO(ctx) error
    MountVirtualMedia(ctx, spec *MediaSpec) error;  UnmountVirtualMedia(ctx) error
    VirtualMediaStatus(ctx) (*VirtualMediaInfo, error)
    GetSensors(ctx) ([]SensorReading, error)
    GetSystemInfo(ctx) (*SystemInfo, error)
    HardwareIdentity(ctx) (quirks.Identity, error)
    Console(ctx) (*SOLSession, error)
    ClearUEFIBootEntries(ctx) error
    GetEventLog(ctx) (*EventLog, error)
    Close() error
}

type ClientFactory interface{ NewClient(config *Config) (Client, error) }
type ProfileStore  interface{ Get(ctx, id uint64) (*Config, error) }
```

`HardwareIdentity` returns the `quirks.Identity` the client resolves its own
registry entry from, so a caller lands on that client's entry and no other.
It is **not** `SystemInfo`: over IPMI, `SystemInfo.Manufacturer` is the raw
IANA enterprise number (or the FRU Product Manufacturer) and
`SystemInfo.Product` is the FRU Product Name, while the quirk identity is the
vendor name derived from that number plus the FRU Board Product and Product
Part Number. It is in-process only — there is no wire surface for it, and
`SystemInfo` and the six transports are unchanged.

A non-nil error from it means the answer was not definitive and was not
cached, **not** that nothing was learned: the returned `Identity` may be
partially populated (the IPMI path names the vendor from Get Device ID and
can then fail reading the FRU), and the client resolves its own quirk from
that same partial value. Callers retry first, then prefer a partial identity
to none. The bootstrap orchestrator
is its consumer; see
[`docs/architecture/vendor-quirks.md`](../architecture/vendor-quirks.md).

Constructors:

| Constructor | Returns | Notes |
|---|---|---|
| `NewDefaultClientFactory(*slog.Logger) *DefaultClientFactory` | dispatches on `Config.Protocol` via `protocolFactories` | used by the **standalone CLI** path |
| `NewIPMIClientFactory(*slog.Logger) *IPMIClientFactory` | always an IPMI client | **used by the daemon** — see §4 |
| `NewRedfishClientFactory(*slog.Logger) *RedfishClientFactory` | always a Redfish client | |
| `NewService(ServiceParams) (*Service, error)` | profile-facing service | `Factory` required; `Profiles` optional |
| `NewVendorProbe(*Config, *slog.Logger) (*VendorProbe, error)` | one unauthenticated `GET /redfish/v1/` | no session, no caching |
| `NewAutoCertManager(*Config, CertBackend, *slog.Logger) (*AutoCertManager, error)` | vendor-dispatching cert manager | probing deferred to first use |
| `NewRedfishCertManager(*Config, *slog.Logger) (ManagedCertificateManager, error)` | Redfish `CertificateService` backend | registered in `pkg/bmc`'s own `init()` |
| `smc.NewCertManager(*bmc.Config, *slog.Logger) (*smc.CertManager, error)` | ATEN CGI backend | registers itself on side-effect import |
| `NewUserManager(ctx, *Config, *slog.Logger) (ManagedUserManager, error)` | opens a fresh RMCP+ session | caller **must** `Close` |
| `NewRedfishUserManager(*Config, *slog.Logger) (ManagedUserManager, error)` | Redfish `AccountService` backend | |
| `NewIPMIUserManager(sender, channel uint8, *slog.Logger) UserManager` | raw IPMI backend over an existing session | |
| `NewRotationEngine(RotationOptions) (*RotationEngine, error)` | store-ahead rotation engine | |
| `NewMemoryStore() *MemoryStore` | in-memory `CredentialStore` | tests and single-process use |
| `credentials.NewQuicBaaSStore(SecretsService) (*QuicBaaSStore, error)` | persistent `CredentialStore` | encryption at rest is the service's |
| `NewCredentials(username string, password []byte) *Credentials` | password moved into locked memory | |
| `NewCredentialsFromStrings(username, password string) *Credentials` | same, from strings | |
| `NewCertificateInfo(*x509.Certificate, now time.Time) *CertificateInfo` | metadata view | |

Package functions:

`BuildTLSConfig(ctx, *Config) (*tls.Config, error)`,
`HTTPSEndpoint(*Config) string`,
`RecommendCertBackend(Vendor) CertBackend`,
`RegisterCertFactory(CertBackend, CertManagerFactory)`,
`DiscoverMAC(ctx, *Config, *slog.Logger) (string, error)`,
`DiscoverMACs(ctx, *Config, *slog.Logger) ([]string, error)`,
`DetectProtocol(ctx, address string, timeout time.Duration) Protocol`,
`GenerateRandomPassword(n int) (*memguard.Secret, error)`,
`CredentialPath(name string) string`,
`NameFromCredentialPath(path string) string`,
`MarshalCredentials(*Credentials) ([]byte, error)`,
`UnmarshalCredentials([]byte) (*Credentials, error)`,
`DefaultConfig() *Config`, `DefaultRedfishConfig() *Config`,
`DefaultEnrollmentConfig() *EnrollmentConfig`.

`pkg/quirks`: `ResolveIdentity(Identity) Quirk`,
`Resolve(manufacturer, model string) Quirk`, `Default() Quirk`.

### Enumerations — the exact string values

| Type | Values |
|---|---|
| `PowerState` | `"on"`, `"off"`, `"unknown"` |
| `BootDevice` | `"pxe"`, `"disk"`, `"cdrom"`, `"virtual_media"`, `"none"` |
| `Protocol` | `"ipmi"`, `"redfish"` |
| `CertBackend` | `"auto"`, `"redfish"`, `"smc-cgi"` |
| `Vendor` | `"unknown"`, `"supermicro"`, `"dell"`, `"hpe"`, `"lenovo"`, `"generic"` |
| `MediaProtocol` | `"http"`, `"https"`, `"cifs"`, `"nfs"` (URL scheme `smb` also maps to `cifs`) |
| `Privilege` (a `uint8`, **not** a string) | `PrivilegeCallback` `0x01`, `PrivilegeUser` `0x02`, `PrivilegeOperator` `0x03`, `PrivilegeAdministrator` `0x04`, `PrivilegeNoAccess` `0x0F` |

Every one of these has an `IsValid()` method backed by a package-level map, not
a `switch`.

**The SDK's enums are different values for the same concepts.**
`sdk/go/services/bmc/types.go` declares `PowerState` as `"ON"`/`"OFF"`/
`"UNKNOWN"`/`"UNSPECIFIED"`, `BootDevice` as `"PXE"`/`"DISK"`/`"CDROM"`/
`"VIRTUAL_MEDIA"`/`"NONE"`/`"UNSPECIFIED"`, and `Privilege` as a **string**
(`"ADMINISTRATOR"`, `"OPERATOR"`, `"USER"`, `"CALLBACK"`, `"NO_ACCESS"`,
`"UNSPECIFIED"`). They are proto-derived and converted at the boundary
(`PowerStateFromProto`, `BootDeviceToProto`, `PrivilegeToProto`). Do not compare
a `bmc.PowerState` with a `bmcsvc.PowerState`.

## 3. Configuration — two different types, one word

This is the single largest source of confusion in this feature.

### 3.1 `bmc.Config` — the runtime type (platformd YAML, top-level `bmc:`)

Bound to `App.BMCConfig` (`pkg/app/app.go`, tag `yaml:"bmc,omitempty" mapstructure:"bmc"`).

| Key | Go field | Type | Default | Meaning |
|---|---|---|---|---|
| `address` | `Address` | string | — | **Required.** IP or hostname |
| `port` | `Port` | int | `623` (`DefaultConfig`) / `443` (`DefaultRedfishConfig`) | 1–65535 |
| `username` | `Username` | string | — | |
| `password` | `Password` | string, `secret:"true"` | — | Use a `kms://` reference |
| `protocol` | `Protocol` | `Protocol` | `ipmi` | `ipmi` or `redfish` |
| `encryption-key` | `EncryptionKey` | string, `secret:"true"` | — | Hex KG key for IPMI 2.0 RAKP |
| `sol-payload-instance` | `SOLPayloadInstance` | byte | `0` | `0` = consult the quirk registry, fall back to `0x01`. Permitted `0x01`–`0x0F` |
| `certificate` | `Certificate` | `*common.Identity` | nil | nil disables BMC TLS management |
| `key` | `Key` | `*common.KeyConfig` | nil | |
| `backend` | `Backend` | `CertBackend` | `""` → treated as `auto` | |
| `allow_cgi_fallback` | `AllowCGIFallback` | bool | `false` | Permits auto-mode to select `smc-cgi` |
| `enrollment` | `Enrollment` | `*EnrollmentConfig` | nil → `DefaultEnrollmentConfig()` | |
| — | `TLS` | `TLSProvider` | nil | `yaml:"-" json:"-"` — injected by the daemon, never serialized |

`Config.Validate()` enforces, in order: non-empty `address`; `port` in
1–65535; `Protocol.IsValid()`; then `validateCertBlock`:

- `certificate` and `key` must both be set or both be absent, else
  `ErrInvalidConfig{Field: "certificate/key"}`.
- With neither set, `backend` must be empty — a configured backend with no cert
  block is a lie about what the node is doing.
- `Certificate.ACME.Challenge` must be present **and equal to `"dns-01"`**.
  Anything else is `ErrInvalidConfig{Field: "certificate.acme.challenge"}`,
  raised at config load, not at first renewal.

Example (placeholder values only):

```yaml
bmc:
  address: bmc.example.com
  port: 443
  username: admin
  password: "kms://bmc/password?ensure=true&len=16&enc=base64"
  protocol: redfish
  backend: auto
  allow_cgi_fallback: false
  certificate:                   # common.Identity — acme / sans / subject / valid
    acme:
      challenge: dns-01          # ENFORCED: any other value fails config load
    valid: 90
  key:                           # common.KeyConfig
    algorithm: ECDSA
  enrollment:
    auto: false
    replace-certificate: true
    backup: true
    rotate-password: false
    dns-register: true
    dane-publish: true
```

### 3.2 `entities.BMCConfig` — the persisted device-profile type

`pkg/device/entities/bmc.go`. **Five fields only:** `address`, `port`,
`username`, `password` (`secret:"true"`), `protocol`. Constants
`DefaultBMCIPMIPort = 623`, `DefaultBMCRedfishPort = 443`;
`EffectivePort()` falls back to the protocol default when `port` is `0`.
Validation errors are their own types: `ErrBMCAddressRequired`,
`ErrBMCInvalidPort`, `ErrBMCUnknownProtocol`, `ErrBMCUsernameRequired`,
`ErrBMCPasswordRequired`.

`profileBMCToConfig` (`pkg/api/daemon/bmc_profile_store.go`) maps those five
fields plus the injected `TLSProvider` into a `*bmc.Config`. **`Certificate`,
`Key`, `Backend`, `AllowCGIFallback`, `Enrollment`, `EncryptionKey` and
`SOLPayloadInstance` are left at their zero values on this path.** A device
profile therefore cannot carry an enrollment policy or a cert backend today,
whatever `configuration.md` shows.

### 3.3 `EnrollmentConfig`

| YAML | Field | Default | Effect |
|---|---|---|---|
| `auto` | `Auto` | `false` | Enroll on first BMC contact without an operator call |
| `replace-certificate` | `ReplaceCertificate` | `true` | Deploy a platform-issued certificate |
| `backup` | `Backup` | `true` | Capture the factory certificate before replacing it |
| `rotate-password` | `RotatePassword` | `false` | Disruptive; opt in explicitly |
| `dns-register` | `DNSRegister` | `true` | A record `<hostname>-bmc.<zone>` |
| `dane-publish` | `DANEPublish` | `true` | TLSA records; needs the previous two |

`Config.effectiveEnrollment()` returns `Enrollment` when non-nil, else
`DefaultEnrollmentConfig()`. Per-call `*bool` overrides
(`app.BMCEnrollOptions`) win over the profile value; a nil pointer means "keep
the profile default", which is what makes the CLI flags tri-state.

### 3.4 Environment variables

| Variable | Consumed by | Meaning |
|---|---|---|
| `PLATFORM_CA_CERT` | `pkg/cli/commands/bmc/helpers.go` | CA bundle verifying the platformd TLS certificate on the raw-HTTP CLI path |
| `PLATFORM_CLIENT_CERT` | same | Client certificate for mutual TLS to platformd |
| `PLATFORM_CLIENT_KEY` | same | Client key |
| `PLATFORMCTL_BACKUPS_DIR` | `pkg/cli/commands/bmc/enroll.go` | Default for `--backups-dir` (flag wins) |

Precedence on the CLI: **flag > environment > built-in default.**

## 4. Invariants

1. **`bmc.Service` caches one client per profile ID, forever, in a `sync.Map`.**
   Concurrent misses both construct; `LoadOrStore` picks a winner and the loser
   calls `Close()` on its own client. There is **no invalidation** — a profile
   whose BMC address or credentials change is not re-read until `Service.Close()`
   or daemon restart.
2. **`Profiles` is optional; `Factory` is not.** `NewService` returns
   `ErrInvalidConfig{Reason: "client factory is required"}` for a nil factory.
   With a nil `Profiles`, every profile-based method returns
   `ErrProfileNotFound{ProfileID: id}` rather than dereferencing nil.
3. **Any `ProfileStore.Get` failure becomes `ErrProfileNotFound`.** The
   underlying cause is discarded. A malformed profile and a missing profile are
   indistinguishable to the caller.
4. **`Config.Validate()` runs inside every `NewClient`.** Invalid config never
   reaches a transport.
5. **The daemon's factory ignores `Config.Protocol`.**
   `pkg/api/daemon/daemon.go` constructs the service with
   `bmc.NewIPMIClientFactory`, and `IPMIClientFactory.NewClient` returns an IPMI
   client unconditionally. A device profile with `protocol: redfish` still gets
   an IPMI client on the daemon path. This is verified behavior, not a
   simplification.
6. **The IPMI client borrows a Redfish client lazily.** `ensureRedfishClient`
   builds one on port `443` with the same address, credentials and `TLSProvider`,
   and `MountISO`, `UnmountISO`, `MountVirtualMedia`, `UnmountVirtualMedia`,
   `VirtualMediaStatus` and `ClearUEFIBootEntries` delegate to it. Consequence
   of (5): virtual media works from a `protocol: ipmi` profile, and requires
   HTTPS reachability on 443.
7. **Cert and user managers are per call, never cached.** `certManagerFor` and
   `userManagerFor` build a fresh manager each time and the `Service` methods
   `defer mgr.Close()`. Cert managers hold short-lived TLS state; user managers
   hold a live RMCP+ session.
8. **`AutoCertManager` probes once, then caches.** `resolveBackends` is guarded
   by a mutex and memoizes `primary`, `fallback`, `resolved` and `vendor`.
   `Backend()` returns the requested backend until the probe has run.
9. **`GetWebCertificate` never depends on the backend.** It reads the live TLS
   handshake peer certificate, so it works on any BMC — including one whose
   firmware supports no certificate management at all.
10. **Fallback only triggers on an "unsupported" signal.**
    `isUnsupportedBackendError` matches `ErrRedfishRequest` status `501`, `405`
    or `404`, or the strings `not implemented`, `unimplemented`, `not supported`,
    `methodnotallowed`, `method not allowed`, `501`. Anything else propagates
    immediately. Fallback construction is best-effort: a candidate whose factory
    errors is skipped, not fatal.
11. **The virtual-media backend chain is ordered and fall-through is typed.**
    `virtualMediaBackends()` returns standard Redfish → Supermicro OEM Redfish →
    Supermicro CGI. Only `ErrVirtualMediaLicenseRequired` and
    `ErrVirtualMediaUnsupported` advance the chain; anything else returns
    `ErrVirtualMediaBackendFailed`. Exhausting the chain gives
    `ErrVirtualMediaAllBackendsFailed` carrying every `VirtualMediaAttempt`.
12. **`MediaSpec.Validate()` infers `Protocol` from the URL scheme** when empty,
    and rejects an explicit `Protocol` that contradicts the scheme.
13. **`quirks.Resolve` always returns a valid `Quirk`.** No nil check, no error.
14. **`pkg/quirks` must never import `pkg/bmc`.** Backend and strategy names are
    opaque strings on the quirks side.
15. **Enrollment always returns a complete step list.** Skipped steps are
    recorded with `OK: true` and a skip reason; a failure returns the partial
    result so the operator sees exactly how far the ceremony got.
16. **DANE publication failure is non-fatal in both ceremonies**, and so is
    `pin-delete` in restore. The certificate is already deployed by then; the
    TOFU resolver re-pins on the next connection.
17. **Restore never re-uploads the backed-up factory certificate.** The platform
    holds no private key for it. The BMC regenerates its own.
18. **`RotationEngine` is store-ahead.** The store is written *before* the BMC,
    so the store is always the best available guess at real BMC state.
19. **No RMCP+ datagram a BMC sends reaches the log.** `sendRecv` logs the
    received length only, at every level: the exchange it carries includes
    RAKP message 2, whose HMAC is keyed by the BMC user's password and
    recovers it offline (`TestSendRecv_ResponseBytesNeverReachTheLog`).

## 5. Fail-closed paths

| Path | Behavior |
|---|---|
| No `TLSProvider` on a Redfish/HTTPS connection | `BuildTLSConfig` returns system roots at TLS 1.2+ — which **fails** against a self-signed BMC. The doc comment names this "the correct secure default" |
| `certificate` set, `challenge != dns-01` | Config load fails. The node does not start with a BMC cert policy that cannot succeed |
| `certificate` set without `key` (or the reverse) | Config load fails |
| `backend` set with no `certificate`/`key` | Config load fails |
| Auto mode resolves to `smc-cgi` with `allow_cgi_fallback: false` | `ErrAutoCertCGIGated`. No upload is attempted |
| Standalone Redfish with neither `--bmc-pin` nor `--bmc-ca-file`, non-interactive | `ErrBMCNoPinOrCAFile`. Interactive sessions get capture-then-confirm instead |
| `--bmc-pass-file` mode looser than `0600` | `ErrBMCInsecurePasswordFile`. The file is not read |
| `--bmc-host` given together with `--server-url`/`--profile-id` | `ErrBMCFlagConflict`. Neither mode is guessed |
| Neither `--bmc-host` nor daemon flags | `ErrBMCNoMode` |
| `bmc cert restore` without `--factory` | Rejected. The flag exists solely to make accidental invocation impossible |
| `Provision` / `ProvisionStatus` with no baremetal orchestrator wired | gRPC `Unavailable` with reason `SERVICE_NOT_CONFIGURED`, REST `503` — the daemon passes `nil` for the baremetal service today |
| Rotation apply or verify fails | Rollback is attempted; the outcome is encoded in the error type (§6) |
| IPMI password (or KG key) shorter than 14 bytes, **under FIPS activation** | `ErrFIPSKeyTooShort` at session open. See below |

**The FIPS credential floor (#209).** IPMI 2.0 derives its RMCP+ session keys
directly from the BMC password, and FIPS 140-3 requires at least 112 bits of
keying material for an HMAC key. `crypto/hmac.New` enforces that by **panicking**
rather than returning an error, so before #209 a FIPS-activated daemon opening a
session against a controller with a short password took the whole process down
mid-handshake. `rmcpValidateSessionSecret` now refuses at session open, before a
socket is dialled, with a typed error.

Two properties of that check are deliberate and easy to get wrong:

- **It is a runtime check, not a build-tag one**, unlike this package's
  algorithm tables (`//go:build fips`, so MD5 and SHA-1 are absent from the
  binary): `crypto/hmac` enforces on `GODEBUG`, which an untagged binary can
  also run under. Why the two switches differ is in
  [FIPS mode](../fips/architecture.md).
- **Non-FIPS behaviour is unchanged.** A short password is accepted as it always
  was. A FIPS-capable build is not a FIPS-activated one.

The operational consequence, stated rather than softened: under FIPS activation
a controller whose password is shorter than 14 bytes is **unreachable over
RMCP+**. Redfish over TLS is unaffected and remains available for it. This is
doc 04 ruling 7 applied to an interop surface — restrict to approved options, or
disable with a clear typed error — and the error says the mode is the constraint
so it does not read as a broken controller or a wrong password.

The one deliberate exception is `captureAndConfirmSPKI`: it dials with
`InsecureSkipVerify` to capture the peer certificate, exchanges **no application
data**, closes the connection, prints subject/issuer/expiry/SPKI pin to stderr,
requires a literal `yes`/`y` on stdin, and then reconnects pinned. It is the
only `InsecureSkipVerify` call site on this path and is annotated as such.

## 6. Error semantics

All `pkg/bmc` errors are **value types implementing `error`**, matched with
`errors.As` on the value (not a pointer). Those carrying a `Cause` implement
`Unwrap`.

### Configuration and lifecycle

| Error | Returned when |
|---|---|
| `ErrNilConfig` | A nil `*Config` reached a constructor |
| `ErrInvalidConfig{Field, Reason}` | Validation failure; `Field` names the YAML key |
| `ErrConnectionFailed{Address, Cause}` | Dial, HTTP or decode failure reaching the BMC |
| `ErrRedfishServiceRootStatus{Status}` | Non-2xx from `/redfish/v1/` during vendor probing |
| `ErrClientClosed` | An operation on a closed client |
| `ErrProfileNotFound{ProfileID}` | Profile absent, has no BMC block, or no `ProfileStore` is wired |
| `ErrTLSProvider{Endpoint, Err}` | The injected `TLSProvider` failed |
| `ErrUnsupportedOperation{Operation}` | The active protocol cannot do it |

### Control operations

`ErrPowerOperation{Operation, Cause}`, `ErrBootDevice{Device, Cause}`,
`ErrInvalidBootDevice{Device}`, `ErrInvalidPowerState{State}`,
`ErrVirtualMedia{Operation, Cause}`, `ErrInventory{Cause}`,
`ErrSensorRead{Cause}`.

`ErrEventLogRead{Operation, Cause}` is what `GetEventLog` returns when the SEL
cannot be read (IPMI Get SEL Info / Get SEL Entry, Redfish LogServices). It
returns `ErrUnsupportedOperation` — not a stub — when the board genuinely has
no such surface: no Redfish `LogServices`, or no SEL among them.

Two carry design intent worth stating:

- **`ErrBootOverrideUnsupported{Backend, Vendor, Device, Reason}`** is a *soft*
  failure. The Redfish dispatch layer treats it as "try the standard DMTF PATCH
  instead", so a vendor backend that is a documented stub does not block the
  orchestrator's boot flow.
- **`ErrUEFIBootClearUnsupported{Manufacturer, Model, Cause}`** is what
  `ClearUEFIBootEntries` returns when the BMC advertises no `BiosReset` action
  and no vendor fallback is wired. The caller routes to a vendor CGI path or
  surfaces the limitation; it is not swallowed.

### IPMI transport

`ErrRAKPAuthFailed`, `ErrSessionClosed`, `ErrPacketTooShort`,
`ErrIntegrityCheckFailed`, `ErrCompletionCode`,
`ErrResponseMismatch{Command, NetFn, GotCommand, GotNetFn}` (the datagram
answers another exchange), `ErrUDPSend`, `ErrUDPRecv`,
`ErrDecryptFailed`, `ErrEncryptFailed`, `ErrIPMIShortResponse{Command, Got, Want}`,
`ErrSDRParse{Reason}`, `ErrSDRResponseTooShort{Operation, Length, Expected}`,
`ErrGetSDRRepoInfo`, `ErrReserveSDR`, `ErrGetFRUInfo`, `ErrReadFRU{Offset, Cause}`,
`ErrFRURead{Reason, Cause}`, `ErrBMCResetTimeout{Cause}`.

SOL: `ErrSOLActivateFailed`, `ErrSOLDeactivateFailed`, `ErrSOLSessionClosed`,
`ErrSOLTimeout`.

Discovery: `ErrMACNotFound`, `ErrProtocolDetectionFailed`,
`ErrMACDiscoveryUnsupported`, `ErrOEMMACParse`, `ErrOEMMACCommand`.

### Certificate management

`ErrAutoCertResolve{Cause}`, `ErrAutoCertCGIGated{Vendor}`,
`ErrAutoCertBackendUnavailable{Backend}` (almost always a missing side-effect
import of a backend subpackage),
`ErrAutoCertAllBackendsFailed{Primary, Fallback, PrimaryE, FallbackE}`.

`pkg/bmc/smc`: `ErrLoginFailed`, `ErrNoSessionCookie`, `ErrUploadFailed`,
`ErrValidateFailed`, `ErrResetFailed`, `ErrInvalidInput`, `ErrTransport`,
`ErrDefaultSSLFailed`, `ErrRestoreUnchanged`.

### Credentials and rotation — the state each one leaves behind

`ErrCredentialsNotFound{Name}`, `ErrInvalidCredentials{Reason}`,
`ErrInvalidRotationConfig{Field, Reason}`.

| Error | BMC has | Store has | Operator action |
|---|---|---|---|
| `ErrRotationGenerate` | old | old | Retry |
| `ErrRotationStoreAhead` | old (untouched) | old | Fix the store, retry |
| `ErrRotationConnect{Phase}` | depends on phase | new | Inspect, then re-run |
| `ErrRotationApply` | old | new | Rollback path runs; see below |
| `ErrRotationVerify` | new (apparently) | new | Rollback path runs |
| `ErrRotationReverted{Cause}` | old | old | **Clean failure.** Retry safely |
| `ErrRotationStoreRollback{Cause}` | old | new | Re-`Put` the old credentials |
| `ErrRotationCatastrophic{Name, ApplyErr, RollbackE}` | unknown | new | **Manual intervention.** Verify the BMC by hand |

`ErrRotationReverted` is the *good* failure: both sides are back where they
started. `ErrRotationCatastrophic` is the only one that requires a human.

### SDK boundary

`sdk/go/services/bmc/errors.go` wraps every RPC failure in a **pointer** type
with `Unwrap`: `*ErrPowerFailed`, `*ErrBootDeviceFailed`,
`*ErrVirtualMediaFailed`, `*ErrSensorsFailed`, `*ErrSystemInfoFailed`,
`*ErrProvisionFailed`, `*ErrCertificateFailed`, `*ErrUserFailed`,
`*ErrEnrollFailed`, `*ErrRestoreFailed`. Each carries `ProfileID` and `Cause`;
the power, media, cert and user variants also carry `Action`.
`NewClient` returns `common.ErrNilConnection` for a nil adapter or nil
underlying connection.

*(The legacy `sdk.md` lists eight error types and describes the nil-connection
error as `bmc.ErrNilConnection`. There are ten, and the symbol is
`common.ErrNilConnection`.)*

### Transport mapping

REST responses use the platform envelope
`{"code", "success", "error", "payload"}`. Status mapping follows the platform
table in [`docs/daemon/api.md`](../daemon/api.md) §4; the BMC-specific causes
are in [api.md](api.md) §7.

## 7. Persistence

| What | Where | Shape |
|---|---|---|
| BMC connection settings | Device profile entity | `entities.BMCConfig`, five fields |
| BMC account credentials | QuicBaaS secrets service | key `bmc/<name>` (`CredentialPath`); value is `credentialRecord` JSON (`{"username","password"}`); **versioned**, `Put` creates a new version, `Delete` is a soft delete preserving history, `History` returns newest-first |
| Enrollment outcome | `Device.BMCEnrollment` (`entities.BMCEnrollment`) | `Host`, `DNSName`, SPKI pin, `FactoryCertSHA256`, TLSA state |
| Managed cert targets | `CertTargetRegistry`, in memory | `CertTarget` named `bmc.<nodeID>` |
| Factory certificate backup | **client side only**, under `<backups-dir>/<hostname>/bmc/` | `factory-cert.pem`, `factory-cert.json`, `enrollment.json`; directory `0700`, files `0600` |

**BMC TLS private keys are never persisted.** They are generated fresh per
issuance and shipped to the BMC. BMC *account* passwords do persist, for audit
and rotation. Both rules are stated in `pkg/bmc/CLAUDE.md`.

Compatibility: `credentialRecord` is the on-disk contract for stored
credentials; changing its field names breaks every stored credential.
`MarshalCredentials` returns plaintext bytes that **the caller must zero** after
the store write — the doc comment says so and `UnmarshalCredentials` zeroes its
input unconditionally via `defer zero(b)`.

## 8. Protected memory

Non-negotiable, and enforced by signature rather than convention:

- `UserManager.CreateUser` and `SetUserPassword` take `*memguard.Secret`. Raw
  `string`/`[]byte` passwords are deliberately absent from the interface.
- `CertificateManager.ReplaceWebCertificate` takes `certPEM []byte` and
  `keyPEM *memguard.Secret`.
- `PasswordGenerator` is `func() (*memguard.Secret, error)`;
  `GenerateRandomPassword(n)` returns one. `DefaultPasswordLength` is `20`; the
  alphabet is `[A-Za-z0-9]` only, because BMC firmware routinely mangles
  punctuation.
- `Credentials.Password` is a `*memguard.Secret` with `Destroy`, `IsAlive` and
  `Clone`.
- `Service.ReplaceWebCertificate` copies the caller's `keyPEM` into a fresh
  `memguard.Secret` and destroys it on return — and its doc comment states that
  it does **not** scrub the caller's slice. Callers own that.
- Intermediate `[]byte` buffers (PEM bundles, multipart bodies) are zeroed
  immediately after `httpClient.Do` returns.

## 9. Concurrency

- `Service.clients` is a `sync.Map`; `clientFor` uses `LoadOrStore` and closes
  the losing duplicate. No mutex is held across a network dial.
- `ipmiClient` is shared by every caller of a profile, so its lifecycle is
  locked in two layers. `openMu` serialises lazy establishment (`ensureOpen`,
  `ensureRedfishClient`), so concurrent first callers open exactly one RMCP+
  session. `opMu` is an `RWMutex`: every operation holds it for reading from
  `acquire` / `acquireRedfish` until it returns, and `Close` flips `closed`,
  then holds it for writing while it tears down the session and the Redfish
  delegate — so `Close` waits for in-flight operations, and an operation never
  has its session pulled out from under it. Helpers reached from an operation
  (`readFRU`, `hardwareIdentity`, `resolveSOLPayloadInstance`) run under the
  caller's read lock and never acquire again. A `SOLSession` returned by
  `Console` keeps using the client's RMCP+ session, so it holds the read pin
  until its first `Deactivate` (`releasePin`, once); `Close` deactivates every
  console still open before taking the write lock, so closing the client never
  waits on a console its owner forgot. Below the client, `rmcpSession.Send`
  holds `exchangeMu` across the write-then-read of one command — the RMCP+
  session has no request correlation (`rqSeq` is fixed) — and
  `unwrapResponse` rejects a datagram whose command or netFn does not answer
  the request (`ErrResponseMismatch`), so concurrent IPMI commands on the
  shared client are serialised per exchange and a crossed response is an
  error rather than another command's data; `rebindForSOL` swaps the socket
  under the same lock. An active console is the exception: its receive loop
  owns the socket's reads (which is why `openSOLConsole` in `pkg/bootstrap`
  and the CLI console open a client dedicated to the console), and
  `Deactivate` waits for the loop to return (`loopDone`) before it sends
  Deactivate Payload, so that command's response is not swallowed. The IPMI-derived hardware identity is an `atomic.Pointer`
  filled with `CompareAndSwap` (§10).
- `AutoCertManager` guards `resolveBackends`, `Backend()` and `Close()` with a
  `sync.Mutex`. Its lazily-built managers are shared once resolved.
- The cert-backend factory registry is guarded by a `sync.RWMutex`;
  `RegisterCertFactory` replaces an existing entry for the same backend and
  ignores a nil factory.
- `MemoryStore` uses a `sync.RWMutex`.
- `quirks.registry` is built once in `init()` and read-only thereafter.
- `ipmiClient.closed` is an `atomic.Bool`; every method checks it first.
- `SOLSession` is an `io.ReadWriteCloser` — a single long-lived stream, not
  safe to fan out.

## 10. Vendor quirk resolution

`ResolveIdentity(Identity{Manufacturer, Model, PartNumber})`, case-insensitive
and whitespace-trimmed on every field:

1. board-specific entries for that manufacturer whose non-empty `model` key
   is a **substring** of `Model` (so `x10sdv` matches `X10SDV-TP8F`) **or**
   whose non-empty `partNumberPrefix` is a **prefix** of `PartNumber` (so
   `sys-5018d-fn` matches `SYS-5018D-FN8T-AS001` on firmware that serves the
   placeholder `Model: Super Server`). The most specific wins: a `model` key
   **equal** to `Model` beats a substring or prefix hit, then the longer
   matching key; declaration order only breaks exact ties
2. the manufacturer-wide entry (no model or part-number key)
3. `Default()`

`Resolve(manufacturer, model)` is `ResolveIdentity` with an empty
`PartNumber`. The returned `Quirk.Key` names the winning entry
(`supermicro/x10sdv`, `supermicro`, `default`, …); `redfishClient` logs it at
`Info` once when discovery caches the identity, and `ipmiClient` logs its
own resolution — manufacturer from the Get Device ID IANA number, model and
part number from the FRU — once when `hardwareIdentity` first caches it
(`manufacturerName` is that identity's `Manufacturer` field).

`Vendor.ManufacturerString()` supplies the canonical Redfish
`System.Manufacturer` key: `Supermicro`, `Dell Inc.`, `HPE`, `Lenovo`; `""` for
`VendorUnknown` and `VendorGeneric`, which resolve to `Default()`.

Vendor detection (`classifyVendor`) reads the service root's standardized
`Vendor` field first, matching lower-cased substrings
(`supermicro`, `dell`, `hpe`, `hewlett`, `lenovo`); falls back to `Oem`
extension keys (`Supermicro`, `Dell`, `Hpe`, `Hp`, `Lenovo`) — which is what
rescues X10 ATEN firmware that omits `Vendor` entirely; and returns
`VendorGeneric` when the root parses with a `RedfishVersion` but no vendor
signal, `VendorUnknown` otherwise.

`recommendedCertBackend` maps `supermicro` → `smc-cgi` and everything else →
`redfish`.

**Adding a board is a data-only change**: one entry in
`pkg/quirks/registry.go`. No control-path edits.

## 11. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/bmc/*_test.go`, `pkg/bmc/smc/*_test.go`, `pkg/bmc/credentials/*_test.go`, `pkg/quirks/quirks_test.go` | Config validation, factory dispatch, vendor classification, quirk resolution, cert-backend selection and fallback, virtual-media dispatch, rotation state machine, credential marshalling, SDR/FRU parsing, RMCP+ framing |
| Unit (CLI) | `pkg/cli/commands/bmc/*_test.go` | Flag validation, mode conflict, standalone config construction, enroll option tri-state |
| Unit (API) | `pkg/webservice/v1/bmc/*_test.go`, `pkg/api/mcp/bmc_dispatch_test.go`, `pkg/api/daemon/quic_dispatch_guard_test.go` | Handler status codes, MCP tool dispatch, QUIC opcode routing |
| Unit (SDK parity) | `pkg/api/daemon/bmc_{quic,mcp,embedded}_sdk_test.go` (drivers in `bmc_sdk_parity_test.go`) | Every `BMCService` method through the SDK's QUIC, MCP and embedded adapters against the daemon's handlers; the gRPC scope and not-found refusals |
| Integration | `test/integration/bmc/` | Real containerized vBMC responders |

Make targets: `make test-bmc` (runs `./pkg/bmc/...`,
`./pkg/app/bmc_cert_test.go`, `./pkg/cli/commands/bmc/...`),
`make coverage-bmc`, `make integration-test-bmc` (drives
`build/docker/devcontainer/run-integration-tests.sh bmc`).

**Fault-injection seams**, for anyone writing a test:

- `newBMCClient` in `pkg/cli/commands/bmc/standalone.go` is a package-level
  `var` specifically so tests can inject a `MockClient`.
- `bmc.MockClient` (`pkg/bmc/mock.go`) implements the full `Client` interface.
- `runEnroll` takes a `bmcEnroller` parameter; a non-nil value bypasses SDK
  construction entirely.
- `enrollCore` (`pkg/app/bmc_enroll.go`) is a struct of function fields —
  `certFetcher`, `certIssuer`, `pinUpdater`, `credStore`, `dnsRegister`,
  `danePublish`, `deviceLoader`, `deviceSaver`. Every one is individually
  replaceable, and several are documented as "may be nil", which is how the
  skip-with-reason step outcomes get exercised.
- `RotationOptions` takes an injectable `PasswordGenerator` and
  `UserManagerFactory`.
- `credentials.SecretsService` is a narrowed interface with a compile-time
  assertion (`var _ SecretsService = (baasservice.SecretsService)(nil)`), so a
  fake needs six methods rather than the full QuicBaaS surface.

**Integration tests must not use `httptest` or in-process doubles.** Two vBMC
flavors run beside the devcontainer on the shared compose network:
`vbmc-supermicro` (`VBMC_VENDOR=Supermicro`; Redfish HTTPS + ATEN CGI + IPMI
RMCP+) and `vbmc-dell` (`VBMC_VENDOR=Dell`; Redfish HTTPS + IPMI RMCP+). Both
serve HTTPS on `8443` and IPMI RMCP+ on UDP `6230`, expose `GET /debug/stats`
for counter assertions and `GET /healthz` for liveness. Helpers:
`bmctest.WaitForReady`, `bmctest.ConfigFor`, `bmctest.WithDNSCert`,
`bmctest.GetStats`, flavors `bmctest.VBMCFlavorSupermicro` /
`VBMCFlavorDell`.

vBMC does **not** simulate firmware operations, the SEL, sensor data records,
persistent storage, virtual media, or a full UEFI boot sequence. It is not a
substitute for hardware validation.

**Parity gap.** `conventions/feature-docs.md` §4 requires every `cli.md` verb to
have a `CommandDefinition` in the integration parity suite. **No
`CommandDefinition` type exists anywhere in this repository** (grepped
2026-08-18 — it appears only in documentation). The requirement is unmet
repo-wide, not specifically for BMC.

## 12. `pkg/bmc/attestation` — scaffolding, not a capability

The package defines `AttestationProvider`, `Evidence`, `EvidenceMetadata`,
`Measurement`, `Policy`, `VerifyResult`, `Verifier`, `Target`, a
`ProviderFactory` registry (`Register`, `NewProvider`, `DetectVendor`), and
three backends: `dell.RedfishBackend`, `hpe.ILOBackend`,
`supermicro.StubBackend`.

**Nothing outside the package imports it.** `pkg/bmc/CLAUDE.md` records it as
"preserved scaffolding, no real implementation until RoT-capable hardware
available". Treat it as a design placeholder; it has no CLI, no route, and no
transport. Design note: [`docs/architecture/bmc-attestation.md`](../architecture/bmc-attestation.md).

## 13. Observability

Structured events emitted by this feature:

| Event | Emitted by | Fields |
|---|---|---|
| `bmc: vendor probe complete` | `VendorProbe.Detect` | `address`, `vendor`, `redfish_version` |
| `bmc: autocert: resolved backend` | `AutoCertManager.resolveBackends` | `vendor`, `requested`, `resolved`, `has_fallback` |
| `bmc: autocert: primary backend unsupported, trying fallback` | `ReplaceWebCertificate` | `primary`, `fallback`, `error` |
| `bmc: autocert: fallback backend succeeded` | same | `backend` |
| `bmc: created Redfish fallback client for virtual media` | `ipmiClient.ensureRedfishClient` | `address` |
| `bmc: failed to close duplicate client` | `Service.clientFor` | `profile_id`, `error` (warn) |
| `bmc: rotation: new password stored, applying to BMC` | `RotateOnce` | `name`, `slot` |
| `bmc: rotation: verified` | `RotateOnce` | `name`, `slot` |
| `bmc: rotation: apply or verify failed, attempting rollback` | `RotateOnce` | `name`, `slot`, `cause` |
| `bmc: rotation: CATASTROPHIC — rollback failed; store holds new password matching BMC` | `RotateOnce` | `name`, `slot`, `apply_err`, `rollback_err` |
| `bmc-cert-init: no BMC TLS management configured; skipping` | `initBMCCertManagement` | — |
| `bmc-cert-init: BMC TLS management initialized` | same | `device_id`, `node_id`, `backend` |
| `BMC gRPC service initialized and registered successfully` | `pkg/api/daemon/daemon.go` | — |
| `BMC gRPC enroller wired` / `BMC gRPC restorer wired` | same | — |
| `BMC REST enroller wired` | same | — |
| `BMC management routes registered` | `rest_service.go` | — |

**Absence of the two `autocert:` lines means `AutoCertManager` was never
constructed for that BMC** — check that `certificate:` and `key:` are both
populated.

The audit record for the trust lifecycle is `app.BMCEnrollResult.Steps` and
`app.BMCRestoreResult.Steps` (surfaced through the SDK as
`bmcsvc.EnrollResult` / `bmcsvc.RestoreResult`), persisted in condensed form on
`Device.BMCEnrollment`. `BMCEnrollStep.Detail` is documented as never
containing secret material.

**Never log:** BMC passwords, `MediaSpec.Password`, TLS private key PEM,
`memguard.Secret` contents, or the marshalled `credentialRecord`.

## 14. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — transports, QUIC opcodes, status bytes, authorization
- [`docs/architecture/bmc-tls.md`](../architecture/bmc-tls.md) — the certificate lifecycle
- [`docs/architecture/vendor-quirks.md`](../architecture/vendor-quirks.md) — the quirk registry design note
- [`docs/device/`](../device/) — device templates and profiles
- [`docs/bootstrap/`](../bootstrap/) — the orchestrator that enrolls at phase 5a
- Legacy, deleted; these five files hold their content: `README.md`, `configuration.md`, `operations.md`, `sdk.md`, `testing.md`. Corrections are listed in [architecture.md](architecture.md) §9.
