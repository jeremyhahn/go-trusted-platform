# LUKS Key-Slot Management — Engineering

> **Status: NORMATIVE** · Scope: `pkg/api/daemon/luks_*.go`, `pkg/app/backends/luks*.go`, `sdk/go/services/luks`, `pkg/cli/commands/luks` · Last verified: 2026-10-11
> Conflicts with this document are defects. Fix them here first.

---

## 1. Exported surface

### Daemon service — `pkg/api/daemon/luks_service.go`

| Symbol | Purpose |
|---|---|
| `LUKSService`, `NewLUKSService(logger, backend, root)` | The service every transport calls. A nil `root` checker means **never root**. |
| `(*LUKSService).SetBackend`, `Backend` | Swap the backend; guarded by an `RWMutex`. |
| `LUKSBackend` | Interface the service delegates to: `Status`, `ListSlots`, `Info`, `EnrollPassphrase`, `EnrollFIDO2`, `EnrollTPM`, `EnrollRecovery`, `RemoveKey`, `TestUnlock`, `ChangePassphrase`. |
| `RootChecker`, `RootCheckerFunc` | `IsRoot() bool`, consulted by mutating operations. |
| `LUKSKeyType` | `""`, `passphrase`, `fido2`, `tpm`, `recovery`. |
| `LUKSKeyslot`, `LUKSStatus`, `LUKSListSlotsResult`, `LUKSInfo` and the `LUKS<Op>Request` / `LUKS<Op>Result` structs | Request and response types. They carry **no JSON tags**. |
| `(*Daemon).SetLUKSBackend`, `SetLUKSRootChecker` (`daemon.go`) | Inject the backend and root checker into the running service. |

### Backend — `pkg/app/backends/luks.go`

| Symbol | Purpose |
|---|---|
| `LUKSBackend`, `NewLUKSBackend(logger, opts...)` | go-luks2 implementation of `daemon.LUKSBackend`. |
| `WithLUKSFIDO2Handler`, `WithLUKSTPMHandler`, `WithDefaultLUKSHandlers` | Handler options. The default handlers bind the FIDO2 HID enumerator and `/dev/tpmrm0`; failure to build one is logged at debug and leaves it unset. |
| `SetFIDO2Handler`, `SetTPMHandler` | Late handler injection. |
| `LUKSFIDO2Handler`, `LUKSFIDO2EnrollingHandler`, `LUKSTPMHandler` | Handler seams. The enrolling variant writes its salt into the LUKS2 token. |
| `DefaultRootChecker()` | `os.Geteuid() == 0`. |

### SDK — `sdk/go/services/luks`

| Symbol | Purpose |
|---|---|
| `Service` | The ten operations, transport-neutral. |
| `Client`, `NewClient()` | **Stub.** Every method returns `ErrNotYetWired` wrapped in its `Err<Op>Failed`. |
| `GRPCClient`, `NewGRPCClient(conn)`, `NewGRPCClientFromClient` | Working gRPC (and Unix) client. |
| `KeyType`, `Keyslot`, `<Op>Request` / `<Op>Response` | SDK types. |

### CLI — `pkg/cli/commands/luks`

`NewCommand(getFlags)` builds `platformctl luks` and its ten verbs; see
[cli.md](cli.md).

---

## 2. Invariants

1. **Validation order in `LUKSService`.** Mutating operations check root first,
   then `Device`, then the operation's own fields, then that a backend is set.
   Read-only operations (`Status`, `ListSlots`, `Info`) and `TestUnlock` check
   `Device`, then the backend; they never check root.
2. **Field order within an operation:** `EnrollPassphrase` checks the new
   passphrase before the existing one; `EnrollFIDO2` checks the credential ID
   before the existing passphrase; `ChangePassphrase` checks the new passphrase
   before the old one.
3. **The server does not validate slot numbers.** Only the CLI rejects a slot
   outside `0`–`31`.
4. **Every new keyslot passes the FIPS keyslot policy.** `fipsAddKeyOptions` and
   `fipsRecoveryKeyPolicy` (`luks_fips.go`) resolve the KDF and PRF through
   `pkg/fips.ResolveKeyslotPolicy`: on a FIPS host an empty KDF becomes PBKDF2
   with an approved PRF; otherwise go-luks2's defaults apply.
   `pkg/arch/luks_keyslot_policy_test.go` fails the build if a keyslot call
   bypasses it.
5. **New slot detection.** After `AddKey`, the backend reports the slot that was
   absent from the pre-call snapshot; if none is found it reports the highest
   slot.
6. **Key-type classification.** A type derived from the slot's token wins over
   the keyslot's own type. Token and keyslot types map as follows:

   | Reported type | Token / keyslot types |
   |---|---|
   | `passphrase` | `luks2`, `passphrase`, `trusted-platform-luks2` |
   | `fido2` | `fido2`, `fido2-manual`, `systemd-fido2` |
   | `tpm` | `tpm`, `tpm2`, `systemd-tpm2` |
   | `recovery` | `recovery`, `systemd-recovery` |

7. **Recovery keys are formatted dashed** (`RecoveryKeyFormatDashed`), returned
   once, and cleared from the backend's memory after formatting.

---

## 3. Backend operation map

| Operation | go-luks2 call | Notes |
|---|---|---|
| Status | `GetVolumeInfo` | |
| ListSlots | `ListKeyslots` | type per §2.6 |
| Info | header metadata | `SectorSize` defaults to `luks2.DefaultSectorSize`; `MetadataJSON` is the raw JSON area |
| EnrollPassphrase | `AddKey` | |
| EnrollFIDO2 | `AddKey`, then the token | an enrolling handler imports its own token JSON; otherwise a `fido2-manual` token is written |
| EnrollTPM | `AddKey`, then the handler's token JSON | the handler seals to `--handle` / `--pcrs` |
| EnrollRecovery | `AddRecoveryKey` | |
| RemoveKey | `KillKeyslot` | destructive |
| TestUnlock | `ListKeyslots` | **checks only that the slot exists**; no key material is tried |
| ChangePassphrase | `ChangeKey(device, old, new, slot)` | |

---

## 4. Errors

### Service (`pkg/api/daemon/luks_service.go`)

| Error | Message | REST | gRPC |
|---|---|---|---|
| `ErrLUKSNotConfigured` | `luks: backend not configured` | 503 | `Unavailable` |
| `ErrLUKSRootRequired` | `luks: operation requires root privileges` | 403 | `PermissionDenied` |
| `ErrLUKSDeviceRequired` | `luks: device path is required` | 400 | `InvalidArgument` |
| `ErrLUKSPassphraseRequired` | `luks: passphrase is required` | 400 | `InvalidArgument` |
| `ErrLUKSNewPassphraseRequired` | `luks: new passphrase is required` | 400 | `InvalidArgument` |
| `ErrLUKSCredentialIDRequired` | `luks: fido2 credential id is required` | 400 | `InvalidArgument` |
| `ErrLUKSSlotRequired` | `luks: slot index is required` | 400 | `InvalidArgument` |
| anything else | — | 500 | `Internal` |

`ErrLUKSSlotRequired` is mapped but never returned.

### Backend (`pkg/app/backends/luks.go`)

`ErrLUKSVolumeNotFound` (`device is not a LUKS2 volume`),
`ErrLUKSFIDO2NotWired`, `ErrLUKSTPMNotWired` (handler not configured),
`ErrLUKSHardwareUnavailable`. None has a dedicated transport mapping, so each
surfaces as 500 / `Internal`.

### SDK and CLI

`sdk/go/services/luks/errors.go`: `ErrNotYetWired` and one
`Err<Op>Failed{Cause}` per operation, each with `Unwrap`.
`pkg/cli/commands/luks/errors.go`: the validation errors listed in
[cli.md](cli.md) §4.

---

## 5. Configuration and persistence

There is no configuration key. The device is a per-request argument; the CLI
falls back to auto-detection ([cli.md](cli.md) §3).

The only persistent state is the LUKS2 header itself: keyslots and tokens. The
platform stores nothing about the volume.

---

## 6. Wiring as shipped

`daemon.go` constructs `NewLUKSService(logger, nil, nil)` and registers it on
REST, gRPC (TCP and Unix), QUIC and MCP. **No production code calls
`SetLUKSBackend`, `SetLUKSRootChecker`, `NewLUKSBackend` or
`DefaultRootChecker`.** The consequences on every server transport:

- mutating operations return `ErrLUKSRootRequired` (the nil root checker reports
  non-root), before the backend is ever consulted;
- `status`, `list-slots`, `info` and `test-unlock` return `ErrLUKSNotConfigured`.

On the client side, every `platformctl luks` verb calls `luks.NewClient()`, the
stub, so it fails with `not yet wired` after its local checks.

The working pieces are the backend (exercised by its loopback tests) and the
server-side transport adapters (exercised against a stub backend).

---

## 7. Tests

| Test | Covers |
|---|---|
| `pkg/api/daemon/luks_service_test.go` | validation order, root gate, not-configured paths |
| `pkg/api/daemon/luks_grpc_service_test.go` | gRPC adapter and error mapping |
| `pkg/app/backends/luks_test.go`, `luks_fido2_handler_test.go`, `luks_tpm_handler_test.go`, `luks_fips_test.go` | backend, handlers, FIPS policy |
| `pkg/app/backends/luks_integration_test.go` | enroll and test against a loopback LUKS2 volume |
| `pkg/arch/luks_keyslot_policy_test.go` | every keyslot call applies the FIPS policy |
| `pkg/cli/commands/luks/luks_test.go` | verb tree and flag declarations |
| `test/integration/luks/` (`make integration-test-luks`) | CLI, REST, gRPC, QUIC, MCP and Unix adapters; needs `cryptsetup` and root for the loopback volume |

The integration suite accepts *not configured*, *root required*, *not yet wired*
and any `luks: ` error as a pass, so today it proves wire reachability only. It
has no embedded adapter.

---

## 8. Observability

The backend logs, at debug, when a default FIDO2 or TPM handler cannot be built.
The service and backend emit no other logs or metrics; transport-level request
logging applies.
