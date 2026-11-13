# LUKS Key-Slot Management — Engineering

> **Status: NORMATIVE** · Scope: `pkg/api/daemon/luks_*.go`, `pkg/app/backends/luks*.go`, `sdk/go/services/luks`, `pkg/cli/commands/luks`; §9–§10 cover every go-luks2 call site · Last verified: 2026-10-13
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
| `LUKSKeyslot`, `LUKSStatus`, `LUKSListSlotsResult`, `LUKSInfo` and the `LUKS<Op>Request` / `LUKS<Op>Result` structs | Request and response types. The `LUKS<Op>Request` structs carry snake_case JSON tags, matching the pb field names every SDK transport sends; the result structs carry **no JSON tags**, so their JSON keys are the Go field names. |
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
| `GRPCClient`, `NewGRPCClient(conn)`, `NewGRPCClientFromClient` | The client. `NewGRPCClientFromClient(c.LUKS())` dispatches over whichever transport `platform.Client` selected. |
| `KeyTypeFromWire`, `KeyslotFromWire`, `Decode<Op>JSON` | Map the daemon's string keyslot type and untagged JSON replies onto the pb types for the QUIC and MCP adapters; an unknown type is `ErrUnknownWireValue`. |
| `KeyType`, `Keyslot`, `<Op>Request` / `<Op>Response` | SDK types. |

### CLI — `pkg/cli/commands/luks`

`NewCommand(getFlags)` builds `platformctl luks` and its ten verbs; see
[cli.md](cli.md).

---

## 2. Invariants

1. **Validation order in `LUKSService`.** Mutating operations check root first,
   then `Device`, then the operation's own fields, then that a backend is set.
   Read-only operations (`Status`, `ListSlots`, `Info`) and `TestUnlock` check
   `Device`, then the backend; they never check root. One check precedes
   root: `EnrollFIDO2` with `require_pin` is refused with
   `ErrLUKSFIDO2PINUnsupported` before anything else.
2. **Field order within an operation:** `EnrollPassphrase` checks the new
   passphrase before the existing one; `EnrollFIDO2` checks the credential ID
   before the existing passphrase; `ChangePassphrase` checks the new passphrase
   before the old one.
3. **The server does not validate slot numbers.** Only the CLI rejects a slot
   outside `0`–`31`.
4. **Every new keyslot passes the FIPS keyslot policy.** `fipsAddKeyOptions` and
   `fipsRecoveryKeyPolicy` (`luks_fips.go`) resolve the KDF and PRF through
   `pkg/fips.ResolveKeyslotPolicy`: on a FIPS host an empty KDF becomes PBKDF2
   with an approved PRF; otherwise go-luks2's defaults apply (argon2id).
   "FIPS" here means the kernel indicator is set **or** the Go cryptographic
   module runs in FIPS 140-3 mode (`crypto/fips140.Enabled()`, e.g.
   `GODEBUG=fips140=only`): the module refuses Argon2 whatever the kernel says,
   so in that mode an unset KDF also becomes PBKDF2 (go-luks2's SHA-256 PRF).
   A recovery keyslot is covered the same way; `RecoveryKeyOptions` has no hash
   or iteration-time field, so its PBKDF2 cost is go-luks2's calibrated default.
   `pkg/arch/luks_keyslot_policy_test.go` fails the build if a keyslot call
   bypasses it.
5. **New slot detection.** After `AddKey`, the backend reports the slot that was
   absent from the pre-call snapshot. If none is found it fails with
   `ErrLUKSNewSlotNotFound`; it never guesses the highest slot, which can name
   a keyslot the enrollment did not write.
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
8. **A keyslot is never left without its token.** FIDO2 and TPM enrollment write
   the token through `writeEnrollToken`. If the token cannot be written
   (go-luks2 v0.2.0 returns `ErrMetadataTooLarge` when the fixed JSON area is
   full) or the handler returned none (`ErrLUKSTokenMissing`), the new keyslot
   is removed with `KillKeyslot` and the enrollment fails with
   `LUKSTokenWriteError`. A keyslot no unlock strategy can find is worse than a
   failed enrollment.

---

## 3. Backend operation map

| Operation | go-luks2 call | Notes |
|---|---|---|
| Status | `GetVolumeInfo` | |
| ListSlots | `ListKeyslots` | type per §2.6 |
| Info | header metadata | `SectorSize` defaults to `luks2.DefaultSectorSize`; `MetadataJSON` is the raw JSON area |
| EnrollPassphrase | `AddKey` | |
| EnrollFIDO2 | `AddKey`, `FindFreeTokenSlot`, `ImportTokenJSON` / `ImportToken` | an enrolling handler imports its own token JSON; otherwise a `fido2-manual` token is written; a failed token write removes the keyslot (§2.8) |
| EnrollTPM | `AddKey`, `FindFreeTokenSlot`, `ImportTokenJSON` | the handler seals to `--handle` / `--pcrs`; no token JSON is `ErrLUKSTokenMissing` and removes the keyslot (§2.8) |
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
| `ErrLUKSFIDO2PINUnsupported` | `luks: fido2 require-pin is refused: …` | 400 | `InvalidArgument` |
| `ErrLUKSMalformedBody` | `luks: malformed request body` | 400 | — (REST only) |
| anything else | — | 500 | `Internal` |

`ErrLUKSSlotRequired` is mapped but never returned.

### Backend (`pkg/app/backends/luks.go`)

`ErrLUKSVolumeNotFound` (`device is not a LUKS2 volume`),
`ErrLUKSFIDO2NotWired`, `ErrLUKSTPMNotWired` (handler not configured),
`ErrLUKSHardwareUnavailable`, `ErrLUKSNewSlotNotFound` (§2.5),
`ErrLUKSTokenMissing` and `LUKSTokenWriteError{Slot, Err, RollbackErr}` (§2.8).
`LUKSTokenWriteError` unwraps to the write error and, when the keyslot could
not be removed either, to the rollback error; its message then says the keyslot
is still on the volume. None has a dedicated transport mapping, so each
surfaces as 500 / `Internal`.

### SDK and CLI

`sdk/go/services/luks/errors.go`: one `Err<Op>Failed{Cause}` per operation,
each with `Unwrap`, plus `ErrUnknownWireValue` and `ErrWireDecode` for a reply
the wire decoders cannot map.
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
REST, gRPC (TCP and Unix), QUIC and MCP. The platformd startup path then calls
`backends.WireSDKBackends` (`pkg/app/backends/sdk_wiring.go`), which, after the
ceremony backend, injects the production LUKS pieces through the
`SDKBackendTarget` interface (implemented by `*daemon.Daemon`):

- `SetLUKSBackend(NewLUKSBackend(logger, WithDefaultLUKSHandlers()))`: the
  go-luks2 backend, with its FIDO2 and TPM handlers then cleared. No boot
  unlock path consumes what either default handler enrolls: the FIDO2 handler
  binds the 64-byte go-xkms derived key, which the initrd FIDO2 strategy cannot
  derive, and the TPM sealer keeps its sealed passphrase in a `systemd-tpm2`
  header token, while the initrd TPM strategies unseal from the ESP. So
  `EnrollFIDO2` answers `ErrLUKSFIDO2NotWired` and `EnrollTPM`
  `ErrLUKSTPMNotWired` before touching the device. Passphrase, recovery,
  remove, test-unlock and change-passphrase run against the device. The PCR
  check (`pcrCheckedTPMHandler`, `ErrLUKSPCRInvalid`, 400 on REST and
  `InvalidArgument` on gRPC) is in front of the TPM handler when one is wired;
- `SetLUKSRootChecker(DefaultRootChecker())`: the effective-UID root gate for
  mutating operations.

The LUKS backend needs no SDK client, but it is wired only when
`WireSDKBackends` succeeds: if the SDK client is missing it returns
`ErrCeremonyBackendRequiresSDK` and wires nothing, so every server transport
keeps answering as before (mutations `ErrLUKSRootRequired`, reads
`ErrLUKSNotConfigured`).

On the client side, every `platformctl luks` verb reaches the server through
`platform.Client.LUKS()`, so after its local checks it runs against the wired
backend on whichever transport is active.

`TestWireSDKBackends_WiresLUKS` (`pkg/app/backends/sdk_wiring_test.go`) checks
that a fake target receives a non-nil `*LUKSBackend` and a root checker, and
`TestWireSDKBackends_NoSDKClientIsFatal` that a refused wiring sets neither.

---

## 7. Tests

| Test | Covers |
|---|---|
| `pkg/api/daemon/luks_service_test.go` | validation order, root gate, not-configured paths |
| `pkg/api/daemon/luks_grpc_service_test.go` | gRPC adapter and error mapping |
| `pkg/api/daemon/mcp_luks_parity_test.go` | the MCP provider and the gRPC service over one service and an in-memory backend: same answers, and the same code for invalid input, a backend error, non-root and not configured, test-unlock included |
| `pkg/api/mcp/luks_authz_test.go` | each LUKS tool's scope, `tools/call` running the handler only for a caller holding it, test-unlock included |
| `pkg/app/backends/luks_test.go`, `luks_fido2_handler_test.go`, `luks_tpm_handler_test.go`, `luks_fips_test.go` | backend, handlers, FIPS policy |
| `pkg/app/backends/luks_token_test.go` | slot detection, token write and rollback (`ErrMetadataTooLarge`, failed rollback), `AddRecoveryKey` slot; file-backed images, no loop device |
| `pkg/app/backends/luks_integration_test.go` | enroll and test against a loopback LUKS2 volume |
| `pkg/installer/mapped_name_test.go`, `pkg/storage/drive/types_test.go` | mapping names `Unlock` would refuse are rejected before the disk is formatted |
| `pkg/installer/release_test.go`, `pkg/boot/commands/closeinstaller_test.go`, `pkg/firstboot/close_mapping_test.go` | mapping close under the v0.2.0 `Lock` (`ErrMappingBusy`, `ErrVolumeNotUnlocked`) |
| `pkg/arch/luks_keyslot_policy_test.go` | every keyslot call applies the FIPS policy |
| `pkg/cli/commands/luks/luks_test.go` | verb tree and flag declarations |
| `test/integration/luks/` (`make integration-test-luks`) | CLI, REST, gRPC, QUIC, MCP and Unix adapters; needs `cryptsetup` and root for the loopback volume |

The integration suite accepts a typed not-implemented declaration, *not
configured* and *root required* as a pass, so today it proves wire reachability
only. Its REST adapter runs through the SDK REST transport. It has no embedded
adapter.

`pkg/api/daemon/luks_rest_sdk_test.go` runs the SDK REST transport against the
daemon's real REST router, backed by an in-memory `LUKSBackend`, for all ten
operations. It checks the request fields the backend receives, the decoded
reply, and that the device-required, not-configured and root-required refusals
reach the caller as the typed SDK error with the same gRPC code and bare
message QUIC and MCP return. It also checks that a malformed body never echoes
the passphrase.

`pkg/api/daemon/luks_embedded_sdk_test.go` drives all ten operations through
the SDK embedded transport over the registry the daemon's embedded host builds.
Each reply and each backend request must match a direct gRPC call on the same
servicer, and so must the device-required and not-configured refusals. A host
with no LUKS service answers `Unimplemented`.

---

## 8. Observability

The backend logs, at debug, when a default FIDO2 or TPM handler cannot be built.
The service and backend emit no other logs or metrics; transport-level request
logging applies.

---

## 9. go-luks2 v0.1.7 → v0.2.0 audit

PR #684 moved go-luks2 from v0.1.7-alpha to v0.2.0-alpha and brought in the
v0.1.8, v0.1.10 and v0.2.0 behaviour changes at once. Issue #163 audited every
production call site against the upstream CHANGELOG. *Depended* means a call site
relied on the v0.1.7 behaviour and was changed. go-luks2 is selected at
v0.2.0-alpha for the whole build, so anything else linked into the platform that
reaches go-luks2 runs the same version. That includes the initrd unlock
strategies, which reach it through `pkg/storage/luks`.

| Symbol | Change | Call sites | Verdict | Fix / test |
|---|---|---|---|---|
| `Format`, `AddKey`, `ImportToken*`, `KillKeyslot`, `ChangeKey` (header writer) | v0.1.8: `tokens` always written, `keyslots_size` is the area size, secondary header carries `SKUL`, `json_size` comes from the area | every writer in `pkg/app/backends`, `pkg/storage/luks`, `pkg/installer` | No dependency: the platform never reads or writes raw header bytes | — |
| `ImportToken`, `ImportTokenJSON`, `AddKey` (metadata) | v0.1.8: fixed header area; metadata that does not fit is `ErrMetadataTooLarge` instead of growing the area | backend `EnrollFIDO2` / `EnrollTPM`; `installer/fido2_enroll.go` token step; `storage/luks/token.go` | **Depended** (backend): a failed token write was logged and the keyslot kept with no token. `fido2_enroll.go` keeps the keyslot and warns that a manual unlock is needed, by design; a freshly formatted header cannot fill. `token.go` returns the error | §2.8 `writeEnrollToken` rolls back with `KillKeyslot` and returns `LUKSTokenWriteError`; `luks_token_test.go` |
| `AddKey` | v0.1.8: bounded by the keyslots area, `ErrKeyslotsAreaFull` | backend, `installer.go` (TPM and recovery slots), `fido2_enroll.go`, `storage/luks` | No dependency: every caller returns the error | — |
| Every opener (`Unlock`, `AddKey`, `ChangeKey`, `KillSlot`, `AddRecoveryKey`) | v0.1.8 digest derived to its stored length (whitelist, 32-byte carve-out) and every digest tried; v0.2.0 the digest must name the keyslot, segments validated, no evaluable digest is `ErrInvalidHeader`, no keyslots is `ErrNoKeyslots` | all | No dependency: platform headers are written by go-luks2 itself; a malformed header now fails earlier, with a typed error | — |
| `AddRecoveryKey` | v0.2.0 (#42): returns the slot it actually wrote | backend `EnrollRecovery`; `storage/luks/manager.go` | Fixed upstream. The backend's own `detectNewSlot` had the same bug (it guessed the highest slot) | `ErrLUKSNewSlotNotFound` (§2.5); `TestAddRecoveryKey_ReportsTheSlotItWrote`, `TestDetectNewSlot_*` |
| `Unlock` | v0.1.10: the volume key goes through the session keyring as a `logon` key and fails closed with `ErrKeyring*` | `boot/commands/boot.go` installer image; `firstboot/executor.go`, `strategy.go` installer image; `installer/disk.go` root; `installer.go` installer image; `fido2_enroll.go` `VerifyPassphrase`; `fido2_unlock.go` `Unlock`, `TestUnlock`; `storage/luks` `handler.go`, `manager.go` (initrd strategies, multi-drive) | **Environment dependency**, §10. Every wrapper keeps the cause reachable with `errors.Is`, except `FIDO2Unlock.TestUnlock`, which replaced it with "key does not unlock device" | `TestUnlock` now returns a `WrappedError` carrying the cause. Not unit-tested: it derives its key by running `fido2-assert`, which leaves no seam |
| `Unlock` → `ValidateMappingName` | v0.1.10: refuses names device-mapper would mangle (`ErrInvalidMappingName`) | `installer/disk.go` (`disk.encryption.mapped-name`); `initrd/multidrive.go` (`storage.drives[].partitions[].encryption.mapping-name`); everything else uses fixed valid names | **Depended**: both paths format the disk *before* unlocking it, so a bad name wiped the disk and then failed | Refused at validation: installer `Config.Validate` (`ErrInvalidMappedName`), drive `PartitionConfig.Validate` (`InvalidMappingNameError`; an encrypted partition with no name is now `ErrEncryptionMappingNameRequired`); `installer/mapped_name_test.go`, `storage/drive/types_test.go` |
| `Unlock` | v0.2.0: an open mapping is `ErrVolumeAlreadyUnlocked` | all `Unlock` sites | No dependency: v0.1.7 failed here too, untyped | — |
| `Lock` | v0.2.0: retries `EBUSY` for about 3 s, then `ErrMappingBusy`; a mapping that is not open is `ErrVolumeNotUnlocked` | `boot.go` `closeInstaller`; `firstboot/strategy.go` installer close; `installer.go` final close; `installer/release.go` `releaseDisk`; unchecked error-path cleanups in `boot.go`, `executor.go`, `strategy.go`, `installer.go` | **Depended**: the close loops retried every error and treated an already-removed mapping as a failure. Unchecked cleanups now wait up to about 3 s more on a busy mapping, which is harmless | `closeInstaller`, `closeInstallerMapping`, `closeInstalledLUKS` and `releaseDisk` treat `ErrVolumeNotUnlocked` as closed and retry only `ErrMappingBusy`; `closeinstaller_test.go`, `close_mapping_test.go`, `release_test.go` |
| `Mount`, `Unmount` | v0.2.0: `ErrVolumeNotUnlocked`, `ErrNotMounted` wired; `IsMounted` decodes escapes | `storage/luks/manager.go` | No dependency: errors are wrapped and returned | — |
| `Format`, `AddKey`, `AddRecoveryKey` (PBKDF2) | v0.2.0 (#52): calibrated to about 2000 ms with an OWASP floor; `PBKDFIterTime` must be 1–600000; calibration failure is `ErrKDFCalibration` | all PBKDF2 keyslot creation (FIPS hosts, §2.4) | No dependency: no production code sets `PBKDFIterTime` (`storage/luks/handler.go` passes a caller's value through). Each PBKDF2 keyslot now costs about 2 s at install or enrollment. Existing keyslots keep their iterations until rekeyed | — |
| `Format`, `AddKey` (FIPS) | v0.2.0 (#15): FIPS check moved to keyslot creation, so Argon2 keyslots open in FIPS mode | FIPS keyslot policy (§2.4) | No dependency: relaxed, and the platform's own policy still applies | — |
| `KillSlot` | v0.2.0: authenticates through the master-key path ("could not authenticate against …"), checks that the keyslot may be removed and that the header is writable before wiping | `firstboot/executor.go`; `firstboot/strategy.go` (recovery, installer slot) | No dependency: `strategy.go` matches "does not exist", which is still the missing-slot message. The new refusal is safer | — |
| `ErrInvalidPassphrase`, `ErrAlreadyMounted` | v0.2.0: removed | none | No dependency | — |
| `ErrNoFreeTokenSlot`, `ErrTokenNotFound` | unchanged sentinels | `storage/luks/token.go` (`==` checks) | No dependency | — |

**On-disk compatibility.** The module cache, and so every build, holds only
v0.2.0-alpha. A v0.1.7-shaped header cannot be produced in a test without
vendoring the old writer, so none is tested. Upstream's own claim is the
32-byte digest carve-out (v0.1.8), which keeps containers written by older
releases opening. Volumes written by v0.1.7 also lack a `tokens` object, use a
different `keyslots_size`, and have no `SKUL` secondary magic. The first header
write under v0.2.0 (enrollment, rekey, token import) rewrites all three.

---

## 10. Kernel keyring requirement

Since go-luks2 v0.1.10, `Unlock` hands the volume key to device-mapper through
the session keyring as a `logon` key and **fails closed**: it never falls back
to passing the key on the dm table. It needs the kernel built with
`CONFIG_KEYS`, and the `add_key`, `keyctl` and `request_key` syscalls allowed.
A refused keyring is one of `luks2.ErrKeyringBlocked`,
`ErrKeyringUnsupported`, `ErrKeyringQuotaExhausted` or `ErrKeyringFailed`. All
four match `luks2.ErrKeyringUnavailable` and carry a `KeyringUnavailableError`
naming the syscalls. `luks2.CheckKeyringAvailable` is the preflight.

| Where `Unlock` runs | Keyring access |
|---|---|
| Installer, bare metal or VM (root and installer-image unlock) | The host kernel's; no extra setup |
| Installer or firstboot **in a container** | Docker's default seccomp profile blocks the three syscalls, even with `--cap-add SYS_ADMIN`. Run with `--privileged`, `--security-opt seccomp=unconfined`, or a custom profile that allows `add_key`, `keyctl` and `request_key` |
| Initrd (`cmd/platform-initrd`) | The booted kernel's; the image's kernel config must keep `CONFIG_KEYS` |
| Firstboot on the installed system | Same as the initrd |
| Cross-architecture builds under qemu-user | No keyring syscalls (#802): `Unlock` cannot run there; unlock on the target or in a full VM |
| `make integration-test-luks` | The devcontainer must run privileged, or with a seccomp profile allowing the three syscalls |

Every platform caller wraps the `Unlock` error with its cause (`WrappedError`,
`ErrEncryption`, the storage manager's errors), so `errors.Is(err,
luks2.ErrKeyringUnavailable)` holds at the top of each path.
