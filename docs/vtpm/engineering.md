# Virtual TPM — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/vtpm/`, `pkg/swtpm/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Design and boundaries: [architecture.md](architecture.md). Transport matrix:
> [api.md](api.md).

---

## 1. Package layout

`pkg/vtpm/` — the platform-facing feature:

| File | Holds |
|---|---|
| `service.go` | The service façade |
| `types.go`, `config.go` | Types and configuration |
| `generator.go` | Bundle generation — EK, SRK, Secure Boot enrollment |
| `archive.go` | Bundle export and import |
| `nvram.go` | NVRAM handling |
| `target.go`, `tpm_provider.go` | **TPM target resolution** — which TPM a caller actually gets |
| `vm_attestor_device.go`, `vm_attestor_errors.go` | The device a VM attestor talks to |
| `errors.go` | Typed errors |

`pkg/swtpm/` — the swtpm process wrapper: `swtpm.go`, `types.go`, `errors.go`.

## 2. The two nouns: template and bundle

They are not the same thing and the API keeps them separate throughout.

- A **template** is a specification. `CreateTemplate`, `GetTemplate`,
  `ListTemplates`, `DeleteTemplate`, `CloneTemplate`.
- A **bundle** is an instantiated vTPM — its state, its NVRAM, its socket.
  `CreateBundle`, `GetBundle`, `ListBundles`, `DeleteBundle`, plus the runtime
  verbs.

`CloneTemplate` produces a bundle from a template. Errors are separate per noun
(`ErrTemplateNotFound` / `ErrBundleNotFound`,
`ErrTemplateAlreadyExists` / `ErrBundleAlreadyExists`), which is the fastest way
to tell which one you got wrong.

The CLI reflects this: `platformctl vtpm template ...` for templates,
`platformctl vtpm <verb>` for bundles.

## 3. TPM target resolution — the part that will confuse you

`target.go` and `tpm_provider.go` decide **which TPM an operation reaches**: a
hardware TPM character device, an swtpm Unix socket, or nothing. The error set
is unusually specific because each failure means something different:

| Error | Means |
|---|---|
| `ErrNilResolvedTarget` | Resolution produced nothing — a wiring bug |
| `ErrUnknownTPMTarget` | The configured target name is not one the resolver knows |
| `ErrNoTPMDetected` | Nothing found at all |
| `ErrHardwareTPMUnavailable` | A hardware TPM was expected and is not usable |
| `ErrSwtpmSocketUnavailable` | The swtpm socket is not there — usually the daemon is not running |
| `ErrNotCharDevice` | The configured hardware path exists but is not a character device |
| `ErrNotUnixSocket` | The configured socket path exists but is not a socket |
| `ErrTPMDeviceOpenFailed` | Found and could not be opened — permissions, or in use |
| `ErrNilTPMConfig` | No TPM configuration at all |

**`ErrNotCharDevice` and `ErrNotUnixSocket` exist because pointing a hardware
path at a socket (or the reverse) is a common configuration mistake** that would
otherwise surface as an unreadable open error. The type-check happens first.

## 4. Bundle generation

`generator.go` builds a bundle's identity. Its failures are individually named:

`ErrEKGenerationFailed`, `ErrSRKGenerationFailed`, `ErrEKCertInjectionFailed`,
`ErrSecureBootEnrollmentFailed`, `ErrGenerationFailed`,
`ErrSWTPMOperationFailed`.

**EK certificate injection is a distinct step from EK generation.** A bundle can
have an EK and no certificate, which is a bundle that will fail attestation for
a reason that has nothing to do with its keys.

**The certificate is written in `TPM_PT_NV_BUFFER_MAX` chunks.** TPM2_NV_Write
and TPM2_NV_Read move at most `TPM_PT_NV_BUFFER_MAX` bytes per command (TPM 2.0
Part 3 §31.7, §31.13); swtpm reports 1024 and answers a larger write with
`TPM_RC_SIZE`, and an EK certificate is usually larger. `EKCertInjector` reads
the property from the TPM and writes at increasing offsets, on the transport the
provisioning step already holds — swtpm serves one client at a time. The
platform-hierarchy index carries the TCG EK Credential Profile attributes.
`ErrNVBufferMaxUnavailable` names a TPM that does not report the property.

Secure Boot enrollment happens at bundle generation — the enrolled keys are part
of the vTPM's initial state, not something applied later to a running instance.

## 5. Other errors

`ErrVTPMNotFound`, `ErrVTPMAlreadyExists`, `ErrProfileNotAssociated`,
`ErrProfileAssignmentFailed`, `ErrMissingHostname`, `ErrInvalidManifest`.

**`ErrMissingHostname` is required, not optional.** A bundle is bound to a
hostname; a bundle without one cannot be pre-assigned to a machine, which is
what `vtpm create` means by "pre-assigned".

`ErrProfileNotAssociated` / `ErrProfileAssignmentFailed` connect vTPM bundles to
device profiles ([`docs/device/`](../device/)) — a bundle can be pre-assigned to
a device profile so a machine picks up its vTPM at provisioning time.

## 6. Invariants

1. **A bundle is a filesystem artefact with three paths.** `GetBundlePath`,
   `GetTPMSocketPath` and `GetNVRAMPath` are separate RPCs because they are
   three different things: state directory, control socket, NVRAM store.
2. **The swtpm daemon has a lifecycle independent of the bundle.**
   `StartVTPM`, `StopVTPM`, `IsVTPMRunning`. A bundle can exist and not be
   running; quote, seal, unseal, PCR read and extend, and stop on a stopped
   bundle fail with `ErrVTPMNotRunning` (`FailedPrecondition`, REST 409).
3. **Export and import are streaming.** `ExportBundle` is a server stream and
   `ImportBundle` a client stream — a bundle carries NVRAM and state and does
   not fit a unary message.
4. **`ValidateBundle` is separate from `GetBundle`.** Fetching a bundle does not
   check it; validation is an explicit operation.
5. **A bundle is bound to a hostname.** See `ErrMissingHostname`.

## 7. Configuration

The TPM target is not a `vtpm:` key. `ResolveTPMTarget` (`target.go`) reads
the platform `tpm:` section (`App.TPMConfig`, `pkg/app/app.go`), the one
decision point for which TPM an operation reaches:

| `tpm:` setting | Target |
|---|---|
| `simulator: true` | the simulator; `device` is ignored |
| `device: auto` or empty | detected: swtpm socket first, then `/dev/tpmrm0`, then `/dev/tpm0` |
| `device: <path>.sock` | swtpm; the socket must exist |
| `device: /dev/...` | hardware; the character device must exist |

An explicit setting never falls back: a hardware path that is not usable is
`ErrHardwareTPMUnavailable`, a socket that is not there is
`ErrSwtpmSocketUnavailable`, and the type mismatches are the errors in §3.
`pkg/vtpm/config.go` holds the bundle settings
([configuration.md](configuration.md)).

## 8. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/vtpm/*_test.go`, `pkg/swtpm/*_test.go` | Target resolution, bundle generation, archive round-trip, EK certificate injection over a socket, swtpm daemon lifecycle |
| Integration | `test/integration/vtpm/` | Real swtpm processes |

`make test` runs both packages through `TEST_UNIT_PKGS` on a host with no swtpm
and no QEMU. The `pkg/swtpm` tests put a stand-in `swtpm` on `PATH`; the
`pkg/vtpm` EK certificate tests serve the in-memory TPM simulator on a unix
socket, so `InjectCertificate`, `ReadCertificate` and `VerifyCertificate` run
end to end. `test/integration/vtpm/` keeps what needs the real binaries:
`swtpm_setup` accepting several PCR banks, the daemon creating its socket,
EK certificate persistence across a restart, and the QEMU paths.

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide.

## 9. Observability

`IsVTPMRunning` is the liveness check. Bundle paths are the debugging entry
point: if a quote fails, confirm the socket path exists and is a socket before
looking at anything else.

**Sealed data and unseal results must not be logged.** `SealVTPM` and
`UnsealVTPM` carry secrets by definition.

## 10. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/attestation/`](../attestation/) — what consumes a vTPM quote
- [`docs/compute/`](../compute/) — `compute create --tpm` provisions one of these
- [`docs/tpm/`](../tpm/) — the physical TPM surface
- [`docs/device/`](../device/) — device profiles a bundle can be pre-assigned to
