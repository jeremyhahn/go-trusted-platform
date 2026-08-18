# Linux IMA — Architecture

> **Status: NORMATIVE** · Scope: `pkg/ima/`, plus the IMA provisioning path in `pkg/installer/` and `pkg/iso/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> **Verification scope.** Package layout, exported surface, error set, config
> keys, kernel parameters, generated policy and the transport matrix were read
> out of the code on 2026-08-18. Where the legacy files in this folder disagree
> with the code, the code wins and the correction is recorded in §9.

---

## 1. The problem

Secure Boot ends the moment the kernel starts. It proves *what booted*; it says
nothing about the binary a process executed forty minutes later, or the
configuration file something rewrote in between. On a platform whose whole
premise is "this node can prove what it is", that is a gap wide enough to drive
a rootkit through.

The Linux Integrity Measurement Architecture closes it in the kernel: on file
access — execute, mmap-for-execute, module load, kernel image load — the kernel
hashes the file, appends an entry to an append-only log, and extends **PCR 10**
with that entry. The log tells you *what* was measured; PCR 10, because a TPM
PCR can only be extended and never set, tells you the log was not edited after
the fact.

The platform's job is threefold, and only the first two are in this feature's
scope:

1. **Turn IMA on correctly** — kernel parameters, a policy, the tooling to load
   it — and do it from inside the signed boot image, so the configuration cannot
   be changed without re-signing.
2. **Read and verify** the resulting log and PCR from userspace.
3. Feed the result into remote attestation. That is
   [`docs/attestation/`](../attestation/), and today it does **not** consume this
   feature — see §8.

## 2. The shape chosen

Two halves that do not talk to each other:

| Half | Where | What it does |
|---|---|---|
| **Provisioning** | `pkg/installer` (`types.go`, `installer.go`, `alpine.go`), `pkg/iso/prefetch.go` | At install time: adds `ima-evm-utils`, `keyutils`, `attr`; writes `/etc/ima/ima-policy`, `/etc/ima/ima.conf` and the `/etc/local.d/ima.start` boot script; adds TPM drivers and IMA binaries to the initramfs; appends `ima=on`, `ima_policy=`, `ima_hash=`, and optionally `ima_audit=1`, `ima_appraise=`, `evm=fix` to the kernel command line **inside the UKI** |
| **Read and verify** | `pkg/ima` | At runtime: parses `ascii_runtime_measurements` and `policy` from securityfs, replays the log into an expected PCR 10, reads the actual PCR 10 from TPM sysfs, and compares |

The split is deliberate. Provisioning happens once, as root, on a machine being
installed. Reading happens repeatedly, on a running machine, and needs nothing
but read access to two pseudo-filesystems — no TPM library, no privileged
handle, no daemon.

**`pkg/ima` is a pure reader.** It never writes `/sys/kernel/security/ima/policy`
and never extends a PCR. Everything it produces is derived from files the kernel
publishes.

### The key placement decision

Reading a PCR through `/sys/class/tpm/tpm0/pcr-<bank>/<index>` instead of
through a TPM 2.0 command session is what keeps this package free of any TPM
dependency, any device handle, and any lock contention with the platform's own
TPM user. The cost is that a sysfs PCR read is **not** an attested value — it is
what the kernel says the PCR is. Producing a signed quote over PCR 10 is
[`docs/attestation/`](../attestation/)'s job, and it is a different trust
statement (see §6).

## 3. Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Read PCR 10 through a TPM 2.0 session** | Would drag a TPM transport, a device handle and a resource-manager dependency into a package whose only job is parsing text. It would also contend with the platform's own TPM user. sysfs gives the same number with no coupling — and when a *signed* value is needed, the attestation feature's quote path is the right instrument, not this one. |
| **Parse `binary_runtime_measurements` instead of the ASCII log** | The binary log is the canonical, per-bank-correct form, but parsing it means implementing the TCG event-log template formats. The ASCII log is one line per event and trivially parseable. The price is real and is stated in §7: the ASCII log carries one template digest, so a per-bank replay cannot be reconstructed from it. Reading the binary log is **PLANNED**. |
| **Fail parsing on the first malformed line** | A measurement log on a running system can be truncated mid-write, and IMA templates evolve. `ParseEventLog` counts malformed lines into `EventLog.ParseErrors` and continues, so one bad line does not hide ten thousand good ones. A caller that wants strictness checks `ParseErrors`. |
| **Treat a file missing from the allowlist as a violation** | An allowlist built from one boot will never cover the next boot's full measurement set. Defaulting "not in the allowlist" to *fail* would make the verifier useless the first time anyone used it. The verifier only fails a file that is in the allowlist with a different hash. The consequence — `UnexpectedFiles` is never populated — is a real gap, recorded in §9. |
| **Write the IMA policy from the running platform daemon** | The policy is what decides what gets measured. If it can be replaced at runtime by anything short of a re-signed boot image, the measurements it produces prove nothing. The policy ships in `/etc/ima/ima-policy` and is loaded by a boot script whose kernel parameters live inside the signed UKI. |
| **Expose IMA over the platform's transports** | Not rejected — **not built**. `pkg/ima` has no service, no CLI verb and no route. See §8, and [api.md](api.md). |
| **A dedicated IMA config section at the top level of the platform config** | IMA is an operating-system property, configured where the rest of the OS is: `os.ima.*` in the installer config (`installer.OSConfig.IMA`). The legacy documents in this folder show a top-level `ima:` block, which does not exist — §9. |

## 4. Component boundaries

| Piece | Package / path | Owner |
|---|---|---|
| IMA event-log reading and parsing; policy reading and parsing; statistics | `pkg/ima/reader.go`, `types.go` | this repo |
| Measurement verification, allowlists, PCR 10 replay | `pkg/ima/verifier.go` | this repo |
| PCR 10 read from TPM sysfs, bank discovery | `pkg/ima/tpm_integration.go` | this repo |
| IMA configuration schema and defaults | `pkg/installer/types.go` (`IMAConfig`, `DefaultIMAMonitorPaths`) — [`docs/installer/`](../installer/) | this repo, separate feature |
| Kernel command-line parameters, inside the signed UKI | `pkg/installer/installer.go` — [`docs/firmware/`](../firmware/) for how the UKI is signed | this repo, separate feature |
| Policy generation, package installation, boot script, dracut wiring | `pkg/installer/alpine.go` | this repo, separate feature |
| ISO package staging | `pkg/iso/prefetch.go` (`Config.IMAEnabled`, `Config.IMAAuditEnabled`) | this repo, separate feature |
| **The measurement itself** | the Linux kernel's IMA subsystem | **not this repo, not any repo we own** |
| **The TPM** | hardware, or swtpm — reached here only through sysfs | **not this repo** |
| **Quoting PCR 10 and evaluating it against policy** | `pkg/attestation/` — [`docs/attestation/`](../attestation/) | this repo, separate feature (**not wired to this one today** — §8) |
| **What signs the boot image that carries the IMA parameters** | `pkg/uefi`, `pkg/authenticode` — [`docs/firmware/`](../firmware/) | this repo, adjacent feature |

`pkg/ima` imports **nothing** from this repository — only the Go standard
library. And nothing in this repository imports `pkg/ima` (grepped 2026-08-18).
It is a self-contained library with a complete unit test suite and no production
caller. That is a fact about today, not a design goal; see §8.

## 5. Data flow

### 5.1 Install time — turning IMA on

```
os.ima.enabled: true
        │
        ├─▶ packages: ima-evm-utils, keyutils, attr
        │              (+ audit, audit-openrc when audit-enabled)
        │
        ├─▶ /etc/ima/ima-policy      generated from os.ima.policy
        ├─▶ /etc/ima/ima.conf        a plain-text record of the settings
        ├─▶ /etc/local.d/ima.start   loads the policy at boot, loads the
        │                            public key into the .ima keyring
        │
        ├─▶ dracut: add_drivers tpm tpm_tis tpm_crb
        │           install_items /usr/bin/evmctl /usr/bin/keyctl
        │           install_items /etc/ima/ima-policy
        │
        └─▶ kernel cmdline, EMBEDDED IN THE SIGNED UKI:
              ima=on
              ima_policy=<tcb|appraise_tcb|secure_boot|critical_data>
              ima_hash=<sha256|sha1|sha512>
              ima_audit=1              (when audit-enabled)
              ima_appraise=<log|enforce|fix>   (when set and not "off")
              evm=fix                  (when evm: true)
```

The last arrow is the one that matters for trust. Those parameters are inside
the UKI, and the UKI is Authenticode-signed with the Secure Boot DB key
([`docs/firmware/`](../firmware/)). Turning IMA off, or downgrading
`ima_appraise=enforce` to `log`, means producing a different boot image and
getting it signed.

### 5.2 Boot time — the kernel does the work

```
kernel boots with ima=on ima_policy=tcb
        │
        ├─▶ built-in policy active immediately
        │
   /etc/local.d/ima.start
        ├─▶ cat /etc/ima/ima-policy > /sys/kernel/security/ima/policy
        └─▶ keyctl padd asymmetric "" %:.ima < /etc/ima/ima-public-key.pem
        │
        ▼
   every matching file access:
        hash the file ──▶ append a line to ascii_runtime_measurements
                     └──▶ extend PCR 10 with the template hash
```

### 5.3 Runtime — reading and verifying

```
/sys/kernel/security/ima/ascii_runtime_measurements
        │  Reader.ReadEventLog / ParseEventLog / ParseEvent
        ▼
   *EventLog { Events, TotalCount, UniqueFiles, ParseErrors }
        │
        ├──▶ Reader.GetStatistics        → per-algorithm, per-template counts, top paths
        ├──▶ Verifier.VerifyEventLog     → allowlist comparison
        └──▶ Verifier.ComputePCR10(log, bank)
                     │  pcr = 0…0 ; for each PCR-10 event: pcr = H(pcr || TemplateHash)
                     ▼
             expected PCR 10 ──┐
                               ├── Verifier.VerifyPCR10AgainstTPM → match / ErrPCRMismatch
   /sys/class/tpm/tpm0/pcr-<bank>/10 ──┘
        │  Verifier.ReadPCR10FromTPM
```

Nothing here is persisted. Every call re-reads the kernel's files. There is no
store, no cache, no schema and therefore no migration rules.

## 6. Trust boundaries

**IMA policy and PCR 10 are the trust boundary for everything that happens
after the kernel starts** — the exact counterpart to the Secure Boot key
hierarchy, which is the boundary for everything before it
([`docs/firmware/architecture.md`](../firmware/architecture.md) §6). Stated
precisely:

1. **The policy defines the claim.** A measurement log proves that the files
   IMA was *told* to measure had certain hashes. It proves nothing about files
   the policy excluded. `ima_policy=secure_boot` measures only kexec images and
   modules; `ima_policy=tcb` measures every executable and library. Two nodes
   with identical PCR 10 values and different policies are not making the same
   statement. **A verifier that does not know the policy cannot interpret the
   PCR.**
2. **The policy is protected by the boot image, not by file permissions.** The
   kernel parameters that select the built-in policy live inside the signed UKI.
   `/etc/ima/ima-policy` itself is a root-writable file on the encrypted root —
   its integrity comes from the disk encryption and from the fact that IMA
   policy is *append-only* once loaded: the kernel accepts additional rules but
   will not let you remove the ones already in force.
3. **PCR 10 is append-only and resets at reboot.** Extension is
   `PCR = H(PCR || measurement)` — a value can never be lowered or set. That is
   what makes the log tamper-evident: editing the log does not change the PCR,
   and the mismatch is the detection. It also means PCR 10 is different on every
   boot, in file-access order.
4. **Never seal to PCR 10.** Sealing a LUKS key to PCR 10 produces a key that
   unseals only if the machine re-measures the exact same files in the exact
   same order — which it will not. Seal to PCRs 0, 7 and 9. PCR 10 is for
   attestation, and for post-boot application secrets sealed after measurement
   has settled.
5. **A sysfs PCR read is not attestation.** `ReadPCR10FromTPM` returns what the
   kernel reports. On a compromised kernel that number is whatever the attacker
   wants. Verifying the log against sysfs PCR 10 is a **local self-check** — it
   detects log tampering by an unprivileged process, not a compromised kernel.
   A statement a *remote* party can rely on requires a TPM quote signed by an
   attestation key: [`docs/attestation/`](../attestation/).
6. **Appraisal is enforcement; measurement is not.** With
   `ima_appraise=enforce`, a file whose signature does not verify is **not
   executed** — that is a runtime control, and it is the only setting here that
   can stop an attack rather than record it. `log` records and permits; `off`
   does neither. Moving a fleet to `enforce` before every binary is signed
   bricks userspace, which is why the platform defaults to `off`.
7. **The `.ima` keyring is the appraisal trust root.** `ima_appraise` verifies
   `security.ima` xattr signatures against keys loaded into the kernel `.ima`
   keyring. Anything that can add a key to that keyring can authorise any
   binary. The boot script loads `/etc/ima/ima-public-key.pem`; on a kernel with
   lockdown enabled the keyring is further restricted to keys chaining to the
   builtin/secondary keyrings.
8. **EVM protects the metadata.** Without EVM, an attacker who can write
   extended attributes can move a valid `security.ima` signature onto a
   different file. `evm: true` adds an HMAC or signature over the file's
   metadata. The platform sets `evm=fix` when enabled — a *provisioning* mode
   that writes missing EVM values, not an enforcing one.
9. **Allowlist provenance.** `BuildAllowlistFromLog` builds the expected-hash
   set from a log — which means it trusts whatever was running when it was
   built. An allowlist built on a compromised machine attests the compromise.
   Build allowlists from a known-good reference, in a controlled environment.

## 7. Known limits of the PCR 10 replay

Stated here rather than buried in engineering.md, because getting it wrong
produces a false negative on a security check.

`ComputePCR10(log, hashAlg)` extends `event.TemplateHash` **exactly as parsed
from the ASCII log**, using the hash function named by `hashAlg`. It does not
recompute a per-bank template digest, because the ASCII log does not carry the
inputs needed to do so.

On a TPM 2.0 with multiple PCR banks, the kernel extends each bank with a
template hash computed in **that bank's** algorithm. The ASCII log publishes one
template digest. So a replay reconciles with a bank only when the log's template
digest is in that bank's algorithm; against any other bank the comparison
produces `ErrPCRMismatch` for a reason that has nothing to do with tampering.

Read a mismatch as "inconclusive until you have checked bank and algorithm",
not as "compromised". Reconstructing a per-bank replay needs
`binary_runtime_measurements` — **PLANNED**, §3.

Two further limits, both consequences of the ASCII format:

- **The ASCII log has no timestamps.** `Event.Timestamp` is never populated, so
  `DetectMeasurementGaps` always returns nil.
- **The ASCII log has no UID or action field.** `Event.UID` and
  `Event.EventType` are never populated, so `Statistics.FilesByAction` is always
  empty.

## 8. What this feature deliberately does not do

- **It does not measure anything.** The Linux kernel does. This is a reader.
- **It does not load, write or modify the IMA policy at runtime.** The install
  path writes the policy file; the boot script loads it.
- **It does not extend PCRs.** It replays what the log implies and compares.
- **It does not produce a TPM quote or evaluate attestation policy.**
  [`docs/attestation/`](../attestation/) does.
- **It does not verify IMA file signatures.** `VerifySignature` checks that a
  signature is present and at least nine bytes long, then returns nil. Parsing
  the IMA signature header and verifying it against a public key is **PLANNED**
  — the code says so in comments, and this document says so plainly rather than
  letting the method name imply otherwise.
- **It does not verify template hashes.** `verifyTemplateHash` checks only that
  the digest length is one of SHA-1/256/384/512. Recomputing the template hash
  requires implementing each template's serialisation. **PLANNED.**
- **It has no CLI surface.** No `platformctl ima` command group exists.
- **It has no API surface on any transport.** Not REST, not gRPC, not Unix, not
  QUIC, not MCP, not embedded. See [api.md](api.md).
- **It is not wired into attestation.** `pkg/attestation/manifest` has no IMA
  field, and no package in this repository imports `pkg/ima`. The library is
  complete and tested; the integration is **PLANNED**.
- **It does not support the binary measurement log.** `EventPaths.BinaryRuntime`
  names the path; nothing reads it. **PLANNED.**

## 9. Where the code contradicts the legacy documents

| Legacy claim | Reality in code |
|---|---|
| `README.md`, `configuration.md`: IMA is configured under a top-level `ima:` section | It is `os.ima.*` — `installer.OSConfig.IMA`, an `*IMAConfig` under the installer config's `os:` block. A top-level `ima:` key is ignored. |
| `configuration.md`: "When IMA is enabled, the following paths are monitored by default" followed by a long list | `installer.DefaultIMAMonitorPaths()` exists and is unit-tested, but **nothing calls it**. The generated policy contains only the built-in rules for the selected policy type plus whatever is in `os.ima.monitor-paths`. With no `monitor-paths`, none of those paths gets a rule. |
| `api-reference.md`: `NewVerifier` accepts `WithTPMSysPath(path string)` | No such option. The two `VerifierOption`s are `WithAllowlist(map[string][]byte)` and `WithReader(*Reader)`. Custom TPM paths are passed per call: `ReadPCR10FromTPMWithPath`, `VerifyPCR10AgainstTPMWithPath`, `IsPCR10AvailableWithPath`, `IsTPMAvailableWithPath`, `GetAvailablePCRBanksWithPath`. |
| `api-reference.md`: `GetStatus` returns `PolicyType`, `AppraiseMode`, `EVMEnabled`, `SigningKeyLoaded`, `PCR10Value`, `TPMAvailable`, `AvailablePCRBanks` | Those fields exist on `Status` and `GetStatus` **never sets any of them**. It sets `Available`, `Enabled`, `PolicyLoaded`, `HashAlgorithm`, `MeasurementCount` and `ViolationCount` only. The rest are always zero-valued. |
| `api-reference.md`: `VerificationResult.UnexpectedFiles` = "files measured but not in allowlist" | Never populated. `verifyAgainstAllowlist` returns nil for a path absent from the allowlist, and nothing appends to `UnexpectedFiles`. |
| `README.md`: `EventLog.ViolationCount` reflects policy violations | `ParseEventLog` never sets it; it is always 0. The real count comes from `Reader.ReadViolations()`, which reads `/sys/kernel/security/ima/violations`. Consequently `Status.ViolationCount`, which is copied from the log, is also always 0. |
| `troubleshooting.md`: `platformctl ima policy generate --output /etc/ima/ima-policy` | **No such command.** There is no `ima` command group at all. |
| `tpm-integration.md`: `platformctl ima verify`, `platformctl ima status`, `platformctl ima export --format json` | **No such commands.** |
| `tpm-integration.md`: `platformctl tpm pcr read --pcr 10 --bank sha256` | **No such verb.** `platformctl tpm` has `extend`, `policy`, `eventlog`, `nvram`, `seal`, `unseal` and others, but no `pcr` subcommand. Read PCR 10 with `cat /sys/class/tpm/tpm0/pcr-sha256/10`. |
| `tpm-integration.md`: the host manifest includes IMA data | `pkg/attestation/manifest` has no IMA field. Nothing in the repository imports `pkg/ima`. |

One defect found in the code itself, recorded rather than silently documented
around:

1. **Custom monitor paths generate a rule IMA cannot use.** For each entry in
   `os.ima.monitor-paths` the generator emits
   `measure func=FILE_CHECK mask=MAY_READ uid=0 pcr=10 obj_type=<path>`.
   In IMA policy syntax `obj_type=` matches an **SELinux object type**, not a
   filesystem path — IMA has no path-prefix matcher. On a system without SELinux
   labels matching those strings the rules match nothing; a strict kernel parser
   rejects them and the whole policy load fails. Raised as an owner question.

For the avoidance of doubt on a related point that *is* correct: the OpenRC
`local` service, which runs `/etc/local.d/ima.start`, **is** added to the default
runlevel by the Alpine installer (`defaultServices` in
`pkg/installer/alpine.go`), so the generated policy does get loaded at boot.

## 10. Related

- [engineering.md](engineering.md) — exported surface, invariants, errors, tests
- [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/firmware/architecture.md`](../firmware/architecture.md) — Secure Boot,
  the UKI that carries the IMA kernel parameters, and module signing
- [`docs/attestation/`](../attestation/) — quotes and policy evaluation, the
  consumer this feature is built for and not yet wired to
- [`docs/installer/`](../installer/) — where `os.ima.*` is consumed
- [`docs/daemon/api.md`](../daemon/api.md) — the transport model this feature
  is absent from
- Legacy notes retained in this folder: [README.md](README.md),
  [policies.md](policies.md), [configuration.md](configuration.md),
  [tpm-integration.md](tpm-integration.md), [api-reference.md](api-reference.md),
  [troubleshooting.md](troubleshooting.md)
