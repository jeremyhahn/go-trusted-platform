# Linux IMA — Using It

> **Status: REFERENCE** · Scope: operator tasks for runtime file integrity measurement · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Task-oriented. Internals are in [engineering.md](engineering.md).

---

## What this is

Secure Boot proves what booted. IMA proves what ran afterwards.

With IMA on, the Linux kernel hashes every file it is told to care about at the
moment it is used — executed, mapped for execution, loaded as a module — writes
a line into an append-only log, and extends **PCR 10** in the TPM with that
line. Because a PCR can only ever be extended, editing the log after the fact
does not change the PCR, and the mismatch is how you find out.

Two settings decide what you get:

| Setting | What it does |
|---|---|
| **`policy`** | Which files get measured at all |
| **`appraise-mode`** | Whether a file that fails its signature check is *recorded* or *blocked* |

Measurement is detection. Appraisal is prevention. Most deployments start with
measurement only, and that is the right default.

---

## Prerequisites

1. **A kernel with IMA compiled in.** `grep CONFIG_IMA= /boot/config-$(uname -r)`
   should show `CONFIG_IMA=y`. The platform's own kernel has it.
2. **securityfs mounted** at `/sys/kernel/security`. Normally automatic;
   otherwise `mount -t securityfs securityfs /sys/kernel/security`.
3. **A TPM**, if you want PCR 10 to mean anything. Without one, measurements are
   still logged but there is nothing anchoring the log.
4. **Access to the installer config.** IMA is turned on at install time, not at
   runtime — see below for why.

---

## Task: turn IMA on

There is **no CLI verb**. IMA is a declarative property of the operating system,
set in the installer config under `os:`:

```yaml
os:
  ima:
    enabled: true
    policy: tcb
    hash-algorithm: sha256
    appraise-mode: "off"
    audit-enabled: true
```

Install (or reinstall) with that config. At install time the platform:

- installs `ima-evm-utils`, `keyutils` and `attr` (plus `audit` and
  `audit-openrc` when `audit-enabled: true`);
- writes `/etc/ima/ima-policy` generated from your `policy` choice;
- writes `/etc/local.d/ima.start`, which loads that policy at boot;
- pulls the TPM drivers and the IMA binaries into the initramfs;
- appends `ima=on ima_policy=… ima_hash=…` (and `ima_audit=1`,
  `ima_appraise=…`, `evm=fix` as configured) to the kernel command line.

**Note that `ima:` goes under `os:`, not at the top level of the config.** Older
documents in this folder show a top-level `ima:` block; that key is ignored.

### Why it is not a runtime switch

Those kernel parameters live inside the Unified Kernel Image, and the UKI is
signed with the Secure Boot DB key. That is deliberate: if IMA could be turned
off, or `ima_appraise=enforce` downgraded to `log`, by editing a file on disk,
then every measurement it produced would be worth nothing. Changing IMA
configuration means producing a new boot image and getting it signed.

---

## Task: choose a policy

| `policy` | Measures | Use when |
|---|---|---|
| `tcb` | Every executable, every library mapped for execution, kernel modules, firmware, kexec images | The default. Start here |
| `appraise_tcb` | The same, with `ima-sig` templates, **plus appraisal rules** requiring valid signatures on root-owned executables and modules | You have signed your binaries and want enforcement |
| `secure_boot` | kexec kernel, kexec initramfs, kernel modules only | Very low measurement volume; you care about the boot path and nothing else |
| `critical_data` | Critical kernel data via `CRITICAL_DATA` | Specialised |

Anything else falls through to a three-rule TCB subset.

Every generated policy ends with `dont_measure` rules for procfs, sysfs,
debugfs, tmpfs, ramfs and securityfs, which is what keeps the log from filling
with pseudo-filesystem noise.

### About `monitor-paths`

`os.ima.monitor-paths` is meant to add extra directories. **Do not rely on it
today.** The generator emits `obj_type=<path>` for each entry, and IMA's
`obj_type` matches an SELinux object type, not a filesystem path — IMA has no
path-prefix matcher. On a system without matching SELinux labels the rules match
nothing, and a strict kernel parser will reject the whole policy. This is
recorded as a defect in [architecture.md](architecture.md) §9.

Related: an older document in this folder lists forty "default monitor paths"
that are supposedly measured automatically. They are not — the function that
returns that list is never called. What you configure is what you get.

---

## Task: choose an appraise mode

| Mode | Behaviour |
|---|---|
| `off` | No appraisal. Measurement only. **The platform default** |
| `log` | Appraisal failures are logged; execution proceeds |
| `enforce` | Appraisal failures **block execution** |
| `fix` | Writes missing/invalid signatures as files are accessed. A provisioning mode |

The safe progression is `off` → `log` → read the logs for a week → `enforce`.

Going straight to `enforce` on a system whose binaries are not all signed
produces a machine where nothing runs, including the tools you would use to fix
it. `enforce` also needs the signing public key loaded into the kernel `.ima`
keyring; the boot script loads `/etc/ima/ima-public-key.pem` if it is present.

**Note:** `os.ima.signing-key-path` and `os.ima.public-key-path` are recorded in
the config but the installer does not consume them — the boot script loads a
hard-coded `/etc/ima/ima-public-key.pem` regardless. Put your key there.

---

## Task: confirm IMA is actually running

```bash
# The interfaces exist
ls /sys/kernel/security/ima/
# expect: ascii_runtime_measurements  binary_runtime_measurements  policy  violations

# The kernel booted with the parameters you expect
grep -o 'ima[^ ]*' /proc/cmdline
# expect: ima=on ima_policy=tcb ima_hash=sha256 …

# Measurements are accumulating
wc -l < /sys/kernel/security/ima/ascii_runtime_measurements

# Your custom policy loaded (not just the built-in one)
cat /sys/kernel/security/ima/policy
```

If the interfaces are missing, the kernel has no IMA support or securityfs is
not mounted. If they exist but the measurement count is tiny, the policy is
narrower than you think.

---

## Task: read the log

Each line is:

```
PCR TEMPLATE_HASH TEMPLATE_NAME ALG:FILE_HASH PATH [SIGNATURE]
10  a1b2…          ima-ng       sha256:def4…   /usr/bin/bash
```

```bash
# What ran recently
tail -20 /sys/kernel/security/ima/ascii_runtime_measurements

# Did a specific binary run?
grep '/usr/bin/bash' /sys/kernel/security/ima/ascii_runtime_measurements

# Which templates are in use?
cut -d' ' -f3 /sys/kernel/security/ima/ascii_runtime_measurements | sort | uniq -c

# Most-measured paths
cut -d' ' -f5 /sys/kernel/security/ima/ascii_runtime_measurements \
  | sort | uniq -c | sort -rn | head -20

# Keep a copy
cp /sys/kernel/security/ima/ascii_runtime_measurements /tmp/ima-events.txt
```

The log is an inventory of every binary this machine has executed. It is not
secret, but do not paste it into a ticket without thinking.

---

## Task: read PCR 10

```bash
cat /sys/class/tpm/tpm0/pcr-sha256/10

# Which banks does this TPM expose?
ls /sys/class/tpm/tpm0/ | grep '^pcr-'
```

`platformctl tpm eventlog` shows the **TCG firmware** event log — PCRs 0 to 7,
the boot path. It is a different log about different things. Do not use one to
answer a question about the other.

---

## Task: verify measurements from Go

There is no CLI. `pkg/ima` is the interface:

```go
reader := ima.NewReader()
verifier := ima.NewVerifier()

log, err := reader.ReadEventLog()
if err != nil {
    return err
}

// Replay the log into an expected PCR 10 and compare with the TPM
if err := verifier.VerifyPCR10AgainstTPM(log, ima.PCRBankSHA256); err != nil {
    // See the warning below before concluding anything
    return err
}
```

**Read this before acting on a mismatch.** The replay extends the template hash
exactly as it appears in the ASCII log. A TPM 2.0 extends each PCR bank with a
digest in *that bank's* algorithm, and the ASCII log publishes only one. So a
comparison against a bank whose algorithm differs from the log's template digest
will not reconcile — and the failure looks identical to tampering.

Treat `PCR value mismatch` as **inconclusive** until you have checked which bank
you asked for and which algorithm the log's template hashes are in. Full
explanation in [architecture.md](architecture.md) §7.

---

## Things that will bite you

**PCR 10 is different on every boot.** Files are measured in access order, and
that order changes. This is normal and expected.

**Never seal a LUKS key to PCR 10.** It will unseal exactly once and then never
again. Seal to PCRs 0, 7 and 9 — firmware, Secure Boot state, and kernel command
line. PCR 10 is for attestation, and for secrets sealed *after* boot
measurement has settled.

**IMA state cannot be reset without a reboot.** A PCR can be extended, never
lowered. If you want a clean log and a clean PCR 10, reboot.

**Rising violations mean writers, not attackers.** A climbing
`/sys/kernel/security/ima/violations` usually means Time-of-Measure /
Time-of-Use conditions — a file being written while it is open for execution.
Investigate the file, not the intruder, first.

**An allowlist built on this machine attests this machine.**
`BuildAllowlistFromLog` records whatever was running when you ran it. If the
machine was already compromised, you have just written down the compromise as
"expected". Build allowlists from a known-good reference in a controlled
environment.

**IMA configuration failure at install time is a warning, not an error.** The
installer logs `Failed to configure IMA, continuing without it` and finishes the
install. A node can therefore come up looking healthy with no IMA at all. Check
`/sys/kernel/security/ima/` on a freshly installed node before assuming it is
measuring.

---

## Troubleshooting

**`/sys/kernel/security/ima/`: no such file or directory**
Kernel without `CONFIG_IMA`, securityfs not mounted, or `ima=on` missing from
the command line. Check all three, in that order.

**The policy file is empty**
The built-in `ima_policy=` policy is active but your custom policy did not load.
Check that `/etc/ima/ima-policy` exists and try loading it by hand:

```bash
cat /etc/ima/ima-policy > /sys/kernel/security/ima/policy
dmesg | tail -20
```

`dmesg` will name the offending rule if the parser rejected one. The
`obj_type=` defect above is the most likely culprit if you set `monitor-paths`.

**`PCR value mismatch`**
Check the bank first (see the warning above). Then check that the log has not
been truncated. Only after both should you treat it as an integrity finding.

**`IMA: HASH_NOT_AVAILABLE` or `IMA: INTEGRITY_UNKNOWN` in the logs**
Appraisal is on and a file has no valid signature. In `log` mode this is
informational; in `enforce` mode that file did not run. Either sign the file
(`evmctl ima_sign --key /etc/ima/signing-key.pem /path/to/file`) or drop back to
`log` while you work through the set.

**The log is enormous and the machine feels slow**
The policy is broader than it needs to be. Move to `secure_boot`, or add
`dont_measure` rules for the noisy filesystems. Every generated policy already
excludes procfs, sysfs, debugfs, tmpfs, ramfs and securityfs.

**`TPM device not available`**
`ls /sys/class/tpm/tpm0/`. If it is absent, load the drivers
(`modprobe tpm_tis`, `modprobe tpm_crb`) or check that the TPM is enabled in
firmware. If the directory exists but the PCR file does not, the bank you asked
for is not allocated on this TPM.

**A verification helper returns nothing at all**
Several helpers depend on fields the ASCII log does not carry.
`DetectMeasurementGaps` always returns nil (no timestamps);
`Statistics.FilesByAction` is always empty (no action field);
`VerificationResult.UnexpectedFiles` is always empty. These are known gaps, not
your usage — [engineering.md](engineering.md) §2.5.

---

## What is not here

- **No `platformctl ima` command.** Older documents in this folder show
  `ima status`, `ima verify`, `ima export` and `ima policy generate`. None of
  them exist.
- **No `platformctl tpm pcr read`.** Also shown in older documents; also does
  not exist. Use `cat /sys/class/tpm/tpm0/pcr-sha256/10`.
- **No REST, gRPC, QUIC or MCP surface.** A control plane cannot currently ask a
  node for its measurement log over any transport. See [api.md](api.md).
- **No attestation integration yet.** PCR 10 is not in the host manifest and
  nothing in the platform consumes `pkg/ima`. Remote attestation over IMA
  measurements is PLANNED — [architecture.md](architecture.md) §8.
- **No real signature verification.** `VerifySignature` checks that a signature
  is present and long enough. It does not verify it. Use `evmctl` for that until
  the implementation lands.

---

## Where to go next

- [architecture.md](architecture.md) — the trust model, and exactly what a PCR
  10 value does and does not prove
- [engineering.md](engineering.md) — every exported function, and every field
  that is declared but never populated
- [api.md](api.md) — the transport gaps, recorded rather than hidden
- [`docs/firmware/user.md`](../firmware/user.md) — Secure Boot, the layer below
- [`docs/attestation/`](../attestation/) — proving any of this to somebody else
- [`docs/installer/`](../installer/) — where `os.ima.*` is applied
