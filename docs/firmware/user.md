# Firmware Trust — Using It

> **Status: REFERENCE** · Scope: operator tasks for UEFI Secure Boot, UKIs and kernel module signing · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Task-oriented. Internals are in [engineering.md](engineering.md).

---

## What this is

UEFI Secure Boot means the firmware refuses to run a boot image that is not
signed by a key you enrolled. This platform gives you the whole chain: it makes
the keys, packs the kernel and initramfs into one signed file, signs it, and —
only when it can prove doing so is safe — enrolls the keys into the firmware.

The one thing to internalise before you start:

> **Enrolling a Platform Key is irreversible from software.** Once PK is in
> firmware, the machine boots only what the enrolled signature database accepts.
> If that turns out to be nothing, you get the machine back by walking to it —
> or by opening a BMC console — and clearing the keys in the firmware setup
> menu. There is no `platformctl secure-boot rollback`, and there never will be.

Everything in the tooling is arranged around making that outcome impossible to
reach by accident.

---

## Prerequisites

1. **The node boots in UEFI mode**, not legacy BIOS/CSM. `/sys/firmware/efi`
   must exist.
2. **efivarfs is mounted.** Normally automatic; if not,
   `mount -t efivarfs efivarfs /sys/firmware/efi/efivars`.
3. **You can reach the firmware setup menu** — physically, or through the BMC.
   This is your recovery path. Do not start without it.
4. **You have a signed UKI on the ESP.** By default the platform installer puts
   it at `/boot/efi/EFI/BOOT/BOOTX64.EFI`.
5. **You have PK, KEK and DB certificates.** By default at
   `/etc/trusted-platform/secure-boot/{PK,KEK,DB}.crt`.

---

## The three things that are not the same thing

| Thing | Signed by | Checked by | Checked when |
|---|---|---|---|
| **The boot image (UKI)** | the DB key | firmware | at boot |
| **Kernel modules** | the module-signing key | the kernel's own keyring | at `insmod` |
| **Files on disk at runtime** | (measured, not signed) | IMA, into PCR 10 | at every file access — see [`docs/ima/user.md`](../ima/user.md) |

Different keys, different enforcement points, different failure modes. Fixing a
module-loading problem by touching Secure Boot keys is a common and expensive
mistake.

---

## Task: find out where you stand

Always start here. It writes nothing.

```bash
platformctl secure-boot status
```

You get four facts and four databases:

- **`SetupMode: enabled`** — the firmware has no active Platform Key. This is
  the *only* state in which keys can be enrolled.
- **`SecureBoot: enabled`** — the firmware is currently enforcing.
- **`UserMode: enabled`** — a PK is enrolled and the firmware has left Setup
  Mode.
- **`PK` / `KEK` / `db` / `dbx`** — one line each: how many certificates, how
  many hashes, and the subject of each certificate. `absent` means the variable
  is not there at all.

`platformctl secure-boot status -o json` gives you the same thing in a shape you
can diff across a fleet.

The four states you can be in:

| `SetupMode` | `SecureBoot` | What it means |
|---|---|---|
| enabled | disabled | Blank slate. You can enroll. |
| disabled | enabled | Enforcing. Nothing to do — enrollment would be refused anyway. |
| disabled | disabled | Keys enrolled but enforcement off in firmware setup. Turn it on in the setup menu. |
| enabled | enabled | Should not happen. Investigate before writing anything. |

---

## Task: enroll Secure Boot keys on a bare-metal node

### Step 1 — put the firmware in Setup Mode

In the firmware setup menu, clear or delete the Secure Boot keys. The exact
wording varies by vendor: "Restore Factory Keys" is usually the wrong option —
you want "Clear Secure Boot Keys", "Delete all Secure Boot variables", or
switching the Secure Boot mode from *Standard* to *Custom* and then clearing.

Confirm from the OS:

```bash
platformctl secure-boot status     # expect SetupMode: enabled
```

### Step 2 — rehearse

```bash
platformctl secure-boot enroll
```

This runs **every** guard the commit runs and writes nothing:

- efivarfs present and readable
- firmware in Setup Mode
- `PK.crt`, `KEK.crt`, `DB.crt` load and parse
- the signed UKI verifies, **and** its embedded certificate is exactly the DB
  certificate about to be enrolled

It prints `DRY RUN — no variables were written`, the UKI path, and the three
certificate subjects. **A dry run that passes is a commit that will work.** If
it fails, fix that before going further; see Troubleshooting below.

### Step 3 — commit

```bash
platformctl secure-boot enroll --commit
```

Keys are written `db` → `KEK` → `PK`, PK last. That order is the safety
property: writing PK is what arms enforcement, so if anything fails earlier the
node is still bootable.

### Step 4 — confirm and reboot

```bash
platformctl secure-boot status     # expect SetupMode: disabled, PK/KEK/db present
reboot
```

Secure Boot enforcement is active on the next boot.

### The one-command form

`platformctl secure-boot enforce` is `status` + `enroll` in one gate: if the
node is already enforcing it reports success and writes nothing; otherwise it
runs the whole pipeline and, after a commit, re-reads the firmware to confirm a
Platform Key is actually present.

```bash
platformctl secure-boot enforce            # dry run
platformctl secure-boot enforce --commit
```

Use `enforce` when you are driving a fleet and want the "make it so, or tell me
why not" shape. Use `enroll` when you are working on one machine and want the
steps separated.

### Rehearsing without a machine to risk

Both verbs accept `--efivars`, pointing at a directory laid out like efivarfs.
That is how you exercise the guards — including the UKI verification — with no
firmware involved:

```bash
platformctl secure-boot enroll \
    --efivars ./testdata/efivars \
    --uki ./out/BOOTX64.EFI \
    --keys-dir ./out/secure-boot-keys
```

---

## Task: build and sign a boot image by hand

The installer does this for you. Do it by hand when you are debugging, or
producing an image out of band.

```bash
# 1. Build the UKI (unsigned)
platformctl install uki \
    --kernel /boot/vmlinuz-6.6.64-0-lts \
    --initramfs /boot/initramfs-6.6.64-0-lts \
    --cmdline "root=/dev/mapper/cryptroot ro quiet" \
    --output ./BOOTX64.EFI.unsigned

# 2. Sign it with the DB key
platformctl authenticode sign \
    --key <install-dir>/secure-boot/DB.key \
    --cert <install-dir>/secure-boot/DB.crt \
    --input ./BOOTX64.EFI.unsigned \
    --output ./BOOTX64.EFI

# 3. Put it on the ESP
install -m 0755 ./BOOTX64.EFI /boot/efi/EFI/BOOT/BOOTX64.EFI
```

Three things people get wrong:

**The kernel command line is inside the signed file.** That is the point of a
UKI — an attacker cannot append `init=/bin/sh` at the boot menu because there is
no boot menu entry to edit. It also means changing the command line requires
rebuilding and re-signing.

**`--stub` is not architecture-aware.** Both UKI builders read
`/usr/lib/systemd/boot/efi/linuxx64.efi.stub` regardless of what
`SetArchitecture` was told. On aarch64 you must pass `--stub` explicitly.

**Do not verify with `platformctl authenticode verify` and believe it.** See the
warning below.

---

## Task: survive a kernel update

A kernel package upgrade leaves the old UKI in place. On a node that enforces
Secure Boot, booting the new kernel requires a new UKI signed by the same DB
key.

```bash
platformctl install uki-rebuild --kver 6.6.67-0-lts
```

Normally this runs automatically from the kernel-update hook. What it does:
rebuild the UKI with the persisted command line, resolve the *existing* DB
signer — locally from a `file://` key, or by hash-signing against the
control-plane KMS — sign, **verify**, spot-check the new modules for signature
trailers, and only then swap atomically. The previous image is kept as
`BOOTX64.EFI.prev`.

**It will never generate a new DB key.** A fresh key is not in your firmware's
`db`, so a UKI signed with it would not boot. If the signer cannot be resolved
the command fails, the swap is aborted, and the working UKI stays where it is —
the old kernel still boots. That non-zero exit is the correct outcome, not a bug
to work around.

---

## Task: provision the kernel module-signing key

This is a **different key** from your Secure Boot keys, and a one-time,
per-platform operation.

```bash
platformctl iso module-signing-key
```

By default it writes `$HOME/.trusted-platform/secure-boot/module-signing-key.pem`
(mode `0600`) and prints the path, subject, expiry and SHA-256 fingerprint. The
FIPS kernel build embeds the certificate into the kernel's built-in trusted
keyring, so every module signed with this key loads on every kernel built from
it.

Rules, in order of how much they will cost you:

1. **Back it up.** Regenerating it orphans every module signed with the old key
   on every kernel already built. The command refuses to overwrite an existing
   key without `--force` precisely because of this.
2. **Keep it out of the repository and out of any Docker build context.** The
   builder mounts it read-only.
3. **Treat it as root-equivalent.** Anyone holding it can sign a kernel module
   that loads under `CONFIG_MODULE_SIG_FORCE`.

There is no runtime opt-out for module signature enforcement — it is a
compile-time kernel decision, and there is no kernel parameter that disables it.

---

## Troubleshooting

**"firmware not in setup mode"**
The firmware still has an active Platform Key. Clear the Secure Boot keys in the
firmware setup menu. This is the intended guard, not a failure — it exists so a
stray command cannot half-enroll a machine.

**"efivarfs not available"**
Either the node booted in legacy BIOS/CSM mode, or efivarfs is not mounted, or
you are in a container without `/sys` passthrough. Check `/sys/firmware/efi`
exists at all; if it does not, this is a firmware boot-mode problem, not a
platform problem.

**"signed uki verification failed"**
The image at `--uki` is not signed by the certificate at `--db-cert`. Three
usual causes, in order of likelihood: you rebuilt the UKI and forgot to sign it;
you signed it with a different DB key than the one whose certificate you are
enrolling; the UKI path is wrong and you are pointing at a stale or vendor
image. This gate is what stops you creating an unbootable machine — do not try
to route around it.

**"secure-boot: signed UKI not found at /boot/efi/EFI/BOOT/BOOTX64.EFI"**
Either the ESP is not mounted, or your UKI lives somewhere else. Pass `--uki`.

**"failed to load PK certificate from …"**
The certificate is missing, is not PEM, or is not a `CERTIFICATE` block. Check
`--keys-dir`, or pass `--pk-cert` / `--kek-cert` / `--db-cert` explicitly.

**`platformctl authenticode verify` fails with "certificate is required"**
Pass `--cert`. The help text says it is optional; it is not — the command cannot
construct its verifier without one. Recorded as a defect in
[cli.md](cli.md) §3.2.

**`authenticode verify` says OK but the firmware still refuses the image**
Expected, unfortunately. That verb checks the signature against the certificate
*embedded in the file*; it does not check that the file was signed by the
certificate you passed in `--cert`, and it builds no trust chain. The check that
matters is the one `platformctl secure-boot enroll` runs. Use the dry run as
your verification step.

**The node enrolled successfully but still shows `SecureBoot: disabled`**
Enforcement activates on the **next boot**. If it is still disabled after a
reboot, check the firmware setup menu — some vendors keep a separate
"Secure Boot: Enabled/Disabled" switch independent of key presence.

**A kernel module will not load after a kernel update**
This is the module keyring, not Secure Boot. The module must be signed by a key
in the kernel's trusted keyring. A kernel built with an *ephemeral* per-build
key (the development default, `MODULE_SIGNING_KEY` unset) only loads modules
from that same build. Production kernels must be built with the stable key.

**A `.ko.xz` module cannot be signed**
It cannot, today. There is no pure-Go xz codec in the module graph and an
installer-environment signer cannot shell out to `xz`. The file is left
untouched rather than silently skipped. `.ko.gz` and `.ko.zst` work.

**The UKI built but the machine hangs with no output**
Almost always a missing or wrong EFI stub. The base PE must be systemd-stub —
the kernel's own EFI stub does not read PE sections, so the kernel comes up with
no command line and no initrd and hangs silently. Install the systemd EFI stub
package, or pass `--stub`.

**"failed to read EFI stub at /usr/lib/systemd/boot/efi/linuxx64.efi.stub
(install systemd-efistub package)"**
Exactly what it says.

---

## Recovering a node that will not boot

1. Get to the firmware setup menu (physical console or BMC).
2. Clear the Secure Boot keys. The firmware returns to Setup Mode and boots
   unsigned images again.
3. Boot the node, fix the image or the key material, and re-run the dry run
   until it passes before committing again.

If the DB *key* is lost but PK and KEK are still enrolled: the currently signed
UKI keeps booting, but you can never sign a new one. Recovery is the same —
clear PK in firmware setup, regenerate the key material, re-provision with a
newly signed image.

---

## What is not here

If you came from this folder's older documents looking for AVR microcontroller
flashing, Raspberry Pi OTP secure boot, Android/GrapheneOS fastboot, firmware
OTA updates or a `platformctl firmware` command: **none of that is implemented.**
Those documents describe a plan. See [architecture.md](architecture.md) §8–§9
for exactly what exists and what does not.

---

## Where to go next

- [cli.md](cli.md) — every verb and every flag
- [api.md](api.md) — what is reachable over a transport (almost nothing, on
  purpose) and what is a tracked gap
- [architecture.md](architecture.md) — the trust model and why the guards are
  shaped the way they are
- [`docs/ima/user.md`](../ima/user.md) — runtime file integrity, the layer above
- [`docs/attestation/`](../attestation/) — proving to someone else what booted
- [`docs/installer/`](../installer/) — how all of this happens automatically at
  install time
