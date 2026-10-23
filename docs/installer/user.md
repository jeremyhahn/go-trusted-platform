# Installer — Using It

> **Status: REFERENCE** · Scope: installing a Trusted Platform node · Last verified: 2026-08-18
> Task-oriented, in the order you do things. Internals are in
> [engineering.md](engineering.md); the design is in
> [architecture.md](architecture.md).
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## What this is

You build an ISO, boot a machine from it, and end up with a node whose disk is
encrypted, whose boot chain is signed, and whose disk encryption key is sealed
to that machine's TPM so it only unlocks when the machine boots the way you
expect.

Three things surprise people, so read them before you start:

1. **Nothing is sealed to the TPM during installation.** The install finishes,
   the machine reboots, and *the first production boot* is what provisions the
   TPM and seals the key. An install that "completed" is not a finished node.
2. **Between install and first boot, the EFI partition holds your disk
   encryption key** inside a container whose password is a published constant.
   That is a deliberate trade for forensic protection, not a secret. Don't
   leave a machine in that state, and don't image the disk in that state.

---

## Prerequisites

On the machine where you build the ISO:

- QEMU with KVM, `qemu-img`, and OVMF firmware, if you want to test the image.
- `swtpm` for the software TPM in tests.
- `xorriso` (and `7z` or `bsdtar` for extraction).
- Network access to an Alpine mirror, unless you already have the base ISO.

On the machine you are installing:

- UEFI firmware. This is a UEFI-only installer — it builds a Unified Kernel
  Image and enrols UEFI Secure Boot variables.
- A TPM 2.0 device at `/dev/tpmrm0` or `/dev/tpm0`, if you want the disk to
  unlock unattended. Without one, installation still works; the disk will need
  a passphrase at every boot.
- **An EFI partition of at least 200 MB.** The default is 538 MB, which is
  fine. The installer container needs 100 MB of it alongside a UKI that can
  approach 74 MB.

---

## 1. Build an ISO

```bash
platformctl iso create
```

That downloads Alpine, extracts it, generates Secure Boot keys, copies the
running `platformd` binary into the image, and builds a bootable hybrid
BIOS/UEFI ISO named `trusted-<os>-<version>-<arch>.iso`.

Common variations:

```bash
# FIPS 140-3 image
platformctl iso create --fips

# Point installs at your own package mirror
platformctl iso create --apk-mirror http://mirror.example.com:8080

# Start from a template and layer per-node overrides
platformctl iso create --platform-config base.yaml --overrides node-01.yaml

# Smaller image that fetches packages at install time
platformctl iso create --pre-fetch=false
```

**Leave `--pre-fetch` on** unless you know the install network permits outbound
HTTPS to the Alpine CDN. It is on by default so the ISO works over BMC virtual
media, on an air-gapped bench, and over a PXE bootstrap subnet — all three of
which are exactly the cases where an install-time mirror is not reachable.

**`--mirror` and `--apk-mirror` are different things.** `--mirror` is where the
*build* fetches from. `--apk-mirror` is baked into the installed kernel command
line and is where the *install* fetches from when there is no CD-ROM — the PXE
case.

**`--overrides` needs `--platform-config`.** It is a merge onto a template; on
its own it fails.

---

## 2. Test it before you touch hardware

```bash
platformctl iso test install --iso trusted-alpine-1.0.0-x86_64.iso
platformctl iso test firstboot
platformctl iso test boot
```

or all three in sequence:

```bash
platformctl iso test all
```

This runs QEMU with a software TPM and OVMF, and enrols the Secure Boot keys
into NVRAM. Each command opens an interactive session; `Ctrl-C` exits.

The install test **rebuilds the disk image from scratch every time** and resets
OVMF NVRAM so the firmware rediscovers the CD-ROM. `firstboot` and `boot` reuse
the disk and preserve the TPM state, which is what makes the sealed key
unsealable on the second boot — that is the point of running them in order.

Network boot:

```bash
sudo platformctl iso test pxe --iso trusted-alpine-1.0.0-x86_64.iso
```

**`iso test pxe` needs root** for bridge and TAP setup. So does
`iso test client-server`, unless you pass `--user-network` (which only works
with `--server-only`).

---

## 3. Write your installer configuration

Start from a profile. There are four: `dev`, `production`, `production-hs`,
`fips`.

The essentials, in `/etc/platformd/install.yaml` on the target or on the ISO:

```yaml
disk:
  device: /dev/sda
  partition-table: gpt
  efi-partition-size: 538
  root-filesystem: lvm
  lvm-volume-group: vg0
  lvm-logical-volume: root
  encryption:
    version: luks2
    cipher: aes-xts-plain64
    key-size: 512
    passphrase: "<your LUKS passphrase>"
    mapped-name: cryptroot
    tpm:
      enabled: true
      factory-reset-on-firstboot: true
      recovery-key-strategy: escrow
os:
  os: alpine
  hostname: node-01.example.com
  fips: false
  lockdown: true
  lockdown-mode: confidentiality
  kernel-modules: [igb, ixgbe]
enable-tpm-sealing: true
pcrs: [0, 7, 9]
```

Four decisions worth making deliberately:

**`factory-reset-on-firstboot`.** `true` wipes the TPM's owner, endorsement and
lockout hierarchies before provisioning. Set it for fresh hardware and for
retrying after a failed install. Clear it when you are re-imaging a node whose
TPM state you want to keep, or when something else owns a hierarchy auth. The
Go default is `false`; the reference templates set it `true`. Full detail:
[factory-reset.md](factory-reset.md).

**`allow-missing-ek-certificate`.** By default firstboot refuses a TPM that
carries no EK certificate, before it changes anything on the TPM, and the node
does not serve. Set it `true` only for a TPM that cannot have one (swtpm, a
vTPM, a part shipped without one): firstboot then provisions the TPM without an
IDevID and logs a warning that names the setting. The Go default and every
reference template leave it `false`. Full detail:
[architecture.md](architecture.md), "First provision, the EK and recovery".

**`recovery-key-strategy`.** `escrow` (the default) keeps the recovery
passphrase and moves it into the tenant secret store, where an ACL governs it.
`destroy` removes the keyslot on first boot and leaves the TPM seal as the only
way in. Choosing `destroy` is choosing to have no break-glass path — pick it for
kiosks and golden-image fleets, not for anything you would want to recover.

**`kernel-modules`.** Bare metal usually needs its NIC driver listed here
(`igb`, `ixgbe`, …). A node that installs fine and then comes up without a
network is almost always a missing module.

**`network.role`.** A node on the platform network declares its role
(`control-plane`, `compute` or `gateway`) and addresses its zones by name; the
VLAN IDs come from `sdn.environment`:

```yaml
network:
  role: compute
  platform-vrf:
    address: 10.4.144.20/32      # from the platform-hosts range
  bonds:
    - name: bond0
      type: ovs
      bridge: br-fabric
      mode: balance-tcp
      lacp: active
      interfaces: [eth6, eth7]
      vlans:
        - {zone: fabric, ipv4-address: 10.4.1.20/24}       # the VTEP, required
        - {zone: hypervisor, ipv4-address: 10.4.3.20/24}
sdn:
  enabled: true
  environment: {id: 4}
```

A compute node may only hold addresses on fabric, hypervisor and storage; a
control-plane node also on control-plane. Neither may use DHCP or turn on
`ip-forward`, and the installer writes a firewall that drops traffic between
the host's interfaces. Gateways are exempt. The rules and the files written are
in [engineering.md](engineering.md#host-addressing-by-role-networkrole).

---

## 4. Install

Boot the target from the ISO, then:

```bash
platformctl install system --config /etc/platformd/install.yaml
```

Fully unattended:

```bash
platformctl install system --os alpine --disk /dev/sda \
    --password "$LUKS_PASSPHRASE" --hostname node-01 --automated
```

**`--automated` fails immediately if no LUKS password is configured.** That is
deliberate — an unattended install that silently chose a password for you would
be worse.

**Keep secrets off the command line.** `--password`, `--root-password` and
`--eab-hmac` appear in the process table and in shell history. Put them in a
mode-0600 config file.

**Watch for the post-install script.** It is the only step whose failure aborts
the install, because it configures operator access — SSH keys, serial getty,
sshd overrides. A node that "installed" without it is a node you cannot reach.

When it finishes: remove the media and reboot. **The first boot is where the
real work happens.** Watch it on the console or the BMC serial channel.

### A node whose root is an NBD export (`diskless-nbd`)

A node with `boot_model: diskless-nbd` in `bootstrap.yaml` has no local disk.
Its installer command line carries `platform_boot_model=diskless-nbd` and
`platform_nbd_server`, and the installer ignores `disk.device` and installs
onto `/dev/nbd0`, the node's export on the boot server. Three things must hold
before it starts, or it stops before it clears the TPM or formats anything:

- The node enrols first, through the same `enroll-01` or `endorse-01` client
  every node uses, because the export admits only its IDevID. The live
  environment does not supply that client yet (**Planned**), so today every
  `diskless-nbd` install stops here.
- `/dev/nbd0` is attached to the export. The installer checks and never
  attaches it itself (the attach is **Planned** with `platform-initrd`).
- `disk.encryption` is set. The export is always LUKS2; the boot server only
  ever holds ciphertext.

The export's first partition holds what a disk's EFI partition would: the UKI,
`tpm2/pcr-banks` and, after the first boot, the sealed key. The node mounts it
at `/boot/efi`, so the checks in [First boot](#5-first-boot) are the same.

From the next network boot on, the boot server hands the node that UKI instead
of the installer. If an install stopped partway, the export is partitioned but
holds no UKI. The node's boot then fails with HTTP 500 rather than reinstalling
over it. To reinstall, power the node off, remove `<volume_dir>/<hostname>.img`
on the boot server, and boot it again.

### Signing without shipping the key

If your Secure Boot DB key lives in the control-plane KMS and must not travel:

```bash
platformctl install system --config /etc/platformd/install.yaml \
    --provision-server-url https://platform.example.com:8443 \
    --eab-kid "$EAB_KID" --eab-hmac "$EAB_HMAC" \
    --ek-serial "$EK_SERIAL" --mac aa:bb:cc:dd:ee:ff \
    --ca-bundle /media/cdrom/ca-bundle.pem
```

Only the digest leaves the node; only a signature comes back. Omit
`--provision-server-url` and the installer generates keys on the node instead —
which is the right answer for an air-gapped install and the wrong answer for a
fleet.

---

## 5. First boot

Nothing to type. The initramfs opens the installer container, provisions the
TPM, seals the LUKS key to the PCR values this machine actually measures,
unlocks the root, copies platform state onto it, applies your
`recovery-key-strategy`, and securely wipes the container.

Afterwards the EFI partition should contain `tpm2/seal-platform.pub`,
`tpm2/seal-platform.priv` and `tpm2/pcr-banks`. `tpm2/installer.luks` is
still there after the **first** boot by design — the seal is proven by the
next boot unsealing with it — and is securely wiped by the next boot that
unlocks with `TPM-PCR` (`platform-initrd boot` logs `Seal confirmed by
TPM-PCR unlock`). Reboot once and check:

```bash
ls -la /boot/efi/tpm2/
```

If `installer.luks` is still there after that reboot, the seal did not unlock
the root (the initrd fell back to the keyfile) and the container was preserved
deliberately so you can retry. **Do not put that machine into service.** See
troubleshooting.

---

## 6. Living with it

### Kernel upgrades

An upgrade changes the measurements, which invalidates the seal. The installer
puts a hook in place so an ordinary `apk upgrade linux-lts` rebuilds and
re-signs the UKI. If the hook failed to install, do it by hand:

```bash
platformctl install uki-rebuild
platformctl install uki-rebuild --kver 6.12.8-lts
```

Then plan the reseal. A new UKI produces new PCR values, and anything sealed to
the old ones — the LUKS key, vTPM secrets, golden-PCR attestation policy — needs
updating in the same maintenance window. Nothing re-seals automatically —
the hook rebuilds and re-signs only — so expect the next boot to stop at the
passphrase prompt ([architecture.md](architecture.md) trust boundary 4).

### Firmware updates

Same problem, less warning. A BIOS update changes PCR 0 and the TPM-PCR unlock
stops working. Boot with the passphrase, then reseal.

### Retrieving the recovery passphrase

Under `escrow`, it is in the tenant secret store at
`tenants/{tenant}/nodes/{node}/secrets/luks/recovery`. Under `destroy`, it is
gone and was meant to be.

### Wiping a container by hand

```bash
platformctl wipe --path /boot/efi/tpm2/installer.luks --trim
```

**Keep `--trim` on.** Overwriting a file does not reach the SSD blocks the
controller already remapped; the TRIM is what releases them.

---

## Troubleshooting

**"daemon connection required for 'iso build' command".**
Not a connection problem. Five `iso` verbs are unimplemented stubs. Use
`platformctl iso create`, which runs the whole pipeline.

**The install aborted on the post-install script.**
Intentional. Fix the script — it configures how you reach the machine. If a
step in it is genuinely cosmetic, make the script trap that error and exit 0;
the installer cannot tell "tweak failed" from "no operator access".

**`TPM_RC_BAD_AUTH` during first boot.**
A previous run left owner-hierarchy auth set to something this run doesn't know.
Set `factory-reset-on-firstboot: true` and reinstall, or clear the TPM from a
running system:

```bash
platformctl tpm clear --device /dev/tpm0 --force --confirm
```

That schedules a firmware clear over the UEFI Physical Presence Interface and
reboots. Some firmware asks for confirmation at the BIOS screen. Then retry
firstboot.

**The machine reboots once during install and the TPM clear is mentioned.**
Expected when the software `TPM2_Clear` hits dictionary-attack lockout. The
installer schedules a PPI ForceClear and warm-resets so the firmware services it
at the next POST. It is loop-guarded by a marker on the EFI partition, so it
happens at most once.

**Boot hangs with no output.**
Read `/run/platform-initrd-boot.log` from an emergency shell. It records
numbered steps (`step01` … `step05`), so you can see exactly where it stopped.
The same lines go to the serial console.

**"initrd: unlock failed", or it drops to a passphrase prompt.**
Every unlock strategy declined or failed. Common causes, in order of
likelihood: PCR values changed (firmware or kernel update); the PCR selection
could not be resolved (no `--pcrs`, no `pcr-banks` file, no reachable
`config.yaml`); no TPM device; the installer container is gone but sealing never
completed. Enter the LUKS passphrase, boot, and reseal.

**`installer.luks` still on the ESP after the second boot.**
The second boot did not unlock with `TPM-PCR` (sealing failed, or the PCRs
moved) and the container was kept for a retry — which means the disk
encryption key is still sitting on an unauthenticated partition. Diagnose the
seal failure, complete firstboot, and confirm the container is gone. If you
must clear it manually, use `platformctl wipe --path … --trim` and be aware you
have then removed your only unsealed copy of the key.

**"refusing to install" with `/dev/nbd0: …`.**
A `diskless-nbd` install found no usable export: the `nbd` module is not
loaded, `nbd0` is not attached, the export is empty, or `disk.encryption` is
not set. The message names which. Nothing was touched; attach the export or
fix the config and rerun.

**"enrollment: refusing to attach the NBD export".**
A `diskless-nbd` node did not enrol, so it holds no IDevID to attach its export
with: no enrollment client is configured, enrollment failed (the client's own
error follows), or it returned no certificate. Nothing was touched.

**No TPM detected.**
The installer logs *"TPM sealing enabled but no TPM device found, continuing
without TPM"* and clears the flag. The install proceeds and the disk will need a
passphrase at every boot. On a VM this is normal; on hardware, check that the
TPM is enabled in firmware and that `/dev/tpmrm0` or `/dev/tpm0` exists.

**Secure Boot did not get enforced.**
Enforcement only proceeds when the signed UKI provably verifies against the db
certificate *and* the firmware is in Setup Mode. If either is false the
installer logs a warning and leaves the node bootable-but-unsigned rather than
risking a machine that will not boot at all. Put the firmware into Setup Mode
and reinstall, or enrol the keys manually.

**A node came up with no network.**
Almost always a missing NIC driver. Add it to `os.kernel-modules` and reinstall.

**`iso test install` "failed" but the disk looks right.**
The autoinstall script reboots at the end, QEMU exits non-zero, and the harness
treats that as success when the disk exists and is over 100 MB. If you see a
real failure, the disk will be missing or tiny.

**Recovery's "Attempt to reseal TPM keys" refuses.**
Expected. The initrd cannot store a new seal (the ESP seal files are written
only by first boot), so `platform-initrd recovery` does not reseal, and its menu
option says *"the resealed data cannot be stored"* instead of reporting success.
Unlock, boot, and reseal from the running system.

---

## Where to go next

- [cli.md](cli.md) — every verb and every flag
- [api.md](api.md) — why there is no API, and what provisioning owns instead
- [architecture.md](architecture.md) — the two-phase design and its trust boundaries
- [factory-reset.md](factory-reset.md) — `TPM2_Clear` and `recovery-key-strategy` in full
- [`docs/ipxe/`](../ipxe/) — booting a machine over the network
- [`docs/provisioning/`](../provisioning/) — authorising a machine before it installs
