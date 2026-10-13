# TPM Factory Reset on First Boot

> **Status: REFERENCE** · Last verified: 2026-10-13
> The `factory-reset-on-firstboot` and `recovery-key-strategy` installer settings: what each does to the TPM and the recovery passphrase.

## What it is

`disk.encryption.tpm.factory-reset-on-firstboot` is an installer-config flag
that controls whether `firstboot` issues a destructive `TPM2_Clear` before
provisioning the platform's TPM keys.

| | Behaviour |
|---|---|
| `factory-reset-on-firstboot: false` (Go default) | `firstboot` calls `FactoryReset(ownerAuth)`. Each persistent handle is evicted using the supplied owner auth. **Fails with `TPM_RC_BAD_AUTH`** if a previous failed run set the owner hierarchy auth to a value the current run doesn't know. |
| `factory-reset-on-firstboot: true` (reference templates default) | `firstboot` calls `FactoryResetWithClear(ownerAuth)`. **TPM2_Clear via the LOCKOUT hierarchy with empty auth runs FIRST**, then the regular eviction pass. The Clear resets owner / endorsement / lockout hierarchy auths to empty AND wipes all persistent objects in those hierarchies. Manufacturer EK certificates in the Platform hierarchy are preserved (TCG spec). |

## Why two modes

`TPM2_Clear` is destructive. It rolls back any state a previous owner — or a
previous failed run — left in the TPM. The Go library has a hard rule that
**destructive operations must be opt-in**: a method named `FactoryReset` is
allowed to fail loudly, but it is never allowed to silently destroy state
the operator didn't ask to destroy. So:

* The Go library function `FactoryReset()` is non-destructive (eviction only).
* The Go library function `FactoryResetWithClear()` is destructive (Clear + eviction).
* Which one `firstboot` calls is decided **by the installer config**, not by Go.

## When to enable

Set `factory-reset-on-firstboot: true` when:

* You are deploying to **fresh hardware** that has not been provisioned by this
  platform before.
* You are **first-time provisioning** newly-purchased servers.
* You are **recovering from a stuck TPM** where a previous failed install
  attempt left owner-hierarchy auth set to an unknown value. (This is the
  exact failure mode that took several hours to diagnose on `node-02` on
  2026-04-07 — the previous failed attempt set owner auth, and every
  subsequent retry hit `TPM_RC_BAD_AUTH` on the eviction pass.)
* Your reference architecture ships fresh ISO images to fresh nodes.

The reference architecture templates in
`configs/platform/templates/**/control-plane.yaml` and friends default this
to `true` because that's the expected lifecycle.

## When to disable

Set `factory-reset-on-firstboot: false` when:

* You are **re-imaging a node** that already has known-good TPM state you
  intend to preserve (e.g., manufacturer-provisioned IDevID/IAK certificates
  in the EH hierarchy that you don't want to lose).
* The TPM is **shared with another component** that owns one of the
  hierarchy auths.
* You are running **regulated workloads** where every TPM clear must be
  audited and recorded out-of-band.
* You are testing the firstboot retry logic and want to assert that the
  non-destructive path fails the way you expect.

## What gets cleared, what's preserved

`TPM2_Clear` (per TCG TPM 2.0 Library Spec Part 1, §13.5):

| Hierarchy | Cleared |
|---|---|
| Owner | YES — auth → empty, all persistent objects evicted, all NV indexes in TPM_RH_OWNER undefined |
| Endorsement | YES — auth → empty, all persistent objects evicted, all NV indexes in TPM_RH_ENDORSEMENT undefined |
| Lockout | YES — auth → empty, dictionary attack lockout state reset |
| Platform | NO — preserved. This is where manufacturer EK certificates live. |

After Clear, the EvictControl pass in `FactoryResetWithClear` runs as a
defense-in-depth: any TCG-standard EK persistent handles (`0x81010001` RSA,
`0x81010002` ECC P-256) and EK certificate NV indices (`0x01C00002`,
`0x01C0000A`, etc.) are explicitly preserved.

## Two-phase provisioning (important)

TPM sealing is **deferred to the first production boot** — it does NOT run
in the installer environment. This matters because PCR values measured
during the installer (Alpine autoinstall kernel + its initrd) do not match
PCR values measured during the production UKI. If the installer tried to
seal against its own PCRs, every subsequent production boot would fail
`TPM2_Unseal` with a policy-check error.

### Phase A — installer

`pkg/installer/installer.go` `prepareLUKSKeyForTPM()`:

1. Generates a random 32-byte LUKS key and a recovery passphrase
2. Formats target root LUKS2 with **slot 1 = LUKS key**, **slot 2 = recovery passphrase**
3. Creates an ephemeral 100 MB LUKS2 container at `/boot/efi/tpm2/installer.luks`
   (password `"forensic-protection-only"` — model is wipe-before-exposure,
   not confidentiality)
4. Writes `luks-key.bin`, `recovery-key.txt`, and `etc/trusted-platform/config.yaml`
   inside the container
5. Installs the production UKI
6. Reboots

At this point the TPM has NOT been touched. No sealing has happened.

### Phase B — first production boot (in platform-initrd)

`pkg/firstboot/strategy.go` `FirstbootSealStrategy.Unlock()`:

1. `CanUnlock()` detects first boot via two intrinsic state signals:
   - `/boot/efi/tpm2/installer.luks` exists (set in Phase A)
   - no sealed-blob files exist yet
2. Opens the installer container, reads the LUKS key and recovery passphrase
3. Runs `provisionInsideInstaller()` → calls `FactoryReset` or
   `FactoryResetWithClear` per `factory-reset-on-firstboot`, then `Install()`
   with empty hierarchy auths (EK + SSRK + platform policy + IAK + IDevID),
   and creates the **Platform KeyStore SRK** (default `0x81000002`) through
   the same `pkg/platform` keychain path platformd uses — platformd then
   adopts the fully-provisioned TPM instead of re-provisioning it (#61)
4. Seals the LUKS key **under the Platform KeyStore SRK** to **live
   production PCRs** via `sealKeyToTPM()` (correct environment because we
   are inside the production UKI)
5. Unlocks the LUKS root partition using the LUKS key
6. Copies installer state to the root filesystem
7. Applies `recovery-key-strategy` (see next section)
8. `closeInstaller()` securely wipes `installer.luks` via `luks2.Wipe`
   (random overwrite + TRIM + unlink)

### Phase C — platformd first run (post-pivot)

`pkg/app/firstboot_handoff.go` `(*App).ConsumeFirstbootHandoff()`:

When `recovery-key-strategy=escrow`, Phase B stages the recovery passphrase
at `/run/platform/firstboot-handoff/recovery.key` (tmpfs, 0600, root only).
On first platformd startup, `serve.go` calls `ConsumeFirstbootHandoff`,
which:

1. Reads the staged passphrase
2. Stores it in the tenant secret store at
   `tenants/{tenant}/nodes/{node}/secrets/luks/recovery`
3. Writes an audit breadcrumb at
   `tenants/{tenant}/nodes/{node}/params/firstboot/escrowed_at`
4. Shreds and unlinks the tmpfs file

The tmpfs directory does not survive a reboot, so the handoff is
single-consumer by construction.

## recovery-key-strategy

Controls what happens to the LUKS recovery passphrase (slot 2) at the end
of Phase B.

```yaml
disk:
  encryption:
    tpm:
      enabled: true
      factory-reset-on-firstboot: true
      recovery-key-strategy: escrow   # destroy | escrow  (default: escrow)
```

| Strategy | Phase B action | Phase C action | Post-first-boot state |
|---|---|---|---|
| `destroy` | `luks2.KillSlot(2)` | nothing | Only slot 1 (TPM-sealed) can unlock. Passphrase is unrecoverable. |
| `escrow` (default) | stage at tmpfs handoff | store at `tenants/{t}/nodes/{n}/secrets/luks/recovery`, shred tmpfs | Slot 2 still valid. Authorized operator can retrieve the passphrase from the secret store for break-glass recovery. |

### When to use `destroy`

- Kiosk / single-purpose appliances where human recovery is not expected
- Fully unattended deployments with golden-image reprovisioning as the
  recovery path
- Strict compliance environments that forbid any out-of-band recovery

### When to use `escrow`

- Default for all general-purpose deployments
- Environments where an authorized operator needs a break-glass path in
  case TPM state becomes unusable (failed firmware update, board swap,
  hierarchy auth drift)
- Multi-tenant deployments where recovery is gated by a secret store ACL

## Wire path

```
installer.yaml
  disk:
    encryption:
      tpm:
        enabled: true
        factory-reset-on-firstboot: true    # ← TPM2_Clear opt-in
        recovery-key-strategy: escrow        # ← destroy | escrow
              ↓
pkg/installer/types.go          TPMSealConfig.FactoryResetOnFirstBoot
                                TPMSealConfig.RecoveryKeyStrategy
              ↓
pkg/firstboot/strategy.go       FirstbootSealStrategy.shouldFactoryResetWithClear()
                                FirstbootSealStrategy.applyRecoveryKeyStrategy()
              ↓
go-xkms/pkg/tpm2/provision.go   TPM2.FactoryResetWithClear() → TPM2.Clear() + eviction
go-luks2/pkg/luks2              luks2.KillSlot(slot=2)        (destroy)
              ↓
tmpfs handoff                   /run/platform/firstboot-handoff/recovery.key  (escrow)
              ↓
pkg/app/firstboot_handoff.go    (*App).ConsumeFirstbootHandoff()
              ↓
tenant secret store             tenants/{t}/nodes/{n}/secrets/luks/recovery
```

## platformd's seal-preservation gate (#61)

platformd's startup carries its own TPM recovery path (`pkg/app/app.go`,
`needsProvisioning`): when it decides the TPM needs provisioning, it
factory-resets first. That path is **gated on the ESP seal artifacts**: when
`seal-platform.pub`/`.priv` exist, a TPM-sealed LUKS unlock is in play, and
platformd runs only the seal-preserving repair: the idempotent, non-clearing
`Install`, which creates only what is missing — no `TPM2_Clear`, and no
`FactoryReset` either, since its evict pass would remove the Platform
KeyStore SRK the seal is parented under. `ProvisionPlatform` is skipped
entirely, because its `TPM.Provision` begins with `TPM2_Clear`. A missing
Platform SRK is recreated later by `InitPlatformKeyStore` through the
`pkg/platform` keychain. The repair also never requests `PlatformPolicy`
from `Install`: `CreatePlatformPolicy` extends the platform PCR
unconditionally, and by the time the repair runs `OpenTPM` has already
restored a zero PCR — a second extension would leave the existing Platform
SRK's PCR policy branch unsatisfiable for the rest of the boot. The repair
inspects the PCR itself and extends exactly once, only when it is
demonstrably still zero, failing typed when its state cannot be read.

The artifact probe is TRI-STATE (`probeTPMSealArtifacts`): present, absent,
or indeterminate. Absence is answered only against a mounted, VERIFIED ESP
whose artifacts demonstrably do not exist — verified means the filesystem
at the mount point is mounted from a `/dev` block device, is vfat (the only
filesystem an EFI System Partition can be), and carries the `EFI/`
directory every ESP this platform booted from necessarily has. A
mount-point string match alone proves nothing: an empty tmpfs or the wrong
partition at `/boot/efi` would otherwise make the artifacts' absence look
like proof while the real seal sits on the unmounted ESP. An unmounted or
unverified ESP or an unreadable artifact path is INDETERMINATE, and `resolveTPMRecovery` turns
that into a typed startup error (`ErrTPMSealStateUnknown`) telling the
operator to make the ESP readable — never a guess in either direction.
Guessing "present" would silently substitute the partial repair for full
provisioning on a fresh node (no hierarchy auth, no CA, no enrollment)
while reporting success; guessing "absent" would run `TPM2_Clear` against a
possibly real seal. The recovery decision also carries the CAUSE: Platform
SRK policy drift beside a present seal is a typed `ErrTPMSealPolicyDrift`
startup error — the install-only repair cannot recreate the seal parent,
so continuing would adopt an SRK whose policy-authorized operations all
fail; the operator restores the prior PCR state, or unlocks with the
recovery key and removes the ESP seal artifacts to authorize
re-provisioning. platformd never runs `TPM2_Clear` and never schedules
the UEFI PPI ForceClear + warm reset unless the seal is proven absent — a
Clear regenerates the storage primary seed and permanently strands the seal
(`TPM_RC_INTEGRITY` on every subsequent unseal). The PPI escalation also
syncs its `/var/lib/tpm2/ppi-clear-attempted` loop sentinel to disk before
the SysRq reset, because SysRq-b does not flush filesystems and an unsynced
sentinel turned the bounded escalation into a reboot loop.

Adoption is completed, not just tolerated: firstboot creates the identity
HANDLES (IAK/IDevID), but only `ProvisionPlatform` used to import the EK
certificate, issue the IAK/IDevID certificates (ACME device enrollment or
local TCG-CSR signing), and activate the node. After an adoption or a
seal-preserving repair, `InitTPM` checks the TPM certificate store
(`platformIdentityComplete`) and, when the certificates are missing, runs
`CompletePlatformIdentity` — the non-destructive tail of
`ProvisionPlatform` (CA init, EK cert import, certificate issuance /
enrollment, attestation, activation) with no `TPM2_Clear` and no
hierarchy-auth change. Issued IAK/IDevID certificates are persisted to the
TPM certificate store (`ProvisionIAKCert` / `ProvisionIDevIDCert`), which
is both what the daemon's IDevID API serves and what marks the identity
complete on subsequent boots.

## Recovery from a stuck TPM without changing the flag

If a node was deployed with the flag set to `false` and the install failed
because the TPM has stale owner auth, you can recover from the running OS
without re-deploying:

```bash
# Pure-Go path (recommended):
platformctl tpm clear --device /dev/tpm0 --force --confirm

# That uses the UEFI Physical Presence Interface (PPI) to schedule a clear
# via the firmware on next boot. The system reboots; the firmware processes
# the request and clears the TPM. Most Supermicro firmwares process the
# request without prompting; some require operator confirmation at the
# BIOS Setup screen via iKVM HTML5.
#
# After reboot, retry firstboot:
platformctl firstboot --luks-device /dev/sdaN --debug
```

This is **only** for recovery — for routine deployments, set the installer
config flag and let the Go code handle it.

## LUKS keyslot layout

For reference, the installed root LUKS header ends up with the following
layout after a successful first production boot:

| Slot | Contents | Lifetime |
|---|---|---|
| 0 | installer passphrase | killed by firstboot as soon as the sealed key is written (`killInstallerKeyslot`) |
| 1 | TPM-sealed LUKS key | steady-state unseal path |
| 2 | recovery passphrase | kept if `escrow`, removed if `destroy` |

The constants are defined in `pkg/firstboot/strategy.go` as
`luksSlotTPMKey` and `luksSlotRecovery` — any code that adds or removes
keyslots MUST use those constants.
