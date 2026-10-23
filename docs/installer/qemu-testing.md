# QEMU

> **Status: REFERENCE** · Last verified: 2026-10-13
> What a QEMU/KVM guest needs for the full Trusted Platform boot, and the disk-cache setting for nested-virt hosts.

This section outlines the concepts, configuration and procedures needed to boot a QEMU / KVM instance on linux with full support for the Trusted Platform.

# Requirements for Full Support

1. Secure Boot Keys
* Platform Key (PK)
* Key Exchange Key (KEK)
* Database Key (DB)
2. UEFI OVMF firmware w/ SB
3. Bootable ISO (signed)

#### Installation

1. Installed Unified Kernel Image (signed)
2. LUKS encrypted file system
3. The UKI at the default removable-media path `/EFI/BOOT/BOOTX64.EFI` (`BOOTAA64.EFI` on arm64), which the installer also registers as a UEFI boot entry.

# References

https://edk2-devel.narkive.com/vuOBSb6w/edk2-adding-public-keys-to-ovmf

https://docs.oracle.com/en/operating-systems/oracle-linux/secure-boot/sboot-OverviewofSecureBoot.html#sb-enabling

https://qemu-project.gitlab.io/qemu/system/confidential-guest-support.html


# Nested Virtualization Hosts

The test harness defaults the VM disk to `cache=writethrough` — every guest
write is host-synchronous, which is faithful to bare metal. On a host that is
itself a VM, that synchronous path can exceed the guest's 30-second SCSI
command timeout under the installer's write bursts (apk extraction, dracut,
LUKS formatting); the guest then sees `I/O error, dev sda ... op WRITE`
storms, dm-crypt propagates `EIO`, and the install is corrupted.

On nested-virt hosts pass a relaxed cache mode — the disk under test is a
throwaway artifact, so host-crash durability is irrelevant:

```bash
platformctl iso test install --iso trusted-platform.iso --disk-cache unsafe
```
