# QEMU

This section outlines the concepts, configuration and procedures needed to boot a QEMU / KVM instance on linux with full support for the Trusted Platform.

# Requirements for Full Support

1. Secure Boot Keys
* Platform Key (PK)
* Key Exchange Key (KEK)
* Database Key (DB)
2. UEFI OVMF firmware w/ SB
3. Bootable ISO (signed)

#### Installation

1. Installed Kernel w/ EFI Stub (signed)
2. LUKS encrypted file system
3. UEFI boot entry pointing to `/EFI/debian/kernel.efi` or use the default path `/EFI/Boot/bootx64.efi`.

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
