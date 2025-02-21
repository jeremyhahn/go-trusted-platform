# Trusted Platform ISO

The Trusted Platform ISO is built using the `trusted-platform-iso-builder` container located in the [docker build](/build/docker/trusted-platform-iso-builder) directory.


# Building the ISO

The `build/docker/trusted-platform-iso-builder` directory contains a Makefile and several scripts that generate secure boot keys and build a signed ISO ready to boot and perform a full unattended install using the [Debian Preseed](https://wiki.debian.org/DebianInstaller/Preseed) in the same directory.

The secure boot keys are copied into the ISO and used to sign the operating system during the install. 

The resulting install is a Debian operating system configured for Secure and Measured Boot using custom keys. The kernel is built with [EFI Stub](https://docs.kernel.org/admin-guide/efi-stub.html) which supports being booted directly from your system's UEFI.

Booting the kernel directly from UEFI bypasses the usual Shim and 2nd stage bootloader such as Grub or systemd-boot. This configuration reduces potential attack vectors during the boot process and quickly boots the operating system.

## Examples

    # Create trusted-platform.iso for hardware TPM 2.0
    make secure-boot-keys build run

    # Create trusted-platform-swtpm.iso for software TPM 2.0
    make secure-boot-keys build run-swtpm


# Installing the OS

#### QEMU / KVM

The included Makefile has support for QEMU. Once the ISO has been built, use the `install` targets to launch a QEMU instance using KVM acceleration. The `qemu-install-uefi-sb` target provides a virtual machine using the [Reference Architecture](ARCHITECTURE-REF.md).

The following QEMU specific configurations are required:

* UEFI OVMF Secure Boot keys enrolled
* Hardware TPM 2.0 (host passthrough)
* Software TPM (optional - in leui of HW TPM)

##### UEFI / OVMF

The tool `virt-fw-vars` is used to enroll secure boot keys into the OVMF_VARS UEFI NVRAM file.

https://gitlab.com/kraxel/virt-firmware/-/tree/master?ref_type=heads#virt-fw-vars


# Booting the OS

The installed Operating System writes a custom compiled and signed kernel with EFI stub support to `/EFI/debian/kernel.efi` and copies it to the default EFI location `EFI/Boot/bootx64.efi`. This allows default systems that honor the default path to boot without any custom UEFI boot entries. 

#### Bare Metal

If your UEFI system does not automatically load the default bootx64.efi path, you will need to set the path manually. Refer to your motherboard documentation on how to access your UEFI firmware interface to set the boot entry.

#### QEMU / KVM

The included `Makefile` provides support for booting the hard disk in the same way a physical computer would boot from a hard disk, or most standard virtual machine configurations. 

    # Boot from the qcow2 disk
    make qemu-run-uefi-sb

#### Direct Kernel Boot

QEMU supports [Direct Kernel Boot](https://qemu-project.gitlab.io/qemu/system/linuxboot.html) which is very useful for fast Linux kernel testing.

    # Mount the qcow2 disk and directly boot the kernel
    make qemu-run-uefi-sb-direct
