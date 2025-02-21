# Reference Architecture

This document discusses the reference architecture for the Trusted Platform.

There are many different ways to deploy and use the Trusted Platform, for example, home, office or corporate authentication and network access, devops automation workflows, building secure, trusted web services, and running a public or private cloud.

Here we will take a look at an Internet of Things (IoT) platform that operates as a hybrid cloud.


![Alt text](assets/reference-architecture.drawio.png?raw=true "IoT Reference Architecture")


# System Requirements

The following are a set of configuration requirements needed to meet a "fully configured" system as per the Reference Architecture.

1. Hardware TPM 2.0 (FIPS compliance)
2. Secure Boot enabled
3. BIOS password set
4. Custom UEFI keys enrolled
5. Signed Linux EFI Stub
6. Shim removed
7. LUKS encrypted root file system
8. LUKS key sealed to TPM

Note that a software TPM (SWTPM) does not meet the requirements for a "fully configured" Trusted Platform instance as they are unable to provide the same level of security as a real hardware TPM device.

# Unified Kernel Image & Immutable Infrastructure

The Trusted Platform is intended to run on [immutable infrastructure](https://www.hashicorp.com/en/resources/what-is-mutable-vs-immutable-infrastructure).

The platform software includes tooling to build custom ISOs and container images with custom secure boot keys specific to the system being provisioned.

The included ISO tooling builds a custom Linux kernel with [EFI Stub](https://docs.kernel.org/admin-guide/efi-stub.html) support and subsequently peforms a [Unified Kernel Image](https://github.com/uapi-group/specifications/blob/main/specs/unified_kernel_image.md) build. The resulting UKI is signed using the secure boot keys generated during the installation process, making it ready to boot directly from the system's [UEFI](UEFI-SECURE-BOOT.md) firmware after the secure boot keys have been enrolled.

Upgrading the kernel requires building a new UKI. Following immutable infrastructure best practices, this can be accomplished by using the included tooling to build a new UKI, ISO, container image or whatever media best suits your immutable infrastructure platform and automated deployment architecture.

The Trusted Platform supports bare metal, virtual, cloud, containerized and hybrid environments.
