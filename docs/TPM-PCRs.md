# TPM Platform Configuration Registers (PCRs)

## List of PCRs

https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/

## UEFI Secure Boot Chain

https://laurie0131.gitbooks.io/understanding-uefi-secure-boot-chain/content/overview.html

## Measured Boot

https://bootlin.com/blog/measured-boot-with-a-tpm-2-0-in-u-boot/


### Linux

## Microsoft

PCR 0: Core root-of-trust for measurement, EFI boot and run-time services, EFI drivers embedded in system ROM, ACPI static tables, embedded SMM code, and BIOS code
PCR 1: Platform and motherboard configuration and data. Handoff tables and EFI variables that affect system configuration
PCR 2: Option ROM code
PCR 3: Option ROM data and configuration
PCR 4: Master boot record (MBR) code or code from other boot devices
PCR 5: Master boot record (MBR) partition table. Various EFI variables and the GPT table
PCR 6: State transition and wake events
PCR 7: Computer manufacturer-specific
PCR 8: NTFS boot sector
PCR 9: NTFS boot block
PCR 10: Boot manager
PCR 11: BitLocker access control

## Secure Boot vs Trusted Boot

In trusted boot, hashing is used to measure changes at each step of the critical
boot process, whereas in secure boot, firmwares are digitally signed and verified. 

Secure boot is generally configured along with trusted boot.

## Disk Encryption

https://tpm2-software.github.io/2020/04/13/Disk-Encryption.html

https://github.com/salrashid123/tpm2/blob/master/luks/README.md