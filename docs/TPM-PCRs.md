# TPM Platform Configuration Registers (PCRs)

## List of PCRs

https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/

## UEFI Secure Boot Chain

https://laurie0131.gitbooks.io/understanding-uefi-secure-boot-chain/content/overview.html

## Measured Boot

https://bootlin.com/blog/measured-boot-with-a-tpm-2-0-in-u-boot/


### Linux


| PCR # | Used By | From Location | Measured Objects | Log | Use Reported By |
| ------ | ----              | -----             | ----- | ----- | ----- |
| 0     | Firmware           | UEFI Boot Component | Core system firmware executable code | UEFI TPM event log	| n/a |
| 1     | Firmware           | UEFI Boot Component | Core system firmware data/host platform configuration; typically contains serial and model numbers | UEFI TPM event log | n/a |
| 2     | Firmware           | UEFI Boot Component | Extended or pluggable executable code; includes option ROMs on pluggable hardware | UEFI TPM event log	| n/a |
| 3     | Firmware           | UEFI Boot Component | Extended or pluggable firmware data; includes information about pluggable hardware | UEFI TPM event log	| n/a |
| 4     | Firmware           | UEFI Boot Component | Boot loader and additional drivers; binaries and extensions loaded by the boot loader | UEFI TPM event log	| n/a |
| 5     | Firmware           | UEFI Boot Component | GPT/Partition table | UEFI TPM event log	| n/a |
| 7     | Firmware           | UEFI Boot Component | SecureBoot state | UEFI TPM event log	| n/a |
| 8     | grub               | UEFI Boot Component | Commands and kernel command line | UEFI TPM event log	| n/a |
| 9     | grub               | UEFI Boot Component | All files read (including kernel image) | UEFI TPM event log	| n/a |
| 9     | Linux Kernel       | Kernel              | All passed initrds (when the new LOAD_FILE2 initrd protocol is used) | UEFI TPM event log	| n/a |
| 10    | IMA                | Kernel              | Protection of the IMA measurement log | IMA event log	| n/a |
| 11    | systemd-stub       | UEFI Stub           | All components of unified kernel images (UKIs) | UEFI TPM event log	| in EFI variable StubPcrKernelImage |
| 11    | systemd-pcrphase   | Userspace           | Boot phase strings, indicating various milestones of the boot process | Journal (for now)	| n/a |
| 12    | systemd-stub       | UEFI Stub           | Kernel command line, system credentials and system configuration images | UEFI TPM event log	| in EFI variable StubPcrKernelParameters |
| 13    | systemd-stub       | UEFI Stub           | All system extension images for the initrd	| UEFI TPM event log | in EFI variable StubPcrInitRDSysExts |
| 14    | shim               | UEFI Boot Component | “MOK” certificates and hashes | UEFI TPM event log | n/a |
| 15    | systemd-cryptsetup | Userspace           | Root file system volume encryption key	| Journal (for now) | n/a |
| 15    | systemd-pcrmachine | Userspace           | Machine ID (/etc/machine-id) | Journal (for now) | n/a |
| 15    | systemd-pcrfs      | Userspace           | File system mount point, UUID, label, partition UUID label of root file system and /var/ | Journal (for now) | n/a |


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


# References

https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/