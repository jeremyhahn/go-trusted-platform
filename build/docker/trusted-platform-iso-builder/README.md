# trusted-platform-iso-builder

This is the build container for the Trusted Platform ISO. The ISO is based on the latest version of Debian 12 bookworm with the Trusted Platform pre-installed. The ISO is intended for bare metal, virtual machines, PXE boot clients, automated Packer builds, and anywhere else a pre-built ISO is useful.

# Build

The included `Makefile` provides targets to build and run the platform runtime containers.

# Makefile

## Variables

| Variable Name       | Description                                              | Default Value                                       |
|---------------------|----------------------------------------------------------|---------------------------------------------------|
| `IMAGE_NAME`        | Name of the Docker image for the trusted platform ISO.   | `trusted-platform-iso-builder`                 |
| `IMAGE_NAME_SWTPM`  | Name of the Docker image for the trusted platform ISO with Software TPM. | `trusted-platform-iso-builder-swtpm` |
| `ISO_NAME`          | Name of the ISO file for the trusted platform.           | `trusted-platform.iso`                         |
| `ISO_NAME_SWTPM`    | Name of the ISO file for the trusted platform with Software TPM. | `trusted-platform-swtpm.iso`             |
| `ISO_NAME_DEBIAN`   | Name of the Debian ISO file.                             | `debian-12.8.0-amd64-netinst.iso`                |
| `QEMU_DISK`         | QEMU disk file name.                                     | `trusted-platform.qcow2`                       |
| `QEMU_DISK_SWTPM`   | QEMU disk file name for Software TPM.                    | `trusted-platform-swtpm.qcow2`                 |
| `QEMU_DISK_SIZE`    | Size of the QEMU disk.                                   | `10G`                                            |
| `QEMU_BRIDGE`       | Name of the network bridge for QEMU.                     | `virbr0`                                         |
| `TPM_DEVICE`        | Path to the TPM device on the host.                      | `/dev/tpmrm0`                                    |
| `OVMF_CODE_MS`      | Path to UEFI firmware with Secure Boot and Microsoft certs. | `/usr/share/OVMF/OVMF_CODE_4M.ms.fd`        |
| `OVMF_VARS_MS`      | Path to UEFI variable store with Secure Boot and Microsoft certs. | `/usr/share/OVMF/OVMF_VARS_4M.ms.fd`  |
| `OVMF_CODE_SECBOOT` | Path to UEFI firmware with Secure Boot.                  | `/usr/share/OVMF/OVMF_CODE_4M.secboot.fd`        |
| `OVMF_CODE`         | Path to UEFI firmware without Secure Boot.               | `/usr/share/OVMF/OVMF_CODE_4M.fd`                |
| `OVMF_VARS`         | Path to UEFI variable store without Secure Boot.         | `/usr/share/OVMF/OVMF_VARS_4M.fd`                |


## Targets

| Target Name            | Description                                                                                  |
|-------------------------|----------------------------------------------------------------------------------------------|
| `default`              | Cleans, builds all Docker images, and runs all images.                                       |
| `build`                | Builds the main Docker image for the trusted platform ISO.                                   |
| `build-swtpm`          | Builds the Docker image for the trusted platform ISO with Software TPM.                      |
| `build-all`            | Builds both the main and Software TPM Docker images.                                         |
| `run`                  | Runs the Docker container for the trusted platform ISO.                                      |
| `run-swtpm`            | Runs the Docker container for the trusted platform ISO with Software TPM.                    |
| `run-all`              | Runs both the main and Software TPM containers.                                              |
| `clean`                | Removes Docker images and cleans up generated files and directories.                         |
| `qemu-bridge`          | Configures the QEMU network bridge. Must be run as root.                                     |
| `qemu-install`         | Creates a QEMU disk and installs the ISO using legacy BIOS.                                  |
| `qemu-install-uefi`    | Installs the ISO using UEFI without secure boot.                                             |
| `qemu-install-uefi-sb` | Installs the ISO using UEFI with secure boot.                                                |
| `qemu-install-uefi-sb-ms` | Installs the ISO using UEFI with secure boot and Microsoft signing certificates.           |
| `qemu-install-swtpm`   | Installs the ISO using legacy BIOS with Software TPM.                                        |
| `qemu-run`             | Runs the installed QEMU image using legacy BIOS.                                             |
| `qemu-run-uefi`        | Runs the installed QEMU image using UEFI without secure boot.                                |
| `qemu-run-uefi-sb`     | Runs the installed QEMU image using UEFI with secure boot.                                   |
| `qemu-run-uefi-sb-ms`  | Runs the installed QEMU image using UEFI with secure boot and Microsoft signing certificates.|
| `qemu-run-swtpm`       | Runs the installed QEMU image using legacy BIOS with Software TPM.                           |
| `qemu-run-all`         | Runs all QEMU configurations (legacy, UEFI, UEFI secure boot, etc.).                        |
| `virsh-run`            | Defines and starts the virtual machine using `virsh`.                                        |
| `virsh-clean`          | Stops and undefines the virtual machine using `virsh`.                                       |
| `virsh-list`           | Lists all virtual machines using `virsh`.                                                    |
| `virt-viewer`          | Opens a viewer for the virtual machine using `virt-viewer`.                                  |
| `virt-console`         | Attaches to the virtual machine console using `virsh`.                                       |
