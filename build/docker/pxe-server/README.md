# pxe-server

This is [PXE Boot](https://en.wikipedia.org/wiki/Preboot_Execution_Environment) image for bootstraping network hosts.

QEMU support is also included to test the PXE Boot server.

# Build

## Makefile

The included Makefile provides several targets to faciliate building, initalizing, and testing the PXE Boot container.

#### Variables

The PXE network belongs to the deployment, so it has no defaults: `pxe-server` stops with an error naming each required variable that is unset. The image stays generic (`build` and `push` need none of them); the container writes its DHCP scope at start from `DHCP_SUBNET`, `DHCP_NETMASK`, `DHCP_RANGE_START`, `DHCP_RANGE_END`, `DHCP_ROUTER` and `DHCP_NEXT_SERVER`, which the `pxe-server` target derives from the variables below, and exits if any is missing.

| **Variable**      | **Default Value**                                                                                                             | **Description**                                                        |
|-------------------|-------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| `ISODIR`          | `volume/iso`                                                                                                                  | Directory for storing ISO images and netboot files.                    |
| `IMAGE_NAME`      | `pxe-server`                                                                                                                  | Docker image name for the PXE server.                                  |
| `CONTAINER_NAME`  | `pxe-server`                                                                                                                  | Docker container name for the PXE server.                              |
| `NETWORK_NAME`    | `pxe-net`                                                                                                                     | Docker network name for the PXE server.                                |
| `SUBNET` | _required_ | Subnet (CIDR) of the PXE network, used for the Docker network and the DHCP scope. |
| `NETMASK` | _required_ | Netmask of `SUBNET` for the DHCP scope (for example `255.255.255.0`). |
| `IP_RANGE` | _required_ | IP range for the Docker network. |
| `GATEWAY` | _required_ | Gateway of the PXE network; also the DHCP `routers` option. |
| `STATIC_IP` | _required_ | Static IP of the PXE server container; also the DHCP `next-server`. |
| `DHCP_RANGE_START` | _required_ | First address the DHCP server leases. |
| `DHCP_RANGE_END` | _required_ | Last address the DHCP server leases. |
| `QEMU_DISK`       | `debian12.qcow2`                                                                                                              | Filename for the QEMU disk image.                                      |
| `QEMU_DISK_SIZE`  | `5G`                                                                                                                          | Size of the QEMU disk image.                                           |
| `QEMU_BRIDGE`     | `br-3114e390c8a6`                                                                                                             | Bridge interface used for QEMU networking.                             |
| `DEBIAN_URL`      | `https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.8.0-amd64-netinst.iso`                                    | URL for the Debian netinst ISO.                                        |
| `VYOS_URL`        | `https://github.com/vyos/vyos-nightly-build/releases/download/1.5-rolling-202412100007/vyos-1.5-rolling-202412100007-generic-amd64.iso` | URL for the VyOS ISO image.                                            |
| `MIRROR`          | `deb.debian.org`                                                                                                              | Debian mirror used for downloading netboot files.                      |
| `ARCH`            | `amd64`                                                                                                                       | Architecture for the installer.                                        |
| `DIST`            | `stable`                                                                                                                      | Debian distribution release (e.g., stable).                            |

#### Targets

| **Target**      | **Description**                                                                                                                                                   |
|-----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `default`       | Alias that builds the Docker image (`load`) and deploys the PXE server container (`pxe-server`).                                                                    |
| `init`          | Initializes directories, downloads netboot files and Debian release files, verifies checksums and GPG signatures, and imports the Debian archive key.           |
| `load`          | Builds the Docker image locally using a multi-platform build (`--load` option).                                                                                   |
| `push`          | Builds and pushes the Docker image to Docker Hub (or your specified registry) for multiple architectures.                                                          |
| `pxe-server`    | Creates the Docker network (if it doesn’t already exist) and runs the PXE server container with the appropriate IP settings and volume mounts.                  |
| `redeploy`      | Force removes the existing PXE server container, redeploys it (by invoking the `run` target), and displays container logs.                                          |
| `clean`         | Cleans up by removing downloaded ISOs, the Docker container and image, and deletes the Docker network.                                                              |
| `qemu-bridge`   | Configures QEMU networking by adding the specified bridge interface to `/etc/qemu/bridge.conf`.                                                                      |
| `qemu-install`  | Creates a new QEMU disk image and starts a QEMU virtual machine for installation using the specified disk size and bridge interface.                                |
| `qemu-run`      | Runs a QEMU virtual machine using an existing disk image with specified networking and boot options.                                                               |
| `qemu-rpi`      | Launches a QEMU instance emulating a Raspberry Pi (ARM) environment using specified kernel and initramfs images, with networking and serial console configured. |

# Testing

To test the container, initialize, build, and run the container as follows:

## Init

The `init` target downloads the [Debian 12 NetBoot](https://wiki.debian.org/DebianInstaller/NetbootFirmware) image to the ISO volume so the container can mount it and host it via TFTP.

## Load

The `load` target builds the docker container and loads it into the local repository.

## pxe-server

The `pxe-server` target creates a `pxe-net` network and starts a new container using the local image loaded by the previous section.

## qemu-install

The `qemu-install` target launches a QEMU host with PXE boot enabled and installs the operating system via PXE Boot / TFTP.
