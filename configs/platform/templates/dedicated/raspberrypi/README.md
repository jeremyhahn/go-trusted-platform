# Raspberry Pi — dedicated profile

A Raspberry Pi 4 — or, experimentally, a Pi 5 — as a **compute** node of the
dedicated profile, joining the x86 control plane and gateway of [`supermicro/x10/`](../supermicro/x10/). It
ships as a factory SD-card image, not an installer ISO:

```sh
platformctl diskimage create --target rpi --model rpi4 --role compute \
  --overrides node.yaml --ca-bundle cp-ca.pem
```

`--role compute` builds [`rpi4/compute.yaml`](./rpi4/compute.yaml), or
[`rpi5/compute.yaml`](./rpi5/compute.yaml) with `--model rpi5`. A model the
builder does not know, or a role or model with no file here, is refused
(`ErrRoleTemplate`); the build never falls back to the single-node image. The image pipeline is
[docs/factory-image/](../../../../../docs/factory-image/), and the hardware
prerequisites (SLB9670 TPM HAT, serial console) are those of
[`single-node/raspberrypi/`](../../single-node/raspberrypi/README.md).

| Role | Template | Status |
|---|---|---|
| compute | `rpi4/compute.yaml` | Builds; loads and validates against the reference network; no hardware run yet |
| compute | `rpi5/compute.yaml` | **Experimental**: builds, loads and validates; TPM, console and Ethernet unvalidated on a Pi 5 ([below](#raspberry-pi-5-experimental)) |
| gateway | none | Not supported on a one-port Pi (below) |
| control-plane | none | Stays on x86 (below) |

## What `rpi4/compute.yaml` changes against `supermicro/x10/compute.yaml`

| Key | x10 | rpi4 | Why |
|---|---|---|---|
| `disk.device` / `partition-table` | `""` (installer picks) / `gpt` | `/dev/mmcblk0` / `mbr` | the SD card; the Pi firmware reads only an MBR |
| `os.architecture` / `kernel-package` | `x86_64` / unset (`linux-lts`) | `aarch64` / `linux-rpi` | the Alpine Raspberry Pi kernel |
| `os.kernel-modules` | `igb`, `ixgbe`, `e1000e`, `i40e`, … | `8021q`, `openvswitch`, `vxlan` | GENET is built in, no PCIe NICs; `8021q` carries the zone VLANs |
| `network.interfaces` | the bond members | `eth0`, type `manual` | the one port is the switch trunk (port class `hypervisor`) |
| `network.bonds` | `bond0`, zone ports on `br-fabric` | `[]` | a bond needs two members |
| `network.vlans` | none | `zone401` fabric, `zone403` hypervisor, `zone407` storage on `eth0` | the host's zone addresses (`10.4.{1,3,7}.20/24`) as Linux 802.1Q interfaces |
| `uki.kernel-path` / `initramfs-path` | `-lts` | `/boot/vmlinuz-rpi` / `/boot/initramfs-rpi` | the `linux-rpi` file names |
| `install-target`, `boot.firmware` | unset (ISO install, UEFI) | `image`, `uboot` | Phase A runs on the build host; U-Boot carries the Secure Boot keys |
| `hardware-manufacturer` / `hardware-model` | unset | `Raspberry Pi` / `Raspberry Pi 4 Model B` | the `pkg/quirks` console line |
| `seal-pcrs` | `[7, 9]` | `[0, 4, 7, 9]` | U-Boot's TCG2 measures 0, 4, 7; the EFI stub measures 9 |
| `tpm.idevid` model / serial | `SuperMicro X10` / `sm-compute-01` | `Raspberry Pi 4 Model B` / `rpi4-compute-01` | override the serial with the Pi's `/proc/cpuinfo` serial |
| `os.packages` | no VM packages | adds `qemu-system-aarch64`, `qemu-img`, `swtpm`, `swtpm-tools`, `aavmf` after `lsblk` | the aarch64 compute VMs ([below](#compute-vms)) |

Everything else — `network.role: compute`, `ip-forward: false`, the
`platform-vrf` address, `trust.bmc`, NTS from the control plane, ACME
`enroll-01` and the listener's `device-attest-01`, SDN environment 4 — is the
x10 compute role unchanged. The `bmc` block is kept as the single-node rpi4
template keeps it; the Pi has no BMC.

## A Pi on a flat DHCP network

`rpi4/compute.yaml` assumes the rack: `eth0` is a trunk with the zone VLANs.
A Pi on a flat network instead, such as an access port on the office VLAN 101
with its own DHCP server, is built from the same template with an override
that deletes the rack's network sections and makes `eth0` a DHCP client:

```yaml
os:
  hostname: pi4-01
network:
  dns: null            # the DHCP client writes resolv.conf
  dnsmasq: null
  platform-vrf: null
  vlans: []
  interfaces:
    - name: eth0
      type: dhcp
```

```sh
platformctl diskimage create --target rpi --model rpi4 --role compute \
  --overrides rpi4-flat-dhcp.yaml
```

A `null` deletes the template's key and `[]` replaces its list
([docs/device-templates.md, "Merge Rules"](../../../../../docs/device-templates.md#merge-rules)).
The template file is not changed. The override is
`pkg/cli/commands/diskimage/testdata/rpi4-flat-dhcp.yaml`; its test renders
`iface eth0 inet dhcp` with no 802.1Q or VRF device and no `10.4.x` address.
It changes only `network:` — `dns.resolver`, `trust.bmc`, `ntp` and `acme`
still point at the rack's control plane and need the site's values.

## Smart-card tokens

Every Pi image carries the token stack, whatever the model and role: the image
target adds it, not this template's `os.packages`
([docs/factory-image/engineering.md](../../../../../docs/factory-image/engineering.md)).
The target's lists (`pkg/diskimage/rpi/target.go`: `pcsc-lite`,
`pcsc-lite-openrc`, `ccid`, `opensc`, `yubico-piv-tool-libs`, and the `pcscd`
service) are appended to `os.packages` and `os.services` of the
`configs/installer.yaml` the image bakes from this template, so the installer
installs them and enables pcscd. pcscd starts at boot, and a YubiKey or a
Nitrokey HSM on a USB port answers
PKCS#11 through `libykcs11.so` (YubiKey PIV) or `opensc-pkcs11.so` (Nitrokey
HSM).

## Compute VMs

The Pi 4 runs **aarch64** compute VMs. On an arm64 host the compute `arch`
defaults to `aarch64`, so the template needs no compute keys for it. Each VM:

- runs under KVM with `-cpu host` on the `virt` machine;
- boots UEFI from the AAVMF firmware in `/usr/share/AAVMF`, from the `aavmf`
  package;
- gets an swtpm vTPM as `tpm-tis-device`.

Every default can be overridden under `compute:`. The keys and defaults are in
[docs/compute/engineering.md §4](../../../../../docs/compute/engineering.md#4-configuration).
The package names have not yet been checked against an Alpine 3.22 APKINDEX.

## Raspberry Pi 5 (experimental)

`rpi5/compute.yaml` is `rpi4/compute.yaml` with the Pi 5's name in
`hardware-model` and `tpm.idevid.model`, the serial `rpi5-compute-01`, and
comments on what is unvalidated. It does not carry the compute VM packages.
Every other row of the x10 table above is the same. The image builder knows the board (`pkg/diskimage/rpi`, model `rpi5`:
`bcm2712-rpi-5-b.dtb`, `Experimental`).

What the Pi 5 has, as built:

- **No VideoCore firmware on the card.** The Pi 5 bootloader EEPROM reads
  `config.txt` and loads `kernel8.img` (U-Boot) itself, so the image stages no
  `start*.elf` / `fixup*.dat` (`Model.Firmware` is empty).
- **The same `config.txt`, U-Boot board and overlay** as the Pi 4: U-Boot
  `rpi_arm64` as `kernel8.img`, `dtoverlay=tpm-soft-spi`,
  `dtoverlay=disable-bt`.

What is unvalidated — no Pi 5 has booted the image:

- **The TPM, and with it every seal PCR.** On the Pi 5 the 40-pin header's
  GPIO and SPI belong to the RP1 I/O chip behind PCIe. The U-Boot build
  bit-bangs the SLB9670 over the BCM2835 GPIO controller
  (`build/docker/uboot-builder/configs/rpi_arm64-tpm.config`,
  `configs/tpm-soft-spi.dts`), and its README states the Pi 5 is unvalidated
  there. If U-Boot cannot reach the TPM it measures nothing into PCRs 0, 4
  and 7, and the EFI stub's PCR 9 goes through U-Boot's TCG2 too, so
  `seal-pcrs: [0, 4, 7, 9]` cannot seal. Making it work is a U-Boot change
  (an RP1 GPIO path, or another TPM transport) and a hardware run; the
  template does not paper over it.
- **The serial console.** The Pi 5 firmware and U-Boot log to the dedicated
  debug-UART connector, and GPIO 14/15 is an RP1 UART. The `pkg/quirks`
  Raspberry Pi entry (`console=ttyAMA0,115200 console=tty1`) is the Pi 4's;
  HDMI (`tty1`) is still `/dev/console`.
- **Ethernet.** The port is a Cadence GEM (`macb`) on RP1, not the Pi 4's
  GENET; that Alpine `linux-rpi` brings it up as `eth0` is unverified.
- **Signed boot.** The Pi 5 OTP burn and secure boot are UNSUPPORTED until
  hardware validation ([docs/factory-image/user.md](../../../../../docs/factory-image/user.md)).

## Boot and where diskless-nbd slots in

The node boots from its SD card: Pi firmware → U-Boot → signed UKI →
`platform-initrd` → LUKS root sealed to the TPM. It does not depend on the
diskless NBD root (#689). When the installer target `nbd` lands, a diskless
Pi compute node keeps this template's role, network and identity and changes
only its root: `boot_model: diskless-nbd` in `bootstrap.yaml`, the export on
the provisioning segment (VLAN 405), LUKS + TPM on the NBD device instead of
`/dev/mmcblk0`. That model is specified in
[docs/installer/architecture.md, "Diskless over NBD"](../../../../../docs/installer/architecture.md)
and its node-side status in
[docs/installer/engineering.md](../../../../../docs/installer/engineering.md)
(`diskless-nbd` node side).

## Why there is no gateway template

The gateway's firewall, zone-matrix and NAT64 pipelines classify on the VLAN
tag of traffic entering `br-fabric` (`pkg/sdn/gateway/zoneflows/generators.go`,
`CompileMatrixRules` and `CompileStatefulMatrixRules`;
`pkg/sdn/gateway/nat64/service.go`). The zone ports that carry those tags are
created only from a bond's VLANs (`pkg/app/sdn.go`), and a bond needs two
members (`pkg/installer/types.go`). A Pi 4 or Pi 5 has one port, so its zone addresses
can only be Linux 802.1Q interfaces, and routed traffic between them would
bypass the pipelines — a gateway that forwards without enforcing. The x10
`gatewayd.yaml` also takes two WAN NICs, and `jool-modules-lts` (the NAT64
translator, `pkg/config/gateway_role.go`) is built for `linux-lts`, not
`linux-rpi`.

## Why there is no control-plane template

The control plane embeds go-qrdb, which the platform consumes as a Go source
module through go-quicbaas (`go.mod`), not as a released binary. It
cross-compiles for arm64 with the rest of the daemon (`make build-arm64`,
`make rpi-binaries`), so there is no separate arm64 release to wait for;
running a Raft control plane on a Pi is a resource question that has not been
measured.
