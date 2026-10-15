# Raspberry Pi — dedicated profile

A Raspberry Pi 4 — or, experimentally, a Pi 5 — as a **compute** node of the
dedicated profile, joining the x86 control plane and gateway of [`supermicro/x10/`](../supermicro/x10/),
and a Compute Module 4 or a Pi 4 as a standalone **control plane**
([below](#control-plane)). It ships as a factory SD-card image, not an
installer ISO:

```sh
platformctl diskimage create --target rpi --model rpi4 --role compute \
  --overrides node.yaml --ca-bundle cp-ca.pem
```

`--role compute` builds [`rpi4/compute.yaml`](./rpi4/compute.yaml), or
[`rpi5/compute.yaml`](./rpi5/compute.yaml) with `--model rpi5`;
`--role control-plane` builds [`cm4/control-plane.yaml`](./cm4/control-plane.yaml)
with `--model cm4`, or [`rpi4/control-plane.yaml`](./rpi4/control-plane.yaml).
A model the builder does not know, a role that is not `gateway`,
`control-plane` or `compute`, or a role or model with no file here, is refused
(`ErrRoleTemplate`); the build never falls back to the single-node image. The image pipeline is
[docs/factory-image/](../../../../../docs/factory-image/), and the hardware
prerequisites (SLB9670 TPM HAT, serial console) are those of
[`single-node/raspberrypi/`](../../single-node/raspberrypi/README.md).

| Role | Template | Status |
|---|---|---|
| compute | `rpi4/compute.yaml` | Builds; loads and validates against the reference network; no hardware run yet |
| compute | `rpi5/compute.yaml` | **Experimental**: builds, loads and validates; TPM, console and Ethernet unvalidated on a Pi 5 ([below](#raspberry-pi-5-experimental)) |
| control-plane | `cm4/control-plane.yaml` | Builds; loads and validates against the reference network; standalone, no hardware run yet ([below](#control-plane)) |
| control-plane | `rpi4/control-plane.yaml` | As `cm4`, for a Pi 4 Model B |
| gateway | none | Not supported on a one-port Pi (below) |

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
| `tpm.idevid` model / serial | `SuperMicro X10` / `sm-compute-01` | `Raspberry Pi 4 Model B` / `rpi4-compute-01` | an SD-booted or `diskless-nbd` Pi overrides the serial with its `/proc/cpuinfo` serial, and bootstrap refuses two such Pis on one serial; a `diskless` Pi keeps it, since platformd replaces it with the Pi's EK-derived name at every boot |
| `os.packages` | no VM packages | adds `qemu-system-aarch64`, `qemu-img`, `swtpm`, `swtpm-tools`, `aavmf` after `lsblk` | the aarch64 compute VMs ([below](#compute-vms)) |

Everything else — `network.role: compute`, `ip-forward: false`, the
`platform-vrf` address, `trust.bmc`, NTS from the control plane, ACME
`enroll-01` and the listener's `device-attest-01`, SDN environment 4 — is the
x10 compute role unchanged. The `bmc` block is kept as the single-node rpi4
template keeps it; the Pi has no BMC.

## More than one Pi

The template's addresses are one Pi's: `.20` in the platform VRF and in each
zone VLAN. Bootstrap refuses two nodes whose merged configs share an address,
so every further Pi sets its own in its node entry's `overrides:`. `vlans` is a
list and an override replaces it whole, so it repeats all three entries:

```yaml
overrides:
  network:
    platform-vrf:
      address: 10.4.144.21/32
    vlans:
      - {name: zone401, zone: fabric, parent: eth0, ipv4-address: 10.4.1.21/24, auto-start: true}
      - {name: zone403, zone: hypervisor, parent: eth0, ipv4-address: 10.4.3.21/24, auto-start: true}
      - {name: zone407, zone: storage, parent: eth0, ipv4-address: 10.4.7.21/24, auto-start: true}
```

A Pi netbooted diskless (`boot_model: diskless` or `diskless-nbd`) also needs
`install-target: disk`: its installer runs on the Pi, and bootstrap refuses
the template's `image`. `eth0` stays `manual` for a diskless Pi too; the
compute role holds no provisioning (VLAN 405) address. The
[tgw-01 example](../../../../bootstrap/tgw01-vlan405.example.yaml) does both
for three Pis.

## A Pi on a flat DHCP network

`rpi4/compute.yaml` assumes the rack: `eth0` is a trunk with the zone VLANs.
A Pi on a flat network instead, such as an access port on the office VLAN 101
with its own DHCP server, is built from the same template with an override
that deletes the rack's network sections and makes `eth0` a DHCP client:

```yaml
os:
  hostname: pi4-01
network:
  role: null           # a compute role refuses DHCP; see below
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
`pkg/cli/commands/diskimage/testdata/rpi4-flat-dhcp.yaml`. Its test
(`flat_dhcp_test.go`) loads the merged result through the host-network check
platformd runs at startup, then renders `iface eth0 inet dhcp` with no 802.1Q
or VRF device and no `10.4.x` address.

`role: null` is what lets platformd load it. A compute role permits only
static addresses in its zones (`pkg/installer/network_role.go`), so with the
template's role kept a DHCP `eth0` is refused (`ErrDHCPNotPermitted`). With no
role the addressing is not constrained, and the role's host hardening goes
too: no forward-drop nftables table, no forwarding sysctl, nftables is not
installed (`pkg/installer/alpine_hostnet.go`, `alpine.go`), and a
network-configuration failure during install is logged rather than fatal
(`pkg/installer/installer.go`). The kernel default — no forwarding — still
applies.

It changes only `network:` — `dns.resolver`, `trust.bmc`, `ntp` and `acme`
still point at the rack's control plane and need the site's values.

## Secrets

Every secret in these templates is a `kms://` reference, the platform PINs
included (`platform.so-pin`, `platform.user-pin`). platformd generates them on
its first start and returns the same values on every start after; nothing
earlier in the boot reads them. Put no literal PIN or password in an override
such as `cm4/desk-overrides.yaml`
([docs/device-templates.md](../../../../../docs/device-templates.md#platform-pins)).

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

## Control plane

`cm4/control-plane.yaml` is `supermicro/x10/control-plane.yaml` with the Pi
rows of the compute table above; `rpi4/control-plane.yaml` is the same file
for a Pi 4 Model B. Each is a full copy — templates have no include mechanism.

| Key | x10 | cm4 / rpi4 |
|---|---|---|
| `disk.device` / `partition-table` | `""` / `gpt` | `/dev/mmcblk0` / `mbr` |
| `os.architecture` / `kernel-package` | `x86_64` / unset (`linux-lts`) | `aarch64` / `linux-rpi` |
| `network.interfaces` / `bonds` | the bond members / `bond0` | `eth0`, type `manual` (the trunk) / `[]` |
| zone addresses | `10.4.1.10/24` fabric, `10.4.6.10/24` control-plane on the bond | the same two as 802.1Q interfaces `zone401`, `zone406` on `eth0` |
| `uki` paths, `install-target`, `boot.firmware` | `-lts`, ISO install, UEFI | `-rpi`, `image`, `uboot` |
| `hardware-manufacturer` / `hardware-model` | unset | `Raspberry Pi` / `Raspberry Pi Compute Module 4` or `Raspberry Pi 4 Model B` |
| `seal-pcrs` | `[7, 9]` | `[0, 4, 7, 9]` |
| `tpm.device` | `/dev/tpmrm0` | `/dev/tpmrm0`, the SLB9670 on SPI0 CE1; fails closed if absent |
| `tpm.idevid` model / serial | `SuperMicro X10` / `sm-cp-01` | the board name / `cm4-cp-01` or `rpi4-cp-01`; override with `/proc/cpuinfo`'s serial |

Everything else is the x10 control plane: `network.role: control-plane`, its
CA and ACME server, internal and public DNS, NTP serving, attestation
collector, SDN controller and webservices. QuicBaaS runs standalone —
`storage-backend: file`, `node-id: 1`, no `join-addresses` — so no Raft
consensus is engaged.

Prerequisites:

- **The TPM HAT.** An SLB9670 on SPI0 CE1, the same HAT and `tpm-soft-spi`
  overlay as the compute image
  ([`single-node/raspberrypi/`](../../single-node/raspberrypi/README.md)).
  The IDevID, the CA's TPM keys and the LUKS seal live in it, and
  `tpm.device: /dev/tpmrm0` names the hardware TPM explicitly, which never
  falls back to a software TPM.
- **Memory.** The templates are sized for **8 GB of RAM**. That is the owner's
  stated figure, not a measurement: confirm it from `/proc/meminfo` at the
  first ssh.
- **A CM4 that boots its SD slot**: a CM4 Lite, on a carrier with an SD slot.
  An eMMC CM4 boots its eMMC. The SD image steps are in
  [docs/factory-image/user.md, "CM4 SD card"](../../../../../docs/factory-image/user.md#cm4-sd-card).

### On the rack and on the desk

As shipped, the template is the rack form: `eth0` is a switch trunk carrying
the fabric (401) and control-plane (406) zones, and the gateway owns each
zone's `.1` ([docs/architecture/deployment-reference.md](../../../../../docs/architecture/deployment-reference.md)).

The desk form is [`cm4/desk-overrides.yaml`](./cm4/desk-overrides.yaml): one
static address, `192.0.2.10/24` on the provisioning segment (VLAN 405), on an
untagged `eth0`, with no router and no default gateway.

```sh
platformctl diskimage create --target rpi --model cm4 --role control-plane \
  --overrides configs/platform/templates/dedicated/raspberrypi/cm4/desk-overrides.yaml
```

The override is an example file beside the template, not a template: `--role`
never builds it. It sets `network.role: null`, deletes `platform-vrf`, empties
`vlans`, makes `eth0` static and points `dns.nameservers` at `192.0.2.10`.
`role: null` is needed because a control-plane role permits addresses in the
fabric, hypervisor, storage and control-plane zones only and requires a fabric
address (`pkg/installer/network_role.go`); `192.0.2.10` is in provisioning. The
role rule is unchanged. A null role costs the host hardening described for the
[flat DHCP override](#a-pi-on-a-flat-dhcp-network): no forward-drop nftables,
no forwarding sysctl, and a non-fatal network failure at install.
`pkg/cli/commands/diskimage/desk_overrides_test.go` loads the merged result
through the host-network check platformd runs at startup and renders it.

What the desk control plane does without a gateway (lines of
`cm4/control-plane.yaml`):

- **Its own, and unaffected:** the CA (`certificate-authority`, :905) and its
  ACME server (internal webservice, :1188; the client directory
  `cp.example.internal:9443`, :594); internal DNS on port 9053 (:426); NTP
  serving, which allows `192.0.2.0/24` (:537) under the NTS name
  `cp.example.internal` (:581); the QuicBaaS store (:690).
- **Lost — the route out:** the public DNS forwarders `1.1.1.1` and `8.8.8.8`
  (:363-364) and the resolver fallback (:314-315); the preferred NTP upstream
  `10.4.6.1` (:510), which is the gateway's control-plane address and is not on
  the desk; `pool.ntp.org` (:516); the BMC at `10.4.2.20` (:677).
- **NTP warns and carries on:** the startup gate blocks for 120 s (:523-524),
  then `on-timeout: warn-and-continue` (:528) boots the node flagged
  time-unsynced in health; `orphan-fallback: true` (:531) keeps it serving its
  own clock to the desk.
