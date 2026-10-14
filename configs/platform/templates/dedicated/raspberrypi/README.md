# Raspberry Pi — dedicated profile

A Raspberry Pi 4 as a **compute** node of the dedicated profile, joining the
x86 control plane and gateway of [`supermicro/x10/`](../supermicro/x10/). It
ships as a factory SD-card image, not an installer ISO:

```sh
platformctl diskimage create --target rpi --model rpi4 --role compute \
  --overrides node.yaml --ca-bundle cp-ca.pem
```

`--role compute` builds [`rpi4/compute.yaml`](./rpi4/compute.yaml). A role or
model with no file here is refused (`ErrRoleTemplate`); the build never falls
back to the single-node image. The image pipeline is
[docs/factory-image/](../../../../../docs/factory-image/), and the hardware
prerequisites (SLB9670 TPM HAT, serial console) are those of
[`single-node/raspberrypi/`](../../single-node/raspberrypi/README.md).

| Role | Template | Status |
|---|---|---|
| compute | `rpi4/compute.yaml` | Builds; loads and validates against the reference network; no hardware run yet |
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

Everything else — `network.role: compute`, `ip-forward: false`, the
`platform-vrf` address, `trust.bmc`, NTS from the control plane, ACME
`enroll-01` and the listener's `device-attest-01`, SDN environment 4 — is the
x10 compute role unchanged. The `bmc` block is kept as the single-node rpi4
template keeps it; the Pi has no BMC.

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
members (`pkg/installer/types.go`). A Pi 4 has one port, so its zone addresses
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
