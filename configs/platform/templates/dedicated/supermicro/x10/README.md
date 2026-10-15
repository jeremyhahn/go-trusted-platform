# Supermicro X10 — deployment profile

Templates in this directory target Supermicro X10-generation boards
(X10SDV / X10SRi / X10DRi class). This file records what the **hardware**
needs before any of them will install — settings that live in BIOS setup
and cannot be expressed in a template. Read it before the first PXE install
of a node, and again before a re-provision.

Every item below was measured on the X10 reference nodes on 2026-09-13, not
taken from a manual. Each one cost at least one install cycle to discover.

## BIOS settings required for UEFI PXE install

The Trusted Platform installer is **UEFI-only** (`docs/installer/user.md`).
It lays down a signed UKI at `EFI/BOOT/BOOTX64.EFI` on a GPT disk and
registers a UEFI NVRAM entry for it. Under legacy BIOS the install
*reports success* and produces a machine that cannot boot (#648 item 4), so
the ROM mode is not optional.

Three settings, all three required. X10 defaults ship with all three wrong.

| Setting | Where | Required value | Default |
|---|---|---|---|
| **Onboard LAN1 Option ROM** | Advanced → PCIe/PCI/PnP Configuration | `EFI` | `Legacy` |
| **Network Stack** | Advanced → Network Stack Configuration | `Enabled` | `Disabled` |
| **IPv4 PXE Support** | Advanced → Network Stack Configuration | `Enabled` | `Disabled` |

LAN1 is `eth0`, the management NIC the templates configure. If a different
port is cabled for management, set that port's Option ROM instead.

### Why all three, and what each failure looks like

- **Option ROM = `Legacy`.** The NIC PXE-boots with the legacy ROM. The boot
  server sees `arch 0x0000` and serves `undionly.kpxe`. The installer runs
  under legacy BIOS and produces an unbootable install. This is the state
  to catch *before* the installer runs — see "Verifying" below.
- **Option ROM = `EFI`, Network Stack = `Disabled`.** Switching the ROM
  removes the legacy "Network Card" boot entry from NVRAM, but the firmware
  does **not** create a UEFI network entry until the Network Stack is
  enabled. With no network entry at all, boot order falls straight through
  to the disk and the node silently boots its old OS. Zero DHCP traffic.
- **All three set.** The firmware enumerates a `UEFI: IP4 …` boot entry,
  the NIC announces `arch 0x0007`, and the boot server serves `ipxe.efi`.

The UEFI network entry may not appear until the **second** reboot after
enabling the stack; Supermicro enumerates it late.

## UEFI PXE does not complete on this firmware

**Set the LAN Option ROM to `Legacy` for a PXE install on these boards.** The
UEFI path gets an address and then stops:

```
arch 0x0007  →  Discover → Offer → Request → ACK   (Your-IP, siaddr, file ipxe.efi)
             →  zero TFTP packets, ever
```

Measured repeatedly on 2026-09-13 against a server whose DHCP and TFTP are both
known good (the same server, same boot, serves the legacy ROM a complete
install; `ipxe.efi` fetches correctly with a TFTP client). Ruled out by
experiment: DHCP options 66/67 present or absent, options 60/43 present or
absent, one network boot entry or eight, Secure Boot (disabled — `SetupMode=1`,
no PK). The console reports `no media presence`, which suggests the UEFI PXE
attempt aborts on link state before TFTP and the DHCP exchange observed is the
UEFI network stack configuring itself afterwards.

The legacy ROM completes TFTP and installs reliably on the same NIC, port and
cable. Until the UEFI path is understood, legacy is the supported PXE mode here.
Note the trade-off: a legacy install cannot register a UEFI NVRAM entry (see
"NVRAM BootOrder" below), so the node needs `UefiHdd` / `Continuous` set on the
BMC afterwards to boot its installed UKI.

Changing the Option ROM mode **adds and removes boot entries**: setting it to
`EFI` deletes the legacy `Network Card` entry and (once the Network Stack is
enabled) creates one `UEFI: IP4 …` entry per port; setting it back to `Legacy`
reverses that. Re-check the boot order after either change.

## What the BMC can and cannot do on this firmware

Measured against the X10 BMC (Redfish `ComputerSystem.v1_3_0`, IPMI 2.0):

- **`BootSourceOverrideTarget` offers `Pxe` but not `UefiPxe`**, and there
  is no `BootSourceOverrideMode`. A `Pxe` override fires the **legacy** ROM
  regardless of the OPROM setting and regardless of NVRAM boot order. Do not
  use the override to trigger a UEFI PXE install; it cannot.
- **IPMI `chassis bootdev pxe options=efiboot` does not switch the ROM
  mode** either. The `efiboot` option is accepted and ignored for network.
- **`chassis bootparam get 5` reports `BIOS PC Compatible (legacy) boot`
  on a node that is verifiably UEFI-booted** (`/sys/firmware/efi` present).
  That line is not a boot-mode signal; do not read it as one.
- `UefiHdd` **is** offered and works. It is the recovery path for a node
  that installed correctly but whose firmware falls through to PXE: set
  `UefiHdd` / `Continuous` and the installed UKI boots on every reset.

The only way to get a UEFI PXE boot on this firmware is the NVRAM
**BootOrder** with the UEFI network entry first — no override involved.

## NVRAM BootOrder and the installer

The installer deliberately writes its `Trusted Platform` UKI entry **first**
in BootOrder (`pkg/installer/installer.go`, `[UEFI] Creating NVRAM boot
entry`). That is a workaround for the X10 *legacy* PXE bug `PXE-E79: NBP is
too big to fit in free base memory`, which otherwise halts the firmware at
"Reboot and Select proper Boot device" instead of falling through to the
disk. It assumes re-installs arrive through a BMC `Cd` override.

Consequence: after one successful install, a UEFI network entry that the
BIOS boot-order screen shows *above* "Hard Disk" is still **below**
`Trusted Platform` in NVRAM, because `Trusted Platform` is a file-path entry
outside the device-class grouping the screen displays. A plain reset boots
the UKI; the node never netboots. To re-provision over PXE, move the UEFI
network entry ahead of it (from the running OS via `efivars`, or in BIOS
setup), then reset. With the OPROM set to `EFI` the `PXE-E79` bug does not
apply and network-first is safe.

## Verifying before the installer touches the disk

The boot server logs the client architecture on the first DHCP Discover.
Check it **before** autoinstall starts — the installer does not refuse a
legacy boot (#648):

```
"arch":"0x0000"  boot_file undionly.kpxe   → legacy ROM: power the node off NOW
"arch":"0x0007"  boot_file ipxe.efi        → UEFI: let the install run
```

The Discover arrives ~60–90 s after power-on; autoinstall does not start
partitioning until ~2 min after that, so there is time to abort.

## Certificate identity: which CA issues what

The control plane is the enterprise/privacy CA for this profile. It enrols
every other node and issues that node its IAK and IDevID over ACME
`enroll-01`, so the node's device identity chains to the control-plane CA —
not to anything the node minted itself.

That has a consequence for the node's own TLS listener, and it is the reason
`gateway.yaml` and `compute.yaml` set:

```yaml
certificate:
  acme:
    challenge: device-attest-01
```

Without it, `issueWebServiceCertificate` falls to its local-CA branch and the
node serves a certificate issued by its OWN CA (`ca01.gw…`, `ca01.compute…`).
Two things then fail, both silently:

- The reporting collector verifies a node against the platform anchor — the
  control-plane CA, and nothing else.
  A locally-issued certificate cannot chain there, so the collector's mTLS
  fails against every node and remote attestation produces no verdict.
- The bootstrap orchestrator's post-install health probe verifies against the
  control-plane bundle it captured during the CP phase, and fails identically.

`device-attest-01` makes the node prove the enrolment it already holds and
take its operational certificate from the control-plane CA, per
`docs/architecture/deployment-reference.md` — *"auto-enroll with
control-plane CA via custom ACME extensions (enroll-01, device-attest-01)"*.

**The control plane itself is the exception** and deliberately has no
`acme.challenge` on its listener: it is the CA, so it issues its own.

`control-plane.yaml` also carries the `attestation.reporting` block that
starts the collector. That key is also the gate on the control plane
registering itself as a device in its own registry (#472), so a control plane
without it is absent from its own fleet view.

## Gateway node: the NAT64 translator packages

`gateway.yaml` lists Alpine's Jool packages in `os.packages` —
`jool-modules-lts`, `jool-tools` and `jool-tools-openrc` — so the gateway node
can run gatewayd's `nat64:` section. Only the gateway carries them; the control
plane and compute nodes do not run gatewayd. A gateway-role ISO prefetches the
same three into its offline repository.

`gatewayd.yaml` ships the `nat64:` section commented out, because its
`translator-port` and `pool4` addresses are site decisions. Uncommenting it
yields a section the gateway accepts as-is (the profile's template test loads it
that way). With it enabled, the gatewayd init script platformd writes at first
boot runs `modprobe jool` before starting the daemon.

`jool-modules-lts` is built for exactly one `linux-lts` release. Upgrade the
two together: a kernel that outruns the module package leaves `jool`
unloadable, the init script warns and starts gatewayd anyway, and gatewayd
refuses the `nat64:` section (`ErrNAT64ModuleUnavailable`) instead of passing
IPv6-only traffic untranslated. See `docs/gateway/user.md`, "IPv6-only clients".

## Other notes

- **Serial-over-LAN** works (`ipmitool -I lanplus … sol activate`) and the
  templates put the console on `ttyS1,115200n8`, but the SOL session shows
  only *new* output — a static screen (BIOS setup, an idle prompt) reads as
  empty. Send a key to refresh.
- The **SEL fills and stops logging**. One control-plane BMC held 512 entries of
  `Correctable ECC @DIMMB1(CPU1)` from 2024 and had disabled logging on
  "Log full". Clear it (`ipmitool sel clear`) after commissioning or the
  event log is useless when you need it.
- A successful install **powers the node off** rather than rebooting
  ("Remove the installation media and reboot"). A powered-off node after
  an install is the success case, not a failure.
- **Every secret is a `kms://` reference**, the platform PINs included
  (`platform.so-pin`, `platform.user-pin`). platformd generates them on its
  first start and returns the same values on every start after; nothing
  earlier in the boot reads them. Put no literal PIN or password in an
  override ([docs/device-templates.md](../../../../../../docs/device-templates.md#platform-pins)).


### Gateway overlay fields

`gatewayd.yaml` includes a disabled `gateway.overlay:` example for #709. Fill `local-vtep` with the gateway's fabric VLAN address, `access-port` with the OVS port that carries workload VLANs into the overlay, and `rr-peers` with the control-plane route reflectors. The overlay's EVPN speaker dials those reflectors from `local-vtep` and opens no listener (the transit speaker already holds TCP 179), so each reflector must accept the session from that address, and no RR peer may be `passive`. `vnis` lists the L2VNIs the overlay joins at start, each with the access-port VLAN that carries it (VLAN 401 carries VNI 40100 here); `default-vni` must be one of them, and the overlay reports healthy only while it carries all of them. `verdict-max-age` defaults to 15m and is the maximum age of a signed attestation verdict accepted for remote VTEP admission. `verdict-clock-skew` (30s) bounds how far ahead of the gateway's clock that verdict may be dated, and `admission-sweep-interval` (30s) is how often installed VTEPs are re-admitted. `overlay-asn` must be a private 2-octet ASN (64512-65534). The overlay cannot be enabled beside the firewall, NAT or load balancer, so enabling it on this profile means disabling `gateway.firewall`.
