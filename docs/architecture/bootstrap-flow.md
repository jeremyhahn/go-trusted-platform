# Bootstrap Flow — End-to-End Architecture

> **Status: REFERENCE** · Last verified: 2026-10-13
> The end-to-end bootstrap path across BMC, installer, firstboot and daemon; [../bootstrap/](../bootstrap/) is normative.

Master reference for how `platformctl bootstrap run` produces a working
Trusted Platform deployment — from BMC discovery through
virtual-media install to `platformd` serving requests.

**Audience:** operators deploying real hardware, and developers modifying
`pkg/bootstrap/`, `pkg/iso/`, `pkg/ipxe/`, or `pkg/cli/commands/iso/`.

**Scope:**
- Single-node deployment (CP + GW collocated)
- 3-node dedicated deployment (CP, GW, compute on separate boxes)
- HA cluster (documented at a high level; see `deployment-reference.md` §3)

**Not in scope:**
- Post-bootstrap re-provisioning — see `docs/provisioning/config-delivery.md`
- Production ACME renewal / certificate lifecycle — see `docs/ca/acme.md`
- Factory reset — see `docs/installer/factory-reset.md`

---

## 1. Process-Level Architecture

Trusted Platform uses a **two-daemon sidecar model** on every deployment
topology. Control-plane services and data-plane services run in separate
processes even when collocated on a single box.

```
┌─────────────────────────────────────────────────────────────────┐
│ Any node running Trusted Platform services                       │
│                                                                  │
│  ┌──────────────────────┐      ┌────────────────────────┐       │
│  │  platformd           │      │  gatewayd              │       │
│  │  (control plane)     │      │  (data plane)          │       │
│  │                      │      │                        │       │
│  │  Host services:      │      │  BGP, DHCP server      │       │
│  │   • TPM/vTPM         │      │  Firewall, NAT         │       │
│  │   • QEMU/KVM         │      │  Load-balancer         │       │
│  │   • LUKS             │      │  Tunnels (GRE/VXLAN)   │       │
│  │                      │      │  Edge onboarding       │       │
│  │  Services:           │      │  Overlay (EVPN)        │       │
│  │   • CA, ACME         │      │  OVS bridge (own       │       │
│  │   • DNS authoritative│      │   OVSDB connection)    │       │
│  │   • IAM, KMS         │      │                        │       │
│  │   • QuicBaaS         │      │  metrics               │       │
│  │   • REST 8443        │      │   127.0.0.1:9169       │       │
│  │   • gRPC 10443       │      │                        │       │
│  │   • QUIC 9444        │      │                        │       │
│  │   • MCP 9445         │      │                        │       │
│  │   • Unix /run/       │      │                        │       │
│  │     platformd.sock   │      │                        │       │
│  └──────────────────────┘      └────────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

**Privilege boundary**: `platformd` is one process; after start-up it
can drop to the user named by `--setuid` (`pkg/app/privileges.go`).
`gatewayd` owns its OVS bridge through its own OVSDB connection, and can
run sections in privilege-dropped child processes
(`gatewayd service run <process>`, `pkg/sdn/gateway/process/`).

See [`../daemon/`](../daemon/) and [`../gateway/architecture.md`](../gateway/architecture.md)
for the full process model.

### Why not one process?

| Concern | One process | Two processes (current) |
|---------|-------------|-------------------------|
| Privilege surface | Combined caps (TPM + network) | Smallest caps per daemon |
| Failure isolation | BGP crash kills CA | BGP crash leaves CA up |
| Scale-out to dedicated GW node | Requires extracting from monolith | Config + systemd unit move |
| Operational parity single-node ↔ 3-node | Two code paths | Same binaries, same code paths |
| IPC overhead | 0 | Unix socket (hot paths negligible) |

The two-process model is a load-bearing decision. Do not collapse it
into a single binary without revisiting this tradeoff explicitly.

---

## 2. Deployment Topologies

### 2.1 Single-node (default for `platformctl iso create` with no flags)

```
┌─────────────────────────────────────────────────────┐
│  trusted-platform.local                             │
│                                                     │
│   platformd (server) + gatewayd                     │
│   ├── eth0  (DHCP from upstream ISP/router)         │
│   ├── br-fabric (OVS: every zone, host-local)       │
│   └── br-int    (OVS: VMs and pods)                 │
│                                                     │
│   systemd target: trusted-platform.target           │
│     ├── platformd.service                           │
│     └── gatewayd.service  (After=platformd.service) │
└─────────────────────────────────────────────────────┘

Default template: configs/platform/templates/single-node/default.yaml
```

### 2.2 3-node dedicated

```
                    Internet
                      │
                 Core Router / Switch
                      │
      ┌───────────────┼───────────────┐
      │               │               │
   ┌──▼───┐      ┌────▼───┐      ┌────▼─────┐
   │gw-01 │      │ cp-01  │      │compute-01│
   │      │      │        │      │          │
   │ptfmd │      │ ptfmd  │      │  ptfmd   │
   │gtwyd │      │ (SRV)  │      │ (CLIENT) │
   │(CLNT)│      │        │      │          │
   └──────┘      └────────┘      └──────────┘
```

- cp-01 (SERVER): CA, ACME, DNS authoritative, IAM, KMS, QuicBaaS
- gw-01 (CLIENT): platformd client + gatewayd (BGP, DHCP, NAT, firewall)
- compute-01 (CLIENT): platformd client + QEMU/KVM workloads

Templates: `configs/platform/templates/dedicated/<vendor>/<model>/{control-plane,gateway,compute}.yaml`

### 2.3 HA cluster (3 CP + 2 GW + N compute)

High-level — see `deployment-reference.md` §3.

---

## 3. Install-Time Config Resolution

The platform ISO resolves its device config using a three-tier priority
chain. This is the single most important architectural decision to
understand: **config can be baked (default) or fetched dynamically, but
never both from the same source.** Baked serves as a fallback when
dynamic is requested.

```
                       ISO boots on node
                              │
                              ▼
        ┌─────────────────────────────────────────┐
        │ Kernel cmdline has platform_config=URL? │
        └───────────┬─────────────────┬───────────┘
                    │ yes             │ no
                    ▼                 │
    ┌───────────────────────────┐     │
    │ PRIO 1 — Dynamic fetch    │     │
    │   Discover local MAC      │     │
    │   GET <URL>/<mac-dashed>/ │     │
    │       installer.yaml      │     │
    │   2xx → use body          │     │
    │   non-2xx → fall through  │     │
    └────────┬──────────────────┘     │
             │ fail                   │
             ▼                        ▼
    ┌─────────────────────────────────────┐
    │ PRIO 2 — Baked                      │
    │   /media/cdrom/configs/             │
    │     installer.yaml exists?          │
    │   use it                            │
    └─────────┬───────────────────────────┘
              │ absent
              ▼
    ┌─────────────────────────────────────┐
    │ PRIO 3 — Fatal                      │
    │   drop to shell, print diagnostics  │
    └─────────────────────────────────────┘
```

**Hostname resolution runs independently** (even when PRIO 2 wins the
config race):

```
PRIO -1: GET /config/mac/<mac>/hostname   (orchestrator-published)
PRIO  0: platform_hostname=X kernel cmdline
PRIO  1: installer.yaml's os.hostname key
PRIO  2: Alpine live-env `hostname` command (fallback)
```

Having hostname as a separate fetch lets a **shared ISO** serve CP
and GW installs simultaneously: each node gets its role's full config
AND its per-node hostname, both keyed by MAC.

---

## 4. `platformctl iso create` — Three Modes

```
                    platformctl iso create
                             │
      ┌──────────────────────┼──────────────────────┐
      │                      │                      │
      ▼                      ▼                      ▼
  (no flags)           --platform-config X       --config-server URL
                       [--overrides Y]           [--platform-config X]
                                                 [--overrides Y]
      │                      │                      │
      ▼                      ▼                      ▼
  Use default           Merge X + Y            Dynamic fetch at boot
  single-node           Bake result            Kernel cmdline:
  template,             into ISO                 platform_config=<URL>
  bake into ISO                                If X also provided:
                                                bake as PRIO 2 fallback
```

| Mode | When to use |
|------|-------------|
| **Default baked** | Single-node deployments, offline labs, operator-preferred "just works" |
| **Custom baked** | Multi-node where each role gets its own pre-built ISO |
| **Dynamic** | Multi-node where one shared ISO installs all roles (CP + GW + compute) via MAC keying |
| **Hybrid** | Dynamic preferred + baked as safety net if the config server is unreachable |

### The factory image is the baked mode without a live installer

`platformctl diskimage create` (`pkg/diskimage`, [docs/factory-image/](../factory-image/))
stages the same media `iso create` does (`(*iso.Customizer).StageMedia` in `pkg/iso`: prefetched
apks for the target architecture, the platform binaries, the merged
platform config, Secure Boot keys, CA bundle) and then runs Phase A itself,
on the build host, inside an arm64 container against a loop-mounted image
(`installer.Config.Target = image`). The config delivery is therefore
**default baked** or **custom baked** only — there is no live installer on
the device to fetch a dynamic config — and the device's first boot is the
unchanged Phase B (platform-initrd unlock, firstboot provisioning and
sealing, platformd). The Raspberry Pi is the first target; the QEMU virt
stand-in exists so the chain is tested without the hardware.

### Diskless image boot is the stateless sibling of the factory image

The diskless image path reuses the media pipeline but serves the root over the
boot server instead of writing it to local block storage. A media set built
with `diskimage netboot --diskless` carries a squashfs of the installed root,
a separate dm-verity hash tree, and a manifest of the root hash, salt and
sizes signed with the Secure Boot DB key. Diskless is chosen per node:
`boot_model: diskless` in `bootstrap.yaml` reaches the container manifest, and
only that node's device script adds `platform_boot_model=diskless`. The root
hash is never served as mutable metadata or taken from a command line the
network supplies: the installer verifies the signed manifest against the DB
certificate and writes `platform_roothash=` (not systemd's `roothash=`, which
dracut's systemd-veritysetup generator would also act on), the salt, the sizes
and `platform_rootfs_url=` / `platform_verity_url=` into the UKI command line
it signs, so Secure Boot and measured boot bind the fetched root to the
verified UKI.

During early boot the dracut hooks read `platform_boot_model=diskless` from the
signed command line and take the diskless branch: they wait on and unlock no
local root, bring the network up, and run `platform-initrd boot --diskless`. A
disk node's command line carries no diskless parameter and its hooks unlock
LUKS exactly as before. `platform-initrd` fetches both files into bounded
tmpfs, opens the root as a device-mapper verity table with the signed root
hash and pinned parameters, mounts the squashfs read-only, and overlays it
with tmpfs at `/sysroot`. dm-verity checks every block as it is read, so a
substituted image panics the node at the squashfs mount instead of booting.
After `switch_root` the node is stateless. There is no LUKS root to seal, so
the `tpm-firstboot-seal` service exits before its LUKS lookup. `platformd` reads the boot model from the
kernel command line and decides provisioning from the TPM alone: a TPM holding
the EK, SSRK, Platform SRK, IAK and IDevID at their persistent handles is
adopted untouched on every boot, and an unprovisioned one runs first
provisioning once ([docs/tpm/architecture.md §4d](../tpm/architecture.md)).
On every later boot the identity certificates are gone with the tmpfs, so
`platformd` fetches them back from the control plane rather than re-mint them.
It presents its recorded IDevID over mTLS with the TPM-resident key and
answers an IAK quote bound to that TLS connection. The control plane runs the
device quote verifier and returns that device's IDevID chain, IAK
certificate, the platform CA bundle and its profile
([docs/device/api.md §4.6](../device/api.md)). Any refusal stops startup at
`ErrDisklessIdentityUnavailable`.

---

## 5. End-to-End Bootstrap Sequence (multi-node, dynamic)

```
  ┌────────┐          ┌────────────────┐         ┌──────────┐
  │Operator│          │ Deployer host  │         │ Target   │
  │        │          │ (jumpbox)      │         │ node BMC │
  │platfrm │          │                │         │          │
  │ctl     │          │ pxeboot        │         │ Redfish/ │
  │bootstrp│          │ container      │         │ IPMI     │
  │ run    │          │  • SMB share   │         │          │
  │        │          │  • HTTP :8080  │         │          │
  └────┬───┘          │    /config/mac │         └────┬─────┘
       │              │    /install-log│              │
       │              │    /ipxe       │              │
       │              └────────┬───────┘              │
       │                       │                      │
       │── SSH ────────────────▶                      │
       │                       │                      │
       │──── Phase 0: Discovery ──────────────────────▶
       │                                              │
       │       query BMCs for MACs, vendor, firmware  │
       │◀─────────────────────────────────────────────│
       │                                              │
       │──── Phase 4: Seed (merge + publish) ──────▶  │
       │                       │                      │
       │      for each node:   │                      │
       │        template + overrides → YAML           │
       │        for each MAC:  │                      │
       │          PUT /config/mac/<mac>/installer.yaml│
       │          PUT /config/mac/<mac>/hostname      │
       │                       │                      │
       │──── Phase 5: Boot ───────────────────────────▶
       │                       │                      │
       │   stage ISO to SMB    │                      │
       │──────────────────────▶│                      │
       │                       │                      │
       │   BMC: mount vmedia + set boot-once + reboot │
       │──────────────────────────────────────────────▶
       │                                              │
       │                                   ┌──────────▼────────┐
       │                                   │ Node POST         │
       │                                   │ BIOS → boot ISO   │
       │                                   │                   │
       │                                   │ autoinstall.sh:   │
       │                                   │  discover MAC     │
       │                                   │  GET /config/mac/ │
       │                                   │    <mac>/         │
       │                                   │    installer.yaml │
       │                                   │  GET /config/mac/ │
       │                                   │    <mac>/hostname │
       │                                   │                   │
       │                                   │  partition disks  │
       │                                   │  LUKS2 + TPM seal │
       │                                   │  install UKI      │
       │                                   │  reboot to disk   │
       │                                   │                   │
       │                                   │  platformd starts │
       │                                   │  POST install-log │
       │                                   └──────────┬────────┘
       │                                              │
       │◀── Phase 6: Watch — install-log upload ──────│
       │                                              │
       │   Phase 5a: BMC Enroll (if bmc_enroll: true)│
       │      POST /api/v1/bmc/{profileID}/enroll     │
       │      write backups (factory-cert + meta)     │
       │      per-node non-fatal; all outcomes logged │
       │                                              │
       │   Phase 7: Teardown                          │
       │      BMC unmount vmedia                      │
       │      cleanup SMB stage                       │
       │      (hostname staging persists — needed     │
       │       for re-installs)                       │
       ▼
```

Phase numbering matches `pkg/bootstrap/orchestrator.go` internal states
and `docs/bootstrap/architecture.md` (Data flow — day zero through first boot).

---

## 6. Per-MAC Keying — Why One ISO Serves All Roles

A shared ISO works for CP + GW + compute installs because **config is
keyed by MAC, not by hostname**. The orchestrator publishes each node's
merged config under every MAC address that node owns (YAML-declared
plus BMC-discovered):

```
bootstrap.yaml:                     HTTP server state after Phase 4:
──────────────                      ──────────────────────────────────
nodes:                              /config/mac/aa-bb-cc-11-22-33/
  - hostname: node-02                 installer.yaml  (CP config)
    role: control-plane               hostname        ("node-02")
    macs: [aa:bb:cc:11:22:33]       /config/mac/aa-bb-cc-11-22-44/
    overrides_file:                   installer.yaml  (CP config)
      node-02.control-plane.yaml      hostname        ("node-02")
                                    (all MACs of node-02 map to same config)
  - hostname: gw-01
    role: gateway                   /config/mac/dd-ee-ff-44-55-66/
    macs: [dd:ee:ff:44:55:66]         installer.yaml  (GW config)
    overrides_file:                   hostname        ("gw-01")
      gw-01.gateway.yaml            /config/mac/dd-ee-ff-44-55-77/
                                      installer.yaml  (GW config)
                                      hostname        ("gw-01")
```

At install, `autoinstall.sh` enumerates every NIC on the target node,
tries each MAC against the config server, and the first MAC that
matches wins. Multi-NIC hosts get their role's config regardless of
which interface the live environment enumerates as `eth0`.

---

## 7. Dynamic Config URL Shape

`--config-server` bakes this kernel cmdline parameter:

```
platform_config=http://<deployer>:8080/config/mac
```

At install time, `autoinstall.sh` appends the MAC and file name:

```
http://<deployer>:8080/config/mac/<mac-dashed>/installer.yaml
http://<deployer>:8080/config/mac/<mac-dashed>/hostname
```

where `<mac-dashed>` is lowercase `aa-bb-cc-dd-ee-ff` (colons and
uppercase both rejected by the server).

The HTTP server is `pkg/ipxe/http_server.go`; endpoint handlers are
documented in `docs/ipxe/architecture.md`.

---

## 8. Boundary: Bootstrap vs Post-Bootstrap Config Delivery

Bootstrap-time config delivery (this doc) differs from production
post-bootstrap config delivery (`docs/provisioning/config-delivery.md`):

| Aspect | Bootstrap-time | Post-bootstrap (production) |
|--------|----------------|------------------------------|
| Runs on | Pxeboot container on deployer host | Installed `platformd` on control plane |
| Network | Private deployer network | Public or private management network |
| TLS | Plain HTTP (private net) | HTTPS with mTLS |
| Trust establishment | None — deployer trusts operator | `platformctl-static bootstrap trust` with DANE / Noise / SPKI |
| Authentication | None | EAB (External Account Binding) + nonce |
| Config source | Template + overrides merged by orchestrator | `platformd` device-profile store |
| Device identification | MAC address | TPM EK serial → MAC → prefix match |
| Failure mode | Installer drops to shell | QR session handoff for operator intervention |

The two flows share a URL convention and a kernel cmdline parameter
name but are otherwise independent code paths. Do not confuse them.

---

## 9. Source-of-Truth Pointers

| Concern | File | Doc |
|---------|------|-----|
| Orchestrator phases | `pkg/bootstrap/orchestrator.go` | `docs/bootstrap/architecture.md` (Data flow) |
| Template merge | `pkg/config.DeepMergeYAMLFiles` | `docs/device-templates.md` |
| Per-MAC publishing | `pkg/bootstrap/virtual_media.go::stagePerMACConfig` | `docs/bootstrap/architecture.md` (Phase 3 · Control plane) |
| HTTP config server | `pkg/ipxe/http_server.go` | `docs/ipxe/architecture.md` |
| ISO build (baked mode) | `pkg/iso/customize.go`, `pkg/cli/commands/iso/create.go` | `docs/installer/iso-building.md` |
| autoinstall priority chain | `pkg/iso/customize.go` (embedded shell) | `docs/installer/autoinstall.md` |
| Kernel cmdline params | `pkg/iso/customize.go::buildDynamicConfigParams` | `docs/reference/kernel-cmdline.md` |
| cmdline → trust: YAML mapping | `pkg/trust/config.go`, `pkg/iso/customize.go` lines 3342-3351 | `docs/reference/kernel-cmdline.md` §3a |
| BMC enroll phase (Phase 5a) | `pkg/bootstrap/orchestrator.go` | `docs/bmc/engineering.md` §3.3 |
| Single-node template | `configs/platform/templates/single-node/default.yaml` | `configs/platform/templates/single-node/README.md`, `docs/device-templates.md` |
| Dedicated templates | `configs/platform/templates/dedicated/<vendor>/<model>/` | `configs/platform/templates/dedicated/README.md`, `docs/device-templates.md` |
| OVS bond creation (native OVSDB) | `pkg/app/sdn.go::initOVSBonds`, `pkg/sdn/ovs/port.go::AddBond` | `configs/platform/templates/dedicated/README.md` §Network Architecture |
| DNS via local dnsmasq → CP:9053 | `pkg/installer/alpine.go::configureDNSWithDnsmasq` | `configs/platform/templates/dedicated/README.md` §DNS Resolution |

**Before changing any of the above files, read this doc and the
linked companion doc.** If a change breaks the documented contract,
update the doc in the same commit.
