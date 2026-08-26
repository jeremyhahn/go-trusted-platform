# Dedicated Deployment Profile

Three-node reference architecture: one control-plane, one gateway, one
compute worker. Each role runs on its own physical box. This is the
current production-validated profile and the template the bootstrap
orchestrator targets by default.

For single-box or cluster topologies, see the sibling profiles:
- [`../single-node/`](../single-node/) — CP + GW + compute collocated (lab / edge)
- [`../high-availability/`](../high-availability/) — 3× CP Raft + 2× GW + N× compute (planned)

---

## Topology

```
                        Internet
                           │
                    Upstream ISP / Router
                           │
                      Trusted switch
                       (VLAN-aware)
         ┌─────────────────┼─────────────────┐
         │                 │                 │
    ┌────▼────┐       ┌────▼────┐       ┌────▼────┐
    │ lab-node-1 │       │ lab-node-2 │       │ lab-node-3 │
    │ gateway │       │   CP    │       │ compute │
    │         │       │         │       │         │
    │ gatewayd│       │ platformd        │ platformd│
    │ platformd (CLIENT)  (SERVER) │       │ (CLIENT)│
    └─────────┘       └─────────┘       └─────────┘
      ▲                   ▲                   ▲
      │ trusted0          │ trusted0          │ trusted0
      │ (OVS bond)        │ (OVS bond)        │ (OVS bond)
      │ eth6+eth7         │ eth6+eth7         │ eth6+eth7
      │                   │                   │
      └───────────────────┴───────────────────┘
                  trusted network
                  (LACP / balance-tcp)
```

All three nodes speak to each other over the **`trusted0` OVS bridge**
backed by an **OVS bond** of two physical NICs. The bond is created
natively by `platformd` via OVSDB wire-protocol at runtime (no kernel
bonding driver, no `ovs-vsctl` fork).

---

## Role Responsibilities

| Role | Binaries | Owns |
|------|----------|------|
| **Control plane** (`lab-node-2`) | `platformd` (server mode) | CA + ACME server, authoritative DNS zones (internal + public), IAM, KMS, QuicBaaS storage, OVS master |
| **Gateway** (`lab-node-1`) | `platformd` (client), `gatewayd` | BGP edge, DHCP for LAN clients, firewall, NAT, load balancer, L3 egress, WAN-side TLS termination |
| **Compute** (`lab-node-3`) | `platformd` (client) | QEMU/KVM VMs, Podman containers, local workload storage |

**Gateway and compute are ACME-enrolled clients of the control plane's
CA.** First-boot platformd on those nodes registers with
`https://<cp-hostname>.<internal-domain>:9443/api/v1/acme/directory`,
completes a challenge, and receives the production webservice
certificates. The root CA bundle is baked into the install ISO so the
first ACME connection can verify TLS before any cert has been issued.

---

## Network Architecture

### Bond / Bridge

- **`bond0`** is an OVS bond port on `trusted0` — *not* a Linux kernel
  bond netdev. Mode: `balance-tcp` with `lacp: active`. Members:
  `eth6` + `eth7` (Supermicro X10 SFP+ ports).
- **`trusted0`** is an Open vSwitch bridge created via native OVSDB
  `Transact` from `platformd::initOVSBridge`. The bridge is assigned
  the trusted subnet's gateway IP (e.g. `10.200.0.1/24`) at
  `initBridgeIPs` time.
- NIC member interfaces (`eth6`, `eth7`) are brought up as raw
  manual-configured interfaces in `/etc/network/interfaces`. OVS
  claims them when `ovsdb-server` + `ovs-vswitchd` start at boot.

### DNS Resolution

Each node runs a **local `dnsmasq`** on `127.0.0.1:53`. dnsmasq's
upstream (`server=`) is the control plane's internal DNS on
`<cp_ip>#9053`. Why this pattern?

- `platformd` does **not** run as root; its DNS service binds to
  unprivileged ports (9053 for internal zone, 8053 for public).
- libc resolvers always query port 53, so clients need something
  listening there.
- Local `dnsmasq` + explicit port forward (`server=<cp_ip>#9053`)
  lets the kernel-level resolver talk to CP's DNS via a standard
  port without granting `CAP_NET_BIND_SERVICE` to platformd workers.

`/etc/resolv.conf` on every node:
```
search <public-domain> <internal-domain>
nameserver 127.0.0.1
```

Search-domain list is populated by the bootstrap orchestrator from
`platform.domain` + `platform.internal_domain` in `bootstrap.yaml`.

### Subnets

| Name | VLAN | CIDR | Purpose |
|------|------|------|---------|
| trusted | 200 | 10.200.0.0/24 | Server-to-server east/west, CP/GW/compute |
| provisioning | 201 | 10.201.0.0/24 | PXE boot, initial node setup |
| quarantine | 202 | 10.202.0.0/24 | Isolated untrusted / failed nodes |
| storage | 203 | 10.203.0.0/24 | Back-end storage traffic |

---

## Config Delivery

Per-node config is **never baked into a shared ISO**. The bootstrap
orchestrator:

1. Merges the role template (`dedicated/supermicro/x10/<role>.yaml`) +
   `overrides_file` + inline `overrides:` from `bootstrap.yaml`.
2. Publishes the result to the pxeboot HTTP server at
   `/config/mac/<mac-dashed>/installer.yaml` for **every** MAC the
   node has (YAML-declared + BMC-discovered).
3. ISO boots the target, `autoinstall.sh` discovers its MAC, fetches
   the per-MAC config via the `platform_config=` kernel cmdline URL
   (baked by `platformctl iso create --config-server`), and installs.

See [`docs/bootstrap/config-delivery.md`](../../../../docs/bootstrap/config-delivery.md)
for the full flow and [`docs/architecture/bootstrap-flow.md`](../../../../docs/architecture/bootstrap-flow.md)
for orchestrator phase diagrams.

---

## Override Precedence

Templates at this level are **deployment-agnostic** — they declare role
behavior, not site-specific addresses. Operators layer in site values
via `overrides_file` (external) + `overrides:` (inline in
bootstrap.yaml):

```
Template (this directory)
  └── overrides_file (private repo, per-node)
      └── overrides: (inline, bootstrap.yaml, smallest + wins)
          └── platform: global identity (only fills empty fields)
```

Inline `overrides:` wins over `overrides_file`; the file in turn wins
over the template. `platform:` global identity (domain, hostmaster,
tenant-id) only *fills* empty template fields — it never overrides.

---

## Templates

| File | Role | Notes |
|------|------|-------|
| [`supermicro/x10/control-plane.yaml`](./supermicro/x10/control-plane.yaml) | CP | Embedded ACME server, DNS :9053 / :8053, QuicBaaS, KMS, IAM |
| [`supermicro/x10/gateway.yaml`](./supermicro/x10/gateway.yaml) | GW | Enrolls with CP via ACME, BGP, DHCP, firewall |
| [`supermicro/x10/compute.yaml`](./supermicro/x10/compute.yaml) | Compute | Enrolls with CP via ACME, QEMU/KVM + Podman |
| [`dell/r640/`](./dell/r640/) | R640 variants | Phase-2 hardware (UNTESTED) |

---

## Key Config Sections (All Three Templates)

### `debug: true | false`

When `true`, installer:
- Adds `openssh` + enables sshd
- Injects operator SSH key from `os.post-install` hook
- Sets root password from `os.root-password` for iKVM/SOL
- Bakes `platform_debug=1` into kernel cmdline

When `false` (production), no remote access except via the platform's
normal APIs.

### `sdn.ovs` + `network.bridges` + `network.bonds`

```yaml
sdn:
  ovs:
    socket: /var/run/openvswitch/db.sock
    bridge: trusted0

network:
  bridges:
    - name: trusted0
      type: ovs
      auto-start: true
  bonds:
    - name: bond0
      type: ovs            # Important: ovs, not linux
      bridge: trusted0
      mode: balance-tcp
      lacp: active
      interfaces: [eth6, eth7]
```

`platformd` reads `network.bonds` at startup and creates the OVS bond
via OVSDB wire protocol (see `pkg/app/sdn.go::initOVSBonds`).

### `sdn.fabric.segments`

Only `provisioning` and `quarantine` are first-class fabric roles
(they trigger PXE onboarding and isolation flows respectively).
Production and storage segments have **no `role:`** field — an
empty/absent role is semantically "general data plane".

```yaml
sdn:
  fabric:
    segments:
      - name: trusted
        vlan: 200
        # no role — trusted is implicit general data plane
      - name: provisioning
        vlan: 201
        role: provisioning
      - name: quarantine
        vlan: 202
        role: quarantine
```

Setting `role: server` or `role: storage` fails the fabric validator
and defers SDN initialization.

### `dns.internal.port: 9053` + `dns.public.port: 8053`

Non-privileged so `platformd` workers don't need
`CAP_NET_BIND_SERVICE`. Clients reach it via local `dnsmasq`
(see "DNS Resolution" above).

### `ntp` — Time Synchronization

All three role templates ship an `ntp:` section. Time is a trust
primitive here: TPM attestation freshness, ACME issuance, DANE/DNSSEC
signature windows and JWT validity are all meaningless against a wrong
clock, and a node that boots with no time daemon runs on whatever its
RTC says.

| Role | Mode | Sources | Serves |
|------|------|---------|--------|
| control-plane | `both` | `198.18.0.1` (edge router, preferred) + `pool.ntp.org` | `198.18.0.0/24`, `172.16.201.0/24` with NTS |
| gateway | `consume` | `198.18.0.10` (control plane) over NTS | — |
| compute | `consume` | `198.18.0.10` (control plane) over NTS | — |

platformd does not implement NTP: chrony is a mandatory install package
and platformd renders `chrony.conf`, manages the OpenRC service, and
reads sync state from its control socket. The startup gate blocks
bring-up (120s) after network setup and before TPM/CA init; on timeout
the node boots flagged `time-unsynced` in health status.

`serve.listen-networks` is an explicit CIDR allow-list — never
`0.0.0.0/0`. Change the upstream addresses in your override file when
your edge router or control-plane address differs.

Full schema: `docs/device-templates.md` (Time Synchronization).
API surface: `docs/ntp/api-reference.md`.

### `os.kernel-modules`

```yaml
os:
  kernel-modules:
    - igb      # Supermicro X10 1GbE
    - ixgbe    # Supermicro X10 10GbE SFP+
    - e1000e
    - i40e
    - ice
    - openvswitch
    - vxlan
    # NOTE: no `bonding` module — we use OVS bonds, not Linux bonds
```

### `webservices[].sans`

Deployers should override the `sans:` list in their override file so
the ACME-issued certificate has the correct DNS SANs for the node's
FQDNs. Example:

```yaml
webservices:
  - name: internal
    sans:
      - lab-node-2.cp.example.internal
      - lab-node-2.trusted-platform.io
      - 10.200.0.1
```

---

### `trust.bmc` — BMC Trust Chain (Phase 3)

All three templates now ship a `trust.bmc` scope alongside the existing
`bmc:` section. This configures the TLS trust chain used when the platform
connects to BMC endpoints (Redfish HTTPS, IPMI-over-TLS, vendor CGI).

```yaml
trust:
  bmc:
    # BMC endpoint trust chain. First strategy to succeed wins.
    # tofu is NOT available here (#83): it fetches a CA bundle and a BMC
    # serves none. Use a per-node bmc_spki_pin for first contact.
    strategies: [dane, spki, ca-file]
    dane:
      dns-server: "198.18.0.10:8053"   # CP public DNS (GW/compute)
      # dns-server: "127.0.0.1:8053"     # for CP itself
```

TLSA records are published at `_443._tcp.<hostname>-bmc.<internal-zone>` by
the BMC enroll ceremony and the AutoCertManager rotation hook.

**`tofu` is not available for the bmc class** (#83) — it fetches a CA bundle
and a BMC serves none; use a per-node `bmc_spki_pin` for first contact. The comment
in each template tells operators exactly when to do this. Override in your
private overrides file:

```yaml
trust:
  bmc:
    strategies: [dane, spki, ca-file]
```

See [`docs/device-templates.md`](../../../../docs/device-templates.md#bmc-trust-chain-trustbmc)
for the full chain semantics, TLSA naming convention, and deprecated field
replacements (`bmc.skip-tls-verify` and `bmc.ca-cert-path`).

---

## Keeping This Doc Current

**This README is the single source of truth for the dedicated profile's
operational contract.** When a template shape changes, this doc changes.
Specifically, update the doc in the SAME commit when:

- A new template field changes deployment behavior
- The bond / bridge / DNS / fabric structure is modified
- A new role is added or a role's responsibilities shift
- Override precedence or merge semantics change

Architecture pointers that relate to provisioning, ISO build, and
install flow:

| Concern | Primary doc |
|---------|-------------|
| Bootstrap phases + orchestrator flow | [`docs/architecture/bootstrap-flow.md`](../../../../docs/architecture/bootstrap-flow.md) |
| Dynamic config delivery (per-MAC staging) | [`docs/bootstrap/config-delivery.md`](../../../../docs/bootstrap/config-delivery.md) |
| ISO build flags + modes | [`docs/installer/iso-building.md`](../../../../docs/installer/iso-building.md) |
| autoinstall.sh priority chain | [`docs/installer/autoinstall.md`](../../../../docs/installer/autoinstall.md) |
| Kernel cmdline parameter reference | [`docs/reference/kernel-cmdline.md`](../../../../docs/reference/kernel-cmdline.md) |
| Templates + overrides | [`docs/device-templates.md`](../../../../docs/device-templates.md) |
| Binary separation (platformd/gatewayd/platform-initrd) | [`docs/architecture/binary-separation.md`](../../../../docs/architecture/binary-separation.md) |
