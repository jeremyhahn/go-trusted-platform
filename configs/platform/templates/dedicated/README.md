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
                  ISP A ─────┴───── ISP B         (1G WAN ports, gateway only)
                           │
                    ┌──────▼──────┐
                    │    gw-01    │  gatewayd + platformd (client)
                    │   gateway   │  role: gateway (routes, NATs)
                    └──────┬──────┘
                           │ bond0 → br-fabric, port class gateway
                           │ (400, 401, 404-406, 408)
              Platform switch pair (pure L2, MTU 9216)
                           │ bond0 → br-fabric, port class hypervisor
                           │ (401, 403-408, native 405)
             ┌─────────────┴─────────────┐
        ┌────▼────┐                 ┌────▼────┐
        │  cp-01  │                 │compute-01│
        │   CP    │ platformd       │ compute │ platformd
        │         │ (server)        │         │ (client)
        └─────────┘                 └─────────┘
   BMCs: access ports on management (402), port class bmc
```

Every node's data trunk is an **OVS bond of two 10G NICs on `br-fabric`**,
created natively by `platformd` over the OVSDB wire protocol at runtime (no
kernel bonding driver, no `ovs-vsctl` fork). Workloads attach to a separate
integration bridge, **`br-int`**, which never carries the trunk.

---

## Role Responsibilities

| Role | Binaries | Owns |
|------|----------|------|
| **Control plane** (`cp-01`) | `platformd` (server mode) | CA + ACME server, authoritative DNS zones (internal + public), IAM, KMS, QuicBaaS storage, OVS master |
| **Gateway** (`gw-01`) | `platformd` (client), `gatewayd` | BGP edge, the only router on the platform tier, firewall, NAT, load balancer, L3 egress, WAN-side TLS termination |
| **Compute** (`compute-01`) | `platformd` (client) | QEMU/KVM VMs, Podman containers, local workload storage |

**Gateway and compute are ACME-enrolled clients of the control plane's
CA.** First-boot platformd on those nodes registers with
`https://<cp-hostname>.<internal-domain>:9443/api/v1/acme/directory`,
completes a challenge, and receives the production webservice
certificates. The root CA bundle is baked into the install ISO so the
first ACME connection can verify TLS before any cert has been issued.

The platform listener (`tls-port: 9443`) of every `gateway.yaml` and
`compute.yaml` here, Supermicro X10 and Dell R640 alike, sets
`certificate.acme.challenge: device-attest-01`, so its certificate comes from
the control-plane CA and not the node's own. The reporting collector and the
bootstrap orchestrator's post-install health probe verify that listener
against the platform anchor by its subject CN; a locally-issued certificate
fails both. [`supermicro/x10/README.md`](./supermicro/x10/README.md#certificate-identity-which-ca-issues-what)
explains why. `control-plane.yaml` has no challenge: it is the CA.

---

## Network Architecture

### Bond / Bridge

- **`bond0`** is an OVS bond port on `br-fabric` — *not* a Linux kernel
  bond netdev. Mode: `balance-tcp` with `lacp: active`. Members: the two
  10G ports (`eth6` + `eth7` on the Supermicro X10, `ens2f0` + `ens2f1` on
  the Dell R640).
- **`br-fabric`** is the Open vSwitch bridge that carries the physical
  trunk, created via native OVSDB `Transact` from
  `platformd::initOVSBridge`. The host's own zone addresses are OVS internal
  ports on it, tagged with the zone's VLAN.
- **`br-int`** is the integration bridge for VM and container ports. It has
  no uplink and never carries the trunk; workloads reach the network only
  through the overlay (#709).
- NIC member interfaces are brought up as raw manual-configured interfaces
  in `/etc/network/interfaces`. OVS claims them when `ovsdb-server` +
  `ovs-vswitchd` start at boot.

### Host Addressing by Role

A host holds an address only on the zones it uses (reference network,
"Host addressing"); the VLANs it passes through to guests get none.

| Node | Role | Zone addresses | Platform VRF |
|------|------|----------------|--------------|
| gw-01 | `gateway` | `.2` on transit, fabric, quarantine, provisioning, control-plane, backup; answers for `.1` | `10.4.144.2/32` |
| cp-01 | `control-plane` | fabric `10.4.1.10`, control-plane `10.4.6.10` | `10.4.144.10/32` |
| compute-01 | `compute` | fabric `10.4.1.20`, hypervisor `10.4.3.20`, storage `10.4.7.20` | `10.4.144.20/32` |

`network.role` drives the installer's checks and what it writes:

- control-plane and compute hosts never forward (`ip-forward: false`), and
  the installer writes a host firewall that drops traffic between
  interfaces; a static address outside the role's zones, or a DHCP
  interface, fails validation;
- the gateway is exempt: it routes and NATs by role;
- the platform-VRF address lives in a Linux VRF, not on an underlay
  interface. Until the platform overlay (#709) and the platform VRF land, a
  compute node has no route to the control-plane zone; reachability between
  a compute node and the control plane arrives with them.

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

### Environment and Zones

Every number comes from `sdn.environment`; the templates use environment
4, the reference example. The zone at offset _n_ is VLAN `4·100+n` with
`10.4.n.0/24` and `<ULA>:40n::/64`; the upper half of the /16
(`10.4.128.0/17`) is the IPAM pool. Inside a zone subnet: `.1` the gateway,
`.2`/`.3` the gateway nodes, `.10`–`.19` control-plane nodes, `.20`–`.49`
other static hosts, `.50`–`.254` DHCP where the zone serves it.

| Zone | VLAN | IPv4 | Purpose |
|------|------|------|---------|
| transit | 400 | 10.4.0.0/24 | Gateway edge: upstream handoff and peering (gateway ports only) |
| fabric | 401 | 10.4.1.0/24 | VXLAN underlay: VTEPs and EVPN |
| management | 402 | 10.4.2.0/24 | BMCs only (BMC access ports only) |
| hypervisor | 403 | 10.4.3.0/24 | Live migration |
| quarantine | 404 | 10.4.4.0/24 | Non-compliant nodes: authentication and remediation |
| provisioning | 405 | 192.0.2.0/24 | Onboarding: DHCP, PXE, DNS, ACME (the hypervisor trunk's native VLAN) |
| control-plane | 406 | 10.4.6.0/24 | Control-plane nodes |
| storage | 407 | 10.4.7.0/24 | Storage traffic |
| backup | 408 | 10.4.8.0/24 | Backup traffic |

| IPAM range | Prefix | Use |
|------------|--------|-----|
| tunnel point-to-point | 10.4.128.0/22 | /31 links; `10.4.128.0/31` is the reserved gateway HA sync link |
| loopbacks | 10.4.132.0/22 | /32 loopbacks |
| service VIPs | 10.4.136.0/21 | platform service VIPs |
| platform-VRF hosts | 10.4.144.0/20 | one address per attested host |
| tenant default | 10.4.192.0/18 | tenant overlay subnets |

The zone pools and the IPAM ranges are seeded into IPAM at startup; the
templates declare no networks or pools. `public` and tenant networks are
overlays, not zones. A site that cannot follow the reference overrides
single zones under `sdn.environment.overrides` (VLAN, subnet, subnet6)
instead of renumbering.

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

### `sdn.environment` + `sdn.ovs` + `network`

```yaml
sdn:
  environment:
    id: 4
    base: 10.0.0.0/8
    ula: fd12:3456:789a::/48   # generate your own random global ID
  ovs:
    socket: /var/run/openvswitch/db.sock
    bridge: br-fabric

network:
  role: control-plane
  ip-forward: false
  platform-vrf:
    address: 10.4.144.10/32
  bridges:
    - name: br-fabric
      type: ovs
      interfaces: [bond0]
    - name: br-int
      type: ovs
  bonds:
    - name: bond0
      type: ovs            # Important: ovs, not linux
      bridge: br-fabric
      mode: balance-tcp
      lacp: active
      interfaces: [eth6, eth7]
      vlans:
        - {zone: fabric, ipv4-address: 10.4.1.10/24, auto-start: true}
        - {zone: control-plane, ipv4-address: 10.4.6.10/24, auto-start: true}
```

`platformd` reads `network.bonds` at startup and creates the OVS bond via
OVSDB wire protocol (see `pkg/app/sdn.go::initOVSBonds`); each `vlans[]`
entry becomes an OVS internal port tagged with its zone's VLAN.

### `sdn.fabric` — switch ports by class

The control-plane template carries the switch fabric. Every platform port
has a class, and its allowed VLANs, native VLAN and MTU 9216 are derived
from the environment; no port is trunked the whole block.

| Class | Mode | VLANs (block 4) |
|-------|------|-----------------|
| `gateway` | trunk | 400, 401, 404-406, 408 |
| `hypervisor` | trunk | 401, 403-408, native 405 |
| `bmc` | access | 402 |
| `mgmt-uplink` | trunk | 402 |
| `peer-link` | trunk | every zone of the block (`peers[].peer-link-ports`) |

```yaml
sdn:
  fabric:
    switches: [...]
    peers:
      - {switch-a: switch-01, switch-b: switch-02, peer-link-ports: [Ethernet1/49, Ethernet1/50]}
    ports:
      - {switch-id: switch-01, port: Ethernet1/3, class: gateway, description: gw-01 data}
      - {switch-id: switch-01, port: Ethernet1/25, class: hypervisor, description: cp-01 data}
      - {switch-id: switch-01, port: Ethernet1/41, class: bmc, description: gw-01 BMC}
```

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
| control-plane | `both` | `10.4.6.1` (the gateway, preferred) + `pool.ntp.org` | `10.4.6.0/24`, `192.0.2.0/24` with NTS as `cp.example.internal` |
| gateway | `consume` | `cp.example.internal` (control plane) over NTS | — |
| compute | `consume` | `cp.example.internal` (control plane) over NTS | — |

platformd does not implement NTP: chrony is a mandatory install package
and platformd renders `chrony.conf`, manages the OpenRC service, and
reads sync state from its control socket. The startup gate blocks
bring-up (120s) after network setup and before TPM/CA init; on timeout
the node boots flagged `time-unsynced` in health status.

**Nodes name the control plane, they do not address it.** RFC 8915 key
establishment is a TLS handshake, and chronyd verifies the NTS-KE
certificate against the name in its own `server` directive. Platform
certificates carry DNS SANs only, so an IP address in
`ntp.consume.upstream` can never validate — the node then never
synchronises and burns the full 120s gate at every boot. The name
`cp.example.internal` resolves through the same path the ACME directory
URL already uses: the node's local dnsmasq forwards the internal zone to
the control plane's internal DNS server, whose zone carries the `cp` A
record. No `/etc/hosts` entry is involved, and a change of the control
plane's address needs no node re-render.

The name has to satisfy **two** conditions, not one, and they are checked
in different places:

| Condition | Where it lives | What a miss looks like |
|---|---|---|
| The served certificate carries the name | `ntp.serve.nts.server-names` on the control plane | The NTS-KE handshake fails; chronyd reports the source unreachable and never says why |
| The address the name resolves to is inside the allow list | `ntp.serve.listen-networks` on the control plane | The handshake **succeeds** and the node is then refused time; everything looks configured and the clock never moves |

The second condition is easy to miss because the first one passing makes
the configuration look correct. platformd resolves every configured
server name at bring-up and at each certificate renewal and drives the
control plane's `ntp` health component to degraded under one of two
markers:

- **`nts-name-unreachable`** — the name resolved onto a segment
  `listen-networks` refuses. The message names the name, the address and
  the allow list. Reconcile by widening `listen-networks` to that
  segment, or by publishing the name on a segment already listed.
- **`nts-name-unresolvable`** — the name did not resolve on the control
  plane at all, and the message carries the resolver's own error. Nodes
  forward the internal zone through the control plane, so a name it
  cannot resolve is one no node can reach. Publish the record, or repair
  the resolver.

They are never merged: an unresolvable name has no address, so it is not
reported as one the allow list refuses. The platform reports the mismatch
and does not choose for you.

Entries in `server-names` are DNS names; an IP address is rejected at
configuration validation. The certificate is platform-CA-issued by the
renewal sweep (first boot writes a self-signed one only so the daemon can
start), and the platform CA is already in every node's system trust store
from the install ISO
(`/usr/local/share/ca-certificates/trusted-platform-ca.crt`), which is
what makes the handshake verify with no extra anchor to distribute.

`serve.listen-networks` is an explicit CIDR allow-list — never
`0.0.0.0/0`. Change the upstream names and the served
`ntp.serve.nts.server-names` together in your override file when your
domain differs; change the edge-router address when yours differs.

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
      - cp-01.cp.example.internal
      - cp-01.example.com
      - 10.4.6.10
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
      dns-server: "10.4.6.10:8053"       # CP public DNS (GW/compute)
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

### `platform-ca-file` — The Platform Anchor (gateway role)

The two gateway templates set a top-level `platform-ca-file:`. It is the
platform CA bundle provisioning delivers to the node, and it is gatewayd's
platform anchor: every platform service the gateway talks to is verified
against it. That includes the platform secret store (`secret-store:`), so it
stands behind every `kms://` and `secret://` reference the gateway
configuration carries — the BGP neighbour passwords, the TCP-AO master keys,
the ipsec and wireguard keys — as well as platformd over grpc, the proxy's
mTLS callers and `trust-class: platform` backends, and the telemetry reporter.

```yaml
platform-ca-file: /etc/gatewayd/cp-ca.pem
```

It is not a `trust:` class and there is no strategy to choose: a
platform-issued certificate chains to the platform CA and to nothing else.
platformd derives the same anchor from the chain that issued its IDevID; a
gateway runs no CA and holds no IDevID, so the bundle file is its source. It
replaced the retired `trust: internal:` class.

Without it, a gateway with a `secret-store:` refuses to start
(`secrets.ErrTrustRequired`) rather than starting into a daemon whose every
secret reference fails at service start. The file is read at each
verification, so a rotated bundle needs no restart; a bundle not yet on disk
fails the verification naming the path.

---

## Keeping This Doc Current

**This README is the single source of truth for the dedicated profile's
operational contract.** When a template shape changes, this doc changes.
Specifically, update the doc in the SAME commit when:

- A new template field changes deployment behavior
- The bond / bridge / DNS / fabric / environment structure is modified
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
