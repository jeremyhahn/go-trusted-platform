# Device Templates

> **Status: REFERENCE** · Last verified: 2026-10-13
> Device templates, overrides and secret URIs as built. Upstream SDK identifiers
> belong to go-quicbaas.

## Overview

The Device Template system provides reusable reference architecture configurations
for deploying go-trusted-platform on specific hardware. The workflow is:

1. **Templates** -- Filesystem-based YAML configs organized by vendor/model/role.
   These contain complete, working configurations with sensible defaults.
2. **Overrides** -- Optional YAML files containing only site-specific values
   (hostnames, IPs, serials, credentials). Merged on top of the template.
3. **Device Configs** -- The final merged result used to build ISOs and provision nodes.

Templates are designed to be version-controlled and shared across deployments.
Overrides keep per-site secrets and addressing out of the shared templates.

## Shipped Templates

Templates are located at `configs/platform/templates/` and organized first by
deployment profile, then by vendor and hardware model:

```
configs/platform/templates/
  dedicated/          # 3-node: 1 CP + 1 GW + 1 compute (active)
    README.md         ← profile architecture + operational contract
    vendor/
      model/
        control-plane.yaml
        gateway.yaml
        compute.yaml
  single-node/        # All-in-one (CP + GW + compute on one box)
    README.md
    default.yaml
  high-availability/  # HA cluster (planned)
```

Each profile directory has its own `README.md` describing the topology,
role responsibilities, bond/bridge layout, DNS strategy, and the
expected override precedence. When a template shape changes, the
profile's README is updated in the same commit so it stays the
single source of truth for the profile's contract. See
[`configs/platform/templates/dedicated/README.md`](../configs/platform/templates/dedicated/README.md)
for the current production reference.

### Deployment Profiles

| Profile | Layout | Status |
|---------|--------|--------|
| `dedicated` | 3 dedicated nodes: 1 CP, 1 GW, 1 compute | **Active** |
| `single-node` | CP + GW + compute colocated on one node | Active (default ISO; Raspberry Pi factory image) |
| `high-availability` | 3 CP, 2 GW, 2 compute with Raft consensus | Planned |

### Available Templates

| Vendor | Model Family | Profile | Roles | Status |
|--------|--------------|---------|-------|--------|
| Supermicro | X10 (X10SDV-TP8F, etc.) | dedicated | control-plane, gateway, compute | Production |
| Dell | PowerEdge R640 | dedicated | control-plane, gateway, compute | Phase 2 (UNTESTED) |
| Raspberry Pi | 4 Model B (`single-node/raspberrypi/rpi4`) | single-node | control-plane, gateway, compute | Factory SD-card image (`make image-rpi`, [factory-image/](factory-image/)); boots on the QEMU virt stand-in, hardware validation per its `user.md` |
| Raspberry Pi | 4 Model B (`dedicated/raspberrypi/rpi4`) | dedicated | control-plane, compute | Factory SD-card image (`platformctl diskimage create --target rpi --model rpi4 --role compute`, or `--role control-plane`); the compute node joins the x86 control plane and gateway, the control plane is standalone (QuicBaaS `file`, no Raft). A one-port Pi cannot be the gateway — [its README](../configs/platform/templates/dedicated/raspberrypi/README.md) |
| Raspberry Pi | Compute Module 4 (`dedicated/raspberrypi/cm4`) | dedicated | control-plane | Factory SD-card image (`--model cm4 --role control-plane`), standalone; `cm4/desk-overrides.yaml` puts it on one static address with no gateway. No hardware run yet — [its README](../configs/platform/templates/dedicated/raspberrypi/README.md#control-plane) |
| Raspberry Pi | 5 (`dedicated/raspberrypi/rpi5`) | dedicated | compute | **Experimental** (`--model rpi5 --role compute`): the image builds and the template validates, but no Pi 5 has booted it; the TPM behind the RP1 I/O chip, the serial console and the RP1 Ethernet are unvalidated — [its README](../configs/platform/templates/dedicated/raspberrypi/README.md) |

**Each profile directory carries a `README.md` recording what the hardware needs
before its templates will install** — BIOS settings, BMC behaviour, firmware quirks —
none of which a template can express. Read it before the first PXE install of a
node and before any re-provision. The X10 one
([`supermicro/x10/README.md`](../configs/platform/templates/dedicated/supermicro/x10/README.md))
documents three BIOS settings that all ship wrong by default and, absent, produce an
install that reports success and cannot boot. A profile without a README has not been
deployed on real hardware yet.

Every gateway template configures the gateway with service sections
(`docs/gateway/architecture.md`); none uses the deprecated `modes:` key, and a new
template must not reintroduce it.

## Quick Start

### Default ISO (no flags — single-node)

```bash
platformctl iso create
```

With no flags, `iso create` uses the single-node template at
`configs/platform/templates/single-node/default.yaml` and bakes the
merged config into the ISO. This matches the reference-architecture
single-node deployment (CP + GW on one box) documented in
`docs/architecture/deployment-reference.md` §1.

### Deploy with a specific role template (baked into ISO)

```bash
platformctl iso create \
  --platform-config configs/platform/templates/dedicated/supermicro/x10/control-plane.yaml
```

### Deploy with overrides (template + site-specific overrides, baked)

```bash
platformctl iso create \
  --platform-config configs/platform/templates/dedicated/supermicro/x10/control-plane.yaml \
  --overrides /path/to/my-overrides.yaml
```

The override is deep-merged onto the template by the rules in
[Merge Rules](#merge-rules): a `null` deletes a template key and a list
replaces the template's list unless its entries merge by name.

### Shared ISO with dynamic per-node config (multi-node bootstrap)

```bash
platformctl iso create \
  --config-server http://deployer.lan:8080/config/mac
```

In this mode the ISO carries only a kernel cmdline pointer to the
pxeboot HTTP config server. Per-node merged configs are published
by the bootstrap orchestrator keyed by MAC address. A single ISO
installs CP, GW, and compute correctly. See
`docs/bootstrap/architecture.md` (Phase 3 · Control plane) for the full flow.

### Hybrid (dynamic preferred, baked as fallback)

```bash
platformctl iso create \
  --config-server http://deployer.lan:8080/config/mac \
  --platform-config configs/platform/templates/single-node/default.yaml
```

Useful when the config server might be unreachable at install time —
the baked config acts as a safety net.

---

### The gateway role signal

`gateway.enabled: true` in a template is what makes a node a gateway to the
installer, the ISO builder and firstboot (#66): that node gets `gatewayd`
packaged and started, and its `gateway:`, `sdn:`, `trust:`, `proxy:`,
`secret-store:` and `control-plane:` sections, plus the `platform-ca-file:` key
(gatewayd's platform anchor), are projected into `/etc/gatewayd/config.yaml`
(`pkg/config.GatewaydConfigSections`). The
gateway templates carry a `control-plane:` reporter section whose `gateway-id`
must equal `gateway.id` — it is the Common Name of the client certificate the
control plane issued for the gateway. platformd itself does not decode
`gateway:` or `control-plane:`.

Gateway overlay fields live in gatewayd's own `gateway.overlay:` section: the
local fabric VTEP address (`local-vtep`), underlay interface/MTU, OVS access
port, overlay ASN, route-reflector peers, VXLAN port, default VNI, maximum VNIs
and the admission settings `verdict-max-age` (15m default), `verdict-clock-skew`
(30s) and `admission-sweep-interval` (30s). Those values are not derived from the
platformd-side `sdn.overlay:` block; templates must project the gatewayd fields
when a profile enables the overlay service.

## Delivery Modes

| Mode | Flags | Config location | When to use |
|------|-------|-----------------|-------------|
| **Default baked** | (none) | ISO: `/media/cdrom/configs/installer.yaml` | Single-node deploys |
| **Custom baked** | `--platform-config [--overrides]` | ISO | Per-role ISOs in multi-node |
| **Dynamic** | `--config-server URL` | Orchestrator HTTP `/config/mac/<mac>/installer.yaml` | Fleet bootstrap, shared ISO |
| **Hybrid** | `--config-server URL --platform-config X` | Dynamic with baked fallback | Multi-node with unreliable config-server reach |

See `docs/architecture/bootstrap-flow.md` §3 for the install-time
priority chain that picks between modes.

## Override Files

An override file uses the same YAML structure as a template but only includes
the fields you want to change. All other values are inherited from the template.

### Example Override

```yaml
os:
  hostname: cp-01

network:
  interfaces:
    - name: eth0
      type: dhcp

tpm:
  idevid:
    serial: MY-SERIAL-001
```

### Merge Rules

`platformctl diskimage create --overrides`, `platformctl iso create
--overrides` and device-profile overrides all merge with `pkg/config`
(`DeepMergeYAML`, `DeepMergeMaps`), which follows JSON Merge Patch
(RFC 7386 §2) and adds keyed list merging:

| Override value | Result |
|---|---|
| a key the override does not name | the template's value is kept |
| a scalar | replaces the template's value |
| a map | merges key by key into the template's map |
| `null` (or `~`, or an empty value) | **deletes** the key, at any depth; a `null` for a key the template lacks changes nothing |
| a list of maps that share `name`, `id` or `role` with the template's list | merges entry by entry: matching entries merge, new entries are appended, template entries the override does not name are kept |
| any other list, including `[]` | **replaces** the template's list; `[]` empties it |

To remove a template section, set it to `null`; to remove every VLAN or
bond, set the list to `[]`. A keyed list cannot lose one entry by merge;
give the whole file with `--platform-config` instead.

### Example: Raspberry Pi 4 on a Flat DHCP Network

The rpi4 compute template is a rack node: `eth0` is a trunk carrying the
zone VLANs, with a platform VRF and a local dnsmasq forwarding to the
control plane at `10.4.6.10`. On a flat network — an access port with a
DHCP server, such as an office VLAN — the same template builds a DHCP node
with this override:

```yaml
os:
  hostname: pi4-01
network:
  role: null           # a compute role permits only static zone addresses
  dns: null            # no resolv.conf is rendered: the DHCP client writes it
  dnsmasq: null
  platform-vrf: null
  vlans: []
  interfaces:
    - name: eth0
      type: dhcp
```

```bash
platformctl diskimage create --target rpi --model rpi4 --role compute \
  --overrides rpi4-flat-dhcp.yaml
```

The rendered `/etc/network/interfaces` has `iface eth0 inet dhcp` and no
802.1Q or VRF device. The file is
`pkg/cli/commands/diskimage/testdata/rpi4-flat-dhcp.yaml`, and
`TestRPi4FlatDHCPOverridesRenderAnAccessPort` loads it through the
host-network check platformd runs at startup, then renders it. It changes only
`network:`; the template's other control-plane references (`dns.resolver`,
`trust.bmc`, `ntp`, `acme`) still name the rack and need the site's values.

`role: null` is required: with the template's `network.role` kept, platformd
refuses a DHCP interface (`ErrDHCPNotPermitted`, `pkg/installer/network_role.go`).
A host with no role also gets none of the role's hardening — no forward-drop
nftables table and no forwarding sysctl — which the
[Raspberry Pi README](../configs/platform/templates/dedicated/raspberrypi/README.md#a-pi-on-a-flat-dhcp-network)
spells out. The CM4 control plane's desk override,
`dedicated/raspberrypi/cm4/desk-overrides.yaml`, takes the same route to one
static address outside the control-plane zones.

### Common Override Fields

| Field | Description |
|-------|-------------|
| `os.hostname` | Per-node hostname |
| `network.*` | Site-specific IPs, nameservers, interfaces |
| `tpm.idevid.serial` | Actual chassis serial number |
| `domain` | Your domain name |
| `hostmaster` | SOA contact email |
| All `password:` fields | Replace placeholder credentials |
| NIC interface names | Match actual hardware (`ip link`) |
| `webservices[].sans` | DNS SANs for TLS certificates |

**Bootstrap pipeline note**: when an override file is referenced from
`bootstrap.yaml` (`overrides_file`) or written as an inline `overrides:`
block, the node-identity keys `os.hostname`, `network.interfaces`, and
`bmc.address/username/password/protocol` are forbidden
(`ErrForbiddenOverrideKey`) — set the first-class `nodes[]` fields
instead. They remain valid in standalone ISO override files
(`platformctl iso create --overrides`).

## Custom Templates Directory

`--platform-config` takes any template path, so your own templates directory
needs no extra flag:

```bash
platformctl iso create \
  --platform-config my-templates/vendor/model/role.yaml \
  --overrides site-overrides.yaml
```

During bootstrap, the orchestrator's seeder (`pkg/bootstrap/seeder.go`) uploads
the templates to the control plane, making them available through the API and
web UI for profile creation and management.

## Secret URI Schemes

Templates use URI schemes for all password and PIN fields instead of literal
values. This allows templates to be safely version-controlled and shared
without exposing secrets.

| Scheme | Example | Description |
|--------|---------|-------------|
| `kms://` | `kms://<path>?ensure=true&len=32&enc=base64` | Canonical scheme: ensure-persist-or-fetch from QuicBaaS KMS |
| `idevid://` | `idevid://base64data` | Decrypt using the device IDevID certificate |

### kms:// (canonical)

The `kms://` scheme is the canonical secret URI. It identifies a secret by
path in the QuicBaaS KMS and, when the `?ensure=true` query parameter is
present, applies the Vault-style generate-on-first-boot / return-on-subsequent-boot
semantics via `SecretsService.EnsureSecret` and a distributed lock:

- `kms://ca/root/keys/0/password?ensure=true&len=32&enc=base64`
  -- ensures a 32-byte base64-encoded secret exists at the given path.
  First call generates and persists; every subsequent call returns the same
  stable bytes.
- Query parameters:
  - `ensure=true` -- opt in to the ensure semantics (generate-and-persist)
  - `len=N` -- entropy length: bytes for `base64` / `hex` / `raw`, digits for `numeric`
  - `enc=base64`, `enc=hex`, `enc=numeric` or `enc=raw` -- encoding of the
    returned value. `base64` is unpadded base64url, so `len=32` yields a
    43-character value; `raw` yields the `len` random bytes verbatim.
- **TPM authorization values must use `enc=raw`.** A `TPM2B_AUTH` is capped at
  one digest (32 bytes on a SHA-256 TPM), and a 43-character base64 value
  overflows it with `TPM_RC_SIZE`. Templates therefore use
  `?ensure=true&len=32&enc=raw` for every `srk-auth`, for
  `webservice(s)[*].key.password`, and for `acme.client.account.key.password`
  -- any key with `tpm-policy: platform` has its password sealed into a TPM
  keyed-hash object regardless of its `store:` setting. CA
  `keys[*].password` (PKCS#8 encryption) and `bmc.password` (an IPMI account
  credential) are not TPM auth values and keep `enc=base64`. See
  [Configuration Secret Schemes](secrets/config-secret-schemes.md#tpm-authorization-values-must-use-encraw).
- Changing `len` or `enc` for a path that already has a generated secret
  returns `ErrSecretSpecMismatch`; delete the KMS path or redeploy onto a
  clean secret store.
- Paths are short-form. The tenant and node identifiers are
  implicitly prepended at resolution time by
  `LocalSecretsResolver.WithIdentity`, using `platform.tenant_id` and
  the node hostname. Templates must not embed `tenants/…/nodes/…`
  literals or `{{tenant}}` / `{{node}}` placeholders.

### idevid://

The `idevid://` scheme contains base64-encoded ciphertext that is
decrypted using the device's IDevID certificate private key. This is used
for secrets delivered to a specific device during provisioning, ensuring
only the intended hardware can decrypt them.

## Secrets Lifecycle

Secrets follow a single unified lifecycle:

1. **Template load** -- The platform loads the merged template+overrides
   config. All `kms://?ensure=true` URIs are placeholders at this point.
2. **First boot** -- On first resolution, `SecretsService.EnsureSecret`
   takes a distributed lock on the KMS path, generates a random value per
   the URI spec (`len`, `enc`), persists it in the QuicBaaS KMS, and
   returns the generated bytes.
3. **Subsequent boots** -- Every future resolution returns the same stored
   bytes -- the URI becomes fully deterministic after first use.
4. **Rotation** -- Delete the KMS path (or use a rotation API) to force
   regeneration on next boot.

This unified model replaces the older `autogen://` + migration pattern --
secrets are born in the KMS and stay there, with no intermediate plaintext
on-disk state.

## Secure Boot Configuration

Templates include an optional `secure-boot:` section that configures UEFI Secure Boot key management and enforcement. Secure Boot keys are referenced by URI (`kms://` for remote KMS, `file://` for airgap/dev) rather than filesystem paths, enabling flexible deployment from multiple backends.

```yaml
secure-boot:
  enabled: true
  enforce: false
  resign-mode: remote
  pk:  { cn: "Trusted Platform Secure Boot PK",  store: tpm2,     key-uri: kms://platform/secureboot/pk,  cert-uri: kms://platform/secureboot/pk-cert }
  kek: { cn: "Trusted Platform Secure Boot KEK", store: tpm2,     key-uri: kms://platform/secureboot/kek, cert-uri: kms://platform/secureboot/kek-cert }
  db:  { cn: "Trusted Platform Secure Boot DB",  store: software, key-uri: kms://platform/secureboot/db,  cert-uri: kms://platform/secureboot/db-cert }
```

### Configuration Fields

| Field | Description |
|-------|-------------|
| `enabled` | Enable Secure Boot support (UKI signing). Default: false. |
| `enforce` | Attempt to enroll keys into firmware and activate Secure Boot (bare-metal only). Default: false. SAFETY: enforcement only proceeds if the signed UKI verifies against the db certificate AND the firmware is in Setup Mode. Failures are logged as warnings and never abort the install. |
| `resign-mode` | `remote` (default) or `local`. Controls whether DB signing uses remote KMS (digest only) or local key material. Use `remote` for production (DB key never leaves the server). |
| `pk`, `kek`, `db` | Key reference blocks. Each contains `cn`, `store`, `key-uri`, and `cert-uri`. |

### URI Schemes

| Scheme | Example | Purpose |
|--------|---------|---------|
| `kms://` | `kms://platform/secureboot/db` | **Canonical for production**: Remote KMS backend. The `store` field selects the backend (tpm2, software, etc.). |
| `file://` | `file:///etc/secureboot/db.key` | Airgap/dev mode: key material on disk. Use only in isolated environments. |
| `idevid:` | `idevid://base64data` | Inline secret: base64-encoded ciphertext decrypted by device IDevID cert. |

### Default Placement

The production default places PK/KEK in the TPM (where they never leave silicon) and DB in the CP-KMS (for remote hash-signing):

```yaml
pk:  store: tpm2       # Key never leaves TPM
kek: store: tpm2       # Key never leaves TPM
db:  store: software   # CP-KMS backed
```

### Common Overrides

Override the key URIs to use on-disk keys for development or airgap scenarios:

```yaml
secure-boot:
  enabled: true
  enforce: false
  resign-mode: local
  db:  { cn: "DB", store: software, key-uri: file:///secure-boot-keys/db.key, cert-uri: file:///secure-boot-keys/db.crt }
```

See `docs/firmware/secure-boot.md` for the complete Secure Boot architecture, kernel module signing, and bare-metal enforcement details.

## Time Synchronization (ntp)

Time is a trust primitive. TPM attestation freshness, ACME (RFC 8555)
issuance, DANE/DNSSEC signature windows, and JWT `exp`/`nbf` are all
meaningless against a wrong clock — a node that boots years slow corrupts
every one of them silently.

platformd does **not** implement NTP. chrony is installed as a mandatory
package (`pkg/installer/alpine.go`, prefetched for offline installs) and
runs as an OpenRC service; platformd renders `/etc/chrony/chrony.conf`,
manages the service, polls chrony's control socket, and exposes the state
over REST/gRPC/QUIC/MCP/Unix (see `docs/ntp/api.md`).

Following the platform's explicit-configuration convention, removing the
`ntp:` section entirely makes platformd leave chrony alone.

```yaml
ntp:
  enabled: true
  mode: both                 # serve | consume | both
  consume:
    upstream:
      - address: 10.4.6.1
        prefer: true
        iburst: true
        nts: false
      - address: pool.ntp.org
        pool: true
        iburst: true
        nts: false
    startup-gate:
      block-until-synced: true
      timeout: 120s
      on-timeout: warn-and-continue
    orphan-fallback: true
  serve:
    listen-networks:
      - 10.4.6.0/24
      - 192.0.2.0/24
    local-stratum: 10
    nts:
      enabled: true
      cert-uri: kms://platform/ntp/nts-cert
      key-uri: kms://platform/ntp/nts-key
      server-names:
        - cp.example.internal
  rtc:
    write-back: true
```

### Fields

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `enabled` | bool | — | Gates the whole subsystem. A present-but-disabled section behaves like an absent one |
| `mode` | enum | — | `serve`, `consume`, or `both` |
| `consume.upstream[].address` | string | — | Host name or IP of the upstream. With `nts: true` it MUST be a name the served certificate carries — see below |
| `consume.upstream[].pool` | bool | false | Render as a chrony `pool` directive instead of `server` |
| `consume.upstream[].prefer` | bool | false | Prefer this source over the others |
| `consume.upstream[].iburst` | bool | false | Fast initial burst — what turns a multi-year RTC error into a sub-minute correction |
| `consume.upstream[].nts` | bool | false | Require RFC 8915 Network Time Security towards this source |
| `consume.startup-gate.block-until-synced` | bool | false | Block bring-up until the clock converges |
| `consume.startup-gate.timeout` | duration | `120s` | Gate deadline |
| `consume.startup-gate.on-timeout` | enum | `warn-and-continue` | `warn-and-continue` or `fail-startup` |
| `consume.orphan-fallback` | bool | false | Keep serving from the local clock when no upstream is reachable |
| `serve.listen-networks` | []CIDR | — | **Explicit** allow-list. `0.0.0.0/0` and `::/0` are rejected |
| `serve.local-stratum` | int | `10` | Orphan-mode stratum (1-15) |
| `serve.nts.enabled` | bool | false | Run the NTS-KE server |
| `serve.nts.cert-uri` / `key-uri` | URI | — | Platform CA-issued material; resolved by the secrets engine before chronyd starts |
| `serve.nts.server-names` | []string | — | Extra DNS names the served NTS-KE certificate is issued for, on top of this node's hostname and FQDN. DNS names only; an IP address is rejected at validation |
| `rtc.write-back` | bool | false | Run `hwclock --systohc` after confirmed sync so the next cold boot starts sane |

### Per-role defaults

| Role | Mode | Behavior |
|------|------|----------|
| control-plane | `both` | Consumes the operator-supplied upstream (edge router preferred, public pool as fallback), serves the control-plane and provisioning CIDRs with NTS on, falls back to orphan/local-stratum when no upstream is reachable |
| gateway | `consume` | Consumes from the control plane over NTS, by name (`cp.<internal-domain>`) |
| compute | `consume` | Consumes from the control plane over NTS, by name (`cp.<internal-domain>`) |
| single-node | `both` | Consumes a public pool, serves the local network with NTS on |

### Naming the NTS upstream

An NTS client is a TLS client. chronyd verifies the NTS-KE server's
certificate against **the name written in its own `server` directive**, so
with `nts: true` the upstream address must be a DNS name the served
certificate carries. Platform certificates are DNS-only by standing
ruling, so an IP address there can never validate: chronyd retries the
handshake forever, the node never synchronises, and every boot burns the
full startup gate. That is the failure #509 measured on the fleet.

The two halves of the contract:

- **On the node**, `ntp.consume.upstream[].address` is the control
  plane's role alias in the internal zone, `cp.<internal-domain>`. It
  resolves through the same path the ACME directory URL already uses —
  the node's local dnsmasq forwards the internal zone to the control
  plane's internal DNS server, whose zone carries the `cp` A record.
  Nothing is written to `/etc/hosts`, and a change of the control plane's
  address needs no node re-render.
- **On the control plane**, `ntp.serve.nts.server-names` lists that same
  name. First boot writes a self-signed certificate so the daemon can
  start; the certificate-renewal sweep replaces it with a
  platform-CA-issued certificate carrying the node's hostname, its FQDN
  and every configured server name, and marks it due again whenever the
  certificate chronyd actually serves is missing one of them. Nodes trust
  the issuer through the platform CA already in their system trust store
  from the install ISO
  (`/usr/local/share/ca-certificates/trusted-platform-ca.crt`).
- **Also on the control plane**, `ntp.serve.listen-networks` must cover
  the address the name resolves to. This is a separate condition and the
  one that is easy to miss: the certificate can be perfectly valid, the
  handshake succeeds, and the node is then refused time because no
  `allow` directive covers the address. The clock never moves and nothing
  about the configuration looks wrong. platformd resolves every
  configured server name at bring-up and at each renewal and reports a
  mismatch on the `ntp` health component, degraded, under one of two
  markers: `nts-name-unreachable` when the name resolved onto a segment
  the allow list refuses (naming the name, the address and the list), and
  `nts-name-unresolvable` when the name did not resolve on the control
  plane at all (carrying the resolver's error — nodes forward the
  internal zone through the control plane, so no node can reach it
  either). Widening `listen-networks`, republishing the name on an
  already-allowed segment, and publishing the missing record are all
  valid fixes; the platform reports and does not choose.

### Startup ordering

The sync gate runs **after** network bring-up (`initSDN`) and **before**
TPM/CA initialization, so no trust decision is ever made against an
unverified clock. On timeout the approved default `warn-and-continue`
boots the node and flags the `ntp` health component `time-unsynced`, so
the drift shows up in fleet monitoring instead of going unnoticed.
`fail-startup` aborts bring-up instead.

### Security

`serve.listen-networks` is an explicit allow-list and is validated at
config load: an open NTP server is a reflection-amplification source.
Consume-only nodes render `port 0` and never listen on 123. chrony's UDP
command port is disabled; the platform reads state over the local Unix
control socket. A large correction observed *after* the first-boot
correction is flagged as a health anomaly rather than silently accepted.

## BMC Configuration

Templates include a `bmc:` section that describes the baseboard management
controller for the hardware model. This enables automated lifecycle
management including power control, firmware updates, and reimaging through
IPMI 2.0 RMCP+ and Redfish APIs.

```yaml
bmc:
  address: 10.4.2.20
  username: admin
  password: "kms://bmc/password?ensure=true&len=16&enc=base64"
  protocol: ipmi
```

Template BMC passwords use the canonical `kms://?ensure=` scheme so the
first provisioning run generates a random password and persists it in the
KMS. Override the `address`, `username`, and (if needed) `password` with
real values in your private override file:

```yaml
bmc:
  address: 10.0.1.100
  username: admin
  password: "your-bmc-password"
```

With BMC credentials in place, the platform can:

- Power-cycle nodes for reimaging without physical access.
- Mount virtual media for PXE-free OS installation.
- Monitor hardware health sensors and thermal state.
- Trigger self-healing by automatically rebuilding failed nodes from
  their stored deployment profile.

## BMC Trust Chain (trust.bmc)

Every template that ships a `bmc:` section also ships a `trust:` section with
a `bmc:` class scope. The `trust.bmc` class configures the TLS trust chain used
when the platform connects to BMC endpoints (Redfish, IPMI-over-TLS, vendor
CGI endpoints).

### Chain ordering

All shipped templates use the canonical Phase 3 BMC trust chain:

```yaml
trust:
  bmc:
    # BMC endpoint trust chain. First strategy to succeed wins.
    # tofu is first-contact only — REMOVE it once DANE TLSA records for
    # <hostname>-bmc.<internal-zone> are published (bmc enroll does this).
    strategies: [dane, spki, ca-file, tofu]
    dane:
      dns-server: "127.0.0.1:8053"   # local or CP public DNS
```

Strategies are attempted left-to-right; the first that succeeds is used:

| Strategy | When it succeeds |
|----------|-----------------|
| `dane` | DNSSEC-validated TLSA record exists at `_443._tcp.<hostname>-bmc.<internal-zone>` |
| `spki` | A pinned SPKI SHA-256 hash matches the BMC's leaf certificate |
| `ca-file` | The BMC certificate chains to the PEM bundle at `trust.bmc.ca-file` |
| `tofu` | First connection: captures and pins the BMC leaf SPKI. Subsequent connections verify the stored pin. |

### TLSA record naming convention

BMC TLSA records are published at:

```
_443._tcp.<hostname>-bmc.<internal-zone>
```

For example, if the node hostname is `node-02` and the internal zone is
`example.internal`, the TLSA record lives at:

```
_443._tcp.node-02-bmc.example.internal
```

The enroll ceremony and the AutoCertManager rotation hook publish this record
automatically when BMC enrollment completes.

### Explicit-TOFU rule

TOFU is **never an implicit fallback**. It appears in the template chain
explicitly, with a comment instructing operators to remove it once DANE TLSA
records are live. The template comment reads:

> tofu is first-contact only — REMOVE it once DANE TLSA records for
> `<hostname>-bmc.<internal-zone>` are published (bmc enroll does this).

Environments where DANE TLSA records are already published can remove `tofu`
from the strategies list in their override file:

```yaml
trust:
  bmc:
    strategies: [dane, spki, ca-file]
```

### Deprecated fields

The following `bmc:` fields that provided ad-hoc TLS configuration are
deprecated and will be removed in a future release. The `trust.bmc` chain
supersedes them:

| Deprecated field | Replacement |
|-----------------|-------------|
| `bmc.skip-tls-verify` | Remove the field; use `trust.bmc` strategies instead. Never skip TLS verification. |
| `bmc.ca-cert-path` | Move the path to `trust.bmc.ca-file`; add `ca-file` to the strategies chain. |

## Platform PINs

Templates include `platform.so-pin` and `platform.user-pin` fields using
the canonical `kms://?ensure=` scheme:

```yaml
platform:
  so-pin:   "kms://platform/so-pin?ensure=true&len=8&enc=numeric"
  user-pin: "kms://platform/user-pin?ensure=true&len=6&enc=numeric"
```

platformd resolves these references when it starts, before it reads either
PIN: `SecretsService.EnsureSecret` generates and persists them on first
resolve and returns the same stable bytes on every subsequent boot. Nothing
earlier in the boot reads them: firstboot provisions the TPM with no
hierarchy auth, and the initramfs and installer never open these fields.
There is no need to pass PINs on the command line or store them in override
files.

No shipped template carries a literal PIN, password or key: every field the
platform schema marks secret holds a `kms://` reference.
`TestShippedTemplates_NoLiteralSecrets` (`pkg/app`) fails the build on a
literal value in any template or override example.

## Bootstrap Integration

The `bootstrap.yaml` file references templates by role and applies per-node
overrides automatically during fleet provisioning. Node identity comes from
the first-class node fields — after the overrides merge, the seeder injects
`hostname` as `os.hostname`, the non-empty `bmc_*` fields as
`bmc.address/username/password/protocol`, and `interfaces` as
`network.interfaces`, overwriting any merged value:

```yaml
nodes:
  - hostname: cp-01
    role: control-plane
    template: dedicated/supermicro/x10/control-plane.yaml
    interfaces:
      - name: eno1
        type: static
        ipv4-address: 10.0.1.10/24
        ipv4-gateway: 10.0.1.1
        auto-start: true
    overrides:
      tpm:
        idevid:
          serial: CP01-CHASSIS-SERIAL

  - hostname: gw-01
    role: gateway
    template: dedicated/supermicro/x10/gateway.yaml
```

Repeating the identity keys (`os.hostname`, `network.interfaces`,
`bmc.address`, `bmc.username`, `bmc.password`, `bmc.protocol`) inside an
`overrides:` block or `overrides_file` fails validation with
`ErrForbiddenOverrideKey` (reported with file:line). See the
[bootstrap config reference](bootstrap/engineering.md#3-invariants).

When a `bootstrap.yaml` includes a `switch:` section for physical-switch
auto-configuration, that switch's SSH access is **host-key pinned and
fail-closed**: set `known_hosts_path` to the directory holding the
switch's pinned host-key envelope or Phase 1 refuses to connect (there is
no trust-on-first-use). See [Switch Management](switch/user.md)
for the field reference and the pin-provisioning workflow.

## Automation

The platform API supports creating deployment profiles from templates
combined with overrides. This enables:

- **Self-healing** -- Nodes that fail reprovisioning can be rebuilt from
  their stored profile without manual intervention.
- **Fleet scaling** -- New nodes of a given role are provisioned by
  applying the role template with node-specific overrides.
- **Audit trail** -- Every deployed configuration traces back to a
  versioned template plus a set of overrides.

Profiles are stored in QuicBaaS and accessible via all platform protocols
(REST, gRPC, QUIC, MCP, Unix socket).

## Zone Override Seam

Templates declare an environment (`sdn.environment`) and nothing per VLAN:
every zone's VLAN, subnet, IPAM pool and switch port list is derived from it
by the network plan (`pkg/sdn/netplan`). The built-in zones — `transit`,
`fabric`, `management`, `hypervisor`, `quarantine`, `provisioning`,
`control-plane`, `storage`, `backup` — live in the code defaults registry
(`pkg/sdn/zone/defaults.go`), and their numbering is fixed. Templates do not
restate them: baking zone policy into every template would freeze the
defaults and make upgrades painful. See the [reference
network](architecture/reference-network.md).

There is no `trusted` zone. Trust is carried by identity: OVS and the overlay
admit only a device with a valid IDevID. After enrollment a device's port
carries the zones of its role's port class (`gateway` or `hypervisor`).

### Overriding zone policy

Override files can supply a `zones:` block to tune a built-in zone's policy,
or to add an owner-defined zone at offset 09–99:

```yaml
sdn:
  zones:
    - name: storage                 # tune a built-in: replaces its policy
      isolate: true
      services: [storage]
      allow_to: [{zone: storage, services: [storage]}]
    - name: lab                     # an owner-defined zone: VLAN 409 in environment 4
      offset: 9
      port_classes: [hypervisor]
      isolate: true
```

Only list zones whose policy you need to change. A built-in zone's offset,
port classes and lifecycle role cannot be changed.

### Site numbering that departs from the reference

A site whose VLANs or subnets cannot follow the reference overrides single
zones in its private override file. The zone keeps its identity; only where it
lives changes:

```yaml
sdn:
  environment:
    id: 4
    overrides:
      - zone: control-plane
        vlan: 3006
        subnet: 192.0.2.0/24
```

Every host address then follows the overridden subnet (`network.bonds[].vlans[]`
names the zone, never a VLAN number).
