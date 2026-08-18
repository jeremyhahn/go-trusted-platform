# Bootstrap Config Delivery

Covers **bootstrap-time** device-config delivery — how the bootstrap
orchestrator gets per-node config onto a freshly-installing machine
before `platformd` is up.

For **post-bootstrap** (production) config fetch by already-running
devices, see `docs/provisioning/config-delivery.md`. For the overall
architecture that places this doc in context, see
`docs/architecture/bootstrap-flow.md`.

---

## 1. Two Delivery Modes, One Default

| Mode | Where config lives | When to use |
|------|--------------------|-------------|
| **Baked** (default) | `/media/cdrom/configs/installer.yaml` inside ISO | Single-node, offline, operator wants one-shot ISOs |
| **Dynamic** | pxeboot HTTP server `/config/mac/<mac>/installer.yaml` | Multi-node fleet, shared ISO, per-MAC role selection |
| **Hybrid** | Both — dynamic tried first, baked as fallback | Multi-node with safety net for config-server outages |

A single ISO can carry both. The install-time priority chain
(`docs/installer/autoinstall.md`) picks dynamic first if the kernel
cmdline says to, then falls back to baked.

---

## 2. Baked Mode (default)

```
  operator                                  target node
     │                                           │
     │ platformctl iso create                    │
     │   [--platform-config X] [--overrides Y]   │
     │                                           │
     ▼                                           │
  ┌─────────────────────────┐                    │
  │ iso create:             │                    │
  │  1. resolve template    │                    │
  │     no flag → single-   │                    │
  │            node/default │                    │
  │  2. merge overrides     │                    │
  │     if --overrides Y    │                    │
  │  3. write to            │                    │
  │     /media/cdrom/       │                    │
  │     configs/            │                    │
  │     installer.yaml      │                    │
  └───────────┬─────────────┘                    │
              │ deliver ISO                      │
              ▼                                  ▼
            ┌──────────────────────────────────────┐
            │ Node boots ISO                       │
            │                                      │
            │ autoinstall.sh PRIO 2:               │
            │   /media/cdrom/configs/installer.yaml│
            │   → /etc/trusted-platform/config.yaml │
            └──────────────────────────────────────┘
```

The default template when no flag is passed is
`configs/platform/templates/single-node/default.yaml`, which enables
both `platformd` (control plane) and `gatewayd` (data plane) collocated
on one box per the reference architecture.

---

## 3. Dynamic Mode

```
  orchestrator                 pxeboot HTTP             target node
  (pkg/bootstrap/)              (deployer :8080)          (booting ISO)
       │                              │                        │
       │ Phase 4 Seed                 │                        │
       │  for each node:              │                        │
       │   merge template+overrides   │                        │
       │   for each MAC:              │                        │
       │     PUT /config/mac/<mac>/   │                        │
       │       installer.yaml ────────▶                        │
       │     PUT /config/mac/<mac>/   │                        │
       │       hostname  ─────────────▶                        │
       │                              │                        │
       │ Phase 5 Boot                 │                        │
       │  BMC vmedia + reboot ─────────────────────────────────▶
       │                              │                        │
       │                              │◀── GET /config/mac/    │
       │                              │     <mac-dashed>/      │
       │                              │     installer.yaml ────│
       │                              │                        │
       │                              │◀── GET /config/mac/    │
       │                              │     <mac-dashed>/      │
       │                              │     hostname ──────────│
       │                              │                        │
       │                              │                        │
       │                              │  (install → disk → reboot)
       │                              │                        │
       │                              │◀── POST /install-log/  │
       │                              │     <mac>/success ─────│
```

ISO built with `--config-server=http://<deployer>:8080/config/mac`
gets the kernel cmdline parameter `platform_config=<URL>` baked in.
At install time, `autoinstall.sh` appends `/<mac-dashed>/installer.yaml`
and does an HTTP GET.

**Why per-MAC, not per-hostname**: the installer only knows its own
MAC. It doesn't know it's "lab-node-2" until the config tells it.
Publishing under every MAC the orchestrator has discovered (YAML +
BMC) guarantees the installer finds its config on the first NIC the
live environment enumerates.

---

## 4. Hybrid Mode

```
platformctl iso create \
  --config-server http://deployer:8080/config/mac \
  --platform-config configs/platform/templates/.../fallback.yaml
```

Both mechanisms enabled. At install time:
1. `autoinstall.sh` PRIO 1 tries dynamic fetch
2. On any failure (DNS, network, 404, 5xx), falls through to PRIO 2
3. PRIO 2 reads the baked `/media/cdrom/configs/installer.yaml`

Use hybrid when the bootstrap orchestrator environment has
intermittent network connectivity to the target's install network,
or when you want a guaranteed-bootable ISO that can still benefit
from fresh per-node config when available.

---

## 5. What the Orchestrator Publishes (per MAC)

Per `pkg/bootstrap/virtual_media.go::stagePerMACHostname`:

| Key | Content-Type | Content |
|-----|--------------|---------|
| `installer.yaml` | `application/yaml` | Full merged device config (template + overrides_file + inline overrides + node identity injection) |
| `hostname` | `text/plain; charset=utf-8` | Target hostname (e.g., `lab-node-2`) |

Published under **every MAC** in `union(node.MACs YAML-declared, BMC-discovered MACs)`.

Max payload size: 256 KiB (see `maxConfigValueBytes` in
`pkg/ipxe/http_server.go`). Larger configs fail the PUT with HTTP 413.

---

## 6. URL Format

```
Server URL (baked into cmdline via --config-server):
    http://<deployer_host>:8080/config/mac

Per-MAC fetch URL (built at install time by autoinstall.sh):
    <server URL>/<mac-dashed>/installer.yaml
    <server URL>/<mac-dashed>/hostname

where <mac-dashed> is lowercase with dashes:
    aa-bb-cc-dd-ee-ff
```

Server rejects uppercase or colon-separated MACs with HTTP 400. Keep
clients consistent — `autoinstall.sh` lowercases and dash-formats
before issuing the request.

---

## 7. Orchestrator Responsibilities (Phase-by-Phase)

See `docs/bootstrap/pxe-bootstrap.md` for the complete orchestrator
state machine. Config-delivery-relevant phases:

**Phase 0 — Discovery**
- Enumerate nodes from bootstrap.yaml
- Query each node's BMC for MAC addresses
- Union YAML `macs:` list with BMC-discovered MACs

**Phase 4 — Seed**
- For each node:
  - Load role template (`configs/platform/templates/<profile>/<vendor>/<model>/<role>.yaml`)
  - Apply `overrides_file` (deep merge, override wins on conflict)
  - Apply inline `overrides` block from bootstrap.yaml (deep merge)
  - Inject node identity (overwrite): `os.hostname`, non-empty
    `bmc.address/username/password/protocol`, and `network.interfaces`
    from the node's first-class `hostname`/`bmc_*`/`interfaces` fields
  - Serialize merged YAML
- For each MAC of each node:
  - PUT merged YAML to `/config/mac/<mac>/installer.yaml`
  - PUT hostname to `/config/mac/<mac>/hostname`
- For client nodes (non-control-plane), additionally stage trust
  material captured from the control plane:
  - PUT CA bundle PEM to `/config/mac/<mac>/ca-bundle.pem` (installer
    adds it to the OS trust store, unblocking first-boot ACME
    enrollment against the private CA)
  - PUT SPKI pin to `/config/mac/<mac>/bootstrap-spki-pin` (fallback
    for the platform's SPKI bootstrap-trust strategy when bundle
    delivery is unavailable)

  The CA bundle fetch uses **capture-then-verify**, not blind TOFU:
  the orchestrator captures the TLS chain presented by the control
  plane during the handshake and, after reading the bundle, verifies
  that chain against the bundle itself (anchored at the CP address it
  dialed). A bundle whose serving chain does not verify against it is
  rejected and never staged. The SPKI pin capture hard-requires the
  verified CA pool from the bundle fetch — if the bundle fetch failed,
  no pin is captured (the node falls back to its remaining
  trust-bootstrap strategies) rather than pinning an unverified
  endpoint.

**Phase 5 — Boot**
- Stage ISO to SMB share
- BMC: mount virtual media, set boot-once to CD, reboot

**Phase 6 — Watch**
- Poll `/install-log/<mac>/status` for install progress
- Collect install.log on success or failure

---

## 8. Operator Workflow Examples

### 8.1 Single-node deploy (baked default)

```
platformctl iso create \
  --output single-node.iso

# Burn to USB, boot, install. Uses shipped single-node template
# with reference-architecture defaults.
```

### 8.2 Single-node with customization

```
platformctl iso create \
  --platform-config configs/platform/templates/single-node/default.yaml \
  --overrides /path/to/my-site-overrides.yaml \
  --output my-single-node.iso
```

### 8.3 Dedicated 3-node with per-role baked ISOs

```
for role in control-plane gateway compute; do
  platformctl iso create \
    --platform-config configs/platform/templates/dedicated/supermicro/x10/${role}.yaml \
    --overrides /path/to/overrides/${role}.yaml \
    --output ${role}.iso
done
# Use bootstrap.yaml with per-node iso_path references.
```

### 8.4 Dedicated 3-node with shared ISO + dynamic fetch

```
platformctl iso create \
  --config-server http://deployer.lan:8080/config/mac \
  --output shared.iso

# bootstrap.yaml references overrides_file per node. Orchestrator
# merges template+overrides per node at Phase 4 and publishes
# per-MAC. Single ISO installs CP, GW, and compute correctly.
platformctl bootstrap run --config /path/to/infra/dedicated/bootstrap.yaml
```

### 8.5 Hybrid (dynamic preferred, baked fallback)

```
platformctl iso create \
  --config-server http://deployer.lan:8080/config/mac \
  --platform-config configs/platform/templates/single-node/default.yaml \
  --output hybrid.iso
```

---

## 9. Security Considerations

- Bootstrap HTTP server runs on a **private deployer network** — plain
  HTTP is acceptable because operator controls the wire and no secrets
  traverse unencrypted.
- Config YAML files contain references to KMS key IDs and secret names,
  **not raw secrets**. Secrets are resolved at `platformd` startup
  against the ceremony-unlocked KMS. See `docs/secrets/`.
- Adversary on the install network could poison a MAC→config mapping.
  Mitigations: segment the deployer network, require operator-signed
  bootstrap.yaml (future work), migrate to post-bootstrap config
  delivery (`docs/provisioning/config-delivery.md`) after first install
  for day-2 changes.
- **Never** use this path for production re-provisioning. Use
  `platformctl-static bootstrap trust` with DANE/Noise/SPKI + EAB for
  any device-config fetch outside the initial bootstrap window.

---

## 10. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| autoinstall drops to shell after "config fetch failed" | Config server unreachable or MAC not published | Check `curl http://<deployer>:8080/config/mac/<mac>/installer.yaml` from the install environment |
| Installed node runs with generic "server" hostname | `/config/mac/<mac>/hostname` not published or autoinstall fetched before orchestrator PUT | Verify Phase 4 ran before Phase 5; check orchestrator logs for "staged per-MAC hostname" |
| CP installs with GW config (or vice versa) | YAML MAC list doesn't match actual NIC MACs | Add BMC discovery or list all NIC MACs in `bootstrap.yaml`'s `macs:` for that node |
| HTTP 413 on config PUT | Merged config >256 KiB | Trim template/overrides; file bug to raise `maxConfigValueBytes` if legitimately needed |
| HTTP 400 on config GET | MAC formatted as `AA:BB:CC:...` | Client must use lowercase dashed format `aa-bb-cc-...` |

---

## 11. See Also

- `docs/architecture/bootstrap-flow.md` — overall architecture
- `docs/bootstrap/pxe-bootstrap.md` — orchestrator phase detail
- `docs/installer/autoinstall.md` — install-time priority chain
- `docs/installer/iso-building.md` — `platformctl iso create` reference
- `docs/ipxe/architecture.md` — HTTP server endpoints
- `docs/device-templates.md` — template + overrides semantics
- `docs/reference/kernel-cmdline.md` — all `platform_*` cmdline params
- `docs/provisioning/config-delivery.md` — post-bootstrap production flow
- `configs/platform/templates/dedicated/README.md` — dedicated 3-node profile architecture (bond / bridge / DNS / fabric)
- `configs/platform/templates/single-node/README.md` — CP+GW collocated profile
