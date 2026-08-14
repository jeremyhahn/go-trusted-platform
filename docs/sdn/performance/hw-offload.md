# OVS Hardware Offload (tc-flower)

Hardware flow offload moves established OVS datapath flows out of the
kernel software path and into the NIC's embedded switch. platformd enables
it declaratively via the `sdn.ovs.hw-offload` config key (see
[configuration.md](../configuration.md), `ovs:` section); this document
covers the hardware/kernel requirements, bring-up order, what actually
offloads, and how to verify it.

## Requirements

### NIC support matrix

| NIC | Driver | Offload engine | Notes |
|-----|--------|----------------|-------|
| Mellanox/NVIDIA ConnectX-5 | `mlx5_core` | switchdev e-switch | tc-flower L2/VLAN/VXLAN; CT offload limited by firmware generation |
| Mellanox/NVIDIA ConnectX-6 Dx/Lx | `mlx5_core` | switchdev e-switch | Full tc-flower + connection-tracking offload |
| Mellanox/NVIDIA ConnectX-7 (400G) | `mlx5_core` | switchdev e-switch | Full tc-flower + connection-tracking offload |
| NVIDIA BlueField-2/3 | `mlx5_core` | switchdev e-switch (DPU) | Same mlx5 switchdev path; can also run OVS on the DPU Arm cores |
| Broadcom NetXtreme-E (incl. 400G Thor2) | `bnxt_en` | TruFlow | tc-flower via `CONFIG_BNXT_FLOWER_OFFLOAD`; CT offload depends on firmware |

Both driver families are included in the platform's installer/initrd
driver set (`mlx5_core`, `bnxt_en` in the initramfs module injection, the
PXE `modules=` cmdline, the installed system's `/etc/modules`, and the
dracut `--add-drivers` list), and the ISO prefetch ships
`linux-firmware-mellanox` plus `linux-firmware-bnx2`/`-bnx2x`.
ConnectX and NetXtreme-E datapath firmware runs from on-board flash;
the packages cover devlink/mlxfw flashing and the legacy bnx2/bnx2x
runtime blobs.

### Kernel config

The tc classifier path, the conntrack fast path, and the driver-side
offload engines are all gated behind kernel config symbols:

| Symbol | Gates |
|--------|-------|
| `CONFIG_NET_CLS_FLOWER` | tc-flower classifier (all offload) |
| `CONFIG_NET_SWITCHDEV` | switchdev representor model |
| `CONFIG_NET_TC_SKB_EXT` | tc recirculation metadata (OVS multi-table offload) |
| `CONFIG_NF_FLOW_TABLE` | conntrack flow-table fast path |
| `CONFIG_NET_ACT_CT` | tc `ct` action (offloading `ct()` flows) |
| `CONFIG_MLX5_ESWITCH` | mlx5 switchdev e-switch |
| `CONFIG_MLX5_CLS_ACT` | mlx5 tc-flower offload |
| `CONFIG_MLX5_TC_CT` | mlx5 connection-tracking offload |
| `CONFIG_BNXT_FLOWER_OFFLOAD` | bnxt_en tc-flower (TruFlow) offload |

**Alpine `linux-lts` caveat:** these symbols are NOT guaranteed across
Alpine releases and must be verified per release against the running
kernel:

```sh
# Core tc/ct fast path
zcat /proc/config.gz | grep -E 'CONFIG_(NET_CLS_FLOWER|NET_SWITCHDEV|NET_TC_SKB_EXT|NF_FLOW_TABLE|NET_ACT_CT)='

# Driver-side engines
zcat /proc/config.gz | grep -E 'CONFIG_(MLX5_ESWITCH|MLX5_CLS_ACT|MLX5_TC_CT|BNXT_FLOWER_OFFLOAD)='
```

`=y` or `=m` is required for each; a missing line or `# ... is not set`
means that offload stage silently falls back to the kernel software path.
The installer exposes this check programmatically as
`installer.CheckHWOffloadSupport` (parses `/proc/config.gz`-style content
and reports missing symbols, grouped core/mlx5/bnxt).

## Bring-up order

Ordering matters: the NIC must be in switchdev mode **before**
ovs-vswitchd starts, and `hw-offload` is read **once** at ovs-vswitchd
startup.

1. **Switch the e-switch to switchdev mode** (per PF, before ovs-vswitchd
   starts — typically from an early boot script or udev rule):

   ```sh
   devlink dev eswitch set pci/0000:3b:00.0 mode switchdev
   ```

   This creates one representor netdev per VF/SF; OVS ports attach to the
   representors, not the VFs themselves. Verify with
   `devlink dev eswitch show pci/0000:3b:00.0`.

2. **Enable offload in the platform config:**

   ```yaml
   sdn:
     ovs:
       hw-offload: true
       tc-policy: none   # optional; see below
   ```

   platformd writes `other_config:hw-offload=true` (and
   `other_config:tc-policy` when set) to the global Open_vSwitch row on
   startup — see the `ovs:` section in
   [configuration.md](../configuration.md).

3. **Restart ovs-vswitchd** if the value changed on a running system.
   ovs-vswitchd reads `hw-offload` once at startup; platformd logs a
   prominent warning when it changes the value but never restarts the
   daemon itself.

`tc-policy` values:

| Value | Behavior |
|-------|----------|
| `none` (default) | Try hardware, fall back to tc software path |
| `skip_sw` | Hardware only — flows that cannot offload are dropped from tc (debugging/enforcement) |
| `skip_hw` | Software only — disables hardware offload while keeping the tc datapath (A/B debugging) |

## What offloads (and what does not)

| Flow class | Offloads? | Notes |
|------------|-----------|-------|
| L2 forwarding, VLAN push/pop | Yes | Basic tc-flower match/actions |
| VXLAN encap/decap | Yes | Including tunnel-key (VNI/outer header) matches on the uplink representor |
| Established conntrack flows (`ct_state=+est`) | Yes | Requires the kernel CT symbols above; flow-table fast path handles the established fastpath |
| Group *select* buckets (LB first packets) | No | Bucket selection is not expressible in tc; the first packet(s) of each load-balanced connection stay in the kernel path |
| `ct(alg=...)` flows | No | ALG helpers require kernel conntrack |
| Deep recirculation chains | No | Beyond the NIC's recirculation depth, flows stay in software |

**Operational implication:** for load-balanced (group/select) traffic the
first packet of every new connection traverses the kernel datapath and
only the established flow offloads. Connection-setup rate therefore
remains CPU-bound even with offload enabled; steady-state established
throughput is what the NIC accelerates.

## Verification

```sh
# Offloaded datapath flows (empty output = nothing offloaded)
ovs-appctl dpctl/dump-flows type=offloaded

# Software-path flows for comparison
ovs-appctl dpctl/dump-flows type=ovs

# Per-representor hardware counters
ethtool -S <representor> | grep -i offload

# Raw tc view: offloaded filters are flagged in_hw / not_in_hw
tc -s filter show dev <representor> ingress
```

A flow marked `offloaded:yes, dp:tc` in `dump-flows` output is running in
hardware.

## Performance numbers

None are published here by design. Throughput/latency/CPS figures depend
on NIC generation, firmware, and kernel; they will be captured in the
X10 lab validation report ([x10-lab-validation.md](./x10-lab-validation.md)
— runbook ready, results table empty until measured on offload-capable
platform hardware).
