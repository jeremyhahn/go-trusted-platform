# X10 Lab Validation Runbook — Hardware Offload / 400G

Concise procedure for validating OVS hardware flow offload and recording
datapath performance numbers on the X10 mini cluster. Companion to
[hw-offload.md](./hw-offload.md) (bring-up detail) and the
`platformctl sdn gateway perf` command
([operations.md](../gateway/operations.md#performance-verification)).

> **Written ahead of hardware availability.** The current lab NICs on the
> X10 minis are 1/10G Intel parts with no tc-flower offload engine —
> 400G validation requires ConnectX-6 Dx/Lx or ConnectX-7 (or Broadcom
> Thor2) hardware plus a peer traffic generator. This runbook is the
> procedure to execute when that hardware lands; every results cell
> below stays empty until then. **Record measured values only — never
> projections.**

## 1. Lab prerequisites

- Two nodes with offload-capable NICs cabled back-to-back or through a
  switch fabric rated for the target line rate (400G validation:
  ConnectX-7 / QSFP-DD DACs; the X10 minis' onboard NICs cannot carry
  this test).
- Kernel config verified on BOTH nodes — run the checks from
  [hw-offload.md §Kernel config](./hw-offload.md) (the installer's
  `CheckHWOffloadSupport` in `pkg/installer/hwoffload.go` performs the
  same symbol scan at provisioning time and its report is in the install
  log).
- A traffic generator peer: T-Rex (stateful profiles preferred for CT
  validation) or kernel `pktgen` for raw packet-rate ceilings.
- platformd running on the device-under-test (DUT) with the `sdn:`
  config section enabled so `platformctl sdn gateway perf` is served.

## 2. Switchdev + hw-offload bring-up (DUT)

Follow [hw-offload.md](./hw-offload.md) §Bring-up order; summary:

```sh
# 1. NIC into switchdev mode BEFORE attaching to OVS
devlink dev eswitch set pci/<pcie-addr> mode switchdev

# 2. Enable OVS offload (declaratively via sdn.ovs.hw-offload, or):
ovs-vsctl set Open_vSwitch . other_config:hw-offload=true \
                            other_config:tc-policy=none
systemctl restart openvswitch   # hw-offload is read at vswitchd start

# 3. Attach the uplink + representors to the bridge, then verify
platformctl sdn gateway perf datapath   # hw_offload_enabled must be true
```

## 3. Traffic methodology

- Path under test: the VXLAN overlay path (VNI → VLAN decap pipeline),
  MTU 9000 end-to-end (`ip link set <uplink> mtu 9000` on both ends and
  the generator).
- T-Rex: stateful HTTP-like profile with enough distinct flows to
  exceed the megaflow cache warm-up (≥ 64k concurrent), ramping to the
  target rate. Long-lived flows are REQUIRED — offload applies to
  established datapath flows.
- pktgen: fixed-tuple UDP streams for raw ceiling only; note pktgen
  traffic never establishes conntrack state, so use it for the
  stateless baseline row only.
- Each run: 5 minutes steady state after 1 minute warm-up; record the
  steady-state window only.

## 4. Measurement procedure

For every run, capture BEFORE and AFTER snapshots on the DUT:

```sh
# 1. Datapath counters (hits/misses/lost + offloaded flow count)
platformctl sdn gateway perf datapath -o json

# 2. Offloaded flow inventory (per-flow, from ovs-vswitchd)
ovs-appctl dpctl/dump-flows type=offloaded | wc -l
ovs-appctl dpctl/dump-flows type=ovs | wc -l      # residual software flows

# 3. Representor/uplink hardware counters
ethtool -S <uplink> | grep -E 'rx_packets|tx_packets|rx_bytes|tx_bytes|discard|drop'

# 4. Conntrack population (CT offload verification)
platformctl sdn gateway perf conntrack -o json

# 5. Control-plane programming rate (unrelated to line rate; run once)
platformctl sdn gateway perf flows --count 10000 --batch -o json
```

**Acceptance criterion:** with steady-state established traffic, ≥ 99%
of packets must land on hardware-offloaded flows. Compute it from the
before/after `perf datapath` snapshots: the delta of `hits` attributable
to `type=offloaded` flows (cross-check with `ethtool -S` representor
counters — representor RX/TX barely moving while uplink counters race is
the signature of working offload).

## 5. Results template

Measured values only. Leave cells empty until the run is executed on
real hardware; do not copy numbers from vendor datasheets.

| Run | NIC / fw | Kernel | Profile (gen, flows, MTU) | Offered rate | Achieved rate | % pkts offloaded | dp hits Δ | dp misses Δ | dp lost Δ | CT entries | Notes |
|-----|----------|--------|---------------------------|--------------|---------------|------------------|-----------|-------------|-----------|------------|-------|
| baseline (offload off) | | | | | | 0% (by config) | | | | | |
| offload on, stateless | | | | | | | | | | | |
| offload on, stateful CT | | | | | | | | | | | |
| offload on, VXLAN overlay | | | | | | | | | | | |

## 6. Troubleshooting

Flows not offloading (`dpctl/dump-flows type=offloaded` empty):

- `tc-policy` — must be `none` (or `skip_sw`); `skip_hw` disables
  offload by definition. Check `ovs-vsctl get Open_vSwitch . other_config`.
- Kernel symbols — re-run the [hw-offload.md](./hw-offload.md) config
  check (`CONFIG_NET_TC_SKB_EXT` missing is the classic silent failure:
  first-table flows offload, recirculated ones do not).
- NIC not in switchdev mode — `devlink dev eswitch show pci/<addr>`
  must report `mode switchdev`; legacy mode offloads nothing.
- vswitchd started before `hw-offload=true` was set — restart
  openvswitch; the flag is read once at start.
- CT flows staying in software — mlx5 CT offload needs
  `CONFIG_MLX5_TC_CT` plus ConnectX-6+ firmware; check
  `dmesg | grep -i 'ct offload'` and the mlx5 firmware release notes.
- Individual flow rejection reasons — `ovs-appctl coverage/show` and
  `ovs-vsctl get Open_vSwitch . other_config:tc-policy`, then
  `tc -s filter show dev <representor> ingress` to see whether the
  filter carries `in_hw`/`not_in_hw`.

## 7. Related

- [hw-offload.md](./hw-offload.md) — requirements, bring-up, verification detail
- [operations.md §Performance Verification](../gateway/operations.md#performance-verification) — the perf CLI
- [firewall/performance.md](../firewall/performance.md) — ct pipeline characteristics
