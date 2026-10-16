# Firewall Performance

> **Status: REFERENCE** · Last verified: 2026-10-15
> What determines firewall throughput now that the userspace engine is gone.

The former Go userspace firewall engine has been replaced by the
OVS-native conntrack firewall (`ct()` / `ct_state` flows); its code
(`pkg/sdn/firewall`) has been deleted. Packets are filtered entirely
in the kernel OVS datapath — there is no Go userspace packet path.

## Performance Characteristics

With the OVS-native design, firewall performance is determined by the
kernel OVS datapath (megaflow cache hit rate, conntrack table sizing)
and by NIC hardware offload support — not by Go code. No benchmark
figures were ever published for the deleted userspace engine; it was
never deployed in production. Established connections match the
`+est` fast-path flow and are eligible for kernel conntrack offload
on NICs that support it.

Measured numbers will be published from lab validation only. See
[performance/x10-lab-validation.md](../performance/x10-lab-validation.md)
for the validation runbook (results table stays empty until the runs
complete on offload-capable X10 lab hardware).

## Tuning Guidelines

Until lab-validated guidance exists, tuning follows standard OVS
practice:

- Prefer an `established` fast-path rule so most traffic matches the
  conntrack `+est` state without full rule evaluation.
- Keep rule and zone counts modest; each distinct match dimension
  increases megaflow cache fragmentation.
- Size the kernel conntrack table (`net.netfilter.nf_conntrack_max`)
  and timeouts for the expected connection churn.
- Enable NIC offloads (checksum, TSO, and tc flower/OVS hardware
  offload where supported) for the datapath NICs.

## Monitoring

Datapath counters are exposed by OVS itself:

```bash
ovs-appctl dpctl/show -s          # datapath packet/byte/flow stats
ovs-appctl dpctl/ct-stats-show    # conntrack entry counts by state
ovs-ofctl dump-flows br-int       # per-flow packet/byte counters
```

## See Also

- [Architecture](./architecture.md) - Internal design
- [Configuration](./configuration.md) - Config reference
- [README](./README.md) - Overview
