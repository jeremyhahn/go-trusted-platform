# High-Availability Deployment Profile (Planned)

Full HA cluster layout:

- 3 control-plane nodes (Raft quorum)
- 2 gateway nodes (active-active with VIP failover)
- 2 compute nodes (workload redundancy)

## Status

Not implemented yet. Will be populated once the `dedicated/` profile is
proven end-to-end.

## Intended Use

- Production deployments with availability SLOs
- Multi-tenant platforms where datastore and gateway resilience matter

The network follows the HA topology of the reference network
(`docs/architecture/reference-network.md`): the same zones and port classes
as `dedicated/`, on a vPC/MLAG switch pair, with the gateway pair sharing each
zone's `.1` as a VRRP address (`.2` and `.3` are the gateway nodes) and
syncing state over the reserved `10.E.128.0/31` link.

QuicBaaS runs with `storage-backend: raft` and full Raft consensus across
the 3 control-plane nodes. Gateway nodes form their own smaller Raft
cluster for conntrack/firewall state replication.

See [dedicated/](../dedicated/) for the current reference architecture.
