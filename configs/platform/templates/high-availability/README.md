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

QuicBaaS runs with `storage-backend: raft` and full Raft consensus across
the 3 control-plane nodes. Gateway nodes form their own smaller Raft
cluster for conntrack/firewall state replication.

See [dedicated/](../dedicated/) for the current reference architecture.
