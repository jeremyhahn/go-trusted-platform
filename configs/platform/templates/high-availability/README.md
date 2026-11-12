# High-Availability Deployment Profile

Full HA cluster layout:

- 3 control-plane nodes (Raft quorum)
- 2 gateway nodes (active-active with VIP failover)
- 2 compute nodes (workload redundancy)

## Status

The three control-plane templates are under `supermicro/x10/cp1..cp3`
(`cp1/control-plane.yaml`, `cp2/control-plane.yaml`, `cp3/control-plane.yaml`):
the x10 dedicated control plane with node-id 1, 2 and 3, one shared
`deployment-id`, all three members in `join-addresses`, `pebble` storage and
Raft mutual TLS. The gateway pair (#710) and the compute pair are not provided
yet.

## Intended Use

- Production deployments with availability SLOs
- Multi-tenant platforms where datastore and gateway resilience matter

The network follows the HA topology of the reference network
(`docs/architecture/reference-network.md`): the same zones and port classes
as `dedicated/`, on a vPC/MLAG switch pair, with the gateway pair sharing each
zone's `.1` as a VRRP address (`.2` and `.3` are the gateway nodes) and
syncing state over the reserved `10.E.128.0/31` link.

QuicBaaS runs full Raft consensus across the 3 control-plane nodes. Raft is
engaged by `join-addresses`, not by the storage backend (`storage-backend:
raft` is refused; clustered nodes use `pebble`): each control-plane node lists
all three members as `id=host:port`, shares one `deployment-id`, and sets the
three `raft-tls-*-file` keys, because Raft between peers is always mutual TLS.
[configs/platform/cluster/](../../cluster/) holds a working three-server
example, and [docs/cluster/user.md](../../../../docs/cluster/user.md) the rules. Gateway nodes form their own smaller Raft
cluster for conntrack/firewall state replication.

See [dedicated/](../dedicated/) for the current reference architecture.
