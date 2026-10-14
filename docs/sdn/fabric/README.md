# Physical Switch Fabric Management

`pkg/sdn/fabric` programs the platform's physical switches to the
[reference network](../../architecture/reference-network.md): the switch is **pure L2**. It carries the
environment's underlay zone VLANs, each port carries what its **port class** carries, and it does no
routing, SVIs, ACLs or EVPN. Gateways route; VTEPs live on the hosts.

Every number comes from the network plan (`pkg/sdn/netplan`), derived from `sdn.environment` and
`sdn.zones`. The fabric configuration names switches, peer links, LAGs and port classes; it never names
a VLAN.

## What it does

| Operation | Effect on every switch |
|-----------|-----------------------|
| `ApplyFabric` | Creates one VLAN per zone (named after the zone), the LAGs, the peer-link class on every peer-link port, and each assigned port's class |
| `ProvisionPort` | Port becomes a trunk carrying only `provisioning`, native |
| `ActivatePort(class)` | Port carries its class: allowed VLANs, native VLAN, MTU 9216 |
| `QuarantinePort` | Port becomes a trunk carrying only `quarantine`, native |
| `DisablePort` | Port is administratively shut down |

The lifecycle operations are applied to the same port on every MC-LAG/vPC peer switch, so a dual-homed
node's two links stay identical. `ApplyFabric` applies each assigned port only on the switch it is
listed on. All driver operations are idempotent: a port already in the requested state is not touched.

## Port classes

For environment _E_ (zone offsets `x00`–`x08`, owner-defined zones `x09`–`x99`):

| Class | Mode | Allowed VLANs | Native |
|-------|------|---------------|--------|
| `gateway` | trunk | x00, x01, x04, x05, x06, x08 (+ owner zones that list `gateway`) | none |
| `hypervisor` | trunk | x01, x03–x08 (+ owner zones that list `hypervisor`) | x05 `provisioning` |
| `bmc` | access | x02 | — |
| `mgmt-uplink` | trunk | x02 | none |
| `peer-link` | trunk | every zone VLAN of the block | none |

Every port runs MTU 9216 so VXLAN encapsulation never fragments. The table is `netplan.Plan.PortClass`.

## Example

```yaml
sdn:
  environment:
    id: 4
  fabric:
    switches:
      - id: sw-01
        vendor: cisco-nexus
        model: N9K-C93180YC-EX
        mgmt-ip: 192.0.2.10
        credentials-ref: "kms://switches/sw-01"
      - id: sw-02
        vendor: cisco-nexus
        mgmt-ip: 192.0.2.11
        credentials-ref: "kms://switches/sw-02"
    peers:
      - switch-a: sw-01
        switch-b: sw-02
        peer-link-ports: [Ethernet1/50, Ethernet1/52]
    ports:
      - {switch-id: sw-01, port: Ethernet1/3, class: gateway, description: gw-01}
      - {switch-id: sw-01, port: Ethernet1/25, class: hypervisor, description: cp-01}
      - {switch-id: sw-01, port: Ethernet1/41, class: bmc, description: gw-01 bmc}
```

## Status

The fabric manager is a library: `platformd` validates `sdn.fabric` at startup but does not yet drive
the switches from it. Day-zero switch configuration is done by the bootstrap switch phase
(`bootstrap.yaml` `switch:`, [switch management](../../switch/user.md)), which uses the
same port classes from the same plan.

## Documents

- [configuration.md](configuration.md) — the `sdn.fabric` schema and validation
- [api-reference.md](api-reference.md) — the Go API (`Manager`, `Driver`, types, errors)
- [adding-drivers.md](adding-drivers.md) — writing a vendor driver
