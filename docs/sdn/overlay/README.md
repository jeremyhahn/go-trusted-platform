# VXLAN Overlay Networking

> **Status: REFERENCE** · Last verified: 2026-10-15
> Overview of the EVPN/VXLAN overlay.

Multi-host overlay networking for east-west VM and container traffic.

## Overview

The overlay gives every VNI one Layer 2 segment across hosts, and routes
between VNIs with an anycast gateway on every host. It is EVPN over
VXLAN: BGP EVPN routes say which MACs, IPs and VNIs each VTEP serves,
and OpenFlow flows on one OVS bridge forward accordingly through a
single flow-based VXLAN port.

## Key Features

| Feature | Description |
|---------|-------------|
| **VXLAN Encapsulation** | RFC 7348, 24-bit VNI, one `remote_ip=flow` port per host |
| **EVPN Control Plane** | Type-2 MAC/IP, Type-3 IMET and Type-5 prefix routes ([BGP EVPN](../../bgp/engineering.md#7-evpn)) |
| **Decap Authorisation** | a tunnelled frame is accepted only from a VTEP EVPN places on its VNI |
| **BUM Handling** | ingress replication to the VTEPs of the VNI, from Type-3 routes |
| **ARP/ND Suppression** | A flow answers ARP for known IPv4 bindings. An IPv6 NS for a known target is punted to a packet-in controller, answered with a proxy NA and not flooded (RFC 9161). Unknown targets and DAD probes flood. Fail mode: the punts expire 12 s after a crash, are removed on stop, and are withdrawn on any meter or queue drop, so the NS floods ([ND fail mode](../../gateway/engineering.md#fail-mode)) |
| **Symmetric IRB** | anycast gateway on every VTEP; routed traffic crosses the L3VNI |
| **VNI Numbering** | overlay network n of environment E is VNI E·100000+n ([reference network](../../architecture/reference-network.md)) |

## Architecture Overview

```
Host A                                              Host B
+---------------------------+                       +---------------------------+
|  VM1          VM2         |                       |  VM3          VM4         |
|    |            |         |                       |    |            |         |
|    +-----+------+         |                       |    +-----+------+         |
|          | access port    |                       |          | access port    |
|    +-----v------+         |                       |    +-----v------+         |
|    | OVS br-int |         |                       |    | OVS br-int |         |
|    | vxlan-evpn |         |                       |    | vxlan-evpn |         |
|    +-----+------+         |                       |    +-----+------+         |
|          | VTEP 10.0.0.1  |                       |          | VTEP 10.0.0.2  |
+----------|----------------+                       +----------|----------------+
           |      VXLAN, UDP 4789, VNI from the flow           |
           +---------------------------------------------------+
                              |
                      Physical Network
                    (underlay MTU >= 9050)
```

Each host's flows pick the destination VTEP and VNI per frame; adding a
host changes flows, not ports. The pipeline is specified in
[the overlay handler](../../gateway/engineering.md#the-overlay-handler-overlaymodehandler) and the
components in [architecture.md](architecture.md).

## VTEP Discovery

VTEPs learn about each other from EVPN, not from replicated state:

1. Host A adds a VNI and joins its EVI, originating a Type-3 route.
2. Host B imports it: Host A's VTEP is authorised to send on that VNI and
   joins the VNI's flood list.
3. As hosts learn local MACs, their Type-2 routes install the MAC and IRB
   forwarding on every other host.

## Quick Start

### Enable Overlay

```yaml
# config.yaml
sdn:
  enabled: true
  overlay:
    enabled: true
    vxlan-port: 4789
    underlay-interface: "eth0"
```

`underlay-interface` is required without IPsec; there is no default. The
VTEP IP is `overlay.vtep-address`, else the node's detected public IPv4
address; with overlay IPsec it is always `overlay.ipsec.local-address`. MTU
and bridge name use applied defaults (see [Configuration](configuration.md)).

### Verify VTEP Status

```bash
# Check overlay and VTEP registration
platformctl sdn overlay status
platformctl sdn overlay vtep list

# List active VNIs
platformctl sdn overlay vni list
```

### Check Connectivity

```bash
# The one VXLAN port and its options
ovs-vsctl list interface vxlan-evpn

# Underlay reachability and MTU to the remote VTEP
ping -M do -s 9022 10.0.0.2
nc -zuv 10.0.0.2 4789
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Components, the VXLAN port, encapsulation and MTU |
| [Overlay handler](../../gateway/engineering.md#the-overlay-handler-overlaymodehandler) | The OpenFlow data plane |
| [Configuration](configuration.md) | Complete configuration reference |
| [API Reference](api-reference.md) | Multi-protocol API documentation |

## Performance Considerations

| Aspect | Value |
|--------|-------|
| Overlay (workload) MTU | 9000 |
| VXLAN overhead | 50 bytes (Ethernet + IP + UDP + VXLAN) |
| Underlay MTU | at least 9050; platform switch ports run 9216 |
| Hardware offload | enable VXLAN offload on supported NICs |

## Security Model

- A VTEP can inject frames only into the VNIs its EVPN routes place it
  on; everything else from the VXLAN port is dropped in table 10.
- Before a route is installed, the handler's `VTEPAdmitter` vets the
  VTEP; EVPN without one is a config error (`ErrAdmitterNil`). In
  gatewayd it is `gateway.VTEPAdmitter`
  (`pkg/sdn/gateway/vtep_admission.go`): the VTEP address must be a
  platform IPAM fabric allocation of a device whose attestation verdict
  passes, and a periodic sweep re-judges every installed VTEP.
- Encryption of VTEP-to-VTEP traffic comes from overlay IPsec
  (`overlay.ipsec`, which fails closed without SAs) or the underlay.
- VNI isolation keeps segments apart; routing between them crosses the
  anycast gateway.

## Troubleshooting

| Issue | Check |
|-------|-------|
| No overlay connectivity | underlay MTU is at least 9050 on every hop |
| Remote MAC unreachable | the remote host's Type-2 route is received ([BGP EVPN](../../bgp/engineering.md#7-evpn)) |
| Frames from a VTEP dropped | its Type-3 route for the VNI is received; table 10 has a `tun_src` flow for it |
| Dropped packets | `ovs-ofctl -O OpenFlow13 dump-flows br-int` |

## See Also

- [SDN Architecture](../architecture.md)
- [SDN Configuration](../configuration.md)
- [BGP EVPN](../../bgp/engineering.md#7-evpn)
