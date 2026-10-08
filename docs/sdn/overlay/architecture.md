# VXLAN Overlay Architecture

## System Overview

The overlay is EVPN over VXLAN. BGP EVPN carries what each VTEP serves;
OpenFlow on one OVS bridge forwards it. Four pieces divide the work:

| Piece | Package | Owns |
|-------|---------|------|
| EVPN manager | `pkg/sdn/bgp` (`EVPNManager`) | Type-2/3/5 routes: origination, import, MAC Mobility. See [../bgp/evpn.md](../bgp/evpn.md) |
| VTEP manager | `pkg/sdn/vxlan` (`VTEPManager`) | the one flow-based VXLAN port on the bridge |
| Overlay mode handler | `pkg/sdn/gateway/modes` (`OverlayModeHandler`) | the data plane: every overlay flow, built from EVPN routes. See [../gateway/overlay-mode.md](../gateway/overlay-mode.md) |
| Overlay controller | `pkg/sdn/overlay` (`Controller`) | the API-facing registry of VNIs, VTEPs and remote MACs; joins a VNI's EVI to originate its Type-3 route |

```
              BGP EVPN (Type-2 / 3 / 5)
                        |
                 +--------------+
                 | EVPNManager  |
                 +--------------+
                        | route events
                        v
  +--------------------------------------------+
  | OverlayModeHandler                          |
  |  flows: decap authorisation, MAC, ARP,      |
  |  IRB routes, ingress replication            |
  +--------------------------------------------+
        | OpenFlow                  | OVSDB
        v                           v
  +--------------------------------------------+
  | OVS bridge (br-int)                         |
  |   access port   <-->   vxlan-evpn           |
  |   (VNIs as VLANs)      remote_ip=flow       |
  |                        key=flow             |
  +--------------------------------------------+
                        |
                 underlay (UDP 4789)
```

## The VXLAN Port

There is exactly one VXLAN port per bridge, `vxlan-evpn`
(`vxlan.DefaultPortName`), created by `VTEPManager.Start` with
`remote_ip=flow`, `key=flow`, `local_ip` set to the local VTEP and
`dst_port` set to the VXLAN UDP port. Flows choose each frame's
destination VTEP (`tun_dst`) and VNI (`tun_id`) and match the VNI and
source VTEP (`tun_src`) of each frame received on it. Adding or losing a
remote VTEP changes flows, never ports: there are no per-peer or per-VNI
tunnel ports.

`Start` adopts a port of that name that already has these options, and
refuses one that does not (`vxlan.ErrPortConflict`) instead of
rewriting it. `Stop` deletes the port. `OFPort()` is the OpenFlow port
number the flows output to.

## Encapsulation and MTU

```
+-----------+----------+---------+-----------+-------------------------+
| Outer Eth | Outer IP | UDP     | VXLAN     | inner frame             |
| 14 B      | 20 B     | 8 B     | 8 B (VNI) | up to the overlay MTU   |
+-----------+----------+---------+-----------+-------------------------+
            src: local VTEP, dst: tun_dst      UDP dst 4789
```

The overlay MTU is 9000 bytes (`vxlan.OverlayMTU`) and encapsulation
adds 50 (`vxlan.VXLANOverhead`), so the underlay must carry 9050 bytes
(`vxlan.MinimumUnderlayMTU`). A VTEP config with a smaller underlay MTU
is refused rather than fragmenting. Platform switch ports run 9216
(`netplan.MTU`), the default.

## Data Plane

The OpenFlow pipeline, decap authorisation, BUM ingress replication,
ARP suppression and symmetric IRB are specified in
[../gateway/overlay-mode.md](../gateway/overlay-mode.md). In short:

- a frame from the VXLAN port enters the pipeline only when its
  `tun_src` is a VTEP EVPN places on its `tun_id`; every other tunnelled
  frame is dropped;
- a known MAC goes to its VTEP, unknown and broadcast frames are
  replicated to every VTEP on the VNI (from Type-3 routes);
- ARP for known bindings and the anycast gateway is answered by a flow,
  with no packet-in;
- routed traffic crosses the L3VNI router MAC to router MAC.

## Overlay Controller

`overlay.Controller` is the overlay surface of the multi-protocol API
(see [api-reference.md](api-reference.md)). It keeps VNIs, VTEPs, tunnel
records and remote MACs in an in-memory `overlay.StateManager`, expires
learned remote MACs after `MACExpiration`, and reports health from its
OVS and OpenFlow clients and the VTEP manager. With `EnableEVPN`, adding
a VNI with `AdvertiseIMET` joins its EVI (`EVPNManager.JoinVNI`), which
originates the Type-3 route, and removing it leaves the EVI. VNI numbers
follow the reference network plan: overlay network n of environment E is
VNI E·100000+n (`netplan.VNI`).

The controller programs no flows and creates no ports; its records are
bookkeeping for the API. The data plane is the overlay mode handler's.

## Errors

| Error | Package | Meaning |
|-------|---------|---------|
| `ErrUnderlayNotReady` | `vxlan` | the VTEP config names no underlay interface |
| `ErrPortConflict` | `vxlan` | a port with the VTEP's name exists with other options |
| `ErrOVSOperationFailed` | `vxlan` | OVSDB refused a port create, read or delete |
| `ErrVTEPOperationFailed` | `modes` | a route's VTEP was refused admission or is not a usable IPv4 VTEP |
| `ErrFlowOperationFailed` | `modes` | the switch refused a flow change; the flows the batch touched are put back, so the switch and handler state are unchanged |
| `ErrBindingConflict` | `modes` | a Type-2 route claimed the anycast gateway's MAC or IP; refused whole and counted in `RefusedBindings`. A route claiming a local host's IP is not an error: its MAC is bridged and its IP held back until the local host goes |
| `ErrFlowResyncFailed` | `modes` | the switch refused the put-back too, or the rebuild after one; the next change flushes the overlay flows and reinstalls the committed ones before applying anything |

## See Also

- [Overlay mode (data plane)](../gateway/overlay-mode.md)
- [BGP EVPN](../bgp/evpn.md)
- [Configuration](configuration.md)
- [Operations](operations.md)
- [SDN Architecture](../architecture.md)
