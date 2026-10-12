# SDN — Using It

> **Status: REFERENCE** · Last verified: 2026-08-18
> What an operator does with the platform's software-defined network, in the
> order they do it. Internals are in [engineering.md](engineering.md).

---

## What this is

The platform runs its own network rather than sitting on someone else's. It
programs Open vSwitch bridges, decides which port a device may use, segments
traffic into zones and VLANs, and — across hosts — builds a VXLAN overlay.

The part that makes it a *trusted* network: **a port is authorised because the
device on it presented a valid device certificate (IDevID)**, not because it was
plugged into the right socket. A device that cannot prove what it is gets a
provisioning-only path, or a quarantine VLAN, or nothing.

This is not 802.1X. There is no RADIUS server in the picture.

---

## Prerequisites

1. **Open vSwitch running on the host**, with its socket reachable at the path
   in the platform config.
2. **A valid SDN configuration.** The subsystem validates aggressively at
   startup and refuses to start on an inconsistent one — see "When it will not
   start" below.
3. **A zone plan.** Decide your zones before creating bridges. Almost every
   startup failure is a zone that refers to something that does not exist.
4. For multi-host overlay: **reachability between hosts** on the VXLAN transport
   network, and BGP if you are using EVPN. With overlay IPsec on, the VTEP is
   `overlay.ipsec.local-address`, which must be an address of
   `overlay.ipsec.fabric-interface`; platformd refuses to start otherwise
   (`OverlayVTEPError`, see [overlay configuration](overlay/configuration.md)).

---

## The order to build things in

The zones and their numbering come from the configuration, not from commands:
`sdn.environment` numbers the nine built-in zones, and `sdn.zones` tunes their
policy or adds owner-defined zones. Start from a template under
`configs/platform/templates/`, set your environment number and ULA, and check
what the plan derived:

```bash
# The resolved zones, with each one's VLAN, subnets and gateway
platformctl sdn zone list
```

An owner-defined zone can be added at runtime too. It is held in memory and
takes effect at the next restart (`restart_required: true`):

```bash
platformctl sdn zone create --name lab --offset 9 --port-class hypervisor --isolate \
    --allow-to storage:storage
```

A path into `control-plane` or `management` needs an audited override:

```bash
platformctl sdn zone update --name lab --offset 9 --port-class hypervisor --isolate \
    --allow-to control-plane:api \
    --reason "lab CI runners reach the platform API" --approved-by "platform owner"
```

Bridges are part of the host's network configuration, not commands: the trunk
rides `br-fabric` (`sdn.ovs.bridge`) and workloads attach to `br-int`.

---

## The lifecycle zones

`provisioning` (x05) and `quarantine` (x04) are built in and cannot be
removed. A device that has not yet enrolled reaches only the enrollment
services on provisioning; a device that failed a check reaches only
authentication and remediation on quarantine. Once attested, a device's port
carries the zones of its role's port class. A blocked port is
administratively down.

---

## Understanding what state a port is in

```bash
platformctl sdn port state p-01 --bridge br-tenant-a
```

Eight states, and they tell you different things:

| State | What it means | What to do |
|---|---|---|
| `unconnected` | Nothing detected on the port | Check cabling / the VM's tap device |
| `provisioning` | Limited access so the device can enroll | Normal for a new device; watch for it getting stuck here |
| `enrolled` | Enrolled but not activated | The device has an identity and has not claimed it yet |
| `unauthorized` | Not authenticated | The usual resting state for something with no valid certificate |
| `authenticating` | In progress | Transient; if it persists, look at certificate validation |
| `authorized` | Full access | The goal state |
| `quarantined` | Isolated VLAN for scanning or remediation | Something failed a check — find out what before releasing |
| `blocked` | Blocked on policy violation | **Administrative action required** — a blocked port does not recover on its own |

`unconnected` is the zero value, so a port the control plane knows nothing about
reads as `unconnected` rather than as authorised. That is intentional.

A device that needs re-enrollment can go from `enrolled` back to
`provisioning` — that path exists so a re-provisioned device is recoverable
without physically moving it.

---

## Applying policy

```bash
platformctl sdn policy apply --id acl-tenant-a --name tenant-a-acl \
    --type acl --priority 100 --bridge br-tenant-a --enabled
```

**`--enabled` defaults to false.** If you apply a policy and nothing changes,
that is why. Staging a set of policies and enabling them together is the
intended workflow; forgetting the flag is the common mistake.

---

## Multi-host: the overlay

```bash
platformctl sdn overlay status
platformctl sdn overlay vtep list
platformctl sdn overlay vni list
platformctl sdn overlay tunnel list
```

When a workload has moved between hosts and traffic still goes to the old place,
the remote MAC table is stale:

```bash
platformctl sdn overlay mac list
platformctl sdn overlay mac forget 52:54:00:12:34:56
```

---

## Physical switches

```bash
platformctl switch --help
```

Five operations only: list ports, port status, set port VLAN, enable port,
disable port. This is deliberately not a general switch-configuration tool.

---

## Troubleshooting

**The SDN subsystem will not start, and the error names a zone.**
A built-in zone was renumbered or re-classed (`ErrBuiltinIdentity`), an
owner-defined zone is malformed (offset outside 9–99, no port class), or a path
into the control plane has no `privileged_access`. Fix the zone set first; the
numbering errors are downstream of it.

**"sdn.environment is required" or "zones ... are both on VLAN".**
Every number comes from `sdn.environment`. An override that lands one zone on
another's VLAN or subnet, inside the IPAM pool or in a reserved range is refused
at load, because the runtime symptom would be silent cross-zone reachability —
traffic going somewhere it should not, with nothing logged.

**"TC policy without hardware offload" or "DPDK requires netdev".**
The datapath combination you asked for is one the kernel cannot honour. These
are rejected at load rather than showing up later as packet loss.

**A port sits in `unauthorized` forever.**
Certificate validation is failing. Check that the device has an IDevID, that the
issuing CA is trusted, and — if `encode_zone_in_cert` is on — that the zone in
the certificate is a zone that exists.

**A port is `blocked`.**
That is a policy violation and it does not clear itself. Every state can reach
`blocked`, and `blocked` is not a source state for any transition.

**Traffic reaches somewhere it should not, across zones.**
Check the zone's `isolate` and `allow_to`. The built-ins deny every path the
reference does not open; a tuned entry replaces the built-in's whole policy, so
leaving `isolate` out of a tuning entry opens traffic inside the zone. Tenants
are not zones: tenant isolation is the tenant's VRF.

**A bridge has no IP, and the node reports `sdn-addressing` degraded.**
platformd probed the segment before assigning that address and another station
answered for it, so it refused to take it. This is the failure it exists to
prevent: a node quietly stealing the address of the edge router strands every
host that resolves it. The bring-up log carries the refusal with both hardware
addresses:

```
sdn: refusing to assign 10.4.6.1/24 to bridge br-fabric: 00:00:0c:9f:f0:14
already answers for that address on this segment (local 0c:c4:7a:xx:xx:xx)
```

Ask the health endpoint what the node believes:

```bash
platformctl health --detailed
```

A degraded `sdn-addressing` component reports `address-conflict` and names the
refused address, the bridge, and the responding MAC. The daemon also raises a
critical platform event from source `sdn.addressing` on its event stream when
it starts.

Identify the other station from its MAC — `00:00:0c:9f:f0:xx` is Cisco's HSRP
virtual-MAC range, so an answer from that range means you have configured a
node with the router's gateway address. Fix the addressing in the node's
`network:` configuration (or on the other station) and restart platformd. The
guard has no off switch, and nothing clears the degraded component but a
restart with the conflict resolved.

**The node reports `sdn-addressing` degraded with `probe-unavailable`, and
the bridge does have its address.**
The guard could not open a raw ARP socket — usually a missing `CAP_NET_RAW`,
occasionally an interface that was not visible yet, or a non-Linux build. That
failure says nothing about the segment, so the address was assigned rather
than withheld. What you have lost is the evidence that it was free, and the
node says so rather than reporting healthy:

```
SDN: duplicate-address probe unavailable, assigning address unguarded
  bridge=br-fabric address=10.4.6.2/24
  error="arp: probe interface unavailable: operation not permitted"
```

`platformctl health --detailed` lists each unprobed address under
`probe_unavailable` with its cause. Restore the capability and restart
platformd; the component clears when every configured address is probed again.
Until then, treat the addressing on that node as unverified — this is the same
state the guard exists to detect, only without the measurement.

**You need to see what the datapath is actually doing.**
Control-plane state and datapath behaviour can disagree. Flow logs stream over
gRPC (`SDNService.StreamFlowLogs`), and `platformctl sdn port stats` gives
per-port counters.

---

## Where to go next

- [cli.md](cli.md) — every verb and flag
- [api.md](api.md) — every capability on every transport, and the gaps
- [architecture.md](architecture.md) — how port auth, zones and the overlay compose
- [`docs/gateway/`](../gateway/) — gatewayd, BGP, IPAM, reverse proxy
- [`docs/switch/`](../switch/) — physical switch detail
