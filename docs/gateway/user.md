# Edge Gateway — Using It

> **Status: REFERENCE** · Last verified: 2026-08-18
> What an operator does with a gateway node, in the order they do it. Internals
> are in [engineering.md](engineering.md).

---

## What this is

A gateway is where the platform meets networks it does not control — a WAN
uplink, an IoT segment, a BGP peer, a client arriving over HTTPS. It runs its
own binary, `gatewayd`, on its own node role, deliberately separate from the
control plane so that untrusted termination is not sharing a process with the
Raft cluster.

A gateway is configured as a set of **service sections** that are independently
switched on:

`overlay`, `edge`, `transit`, `bgp`, `firewall`, `dhcp`, `pxe`,
`load-balancer`, `nat`, `tunnels`, `proxy`

Note the spelling: **`load-balancer` is hyphenated**, the other ten are single
words. A misspelled section is a service that quietly does not start.

The most distinctive part is the **trusted reverse proxy**: it does not just
terminate TLS and forward. It runs a chain of checks — client certificate,
broker token, and optionally *machine attestation* — and consults the SDN zone
matrix, so a route's reachability follows network zoning rather than being
configured twice and drifting.

---

## Ignore `mode`

You will find `platformctl sdn gateway mode set --modes ...`, a
`SetGatewayMode` RPC, and a `gateway_mode_set` MCP tool. They drive a deprecated
three-value bitmask that can express only `overlay`, `edge` and `transit` — three
of the eleven services. It is retained for compatibility during migration.

Configure a gateway by its service sections.

---

## Prerequisites

1. **A gateway node** running `gatewayd`, with a node identity the control plane
   recognises.
2. **A control plane to fetch configuration from.** A gateway does not author
   its own desired configuration; it reports state up and pulls configuration
   down.
3. **Zones defined** ([`docs/sdn/`](../sdn/)). IPAM pools and proxy routes are
   both checked against them.
4. **The management VPN, ideally.** WireGuard, and gateways should expose it by
   default, so administrators reach management endpoints through an
   authenticated tunnel instead of putting an operator workstation on a data
   zone.

---

## Configuring the daemon

`gatewayd serve --config /etc/gatewayd/config.yaml` reads five top-level
sections: `gateway:` (the service sections above), `proxy:`, `trust:`,
`sdn:`, and `control-plane:`. Two matter beyond the service sections:

```yaml
# The OVS datapath runtime for firewall / nat / load-balancer.
# gatewayd verifies the bridge exists; it does not create it —
# datapath bring-up belongs to the installer or to platformd on a
# gateway-role node.
sdn:
  enabled: true
  ovs:
    socket: /var/run/openvswitch/db.sock
    bridge: trusted0
  networks:
    - name: trusted-net
      vlan: 200
      zone: trusted

# Periodic telemetry to the control plane over mTLS. The client
# certificate is the gateway's IDevID-derived platform identity.
control-plane:
  enabled: true
  base-url: https://cp.example.com:8443
  interval: 30s
  cert-file: /etc/gatewayd/idevid.pem
  key-file: /etc/gatewayd/idevid-key.pem
```

Enabling `firewall`, `nat`, or `load-balancer` without an enabled `sdn:`
section fails startup immediately with a configuration error naming the
service — nothing starts silently inert. Firewall and NAT additionally
require at least one `networks:` entry with a VLAN bound to a zone: an
empty zone matrix would enforce nothing, so it is refused rather than
started. The `sdn:` section is only consumed when one of those services
is enabled — a proxy-only gateway never touches OVS.

`control-plane.cert-file`/`key-file` are required when the section is
enabled: the client certificate is how the control plane knows which
gateway is reporting.

**`gateway-id` must be the certificate's Common Name.** The control plane
does not take the reported ID on trust — it compares it to the Subject CN
of the client certificate and refuses the request otherwise, so a gateway
can only ever report its own state and fetch its own configuration. When
`gateway-id` is omitted the gateway node's `id` is used and must match the
same way. gatewayd checks this at startup and refuses to start on a
mismatch:

```
gatewayd: control-plane gateway-id "lab-node-1" does not match the client
certificate Common Name "gw-edge-1" in /etc/gatewayd/idevid.pem; the
control plane binds reported telemetry to the certificate identity
```

The fix is to set `gateway-id` to the CN the certificate actually carries,
or to have the gateway issued a certificate naming the ID you want it to
report under. There is no override.

---

## Checking a gateway

```bash
platformctl sdn gateway status --output json
```

If a service section is switched off, calls to it answer **503 / unavailable**,
not 404. That distinction is deliberate: the capability exists and is disabled,
which is different from not existing.

A second distinction rides the same 503. When the node has **no gateway service
at all** — a control plane, where gatewayd lives on the edge role — the answer
carries the machine-readable discriminator `SERVICE_NOT_CONFIGURED` (an
`ErrorInfo` detail on gRPC/QUIC/MCP, a `reason` field in the REST body). When
the node *does* host the service and it is merely stopped, the 503 says "not
running" and carries no discriminator.

That is what lets the console's **Networking → Gateway** page show a control
plane the fleet's Reported Gateways plus a quiet "this node does not run
gatewayd" note, while still raising a real error for a gateway node whose
service is down. The prose in the `error` field is operator-facing and is not a
contract — branch on the discriminator.

---

## Addresses: pools before allocations

```bash
platformctl sdn ipam pool create --name tenant-a --cidr 10.20.0.0/24 \
    --gateway 10.20.0.1 --zone trusted --description "Tenant A workloads"

platformctl sdn ipam allocate --pool-id tenant-a --device-id dev-0f21 --hostname web-01
platformctl sdn ipam allocations --pool-id tenant-a
platformctl sdn ipam release --ip 10.20.0.17
```

**`--cidr` cannot be changed later.** `update` has no `--cidr` flag: changing a
pool's range under live allocations would orphan them. Get it right, or replace
the pool.

**`--device-id` is required on allocate.** Addresses belong to devices, which is
what makes the allocation table joinable against the device registry.

The `--zone` must be a zone that exists. A pool declared in an undeclared zone
is rejected at configuration load, not at allocation time.

---

## Announcing address space with BGP

```bash
platformctl sdn gateway bgp status
platformctl sdn gateway bgp peers
platformctl sdn gateway bgp announce --prefix 203.0.113.0/24 --next-hop 198.51.100.1
platformctl sdn gateway bgp routes
platformctl sdn gateway bgp withdraw --prefix 203.0.113.0/24
```

`--next-hop` is optional on announce; omit it to use the session's default.

A BGP session accepts routes from an external speaker, which makes prefix
filtering the control that matters. That is configuration, not a CLI flag.

---

## Load balancing

```bash
platformctl sdn lb vip add --address 203.0.113.10 --protocol tcp \
    --algorithm round-robin \
    --backend 10.20.0.11:8443:2 --backend 10.20.0.12:8443:1

platformctl sdn lb vip list
platformctl sdn lb status
```

Backends are `address:port[:weight]` and `--backend` repeats. `--algorithm` is
`hash` or `round-robin`; omitting it uses the service default.

**`set-backends` replaces the entire set**, it does not add to it:

```bash
platformctl sdn lb vip set-backends --address 203.0.113.10 \
    --backend 10.20.0.11:8443 --backend 10.20.0.13:8443
```

The load balancer has **no REST API** — gRPC, Unix, QUIC, MCP and the CLI only.
A REST-only client cannot see a VIP.

---

## The trusted reverse proxy

Pools before routes, because a route that references a missing pool fails
validation:

```bash
platformctl proxy pool add     # define the backend pool
platformctl proxy route add    # then the route pointing at it
platformctl proxy reload
```

`platformctl proxy reload` **bumps the configuration version** — it does not
re-read a file from disk. That is how consumers learn there is a new version.

When a route is reachable, or unreachable, in a way its definition does not
explain, check the zone matrix:

```bash
platformctl proxy zone-matrix
platformctl proxy status
```

---

## Things the proxy will refuse, and why

It validates before it starts. Every one of these is a refusal by design:

**"auth chain required for non-public routes."**
A route that is not public must have authentication configured now, not later.

**"server tls required for non-public routes."**
Authenticating over plaintext is refused at configuration time. There is no
negotiation at request time.

**"route requires mtls but chain has no mtls capability"** (and the token
equivalent).
This is the most important one. A route that asks for a mechanism the chain
cannot perform is an **error**, not a downgrade. The alternative — silently
serving the route with whatever authentication is available — produces a route
everyone believes requires mTLS and which does not.

**"route references unknown pool."**
Create the pool first.

**"route path prefix must start with /"**, **"backend url scheme must be http or
https"**, **"pool requires at least one backend"**, **"backend weight must not be
negative"**.
Structural validation, all at load.

**"zone extractor and matrix must be configured together."**
Half a zone configuration would evaluate every route against an empty matrix,
which fails open in appearance and closed in effect. Configure both or neither.

**"tcp passthrough is not supported."**
Not a missing feature. A passthrough route could not run the auth chain, and
running the auth chain is the reason this proxy exists.

---

## Measuring the datapath

```bash
platformctl sdn perf flows --bridge br-tenant-a --batch
platformctl sdn perf datapath --bridge br-tenant-a
platformctl sdn perf conntrack
```

`perf flows` with and without `--batch` measure different things — batched
installation behind one barrier versus per-flow barriers. Do not compare the two
numbers.

If these return "unavailable" rather than zeroes, the perf backend is not wired
in. That is a different problem from an idle datapath, and the status code tells
you which you have.

---

## Troubleshooting

**A service section does nothing and reports no error.**
Check the spelling in configuration. `load-balancer` is hyphenated; the other
ten section names are single words.

**Calls to a capability return 503.**
The service section is disabled. Enable it in the gateway's configuration —
which the control plane authors, not the gateway. If the 503 carries
`reason: SERVICE_NOT_CONFIGURED` you are talking to a node with no gateway
service at all — a control plane, not a gateway.

**"service already active" / "service not active".**
Starting a running service or stopping a stopped one. Both are reported rather
than silently ignored.

**A peer is rejected with "reputation too low", "age too young" or "uptime too
low".**
Peer-admission gates on the edge/P2P path. They only fire where that path is
enabled.

**Gateway configuration keeps reverting.**
It is supposed to. The control plane authors desired configuration and the
gateway fetches it. Change it at the control plane.

---

## Where to go next

- [cli.md](cli.md) — every verb and flag
- [api.md](api.md) — every capability on every transport, and the gaps
  (IPAM pool CRUD and the entire load balancer are missing from REST)
- [architecture.md](architecture.md) — the eleven services, the proxy auth chain, trust boundaries
- [`docs/sdn/`](../sdn/) — bridges, ports, port authentication, zones, overlay
