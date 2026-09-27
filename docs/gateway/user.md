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
three-value bitmask that can express only `overlay`, `edge` and `transit`. It
is retained for compatibility during migration.

Configure a gateway by its service sections.

---

## Prerequisites

1. **A gateway node** running `gatewayd`, with a node identity the control plane
   recognises. A node installed from a gateway-role template (`gateway.enabled:
   true`) gets `gatewayd` packaged by the installer and firstboot (#66):
   `/usr/sbin/gatewayd`, the OpenRC service `/etc/init.d/gatewayd` enabled in the
   default runlevel, and `/etc/gatewayd/config.yaml` projected from the platform
   config's `gateway:`, `sdn:`, `trust:`, `proxy:` and `control-plane:` sections.
   The reporter's client certificate, key and CA bundle are **not** produced by
   the platform yet (#149, #431); until they are delivered to the paths the
   `control-plane:` section names, the reporter is rendered `enabled: false` and
   firstboot logs the gap.
2. **A control plane to fetch configuration from.** A gateway does not author
   its own desired configuration; it reports state up and pulls configuration
   down.
3. **Zones defined** ([`docs/sdn/`](../sdn/)). IPAM pools and proxy routes are
   both checked against them.
4. **The management VPN, ideally.** IPsec in FIPS builds, WireGuard only in
   non-FIPS builds (owner design decision 2026-09-26; today the config defines
   only `wireguard` and the section is refused, #558), and gateways should
   expose it by default, so administrators reach management endpoints through an
   authenticated tunnel instead of putting an operator workstation on a data
   zone.

---

## Configuring the daemon

`gatewayd serve --config /etc/gatewayd/config.yaml` reads six top-level
sections: `gateway:` (the service sections above), `proxy:`, `trust:`,
`sdn:`, `control-plane:`, and `secret-store:` (where keys and passwords come
from, below). Two matter beyond the service sections:

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
    - name: control-plane
      vlan: 406
      zone: trusted       # see the zone note below

# Periodic telemetry to the control plane over mTLS. The client
# certificate is the gateway's IDevID-derived platform identity.
control-plane:
  enabled: true
  base-url: https://cp.example.com:8443
  interval: 30s
  cert-file: /etc/gatewayd/idevid.pem
  key-file: /etc/gatewayd/idevid-key.pem
```

Addresses and VLANs in these examples follow
[`../architecture/reference-network.md`](../architecture/reference-network.md)
(environment block 4). `zone: trusted` is what the code accepts today; the
reference design has no `trusted` zone, and the code's zone vocabulary moves
with #708.

NAT may translate to one address (`external-ip`) or, for a gateway with more
than one ISP uplink, to one pool per uplink (#586):

```yaml
nat:
  enabled: true
  internal-cidr: 10.4.6.0/24
  port-range-start: 1024
  port-range-end: 65535
  uplinks:
    - name: ispa
      port: eth6                       # OVS port; defaults to name
      addresses: ["198.51.100.4"]       # single addresses or a-b ranges
      default: true                     # carries every unclaimed destination
    - name: ispb
      port: eth7
      addresses: ["192.0.2.4-192.0.2.5"]
      port-range-start: 2048            # overrides the NAT-wide range
      port-range-end: 60000
      destinations: ["192.0.2.128/25"] # leaves through ISP B
  static:
    - internal: 10.4.6.10
      external: 203.0.113.4             # on the default uplink
    - internal: 10.4.6.11
      external: 192.0.2.6
      uplink: ispb
```

`static` entries are 1:1 in both directions and hairpin: an internal client
addressing the external address reaches the inside host, and the reply comes
back from the external address. IPv6 is never translated (the service is
NAT44) and passes through the NAT gate untouched; `static` requires
`uplinks`.

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

An enabled section reports **active** only while its backend is running:
`firewall`, `nat`, `load-balancer`, `hostfw`, `tunnels`, `transit` (or a
`bgp:` section) and `proxy` have backends today. Enabling `overlay`, `edge`,
`dhcp`, `pxe` or `management-vpn` stops the daemon at startup with
`gateway service "<name>" is enabled but cannot run: <reason>` — those sections
have no implementation behind them yet and the gateway refuses to claim
otherwise. (`overlay` is required by owner design decision 2026-09-26, #709.) When `proxy` is enabled, the host packet filter (`hostfw`) admits
exactly the proxy's fixed listener ports and nothing else the daemon opens.

**`gateway-id` must be the certificate's Common Name.** The control plane
does not take the reported ID on trust — it compares it to the Subject CN
of the client certificate and refuses the request otherwise, so a gateway
can only ever report its own state and fetch its own configuration. When
`gateway-id` is omitted the gateway node's `id` is used and must match the
same way. gatewayd checks this at startup and refuses to start on a
mismatch:

```
gatewayd: control-plane gateway-id "gw-01" does not match the client
certificate Common Name "gw-edge-1" in /etc/gatewayd/idevid.pem; the
control plane binds reported telemetry to the certificate identity
```

The fix is to set `gateway-id` to the CN the certificate actually carries,
or to have the gateway issued a certificate naming the ID you want it to
report under. There is no override.

---

## The host packet filter

The gateway filters traffic to *itself* with nftables (`inet tp_host`, policy
drop), rendered from what it is configured to listen on. You declare only what
the platform does not own:

```yaml
hostfw:
  enabled: true
  extra:
    - interface: eth0            # management leg
      protocol: tcp
      port: 22
      sources: [10.4.2.0/24, fd12:3456:789a:402::/64]
      comment: sshd from the management network
  peers:
    - interface: wan0
      protocol: gre              # or esp
      addresses: [198.51.100.100, 192.0.2.100]
  tunnels: [gre1, gre3]          # BGP and BFD are accepted here
  base-ruleset-path: /etc/nftables.d/tp-host.nft
```

Anything not declared — by you here or by the daemon from its own listeners —
is dropped, and the rendered ruleset says which interface each allow applies
to. `nft list table inet tp_host` shows it, one comment per rule. If you are
rolling this out on a node you reach only over one interface, put that
interface in `unfiltered:` until its listeners are declared; the exception is
printed in the ruleset so it is not forgotten.

## First-hop redundancy

When two gateways serve one plain L2 segment (an environment VLAN or transit),
hosts keep a single default gateway and the pair holds it with VRRPv3.
`pkg/sdn/fhrp` is not wired into gatewayd yet (#596), so the `fhrp:` section
below describes the package's configuration, not something a gateway runs
today. Configure the same group on both nodes with
different priorities; the higher priority is master and the other waits:

```yaml
fhrp:
  enabled: true
  groups:
    - vrid: 20
      interface: trusted0
      priority: 200               # the peer runs 100
      advert-interval-cs: 100     # 1 s
      addresses: [10.4.6.1/24]
      source: 10.4.6.2            # this node's own address on trusted0
    - vrid: 20
      interface: trusted0
      priority: 200
      addresses: [fd12:3456:789a:406::1/64]
      source: fe80::3eec:efff:fe71:52ee
```

Failover from a lost master takes about three advertisement intervals plus a
small skew; a cleanly stopped master hands over in well under a second. `ip
addr show trusted0` on each node shows who holds the address, and the gateway
snapshot reports each group's state, priority and transition count. The host
filter must admit VRRP (IP protocol 112, multicast 224.0.0.18 / ff02::12) on
each group's interface; that allowance is not yet rendered by `hostfw` and is
part of the handler wiring (#596) — until it lands, list the interface under
`hostfw.unfiltered` on a filtered gateway. Put the virtual address in `hostfw`
as an `extra` listener only if the gateway itself serves on it.

Overlay (VXLAN) segments, including the public address block, do not use
VRRP: every gateway answers for the anycast gateway address locally (EVPN
distributed anycast gateway). NAT failover is stateless first (#596);
conntrack state sync is #710.

## Checking a gateway

```bash
platformctl sdn gateway status --output json
```

For what the gateway actually programmed — the BGP sessions and their BFD
state, the tunnels and which uplink each is pinned to, the uplink routing
tables, the host filter's fingerprint, NAT and the base OVS pipeline — read
its telemetry snapshot:

```bash
# The gateway this node runs
platformctl sdn gateway snapshot

# A gateway that reports to this control plane
platformctl sdn gateway snapshot --gateway-id gw-01-gateway
```

Sections are printed only for services the gateway runs. If the Tunnels
section is missing, the tunnels service is not running; a tunnels section with
no rows would mean it runs with nothing configured. The same document backs
the console's Networking → Gateway page and, when the `metrics:` section is
enabled, the gateway's Prometheus endpoint:

```yaml
metrics:
  enabled: true
  listen: "127.0.0.1:9169"   # scrape at /metrics
```

Every series is named `gatewayd_*` and labelled with the gateway id, so
`gatewayd_bgp_peer_established`, `gatewayd_bfd_session_up`,
`gatewayd_tunnel_up` and `gatewayd_hostfw_installed` alert on the same facts
the snapshot shows. A service the gateway does not run emits no series, so an
alert on a missing series is a real absence rather than a zero.

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

Standing a gateway up beside existing routers for the first time — tunnels and
sessions against the live relays, announcing nothing — is its own procedure:
[`docs/operations/gateway-bringup.md`](../operations/gateway-bringup.md).


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

**Which relay carries the traffic is also configuration.** A peer's
`policy.import` and `policy.export` blocks carry the path attributes that rank
one session against another: `local-pref` on import decides which relay this
gateway prefers, and `med`, `prepend` and communities on export tell the far side
how to rank what it receives. Leave them out and the sessions still come up — but
with more than one relay reachable, the path that wins is whichever one GoBGP's
tie-breaks pick, which is not a choice anyone made. Anything the speaker cannot
program is refused when the configuration loads rather than dropped silently on
the wire. Field reference and the full refusal list:
[`docs/sdn/bgp/configuration.md`](../sdn/bgp/configuration.md).

---

## Tunnels to the relays

The transit relays are reached over tunnels declared in `tunnels:`. What the
gateway's section can express **today** is a plain GRE tunnel: `name`, `type`,
`local`, `remote`, `tunnel-ip` and `tunnel-ipv6`.

The tunnel package underneath implements more than that — three transports
(`gre`, `ipsec` wrapping the tunnel in ESP with keys taken from the platform
key store by reference, and `wireguard` outside FIPS builds), per-uplink
pinning so a tunnel's outer packets always leave on the ISP they were sourced
from, and `Rekey` for rotating an `ipsec` tunnel without dropping the session.
**None of it is reachable from a gatewayd configuration yet**: the gateway
section carries six fields and drops the rest
(#606).
Until that lands, run GRE and pin the relay host routes statically — the
bring-up runbook
([`docs/operations/gateway-bringup.md`](../operations/gateway-bringup.md))
says exactly where. Field reference for the package's own schema:
[`docs/sdn/tunnel/configuration.md`](../sdn/tunnel/configuration.md).

## Keys and passwords: where they come from

Nothing that authenticates a session or encrypts a tunnel is written in the
configuration file. The file names it; the platform secret store holds it. Tell
the daemon where that store is:

```yaml
secret-store:
  quicbaas-addr: cp.example.internal:9443
  quicbaas-transport: grpc   # unix | rest | quic | mcp; empty auto-detects
  timeout: 10s
```

Then reference values from it:

```yaml
gateway:
  bgp:
    peers:
      - name: vps-primary
        auth-type: md5                                   # non-FIPS builds only
        auth-key-ref: kms://platform/gateway/bgp/vps-primary
  tunnels:
    - name: ipsec-primary
      transport: ipsec
      ipsec:
        key-ref: kms://platform/gateway/tunnel/primary/out?enc=base64
        peer-key-ref: kms://platform/gateway/tunnel/primary/in?enc=base64
```

A reference is `kms://<path>` or `secret://<path>` — the same store under two
spellings, so use whichever reads better. `<path>` is the secret's path as
`platformctl secrets` shows it. Two options refine it: `?enc=base64` (or
`?enc=hex`) decodes the stored text into bytes, which is what a 36-byte ESP key
or a 32-byte WireGuard key needs, and `#<field>` picks one field out of a secret
that holds several. Without `#<field>` the secret must hold exactly one.

Store a key with `platformctl secrets`. To mint one, generate it there — the
gateway only reads.

Everything about this fails closed, on purpose:

- No `secret-store:` section, and any service that references a secret refuses
  to start. Nothing runs with a reference where a key belongs.
- A `secret-store:` without `platform-ca-file:` is refused
  (`secrets.ErrTrustRequired`): the session to the store is verified against
  the platform CA, and a gateway runs no CA of its own, so it needs the
  platform CA bundle provisioning puts on the node:

  ```yaml
  platform-ca-file: /etc/gatewayd/cp-ca.pem   # the platform CA bundle
  ```

  This is gatewayd's platform anchor: it verifies every platform service the
  gateway talks to — the store, platformd over grpc, the proxy's mTLS callers
  and `trust-class: platform` backends, the control-plane reporter. It is not a
  `trust:` class; there is no strategy to choose. Verification is one-way today
  — the gateway checks the store, the store does not yet get a client
  certificate from the gateway (#658). Both shipped gateway templates set it;
  removing it means commenting `secret-store:` out too. The file is read at
  each verification, so a rotated bundle needs no restart; a bundle not yet
  delivered fails the verification naming the path.
- A reference that does not resolve, or that resolves to nothing, refuses the
  service. An empty password is not a password.
- A bare value where a reference belongs is refused rather than used as the
  secret.
- Errors name the reference and never the material, so they are safe to paste
  into a ticket.

Resolved material is handed to the kernel or to the BGP speaker and then wiped.

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

Routes and pools you add this way are persisted through the platform database
and survive a control-plane restart (#570). Routes you want under version
control go in the control plane's `proxy:` section
(`docs/proxy/configuration.md`); it is seeded at startup as the base layer and
never overwrites a route the API changed. The gateway templates' webservice
virtual hosts no longer proxy anything — the trusted proxy is the proxy.

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
Check the spelling in configuration. `load-balancer` and `management-vpn` are
hyphenated; the other section names are single words.

**Startup fails with `is enabled but cannot run`.**
The section names a service with no implementation (`overlay`, `edge`, `dhcp`,
`pxe`, `management-vpn`); the message carries the blocker and the tracking
issue. Disable the section. `overlay` is required by owner design decision
(2026-09-26) and lands with #709. The gateway will not start a service it cannot
back.

**Startup fails with `parsing configuration section proxy.listeners`.**
A proxy listener `address` is not `host:port`. The host packet filter derives
its inventory from those addresses, so a malformed one is refused rather than
left unfiltered.

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
- [architecture.md](architecture.md) — the service sections, the proxy auth chain, trust boundaries
- [`docs/sdn/`](../sdn/) — bridges, ports, port authentication, zones, overlay
