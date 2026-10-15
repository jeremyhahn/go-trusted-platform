# Tunnel Management

> **Status: REFERENCE** · Last verified: 2026-10-15
> The gateway's transit-relay tunnels in `pkg/sdn/tunnel`.

The `pkg/sdn/tunnel` package manages the gateway's point-to-point tunnels to
the transit relays (the remote nodes that hold the site's eBGP) through
Linux netlink, under a **pluggable transport**, and pins each tunnel's outer
packets to the WAN uplink it was sourced from (#582).

## Architecture

Two managers, both idempotent and safe for concurrent use:

- `tunnel.Manager` — creates, re-keys and removes tunnels from `TunnelConfig`.
- `tunnel.UplinkManager` — owns a routing table per WAN uplink and the `ip rule`s
  that steer traffic into it.

The `Manager` is built with options: `WithKeyProvider` (required by the `ipsec`
and `wireguard` transports; the platform implementation is the quicbaas SDK KMS)
and `WithUplinks` (required when a tunnel names an uplink). A configuration whose
prerequisites are missing is refused before any netlink call
(`ErrKeyProviderRequired`, `ErrUplinkUnknown`).

## Transports

| `transport` | Carrier | Protection | Builds |
|---|---|---|---|
| `gre` (default) | `gre` / `gre6` / `ipip` link | none — the shape most relays speak today | all |
| `ipsec` | the same carrier | ESP, transport mode, `rfc4106(gcm(aes))` 256-bit with 128-bit ICV, ESN, anti-replay window — programmed as XFRM states and policies selecting only the carrier protocol between the two endpoints | all (FIPS-approved primitives) |
| `wireguard` | its own kernel interface | WireGuard (Curve25519 / ChaCha20-Poly1305 / BLAKE2s) | `!fips` only — refused with `ErrTransportUnavailable` under the `fips` build tag |

Keys never appear in configuration: `ipsec.key-ref`, `ipsec.peer-key-ref` and
`wireguard.key-ref` are references the `KeyProvider` resolves
(`handbook/software/conventions/configuration.md` §4). Material is checked for
the exact length the transport needs (36 bytes for AES-256-GCM key+salt, 32 for a
WireGuard private key), handed to the kernel, and zeroized. An empty or short key
is a typed error (`ErrKeyMaterial`) that names the reference and never the bytes.

Install order is fail-closed: for `ipsec` the SAs are programmed first, then the
policies, and only then is the carrier interface created, so no carrier packet
ever leaves in the clear; a failure at any step unwinds what preceded it.
Removal is the reverse. `Rekey(name)` re-resolves both references and updates the
SAs in place (`XFRM_MSG_UPDSA`), outbound first; SPIs and policies do not change,
so the peer rotates the same references in lockstep and traffic never stops.
Nothing in the platform calls `Rekey` yet: `ipsec.rekey-interval` is reported in
the tunnel status (`pkg/sdn/gateway/snapshot.go:372`) but drives no timer.
Liveness is not this package's job: BFD on the BGP neighbor (GoBGP 4.9, #556)
detects a dead path; vendor GRE keepalives are a non-goal.

## Uplinks and policy routing

An `UplinkConfig` names a WAN interface, a routing table id (100–252), the ISP's
IPv4/IPv6 next hops and the uplink's own addresses. `EnsureUplink` installs a
default route in that table and a source rule per address. `BindTunnel` adds a
higher-priority rule for the tunnel's outer endpoint pair
(`from <local>/32 to <remote>/32 lookup <table>`), so a tunnel sourced on uplink A
never egresses through uplink B when the main table's default moves — the
platform's equivalent of an upstream router's `tunnel route-via … mandatory` plus its
return-path PBR. Rules already present in the kernel are adopted, not
duplicated; removal takes the tunnel's pin, then the source rules, then the
table routes.

## Usage

```go
uplinks := tunnel.NewUplinkManager(logger)
_ = uplinks.EnsureUplink(ctx, tunnel.UplinkConfig{
    Name: "ispa", Interface: "eth6", Table: 101,
    GatewayV4: "198.51.100.6", Addresses: []string{"198.51.100.4/29"},
})

mgr := tunnel.NewManager(logger, tunnel.WithKeyProvider(kms), tunnel.WithUplinks(uplinks))
defer mgr.Close()

err := mgr.EnsureTunnel(ctx, tunnel.TunnelConfig{
    Name: "gre-relay-ispa", Type: "gre", Transport: "ipsec", Uplink: "ispa",
    Local: "198.51.100.4", Remote: "203.0.113.100", TunnelIP: "10.4.128.2/31",
    IPsec: &tunnel.IPsecConfig{KeyRef: "kms://platform/tunnel/relay-ispa/out", SPIOut: 0x1001, SPIIn: 0x1002},
})
```

## Integration with BGP

The tunnel addresses (`/31`s from the environment's tunnel point-to-point range,
`10.4.128.0/22` in environment 4 of the
[reference network](../../architecture/reference-network.md)) are the iBGP peer addresses in
`BGPConfig.Neighbors`. The gateway's tunnels service builds both managers from
the `tunnels:` and `routing-uplinks:` sections of the gateway configuration
(`pkg/sdn/gateway/handlers.go:635`). `routing-uplinks:` is distinct from the
gateway's `uplinks:`, which are the NAT and NIC ports.

See [configuration.md](configuration.md) for the field reference.
