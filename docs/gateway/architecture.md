# Edge Gateway Architecture

> **Status: NORMATIVE** · Scope: `pkg/sdn/gateway/`, `pkg/proxy/`, `cmd/gatewayd` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: architecture (this file) · [engineering.md](engineering.md) ·
> [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Longer-form material predating this migration lives in
> [`docs/sdn/gateway/`](../sdn/gateway/) and has not been re-verified.

## The problem

Every network the platform touches has an edge: a WAN link, an IoT segment, an
upstream that speaks BGP, a client that arrives over HTTPS. Those terminations
have nothing to do with each other technically, but they share one property —
**they are where untrusted traffic meets the platform**. Scattering them across
the control plane would put untrusted termination in the same process as the
Raft cluster and the API surface.

## The shape chosen

A **separate binary** — `gatewayd` — running the **edge/gateway node role**.
Roles are configuration, not binaries: `platformd` runs as control-plane or
worker; `gatewayd` is the edge. A gateway terminates and routes; it does not
serve the composed platform SDK.

Its capabilities are **eleven independently enabled service sections**
(`pkg/sdn/gateway/node.go:29-39`):

| Constant | Value | What it does |
|---|---|---|
| `ServiceOverlay` | `overlay` | VXLAN/EVPN overlay participation |
| `ServiceEdge` | `edge` | IoT / P2P edge termination |
| `ServiceTransit` | `transit` | BGP transit for IP blocks |
| `ServiceBGP` | `bgp` | BGP speaker |
| `ServiceFirewall` | `firewall` | Packet filtering |
| `ServiceDHCP` | `dhcp` | DHCP service |
| `ServicePXE` | `pxe` | Network boot |
| `ServiceLoadBalancer` | `load-balancer` | VIP load balancing |
| `ServiceNAT` | `nat` | Network address translation |
| `ServiceTunnels` | `tunnels` | Tunnel management |
| `ServiceProxy` | `proxy` | The trusted authenticating reverse proxy |

**Note the value spelling: `load-balancer`, hyphenated**, while the others are
single words. Configuration that writes `loadbalancer` will not match.

### `GatewayMode` is deprecated compatibility, not the model

`pkg/sdn/gateway/compat.go:26` declares `GatewayMode uint8` — a bitmask with
three values (`GatewayModeOverlay`, `GatewayModeEdge`, `GatewayModeTransit`) —
carrying an explicit deprecation notice: *"Gateway services are now
config-driven. Use GatewayConfig service sections instead of mode flags. This
type is retained for API compatibility during the migration period."*

It maps only three of the eleven services (`serviceToMode` / `modeToService`).
**Do not model a gateway as a mode.** The bitmask cannot express eight of the
eleven services, and anything built on it will be wrong for a gateway that runs
firewall, DHCP, PXE, LB, NAT, tunnels or proxy. `SetGatewayMode` still exists
as an RPC and `platformctl sdn gateway mode set` still exists as a verb — both
are the compatibility surface.

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Run edge services inside `platformd`** | Puts untrusted WAN and IoT termination in the same process as the Raft cluster and the composed API. A gateway compromise would be a control-plane compromise. |
| **A `mode` bitmask as the configuration model** | Tried, and retained only for compatibility. Eight of the eleven services have no bit. Every added service would need a new bit and a new mapping in two directions. |
| **A separate binary per edge function** | Eleven binaries to deploy, version and attest, all sharing the same datapath and the same node identity. One binary with config-driven sections keeps the attestation surface singular. |
| **A general-purpose reverse proxy in front of the platform** | An off-the-shelf proxy authenticates a user or a token. The trusted proxy authenticates against the platform's own identity chain and consults the SDN zone matrix, so a route's reachability follows network zoning rather than being configured twice. |
| **Letting the gateway serve the composed SDK** | Then the edge would need the whole stack's surface at the point where untrusted traffic lands. Gateways consume control-plane configuration; they do not re-export it. |

## Component boundaries

| Piece | Package | Notes |
|---|---|---|
| Gateway node model, service registry | `pkg/sdn/gateway/node.go`, `types.go`, `runtime.go` | The eleven service constants live here |
| Deprecated mode compatibility | `pkg/sdn/gateway/compat.go` | Do not build on it |
| Mode implementations | `pkg/sdn/gateway/modes/` — `edge.go`, `edge_p2p.go`, `edge_pxe.go`, `overlay.go`, `transit.go` | |
| Firewall, load balancer, perf | `pkg/sdn/gateway/services/{firewall,loadbalancer,perf}` | |
| Control-plane liaison | `pkg/sdn/gateway/controlplane/` | State reporting and desired-config fetch |
| Gateway state | `pkg/sdn/gateway/state/` | |
| Zone service | `pkg/sdn/gateway/zone_service.go` | Network zones at the edge |
| P2P discovery | `pkg/sdn/gateway/p2p/` | **Build-tag gated (`platform_p2p`)**; the P2P trusted network is planned, not implemented |
| Proxy service adapter | `pkg/sdn/gateway/proxysvc/` | |
| **The trusted reverse proxy** | `pkg/proxy/` | Its own package: `authchain.go`, `attestation.go`, `tokenauth.go`, `policy.go`, `balancer.go`, `router.go`, `listener.go`, `handler.go`, `identity.go`, `audit.go`, `metrics.go`, `transport.go`, `config.go`, `deps.go`, `errors.go` |
| Binary | `cmd/gatewayd/main.go` | |
| **Import closure** | enforced by `pkg/arch/gatewayguard_test.go` | Separate from the layer guard; never weaken it |

The §R capability row is *"Edge gateway and trusted reverse proxy (routes,
pools, zones)"*, Tier 1, reached through `services/gateway` and
`services/proxy`.

`gatewayd` has its **own import-closure guard test**
(`pkg/arch/gatewayguard_test.go`), separate from the layer guard. That is
deliberate: the binary that terminates untrusted traffic should not silently
acquire the whole platform's dependency tree.

## The trusted reverse proxy

`pkg/proxy/` is what makes this a *trusted* gateway rather than a router with a
proxy bolted on. Three files carry the distinction:

- **`authchain.go`** — a chain of authentication mechanisms rather than one.
- **`attestation.go`** — attestation is one of the links, so a route can require
  the *client machine* to be attested, not merely the user authenticated.
- **`tokenauth.go`** — broker-token validation. The platform validates the `scp`
  claim offline; it is **not** a token-authorization decision point and does not
  run an authorization engine for tokens.

`policy.go` and the `GetZoneMatrix` RPC connect proxy routing to SDN zones: a
route's reachability is derived from network zoning rather than configured
separately and left to drift.

## Data flow — a request arriving at the edge

1. TLS terminates on the proxy listener (`listener.go`).
2. The auth chain runs (`authchain.go`): token validation, client attestation,
   identity resolution — in the order the chain is configured.
3. Policy is evaluated against the zone matrix (`policy.go`).
4. The router picks a route (`router.go`), the balancer picks a backend from its
   pool (`balancer.go`).
5. The request is forwarded (`transport.go`), and the decision is audited
   (`audit.go`) and counted (`metrics.go`).

Steps 2 and 3 fail closed. A route with no matching policy is not reachable.

## Trust boundaries

1. **Internet / IoT segment → gateway.** The primary boundary. Everything
   arriving here is untrusted.
2. **Gateway → control plane.** The gateway reports state and fetches desired
   configuration (`pkg/sdn/gateway/controlplane/`, and the REST control-plane
   routes under `/api/v1/gateway`). It consumes configuration; it does not
   author it.
3. **Proxy → backend.** Crossed after authentication and policy. A backend pool
   trusts that the proxy did its job, which is why the auth chain fails closed.
4. **BGP peer → gateway.** A BGP session accepts routes from an external
   speaker. Prefix filtering is the control, and it is configuration.
5. **Management VPN.** `ManagementVPNConfig` (WireGuard) exists so administrators
   reach management endpoints through an authenticated tunnel rather than being
   dual-homed onto a data zone. Gateways should expose it by default.

## What this feature deliberately does not do

- **It does not serve the composed platform SDK.** Gateways terminate and route.
- **It does not decide token authorization.** It validates broker tokens offline.
- **It does not implement the P2P trusted network.** `pkg/sdn/gateway/p2p/` is
  libp2p peer discovery behind the `platform_p2p` build tag. The P2P/DHT
  designs are planned work with no implementation; do not build against them.
- **It does not own the port authentication state machine.** That is SDN —
  [`docs/sdn/`](../sdn/).
- **It is not configured by `GatewayMode`.** See above.
