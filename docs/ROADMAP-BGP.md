# Multi-Host SDN/BGP/Gateway Implementation Roadmap

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Archived 2026-08-18. The "Active Development" status below was stale: 319 of
> the 320 checkboxes in this file are checked, and the single unchecked box
> (line 138) is a status-legend entry, not a work item.
>
> **Corrected 2026-09-07 (#559).** The 2026-08-18 note said "the work this
> roadmap planned has shipped". That was not true of Phase 3 and Phase 6: a
> checked box here is not evidence that code exists, and several checked boxes
> name packages, files and mechanisms that do not exist anywhere in the
> repository (handbook 00 L9). Each such row is now marked
> **`— NOT IN CODE (#559)`** in place, and the list below is the summary. The
> checkboxes themselves are left as the historical record of what was
> *claimed*; do not tick or untick them.
>
> The shipped behaviour is documented as requirements in [`docs/sdn/`](sdn/)
> (bridges, ports, flows, port authentication, VXLAN/EVPN overlay) and
> [`docs/gateway/`](gateway/) (gatewayd services, BGP, IPAM, reverse proxy).
> Build against those, not against this file.

### Corrections (2026-09-07, #559) — what the checked boxes claimed vs. what exists

| Claimed here | In code |
|---|---|
| `pkg/sdn/gateway/cluster/` (`manager.go`, `election.go`, `health.go`), "Cluster Management", "Failover coordination", "Gateway promotion/demotion" | **Does not exist.** No gateway clustering, election, heartbeat, VIP takeover or state replication is implemented. `pkg/sdn/cluster/gateway_partitions.go` declares partition keys and entry structs for such a design and is referenced by nothing outside its own file. |
| `pkg/sdn/gateway/routing/` (`router.go`, `ecmp.go`, `rib.go`), "L3 routing with RIB", "ECMP load balancing", "Route redistribution" | **Does not exist.** No ECMP anywhere in `pkg/sdn`. |
| `pkg/sdn/gateway/nat/` (`snat.go`, `dnat.go`, `cgnat.go`), "CGNAT for IoT (RFC 6598)" | NAT lives in `pkg/sdn/gateway/services/firewall/nat.go` behind the `nat` service section: **SNAT (masquerade with a port range) and port-forward DNAT only.** No CGNAT, no 1:1 static NAT, no NAT64. |
| `pkg/sdn/gateway/loadbalancer/` (`ingress.go`, `algorithm.go`), "Maglev consistent hashing" | The load balancer is `pkg/sdn/gateway/services/loadbalancer/` behind the `load-balancer` section: an OpenFlow **select group** per VIP with per-VIP conntrack zones. **No Maglev** anywhere in the repository. |
| `pkg/sdn/gateway/edge/` (`onboarding.go`, `acme.go`, `dht_bootstrap.go`, `ipv6_alloc.go`) | Edge behaviour lives in `pkg/sdn/gateway/modes/edge.go` and `edge_p2p.go` (build-tag split on `platform_p2p`). `NewEdgeModeHandler` has no non-test caller. |
| `pkg/sdn/gateway/security/` (`ddos.go`, `ratelimit.go`, `reputation.go`), "5-layer DDoS protection" | `PerPeerRateLimiter` and `DDOSProtection` are types inside `pkg/sdn/gateway/modes/edge.go`; there is no `security/` package and, because the edge handler is never constructed outside tests, neither runs on a live gateway. |
| Phase 3 "Complete 100%" | The package that exists is `pkg/sdn/gateway/{commands,controlplane,modes,p2p,proxysvc,services/{firewall,loadbalancer,perf},state}` plus `node.go`, `types.go`, `runtime.go`, `snapshot.go`, `compat.go`, `zone_service.go`. The mode handlers under `modes/` (overlay, edge, transit) are constructed only by tests; the registered service handlers for overlay, edge, transit, DHCP, tunnels and PXE set a boolean and program nothing (issue #553, Phase 1). |
| Phase 6 "Gateway failover" integration test, "Failover — Kill gateway — Traffic continues", "Gateway failover time < 10s" | **No such test.** `test/integration/cluster/failover_test.go` exercises **Raft leader** failover of the control plane, not a gateway. There is no `test/integration/gateway/` package. |
| "Route signing (coordinator tier)", "Multi-gateway verification (min 3 gateways)" | `RouteSigningKey` in `pkg/sdn/gateway/modes/transit.go` is one in-process Ed25519 key; `VerifyRouteSignature` can verify only its own signature; `AnnouncePrefix` discards the signature it computes. Design status only — see `docs/sdn/bgp/transit.md`. |
| "GatewayMode bitmask (Overlay, Edge, Transit)" as the gateway model | `GatewayMode` (`pkg/sdn/gateway/compat.go`) is **deprecated compatibility**; the model is eleven config-driven service sections. See [`docs/gateway/architecture.md`](gateway/architecture.md). |

Gateway high availability for the two-gateway deployment is decided under epic
#553 (Phase 5, ruling R7), not by anything in this file.

**Version:** 1.0.0
**Last Updated:** 2026-01-20
**Status:** ARCHIVE (was "Active Development"; corrected 2026-08-18)

---

## Executive Summary

This roadmap tracks the implementation of multi-host networking capabilities for go-trusted-platform. The project extends the existing single-host SDN implementation to support:

- **VXLAN Overlay Networking** - East-west VM/container traffic across multiple hosts
- **Unified BGP Service** - GoBGP-based EVPN control plane AND platform IP block announcements
- **Multi-Mode Gateway Nodes** - Three operational modes (Overlay, Edge, Transit) in a single unified gateway architecture
- **QuicBaaS Integration** - Distributed state management via Raft consensus

The implementation enables the platform to operate as a complete SDN fabric with BGP peering to external networks (ISPs, fabric switches) while supporting IoT device onboarding and distributed hash table (DHT) bootstrap services.

---

## Goals

### Primary Goals

1. **Multi-Host Networking** - Enable VMs and containers to communicate across physical host boundaries using VXLAN tunneling
2. **BGP Transit** - Announce platform IPv4/IPv6 blocks to Internet Service Providers and fabric switches
3. **IoT Edge Gateways** - Support device onboarding, DHT bootstrap, and NAT traversal for edge devices
4. **High Availability** - Gateway failover with QuicBaaS-backed state replication — NOT IN CODE (#559)

### Enabled Capabilities

| Capability | Description |
|------------|-------------|
| East-West Traffic | VM-to-VM communication across hosts via VXLAN overlay |
| North-South Traffic | External connectivity via gateway NAT/routing |
| IPv6 Allocation | Automatic IPv6 address assignment from platform pool |
| Device Onboarding | ACME endorse-01/enroll-01 for IoT TPM enrollment |
| DHT Bootstrap | Entry point for new nodes joining Kademlia DHT network |
| BGP Peering | eBGP sessions with ISPs for public IP transit |
| EVPN Control Plane | MAC/IP learning and BUM traffic handling |

---

## Platform IP Allocations

### IPv6 Block

| Property | Value |
|----------|-------|
| **Block** | `2001:db8::/36` |
| **Size** | 4.7 quintillion addresses |
| **Purpose** | Platform node addressing |
| **Hierarchy** | `2001:db8:RRRR:SSSS:HHHH:HHHH:HHHH:HHHH/64` |

**IPv6 Address Hierarchy:**
- `RRRR` = Region ID (65,536 regions)
- `SSSS` = Subnet ID (65,536 per region)
- `HHHH:HHHH:HHHH:HHHH` = Host ID (auto-allocated via DHT)

### IPv4 Block

| Property | Value |
|----------|-------|
| **Block** | `203.0.113.0/24` |
| **Size** | 254 usable addresses |
| **Purpose** | Public gateway pool |

---

## Architecture Overview

```
                         +---------------------------------------------+
                         |            Internet / ISPs                  |
                         |   (eBGP peers for 2001:db8::/36 and        |
                         |         203.0.113.0/24)                     |
                         +----------------------+----------------------+
                                                | eBGP
        +---------------------------------------+---------------------------------------+
        |                                       |                                       |
  +-----v-----+                           +-----v-----+                           +-----v-----+
  | Gateway 1 |                           | Gateway 2 |                           | Gateway N |
  | BACKBONE  |                           |DATACENTER |                           |COORDINATOR|
  |           |                           |           |                           |           |
  | Modes:    |                           | Modes:    |                           | Modes:    |
  | - Transit |<------------------------->| - Transit |<------------------------->| - Edge    |
  | - Overlay |      iBGP (via RR)            | - Overlay |      iBGP (via RR)            | - Overlay |
  | - Edge    |                           | - Edge    |                           |           |
  +-----+-----+                           +-----+-----+                           +-----+-----+
        |                                       |                                       |
  ======|=======================================|=======================================|======
                          VXLAN Overlay Mesh (VNI per tenant)
  ======|=======================================|=======================================|======
        |                                       |                                       |
  +-----v-----+                           +-----v-----+                           +-----v-----+
  | Compute 1 |                           | Compute 2 |                           | Compute N |
  |   VTEP    |<------------------------->|   VTEP    |<------------------------->|   VTEP    |
  | QuicBaaS  |         Raft              | QuicBaaS  |         Raft              | QuicBaaS  |
  +-----------+                           +-----------+                           +-----------+
  | VM1  VM2  |                           | VM3  CT1  |                           | VM4  CT2  |
  +-----------+                           +-----------+                           +-----------+
        ^                                       ^                                       ^
        |                                       |                                       |
  +-----+-----+                           +-----+-----+                           +-----+-----+
  |  IoT/P2P  |                           |  IoT/P2P  |                           |  IoT/P2P  |
  |  Devices  |                           |  Devices  |                           |  Devices  |
  | (DHT Leaf)|                           | (DHT Leaf)|                           | (DHT Leaf)|
  +-----------+                           +-----------+                           +-----------+
```

### Three-Tier BGP Speaker Architecture

| Tier | Role | BGP Function | Prefixes Announced |
|------|------|--------------|-------------------|
| **Backbone** | Core network speakers | eBGP to ISPs | Full `/36` aggregate (2001:db8::/36) |
| **Datacenter** | Regional gateways | eBGP to local ISP | Regional `/48` prefixes |
| **Coordinator** | Route coordination | iBGP RR client | Signs route announcements |

---

## Phase Checklist

### Master Progress

| Phase | Name | Status | Progress |
|-------|------|--------|----------|
| Phase 0 | Documentation | Complete | 100% |
| Phase 1 | VXLAN Infrastructure | Complete | 100% |
| Phase 2 | Unified BGP Service | Complete | 100% |
| Phase 3 | Unified Gateway Nodes | **Partly — see Corrections (#559)** | — |
| Phase 4 | Overlay Controller | Complete | 100% |
| Phase 5 | API Extensions | Complete | 100% |
| Phase 6 | Integration Tests | **Partly — no gateway failover test exists (#559)** | — |

### Phase Status Legend

- [ ] Not Started
- [x] Complete

---

## Phase 0: Documentation

**Status:** Complete ✓
**Estimated LOC:** N/A
**Purpose:** Planning and specification

### Deliverables

- [x] Create implementation plan (vivid-wobbling-marshmallow.md)
- [x] Create roadmap document (this document)
- [x] Create architecture documentation for overlay networking (docs/sdn/overlay/)
- [x] Create BGP architecture documentation (docs/sdn/bgp/)
- [x] Create gateway architecture documentation (docs/sdn/gateway/)
- [x] Create API specification for BGP/Gateway services (api-reference-*.md files)
- [x] Create configuration reference documentation (configuration.md files)
- [x] Update main SDN README with multi-host section

### Design Decisions Documented

- [x] **Route Reflectors**: Mandatory hierarchical RR topology for O(n) session scaling (quintillion node support)
- [x] **IPv6 Allocation**: Inactivity timeout model (30-day timeout, active nodes keep IP forever)

---

## Phase 1: VXLAN Infrastructure

**Status:** Complete ✓
**Estimated LOC:** ~1,500
**New Package:** `pkg/sdn/vxlan/`
**Test Coverage:** vxlan=95.2%, ovs=90.0%, openflow=94.0%, cluster=87.9%

### Package Structure

```
pkg/sdn/vxlan/
+-- types.go          # VNI, VTEPConfig, TunnelState, RemoteMACEntry
+-- errors.go         # Typed errors (ErrVNIInvalid, ErrTunnelFailed, etc.)
+-- vtep.go           # VTEP lifecycle management
+-- tunnel.go         # VXLAN tunnel creation/deletion via OVS
+-- vni_mapper.go     # VLAN <-> VNI mapping (VNI = 1000000 + VLAN)
```

### Deliverables

- [x] **Types Definition** (`types.go`)
  - [x] VNI type with validation
  - [x] VTEPConfig struct
  - [x] TunnelState enum
  - [x] RemoteMACEntry struct
  - [x] VXLANPortConfig struct

- [x] **Error Definitions** (`errors.go`)
  - [x] ErrVNIInvalid
  - [x] ErrVNIAlreadyExists
  - [x] ErrTunnelFailed
  - [x] ErrVTEPNotConfigured
  - [x] ErrRemoteUnreachable

- [x] **VTEP Management** (`vtep.go`)
  - [x] VTEP creation and initialization
  - [x] VTEP shutdown and cleanup
  - [x] Local VTEP IP configuration
  - [x] VTEP status reporting

- [x] **Tunnel Management** (`tunnel.go`)
  - [x] Create VXLAN tunnel to remote VTEP
  - [x] Delete VXLAN tunnel
  - [x] List active tunnels
  - [x] Tunnel health monitoring

- [x] **VNI Mapping** (`vni_mapper.go`)
  - [x] VLAN to VNI mapping function
  - [x] VNI to VLAN reverse mapping
  - [x] VNI range validation
  - [x] Mapping persistence

### OVS Client Extensions

- [x] **VXLAN Port Operations** (`pkg/sdn/ovs/vxlan.go`)
  - [x] `AddVXLANPort(ctx, bridge, port string, cfg *VXLANPortConfig) error`
  - [x] `DeleteVXLANPort(ctx, bridge, port string) error`
  - [x] `ListVXLANPorts(ctx, bridge string) ([]*VXLANPort, error)`
  - [x] `GetVXLANPort(ctx, bridge, port string) (*VXLANPort, error)`

### OpenFlow Tunnel Extensions

- [x] **Tunnel ID Match/Action** (`pkg/sdn/openflow/tunnel.go`)
  - [x] TunnelMatch for VNI-based flow matching
  - [x] ActionSetTunnelID for VXLAN encapsulation
  - [x] ActionSetTunDst for tunnel destination
  - [x] FlowModBuilder fluent API

### QuicBaaS Cluster State

- [x] **VXLAN State Types** (`pkg/sdn/cluster/vxlan_types.go`)
  - [x] VTEPState with versioning
  - [x] TunnelState with versioning
  - [x] VNIMappingState with versioning
  - [x] RemoteMACState with versioning and expiry

- [x] **VXLAN DAOs** (`pkg/sdn/cluster/*_dao.go`)
  - [x] VTEP DAO with CRUD operations
  - [x] Tunnel DAO with CRUD operations
  - [x] VNI Mapping DAO with CRUD operations
  - [x] Remote MAC DAO with CRUD operations

### Unit Tests

- [x] VNI validation tests
- [x] VTEP lifecycle tests
- [x] Tunnel creation/deletion tests
- [x] VNI mapping roundtrip tests
- [x] Error handling tests
- [x] Concurrent access tests

---

## Phase 2: Unified BGP Service

**Status:** Complete ✓
**Estimated LOC:** ~3,000
**New Package:** `pkg/sdn/bgp/`
**Dependency:** GoBGP (`github.com/osrg/gobgp/v3`)
**Test Coverage:** 84.8%

### Package Structure

```
pkg/sdn/bgp/
+-- types.go        # BGPConfig, SpeakerTier, NeighborConfig, RouteTypes
+-- errors.go       # Typed errors
+-- speaker.go      # GoBGP wrapper, unified speaker management
+-- evpn.go         # EVPN routes (Type-2 MAC/IP, Type-3 multicast, Type-5 prefix)
+-- transit.go      # IP block announcement (IPv4/IPv6 transit)
+-- peer.go         # BGP peer state machine, health monitoring
+-- rpki.go         # RPKI validation for route security
+-- dampening.go    # BGP flap dampening (15-60 min suppression)
```

### Deliverables

- [x] **Types Definition** (`types.go`)
  - [x] SpeakerTier enum (Backbone, Datacenter, Coordinator)
  - [x] BGPConfig struct
  - [x] BGPCapabilities struct (EVPN, IPv4/IPv6 Unicast, RPKI)
  - [x] NeighborConfig struct
  - [x] RouteType enum

- [x] **Error Definitions** (`errors.go`)
  - [x] ErrPeerNotFound
  - [x] ErrSessionNotEstablished
  - [x] ErrRPKIValidationFailed
  - [x] ErrRouteRejected
  - [x] ErrDampeningActive

- [x] **BGP Speaker** (`speaker.go`)
  - [x] GoBGP server wrapper
  - [x] Speaker initialization by tier
  - [x] Graceful shutdown
  - [x] Configuration hot reload
  - [x] Metrics export

- [x] **EVPN Routes** (`evpn.go`)
  - [x] Type-2: MAC/IP advertisement (ARP suppression)
  - [x] Type-3: Inclusive multicast (BUM traffic)
  - [x] Type-5: IP prefix advertisement (L3 routing)
  - [x] Route table management
  - [x] Route import/export

- [x] **Transit Routes** (`transit.go`)
  - [x] IPv6 aggregate announcement (2001:db8::/36)
  - [x] IPv6 regional announcement (/48)
  - [x] IPv4 gateway pool announcement (203.0.113.0/24)
  - [x] Prefix origination
  - [x] AS path prepending

- [x] **Peer Management** (`peer.go`)
  - [x] Peer state machine
  - [x] Session establishment
  - [x] Keepalive handling
  - [x] Health monitoring
  - [x] Graceful restart

- [x] **RPKI Validation** (`rpki.go`)
  - [x] ROA validation
  - [x] RPKI cache integration
  - [x] Route filtering based on validation state
  - [x] Graceful degradation on validator unavailability

- [x] **BGP Dampening** (`dampening.go`)
  - [x] Route flap detection
  - [x] Penalty calculation
  - [x] Suppression timer (15-60 min)
  - [x] Route reuse thresholds

### Unit Tests

- [x] Speaker tier configuration tests
- [x] EVPN route encoding/decoding tests
- [x] Transit prefix announcement tests
- [x] Peer state machine tests
- [x] RPKI validation tests
- [x] Dampening calculation tests
- [x] Error handling tests

---

## Phase 3: Unified Gateway Nodes

**Status:** Partly implemented — rows marked `NOT IN CODE (#559)` never shipped
**Estimated LOC:** ~5,000
**New Package:** `pkg/sdn/gateway/`
**Test Coverage:** gateway=93.3%, modes=95.0%

### Package Structure

The tree below is the tree that was **planned**. The tree that **exists** is
`pkg/sdn/gateway/{commands,controlplane,modes,p2p,proxysvc,services/{firewall,loadbalancer,perf},state}`;
the `cluster/`, `routing/`, `nat/`, `loadbalancer/`, `edge/` and `security/`
directories below were never created (#559).

```
pkg/sdn/gateway/
+-- types.go              # GatewayNode, GatewayMode, GatewayCapabilities
+-- errors.go             # Typed errors
+-- node.go               # Gateway node lifecycle
+-- modes/
|   +-- overlay.go        # SDN overlay mode (VXLAN, EVPN)
|   +-- edge.go           # Edge/P2P/IoT mode (device onboarding, DHT)
|   +-- transit.go        # BGP transit mode (IP block announcement)
+-- cluster/
|   +-- manager.go        # HA coordination via QuicBaaS
|   +-- election.go       # Gateway promotion/demotion
|   +-- health.go         # Health monitoring, heartbeat
+-- routing/
|   +-- router.go         # L3 routing engine
|   +-- ecmp.go           # Equal-cost multi-path
|   +-- rib.go            # Routing Information Base
+-- nat/
|   +-- snat.go           # Source NAT for egress
|   +-- dnat.go           # Destination NAT for ingress
|   +-- cgnat.go          # Carrier-grade NAT for IoT (RFC 6598)
+-- loadbalancer/
|   +-- ingress.go        # VIP-based load balancing
|   +-- algorithm.go      # RR, WRR, least-conn, maglev
|   +-- health.go         # Backend health probes
+-- edge/
|   +-- onboarding.go     # IoT device onboarding
|   +-- acme.go           # ACME endorse-01/enroll-01 support
|   +-- dht_bootstrap.go  # DHT bootstrap for new nodes
|   +-- ipv6_alloc.go     # IPv6 address allocation from pool
+-- security/
    +-- ddos.go           # 5-layer DDoS protection
    +-- ratelimit.go      # Per-peer rate limiting
    +-- reputation.go     # Reputation-based access
```

### Phase 3a: SDN Overlay Mode

- [x] **Overlay Gateway** (`modes/overlay.go`)
  - [x] VTEP for VXLAN encap/decap
  - [x] EVPN Type-2 for MAC/IP learning
  - [x] EVPN Type-3 for BUM (ingress replication)
  - [x] ARP suppression
  - [x] Distributed anycast gateway

- [x] **OpenFlow Pipeline**
  - [x] Table 0: Ingress Classification
  - [x] Table 10: VXLAN Decap (VNI -> VLAN)
  - [x] Table 20: Authentication (cert-based)
  - [x] Table 30: MAC Learning / L2 Forwarding
  - [x] Table 40: ARP Handling (suppression)
  - [x] Table 50: L3 Routing (anycast gateway)
  - [x] Table 60: Egress (port or tunnel)

### Phase 3b: Edge/P2P Gateway Mode

- [x] **Edge Gateway** (`modes/edge.go`)
  - [x] ACME endorse-01 support
  - [x] ACME enroll-01 support
  - [x] DHT bootstrap entry point
  - [x] IPv6 allocation from pool
  - [x] NAT traversal (STUN/TURN)
  - [x] Per-peer rate limiting

- [x] **Device Onboarding** (integrated in `modes/edge.go`)
  - [x] TPM EK validation
  - [x] Privacy CA integration (FROST signing)
  - [x] IDevID issuance flow
  - [x] TPM quote verification
  - [x] DHT leaf node registration

- [x] **IPv6 Allocation** (integrated in `modes/edge.go`)
  - [x] Regional pool management
  - [x] CAS atomic allocation
  - [x] Inactivity timeout model (30-day inactivity = reallocation, active = keep forever)
  - [x] Lease expiration handling
  - [x] Cross-region overflow

### Phase 3c: BGP Transit Mode

- [x] **Transit Gateway** (`modes/transit.go`)
  - [x] IPv6 announcement (2001:db8::/36 or /48)
  - [x] IPv4 announcement (203.0.113.0/24)
  - [x] RPKI validation integration
  - [x] BGP dampening (3+ withdrawals/hour -> 15-60 min suppression)
  - [x] Route signing (coordinator tier) — DESIGN ONLY: one in-process Ed25519 key, signature discarded (#559)
  - [x] Multi-gateway verification (min 3 gateways) — NOT IN CODE (#559)

### Gateway Core

- [x] **Types Definition** (`types.go`)
  - [x] GatewayMode bitmask (Overlay, Edge, Transit) — DEPRECATED compat surface; the model is eleven service sections (#559)
  - [x] GatewayNode struct
  - [x] GatewayCapabilities struct
  - [x] UplinkPort struct

- [x] **Gateway Lifecycle** (`node.go`)
  - [x] Gateway initialization
  - [x] Mode activation/deactivation
  - [x] Configuration reload
  - [x] Graceful shutdown

- [x] **Cluster Management** (`cluster/`) — NOT IN CODE (#559)
  - [x] QuicBaaS state manager integration
  - [x] Gateway promotion/demotion
  - [x] Health monitoring and heartbeat
  - [x] Failover coordination

- [x] **Routing Engine** (`routing/`) — NOT IN CODE (#559)
  - [x] L3 routing with RIB
  - [x] ECMP load balancing
  - [x] Route redistribution

- [x] **NAT** (`nat/`) — the package does not exist; SNAT and port-forward DNAT live in `services/firewall/nat.go` (#559)
  - [x] SNAT for egress traffic
  - [x] DNAT for ingress traffic
  - [x] CGNAT for IoT (RFC 6598) — NOT IN CODE (#559)

- [x] **Load Balancer** (`loadbalancer/`) — the package is `services/loadbalancer/` (#559)
  - [x] VIP-based ingress
  - [x] Maglev consistent hashing — NOT IN CODE (#559); the balancer is an OpenFlow select group
  - [x] Health probes

- [x] **Security** (`security/`) — the package does not exist; the types are in `modes/edge.go`, never constructed outside tests (#559)
  - [x] 5-layer DDoS protection
  - [x] Per-peer rate limiting (trusted: 100 req/s, untrusted: 10 req/s)
  - [x] Reputation-based access control

### Gateway Requirements (from docs/dht/)

| Requirement | Value |
|-------------|-------|
| Minimum Reputation | 0.85 |
| Minimum Age | 175+ days |
| Minimum Uptime | 95% |
| Minimum Bandwidth | 100 Mbps |
| IPv6 Inactivity Timeout | 30 days (reallocate only if inactive this long) |
| BGP Route Propagation | 30 seconds |
| BGP Flap Dampening | 15-60 minutes |

### Unit Tests

- [x] Gateway mode tests
- [x] Overlay VTEP tests
- [x] Edge onboarding flow tests
- [x] Transit announcement tests
- [x] NAT translation tests
- [x] Load balancer algorithm tests
- [x] DDoS protection tests
- [x] Rate limiting tests

---

## Phase 4: Overlay Controller

**Status:** Complete ✓
**Estimated LOC:** ~1,500
**New Package:** `pkg/sdn/overlay/`

### Package Structure

```
pkg/sdn/overlay/
+-- types.go        # OverlayConfig, ControllerState
+-- errors.go       # Typed errors
+-- controller.go   # Main orchestrator
+-- state.go        # State management via QuicBaaS
+-- arp.go          # ARP suppression logic
```

### Deliverables

- [x] **Controller Core** (`controller.go`)
  - [x] Initialize all overlay components
  - [x] Coordinate VTEP, BGP, and gateway managers
  - [x] Event-driven state updates
  - [x] Graceful startup/shutdown

- [x] **State Management** (`state.go`)
  - [x] QuicBaaS integration for distributed state
  - [x] VTEP registration/discovery
  - [x] Remote MAC synchronization
  - [x] Tunnel state tracking

- [x] **ARP Suppression** (`arp.go`)
  - [x] ARP request interception
  - [x] Local cache lookup
  - [x] Remote MAC resolution via EVPN
  - [x] ARP response generation

### Unit Tests

- [x] Controller lifecycle tests
- [x] State synchronization tests
- [x] ARP suppression tests
- [x] Multi-component coordination tests

---

## Phase 5: API Extensions

**Status:** Complete ✓
**Estimated LOC:** ~2,000

### gRPC API (`pkg/api/grpc/proto/overlay.proto`)

- [x] **OverlayService**
  - [x] `CreateVNI` / `DeleteVNI`
  - [x] `ListVTEPs`
  - [x] `ListTunnels`
  - [x] `ListRemoteMACs`

- [x] **BGPService** (integrated into GatewayService)
  - [x] `GetBGPStatus`
  - [x] `ListBGPPeers`
  - [x] `ListEVPNRoutes`
  - [x] `ListTransitRoutes`
  - [x] `AnnouncePrefix` / `WithdrawPrefix`

- [x] **GatewayService**
  - [x] `RegisterGateway`
  - [x] `SetGatewayMode`
  - [x] `GetGatewayHealth`
  - [x] `AllocateIPv6`
  - [x] `OnboardDevice`
  - [x] `CreateService` / `AddBackend` (load balancer)

### REST API

- [x] Implement REST handlers for all gRPC services (`pkg/api/rest/overlay_handlers.go`, `gateway_handlers.go`)
- [x] OpenAPI specification

### QUIC API

- [x] QUIC transport implementation (`pkg/api/quic/overlay_handlers.go`, `gateway_handlers.go`)

### MCP API

- [x] MCP tools/resources for AI/LLM integration (`pkg/api/mcp/overlay_tools.go`, `gateway_tools.go`)

### Unix Socket API

- [x] Local IPC implementation (via gRPC over Unix socket)

### CLI Commands (`platformctl`)

- [x] **Overlay Commands**
  - [x] `platformctl sdn overlay status`
  - [x] `platformctl sdn overlay vtep list/get`
  - [x] `platformctl sdn overlay vni list/create/delete`
  - [x] `platformctl sdn overlay tunnel list`
  - [x] `platformctl sdn overlay mac list/forget`

- [x] **Gateway Commands**
  - [x] `platformctl sdn gateway status`
  - [x] `platformctl sdn gateway mode set`
  - [x] `platformctl sdn gateway bgp status/peers/prefixes/announce/withdraw`
  - [x] `platformctl sdn gateway ipam pools/allocate/release/allocations`

- [x] **IPAM Commands**
  - [x] `platformctl sdn ipam pool list/create/delete`
  - [x] `platformctl sdn ipam allocate/release/list`

---

## Phase 6: Integration Tests

**Status:** Partly — the gateway failover row never shipped (#559)
**Estimated LOC:** ~2,500
**Location:** `test/integration/sdn/`

### Multi-Protocol Test Framework

```go
//go:build integration

func TestOverlayMultiProtocol(t *testing.T) {
    t.Run("CLI", func(t *testing.T) { testOverlayCLI(t, ctx) })
    t.Run("REST", func(t *testing.T) { testOverlayProtocol(t, ctx, &restAdapter{}) })
    t.Run("gRPC", func(t *testing.T) { testOverlayProtocol(t, ctx, &grpcAdapter{}) })
    t.Run("QUIC", func(t *testing.T) { testOverlayProtocol(t, ctx, &quicAdapter{}) })
    t.Run("MCP", func(t *testing.T) { testOverlayProtocol(t, ctx, &mcpAdapter{}) })
    t.Run("Unix", func(t *testing.T) { testOverlayProtocol(t, ctx, &unixAdapter{}) })
}
```

### Test Infrastructure Files

| File | Purpose |
|------|---------|
| `adapters.go` | Core `SDNTestAdapter` interface and response types |
| `sdn_rest_adapter.go` | REST client adapter |
| `sdn_grpc_adapter.go` | gRPC client adapter |
| `sdn_quic_adapter.go` | QUIC/HTTP3 client adapter |
| `sdn_mcp_adapter.go` | MCP tool call adapter |
| `sdn_unix_adapter.go` | Unix socket adapter |
| `sdn_cli_adapter.go` | CLI binary adapter |
| `phase6_overlay_test.go` | Overlay integration tests |
| `phase6_gateway_test.go` | Gateway/BGP/IPAM integration tests |
| `phase6_dhcp_test.go` | DHCP integration tests |

### Integration Test Scenarios

- [x] **VXLAN Tests**
  - [x] Multi-node VTEP discovery via QuicBaaS
  - [x] VXLAN tunnel establishment
  - [x] East-west traffic across hosts
  - [x] MAC learning verification
  - [x] ARP suppression validation

- [x] **BGP Tests**
  - [x] EVPN session establishment
  - [x] Type-2/3/5 route exchange
  - [x] Transit prefix announcement
  - [x] RPKI validation
  - [x] Dampening behavior

- [x] **Gateway Tests**
  - [x] Gateway mode activation
  - [x] Gateway failover — NOT IN CODE (#559): the only failover test is Raft leader failover in `test/integration/cluster/`
  - [x] IoT device onboarding flow
  - [x] IPv6 lease allocation and renewal
  - [x] NAT translation
  - [x] Load balancer health probes

- [x] **Multi-Protocol Tests**
  - [x] All APIs via CLI
  - [x] All APIs via REST
  - [x] All APIs via gRPC
  - [x] All APIs via QUIC
  - [x] All APIs via MCP
  - [x] All APIs via Unix socket

---

## Dependencies

### External Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `github.com/osrg/gobgp/v3` | Latest | Pure Go BGP implementation |

### Internal Dependencies

| Package | Purpose |
|---------|---------|
| `pkg/sdn/ovs` | OVSDB client for OVS management |
| `pkg/sdn/openflow` | OpenFlow 1.3 protocol client |
| `pkg/sdn/arp` | ARP table reader |
| `pkg/sdn/netlink` | TAP device management |
| `pkg/sdn/policy` | 802.1X policy engine |
| `pkg/quicbaas` | Distributed state storage |
| `pkg/acme` | ACME protocol for device enrollment |

---

## Documentation Checklist

### Architecture Documentation

- [x] `docs/sdn/overlay/architecture.md` - Overlay networking design
- [x] `docs/sdn/bgp/architecture.md` - BGP service architecture
- [x] `docs/sdn/gateway/architecture.md` - Gateway node design
- [x] `docs/sdn/ipam/architecture.md` - IPAM architecture
- [x] `docs/sdn/dhcp/architecture.md` - DHCP architecture

### API Reference Documentation

- [x] `docs/sdn/overlay/api-reference.md` - Overview
- [x] `docs/sdn/overlay/api-reference-rest.md` - REST endpoints
- [x] `docs/sdn/overlay/api-reference-grpc.md` - gRPC service methods
- [x] `docs/sdn/bgp/api-reference-rest.md` - BGP REST endpoints
- [x] `docs/sdn/bgp/api-reference-grpc.md` - BGP gRPC methods
- [x] `docs/sdn/gateway/api-reference-rest.md` - Gateway REST endpoints
- [x] `docs/sdn/gateway/api-reference-grpc.md` - Gateway gRPC methods
- [x] `docs/sdn/ipam/api-reference.md` - IPAM API overview
- [x] `docs/sdn/ipam/api-reference-rest.md` - IPAM REST endpoints
- [x] `docs/sdn/ipam/api-reference-grpc.md` - IPAM gRPC methods
- [x] `docs/sdn/dhcp/api-reference.md` - DHCP API overview
- [x] `docs/sdn/dhcp/api-reference-rest.md` - DHCP REST endpoints
- [x] `docs/sdn/dhcp/api-reference-grpc.md` - DHCP gRPC methods
- [x] `docs/sdn/*/api-reference-quic.md` - QUIC API reference (all 5 services)
- [x] `docs/sdn/*/api-reference-mcp.md` - MCP API reference (all 5 services)
- [x] `docs/sdn/*/api-reference-unix.md` - Unix socket API reference (all 5 services)

### Configuration Documentation

- [x] `docs/sdn/overlay/configuration.md` - Overlay config reference
- [x] `docs/sdn/bgp/configuration.md` - BGP config reference
- [x] `docs/sdn/gateway/configuration.md` - Gateway config reference
- [x] `docs/sdn/ipam/configuration.md` - IPAM config reference
- [x] `docs/sdn/dhcp/configuration.md` - DHCP config reference
- [x] `docs/sdn/dhcp/plugins.md` - DHCP plugins reference

### CLI Documentation

- [x] `docs/sdn/cli-usage.md` - Unified CLI commands (overlay, gateway, ipam)
- [x] `docs/sdn/bgp/cli-usage.md` - BGP CLI deep dive
- [x] `docs/sdn/dhcp/cli-usage.md` - DHCP CLI commands

### Operations Documentation

- [x] `docs/sdn/overlay/operations.md` - Day-2 operations guide
- [x] `docs/sdn/bgp/troubleshooting.md` - BGP troubleshooting guide
- [x] `docs/sdn/gateway/operations.md` - Gateway operations guide

---

## Testing Checklist

### Unit Test Coverage Requirements

| Package | Target | Actual | Status |
|---------|--------|--------|--------|
| `pkg/sdn/vxlan` | 90%+ | 95.2% | ✅ |
| `pkg/sdn/bgp` | 90%+ | 90.2% | ✅ |
| `pkg/sdn/gateway` | 90%+ | 93.3% | ✅ |
| `pkg/sdn/gateway/modes` | 90%+ | 89.9% | ✅ (practical max) |
| `pkg/sdn/overlay` | 90%+ | 91.0% | ✅ |
| `pkg/sdn/cluster` | 90%+ | 90.1% | ✅ |
| `pkg/sdn/netlink` | 90%+ | 90.1% | ✅ |
| `pkg/sdn/ipam` | 90%+ | 90.4% | ✅ |
| `pkg/sdn/ipam/backends` | 90%+ | 90.2% | ✅ |
| `pkg/sdn/dhcp` | 90%+ | 89.6% | ✅ (practical max) |

### Test Categories

- [x] **Unit Tests** - All packages at 90%+ target (or practical maximum)
- [x] **Integration Tests** - Multi-protocol API testing (test/integration/sdn/)
- [x] **Benchmark Tests** - Performance validation (pkg/sdn/*/benchmark_test.go)
- [x] **Stress Tests** - Scale and reliability testing (test/integration/sdn/stress/)

### Test Infrastructure

- [x] Devcontainer setup for integration tests (existing)
- [x] Multi-protocol test adapters (REST, gRPC, QUIC, MCP, Unix, CLI)
- [x] Mock external BGP peers (test/integration/sdn/mock_bgp/)
- [x] Test topology automation (test/integration/sdn/topology/)

---

## Verification Checklist

### Functional Verification

| Item | Command | Expected Result |
|------|---------|-----------------|
| VTEP Discovery | `platformctl overlay vtep list` | Shows all hosts |
| Tunnels | `platformctl overlay tunnel list` | Shows full mesh |
| East-West Ping | VM-to-VM ping | VM on Host A pings VM on Host B |
| MAC Learning | `platformctl overlay mac list` | Shows remote MACs |
| BGP EVPN Routes | `platformctl bgp routes evpn` | Shows Type-2/3/5 routes |
| BGP Transit Routes | `platformctl bgp routes transit` | Shows announced prefixes |
| ISP Peering | External router check | Receives 2001:db8::/36 |
| Gateway Modes | Gateway status | All three modes active |
| IoT Onboarding | Device enrollment | Receives IPv6, joins DHT |
| Failover | Kill gateway | Traffic continues — NOT VERIFIED; no gateway failover exists (#559) |

### Performance Verification

| Metric | Target |
|--------|--------|
| VXLAN tunnel latency overhead | < 50us |
| BGP convergence time | < 30s |
| Gateway failover time | < 10s — no mechanism exists to measure (#559) |
| IoT onboarding time | < 5s |

### Security Verification

| Item | Validation |
|------|------------|
| RPKI validation | Routes rejected without valid ROA |
| Rate limiting | Untrusted peers limited to 10 req/s |
| DDoS protection | 5-layer protection active |
| Certificate-based auth | All connections authenticated |

---

## Configuration Reference

```yaml
# platform.yaml
sdn:
  overlay:
    enabled: true
    vtep_ip: "10.4.1.10"
    underlay_interface: "eth0"
    underlay_mtu: 9000
    vxlan_port: 4789
    vni_base: 1000000

  bgp:
    enabled: true
    asn: 65000
    router_id: "10.4.1.10"

    # EVPN for overlay
    evpn:
      enabled: true
      rd: "65000:1"
      import_rt: ["65000:100"]
      export_rt: ["65000:100"]

    # Transit for IP blocks
    transit:
      enabled: true
      tier: datacenter  # backbone | datacenter | coordinator
      ipv6_prefixes:
        - "2602:F5BB:1234::/48"
      ipv4_prefixes:
        - "203.0.113.0/24"
      rpki:
        enabled: true
        validators: ["rpki.example.com:323"]
      dampening:
        half_life: 15m
        max_suppress: 60m

    # External peers (ISPs, fabric)
    neighbors:
      - address: "198.51.100.1"
        asn: 64500
        description: "ISP Upstream"
        auth: md5
        auth_key: "${BGP_MD5_KEY}"

  gateway:
    enabled: true
    modes: [overlay, edge, transit]
    tier: datacenter

    # Reputation requirements
    min_reputation: 0.85
    min_age_days: 175
    min_uptime_pct: 95

    # Anycast for distributed routing
    anycast_ip: "10.0.0.1"

    # Uplinks
    uplinks:
      - name: "eth1"
        vlan: 100

    # Edge mode config
    edge:
      enabled: true
      ipv6_pool: "2602:F5BB:1234::/48"
      ipv6_inactivity_timeout: 720h  # 30 days - reallocate only if inactive this long
      acme:
        endorse_enabled: true
        enroll_enabled: true
        frost_pool_id: "privacy-ca-pool"
      stun:
        enabled: true
        port: 3478
      rate_limits:
        trusted: 100    # req/s for rep >= 0.80
        untrusted: 10   # req/s for rep < 0.80

    # NAT config
    nat:
      enabled: true
      snat_pool: "203.0.113.0/24"
      cgnat_pool: "100.64.0.0/10"  # RFC 6598 for IoT

    # Load balancer
    loadbalancer:
      enabled: true
      algorithm: maglev
      health_check_interval: 5s
```

---

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| GoBGP complexity | Start with EVPN, add transit incrementally |
| MTU issues | Require jumbo frames (9000) on underlay |
| Split-brain | QuicBaaS Raft quorum prevents |
| Scale limits | Hierarchical route reflectors mandatory (O(n²) → O(n) session scaling) |
| RPKI dependency | Graceful degradation if validators unavailable |
| IPv6 exhaustion | Regional pools with cross-region overflow |

---

## Files to Modify

| File | Changes |
|------|---------|
| `pkg/sdn/cluster/types.go` | Add VXLANState, VNIMappingState, RemoteMACState, GatewayState |
| `pkg/sdn/ovs/client.go` | Add VXLAN port management methods |
| `pkg/sdn/openflow/messages.go` | Add tunnel ID match/action |
| `pkg/sdn/cluster/sync.go` | Extend for overlay and gateway state sync |
| `pkg/api/grpc/proto/sdn.proto` | Add overlay/bgp/gateway RPCs |
| `pkg/device/sdn_integration.go` | Integrate edge gateway onboarding |

---

## New Packages Summary

| Package | Estimated LOC | Purpose |
|---------|---------------|---------|
| `pkg/sdn/vxlan/` | ~1,500 | VXLAN tunnel management |
| `pkg/sdn/bgp/` | ~3,000 | Unified BGP (EVPN + Transit) |
| `pkg/sdn/gateway/` | ~5,000 | Multi-mode gateway nodes |
| `pkg/sdn/overlay/` | ~1,500 | Overlay controller |
| Integration tests | ~2,000 | Multi-protocol tests |
| **Total** | **~13,000** | |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-18 | Initial roadmap document |

---

## References

- Implementation Plan — originating plan document, not tracked in this repository
- [DHT Network Architecture](docs/dht/02-network-architecture.md)
- [DHT Constants Reference](docs/dht/00-CONSTANTS.md)
- [SDN Package README](docs/sdn/README.md)
- [SDN Architecture](docs/archive/sdn-architecture-2026-01.md)
- [GoBGP Documentation](https://github.com/osrg/gobgp)
- [RFC 7348 - VXLAN](https://datatracker.ietf.org/doc/html/rfc7348)
- [RFC 7432 - BGP EVPN](https://datatracker.ietf.org/doc/html/rfc7432)
