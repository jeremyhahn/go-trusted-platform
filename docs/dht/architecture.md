# Trusted DHT — Architecture

> **Status: PLANNED** · Scope: design only, no implementation · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: architecture (this file) · [engineering.md](engineering.md) ·
> [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. There is no implementation. Read this before anything else in the folder.

**The Trusted DHT is a design. No code for it exists in this repository.**

Verified against the tree on 2026-08-18:

| Check | Result |
|---|---|
| `pkg/dht/` and every sub-package the design names (`pkg/dht/core`, `discovery`, `gateway`, `agent`, `contract`, `requirements`, `arbitration`, `dns`, `federation`) | **do not exist** |
| Any occurrence of `dht` or `DHT` under `pkg/api/` | **none** |
| Any occurrence of `dht` or `DHT` under `sdk/` | **none** |
| A `dht` or `p2p` command group under `pkg/cli/commands/` | **none** |
| A `dht:` or top-level `p2p:` configuration key | **none** |
| `docs/dht/ROADMAP.md` own status line | *"STATUS: Design Complete - Implementation Pending"* |

There is therefore **no CLI, no REST route, no gRPC service, no QUIC opcode, no
MCP tool and no SDK client** for this feature. [cli.md](cli.md) and
[api.md](api.md) say the same thing in their own terms, and neither invents a
surface that does not exist.

The 26 numbered design documents in this folder are retained as the design
record and are indexed in §10. They are **design intent, not a description of
behaviour**, and several of their claims about the current tree are wrong (§9).

## 2. What *does* exist, and is easy to confuse with this

Two pieces of real code in this repository use a Kademlia DHT. **Neither is the
Trusted DHT**, and neither is documented here.

| Real code | What it is | Where it is documented |
|---|---|---|
| `pkg/sdn/gateway/p2p/` (`Node`, `NATStatus`, `NodeStatus`) | A libp2p host used by SDN **gateway** nodes for peer discovery, NAT traversal and secure peer connections. Wraps `go-libp2p` and `go-libp2p-kad-dht`. | [`docs/gateway/`](../gateway/) |
| `pkg/sdn/ipam/backends/dht.go` (`DHTBackend`) | An `ipam.Allocator` that allocates IP addresses through libp2p's Kademlia DHT with a claim-then-verify protocol. Key namespaces `/ipam/pool/`, `/ipam/alloc/`, `/ipam/device/`. | [`docs/sdn/ipam/`](../sdn/ipam/) |

Both are behind the **`platform_p2p` build tag** (`WITH_P2P=1`, see
[`docs/configuration/build-tags.md`](../configuration/build-tags.md)) and are
absent from a default build.

The overlap with this design is the word "DHT" and the choice of Kademlia. The
Trusted DHT design is a global, reputation-governed, TPM-attested,
currency-bearing overlay with its own consensus, CA pool and content
distribution. The SDN code is intra-fabric plumbing. **Do not treat either as a
partial implementation of the other, and do not extend the SDN packages toward
the design without an explicit owner decision.**

## 3. The problem the design addresses

A trusted-computing platform that can attest a node is still limited to the
nodes one organisation owns. The design asks what it would take to run the same
guarantees across machines nobody centrally controls: how to name and find
content, how to decide who may hold a routing or signing role, how to pay for
resources, and how to keep any of it meaningful when an arbitrary fraction of
participants is hostile.

Its answer is that **hardware attestation is the admission control**, and
everything above it — reputation, consensus, currency, arbitration — is built on
the assumption that identity cannot be forged because it is TPM-bound.

## 4. The shape designed

Five layers, from the design's own diagram:

| Layer | Contents |
|---|---|
| Application | Wallet, git repositories, OS images, updates |
| Service | Currency (sharded), content storage, boot server, registry |
| Consensus | Coordinator (PBFT), defense (quorum), reputation, governance (voting) |
| Cryptographic | FROST signatures, DKG, CA (IDevID), TPM attestation |
| Network | Kademlia DHT, P2P swarm (blocks), IPv6, BGP routing |

Core parameters, from `00-CONSTANTS.md`, which the design declares the single
source of truth:

| Parameter | Value |
|---|---|
| Kademlia `k` (bucket size) | 20 |
| Kademlia `alpha` (parallel lookups) | 3 |
| Replication factor | 3 |
| Record TTL | 24h |
| Maximum value size | 1 MB |
| TPM version | 2.0, required |
| Quote freshness window | ±100 ms |
| CA pool size | 0.1% of the network, minimum 100, maximum 10M |
| CA threshold | 33% |
| CA rotation | 1 hour |
| FROST signing pools | 4, threshold t = 33% |
| PBFT committee | 21 nodes, 7-of-21 threshold; fencing-token quorum 15/21 |
| `PBFTBaseTimeout` / `PBFTMaxTimeout` | 800 ms / 10 s |
| `ViewChangeTimeout` / `MaxConsecutiveViewChanges` | 2 s / 7 |
| `HeartbeatInterval` / `FailureDetectionTimeout` | 2 s / 8 s (4 missed) |
| DKG duration (fast / standard / slow) | 5 min / 10 min / 13 min, checkpoint every 30 s |
| VRF commit and reveal windows | 30 s each, 32-byte blinding factor |
| Nonce cache / TTL | 100,000 entries / 30 s |

Roles are earned, not assigned — reputation thresholds from
`09-defense-reputation.md` (declared canonical):

| Role | Minimum reputation | Minimum days | Capabilities |
|---|---|---|---|
| Leaf | 0.0 | 0 | DHT routing, transaction confirmation |
| Hub | 0.80 | 110 | Routing hub, regional caching |
| Gateway | 0.85 | 175 | External connectivity, IPv4 bridge |
| AI Arbitrator | 0.85 | — | Contract dispute resolution |
| CA Participant | 0.90 | 120 | Certificate generation, trust decisions |
| Coordinator | 0.95 | 185 | Consensus leadership, governance |

### Positions the design records, with the reason recorded

These are the design's own decisions and their stated rationale. **None has been
validated by an implementation**, which is exactly why they are written down
before one exists.

| Position | Reason given |
|---|---|
| **All nodes start at reputation 0.0** (`InitialReputation = 0.0`) | Any non-zero starting reputation is a free Sybil subsidy: an attacker mints identities and collects the bootstrap grant. Trust must be earned per identity. |
| **Binary trust, not graduated** — Trusted (hardware TPM **and** whitelisted EK) or Untrusted (everything else) | A spectrum invites arguing about where a given device sits. A binary split makes the capability set of an unattested node explicit and testable. |
| **Core security parameters are compile-time constants, not configuration** | A tunable threshold is a threshold an operator can be socially engineered into lowering, and a network whose members disagree about a threshold does not have one. |
| **Hardware RNG first** — TPM2, then PKCS#11, then software fallback | Key generation on a compromised or virtualised entropy source undermines every layer above it. Software is the last resort, not the default. |
| **IDevID obtained via a Privacy CA using an ACME `enroll-01` challenge**, not self-signed | A self-asserted identity proves nothing about the hardware. `enroll-01` makes the EK-to-manufacturer chain the thing being proved. |
| **Hierarchical Kademlia rather than flat** | A flat routing table over a network sized for 1B+ nodes makes every lookup a global operation; the hierarchy localises routing and caching (see `02-network-architecture.md`, IPv6 /36 capacity analysis). |
| **IGP (OSPF or IS-IS) within a region, external BGP only between regions** | Running BGP intra-region for a membership that changes continuously produces churn that the protocol was never designed to absorb. |
| **`PBFTBaseTimeout` raised from 500 ms to 800 ms** | Coordinators are globally distributed; the worst case of three round trips is ~1050 ms, so a 500 ms base timeout guarantees spurious view changes. This is the one constant in the set with a measured justification attached. |
| **A separate workload/agent identity rather than reusing the node IDevID** | An AI agent that signs with the node's birth identity cannot be revoked without revoking the node. |
| **Evidence-based penalties — TPM-attested proof required for a violation** | A reputation system in which accusations alone carry weight is a denial-of-service tool aimed at honest nodes. |

## 5. Component boundaries — as designed

Nothing in this table exists yet. It records **who would own each piece** so
that an implementation cannot quietly reimplement a lower layer.

| Piece | Planned package | Owner |
|---|---|---|
| DHT core — node ID, routing table, Kademlia protocol, store | `pkg/dht/`, `pkg/dht/core/` | this repo |
| Wire protocol and transport | `pkg/dht/proto/`, `pkg/dht/transport/` | this repo |
| Service discovery and marketplace | `pkg/dht/discovery/` | this repo |
| Browser-extension gateway | `pkg/dht/gateway/` | this repo |
| AI agent collaboration | `pkg/dht/agent/` | this repo |
| Service contracts, requirements, arbitration | `pkg/dht/contract/`, `requirements/`, `arbitration/` | this repo |
| P2P DNS | `pkg/dht/dns/` | this repo |
| Federation and cross-certification | `pkg/dht/federation/` | this repo |
| DDoS protection, untrusted-node work | `pkg/defense/ddos/`, `pkg/defense/work/` | this repo |
| **Threshold signatures (FROST)** | — | **go-frost** |
| **Distributed key generation** | — | **go-frostdkg** |
| **Hardware RNG, TPM attestation, CA/ACME, key management** | — | **go-xkms**, consumed through `go-quicbaas/sdk/go` |
| **Persistent state, IAM, KMS, secrets, object storage, vector search** | — | **go-quicbaas**, consumed through `go-quicbaas/sdk/go` |

**The SDK boundary is not relaxed for this feature.** This repository imports
`go-quicbaas/sdk/go` only. A DHT implementation that reaches for go-xkms,
go-qrdb or go-quicraft directly is a layer violation, and
`pkg/arch/layerguard_test.go` will fail it.

`24-quicbaas-schema.md` specifies the DHT's state storage as a quicbaas schema —
key naming, indexes and migrations — precisely so that the DHT owns no
persistence engine of its own.

## 6. Data flow — as designed

The design's canonical key namespace (`00-README.md`) is the clearest statement
of what the DHT is for:

```
Content blocks      block:{sha256-hash}
File manifests      manifest:{type}:{identifier}
OS images           os:{distro}:{version}:{arch}:{variant}
Git repositories    git:{org}:{repo}:{branch}
Updates             update:{package}:{version}
Node info           node:{node-id}
Reputation          rep:{node-id}
Transactions        tx:{txid}
Shard state         shard:{shard-id}:state
Key-share manifest  ksp:{owner-id}:{content-hash}
Services            service:{service-id}
Agents / rooms      agent:{agent-id}, room:{room-id}
Contracts / escrow  contract:{contract-id}, contract:escrow:{contract-id}
DNS                 dns:{domain}:{record-type}
Federation          cross-cert:{issuer-hash}:{subject-hash}
```

The intended admission path: a node generates a TPM-resident identity, obtains
an IDevID from the distributed CA pool through ACME `enroll-01`, joins at
reputation 0.0 as a Leaf, and earns role eligibility over time and behaviour.
Every privileged operation is signed by a FROST pool rather than an individual.

Detailed flows are in `01-system-overview.md` (content storage, network boot,
cross-shard transaction, defense and penalty).

## 7. Trust boundaries — as designed

1. **TPM → node identity.** A node's identity key is sealed to PCRs 0, 2 and 7,
   and its quotes must be fresh within ±100 ms. Everything above this assumes
   an identity cannot be moved to different hardware.
2. **EK whitelist → trust class.** Hardware TPM plus a whitelisted EK yields
   `Trusted`; anything else is `Untrusted` with a restricted capability set
   (`17-untrusted-nodes.md`).
3. **FROST pool → signing authority.** No single node signs anything that
   matters. Compromise of fewer than the threshold yields nothing.
4. **Reputation → role.** Routing, gateway, CA and coordinator authority are
   consequences of measured behaviour, not configuration.
5. **Gateway → the outside.** The browser extension and external clients reach
   the network only through gateways (`14-browser-extension.md`), which are the
   one place untrusted external input enters.
6. **Federation boundary.** Cross-certification between organisations is
   explicit and bilateral (`22-federation.md`); it is not transitive.

## 8. What the design deliberately does not do

- **It does not replace the platform's own cluster consensus.** Raft-based
  clustering ([`docs/cluster/`](../cluster/)) is intra-deployment; the DHT is
  inter-organisation.
- **It does not implement cryptography.** FROST is go-frost, DKG is
  go-frostdkg, TPM and CA are go-xkms through the quicbaas SDK.
- **It does not implement storage.** State is a quicbaas schema
  (`24-quicbaas-schema.md`).
- **It does not make security parameters configurable.** See §4.
- **It does not admit unattested nodes to privileged roles.** Untrusted nodes
  get a bounded work set and elevated scrutiny.

## 9. Corrections against the design documents

The design documents make claims about this repository that are false. They are
recorded here so the next reader does not act on them.

| Claim | Reality (verified 2026-08-18) |
|---|---|
| `00-README.md` line 3: *"implemented in `pkg/dht/`"* | `pkg/dht/` does not exist. |
| `00-README.md` Implementation Status: Content Storage `pkg/content/` — **Implemented** | `pkg/content/` does not exist. |
| Same table: Update System `pkg/updates/` — **Implemented** | `pkg/updates/` does not exist. |
| Same table: OS Images `pkg/osimage/` — **Implemented** | `pkg/osimage/` does not exist. |
| Same table: Defense System `pkg/defense/` — **Implemented** | `pkg/defense/` does not exist. |
| Same table: Git Storage `pkg/git/` — **Implemented** | `pkg/git/` does not exist. |
| Same table: Boot System `pkg/boot/` — **Implemented** | `pkg/boot/` **does** exist (`pkg/boot/commands/`, `pkg/boot/config/`) but it is the platform's local boot-manager CLI, not a DHT boot server. The row is right about the path and wrong about the meaning. |
| `ROADMAP.md`: *"Hierarchical Kademlia DHT with 160-bit node IDs"* | The same document's §1.1 specifies *"NodeID type (32-byte SHA256 of public key)"* — 256 bits. The two statements contradict each other and the contradiction is unresolved. |
| `api-reference.md`: a protocol/port table (REST 8443, gRPC 9443, QUIC 9444, MCP 9445, Unix `/run/platformd.sock`) | No DHT listener exists on any port. 8443 and 9443 are the platform web service's TLS ports; 9444 and 9445 appear nowhere in the shipped configuration. |
| `api-reference*.md` generally: endpoint, method and tool listings | None are served. See [api.md](api.md). |
| `18-platformd-p2p.md`: a top-level `p2p:` configuration block and `platformctl p2p status` | Neither exists. The only `p2p` keys in the code are `sdn.transit.p2p` (an IPv4 prefix for /31 links) and the gateway's `p2p` boolean, both unrelated. |

**Nothing above has been edited in the design documents themselves.** They are
the design record; this folder is the requirements contract. Where they
disagree, this folder wins.

## 10. The design document index

| # | Document | Subject |
|---|---|---|
| — | [00-README.md](00-README.md) | Navigation hub, key namespace, role table, security summary |
| — | [00-CONSTANTS.md](00-CONSTANTS.md) | **Canonical** constants, timeouts, thresholds |
| 01 | [01-system-overview.md](01-system-overview.md) | Architecture diagrams, component map, data flows, quicbaas integration |
| 02 | [02-network-architecture.md](02-network-architecture.md) | Hierarchical Kademlia, IPv6 addressing, routing, eclipse-attack prevention, SDN/VLAN isolation |
| 03 | [03-security-trust.md](03-security-trust.md) | STRIDE model, TPM trust policy, quantum-resistant crypto, clock sync |
| 04 | [04-cryptographic-protocols.md](04-cryptographic-protocols.md) | FROST, DKG protocol and recovery, wire protocol, key management |
| 05 | [05-certificate-authority.md](05-certificate-authority.md) | Distributed CA pool, threshold issuance, IDevID enrollment, CT logs |
| 06 | [06-consensus-coordination.md](06-consensus-coordination.md) | VRF selection, PBFT, coordinator rotation, partition recovery |
| 07 | [07-currency-transactions.md](07-currency-transactions.md) | UTXO/DAG model, sharding, cross-shard 3PC, slashing |
| 08 | [08-content-distribution.md](08-content-distribution.md) | Block storage, OS images, updates, git, iPXE boot |
| 09 | [09-defense-reputation.md](09-defense-reputation.md) | **Canonical** reputation and penalties |
| 10 | [10-governance-economics.md](10-governance-economics.md) | Voting, upgrades, economics, work credits |
| 11 | [11-operations.md](11-operations.md) | Deployment, monitoring, partition handling, disaster recovery |
| 12 | [12-secure-content-storage.md](12-secure-content-storage.md) | Key Share Partitioning, data classification |
| 13 | [13-service-discovery.md](13-service-discovery.md) | Search, marketplace, escrow |
| 14 | [14-browser-extension.md](14-browser-extension.md) | Chrome/Firefox extension, gateway API |
| 15 | [15-ai-agent-collaboration.md](15-ai-agent-collaboration.md) | Agent identity, chat rooms, workload distribution |
| 16 | [16-ddos-protection.md](16-ddos-protection.md) | Five-layer DDoS defense, PoW, threat intelligence |
| 17 | [17-untrusted-nodes.md](17-untrusted-nodes.md) | Untrusted work assignment, scrutiny levels, penalties |
| 18 | [18-platformd-p2p.md](18-platformd-p2p.md) | P2P mode, ACME `enroll-01`/`endorse-01`, cluster integration |
| 19 | [19-service-contracts.md](19-service-contracts.md) | Contract hierarchy, automation, GPU compute |
| 20 | [20-service-provider-requirements.md](20-service-provider-requirements.md) | Client eligibility, trust requirements |
| 21 | [21-ai-arbitration-system.md](21-ai-arbitration-system.md) | AI arbitrators, hybrid arbitration, bias detection |
| 22 | [22-federation.md](22-federation.md) | Cross-certification, peering, enterprise interoperability |
| 23 | [23-p2p-dns.md](23-p2p-dns.md) | Distributed DNS, naming, custom domains, DNSSEC |
| 24 | [24-quicbaas-schema.md](24-quicbaas-schema.md) | State storage schema, key naming, migrations |
| 25 | [25-kms-frost-lifecycle.md](25-kms-frost-lifecycle.md) | FROST share storage, rotation, backup |
| 26 | [26-organization-identity.md](26-organization-identity.md) | Organization identity model |
| — | [wire-protocol.md](wire-protocol.md) | Protocol buffers, message types, transports |
| — | [ROADMAP.md](ROADMAP.md) | Milestones and phase plan |
| — | `api-reference*.md` (7 files) | **Design-time** protocol sketches — nothing in them is served |

## 11. What has to happen before this folder becomes NORMATIVE

1. An owner decision to build it. New features are the owner's authority alone;
   an agent that finds this folder and starts implementing is out of bounds.
2. The `160-bit` / `32-byte NodeID` contradiction (§9) resolved.
3. The relationship to `pkg/sdn/gateway/p2p` settled: shared libp2p host, or two
   independent stacks. Building either way without deciding produces a
   duplicate.
4. `00-README.md`'s Implementation Status table corrected or deleted.
5. The design's capability set mapped onto `docs/00 §R` rows with owners and
   tiers, so the SDK obligations are known before code exists.

Until then this folder is a design record with a status banner, and the four
sibling files say so.

## 12. Related

- [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/gateway/`](../gateway/) — the libp2p code that actually exists
- [`docs/sdn/ipam/`](../sdn/ipam/) — the DHT IPAM backend that actually exists
- [`docs/cluster/`](../cluster/) — the platform's real, implemented clustering
- [`docs/attestation/`](../attestation/) · [`docs/tpm/`](../tpm/) — the
  attestation the design assumes
