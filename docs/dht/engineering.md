# Trusted DHT — Engineering Contract

> **Status: NORMATIVE** · Scope: the planned `dht` feature (docs/SPEC.md:53); design only, no code exists · Last verified: 2026-10-22
> Conflicts with this document are defects. Fix them here first.
> Design and boundaries: [architecture.md](architecture.md).

---

## 1. There is nothing to contract against yet

**No Trusted DHT code exists in this repository.** There are no exported types,
no constructors, no interfaces, no error values, no configuration keys, no
persistence layout and no tests — because there is no package.

Verified 2026-08-18: `pkg/dht/` is absent, as are `pkg/dht/core/`,
`pkg/dht/transport/`, `pkg/dht/proto/`, `pkg/dht/discovery/`, `pkg/dht/gateway/`,
`pkg/dht/agent/`, `pkg/dht/contract/`, `pkg/dht/requirements/`,
`pkg/dht/arbitration/`, `pkg/dht/dns/`, `pkg/dht/federation/`,
`pkg/defense/ddos/` and `pkg/defense/work/`.

An engineering contract names real identifiers. This document therefore records
**what the design fixes** and **what the design leaves open**, so that when the
work is authorised the first PR has something to be reviewed against — and so
that nobody mistakes a design constant for a Go constant that already exists.

**Do not create any of the identifiers named below to make this document true.**
They are design intent. They become a contract when the owner approves the work
and this banner changes to NORMATIVE.

## 2. Existing code that must not be confused with this

| Package | Build tag | What it is |
|---|---|---|
| `pkg/sdn/gateway/p2p` | `platform_p2p` | `Node` — a libp2p host with Kademlia routing for SDN gateway peer discovery. Constants `DefaultListenPort = 4001`, `DefaultBootstrapTimeout = 30s`, `DefaultConnManagerLowWater = 100`, `DefaultConnManagerHighWater = 400`, `DefaultRoutingTableRefreshPeriod = 10m`, `MaxBootstrapPeers = 20`. |
| `pkg/sdn/ipam/backends/dht.go` | `platform_p2p` | `DHTBackend`, an `ipam.Allocator` over `go-libp2p-kad-dht`. Key prefixes `/ipam/pool/`, `/ipam/alloc/`, `/ipam/device/`; `claimTimeout = 5s`, `claimPropagationDelay = 100ms`, `maxAllocationRetries = 50`, `dhtOperationTimeout = 10s`. Constructor `NewDHTBackend(node *p2p.Node, opts ...ipam.AllocatorOption)`; error `ErrDHTBackendInit`. |

These are real, they compile, they are tested, and they belong to
[`docs/gateway/`](../gateway/) and [`docs/sdn/ipam/`](../sdn/ipam/). Changing
them is not progress on this feature.

## 3. What the design fixes — the numbers an implementation must honour

From `00-CONSTANTS.md`, which the design declares the single source of truth and
which states that these are to be **compile-time constants, not configuration**.

### Kademlia and storage

| Design constant | Value |
|---|---|
| Bucket size `k` | 20 |
| Lookup parallelism `alpha` | 3 |
| Replication factor | 3 |
| Record TTL | 24 h |
| Maximum value size | 1 MB |
| Node ID | SHA-256 of the public key — **but see §6** |

Required primitives per `ROADMAP.md` §1.1: XOR distance, k-bucket split, LRU
eviction with liveness check, **concurrent-safe and lock-free preferred**,
`PING`/`PONG`, `FIND_NODE`, `FIND_VALUE`, `STORE`.

### Consensus and coordination

| Design constant | Value |
|---|---|
| `HeartbeatInterval` | 2 s |
| `MissedHeartbeatThreshold` | 4 |
| `FailureDetectionTimeout` | 8 s |
| `CoordinatorFailoverTimeout` | 10 s |
| `ElectionTimeout` | 5 s |
| `FencingTokenQuorum` | 15 / 21 |
| `EpochTransitionGrace` | 30 s |
| `PBFTBaseTimeout` | 800 ms |
| `PBFTMaxTimeout` | 10 s |
| `ViewChangeTimeout` | 2 s |
| `MaxConsecutiveViewChanges` | 7 |
| `ViewChangeBackoffBase` / `Multiplier` | 500 ms / 2 |
| `OperationalLockTTL` / `LockExtensionInterval` / `MaxLockTTL` | 60 s / 30 s / 120 s |
| `RecoveryLockTTL` | 5 min |
| `VRFCommitWindow` / `VRFRevealWindow` | 30 s / 30 s |
| `VRFMinRevealDelay` | 2 blocks |
| `VRFBlindingFactorSize` | 32 bytes |

### Cryptography and DKG

| Design constant | Value |
|---|---|
| `DKGDuration` (standard) | 10 min |
| `DKGSlowPath` / `DKGFastPath` | 13 min / 5 min |
| `DKGCheckpointInterval` | 30 s |
| FROST pools / threshold | 4 / t = 33% |
| CA pool size | 0.1% of network, min 100, max 10M |
| CA threshold / rotation | 33% / 1 hour |

### Security

| Design constant | Value |
|---|---|
| TPM version | 2.0, required |
| Quote freshness | ±100 ms |
| `NonceMaxCacheSize` | 100,000 per node |
| `NonceTTL` / `NonceCleanupInterval` | 30 s / 5 s |
| `MinReputation` / `MaxReputation` / `InitialReputation` | 0.0 / 1.0 / **0.0** |

### Reputation thresholds (canonical, `09-defense-reputation.md`)

Leaf 0.0 · Hub 0.80 · Gateway 0.85 · AI Arbitrator 0.85 · CA Participant 0.90 ·
Coordinator 0.95, with minimum-age requirements of 0 / 110 / 175 / — / 120 / 185
days.

## 4. Dependency obligations

The design's own dependency table (`ROADMAP.md`), reconciled with this
repository's SDK boundary:

| Capability | Owner | How it must be reached |
|---|---|---|
| Threshold signatures | go-frost | through `go-quicbaas/sdk/go` |
| Distributed key generation | go-frostdkg | through `go-quicbaas/sdk/go` |
| Hardware RNG, TPM 2.0, CA / ACME | go-xkms | through `go-quicbaas/sdk/go` |
| Persistent state, IAM, KMS, secrets, object storage, vector search | go-quicbaas | `go-quicbaas/sdk/go` |

**This repository imports `go-quicbaas/sdk/go` only.** A DHT implementation that
imports go-xkms, go-qrdb, go-quicraft, go-truststrap or go-objstore directly is
a layer violation and `pkg/arch/layerguard_test.go` fails it. If a needed
capability is missing from the SDK, it is added to the owning project first —
never implemented locally.

`24-quicbaas-schema.md` already specifies DHT state as a quicbaas schema, with
key naming, indexes and migrations. **The DHT owns no storage engine.**

## 5. Persistence — as designed

Key namespace from `00-README.md`, reproduced in [architecture.md](architecture.md)
§6. Schema, indexes and migration scripts are `24-quicbaas-schema.md`. FROST
share storage, refresh and backup are `25-kms-frost-lifecycle.md`.

No schema exists in the repository, so there is no compatibility or migration
rule to state yet. The first implementation PR must establish one.

## 6. Open questions the design has not settled

These block an implementation and are recorded so the first agent does not
decide them silently. **Ambiguity in a feature doc is resolved by the owner.**

1. **Node ID width.** `ROADMAP.md` says *"160-bit node IDs"* in its capability
   summary and *"NodeID type (32-byte SHA256 of public key)"* — 256 bits — in
   §1.1. These cannot both be right, and the routing table geometry depends on
   the answer.
2. **Relationship to `pkg/sdn/gateway/p2p`.** One libp2p host shared between the
   SDN mesh and the Trusted DHT, or two independent stacks? Building either way
   without deciding produces a duplicate that is expensive to unwind.
3. **libp2p or a bespoke Kademlia.** `ROADMAP.md` §1.1 specifies building the
   routing table, k-buckets and the Kademlia RPCs from scratch; the code already
   in the tree uses `go-libp2p-kad-dht`. The design does not say which wins.
4. **Which capability rows this feature owns** in `docs/00 §R`, and at what
   tier. Without that, the SDK re-export obligations are unknown.
5. **Whether the currency layer is in scope at all** for a first
   implementation, or whether DHT core, discovery and content distribution ship
   independently of it.
6. **Error vocabulary.** The design specifies no error types. The repository's
   convention is typed errors, never `fmt.Errorf`, and the first PR sets the
   vocabulary for everything after it.

## 7. Error semantics, fail-closed paths, observability

**Not specified.** The design documents describe protocol behaviour and penalty
matrices but define no Go error values, no transport error mapping, no metric
names beyond a handful of illustrative Prometheus counters in
`18-platformd-p2p.md` (`platformd_p2p_leader_changes_total` and siblings, which
are examples in a code block, not registered metrics), and no audit records.

Three fail-closed properties the design *does* state, which an implementation
must preserve:

- **Unattested nodes get a bounded capability set**, never a privileged role
  (`17-untrusted-nodes.md`). The default for an unclassified node is Untrusted.
- **A quote outside the ±100 ms freshness window is not evidence.**
- **A violation requires TPM-attested proof.** An unproven accusation must not
  move reputation.

## 8. Test strategy

None exists. When the work is authorised, the repository's standing rules apply:
TDD, 90%+ coverage goal, at least two tests per function (happy path and error
path), and — for anything exposed on a transport — the multi-protocol parity
pattern already used by `test/integration/tpm/` and its siblings.

## 9. Related

- [architecture.md](architecture.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [ROADMAP.md](ROADMAP.md) — the milestone breakdown this contract would be built against
- [00-CONSTANTS.md](00-CONSTANTS.md) — the canonical constant set
- [`docs/gateway/`](../gateway/) · [`docs/sdn/ipam/`](../sdn/ipam/) — the real libp2p code
