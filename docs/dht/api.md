# Trusted DHT — API

> **Status: PLANNED** · Scope: design only, no implementation · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> One row per designed capability across all six transports. Every cell is
> `MISSING — not implemented`, because the feature has no code.

---

## 1. There is no API. On any transport.

Verified against the tree on 2026-08-18:

| Check | Result |
|---|---|
| `dht` / `DHT` anywhere under `pkg/api/` (gRPC, QUIC, MCP, REST handlers) | **no matches** |
| `dht` / `DHT` anywhere under `sdk/` | **no matches** |
| A `DHTService` in any `.proto` | **none** |
| A DHT opcode in `sdk/go/wire/quicwire/protocol.go` | **none** |
| A DHT tool in `pkg/api/mcp/` | **none** |
| A `/api/v1/dht` route | **none** |
| A DHT field on `ServiceRegistry` (`sdk/go/transport/embedded/adapter.go`) | **none** — the registry has 25 fields and none is DHT |

The only Kademlia code in the repository is the SDN gateway libp2p host and the
IPAM DHT allocator, both behind the `platform_p2p` build tag, and neither
exposes any API of its own
([architecture.md](architecture.md) §2).

## 2. Why the cells do not say `MISSING — docs/13 G7`

`conventions/feature-docs.md` §5 asks for missing transports to be written as
`MISSING — docs/13 G<n>`. `docs/13` tracks **SDK exposure gaps** — capabilities
that exist in the stack and lack a route on some transport, each with an owner.

Nothing here is an exposure gap. There is no capability behind the missing
route. Recording these as G7 debts would put 60-odd fictitious entries into a
register that exists to track real, fixable omissions, and would make the
register useless. The cells therefore read `MISSING — not implemented`, and the
deviation is stated here rather than left for a reviewer to notice.

## 3. Designed capabilities on the six transports

Capability names are taken from the design's own service categories
(`api-reference.md`) and its key namespace (`00-README.md`). **They are design
intent. None is callable.**

| Designed capability | Embedded | Unix | REST | gRPC | QUIC | MCP |
|---|---|---|---|---|---|---|
| Node info | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Routing-table inspection | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Key-value `STORE` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Key-value `FIND_VALUE` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Peer `FIND_NODE` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Peer `PING` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Service advertise | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Service search / browse | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Content block put / get | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Manifest resolve (OS image, git, update) | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Wallet balance | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Transaction submit | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Escrow / payment channel | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Contract create / settle | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Arbitration request | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Agent register | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Chat room join / message | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Task / workload distribution | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Certificate enrollment (`enroll-01`) | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Certificate status / revocation | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Reputation query | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Violation report / evidence submit | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Threat intelligence share | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| PoW challenge / solution | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| P2P DNS resolve | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| P2P DNS record publish | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Federation cross-certify / peering | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Governance vote | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |
| Browser-extension gateway session | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` | `MISSING — not implemented` |

There are no request or response schemas, no status-code mapping, no `scp`
permissions and no pagination rules to document, because there are no
operations.

## 4. The `api-reference*.md` files in this folder are design sketches

Seven files in this folder read like API references and are not:

| File | Claims |
|---|---|
| [api-reference.md](api-reference.md) | A protocol/port table and five service categories |
| [api-reference-rest.md](api-reference-rest.md) | HTTP endpoints |
| [api-reference-grpc.md](api-reference-grpc.md) | Protocol-buffer service definitions |
| [api-reference-quic.md](api-reference-quic.md) | QUIC transport usage |
| [api-reference-mcp.md](api-reference-mcp.md) | MCP tools for AI agents |
| [api-reference-unix.md](api-reference-unix.md) | Unix-socket IPC |
| [api-reference-gateway.md](api-reference-gateway.md) | WebSocket gateway for the browser extension |

**Nothing described in them is served.** Two specific traps:

- `api-reference.md` states *"All protocols provide feature parity."* There is
  no parity to have; there are no protocols.
- Its port table lists REST `8443`, gRPC `9443`, QUIC `9444`, MCP `9445` and a
  Unix socket at `/run/platformd.sock`. `8443` and `9443` are the platform web
  service's real TLS ports and carry no DHT routes; `9444` and `9445` appear
  nowhere in the shipped configuration. Pointing a client at any of them will
  not reach a DHT.

The wire format sketch is [wire-protocol.md](wire-protocol.md); it defines no
generated code in this repository.

## 5. What an implementation would have to satisfy

For reference when the work is authorised, not as a present obligation:

- The six transports are the six in `conventions/api-conventions.md`, declared
  as `ProtocolEmbedded`, `ProtocolUnix`, `ProtocolGRPC`, `ProtocolREST`,
  `ProtocolQUIC`, `ProtocolMCP` in `sdk/go/protocol.go`. Unix is gRPC over a
  Unix domain socket.
- Embedded reach is bounded by `ServiceRegistry`
  (`sdk/go/transport/embedded/adapter.go`); a new service needs a field there or
  it has no embedded route.
- QUIC would need a category opcode, since the sub-opcode space of the existing
  categories is spoken for. The category rule and the allocated bytes are in
  [`docs/daemon/api.md`](../daemon/api.md) §4 — **`0x99` is the physical TPM and
  is not available.**
- Tier 1 capabilities must appear on all six transports.
- Every operation needs an `scp` permission and an entry in the gRPC and MCP
  authorization catalogs. Both catalogs are currently default-allow, which is
  itself an open owner question ([`docs/daemon/api.md`](../daemon/api.md) §5) —
  a new service should not add to the untracked set.

## 6. Related

- [architecture.md](architecture.md) §1 and §9 — the evidence, and the design
  documents' incorrect claims about this tree
- [engineering.md](engineering.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — the real transport model
