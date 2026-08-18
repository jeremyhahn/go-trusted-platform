# Trusted DHT — Using It

> **Status: PLANNED** · Scope: design only, no implementation · Last verified: 2026-08-18
> There is nothing to use. This page says what exists instead, and where the
> design lives.

---

## You cannot use this feature

The Trusted DHT is a **design**. There is no code for it in this product: no
command, no endpoint, no configuration setting, no daemon mode. Nothing you can
type will join a node to it, because there is nothing to join.

If you are here because a document, a diagram or an AI assistant told you the
platform has a peer-to-peer DHT network — it does not. What it has is described
below.

## What the design is for

The idea is a network that extends the platform's hardware-attested trust across
machines that no single organisation owns. Nodes would prove they are running on
a real TPM before being admitted, earn standing over time through measured
behaviour, and collectively provide storage, content distribution, naming,
certificate issuance and a compute marketplace — with no central operator to
trust or to attack.

The pieces the design covers, in the order someone would meet them:

- **Joining.** A node proves it has a genuine TPM, obtains a device certificate
  from a distributed certificate authority, and joins with zero reputation.
- **Earning standing.** Roles — routing hub, gateway, certificate participant,
  coordinator — become available as reputation and age thresholds are met.
- **Storing and finding things.** Content blocks, OS images, software updates
  and git repositories addressed by hash.
- **Paying for things.** A sharded ledger, service contracts, escrow, and
  arbitration when a contract is disputed.
- **Staying up under attack.** Reputation-driven defense, proof-of-work
  challenges for unproven peers, and shared threat intelligence.
- **Reaching it from outside.** A browser extension talking to gateway nodes.

## What exists today instead

| If you want | Use |
|---|---|
| Nodes to find each other peer-to-peer inside your own fabric | The SDN gateway's libp2p mesh — [`docs/gateway/`](../gateway/). Requires a build with `WITH_P2P=1`. |
| IP addresses allocated without a central allocator | The DHT IPAM backend — [`docs/sdn/ipam/`](../sdn/ipam/). Same build requirement. |
| A real, supported cluster | [`docs/cluster/`](../cluster/). This is the platform's actual clustering and it is implemented. |
| Hardware-rooted node identity and attestation | [`docs/tpm/`](../tpm/) and [`docs/attestation/`](../attestation/). |
| Certificate issuance | [`docs/ca/`](../ca/). |
| A registry for images, with attestation gating | [`docs/registry/`](../registry/). |
| Naming and DNS | [`docs/dns/`](../dns/). |

The two libp2p items share a technology with the design and nothing else. They
are plumbing inside one deployment; the design is a network between many.

## Traps in the design documents

The 26 numbered documents in this folder are worth reading if you want to
understand the intent. Three things in them will mislead you if you take them
literally:

**They say the DHT is "implemented in `pkg/dht/`".** It is not. That package
does not exist.

**They list several packages as "Implemented" that do not exist** —
`pkg/content/`, `pkg/updates/`, `pkg/osimage/`, `pkg/defense/`, `pkg/git/`.
One row is half right: `pkg/boot/` does exist, but it is the platform's local
boot-manager CLI, not a DHT boot server.

**The seven `api-reference*.md` files describe endpoints, ports, gRPC methods
and MCP tools that are not served.** Do not point a client at them. The port
table in particular lists two ports that the platform's web service really does
use for something else entirely, so a request will connect and then fail in a
confusing way.

The full list of corrections is [architecture.md](architecture.md) §9.

## If you want this built

It is not an agent's decision. New features and changes to architecture are the
owner's authority alone. Five things have to be settled first — they are listed
in [architecture.md](architecture.md) §11, and the shortest of them is that the
design contradicts itself about how wide a node identifier is.

## Where to go next

- [architecture.md](architecture.md) — the design, its recorded decisions, and
  the index of all 26 documents
- [engineering.md](engineering.md) — the constants an implementation would have
  to honour, and the six open questions that block one
- [cli.md](cli.md) · [api.md](api.md) — both say "nothing here", with the
  evidence
- [ROADMAP.md](ROADMAP.md) — the milestone plan, status *"Design Complete -
  Implementation Pending"*
