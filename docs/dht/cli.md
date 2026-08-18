# Trusted DHT — CLI

> **Status: PLANNED** · Scope: design only, no implementation · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.

---

## 1. There is no CLI surface. The feature is not implemented.

**No `platformctl` verb reaches the Trusted DHT, because the Trusted DHT does
not exist.** Verified against `pkg/cli/commands/` and
`pkg/cli/commands/root.go` on 2026-08-18: there is no `dht` command group, no
`p2p` command group, and no DHT verb inside any other group.

That is the whole of this document's factual content. Everything below exists to
stop the next reader from concluding otherwise from the design documents.

## 2. What the design documents show, and why it is not usable

`18-platformd-p2p.md` contains this in a health-check section:

```
platformctl p2p status
```

with sample output listing mode, trust level, connected peers, DHT records,
IDevID expiry and last quote. **`platformctl p2p` does not exist.** No `p2p`
group is registered in `pkg/cli/commands/root.go`.

The same document shows a top-level `p2p:` configuration block with
`bootstrap_peers`, `listen_addresses`, `enrollment` and a nested `dht:` section.
**No such configuration key is parsed.** The only `p2p` keys in the code are
unrelated:

| Real key | Type | Meaning |
|---|---|---|
| `sdn.transit.p2p` | string | An IPv4 prefix (default `172.16.0.0/24`) from which /31 point-to-point transit link addresses are carved |
| the gateway's `p2p` | bool | `GatewayConfig`'s libp2p toggle, behind the `platform_p2p` build tag |

Neither has anything to do with the Trusted DHT.

## 3. Adjacent CLI that does exist

If you arrived here looking for peer-to-peer behaviour that works today:

| What you want | Where it is |
|---|---|
| SDN gateway libp2p meshing and NAT traversal | `platformctl sdn gateway` — [`docs/gateway/cli.md`](../gateway/cli.md) |
| DHT-backed IP address allocation | `platformctl sdn ipam` — [`docs/sdn/ipam/`](../sdn/ipam/) |
| Real, implemented clustering | `platformctl cluster` — [`docs/cluster/cli.md`](../cluster/cli.md) |
| Node identity and attestation | `platformctl tpm`, `platformctl container attest` — [`docs/tpm/cli.md`](../tpm/cli.md), [`docs/attestation/cli.md`](../attestation/cli.md) |

Both libp2p paths require a build with `WITH_P2P=1` (`platform_p2p` build tag);
they are absent from a default binary.

## 4. When this file becomes real

When the owner authorises the work, this file must be written against
`pkg/cli/commands/dht/` (or whatever the group is actually called) with one
section per verb: purpose, positional arguments, **every** flag with type,
default and whether required, exit codes, output formats, and at least one
runnable example per verb using placeholder hosts. Any verb inside the locked
CLI surface must follow `docs/11-cli-surface` rather than inventing a local
dialect, and every verb needs a matching entry in the integration parity suite.

Until then this file exists and says what it says: **no CLI surface.**

## 5. Related

- [architecture.md](architecture.md) §1 — the full evidence that nothing is implemented
- [engineering.md](engineering.md) · [api.md](api.md) · [user.md](user.md)
