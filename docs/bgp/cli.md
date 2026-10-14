# BGP Speaker — CLI

> **Status: NORMATIVE** · Scope: `pkg/sdn/bgp/` and the gatewayd services that run it · Last verified: 2026-10-14
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

The BGP verbs live under `platformctl sdn gateway bgp`
(`pkg/cli/commands/sdn/gateway.go:123`; its long help, "Manage BGP for EVPN
and transit routing", is at line 125). They call the `platformd` gateway service over whichever transport
the CLI is using: `runBGPAnnounce` builds its client from
`base.Client().Gateway()` (`gateway.go:293`). The global connection flags are
in [the daemon API reference](../daemon/api.md).

> **On `platformd` these verbs reach no speaker.** `platformd` runs no BGP
> speaker, so every verb returns "BGP speaker not configured on this node" after its
> arguments are validated ([api.md §2](api.md#2-behaviour-on-main)).
> **Planned (#65):** backing them with the gateway's transit speaker. To see a
> gateway's real BGP state today, use `gateway snapshot` (below).

## 1. `platformctl sdn gateway bgp`

| Verb | Line | What it does | Flags |
|---|---|---|---|
| `status` | 132 (`runBGPStatus` 145) | Speaker status | none |
| `peers` | 151 (`runBGPPeers` 159) | List BGP peers | none |
| `announce` | 165 (`runBGPAnnounce` 173) | Announce a prefix | `--prefix` (required, 176/178), `--next-hop` (optional, 177) |
| `withdraw` | 182 (`runBGPWithdraw` 189) | Withdraw a prefix | `--prefix` (required, 192/193) |
| `routes` | 197 (`runBGPRoutes` 204) | List announced prefixes | none |

```bash
platformctl sdn gateway bgp status
platformctl sdn gateway bgp peers
platformctl sdn gateway bgp announce --prefix 203.0.113.0/24 --next-hop 198.51.100.1
platformctl sdn gateway bgp withdraw --prefix 203.0.113.0/24
platformctl sdn gateway bgp routes
```

`withdraw` works on every transport. Over REST the SDK sends the prefix as
the `prefix` query parameter, which is where the handler reads it
([api.md §1](api.md#1-the-six-transports)).

## 2. `platformctl sdn gateway snapshot`

`snapshot` (`pkg/cli/commands/sdn/gateway_snapshot.go:31`, `Use` at 36) reads a
gateway's live state. Its BGP section (described at `gateway_snapshot.go:44`)
holds the local ASN, the router ID, and each transit peer's state and received
prefixes ([engineering.md §9](engineering.md#9-observability)).

| Flag | Line | Meaning |
|---|---|---|
| `--gateway-id` | 66 | Read the report the control plane holds for that gateway. Without it, the node's own gateway answers |
| `--all` | 67 | List every gateway that has reported |

`--all` together with `--gateway-id` is refused with `ErrSnapshotArguments`
(`gateway_snapshot.go:73-74`).

The snapshot covers the transit speaker only. The overlay EVPN speaker's
sessions are not in it.

The full `sdn gateway` command tree is in [gateway CLI](../gateway/cli.md).
