# Remote-Access VPN — CLI

> **Status: PARTIAL — the operator verbs ship (#584 PR 3); the client-agent verbs are planned.** · Last verified: 2026-10-13
> `platformctl vpn peer|status|posture-policy` exist (`pkg/cli/commands/vpn`)
> and are exercised over every transport by `test/integration/vpn/`. The
> client-agent verbs below them are still requirements.
> Feature folder: [architecture.md](architecture.md) · [engineering.md](engineering.md) ·
> cli (this file) · [api.md](api.md) · [user.md](user.md).

`platformctl` is both the operator CLI and the **client agent**: the same binary
that enrolls a device, produces its TPM quote and posture report, presents the
person's FIDO2/PIV factor, and brings up the data plane. Transport selection
follows the platform-wide context and flags (`--config`, `--context`,
`--output`).

## `platformctl vpn` — operator verbs

Each verb is one `VPNService` RPC ([api.md](api.md) §1) and needs its scope.

| Verb | RPC | Flags | Scope |
|---|---|---|---|
| `peer enrol <device-id>` | `EnrolPeer` | `--tenant` (required), `--zone <name>` (repeatable; default every allowed zone) | `vpn:write` |
| `peer list` | `ListPeers` | `--tenant` (default every tenant) | `vpn:read` |
| `peer revoke <device-id>` | `RevokePeer` | `--tenant` (required) | `vpn:write` |
| `status` | `GetStatus` | `--gateway <id>` (default every gateway) | `vpn:read` |
| `posture-policy list` | `ListPosturePolicies` | `--tenant` (default every tenant) | `vpn:admin` |
| `posture-policy get <name>` | `GetPosturePolicy` | `--tenant` (required) | `vpn:admin` |
| `posture-policy set <name>` | `SetPosturePolicy` | `--tenant` (required), `--file <rego>` (required; package `vpn.posture`) | `vpn:admin` |
| `posture-policy delete <name>` | `DeletePosturePolicy` | `--tenant` (required) | `vpn:admin` |

The default `--output table` prints one table per verb. `status` has a
`REJECTED PEERS` column naming each peer the gateway refused from its
enrolment set, as `tenant/device: reason`. `posture-policy get` and `set` show
the policy's name and update time; the Rego module is printed only with
`--output yaml|json`, which print the API messages ([api.md](api.md) §2).
`revoke` and `delete` print what they removed. Every verb exits 0 on success and non-zero
with the service's error on failure: an unknown peer or policy, a module that
does not compile, or a node without a VPN control plane (which refuses every
verb rather than printing an empty list).

`peer enrol` on an enrolled device replaces its zones and keeps its first
enrolment time. Enrolment and policy changes reach the gateways on their next
desired-config pull.

Examples:

```sh
platformctl vpn peer enrol laptop-1 --tenant acme --zone management
platformctl vpn peer list --tenant acme --output json
platformctl vpn posture-policy set corp --tenant acme --file vpn_posture.rego
platformctl vpn status --gateway gw-01
platformctl vpn peer revoke laptop-1 --tenant acme
```

## `platformctl vpn` — client-agent verbs *(planned)*

| Verb | Purpose | Flags | Exit |
|---|---|---|---|
| `connect` | Run the admission (identity → quote → posture → factor → lease) and bring the data plane up | `--gateway <host:port>` (required), `--data-plane wireguard\|masque` (default: gateway's preference; `wireguard` absent in FIPS builds), `--factor fido2\|piv`, `--zones <list>`, `--foreground` | 0; 4 refused (reason class printed); 5 posture violation (rules listed) |
| `disconnect` | Revoke the lease and tear the data plane down | — | 0 |
| `posture` | Print the posture report the agent would send | `-o json` | 0 |
| `renew` | Force a renewal now | — | 0; 4/5 as above |
| `lease` | Lease id, address, expiry, next re-attestation | `-o` | 0; 6 not connected |

The client's own lease view is `lease`, because `status` is the operator verb
above.

Examples:

```sh
platformctl vpn connect --gateway gw.letstrust.com:4433 --factor fido2
platformctl vpn posture -o json
platformctl vpn lease
```

Prerequisites for the client verbs: the machine is an enrolled device with an
IDevID (`platformctl device …`), the device is enrolled as a VPN peer
(`platformctl vpn peer enrol`), the person has a FIDO2 or PIV factor enrolled
(`platformctl fido2 …`, `platformctl piv …`), and the agent runs with the
privilege to configure a network interface for the chosen data plane.

None of these verbs works without a server (`--local`): the enrolment set and
the lease are control-plane objects.
