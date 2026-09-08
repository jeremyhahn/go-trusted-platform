# Remote-Access VPN — CLI

> **Status: DESIGN — not implemented.** · Last verified: 2026-09-08
> No verb below exists. Each is a requirement for the implementing PR and needs a
> `CommandDefinition` in the integration suite when it lands.
> Feature folder: [architecture.md](architecture.md) · [engineering.md](engineering.md) ·
> cli (this file) · [api.md](api.md) · [user.md](user.md).

`platformctl` is both the operator CLI and the **client agent**: the same binary
that enrolls a device, produces its TPM quote and posture report, presents the
person's FIDO2/PIV factor, and brings up the data plane. Transport selection
follows the platform-wide flags (`--endpoint`, `--transport rest|grpc|quic|mcp|unix`).

## `platformctl sdn gateway vpn` — operator verbs *(planned)*

| Verb | Purpose | Flags | Exit |
|---|---|---|---|
| `status` | Active leases per data plane, last refusal, pool utilisation | `--gateway <id>`, `-o json\|table` | 0; 1 on transport error |
| `lease list` | List leases | `--tenant`, `--device`, `--expired`, `-o` | 0 |
| `lease get <lease-id>` | One lease with its verdict, posture summary and renewals | `-o` | 0; 2 not found |
| `lease revoke <lease-id>` | Revoke now | `--reason <text>` (required) | 0; 2 not found |
| `posture-policy get\|set\|delete <name>` | Tenant posture policy (Rego) CRUD | `--tenant`, `--file <rego>` (set) | 0; 3 invalid policy |
| `keys rotate` | Rotate the WireGuard server key / MASQUE identity through the KMS | `--data-plane wireguard\|masque` | 0 |

Examples:

```sh
platformctl sdn gateway vpn status --gateway gw-01 -o table
platformctl sdn gateway vpn lease revoke 01J9…Q7 --reason "laptop reported lost"
platformctl sdn gateway vpn posture-policy set default --tenant acme --file vpn_posture.rego
```

## `platformctl vpn` — client-agent verbs *(planned)*

| Verb | Purpose | Flags | Exit |
|---|---|---|---|
| `connect` | Run the admission (identity → quote → posture → factor → lease) and bring the data plane up | `--gateway <host:port>` (required), `--data-plane wireguard\|masque` (default: gateway's preference; `wireguard` absent in FIPS builds), `--factor fido2\|piv`, `--zones <list>`, `--foreground` | 0; 4 refused (reason class printed); 5 posture violation (rules listed) |
| `disconnect` | Revoke the lease and tear the data plane down | — | 0 |
| `status` | Lease id, address, expiry, next re-attestation | `-o` | 0; 6 not connected |
| `posture` | Print the posture report the agent would send | `-o json` | 0 |
| `renew` | Force a renewal now | — | 0; 4/5 as above |

Examples:

```sh
platformctl vpn connect --gateway gw.letstrust.com:4433 --factor fido2
platformctl vpn posture -o json
platformctl vpn status
```

Prerequisites for the client verbs: the machine is an enrolled device with an
IDevID (`platformctl device …`), the person has a FIDO2 or PIV factor enrolled
(`platformctl fido2 …`, `platformctl piv …`), and the agent runs with the
privilege to configure a network interface for the chosen data plane.

None of these verbs works without a server (`--local`): the lease is a
control-plane object.
