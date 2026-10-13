# Remote-Access VPN — User Guide

> **Status: PARTIAL — operators can manage enrolment, posture policies and session status today, from the CLI (#584 PR 3) and the web console (#584 PR 4); connecting a machine is planned.** · Last verified: 2026-10-13
> "Operator tasks" below works now. "First connection" and the client tasks
> describe `platformctl vpn connect`, which has not shipped: until it does, the
> interim administrative VPN on the site firewall remains the way in.
> Feature folder: [architecture.md](architecture.md) · [engineering.md](engineering.md) ·
> [cli.md](cli.md) · [api.md](api.md) · user (this file).

## What it is

A remote-access VPN that lets a machine in only when the machine can prove what
it is (its TPM identity), what state it booted into (a fresh attestation
against the measurements the platform enrolled), that it meets the posture
policy (Secure Boot on, disk encrypted, integrity measurement running), and
that the person at the keyboard is present (a security key or smart card).
Access is a **lease** that expires unless the machine keeps proving all of
that; a lost laptop's lease dies on its own.

Two ways to carry the traffic: **WireGuard** (fast, kernel-native, available on
non-FIPS builds) and **MASQUE** (an HTTP/3 tunnel using the same TLS the
platform uses everywhere; the only option on FIPS builds).

## Prerequisites

- Your machine is an enrolled platform device with a TPM 2.0 and an issued
  device identity (`platformctl device …`).
- You have a FIDO2 security key or a PIV smart card enrolled as a factor
  (`platformctl fido2 …` or `platformctl piv …`). A one-time-password app is
  not supported.
- Secure Boot is on, the root disk is encrypted, and the platform's integrity
  measurement is enabled — or your tenant's posture policy says otherwise.
- The gateway's remote-access service is enabled by an operator and an address
  pool is assigned to your tenant.
- An operator has enrolled your device as a VPN peer of your tenant
  (`platformctl vpn peer enrol`).

## First connection *(planned)*

```sh
platformctl vpn connect --gateway gw.letstrust.com:4433 --factor fido2
```

You will be asked to touch the key (or enter the card PIN). On success the
command prints the lease: your address, the zones you may reach and when the
lease expires. The agent keeps the lease alive by re-attesting in the
background; you do nothing.

## Operator tasks

These work today, over any transport `platformctl` is configured for. Each needs
the scope listed in [cli.md](cli.md).

The web console's **Networking → VPN** page does the same without the CLI: it
shows each gateway's status and live sessions (with any refused peer or
unloadable policy), lists the enrolled peers with a **Revoke** button, and
lists the posture policies, which open in an editor (**View / Edit**, or
**New Policy**). A module that does not compile is refused and the editor
stays open. Enrolling a peer and deleting a policy remain CLI tasks.

- **Let a machine in**: `platformctl vpn peer enrol <device-id> --tenant <t>`.
  Add `--zone <name>` (repeatable) to narrow the zones it may reach; without it
  the peer may reach every zone the gateway allows. A gateway admits only
  enrolled devices, and picks up the change on its next desired-config pull.
- **Who may connect**: `platformctl vpn peer list --tenant <t>`.
- **Cut a machine off**: `platformctl vpn peer revoke <device-id> --tenant <t>`.
- **Who is connected**: `platformctl vpn status` lists, per gateway, the
  admissions, refusals, the last refusal reason and every live lease.
  `--gateway <id>` narrows it to one gateway. The `REJECTED PEERS` column
  names any peer a gateway refused to enrol, with the reason — usually a
  `--zone` that gateway does not serve. Only that peer is refused; re-enrol
  it with zones the gateway allows.
- **Change what is required**: write a Rego module in package `vpn.posture`
  and store it with
  `platformctl vpn posture-policy set <name> --tenant <t> --file <module.rego>`.
  A module that does not compile is refused at once; `status` lists a tenant
  whose policy a gateway could not load.
- **Review policies**: `platformctl vpn posture-policy list|get|delete`.

## Client tasks *(planned)*

- **Check the connection**: `platformctl vpn lease`.
- **See what the gateway will judge**: `platformctl vpn posture -o json` shows
  the exact report before you connect — the fastest way to see why a posture
  rule will fail.
- **Disconnect**: `platformctl vpn disconnect`.

## Troubleshooting

| Symptom | Meaning | What to do |
|---|---|---|
| `refused: untrusted issuer` | Your device certificate does not chain to the platform's anchors | Re-enroll the device; check the gateway's trust bundle |
| `refused: attestation failed` | Your boot measurements no longer match the enrolled ones | A firmware or kernel update changed them; an operator refreshes the device's baseline after confirming the change is legitimate |
| `refused: posture violation: secure_boot` (or `fde`, `ima`) | The named rule failed | Fix the setting on the machine; `platformctl vpn posture` shows the current facts |
| `refused: person factor required/invalid` | No key touch, wrong key, or a factor not enrolled for you | Enroll or use the right factor |
| `unavailable: posture policy` | The tenant's policy could not be loaded — this is a refusal, not a bypass | Operator: fix or restore the policy |
| `unavailable: pool exhausted` | No free addresses in the tenant pool | Operator: grow the pool or revoke stale leases |
| `refused: peer not enrolled` | The device passed identity checks but no operator enrolled it for the tenant | Operator: `platformctl vpn peer enrol` |
| Every `platformctl vpn` operator verb says the service is unavailable | This node runs no VPN control plane; it refuses every call rather than answering with empty lists | Point the CLI at the control-plane node |
| Connected, but a service is unreachable | The zone is not in your lease | Ask for the zone (`--zones`) if your role allows it; otherwise it is by design |
| `data plane wireguard not available` | FIPS build | Use `--data-plane masque` |

## What it does not do

It is not a site-to-site tunnel between gateways, it does not decide what you
may do once inside (roles and the zone matrix do), and it does not replace the
interim VPN until the operators have run both side by side and cut over.
