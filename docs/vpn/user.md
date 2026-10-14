# Remote-Access VPN — User Guide

> **Status: PARTIAL — operators can manage enrolment, posture policies and session status today, from the CLI (#584 PR 3) and the web console (#584 PR 4); the client verbs, both tunnels and the gateway's admission listener exist, but a machine cannot connect yet.** · Last verified: 2026-10-14
> "Operator tasks" below works now, and so does `platformctl vpn posture`.
> `platformctl vpn connect` (with `--foreground` to keep the lease renewed),
> `renew`, `lease` and `disconnect` exist, present the machine's TPM identity
> and bring the WireGuard or MASQUE tunnel up, but `connect` cannot finish
> until the client's security key and smart card support lands. The gateway
> end it connects to, the admission listener, exists (#557), but `gatewayd`
> does not open it on a deployed gateway yet. Until both land the interim
> administrative VPN on the site firewall remains the way in.
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
platform uses everywhere; the only option on FIPS builds). The gateway says
which it offers; `--data-plane wireguard|masque` asks for one.

A WireGuard tunnel (`vpn-wg0`) stays up after `connect` returns. A MASQUE
tunnel (`vpn-masque0`) lives inside the `connect` command, so it needs
`--foreground` and comes down when that command ends; without `--foreground`,
`connect` never picks MASQUE, and `--data-plane masque` alone is refused.
Bringing a tunnel up needs root.

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

## First connection

```sh
platformctl vpn connect --gateway gw.letstrust.com:4433 --tenant acme --device-id laptop-1 --factor fido2
```

`--gateway` is the gateway's admission listener (`management_vpn.listener`,
port 4433 by default). It accepts only a connection presenting your device's
certificate; a machine without one is turned away before anything is asked of
it. `--tenant` and `--device-id` are the tenant and id your device was
enrolled under (`platformctl vpn peer enrol <device-id> --tenant <t>`); both
are required.

You will be asked to touch the key (or enter the card PIN). On success the
command prints the lease: your address, the zones you may reach and when the
lease expires. Add `--ca-file <pem>` when the gateway's certificate does not
chain to the machine's system roots.

The exit code tells a script what happened: 0 connected, 4 refused (the
reason is printed), 5 a posture rule failed (the rules are listed), 1 anything
else.

Add `--foreground` to keep the lease alive: the command stays running and,
each time the lease is due for renewal, proves the machine's state again with
a fresh attestation and posture report. If the machine stops passing (a
posture rule fails, the boot measurements change), the tunnel comes down and
the command exits with the refusal's code. Ctrl-C disconnects. Without
`--foreground` the lease lasts until it expires; `platformctl vpn renew`
renews it by hand.

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

## Client tasks

- **Check the connection**: `platformctl vpn lease` (exit 6 when not
  connected). It reads the machine's own record and contacts no gateway.
- **Renew now**: `platformctl vpn renew`. Exit 0 renewed, 4 refused, 5 a
  posture rule failed, 6 not connected. A refusal that ends the lease brings
  the tunnel down; `refused: renewal not open` only means it is too early and
  the lease is kept.
- **Disconnect**: `platformctl vpn disconnect`. The local lease is dropped and
  the tunnel brought down even if the gateway cannot be reached; the gateway
  then lets the lease expire. A MASQUE tunnel belongs to the
  `connect --foreground` command: Ctrl-C there brings it down.
- **See what the gateway will judge**: `platformctl vpn posture -o json`
  shows the exact report before you connect — the fastest way to see why a
  posture rule will fail. It contacts no gateway.

## Troubleshooting

| Symptom | Meaning | What to do |
|---|---|---|
| `refused: untrusted issuer`, or the TLS handshake fails | Your device certificate is missing, expired, or does not chain to the platform's anchors | Re-enroll the device; check the gateway's trust bundle |
| `refused: attestation failed` | Your boot measurements no longer match the enrolled ones | A firmware or kernel update changed them; an operator refreshes the device's baseline after confirming the change is legitimate |
| `refused: posture violation: secure_boot` (or `fde`, `ima`) | The named rule failed | Fix the setting on the machine; `platformctl vpn posture` shows the current facts |
| `this host has no TPM device identity for the VPN client: <reason>` | The machine's TPM could not be opened or holds no IDevID; the reason says which | Check `/etc/trusted-platform/config.yaml` has a `tpm` section with `idevid`; when the reason asks for `--idevid-cert`, export the certificate with `platformctl tpm idevid certificate -o json` and pass it |
| `not connected` (exit 6) | `lease`, `renew` or `disconnect` found no lease on this machine | `platformctl vpn connect` |
| `refused: renewal not open` | `renew` ran before the lease's renewal time (`platformctl vpn lease` shows it); the lease is kept | Wait for the renewal time, or run `connect --foreground` |
| `lease … expired before it could be renewed` | `connect --foreground` could not renew before the lease expired, usually because the gateway was unreachable; the tunnel is down | Check the network path to the gateway and connect again |
| `refused: person factor required/invalid` | No key touch, wrong key, or a factor not enrolled for you | Enroll or use the right factor |
| `unavailable: posture policy` | The tenant's policy could not be loaded — this is a refusal, not a bypass | Operator: fix or restore the policy |
| `unavailable: pool exhausted` | No free addresses in the tenant pool | Operator: grow the pool or revoke stale leases |
| `refused: peer not enrolled` | The device passed identity checks but no operator enrolled it for the tenant | Operator: `platformctl vpn peer enrol` |
| Every `platformctl vpn` operator verb says the service is unavailable | This node runs no VPN control plane; it refuses every call rather than answering with empty lists | Point the CLI at the control-plane node |
| Connected, but a service is unreachable | The zone is not in your lease | Ask for the zone (`--zones`) if your role allows it; otherwise it is by design |
| `data plane wireguard not available` | FIPS build | Use `--data-plane masque --foreground` |
| `data plane masque not available` | The gateway offers only MASQUE and `connect` ran without `--foreground` | Add `--foreground` |
| `the masque data plane lives only as long as the command: add --foreground` | `--data-plane masque` without `--foreground` | Add `--foreground` |
| `gateway … refused the MASQUE session: HTTP 403` | The gateway holds no lease bound to this machine's certificate for the session | Connect again; an operator checks the lease in `platformctl vpn status` |

## What it does not do

It is not a site-to-site tunnel between gateways, it does not decide what you
may do once inside (roles and the zone matrix do), and it does not replace the
interim VPN until the operators have run both side by side and cut over.
