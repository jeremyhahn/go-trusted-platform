# Remote-Access VPN — CLI

> **Status: PARTIAL — the operator verbs ship (#584 PR 3); `connect`, `connect --foreground`, `disconnect`, `lease`, `posture` and `renew` exist with their exit codes, the verbs that talk to a gateway present this host's TPM device identity, and `connect` brings up the leased WireGuard or MASQUE data plane; the gateway listener they call exists (#557).** · Last verified: 2026-10-14
> `platformctl vpn peer|status|posture-policy` exist (`pkg/cli/commands/vpn`)
> and are exercised over every transport by `test/integration/vpn/`. The
> client verbs are tested against a stand-in for the gateway's admission
> listener, which does not exist yet (#557). A host without a TPM device
> identity exits 1 with "this host has no TPM device identity for the VPN
> client: <reason>".
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

## `platformctl vpn` — client-agent verbs

| Verb | Purpose | Flags | Exit |
|---|---|---|---|
| `connect` | Run the admission (identity → quote → posture → factor → lease) and bring the data plane up | `--gateway <host:port>` (required), `--tenant <t>` (required; the tenant the device is enrolled in), `--device-id <id>` (required; the id the device is enrolled under with `peer enrol`), `--idevid-cert <pem>` (see below), `--data-plane wireguard\|masque` (default: the first plane the gateway offers that this build has; see below), `--factor fido2\|piv`, `--zones <a,b>` (default: every zone the peer may reach), `--ca-file <pem>` (default: the system roots), `--foreground` (stay running and renew the lease; see below) | 0; 4 refused (reason class printed); 5 posture violation (rules listed) |
| `disconnect` | Revoke the lease and tear the data plane down | `--ca-file <pem>`, `--idevid-cert <pem>` | 0; 4 the gateway refused the revocation; 6 not connected |
| `lease` | Lease id, gateway, address, zones, data plane, interface, expiry, next re-attestation | `-o` | 0; 6 not connected |
| `posture` | Print the posture report the agent would send: Secure Boot, IMA and disk-encryption state, agent version, OS and kernel releases, collection time | `-o json` (the report as the gateway's policy receives it) | 0; 1 the report could not be collected |
| `renew` | Renew the lease now with a fresh quote, posture report and, when `connect` presented one, person factor; print the renewed lease | `--ca-file <pem>`, `--idevid-cert <pem>`, `-o` | 0; 4 refused; 5 posture violation; 6 not connected |

Every other failure exits 1: an unreadable `--ca-file`, a gateway that cannot
be reached or whose certificate does not chain to the roots, an unknown
`--factor` or one this host has no signer for (no FIDO2 or PIV signer exists
yet), a host without a TPM device identity, or a data plane that cannot come
up (the lease is then revoked). A 503 from the gateway (`unavailable: …`) is a
refusal and exits 4.

`connect` brings up the data plane the lease names, and needs root (or
`CAP_NET_ADMIN`) to do it:

| Data plane | Interface | Lives | Builds |
|---|---|---|---|
| `wireguard` | `vpn-wg0`, a kernel WireGuard link keyed with a fresh key per admission, the gateway its only peer | Until `disconnect`, a renewal refusal or the lease's end removes it; it outlives the command | Every build but FIPS |
| `masque` | `vpn-masque0`, a TUN carrying a MASQUE CONNECT-IP session (RFC 9484) over HTTP/3 to the lease's template, authenticated with the device certificate | Only as long as the command, so it needs `--foreground`; `--data-plane masque` without it exits 1 before the TPM is opened | Every build |

Without `--data-plane`, `connect` takes the first plane the gateway offers that
it can bring up here: without `--foreground` that is never `masque`, and in a
FIPS build never `wireguard`. Both planes address the interface with the lease
address and route the lease's routes through it. A MASQUE session the gateway
refuses exits 1 with its HTTP status; one whose assigned address is not the
lease's exits 1. If the gateway ends a MASQUE session (an operator revoke, for
one), the TUN closes and `connect --foreground` keeps renewing a lease with no
tunnel until the renewal is refused; it does not reconnect.

A renewal refusal either ends the lease or leaves it standing. It leaves it
standing when the renewal window has not opened yet (`renewal-not-open`), the
gateway no longer knows the nonce (`nonce-unknown`), or the gateway answers 503;
`renew` still exits 4 and the data plane stays up. Every other refusal (a
posture violation, a failed attestation, an unenrolled peer, an expired lease)
ends it: the data plane comes down, the local lease is forgotten, and the verb
exits with the refusal's code.

`connect --foreground` stays running after it connects and keeps the lease
alive. At the lease's renewal time it renews, as `renew` does, with a fresh
quote and posture report, then waits for the renewed lease's renewal time. A
refusal that ends the lease exits with its code (4, or 5 for a posture
violation) with the data plane down. A renewal that fails any other way is
retried every 30 seconds until the lease expires; a lease that expires
unrenewed comes down and the command exits with the last failure's code
(1 when the gateway could not be reached). SIGINT or SIGTERM disconnects, as
`disconnect` does, and exits 0. Without `--foreground` the lease lasts until it
expires, `renew` renews it, or `disconnect` revokes it.

The device identity is this host's TPM, opened from the `tpm` section of the
platform configuration (`/etc/trusted-platform/config.yaml`, then
`/etc/trusted-platform/platformd.yaml`), the same TPM and key names platformd
uses. The IDevID key signs the mTLS handshake; the attestation key quotes the
PCRs over the gateway's nonce, and the quote carries the IDevID certificate. A
host has no device identity, and the verb exits 1, when neither file exists or
has a `tpm` section, the TPM does not open, the `tpm.idevid` section is missing,
or no IDevID certificate is found. The certificate is read from the TPM's NV
index only when `tpm.idevid.cert-handle` holds it, which platformd does not
write today (go-xkms#138); pass the chain with `--idevid-cert`, exported with
`platformctl tpm idevid certificate -o json` (its `certificate_pem`).

`disconnect` forgets the local lease and brings the data plane down even when
the gateway cannot be reached or refuses, or the TPM cannot be opened (the
lease is then not revoked); it still exits non-zero so the
failure is visible, and the gateway lets the lease expire. A MASQUE tunnel is
held by the `connect --foreground` process: interrupting that process brings it
down; `disconnect` from another shell revokes the lease, and the gateway's end
of the session closes that process's TUN. `lease` reads local
state only (`/run/platformctl/vpn.json`) and contacts no gateway. `posture`
collects the report on this host and contacts no gateway and no TPM.

The client's own lease view is `lease`, because `status` is the operator verb
above.

`connect`, `renew` and `disconnect` call the gateway's admission listener
(`--gateway` is its `management_vpn.listener` address), which exists: the
challenge, admit, renew and disconnect routes of [api.md](api.md) §5, over
mTLS with the device's IDevID certificate. The exit code is the one the
listener's refusal class maps to there: 4 for a refusal, 5 for a posture
violation, 6 for a lease that has expired or is not this device's.

Examples:

```sh
platformctl tpm idevid certificate -o json | jq -r .certificate_pem > idevid.pem
platformctl vpn connect --gateway gw.letstrust.com:4433 --tenant acme --device-id laptop-1 --idevid-cert idevid.pem --factor fido2
platformctl vpn connect --gateway gw.letstrust.com:4433 --tenant acme --device-id laptop-1 --idevid-cert idevid.pem --ca-file gw-roots.pem --zones management
platformctl vpn connect --gateway gw.letstrust.com:4433 --tenant acme --device-id laptop-1 --idevid-cert idevid.pem --foreground
platformctl vpn connect --gateway gw.letstrust.com:4433 --tenant acme --device-id laptop-1 --idevid-cert idevid.pem --data-plane masque --foreground
platformctl vpn lease -o json
platformctl vpn posture -o json
platformctl vpn renew --idevid-cert idevid.pem
platformctl vpn disconnect --idevid-cert idevid.pem
```

Prerequisites for the client verbs: the machine is an enrolled device with an
IDevID (`platformctl device …`), the device is enrolled as a VPN peer
(`platformctl vpn peer enrol`), the person has a FIDO2 or PIV factor enrolled
(`platformctl fido2 …`, `platformctl piv …`), and the agent runs with the
privilege to configure a network interface for the chosen data plane.

The client verbs talk to the gateway's admission listener, not to platformd,
so `--context`, `--local` and the transport flags do not apply to them. The
operator verbs need a server: the enrolment set and the policies are
control-plane objects.
