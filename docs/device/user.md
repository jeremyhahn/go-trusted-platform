# Device Identity, Profiles and Inventory — Using It

> **Status: NORMATIVE** · Scope: operator tasks for devices, profiles and templates · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## What this is

You write down what a machine should be **before you plug it in**. When it
boots, it asks the platform who it is, gets exactly the configuration you wrote
down, and nothing else.

Three things to keep straight:

| Thing | What it is | Who writes it |
|---|---|---|
| **Template** | A reusable blueprint — a whole platform config, plus default matching rules | You, once per machine class |
| **Profile** | The pre-boot record for a machine: its identity, its network phases, its config | You, per machine (often from a template) |
| **Device** | The record of a machine that actually enrolled: its TPM keys, its state | Enrollment, not you |

A profile can exist for a machine that never arrives. A device only exists
because a machine presented keys.

---

## Prerequisites

1. **A reachable control plane.** Every command here talks to one. Set a
   context, or pass `--server` and `--transport`.
2. **The device's EK certificate**, if you want cryptographic identity binding.
   You can get it from the machine's TPM vendor, from an already-enrolled
   device record, or from a vTPM bundle. Without it you fall back to matching
   on EK serial or MAC — which works, and is weaker.
3. **Decide your network names up front.** Profiles reference network phases by
   name. The defaults are `provisioning` (enrollment), `trusted`
   (post-enrollment) and `quarantine` (failure). You can rename them per
   profile, but the defaults are what everything else assumes.

---

## Task 1 — Create a profile for one machine

The minimum:

```bash
platformctl device profile create --name worker-01 --role client
```

The version you actually want, with the identity bound:

```bash
platformctl device profile create \
    --name node-02 \
    --role server \
    --zone trusted \
    --ek-serial 1234567890 \
    --mac 00:25:90:FF:AA:02 \
    --ek-cert /etc/platform/ek-certs/node-02.pem \
    --config-file /etc/platform/node-02.yaml
```

**`--ek-cert` takes a file path or an inline PEM string** — it looks for
`-----BEGIN` to decide which. Either way it must parse as an X.509 certificate,
and the check happens locally before anything is sent. A malformed certificate
fails fast with `EK certificate is not a valid PEM x509 certificate`.

**`--role` is the device role vocabulary** ([api.md](api.md) §4.2): the node
roles `control-plane`, `gateway`, `worker` — the same three `device register
--role` takes — plus `server`, `client`, `workstation`, `edge`, `iot`,
`load-balancer` (and `unknown`). The same list is accepted over REST and by the
bootstrap seeder and is stored verbatim; any other string is rejected, never
silently `unknown`.

To change a profile later, only pass what changes:

```bash
platformctl device profile update 123 --ek-cert /etc/platform/ek-certs/node-02.pem
```

---

## Task 2 — Bind a profile to a machine you already enrolled

If the device is registered and carries an EK certificate, let the platform
derive the identity:

```bash
platformctl device profile assign 123 --device 4398046511105
```

That reads the device's EK certificate, computes the decimal serial from it,
and prestages both onto the profile. If the device record has no EK
certificate, it tells you so and asks for `--ek-serial` or `--mac` instead.

To supply the identity yourself:

```bash
platformctl device profile assign 123 \
    --ek-serial 1234567890 \
    --mac 00:25:90:FF:AA:02 \
    --ek-cert /etc/platform/ek-certs/node-02.pem
```

**Explicit flags win over derived values.** If you pass both `--device` and
`--ek-serial`, the flag is used.

To release a profile back to the unassigned pool:

```bash
platformctl device profile unassign 123
```

That clears the EK serial, the MAC, the prestaged certificate and the
assignment flag — all of it, not part of it.

---

## Task 3 — Look at what is enrolled

```bash
platformctl device list --page 1 --page-size 50
platformctl device get 4398046511105
platformctl device find-serial SRV-2024-001
platformctl device get 4398046511105 --output json
```

`device get` shows the EK certificate, attestation public key and signing
public key truncated in table form; use `--output json` to get the full values.

---

## Task 4 — Register a node against a control plane it has no context for

This is the bootstrap case: a fresh machine, no saved `platformctl` context.

```bash
platformctl device register \
    --hostname gw-01 \
    --mac 00:25:90:FF:AA:01 \
    --role gateway \
    --template gateway-default \
    --server https://cp.example.com:8443 \
    --ca-cert /etc/platform/ca.pem
```

Three things about this command that surprise people:

- **It creates a profile, not a device.** The name is historical.
- **`--role` here is `control-plane` | `gateway` | `worker`.** See Task 1.
- **`--override-file` contents go into the profile's `event_log` field**, not
  into a config field, and are not delivered as configuration. If you want a
  platform config delivered, use
  `device profile create --config-file` instead.

---

## Task 5 — Templates

Templates are **REST-only**. There is no CLI verb and no gRPC RPC for template
CRUD; that is a recorded design decision, not an oversight
([api.md](api.md) §4).

```bash
# Upload a template
curl -X POST https://cp.example.com:8443/api/v1/device/templates \
     -H 'Content-Type: application/json' --data @gateway-default.json

# List templates
curl https://cp.example.com:8443/api/v1/device/templates

# Turn a template into a profile
curl -X POST https://cp.example.com:8443/api/v1/device/templates/7/create-profile \
     -H 'Content-Type: application/json' \
     --data '{"name":"gw-02","role":"gateway"}'
```

Creating a profile from a template deep-copies the template's config and match
rules, then applies your overrides. **Config overrides are deep-merged into the
template's YAML**, so you can override a hostname or an IP without restating
the whole file.

---

## Task 6 — Understand what a booting machine will get

Resolution is priority-ordered:

1. **Exact EK certificate serial** — case-insensitive, across all tenants
2. **Exact MAC address** — case-insensitive, across all tenants
3. **Prefix match rules** — MAC prefix, serial prefix, model

The first hit wins. Nothing after it is consulted.

```bash
curl 'https://cp.example.com:8443/api/v1/devices/config?ek_serial=1234567890'
curl 'https://cp.example.com:8443/api/v1/devices/config?mac=00:25:90:ff:aa:02'
```

If nothing matches, you get an error, **not a default profile**. A machine with
no record gets nothing — that is the point.

Prefix rules are **OR across fields**: a profile with both a MAC prefix and a
serial prefix matches if *either* one matches. If two profiles could match the
same machine, the one you get is whichever storage iteration reaches first, and
that order is not specified. Write disjoint rules.

Note also that `manufacturer_match`, `tpm_vendor` and `custom_attributes` are
accepted and stored in match rules but are **not evaluated** when matching.

---

## Task 7 — Watch a machine's lifecycle

A device moves through a fixed set of states, and the transitions are enforced:

```
unknown → registered → installing → installed → activated → attested
                    ↘            ↘           ↘           ↘
                      quarantined ⇄ attested   suspended → revoked
```

- `registered` can also go straight to `activated` for machines with no install
  step.
- `quarantined` means a non-severe compliance failure: the machine is on the
  quarantine network, the port is still up, and re-attestation restores it.
- `suspended` means a severe failure or a revoked certificate: the port is set
  admin-down. Only an operator restores it.
- **`revoked` is terminal.** There is no transition out of it. Plan for that
  before you revoke.

Quarantine and suspension record where the device came from (`prior_state`,
`prior_zone`) so remediation puts it back where it was rather than guessing.

**These transitions are driven by the platform, not by hand.** Quarantine and
suspension come from the SDN quarantine loop reacting to a violation, and the
restore comes from a successful re-attestation — both program the port as well
as the record. There is no operator "disable this device" verb: the generic
device update deliberately refuses to carry a lifecycle state, because a
transition that changed the record without programming the port would report a
machine as cut off while it was still on the network. The console's
Enable/Disable Device control is disabled and says so for that reason; it is
tracked in issue #250.

---

## Troubleshooting

**"at least one of ek_serial or mac_address is required".**
You called assign or config-lookup with no identity. Supply `--device`,
`--ek-serial` or `--mac`.

**"no matching config found for ek_serial=… mac=…".**
Nothing matched. Check, in order: is there a profile with that exact EK serial?
That exact MAC? A prefix rule that covers it? Remember serial comparison is
case-insensitive but prefix rules stored on the profile are normalised —
MAC prefixes lowercase, serial prefixes uppercase.

**"EK certificate is not a valid PEM x509 certificate".**
The file or inline string did not decode as PEM, or the DER inside did not
parse. This is checked at every entry point, so you get the same message from
the CLI, REST, gRPC, QUIC and MCP. Check you exported the certificate and not
the public key.

**"device N has no EK certificate to derive an identity from".**
`assign --device` needs the device record to carry an EK certificate. Either
enrol the machine so the certificate is recorded, or pass `--ek-serial` /
`--mac` explicitly.

**"invalid state transition X → Y".**
The lifecycle table refused it. `revoked` has no exits; `suspended` can only go
to `attested` or `revoked`.

**A profile write returns 503.**
The daemon has no profile service wired. That is a deployment problem, not a
missing profile — check the daemon's service registry
(`GET /api/v1/platform/service-registry`).

**Activation returned success but the switch port did not move.**
The VLAN move is a deliberate no-op when no switch service is configured, or
when the request context carries no switch name and port. "Activated" means the
device record and SDN policy were updated; it does not by itself mean a
physical port changed VLAN. See [`docs/switch/`](../switch/).

**An MCP client says `unknown tool: device_create`.**
That tool is advertised and has no implementation. Use `device_register`,
`device_get`, `device_list`, `device_update`, `device_delete` — the older
family — and the `profile_*` tools, which are all live
([api.md](api.md) §6).

**`platformctl profile list` says "daemon connection required" no matter what.**
That group is a stub; all four of its verbs return that error unconditionally,
including under `--transport embedded`. Use
`platformctl device profile …` for writes and REST for reads
([cli.md](cli.md) §6).

---

## Two things to be careful about

**A profile can contain a BMC password.** `DeviceProfile.BMC` carries a
username and password for IPMI or Redfish. Anyone who can read a profile in
full can read that credential. Config snapshots redact it; a raw profile read
does not. Scope `device:read` accordingly.

**Profile lookup is a full scan.** Every find-by-MAC, find-by-serial and
match iterates every stored profile. This is fine at operator scale and it is
not fine at machine scale. If you are generating profiles programmatically per
device, expect lookup cost to grow linearly.

---

## Where to go next

- [cli.md](cli.md) — every verb and flag
- [api.md](api.md) — every capability on every transport
- [architecture.md](architecture.md) — why identity resolves in that order
- [`docs/sdn/`](../sdn/) — what actually programs the network
- [`docs/switch/`](../switch/) — physical switch ports
- [`docs/attestation/`](../attestation/) · [`docs/bmc/`](../bmc/) · [`docs/vtpm/`](../vtpm/)
