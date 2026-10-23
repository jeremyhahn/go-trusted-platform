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
   name. The defaults are `provisioning` (enrollment), `admitted`
   (post-enrollment: the port carries the zones of the device's role) and
   `quarantine` (failure). You can rename them per
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
    --role worker \
    --ek-serial 1234567890 \
    --mac 00:25:90:FF:AA:02 \
    --ek-cert /etc/platform/ek-certs/node-02.pem \
    --config-file /etc/platform/node-02.yaml
```

With no `--zone`, an admitted device gets its role's zones: a `gateway` gets
the gateway port class, a `control-plane` or `worker` node the hypervisor port
class (its trunk VLANs, native VLAN provisioning). A role without a port class
(`server`, `iot`, …) is admitted only with an explicit `--zone`; without one
admission fails closed and the port stays where it is. See the
[reference network](../architecture/reference-network.md).

### Which zones a profile may name

An explicit `--zone` makes the admitted port an access port on that zone, so the
zone set decides which zones are admission targets (one rule,
`policy.ValidateAdmissionZone`, enforced when the device is admitted):

| Zone | Admission | Why |
|------|-----------|-----|
| `storage`, `backup`, `hypervisor`, an owner-defined zone | allowed | ordinary underlay zones |
| `management` | refused | out-of-band, BMCs only |
| `transit` | refused | the gateway edge only |
| `fabric` | refused | the VXLAN underlay; a host joins it as a VTEP, not as an access port |
| `provisioning`, `quarantine` | refused | lifecycle zones, entered through their own phases |
| `control-plane` | only behind an audited path | allowed only when some zone opens a `privileged_access` path into control-plane, so naming it in a profile cannot skip that audit |
| an undeclared zone | refused | |

A refused zone fails admission with `ErrAdmissionZone` naming the zone and the
reason, and the port stays where it is.

**`--ek-cert` takes a file path or an inline PEM string** — it looks for
`-----BEGIN` to decide which. Either way it must parse as an X.509 certificate,
and the check happens locally before anything is sent. A malformed certificate
fails fast with `EK certificate is not a valid PEM x509 certificate`.

**`--role` is the device role vocabulary** ([api.md](api.md) §4.2): the node
roles `control-plane`, `gateway`, `worker` plus `server`, `client`, `workstation`, `edge`, `iot`,
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

## Task 4 — Register a device record by hand

Machines that enroll through bootstrap create their own device record. To add
one by hand — a machine enrolled out of band, or a record you want before the
machine first boots — register it through your usual context:

```bash
platformctl device register \
    --serial SRV-2024-001 \
    --model r640 \
    --ek-cert /etc/platform/ek-certs/node-02.pem \
    --hash-algo 11
```

It prints the stored device, including the id the control plane assigned — the
id `device profile assign --device` takes (Task 2).

- **It creates a device, not a profile.** Use `device profile create` (Task 1)
  for a profile.
- **The serial is required and must be unused.** A second device with the same
  serial is refused, on every transport, rather than written beside the first
  ([api.md](api.md) §2).

---

## Task 4a — Find the control plane in its own inventory

The control plane enrolls itself as a device on every start where the
attestation reporting collector is enabled, so `device list` includes it. It is
an ordinary row: same fields, same lifecycle, same profile binding. Identify it
by the hostname on its IDevID certificate, or by the product serial its own
`tpm.idevid.serial` config names.

```bash
platformctl device list
platformctl device get <control-plane-device-id>
```

Bind a profile to it once, the same step every enrolled device needs:

```bash
platformctl device profile assign <profile-id> --device <control-plane-device-id>
```

The binding is what gives the attestation verifier a PCR baseline for the
control plane, and what lets you set `--tls-server-name` if the control plane's
webservice certificate carries a role name rather than the device FQDN. The
collector reaches the control plane over loopback without it, using the
certificate name from the control plane's own webservice configuration.

If the control plane does **not** appear, it is one of three things, in the
order worth checking: the collector is not enabled on it
(`attestation.reporting.enabled`), its TPM has no IAK — self-registration is
refused rather than writing a record nothing can verdict — or its
`tpm.idevid.serial` and SMBIOS both report nothing, which leaves the registry
with no identity to key on. The daemon log names which.

## Task 5 — Templates

Template create, get, list, update and delete reach every transport: the
`platformctl device template` verbs ([cli.md](cli.md) §2.8), the gRPC, Unix and
QUIC `DeviceService` RPCs, the `device_template_*` MCP tools and the REST routes
below ([api.md](api.md) §4). Only the lookup by name is REST-only.

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

Ask the same question the machine will, as an operator:

```bash
curl 'https://cp.example.com:8443/api/v1/device/profiles/find-config?ek_serial=1234567890'
curl 'https://cp.example.com:8443/api/v1/device/profiles/find-config?mac=00:25:90:ff:aa:02'
```

The booting machine itself fetches `GET /api/v1/devices/config?mac=…` (or
`?serial=…`) and gets the config back as YAML. That route needs no credentials,
so **only the provisioning listener serves it**: a webservice with
`surface: provisioning`, bound to an address in the provisioning VLAN. Every
other listener answers it with a 404 (#177). See
[`docs/web/user.md`](../web/user.md) to configure that listener.

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
- `suspended` means a severe failure, a revoked certificate or an operator's
  Disable: the port is set admin-down. Only an operator's Enable lifts it, and
  only as far as quarantine.
- **`revoked` is terminal.** There is no transition out of it. Plan for that
  before you revoke.

Quarantine and suspension record where the device came from (`prior_state`,
`prior_zone`) so remediation puts it back where it was rather than guessing.

**Most transitions are driven by the platform.** Quarantine and suspension
come from the SDN quarantine loop reacting to a violation, and the restore
comes from a successful re-attestation — both program the port as well as the
record. The generic device update deliberately refuses to carry a lifecycle
state, because a transition that changed the record without programming the
port would report a machine as cut off while it was still on the network.

**Disable and Enable are the operator's two transitions (#250).** Each is its
own verb, and each programs the switch port before it records anything:

```bash
platformctl device disable 42 --reason "decommissioning rack 3"
platformctl device enable 42
```

In the console, the device table's row menu and the device page carry the
same control. A `suspended` device offers **Enable**; a `revoked` device offers
nothing (revocation is terminal); every other state offers **Disable**, and the
control plane decides whether the transition is allowed.

- **Disable** blocks the machine's switch port and records the device
  `suspended`, with the state reason `operator: <your reason>` (or
  `operator: disabled` when you give none). The badge reads *Disabled*.
- **Enable does not put the machine back in service.** It re-admits the port
  to the quarantine zone, records the device `quarantined` and asks the
  attestation collector to quote it now. Only a passing verdict restores the
  state and network placement it had before it was disabled. A machine that
  fails attestation stays quarantined. The response's
  `reattestation_requested: false` means no collector took the request, and
  the machine waits for the next scheduled attestation cycle.

The control plane refuses rather than record a state nothing enforces, and the
console shows the refusal as an error toast:

| Refusal | Cause |
|---|---|
| `device lifecycle: this control plane has no SDN policy engine ...` | The daemon runs without the attestation quarantine observer on SDN-OVS. No transport can disable or enable a device on it. |
| `device lifecycle: device 42 has no switch port on the SDN fabric to enforce` | The record has no `network_port_id`, so there is no port to block. |
| `device: invalid state transition suspended → suspended` | Disable on a device that is already suspended or revoked. |
| `... device 42 is not suspended (state=attested); only a disabled device can be re-enabled` | Enable on a device that is not suspended. |
| `... no zone carries lifecycle role quarantine` | Enable needs a zone with the quarantine role to re-admit the port into. |

Each refusal is a `400` on REST and `FAILED_PRECONDITION` on gRPC and the Unix
socket. Nothing is recorded and the port is not touched.

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
to `attested`, `revoked`, or — through an operator's Enable — `quarantined`.

**A profile write returns 503.**
The daemon has no profile service wired. That is a deployment problem, not a
missing profile — check the daemon's service registry
(`GET /api/v1/platform/service-registry`).

**Activation returned success but the switch port did not move.**
The VLAN move is a deliberate no-op when no switch service is configured, or
when the request context carries no switch name and port. "Activated" means the
device record and SDN policy were updated; it does not by itself mean a
physical port changed VLAN. See [`docs/switch/`](../switch/).

**`device boot certificate` or `device boot delivery` fails at once with "channel binding unavailable" or "diskless boot needs a TLS 1.3 connection".**
Unix sockets and MCP are not valid channels for boot proofs. The proof is bound
to the TLS session of the connection that carries it, and neither transport has
one, so the call is refused before anything is sent. Use `--protocol grpc`,
`quic` or `rest` ([cli.md](cli.md) §2.7).

**An MCP client says `unknown tool: device_create`.**
That tool no longer exists; it was advertised without an implementation and
was removed in #533. Use `device_register`, `device_get`,
`device_find_by_serial`, `device_list`, `device_update`, `device_delete`, and
the `profile_*` tools ([api.md](api.md) §6). `device_register` takes `serial`
and `model`, not `name` and `device_type`.

**An MCP client's `initialize` fails with `invalid character 'p' after top-level value`.**
The client posted to the bare endpoint, which answers the HTTP mux's plain-text
`404 page not found`. JSON-RPC is served only on the `/mcp` path — use
`https://<host>:9445/mcp`.

**`platformctl profile get` or `match` fails with "not found" / "no profile matches".**
Both exit non-zero on purpose: the id does not exist, or no profile's match
rules fit the MAC, serial or model given. `platformctl profile list` shows
what exists ([cli.md](cli.md) §3.0a).

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
