# Zero-Touch Provisioning — Using It

> **Status: REFERENCE** · Last verified: 2026-08-18
> Bringing a new machine onto the platform, in the order it happens. Internals
> are in [engineering.md](engineering.md).

---

## What this is

A bare machine is racked and powered on. Without anyone logging into it, it
network-boots, obtains a configuration it can trust, installs an operating
system, gets a hardware identity, and joins the platform.

The hard part is the beginning: **the machine has no identity, and the platform
must not trust anything the machine says about itself.**

---

## How that problem is solved

The machine is identified by two things it **cannot choose** — its **TPM
endorsement key serial** and its **MAC address** — plus an **EAB credential**
that was issued to it out of band ([`docs/eab/`](../eab/)).

With those it opens a **provisioning session**. The session is **pending** until
an operator (or an automation with authority) **fulfils** it by linking a device
profile. Only then does the machine receive its configuration.

**There is no self-service path onto the platform.** That is the design.

---

## Prerequisites

1. A control plane with the PXE service and config delivery wired in.
2. **A provisioning network zone** — `platformctl sdn zone create --name
   provisioning --lifecycle-role provisioning`. A booting machine needs somewhere
   to reach the enrollment service and nothing else ([`docs/sdn/`](../sdn/)).
3. **A quarantine zone**, for machines that fail a check.
4. **A device profile** to link at fulfilment ([`docs/device/`](../device/)).
5. **An EAB credential** for the machine.

Set up the two zones first. Without them the port state machine has nowhere to
put a machine that is neither trusted nor gone.

---

## The flow

### 1. The machine boots and opens a session

On the machine being provisioned:

```bash
platformctl provision fetch-config \
    --server-url https://platform.example.com \
    --ek-serial 0x1A2B3C4D \
    --mac 00:11:22:33:44:55 \
    --eab-kid kid-0f21 \
    --eab-hmac "$EAB_HMAC" \
    --output /run/platform/config.yaml
```

Note these verbs take `--server-url`, not the usual `--server`: the machine has
no platform context and no credentials yet.

**`--eab-hmac` is a credential.** Read it from a file or a protected environment
variable rather than typing it — it lands in shell history and in the process
table.

There is also `platformctl provision interactive` for QR-code provisioning,
where a human scanning a code is the out-of-band authorisation.

### 2. An operator fulfils the session

On an operator workstation:

```bash
platformctl provision session list
platformctl provision session get sess-9a3f
platformctl provision session fulfill sess-9a3f --profile-id 42
```

`--profile-id` is a **decimal uint64**, not a name.

This is the gate. Until it happens the machine gets nothing.

### 3. The machine installs

The installer runs from the delivered configuration. Two things it does that an
ordinary installer does not:

- **Secure Boot digests are signed remotely.** The signing key stays on the
  platform; the machine sends a digest and receives a signature. A machine you
  are still deciding whether to trust never holds a Secure Boot signing key.
- **FIDO2 disk unlock is enrolled during installation**, not afterwards. A disk
  encrypted at install time needs its unlock factor enrolled at install time.

### 4. The machine reports completion

The install-complete webhook tells the platform the machine is done. **That is a
report, not a fact** — the platform's state machine decides what it means, and
attestation is what actually establishes trust afterwards
([`docs/attestation/`](../attestation/)).

---

## Managing devices — API only

**There is no `platformctl pxe` command group.** Every device-lifecycle
operation is an API call:

```bash
curl -s        https://platform.example.com/api/v1/pxe/devices
curl -s        https://platform.example.com/api/v1/pxe/devices/mac/00:11:22:33:44:55
curl -s        https://platform.example.com/api/v1/pxe/devices/<id>/events

curl -s -X POST https://platform.example.com/api/v1/pxe/devices/<id>/authorize
curl -s -X POST https://platform.example.com/api/v1/pxe/devices/<id>/quarantine
curl -s -X POST https://platform.example.com/api/v1/pxe/devices/<id>/retry
```

**`/events` is the first thing to read when a machine did not come up.** It is
the device's provisioning history.

**Quarantine, then investigate, then retry.** A device that fails a check goes
to an isolated state rather than being left ambiguous, and `retry` is how it
comes back once you know why.

You can also start and stop the PXE service itself:

```bash
curl -s        https://platform.example.com/api/v1/pxe/status
curl -s -X POST https://platform.example.com/api/v1/pxe/start
curl -s -X POST https://platform.example.com/api/v1/pxe/stop
```

---

## Building images

```bash
platformctl iso profile list
platformctl iso profile validate ./install-config.yaml
platformctl iso build ...
platformctl iso test ...
```

**Validate before you build.** A configuration that fails validation at build
time has already cost you the build.

---

## Rebuilding a UKI after a kernel update

```bash
platformctl install uki-rebuild
```

**This changes what the machine measures at boot.** New PCR values invalidate:

- anything sealed to those PCRs (vTPM-sealed secrets, LUKS keys bound to PCRs)
- golden-PCR attestation policy that named the old values

Plan the re-seal and the policy update in the same window. This is the operation
most likely to make a fleet fail attestation overnight, and it will look like
tampering.

---

## Troubleshooting

**The machine boots but nothing happens.**
The session is pending. Nobody has fulfilled it. `provision session list`.

**"EAB credential rejected."**
Wrong key ID or HMAC, or the credential expired or was already used. See
[`docs/eab/`](../eab/).

**"Nonce stale" or a replay error.**
The exchange took too long, or a nonce was reused. Each attempt gets a fresh
one.

**Everything from the provisioning endpoint returns 429.**
Rate limiting. The endpoint is reachable by machines with no identity, so it is
rate-limited by design. Under a mass provisioning event this is expected — stagger
the boots.

**`/api/v1/pxe/*` returns 503.**
The PXE service may simply be stopped. `POST /api/v1/pxe/start`.

**A device is stuck in quarantine.**
It failed a check. Read `/events` to find out which, fix the cause, then
`retry`. Do not authorize past it without knowing why.

**A machine boots into the provisioning zone and cannot reach the enrollment
service.**
The provisioning zone's flows permit enrollment traffic only. Check that the
enrollment endpoint is reachable from that zone ([`docs/sdn/`](../sdn/)).

**A fleet fails attestation after a kernel update.**
`uki-rebuild` changed the measurements. See above.

---

## Two things to be aware of

**Authorization.** `PXEService`, `ConfigDeliveryService`, `ProvisioningGateway`
and `BMCService` are all in the gRPC scope catalog, which is default-deny.
Authorizing a PXE device needs `pxe:write` and fulfilling a provisioning session
`provisioning:write`, on gRPC and on the webservice's REST operator routes alike,
where the scope sits on top of the admin role. Signing a Secure Boot digest is
pre-auth on gRPC: the machine proves itself inside the request (single-use
nonce, EAB HMAC, EK-certificate binding), not with a platform token. On MCP the
BMC, `pxe_*` and `provision_*` tools take the scopes of their gRPC twins, and
the four device-facing `provision_*` tools are open as their gRPC methods are.
The install-completion webhook `POST /api/v1/pxe/webhook/complete` is
authenticated by the node's mTLS device certificate (#238). See [api.md](api.md) §6 and
[`docs/ipxe/api.md`](../ipxe/api.md) §5.

**Test coverage.** Two provisioning integration suites do not exercise what they
appear to: the PXE suite reaches a platformd with no PXE backend, so every call
answers `SERVICE_NOT_CONFIGURED`, and the authenticode multi-protocol test has
all five adapters commented out. See
[engineering.md](engineering.md) §7.

---

## Where to go next

- [cli.md](cli.md) — every verb and flag
- [api.md](api.md) — every capability on every transport
- [architecture.md](architecture.md) — the pre-enrollment trust problem and how it is solved
- [`docs/device/`](../device/) · [`docs/eab/`](../eab/) · [`docs/sdn/`](../sdn/) ·
  [`docs/attestation/`](../attestation/)
- **Not converted in this pass:** [`docs/bmc/`](../bmc/),
  [`docs/bootstrap/`](../bootstrap/)
