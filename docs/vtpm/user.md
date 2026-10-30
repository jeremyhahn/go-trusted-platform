# Virtual TPM — Using It

> **Status: REFERENCE** · Last verified: 2026-08-18
> Working with virtual TPMs, in the order you do it. Internals are in
> [engineering.md](engineering.md).

---

## What this is

A virtual TPM gives a VM its **own** root of trust rather than borrowing the
host's. That is what makes per-VM attestation mean anything: a quote from a VM's
vTPM says something about that VM, not about the machine it happens to be on.

Underneath it is swtpm — a software TPM daemon — with the platform managing the
bundles, their identities and their lifecycle.

---

## Two nouns to keep straight

| Noun | What it is | Verbs |
|---|---|---|
| **Template** | A specification — Secure Boot on/off, EK algorithm | `vtpm template create\|list\|delete` |
| **Bundle** | An instantiated vTPM: state, NVRAM, socket | `vtpm create\|clone\|list\|info\|delete\|export\|import`, plus runtime verbs |

`vtpm clone --template <id> --hostname <host>` turns a template into a bundle.
The errors are separate per noun, so "template not found" and "bundle not found"
tell you which one you named wrong.

---

## Prerequisites

1. **swtpm installed** on the node. Without it, bundle runtime operations fail
   at target resolution.
2. **A hostname for each bundle.** Bundles are bound to a host — that is what
   "pre-assigned" means, and `--hostname` is required.

---

## Creating a vTPM

Directly:

```bash
platformctl vtpm create --hostname web-01 --ek-algorithm ECC
```

The daemon names the bundle `<hostname>-<unix-nanoseconds>` and the command
prints that id. The examples below call it `web-01-tpm`.

Or from a template, which is the better habit when you have a fleet:

```bash
platformctl vtpm template create --id uefi-sb-ecc \
    --description "UEFI Secure Boot, ECC EK" --ek-algorithm ECC
platformctl vtpm clone --template uefi-sb-ecc --hostname web-02
```

**`--secure-boot` defaults to `true`** on both `vtpm create` and
`vtpm template create`. Note that this is the opposite of `compute create`,
where `--secure-boot` defaults to false. Secure Boot keys are generated and
enrolled **at bundle creation** — they become part of the vTPM's initial state
and cannot be added to a bundle later.

Decide the EK algorithm at creation too. It is an identity property, not a
runtime setting.

---

## Running it

```bash
platformctl vtpm start      --bundle-id web-01-tpm
platformctl vtpm is-running --bundle-id web-01-tpm
platformctl vtpm stop       --bundle-id web-01-tpm
```

A bundle can exist without running. **Every runtime operation on a stopped
bundle fails** with "vTPM not running" (409 on REST, `FailedPrecondition` on
gRPC) — that is "not started", not "broken".

---

## Quoting

```bash
platformctl vtpm quote --bundle-id web-01-tpm \
    --nonce 9f86d081884c7d659a2feaa0c55ad015 \
    --pcrs 0,1,7
```

**`--nonce` is required and is not generated for you.** `container attest`
generates one; `vtpm quote` does not. A quote without a fresh nonce proves
nothing about *when* the measurement was taken, so use one you generated or one
the verifier gave you — never a constant checked into a script.

---

## Sealing and unsealing

```bash
platformctl vtpm seal --bundle-id web-01-tpm \
    --data "$(base64 -w0 secret.bin)" --pcrs 0,7 --auth-value "$AUTH"

platformctl vtpm unseal --bundle-id web-01-tpm \
    --sealed-data "$SEALED" --auth-value "$AUTH"
```

Three things people get wrong:

**Encodings differ between flags.** `seal --data` and `unseal --sealed-data` are
base64; `pcr extend --data` and `quote --nonce` are hex. Read the flag.

**`--pcrs` on seal binds the blob to those PCR values.** It unseals only while
they still match. That is the point — and it is also why an unseal that worked
yesterday fails after a firmware or bootloader change. Sealing to PCRs is a
deliberate fragility.

**`--auth-value` must match between seal and unseal**, and it is a secret. Do
not type it as a literal argument in an interactive shell; a shell with history
will record it.

---

## PCRs

```bash
platformctl vtpm pcr read   --bundle-id web-01-tpm --pcr-index 7
platformctl vtpm pcr extend --bundle-id web-01-tpm --pcr-index 16 --data deadbeef
```

`--pcr-index` (0-23) is required on both. `--data` on extend is **hex**.

---

## Moving a vTPM between hosts

```bash
platformctl vtpm export web-01-tpm --output ./web-01-tpm.tar.gz
platformctl vtpm import ./web-01-tpm.tar.gz
```

The archive carries the vTPM's identity and NVRAM. **Treat it as key material.**
Anyone with the archive has the VM's root of trust.

Export and import stream (they are streaming RPCs underneath) because a bundle
does not fit in a single message.

---

## Troubleshooting

**A runtime operation says the vTPM is not running.**
The swtpm daemon is not running for that bundle. `vtpm start --bundle-id ...`.

**Unavailable, naming the swtpm socket.**
The platform's own `tpm:` setting names a swtpm socket that is not there. This
is the node's TPM, not a bundle's.

**"not a character device" or "not a Unix socket".**
The configured TPM path is the wrong kind of thing — a hardware device path
pointing at a socket, or the reverse. The platform type-checks the path before
opening it so this reports as a configuration error rather than an unreadable
open.

**"no TPM detected" or "hardware TPM unavailable".**
Nothing to talk to. On a node meant to use swtpm, check that the bundle is
started; on a node meant to use hardware, check the device exists and is
readable.

**"TPM device open failed".**
Found it, could not open it. Permissions, or something else holds it.

**A bundle exists but attestation fails.**
Check whether it has an **EK certificate**, not just an EK. Certificate
injection is a separate step from key generation, and a bundle can have the key
without the certificate.

**"missing hostname".**
A bundle must be bound to a host. Supply `--hostname`.

**A quote or PCR read succeeds but the values are not what you expect after a
restart.**
PCRs reset. Anything sealed to them needs the same measurements to be re-made.

---

## One thing to be aware of

The MCP tool surface is duplicated: `vtpm_seal` and `vtpm_bundle_seal` name
the same operation. **Both names work, and they behave the same.** Each of the
nine `vtpm_bundle_*` tools runs its short-named twin and needs the same scope.
The two differ only in argument names: the bundle tools take `bundle_id`
where the short names take `name`. The full mapping is in [api.md](api.md) §5.

---

## Where to go next

- [cli.md](cli.md) — every verb and flag
- [api.md](api.md) — every capability on every transport (six runtime
  operations are QUIC-only)
- [architecture.md](architecture.md) — templates, bundles, target resolution
- [`docs/attestation/`](../attestation/) · [`docs/compute/`](../compute/) ·
  [`docs/tpm/`](../tpm/)
