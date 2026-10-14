# Physical TPM 2.0 — Using It

> **Status: REFERENCE** · Last verified: 2026-08-18
> Working with a node's real TPM, in the order you do it. Internals are in
> [engineering.md](engineering.md); the transport matrix is in [api.md](api.md).

---

## What this is

Every trust claim the platform makes about a node comes out of that node's
TPM 2.0: its identity, its measured boot state, and the secrets it seals. This
page is about the **physical** TPM in the machine.

Two things it is *not*:

- **Virtual TPMs for VMs** are a separate feature — [`docs/vtpm/`](../vtpm/).
- **Deciding whether a set of measurements is acceptable** is attestation —
  [`docs/attestation/`](../attestation/). This feature produces the evidence;
  attestation judges it.

The TPM commands themselves are not implemented by the platform. It drives a
TPM through the trusted-computing stack, exposes it on six transports, and
guarantees one thing above all: **you get the TPM you asked for, or the node
refuses to start.**

---

## Prerequisites

1. **A TPM the platform can open.** One of:
   - a hardware character device (`/dev/tpmrm0` is the usual one),
   - a software TPM listening on a Unix socket (path ending `.sock`),
   - the in-process simulator (`tpm.simulator: true`).
2. **Read/write access to the device** for the user running `platformd`.
3. **A `platformd` you can reach**, on `unix`, `grpc`, `rest`, `quic`, `mcp` or
   `embedded`. Only one verb works without it — `tpm clear --force`.

---

## First: which TPM did you actually get?

This is the first question, always, and it has one answer.

```bash
platformctl tpm info
platformctl tpm status
```

`status` gives you the short version: for the EK, SSRK, PlatformSRK, IAK and
IDevID, whether the handle is present and whether a certificate is installed,
plus PCR 23 and whether it has been extended. A row says `absent` only when the
daemon positively reports the object missing; a lookup that failed says
`error`. The IAK row also tells you whether its certificate carries the TCG
`verifiedTPMRestricted` policy — without it the node is provisioned but will
not pass attestation (see `docs/tpm/cli.md` §2).

If something looks wrong, read the daemon's startup log for the line

```
TPM target resolved  target=... device=...
```

**A `target` of `swtpm` or `simulator` means this node's attestation is
software-rooted.** Its quotes will verify perfectly and prove nothing about
hardware. That is fine for development and is not fine in production. If the
node is meant to have a hardware TPM and the log says otherwise, fix the
configuration — the platform will not have silently downgraded, so the mismatch
is yours, in `tpm.device` or `tpm.simulator`.

---

## Configuring the TPM

The `tpm:` block in the platform config:

```yaml
tpm:
  device: /dev/tpmrm0        # or "auto", or /path/to/swtpm.sock
  simulator: false
  entropy: false
  hash: SHA-256
  ek:
    handle: 0x81010001
  ssrk:
    handle: 0x81000001
  iak:
    handle: 0x81010002
  idevid:
    handle: 0x81020000
    cert-handle: 0x01C90000   # currently IGNORED — see the note below
    model: control-plane
    serial: node-01
  platform-pcr: 23
  platform-pcr-bank: sha256
  golden-pcrs: [7, 9]
  platform-srk:
    srk-handle: 0x81000002
    platform-policy: true
```

Five things people get wrong here:

**`cert-handle` is currently ignored for both identities.** `idevid.cert-handle`
and `iak.cert-handle` are cleared at startup, and the IAK and IDevID
certificates are kept in the platform certificate store instead of TPM NVRAM.
This is a temporary measure: go-xkms defines the NV index as a *counter*, which
the TPM will only accept at 8 bytes, so every certificate-sized NV write fails
and the daemon will not start (go-xkms#138, tracked here as #81). You will see a
warning naming the ignored handle at boot. Setting the field does no harm — it
simply has no effect for now.

**`simulator: true` beats `device:` entirely.** The device path is ignored.

**`device: auto` detects, in order, a swtpm socket, then `/dev/tpmrm0`, then
`/dev/tpm0`.** On a machine that has both, `auto` picks the software one. Name
the device explicitly on anything you care about.

**`ssrk.handle` and `platform-srk.srk-handle` are two different keys.** The
Shared SRK (`0x81000001` by default) and the PlatformSRK (`0x81000002`) are not
interchangeable, and older documentation confused them.

**Never put PCR 10 in `golden-pcrs`.** PCR 10 is IMA and changes on every boot.
Include it and every TPM-sealed secret becomes unreachable after the next
reboot.

---

## Provisioning

```bash
platformctl tpm provision
```

That creates the Endorsement Key, the Storage Root Key and the Attestation Key
— all three `--create-*` flags default to **true**. To create only some of
them, turn the others off explicitly:

```bash
platformctl tpm provision --create-ek --create-srk=false --create-ak=false
```

Then check what you got:

```bash
platformctl tpm ek info
platformctl tpm srk info
platformctl tpm ek certificate > ek.pem
```

`ek certificate` always prints PEM. It converts before printing because raw DER
contains control bytes that will corrupt a terminal — this happened on a live
serial console once, which is why the conversion is not optional.

---

## Device identity

An IDevID is the device's **birth** identity — permanent, TPM-resident,
certified once. An IAK is the attestation key that signs quotes. An LDevID is a
locally significant **operational** identity layered on top of a proven IDevID.

The order is: generate the key, produce a CSR, get it signed, install the
certificate.

```bash
platformctl tpm idevid generate --algorithm ECDSA-P256
platformctl tpm idevid csr --common-name node-01.example.com \
    --organization "Example Inc" --country US
# ... have the CA sign it ...
platformctl tpm idevid install --cert-file ./node-01-idevid.pem
platformctl tpm idevid certificate

platformctl tpm iak generate
platformctl tpm iak csr --common-name node-01.example.com
platformctl tpm iak install --cert-file ./node-01-iak.pem
```

Once the IDevID certificate is installed and valid, you can issue an LDevID:

```bash
platformctl tpm idevid ldevid create \
    --common-name node-01.example.com \
    --algorithm ECDSA-P256 \
    --out ./node-01-ldevid.pem
```

That writes the certificate to `./node-01-ldevid.pem` and the CSR to
`./node-01-ldevid.pem.csr`. **Issuance is refused without a proven, currently
valid IDevID certificate** — that is the whole point of layering it.

`--overwrite` on `idevid generate` / `iak generate` is required to replace an
existing key; without it you get "already exists; use --overwrite to replace".
Replacing an IDevID replaces the device's identity. There is no undo.

---

## Sealing secrets to platform state

```bash
platformctl tpm seal   --cn db-master --data "$SECRET" --password "$SEAL_PW"
platformctl tpm unseal --cn db-master --password "$SEAL_PW" > /run/db-master
```

Four things to know:

**`--data` is a raw string here, not base64.** (`platformctl vtpm seal --data`
*is* base64. The two commands differ.)

**PCR-bound sealing is unavailable — `--pcrs` is refused.** The go-xkms release
the platform builds against seals an object with a PCR selection but no policy
digest as a password-only object, which unseals whatever the PCRs hold. Binding
it to the PCRs needs the PolicyPCR digest or a named TPM policy, and go-quicbaas
does not re-export either yet (go-quicbaas #1171). Until it does, a seal that
names PCRs fails with `FailedPrecondition` and the message names #1171. The
platform never quietly seals it as an object that ignores the PCRs. Unsealing
blobs that already exist is unchanged.

**`unseal` writes the secret to stdout.** Redirect it. Do not let it sit in a
terminal scrollback or a CI log.

**`--password` and `--parent-password` are secrets on your command line.** A
shell with history will record them. Pass them from the environment. The
password is the only thing protecting a sealed object today, so choose a real
one.

There is no policy switch. `--policy` was accepted and ignored until #681
removed it.

---

## NVRAM

```bash
platformctl tpm nvram define --index 0x01000001 --size 256 \
    --attributes AUTHWRITE,AUTHREAD
platformctl tpm nvram write  --index 0x01000001 --data "hello"
platformctl tpm nvram read   --index 0x01000001 --hex
platformctl tpm nvram delete --index 0x01000001
```

Index ranges: `0x01000000`–`0x01FFFFFF` owner-defined,
`0x01400000`–`0x017FFFFF` platform, `0x01800000`–`0x01BFFFFF` endorsement,
`0x01C00000`–`0x01FFFFFF` TCG-defined. Stay in the owner-defined range unless
you know why you are not.

Reads and writes larger than 512 bytes are split automatically — you do not
need to know your TPM's NV buffer limit.

---

## Clearing a TPM

There are two clears and they are not the same operation.

```bash
platformctl tpm clear --confirm                 # normal: TPM2_Clear via the daemon
platformctl tpm clear --force --confirm         # UEFI PPI: schedules a clear, then reboots
```

**Without `--confirm`, `clear` does nothing and still exits 0.** It prints a
warning. A script that checks only the exit code will believe the TPM was
cleared. Always pass `--confirm`.

**`--force` is for the case where the normal clear cannot work** — the TPM is in
dictionary-attack lockout, or its hierarchy authorization is unknown because a
previous install owned it. It bypasses the daemon, talks to the device directly
(`--device`, default `/dev/tpm0`), schedules a Physical Presence Interface clear
that firmware services on the next boot, and then reboots the machine
immediately. If the automatic reboot fails, reboot manually — the clear is
already scheduled.

Both are destructive and neither can be undone.

---

## Recovering the event log and PCRs

```bash
platformctl tpm eventlog
platformctl tpm eventlog --format json
```

The event log is what the firmware and bootloader measured. It is the first
thing to read when a quote does not match expectations, because it tells you
*what* was measured, not just that the digest changed.

**Reading physical PCR values is not a CLI verb.** Use `GET /api/v1/tpm/pcrs`,
the gRPC `GetPCRs` call, or the `platform_tpm_pcrs` MCP tool.

---

## Troubleshooting

**Everything returns "TPM service not available" / 503.**
The daemon has no TPM handle. Either it never opened one, or the device went
away. Check `platformctl tpm status` and the daemon's `TPM target resolved` log
line.

**Startup fails with "hardware TPM unavailable".**
`tpm.device` names a hardware device that is missing or unreadable. The platform
will not fall back to software. Fix the path, fix the permissions, or change the
configuration deliberately.

**Startup fails with "swtpm socket unavailable".**
`tpm.device` ends in `.sock` and there is nothing there — usually the swtpm
daemon is not running.

**Startup fails with "not a character device" or "not a unix domain socket".**
The path exists and is the wrong kind of thing: a hardware path pointing at a
socket, or the reverse. The platform type-checks before opening so this reports
as a configuration error rather than an unreadable open failure.

**"no TPM detected".**
`tpm.device` is `auto` or empty and nothing was found. Name the device.

**Operations start failing after a long session, with an out-of-memory-ish
error.**
Transient handles are exhausted. `platformctl tpm flush`.

**An unseal that worked yesterday fails today.**
The PCRs it was sealed to have changed — firmware update, bootloader change,
kernel change. The secret cannot be re-sealed to PCRs until go-quicbaas #1171
(below). If it fails only after a *reboot* and nothing else changed, check
whether PCR 10 crept into `golden-pcrs`.

**`tpm seal --pcrs` fails with "PCR-bound sealing is unavailable".**
That is deliberate. The SDK cannot bind an object to PCRs yet (go-quicbaas
#1171), so the daemon refuses rather than produce an object the PCRs do not
protect. Seal with a password and no `--pcrs`.

**A quote verifies but attestation still rejects the node.**
Verification and policy are different steps. The quote being signature-valid
says nothing about whether the measurements are acceptable — see
[`docs/attestation/user.md`](../attestation/user.md).

**`platformctl tpm install`, `destroy`, `policy`, `extend`, `enroll` or `xkms`
returns "daemon connection required: operation '…' not yet supported".**
The verb is registered but unwired. It is not a connection problem and starting
the daemon will not help. See [cli.md](cli.md) §6 for what to use instead.

---

## Two things to be aware of

**The QUIC TPM2 opcodes are not scope-checked.** The gRPC `TPMService` and
`IDevIDService` carry `tpm:*` and `idevid:*` scopes — `Clear` and `DeleteEK`
need `tpm:delete`, `DeleteIDevID` needs `idevid:delete`. The TPM and
device-identity MCP tools are not classified yet, so MCP refuses them for every
caller. On QUIC, any valid platform token reaches the TPM2 category; treat
token issuance for a node with a TPM as the access control on that path —
[api.md](api.md) §9.

**The same key has two names depending on transport.** What gRPC and REST call
the AK (`CreateAK`, `/api/v1/tpm/ak`), QUIC and MCP call the IAK
(`SubOpTPM2CreateIAK`, `platform_tpm_iak_create`). If you cannot find a
capability on one transport, look for the other name.

---

## Where to go next

- [cli.md](cli.md) — every verb and flag, including the ones that do nothing
- [api.md](api.md) — every capability on all six transports
- [architecture.md](architecture.md) — why the platform drives a TPM it does not own
- [`docs/vtpm/`](../vtpm/) · [`docs/attestation/`](../attestation/) · [`docs/ca/`](../ca/)
