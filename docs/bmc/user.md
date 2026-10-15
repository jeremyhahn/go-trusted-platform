# BMC — Using It

> **Status: NORMATIVE** · Scope: operator tasks for `platformctl bmc` and the BMC REST surface · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Working with BMCs, in the order you do it. Internals are in
> [engineering.md](engineering.md). All hosts below are placeholders.

---

## What this is

A baseboard management controller is a small computer inside your server that
stays powered whenever the server has mains. Through it the platform can power
the machine on and off, choose what it boots from, mount an installer image,
read temperatures and fan speeds, and watch the serial console — all with no
operating system on the host.

That also makes the BMC the most valuable account in your rack. Whoever holds
its credentials can boot anything they like on the machine. Most of what follows
is about taking that credential and that TLS identity away from the vendor
defaults and putting them under the platform's control.

---

## Prerequisites

1. **Network reachability.** IPMI is UDP `623`. Redfish and vendor CGI are HTTPS
   `443`. **You will need both**, even for a profile configured as IPMI: virtual
   media has no IPMI equivalent, so the platform quietly opens an HTTPS
   connection to the same host on 443 for it.
2. **A BMC account.** Username and password. Do not put the password on a
   command line; use `--bmc-pass-file` with the file at mode `0600`, or a
   `kms://` reference in configuration.
3. **A decision about TLS trust.** The BMC's certificate is self-signed until
   you enroll it. You either pin its public key (`--bmc-pin`), supply a CA
   bundle (`--bmc-ca-file`), or confirm the fingerprint interactively.
   Non-interactive commands must pin — there is no "skip verification" option.
4. **A device profile**, for anything that runs through `platformd`. Every
   daemon-mode command takes `--profile-id`, and the profile is where the BMC's
   address and credentials live.

---

## Two ways to talk to a BMC

| | Daemon mode | Standalone mode |
|---|---|---|
| Selected by | `--server-url` + `--profile-id`, or the `platformctl` context | `--bmc-host` |
| Credentials from | The device profile | `--bmc-user` + `--bmc-pass-file` |
| Audit log | Yes | **No** |
| Persistence | Yes | **No** |
| Use it for | Everyday operations | Bootstrap, one-off recovery, hardware you have not enrolled yet |

**You cannot mix them.** Passing both flag sets is rejected outright, and so is
passing neither. Nothing is inferred.

Two commands are standalone-only: `bmc console` and `bmc mac`. One is
daemon-only: `bmc provision`, plus `bmc enroll` and `bmc cert restore`.

---

## First contact with a new BMC

You have a machine, an IP, and vendor default credentials.

```bash
platformctl bmc cert get \
    --bmc-host bmc.example.com \
    --bmc-user ADMIN \
    --bmc-pass-file "$XDG_CONFIG_HOME/platform/bmc.pass"
```

On a terminal this prints the certificate it found and asks whether you trust
it:

```
BMC TLS certificate at bmc.example.com:443:
  Subject:    CN=...
  Issuer:     CN=...
  Not After:  2027-01-15T10:30:00Z
  SPKI pin:   3f2a...c91d

Do you trust this certificate? [yes/no]:
```

Answer `yes` and it reconnects — properly verified against that pin — then tells
you the value to pass next time. **Save that pin.** Everything scripted needs
it:

```bash
platformctl bmc power-status \
    --bmc-host bmc.example.com --bmc-user ADMIN \
    --bmc-pass-file "$XDG_CONFIG_HOME/platform/bmc.pass" \
    --bmc-pin 3f2a...c91d
```

The same command with no terminal and no pin fails rather than trusting
whatever answers. That is deliberate.

Learn what the machine is:

```bash
platformctl bmc system-info --bmc-host bmc.example.com --bmc-user ADMIN \
    --bmc-pass-file "$XDG_CONFIG_HOME/platform/bmc.pass" --bmc-pin 3f2a...c91d

platformctl bmc mac --bmc-host bmc.example.com --bmc-user ADMIN \
    --bmc-pass-file "$XDG_CONFIG_HOME/platform/bmc.pass" --output json
```

`bmc mac` gives you the host NIC MAC addresses **before the machine has ever
booted an operating system**, which is what a PXE reservation needs. On
Supermicro-family hardware it uses a vendor-specific IPMI command, because the
standard Redfish list is empty on that firmware.

---

## Everyday operations

Once a device profile exists, everything is `--profile-id`.

```bash
platformctl bmc power-status  --server-url https://platform.example.com:8443 --profile-id 42
platformctl bmc power-on      --server-url https://platform.example.com:8443 --profile-id 42
platformctl bmc power-off     --server-url https://platform.example.com:8443 --profile-id 42
platformctl bmc power-reset   --server-url https://platform.example.com:8443 --profile-id 42
platformctl bmc power-cycle   --server-url https://platform.example.com:8443 --profile-id 42

platformctl bmc sensors       --server-url https://platform.example.com:8443 --profile-id 42
platformctl bmc system-info   --server-url https://platform.example.com:8443 --profile-id 42
```

`power-off` is a hard shutdown — the equivalent of holding the button, not of
asking the OS to shut down. `power-cycle` is off then on. `power-reset` is the
reset button.

---

## Installing an operating system out of band

The sequence is: mount the image, tell the machine to boot from it, restart.

```bash
platformctl bmc mount-iso --server-url https://platform.example.com:8443 \
    --profile-id 42 --iso-url https://images.example.com/installer.iso

platformctl bmc set-boot-device --server-url https://platform.example.com:8443 \
    --profile-id 42 --device cdrom --persistent

platformctl bmc power-reset --server-url https://platform.example.com:8443 --profile-id 42

platformctl bmc media-status --server-url https://platform.example.com:8443 --profile-id 42
```

Three things people get wrong here.

**`--device` takes a short list, and it is not the same list the API takes.**
The CLI accepts `pxe`, `disk`, `cdrom` and `bios`. It will refuse
`virtual_media` and `none`, which the API does accept. To clear a boot override
you need REST, gRPC or MCP, not the CLI.

**`--persistent` is advisory on some hardware.** On Supermicro boards the
platform always requests a *continuous* override regardless of the flag, because
that firmware erases a one-shot override before the BIOS reads it — the node
would boot from disk and you would watch an install that never started. The
bootstrap orchestrator clears the override explicitly when it finishes; if you
set one by hand, clear it by hand.

**Virtual media needs HTTPS to the BMC even on an IPMI profile.** If mounting
fails while power control works, check that port 443 is reachable, not port 623.

Clean up when you are done:

```bash
platformctl bmc unmount-iso --server-url https://platform.example.com:8443 --profile-id 42
```

---

## Watching a machine boot

```bash
platformctl bmc console \
    --bmc-host bmc.example.com --bmc-user ADMIN \
    --bmc-pass-file "$XDG_CONFIG_HOME/platform/bmc.pass" \
    --bmc-protocol ipmi --bmc-pin 3f2a...c91d
```

`Ctrl+]` disconnects. Your terminal is in raw mode until then, so `Ctrl+C` goes
to the remote machine.

Capture instead, when there is no terminal:

```bash
platformctl bmc console --bmc-host bmc.example.com --bmc-user ADMIN \
    --bmc-pass-file "$XDG_CONFIG_HOME/platform/bmc.pass" --bmc-protocol ipmi \
    --log-file /var/log/sol-node-01.log
```

Drive a recovery without a human, one line at a time:

```bash
platformctl bmc console --bmc-host bmc.example.com --bmc-user ADMIN \
    --bmc-pass-file "$XDG_CONFIG_HOME/platform/bmc.pass" --bmc-protocol ipmi \
    --log-file recovery.log \
    --send 'reset\r' \
    --send 'boot\r'
```

`--send` is repeatable, with 500 ms between sends by default — firmware command
prompts drop bytes that arrive faster than they echo. Escapes are `\r`, `\n`,
`\t`, `\\`, `\e` and `\xNN`; anything else is rejected rather than silently sent
as literal text.

`--send-break` sends a single serial break and exits, which is often enough to
unstick a firmware menu.

The console is **standalone only**. There is no way to reach it through
`platformd`, because a serial stream is not a request and a response.

---

## Making the BMC trustworthy: enrollment

Enrollment is what turns "some BMC we found" into a platform identity. It
captures the factory certificate as evidence, issues and installs a
platform-signed replacement, stores the credentials, registers the host in
internal DNS, and publishes DANE records so nothing has to trust-on-first-use
again.

```bash
platformctl bmc enroll --profile-id 7
```

Keep the evidence:

```bash
platformctl bmc enroll --profile-id 7 --backups-dir <install-dir>/backups
```

That writes three files under `<install-dir>/backups/<hostname>/bmc/`, directory
`0700`, files `0600`:

| File | What it is |
|---|---|
| `factory-cert.pem` | The certificate the BMC shipped with |
| `factory-cert.json` | Its subject, issuer, serial, validity, and both SHA-256 fingerprints, with a capture timestamp |
| `enrollment.json` | Every ceremony step and its outcome |

You can also set `PLATFORMCTL_BACKUPS_DIR` instead of the flag. Without either,
a notice goes to stderr and nothing is saved.

**The backup is evidence, not a spare key.** The platform never held the factory
certificate's private key, so it can never put that certificate back. What the
backup proves is what the machine's identity was on the day you adopted it.

Override individual steps for one run:

```bash
platformctl bmc enroll --profile-id 7 --rotate-password --dane-publish
```

**A flag you do not pass is not "off".** The four override flags are
three-state: omit one and the profile's stored setting applies. That is why
there is no `--no-dns-register` — pass `--dns-register=false` if you actually
mean to turn it off for this run.

Read the result. Every step reports its own outcome, in this order:
`trust`, `factory-cert`, `credentials`, `replace-certificate`, `dns-register`,
`dane-publish`, `device-stamp`.

A skipped step is reported as `ok` with the reason, so a partial ceremony is
still a complete record. **If `dane-publish` fails, the certificate is already
installed** — DNS was simply unavailable. Re-run enrollment once DNS is back;
nothing is broken in the meantime.

---

## Certificates afterwards

```bash
platformctl bmc cert get    --profile-id 42
platformctl bmc cert status --profile-id 42
platformctl bmc cert get    --profile-id 42 --output json
```

`get` and `status` show the same thing — subject, issuer, serial, validity,
days remaining, SANs, fingerprint. `status` is the name to use in monitoring.

Renewal is automatic once `certificate:` and `key:` are configured for the node:
the platform registers a recurring renewal job pinned to that node and updates
the DANE records around each deployment, publishing the new record *before* the
new certificate goes on so validators never see one with no matching record. The
validity window comes from `certificate.valid` — 90 days in the shipped
examples. You should not normally need to intervene.

To install a certificate you obtained yourself:

```bash
platformctl bmc cert replace --profile-id 42 \
    --cert <install-dir>/certs/bmc.pem \
    --key  <install-dir>/certs/bmc-key.pem
```

The BMC restarts its web server afterwards; expect a few seconds of
unavailability.

To undo enrollment:

```bash
platformctl bmc cert restore --profile-id 42 --factory
```

`--factory` is required and has no shorthand. Restore tells the BMC to generate
a fresh self-signed certificate, deletes the platform's pin, removes the DANE
records and clears the enrollment record. It is not reversible without
re-enrolling, and it does **not** reinstall your backup.

---

## BMC accounts

```bash
platformctl bmc user list --profile-id 42
platformctl bmc user list --profile-id 42 --output json

platformctl bmc user create --profile-id 42 --username operator1 --role operator
platformctl bmc user update-password --profile-id 42 --username operator1
platformctl bmc user update-access   --profile-id 42 --username operator1 --role administrator
platformctl bmc user delete --profile-id 42 --username operator1
```

Roles: `administrator`, `operator`, `user`, `callback`, `no-access`.

**There is no `--password` flag, on purpose.** `create` and `update-password`
prompt on stderr. A password passed as an argument shows up in `ps` output and
in shell history.

If a slot matters — some hardware reserves slots 1 and 2 — `create` takes
`--slot`; `0` lets the BMC assign one. `--channel` defaults to `1`, the usual
dedicated-NIC LAN channel.

---

## Adding hardware the platform has not seen before

Boards deviate, and the platform keeps every deviation in one table rather than
scattered through the code. If a new board misbehaves in one of the known ways —
SOL streams nothing, virtual media will not mount, a boot override is ignored,
certificate upload is rejected — the fix is usually one entry in that table
rather than a code change. Confirm the symptom first with the per-run overrides
(`--sol-instance`, an explicit `backend:` in config), then ask for the entry.

Supermicro, Dell, HPE, Aspeed-based boards, and the VeloCloud EDGE840 already
have entries. Anything else falls back to conservative standards-compliant
defaults, which is correct for most modern server hardware and wrong for X10-era
Supermicro.

---

## Troubleshooting

**"invalid configuration for certificate.acme.challenge" at daemon start.**
BMC certificates must use the `dns-01` ACME challenge. BMCs sit on isolated
management networks that ACME servers cannot reach, so `http-01` can never
succeed. The platform refuses to start with a policy that cannot work, rather
than failing at the first renewal months later. Set `challenge: dns-01`.

**"certificate and key must both be set or both be absent."**
BMC TLS management is on or off, not half on. Configure both blocks or neither.

**"backend is only valid when certificate and key are configured."**
You named a certificate backend without configuring certificate management.
Remove `backend:` or add the `certificate:`/`key:` blocks.

**"auto-cert resolved to smc-cgi ... but CGI fallback is disabled pending
hardware validation."**
The platform detected Supermicro hardware whose certificate path is the legacy
vendor CGI endpoint, and that path is gated until it has been validated against
real firmware. Either set `allow_cgi_fallback: true` after validating, or pin
`backend: smc-cgi` explicitly — pinning bypasses the gate. The gate is against
*silently* choosing that path, not against using it.

**"no factory registered for backend ... (missing side-effect import?)."**
A build that needs the Supermicro CGI backend was compiled without importing the
package that registers it. This is a build defect, not a configuration problem.

**Certificate operations behave as if unmanaged, and the logs never mention
`autocert: resolved backend`.**
That line is emitted once per BMC on first probe. Its absence means the
certificate manager was never constructed — check that both `certificate:` and
`key:` are populated.

**The console connects and logs zero bytes.**
Almost always the wrong SOL payload instance. Some boards route serial output to
instance `0x02` instead of the usual `0x01`, and activating the wrong one
*succeeds* — the BMC accepts the command and then streams nothing. Try
`--sol-instance 2`. If that fixes it, the board needs a quirk entry so nobody
has to discover it again.

**A node ignores the boot override and boots from disk anyway.**
Known X10 ATEN behavior: the firmware erases a one-shot override before POST.
The platform requests a continuous override on affected boards automatically. If
you are on hardware without an entry, the symptom is the tell.

**TLS handshake or certificate-verification failures against the BMC.**
There is no way to skip BMC certificate verification, and that is the design.
Supply `--bmc-pin` (get it from `bmc cert get` on a terminal) or
`--bmc-ca-file`. The two are mutually exclusive.

**"password file has insecure permissions."**
`--bmc-pass-file` requires mode `0600` or stricter. `chmod 600` it. The file is
not read until it is.

**Everything returns HTTP 500 with a message about the BMC.**
The REST layer maps every failure that is not "profile not found" to `500`, so a
powered-off BMC, an unreachable one, and a wrong password all look the same by
status code. Read the `error` string in the response body — it carries the real
cause.

**HTTP 404 on every operation for a profile that exists.**
`404` also covers "the profile has no BMC section" and "the daemon has no device
profile service wired". Check that the profile actually carries a `bmc:` block.

**`platformctl bmc provision` returns an error about the baremetal service.**
Orchestrated provisioning is not wired in a stock daemon build. Use the
mount-ISO / set-boot-device / reset sequence above, or the bootstrap workflow.

**Password rotation left an error you have not seen before.**
Rotation writes the new password to the store *before* the BMC, so the store is
always the best guess at reality. "Rotation reverted" is the good outcome —
both sides are back where they started, retry safely. "Rotation rollback
succeeded on BMC but store write failed" means the BMC has the old password and
the store has the new one; re-store the old. **"CATASTROPHIC rotation failure"
is the only one needing a human**: verify by hand which password the BMC
actually accepts before doing anything else.

**A command works standalone and fails through the daemon, or vice versa.**
The two paths resolve credentials and TLS trust completely differently.
Standalone uses your flags; daemon mode uses the device profile and the
platform trust chain. A profile with stale credentials fails only in daemon
mode.

**A profile's address or credentials changed and the daemon still uses the old
ones.**
BMC clients are cached per profile for the life of the process and are not
invalidated when a profile changes. Restart `platformd`.

---

## Things worth knowing before you rely on them

**BMC operations are not scope-checked on REST.** Any valid platform token can
power off a node, mount an installer, replace a BMC certificate, or create a BMC
administrator through the REST routes. gRPC, QUIC and MCP check the `bmc:*` scopes.
Treat platform tokens that can reach the BMC REST API as equivalent to physical
access, and restrict who holds them. Recorded in [api.md](api.md) §8.

**`--transport embedded` reaches only the SDK-path verbs** (`cert`, `enroll`,
`user`), through a `platformd` hosted in the `platformctl` process. If you need
to work without a daemon at all, that is what standalone mode is for.

**MCP clients reach every BMC operation gRPC does.** That includes
`platform_bmc_create_user` and `platform_bmc_set_user_password`, whose
arguments carry the password, and `platform_bmc_replace_web_certificate`, whose
arguments carry the private key. Grant `bmc:admin` to an AI or MCP client only
if it should hold those.

**Standalone mode leaves no trace.** No audit record, no persisted state.
Use it for bootstrap and recovery, not as a habit.

---

## Where to go next

- [cli.md](cli.md) — every verb and flag, with exact defaults
- [api.md](api.md) — every capability on every transport, and the gaps
- [architecture.md](architecture.md) — why it is shaped this way
- [engineering.md](engineering.md) — types, errors, invariants, tests
- [`docs/architecture/bmc-tls.md`](../architecture/bmc-tls.md) — the certificate lifecycle end to end
- [`docs/bootstrap/`](../bootstrap/) — where enrollment fits into node bring-up
- [`docs/device/`](../device/) — device templates and profiles
