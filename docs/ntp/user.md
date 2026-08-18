# Time Synchronization — Using It

> **Status: NORMATIVE** · Scope: `pkg/ntp/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## Why this matters more than it looks like it should

A wrong clock does not announce itself. It shows up as certificates that will
not validate, attestation that fails for no stated reason, DNSSEC signatures
that look expired, and tokens that expire early or late. None of those errors
mentions time.

That is why the platform manages the clock at all, and why an unsynchronized
node reports **`time-unsynced`** in its health status instead of quietly
carrying on.

The platform does not implement NTP. chrony does the actual work. The platform
writes chrony's configuration, starts it, watches it, and tells you what it
sees.

---

## Prerequisites

1. **chrony installed on the node.** It is a packaged OpenRC service; the
   platform manages it, it does not ship it.
2. **An `ntp:` section in the platform configuration.** Without one, platformd
   **never touches chrony** — no default is installed, nothing is started, and
   every NTP command returns "not configured". That is deliberate, not an
   oversight.
3. **Reachable time sources**, or `orphan-fallback` if this node is meant to be
   its own reference.

---

## Configuring it

Three shapes cover almost every node.

### A node that only consumes time (a worker)

```yaml
ntp:
  enabled: true
  mode: consume
  consume:
    upstream:
      - address: time.example.com
        iburst: true
        prefer: true
      - address: pool.example.net
        pool: true
        iburst: true
    startup-gate:
      block-until-synced: true
      timeout: 120s
      on-timeout: warn-and-continue
  rtc:
    write-back: true
```

A consume-only node renders `port 0` and **never listens on port 123**. It
cannot be used as a time source by anything, which is what you want.

### A node that also serves time (a control-plane node)

```yaml
ntp:
  enabled: true
  mode: both
  consume:
    upstream:
      - address: time.example.com
        iburst: true
        nts: true
    startup-gate:
      block-until-synced: true
    orphan-fallback: true
  serve:
    listen-networks:
      - 10.20.0.0/16          # explicit CIDRs only
    local-stratum: 10
    nts:
      enabled: true
      cert-uri: kms://platform/ntp/nts-server.crt
      key-uri: kms://platform/ntp/nts-server.key
  rtc:
    write-back: true
```

### No time management at all

Omit the `ntp:` section, or set `enabled: false`. Both mean the same thing:
platformd leaves chrony alone entirely.

### The settings people get wrong

**`listen-networks` is mandatory for a serving node and cannot be open.**
`0.0.0.0/0` and `::/0` are rejected at configuration validation, not warned
about. An open NTP server is a reflection-amplification source, and the platform
will refuse to start rather than become one.

**`iburst: true` is what turns a two-year clock error into a sub-minute
correction.** Without it the first sync takes many polling intervals. Set it on
every upstream.

**`nts: true` only works if the upstream supports NTS.** Internal control-plane
sources should set it. Most public NTP servers and nearly every router cannot
do NTS, so setting it there will simply prevent that source from ever being
used.

**`orphan-fallback` only means something on a node that also serves.** It keeps
the node usable as a last-resort reference at a low stratum when no upstream is
reachable.

**Changing the configuration requires a platformd restart.** There is no reload
verb, on any transport. Edit the section, restart, and the next `Apply` renders
and restarts chronyd — but only if the rendered text actually changed, so a
restart never disturbs a clock that is already converged.

**Do not hand-edit `/etc/chrony/chrony.conf`.** It carries a header saying it is
platform-managed, and it is overwritten whenever the render output differs.

---

## The startup gate

When `block-until-synced` is true, platform bring-up waits for the clock before
TPM and CA initialization run. That ordering is the point: those subsystems make
trust decisions, and they must not make them against a bogus clock.

If the clock has not converged when the timeout expires:

| `on-timeout` | What happens |
|---|---|
| `warn-and-continue` (default) | The node boots. Its `ntp` health component reports `time-unsynced`. Fleet monitoring sees it |
| `fail-startup` | Bring-up aborts |

**Use `warn-and-continue` unless you have a specific reason not to.** A node
that refuses to boot because a time server was briefly unreachable is worse than
a node that boots and tells you its clock is untrusted. Choose `fail-startup`
only where a wrong clock is more dangerous than an offline node.

---

## Checking the clock

```bash
platformctl ntp status
```

```
FIELD                 VALUE
synced                true
stratum               3
leap status           Normal
offset (s)            0.000114237
root dispersion (s)   0.001204811
last sync             2026-08-18T09:12:40Z
mode                  both
reference             time.example.com
sources               2/3 reachable
anomaly               false
```

Reading it:

- **`synced`** — chronyd is disciplining the clock. This is the headline.
- **`stratum`** — distance from a reference clock. **`0` means unsynchronized**
  and `16` means unusable; anything between 1 and 15 is fine.
- **`offset (s)`** — how far the system clock is from the reference. Positive
  means ahead. On a converged node this is microseconds.
- **`last sync`** — prints **`never`** if the node has never synchronized.
- **`sources`** — reachable over total. `0/3` means nothing is answering.
- **`anomaly`** — `true` means a large correction happened *after* the node had
  already converged. Read the next section.

---

## Looking at the sources

```bash
platformctl ntp sources
```

```
ADDRESS               MODE    STATE        STRATUM  POLL  REACH  LAST RX  OFFSET
time.example.com      server  selected     2        64s   255    21s      0.000114237
pool.example.net      server  combined     2        64s   255    34s      0.000208441
backup.example.org    server  unreachable  0        64s   0      0s       0.000000000
```

- **`STATE`** is chronyd's verdict on that source: `selected` (the one in use),
  `combined` (contributing), `excluded`, `unreachable`, `falseticker`,
  `jittery`.
- **`REACH`** is an 8-bit register printed in decimal. **`255` means the last
  eight polls all succeeded; `0` means nothing has been heard.** `127` means the
  most recent poll failed and the seven before it succeeded.
- **`falseticker` is the one to investigate.** It means that source disagrees
  with the majority. On a platform where time is a trust primitive, that is
  either a broken server or a hostile one.

---

## When the clock is badly wrong: stepping

```bash
platformctl ntp step
```

This forces an immediate correction instead of slewing. It is an operator
recovery action, and it needs the `ntp:write` permission.

**It refuses when no source is reachable** — you get a conflict error rather
than a clock moved toward stale data. Fix reachability first.

**Think before you run it.** Stepping moves every validity window on the node at
once. Certificates become valid or invalid, tokens expire or un-expire, and
attestation freshness is re-evaluated. Under normal operation chronyd slews and
you never need this. Reach for it when the offset is too large to slew out in
useful time.

---

## The anomaly flag

The platform lets chronyd **step** the clock for the first three updates, so a
node whose hardware clock is years wrong converges immediately. After that,
corrections are slewed — and a correction larger than one second is recorded as
an **anomaly**.

That is a deliberate signal, not noise. After convergence, a large jump means
one of two things:

- a failing oscillator on the node, or
- **a time source that is lying to it.**

The platform will not decide which. It flags the node degraded with the reason,
and leaves the judgement to you.

**The flag latches for the life of the process.** It does not clear when the
clock settles again, and restarting platformd is what resets it. That is
intentional: a transient hostile correction must not disappear from the health
surface a minute later.

---

## Watching it from monitoring

The clock is surfaced as the **`ntp` component** in platform health:

```bash
platformctl health --detailed
```

| What you see | Means |
|---|---|
| `ntp  healthy   clock synchronized` | Fine |
| `ntp  degraded  time-unsynced` | The clock is not disciplined |
| `ntp  degraded  time-unsynced: clock corrected by …s after the first-boot correction` | Anomaly — see above |
| `ntp  unhealthy time-unsynced: …` | chronyd's control socket is not answering |
| **no `ntp` component at all** | The node has no `ntp:` section. Time is not managed here |

**Alert on the string `time-unsynced`.** It is a stable exported constant and it
appears in every degraded and unhealthy case.

The log line worth a separate alert is
`ntp: large clock correction after initial sync` — it is the only one that means
"failing oscillator or hostile source."

---

## Troubleshooting

**"ntp service is not configured on this node" (HTTP 503).**
There is no `ntp:` section, or it is disabled. This is not a fault — it is the
platform declining to manage time it was not asked to manage. Add the section
and restart platformd.

**Everything returns 503 and the section *is* configured.**
chronyd's control socket is not answering. Check the service is running under
OpenRC and that `/run/chrony/chronyd.sock` exists.

**The node boots but the clock never converges.**
Check `platformctl ntp sources`. If every source shows `REACH 0`, it is a
network or firewall problem, not a time problem — nothing is answering on UDP
123. If sources are reachable but the state is `falseticker` across the board,
they disagree with each other.

**platformd refuses to start with a configuration error.**
A malformed `ntp:` section is fatal by design. The message names the field:
mode not one of serve/consume/both, a serving node with no `listen-networks`, an
unrestricted CIDR, a `local-stratum` outside 1–15, an upstream address
containing whitespace or `#`, or NTS enabled without both a certificate and a
key.

**"serve.listen-networks entry … is unrestricted".**
You put `0.0.0.0/0` or `::/0` in the allow-list. Enumerate the networks that
should be allowed to ask this node for time.

**"is still an unresolved secret reference".**
NTS is enabled but the `kms://` URI was not resolved by the secrets engine
before chronyd needed the material on disk. The NTP service fails rather than
serving unauthenticated time. Fix the secret reference; do not work around it by
inlining the material.

**The clock is right but attestation or ACME still fails.**
Check that the *verifier* is synchronized too. Both ends of a freshness or
validity check need a trustworthy clock, and only one of them may be this node.

**`ntp status` shows `synced true` but `last sync` says `never`.**
chronyd reported a zero reference timestamp. Poll again; if it persists, the
control socket is returning partial output — check the platformd log for
`ntp: malformed tracking output`.

**A node lost time across a reboot.**
Set `rtc.write-back: true`. The platform then writes the corrected system time
back to the hardware clock once the gate confirms sync, so the next cold boot
starts sane even before the network is up. A write-back failure is logged, not
fatal.

---

## Where to go next

- [cli.md](cli.md) — every verb and flag
- [api.md](api.md) — every capability on every transport, including what is missing
- [architecture.md](architecture.md) — why chrony, why the gate, why the anomaly latch
- [`docs/health/user.md`](../health/user.md) — the health surface this reports into
- [`docs/ca/`](../ca/) · [`docs/attestation/`](../attestation/) — the two
  subsystems a wrong clock breaks most visibly
