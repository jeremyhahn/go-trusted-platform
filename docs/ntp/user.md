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

**With `nts: true`, the upstream must be a NAME, never an address.** NTS key
establishment is a TLS handshake, and chronyd checks the server's certificate
against exactly the string you wrote in `address`. Platform certificates carry
DNS names only, so an IP address there can never validate: the node retries the
handshake forever, never synchronises, and spends the entire startup gate at
every boot while the configuration reads as if authenticated time were working.

On a node, write the control plane's internal-zone alias:

```yaml
ntp:
  mode: consume
  consume:
    upstream:
      - address: cp.example.internal
        prefer: true
        iburst: true
        nts: true
```

It resolves through the same path the ACME directory URL already uses — your
local dnsmasq forwards the internal zone to the control plane's internal DNS
server, whose zone carries the `cp` A record. You do not need an `/etc/hosts`
entry, and a change to the control plane's address needs no change here.

**On the control plane, list every such name in `serve.nts.server-names`.**

```yaml
ntp:
  mode: both
  serve:
    nts:
      enabled: true
      cert-uri: kms://platform/ntp/nts-cert
      key-uri: kms://platform/ntp/nts-key
      server-names:
        - cp.example.internal
```

The node's own hostname and FQDN are always included; this list adds the names
clients use. Entries are DNS names — an IP address is rejected at configuration
validation, with the reason. First boot writes a self-signed certificate so the
daemon can start, and the certificate-renewal sweep replaces it with a
platform-CA-issued certificate carrying every one of these names.

**Your nodes already trust that CA.** The platform CA bundle is installed into
the system trust store during ISO installation, at
`/usr/local/share/ca-certificates/trusted-platform-ca.crt`, and chrony's NTS
client validates against the system store. That is what makes the handshake
verify — there is no separate anchor to distribute and no `ntstrustedcerts`
directive to set.

If you add a name later, nothing else is needed. The renewal sweep compares
what chronyd is actually serving against the configured names and reissues when
one is missing.

### The second condition: the name must resolve inside the allow list

A valid certificate is necessary and **not sufficient**. `serve.listen-networks`
decides who this node will answer, and it is checked against the packet's
source address, not against the name. If the internal zone publishes your
server name at an address no `allow` entry covers, the client completes the
NTS-KE handshake — the certificate is fine — and is then refused time. The
clock never moves and nothing about the configuration looks wrong.

That is not hypothetical. On the reference fleet the internal zone published
`cp` at the control plane's **management** address while the rendered
`chrony.conf` allowed only the trusted and provisioning `/24`s.

platformd resolves every configured server name at bring-up and at each
certificate renewal. When the resolved address falls outside the allow list it
logs a warning and drives the `ntp` health component to **degraded** with the
marker `nts-name-unreachable`, naming the name, the address and the allow
list:

```
ntp  degraded  nts-name-unreachable: cp.example.internal resolves to
                198.18.1.140, which no serve.listen-networks entry covers
                (198.18.0.0/24, 172.16.201.0/24); clients will complete the
                NTS-KE handshake and then be refused time
```

**A name that does not resolve at all is its own finding**,
`nts-name-unresolvable`, carrying the resolver's own error:

```
ntp  degraded  nts-name-unresolvable: time.example.internal does not resolve on
                this node (lookup time.example.internal: no such host); nodes
                resolve the internal zone through this one, so no client can
                reach it either
```

The two are never merged, because they are different faults with different
fixes. `nts-name-unreachable` means reconcile the zone and the allow list;
`nts-name-unresolvable` means the record is missing or the resolver is down.
An unresolvable name has no address, so it is never reported as one the allow
list refuses.

A finding raised because the resolver was briefly unavailable at bring-up is
true at that instant and clears at the next certificate renewal, or
immediately on a `platformd` restart once the resolver is answering.

**Two ways to reconcile it. Both are valid; the platform reports and does not
choose.**

1. **Widen the allow list to the segment the name resolves on.** Add that CIDR
   to `ntp.serve.listen-networks` on the control plane and restart
   `platformd`. Choose this when the name is deliberately published on the
   management segment and you are content to serve time there.

   ```yaml
   ntp:
     serve:
       listen-networks:
         - 198.18.0.0/24
         - 172.16.201.0/24
         - 198.18.1.0/24     # the segment `cp` resolves on
   ```

   It widens who can ask this node for time, so keep it to segments you
   already trust — never `0.0.0.0/0`, which validation rejects outright.

2. **Publish the name on a segment the allow list already covers.** Point the
   `cp` A record in the internal zone at the control plane's address on that
   segment (its `trusted0` address, for the reference layout) and leave
   `listen-networks` alone. Choose this when time should stay on the overlay.

   Other services resolve the same name: the ACME directory URL and the
   heartbeat both target `cp.<internal-domain>`, so moving the record moves
   them too. Verify those still reach the control plane before committing to
   it, or publish a separate name for time and list that one in `server-names`
   instead.

Either way, confirm afterwards that the health component has cleared:

```sh
platformctl health
```

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
| `ntp  degraded  nts-name-unreachable: …` | This node serves an NTS-KE certificate for a name whose address its own allow list refuses — see "The second condition" above. The clock itself may be fine |
| `ntp  degraded  nts-name-unresolvable: …` | This node advertises an NTS-KE name it cannot resolve. Nodes resolve the internal zone through this one, so no client can reach it either. The message carries the resolver's own error |
| `ntp  unhealthy time-unsynced: …` | chronyd's control socket is not answering |
| **no `ntp` component at all** | The node has no `ntp:` section. Time is not managed here |

`platformctl health` on its own also names any component that is not healthy,
so a degraded clock is visible without remembering the flag:

```
[WARNING] ntp: DEGRADED — time-unsynced
```

**Alert on `time-unsynced`, `nts-name-unreachable` and
`nts-name-unresolvable`.** All three are stable exported constants.
`time-unsynced` means this node's own clock cannot be trusted. The other two
mean this node advertises a time service clients cannot dial: because its
allow list refuses the address, or because the name does not resolve here at
all. They are independent and any combination can be present at once, in
which case the message carries each one.

### The fleet view

On the control plane, each device's attestation report carries the device's own
clock state beside its verdict:

```bash
platformctl attestation reports list
```

```
DEVICE   SERIAL   VERDICT    FRESH   AGE   CLOCK      BASELINE   COLLECTED
9        SN-9     verified   fresh   42s   synced     signed     2026-09-06T02:00:01Z
12       SN-12    verified   fresh   51s   UNSYNCED   signed     2026-09-06T02:00:01Z
15       SN-15    verified   fresh   38s   unknown    signed     2026-09-06T02:00:01Z
```

`unknown` and `UNSYNCED` are different facts and are never merged. `UNSYNCED`
means the node reported a clock it is not disciplining; `unknown` means the
collector could not read the state, which says nothing about the clock. The
console shows the same three states as a badge on the device report.

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

**The node boots but the clock never converges, and the upstream uses NTS.**
Two different faults look identical from the node, and the control plane's own
`ntp` health component tells them apart — read it first.

*The handshake fails.* The upstream is an address rather than a name, or the
served certificate does not carry the name. chronyd reports the source
unreachable and never says why. On the node:

```sh
chronyc -N sources        # the source shows Reach 0 with no traffic counted
getent hosts cp.example.internal
```

On the control plane, read the certificate chronyd is actually serving:

```sh
openssl s_client -connect 127.0.0.1:4460 -alpn ntske/1 </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName
```

Every name a node dials must appear in that SAN list.

*The handshake succeeds and the time never arrives.* The name resolves to an
address the control plane's `serve.listen-networks` does not cover. Look at
the control plane's health component for `nts-name-unreachable`, which names
the address and the allow list, and reconcile them as described in "The second
condition" above. If you see `nts-name-unresolvable` instead, the control
plane cannot resolve the name it is advertising — publish the record in the
internal zone, or repair the resolver; the message carries the resolver's own
error. To check by hand from a node:

```sh
getent hosts cp.example.internal   # what the name resolves to
chronyc -N sources                 # Reach 0 with the handshake completing
```

and on the control plane:

```sh
grep '^allow' /etc/chrony/chrony.conf
```

The address from the first command must fall inside one of those prefixes.

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
