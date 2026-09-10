# Gateway bring-up: standing the first gateway beside the routers

> **Status: NORMATIVE** · Scope: `gatewayd` on a gateway-role node with WAN uplinks ·
> Plan: gateway-as-network-edge (epic [#553]) Phase 3.4 · Last verified: 2026-09-09
>
> Companion documents: [`docs/gateway/user.md`](../gateway/user.md) (what each
> section configures), [`docs/gateway/architecture.md`](../gateway/architecture.md)
> (why the shape is what it is), [`docs/installer/`](../installer/) (how the
> binary and its OpenRC service get onto the node).

This is the procedure that brings a gateway up **beside** the routers it will
eventually replace, with **zero blast radius**: its tunnels and BGP sessions
come up against the live relays, it announces nothing, and the existing routers
stay the only origin of the address space throughout. Nothing here changes what
the internet sees. The cutover — the gateway taking the first-hop addresses and
the sessions — is a separate procedure ([#597]).

Read it end to end before starting. Every step says what it proves and how to
undo it.

---

## 1. What this proves, and what it deliberately does not

The gateway datapath has three independent halves, and this procedure exercises
them in the only order where a failure is cheap:

| Step | Proves | Blast radius if it fails |
|---|---|---|
| Tunnels up | The transport reaches both relays over both ISPs | none — the relays ignore an extra tunnel |
| Sessions up, announcing nothing | The speaker, its authentication, timers, filters and BFD | none — an iBGP client that exports no path changes no routing table |
| A test prefix originated and withdrawn | The origination path end to end, and that withdrawal is clean | one prefix nobody routes to |

What it does **not** prove, and must not be assumed from a green run:

- **Path preference.** The traffic-engineering attributes the routers apply
  (local-pref ladder, MED, AS-path prepend) cannot be expressed in gatewayd
  configuration yet ([#607]). Sessions establish and filter correctly; which
  path would win with more than one relay up is not yet the operator's choice.
  The cutover is blocked on that.
- **Return-path symmetry.** The per-uplink routing tables and rules that keep a
  tunnel's outer packets on the ISP they were sourced from are implemented in
  the tunnel package but not reachable from a gatewayd config ([#606]). Until
  that lands, pin the relay host routes statically (step 2, note).
- **Encrypted transport.** `transport: ipsec` is implemented and unreachable
  from configuration for the same reason ([#606]). Bring-up runs plain GRE,
  which is what the relays speak today.

None of the three is a reason to delay bring-up: each is additive, and the
sessions this procedure establishes are the thing they will later improve.

---

## 2. Preconditions

1. **The node runs gatewayd.** Alpine with OpenRC; `/etc/init.d/gatewayd` and
   the binary come from the installer ([`docs/installer/`](../installer/)), not
   by hand. `rc-service gatewayd status` reports it stopped or running, not
   missing.
2. **platformd is healthy on the same node** and owns the OVS bridge. gatewayd
   attaches to it; it does not create it.
3. **The control-plane identity exists** — `/etc/gatewayd/{client.pem,
   client-key.pem,cp-ca.pem}`. Without it the telemetry and desired-config loops
   are disabled and the gateway is invisible to the control plane; the datapath
   still works.
4. **The key store holds the session secrets** under the references the config
   names (`kms://…`). A reference that does not resolve fails the start with a
   typed error and programs nothing — that is the intended behaviour, not a bug
   to work around by inlining a key.
5. **The relay operators are ready.** The relay side needs the changes in
   section 7 before any session can establish. Coordinate: the gateway retrying
   a refused session is harmless, but you will be debugging the wrong end.
6. **You know the addressing.** For this site: the gateway holds
   `198.18.0.2` on the overlay and `23.143.36.4` as its public identity
   until the cutover (ruling R2, [#553]); the router VIPs stay untouched.

---

## 3. Step 1 — tunnels to both relays over both uplinks

Copy
[`configs/platform/templates/dedicated/supermicro/x10/gatewayd.yaml`](../../configs/platform/templates/dedicated/supermicro/x10/gatewayd.yaml)
to `/etc/gatewayd/config.yaml` and replace the addresses with this
deployment's. The `tunnels:` list is one entry per (relay × uplink) — the same
full mesh the routers run, so a single ISP or a single relay failing leaves two
tunnels standing:

```yaml
  tunnels:
    - name: gre-mia-att
      type: gre
      local: 99.12.246.38          # this gateway's address on the AT&T link
      remote: 45.63.110.165        # the Miami relay
      tunnel-ip: 10.255.0.33/30
      tunnel-ipv6: "2602:F5BB:CAFE:11::1/64"
    # … one per (relay × uplink)
```

Use tunnel subnets **no existing device uses**. The routers already own
`10.255.0.0/30` through `10.255.0.28/30` and `2602:F5BB:CAFE:1::/64` through
`:8::/64` for their own eight tunnels; the block above starts past them
deliberately. Reusing one silently steals a live session.

**The shipped template already has `transit:` and `bgp:` commented out**, so
this step needs no edit — copy it and start. That is deliberate: with those two
present the daemon does not reach the point where tunnels can be inspected at
all. `enabledServices` starts the transit service whenever a `bgp:` section
exists (`transit.enabled` is an OR, not a gate), transit starts the speaker,
and the speaker installs its policy set at start, which is where the dual-stack
defect below aborts startup. Step 2 uncomments the block, once [#619] is merged.

Start the daemon and confirm the interfaces exist and carry their
addresses:

```sh
rc-service gatewayd start
ip -brief link show type gre
ip -brief addr show gre-mia-att        # expect BOTH the /30 and the /64
```

> **Return-path note.** Until [#606] lands, add a host route per relay pinned to
> the uplink its tunnel is sourced from, or the kernel will hash the outer
> packets across both ISPs and the relay will see them arrive from an address
> its session does not expect:
> `ip route add 45.63.110.165/32 via <att-gateway> dev <att-if>`. Record what
> you added; step 6 removes it on rollback.

**Undo:** `rc-service gatewayd stop` removes every tunnel the daemon created.

---

## 4. Step 2 — iBGP sessions that announce nothing

The `bgp:` block establishes one session per tunnel. Three properties make this
step safe, and all three are visible in the template:

- **`announce:` is empty.** It is the export allow-list; with RFC 8212
  default-deny in force, an empty list means the session exports no path at
  all. The routers remain the only origin.
- **`max-prefixes` is small** (10). The relays send a default route and nothing
  else; a relay that suddenly offers a full table tears the session down instead
  of filling the gateway's RIB.
- **`import-allow` is explicit** — default route only, v4 and v6.

> **This step does not work yet, and it stops the daemon starting at all.**
> Uncomment the `transit:` and `bgp:` blocks the template ships commented, and
> the daemon will refuse to start rather than merely failing to peer: a peer
> whose `import-allow` names both an IPv4 and an IPv6 prefix — as all four in
> the template do — makes the speaker fail to start. Wait for [#619]. `policySet` builds one prefix set per direction holding every
> entry, and GoBGP refuses a prefix set that mixes address families:
> `NewPrefixSetFromApiStruct` returns `multiple families`
> (`internal/pkg/table/policy.go:478`). Every test in `pkg/sdn/bgp` drives a
> mock that accepts whatever it is handed, so nothing caught it. Tracked as
> [#620] and fixed by the traffic-engineering change ([#619]); until that
> merges, this step fails at `gatewayd serve` rather than at the session.
> Do not work around it by dropping `::/0` — a v4-only import is a different
> configuration from the one the cutover needs, and it would hide the defect.

Authentication: sessions use the TCP-MD5 compatibility path, which is what the
relays speak today. TCP-AO is the platform standard (ruling R1) and the keychain
is already in the template, but GoBGP 4.9 has no field binding a keychain to a
session, so a peer asking for `tcp-ao` is refused at start rather than run
unauthenticated. **A FIPS build refuses `md5`** — bring-up therefore runs a
non-FIPS build, and that is a decision to record for this deployment, not an
accident.

Restart and watch the sessions come up:

```sh
rc-service gatewayd restart
tail -f /var/log/trusted-platform/gatewayd.log
```

Confirm from the relay side (the gateway's own operator verbs are still stubs —
[#65]):

```sh
# on each relay
birdc show protocols all | grep -A5 <the new client>
```

Expect `Established`, and BFD up if the relay has it enabled. Expect **zero**
routes received from the gateway. A session that establishes and exports
something is a misconfiguration: stop and re-read `announce:`.

**Undo:** `rc-service gatewayd stop`. The relay's session drops on its hold
timer; nothing it learned changes, because it learned nothing.

---

## 5. Step 3 — originate one test prefix, then withdraw it

Use a prefix **the routers do not announce** and nobody routes to. Add it to
the export allow-list and restart:

```yaml
    announce:
      ipv4: ["23.143.36.128/25"]     # a test slice, not the /24 the routers own
      ipv6: []
```

```sh
rc-service gatewayd restart
```

Verify at **both** relays, not one:

```sh
birdc show route where net ~ [ 23.143.36.128/25 ]
birdc show route all 23.143.36.128/25        # the AS path must end at 401870
```

Then remove it and restart again, and confirm it is gone from both relays
within the hold time. A prefix that lingers after withdrawal is the finding
this step exists to catch — investigate before going further, because the
cutover depends on clean withdrawal.

> The operator verbs (`platformctl sdn gateway bgp announce|withdraw`) are
> documented but not wired on this path ([#65]); the config plus a restart is
> the supported route today. When [#65] lands, this step becomes two commands
> and no restart.

**Undo:** remove the prefix from `announce:`, restart, verify absence.

---

## 6. Step 4 — traffic-engineering parity (blocked)

The routers apply a local-pref ladder across the four sessions, MED on export
and an AS-path prepend toward the backup relay. **The gateway cannot express
any of it in configuration yet ([#607]).**

Do not attempt to substitute relay-side policy for it: preference configured at
the relay is not preference the gateway owns, and the cutover would silently
change behaviour when the routers' own policy leaves with them. Leave this step
open, and treat [#607] as a cutover prerequisite.

---

## 7. Relay-side changes (the other operator's work)

These are changes on the relay hosts, not on the platform. They are listed here
so both ends are planned together; the authority for the current relay topology
is the infrastructure documentation, not this file, and **no credential or
device configuration from that side belongs in this repository**.

1. **Accept the gateway as an additional iBGP client** — one neighbour per
   tunnel, same AS, `next hop self`, import filtered to the ARIN prefixes,
   export limited to the default route, matching MD5 secret.
2. **The tunnel interfaces** at the relay end of each new tunnel, with the
   matching addresses from step 1, brought up at boot like the existing ones.
3. **Firewall**: proto 47 from the gateway's two WAN addresses, and the session
   traffic inside each new tunnel interface.
4. **BFD**, if the relay runs it for the existing clients — same intervals as
   the template.
5. **Confirm the ROAs** for the announced space are valid for the origin AS
   before the cutover; upstreams that drop RPKI-invalid announcements will drop
   the gateway's the moment it originates in Phase 5.4.

---

## 8. The host packet filter

`hostfw:` is what stands between the WAN and the daemon's own sockets, and its
allowances are deliberately narrow:

- **GRE (proto 47) only from the relay addresses**, only on the WAN links.
- **BGP (179) and BFD (3784) only on the tunnel interfaces** — never on the WAN
  links themselves, so a scan of the public address finds nothing.
- ICMP and ICMPv6 rate-limited, with neighbour discovery always allowed.

Verify after the sessions are up:

```sh
nft list table inet tp_host
nmap -Pn -p 179,3784 <the gateway's public address>     # both filtered
nmap -Pn -p 179 <the gateway's tunnel address>          # open from the relay only
```

A listener that answers on the WAN address is a finding: the inventory the
service renders from is the set of listeners the daemon declared, so an
unexpected open port means something is listening that nobody declared.

---

## 9. Verification checklist

Run all of it, in order, before calling bring-up done:

- [ ] All tunnel interfaces exist and hold their addresses (`ip -brief addr`).
- [ ] Every session **Established** at the relay, and holding for at least one
      full hold-timer cycle without a flap.
- [ ] BFD up on every session that has it enabled.
- [ ] **Zero** prefixes received from the gateway at either relay.
- [ ] The existing routers' sessions are unchanged — same count, same uptime,
      no flap in their logs during the whole procedure. *This is the one that
      matters: bring-up is a success only if nothing else moved.*
- [ ] The test prefix appeared at both relays and disappeared cleanly.
- [ ] `nft list table inet tp_host` shows the intended allowances and a `drop`
      policy; the port scan above is filtered on the WAN address.
- [ ] The control plane shows the gateway reporting (`/api/v1/gateway/state`),
      and its snapshot's service statuses match what is actually running.
- [ ] The node's own management access still works from a second session that
      you opened **before** starting.

---

## 10. Rollback

In reverse order, and each step is independent:

1. Remove the test prefix from `announce:` and restart.
2. `rc-service gatewayd stop` — every tunnel, session and flow the daemon
   created goes with it. The base pipeline is removed and the bridge's previous
   fail-mode restored, so platformd's own flows keep working.
3. Remove the static relay host routes added in step 1's note.
4. `rc-update del gatewayd default` if the node should not start it again.

platformd is untouched throughout: it owns the bridge, gatewayd only adds to it
and cleans up after itself on stop.

---

## 11. Known gaps at bring-up

| Gap | Effect on bring-up | Issue |
|---|---|---|
| `tunnels:` drops `transport`/`uplink`/`ipsec`/`wireguard` | GRE only; uplink pinning is static routes | [#606] |
| No TE attributes in config | No path preference; cutover blocked | [#607] |
| Gateway BGP operator verbs are stubs | Announce/withdraw is config plus restart | [#65] |
| TCP-AO cannot bind a keychain to a session | MD5 compat path; non-FIPS build for bring-up | upstream GoBGP |
| One prefix set per direction mixes v4 and v6 | **Daemon will not start at all** once `bgp:` is present — the template therefore ships with `transit:`/`bgp:` commented out | [#620] |
| Transit starts whenever `bgp:` exists | `transit.enabled: false` does not gate it; the section must be absent to keep the speaker out of a start | [#620] |

[#553]: http://git.example.internal/jeremyhahn/go-trusted-platform/issues/553
[#597]: http://git.example.internal/jeremyhahn/go-trusted-platform/issues/597
[#606]: http://git.example.internal/jeremyhahn/go-trusted-platform/issues/606
[#607]: http://git.example.internal/jeremyhahn/go-trusted-platform/issues/607
[#65]: http://git.example.internal/jeremyhahn/go-trusted-platform/issues/65
[#620]: http://git.example.internal/jeremyhahn/go-trusted-platform/issues/620
[#619]: http://git.example.internal/jeremyhahn/go-trusted-platform/pulls/619
