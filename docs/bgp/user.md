# BGP Speaker — User Guide

> **Status: NORMATIVE** · Scope: `pkg/sdn/bgp/` and the gatewayd services that run it · Last verified: 2026-10-14
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

BGP runs only on a gateway, in `gatewayd`. You configure it in the gateway's
config file, under `gateway:`. The worked example is the x10 profile's
`configs/platform/templates/dedicated/supermicro/x10/gatewayd.yaml`
(`bgp:` at line 90, `overlay:` at 175). Every key is listed in
[engineering.md §5](engineering.md#5-configuration).

## 1. Peer with an upstream router

Add a `bgp:` section. That alone turns the transit service on
(`pkg/sdn/gateway/types.go:1490`).

```yaml
gateway:
  bgp:
    router-id: 203.0.113.4
    asn: 64500
    peers:
      - name: upstream-a
        address: 198.51.100.1
        asn: 64496
        auth-type: md5
        auth-key-ref: kms://platform/bgp/upstream-a
        families: [ipv4-unicast, ipv6-unicast]
        max-prefixes: 10
        policy:
          import-allow:
            - prefix: 0.0.0.0/0
            - prefix: "::/0"
```

- **Both directions reject by default.** A peer with no `policy` exchanges
  nothing (`pkg/sdn/bgp/policy.go:27-33`). Use `import-allow` and
  `export-allow` to list what may pass, or set `import-default-accept` /
  `export-default-accept` to accept everything.
- **Secrets are references.** `auth-key-ref` names a secret, which is
  resolved when the service starts. The key itself never goes in the file.
- **MD5 is refused in FIPS builds** (`ErrAuthTypeUnavailableInFIPS`). Use
  `auth-type: none` there, until TCP-AO works.
- **Do not use `auth-type: tcp-ao` yet.** The config validates, but the peer
  is refused when the service starts, with
  `ErrTCPAOSessionBindingUnsupported` (`pkg/sdn/bgp/speaker.go:580`).
  Because a refused peer stops the speaker, the whole transit service then
  fails to start. **Planned**, blocked on GoBGP; no issue number is recorded.

## 2. Detect a dead link faster

Add BFD to the peer:

```yaml
        bfd:
          enabled: true
          desired-min-tx-interval: 300ms
          required-min-rx-interval: 300ms
          detection-multiplier: 3
```

Intervals below 50 ms are refused (`ErrBFDIntervalTooShort`). BFD uses UDP
port 3784 unless `port` is set.

## 3. Prefer one upstream over another

Set an import attribute on the preferred peer:

```yaml
        policy:
          import:
            local-pref: 200
```

`med`, `prepend` and `communities` work the same way. Which attributes are
valid in which direction is checked at load
(`pkg/sdn/bgp/attributes.go:383`).

## 4. Announce the site's prefixes

**You cannot, on main.** The transit speaker originates no routes
([architecture.md §4](architecture.md#4-routes-it-originates)).

`announce:` does not announce anything. It is the default export allowlist
for any peer without an `export-allow` (`pkg/sdn/bgp/policy.go:118-121`). The
template leaves it empty (`gatewayd.yaml:157-163`).

`platformctl sdn gateway bgp announce` answers "not configured", because
`platformd` holds no speaker ([api.md §2](api.md#2-behaviour-on-main)).

**Planned (#553)** for the announcement itself, and **(#65)** for the
operator verbs.

## 5. Join the overlay's EVPN control plane

List your route reflectors under the overlay section's `rr-peers`:

```yaml
gateway:
  overlay:
    enabled: true
    overlay-asn: 65000
    rr-peers:
      - name: rr-1
        address: 198.51.100.10
        asn: 65000
        families: [evpn]
```

- **`overlay-asn` must be 64512–65534** (`pkg/sdn/gateway/types.go:531-536`).
- **No `passive` reflectors.** The overlay speaker only dials out, so a
  passive rr-peer is refused (`types.go:540-544`).
- **Route targets.** They are `ASN:(1<<28 | VNI)` for domain 0. VNI 10100
  under ASN 65000 is `65000:268445556`
  ([engineering.md §7](engineering.md#7-evpn)). An rr-peer without
  `import-route-targets` or `export-route-targets` gets, in that direction,
  the route target of every configured VNI
  (`pkg/sdn/gateway/handlers.go:1033-1053`). A list you write is kept as it is.
- **The reflectors are yours.** The platform does not run a route reflector
  ([architecture.md §2](architecture.md#2-who-runs-a-speaker)).

## 6. Check that sessions are up

```bash
platformctl sdn gateway snapshot --gateway-id <gateway-id>
```

The BGP section shows the local ASN, the router ID, and each transit peer's
state and received prefixes. The overlay EVPN sessions are not shown.

The same data is exported as Prometheus metrics:

- `gatewayd_bgp_peer_established`;
- `gatewayd_bgp_peer_uptime_seconds`;
- `gatewayd_bgp_peer_prefixes`;
- `gatewayd_bfd_session_up`;
- `gatewayd_bfd_failure_transitions_total`.

See [engineering.md §9](engineering.md#9-observability).

## 7. When it does not start

| Error | Cause | Fix |
|---|---|---|
| `ErrServiceUnavailable` "the transit service needs a bgp: section" | `transit.enabled` without `bgp:` | Add `bgp:` |
| `ErrServiceUnavailable` "overlay EVPN route targets require a 2-byte overlay ASN" | `overlay-asn` above 65535 | Use 64512–65534 |
| `ErrInvalidRouterID` / `ErrInvalidASN` | Bad `router-id` or `asn` | Fix the value |
| `ErrAuthSecretRequired` | `md5` without `auth-key-ref` | Add the reference |
| `ErrSecretResolutionFailed` / `ErrSecretEmpty` | The referenced secret is missing or empty | Store the secret |
| `ErrKeychainNotFound` | A `tcp-ao` peer names an unknown keychain | Fix `keychain` |
| `ErrTCPAOSessionBindingUnsupported` | Any `tcp-ao` peer | Use `md5` or `none` (§1) |
| `ErrPassivePeerWithoutListener` | A `passive` rr-peer | Remove `passive` |
| `ErrInvalidHoldTime` | `hold-time` 1 or 2 | Use 0 or at least 3 |

A session that reaches its `max-prefixes` (or `max-evpn-prefixes`) is shut
down; a warning is logged at 80%
([engineering.md §8](engineering.md#8-failure-handling-and-restart)).

## 8. Restart behaviour

- A dropped session is retried every `connect-retry` seconds (default 120).
- Graceful restart is on by default (120 s). Turn it off with
  `graceful-restart: false`.
- When the gateway runs its services as supervised processes, a crashed
  routing process is restarted with backoff, at most 5 times in 5 minutes. See
  [gateway architecture](../gateway/architecture.md).
