# DNS Configuration Reference

> **Status: REFERENCE** · Last verified: 2026-10-18
> The `dns:` section of the platform configuration (`Config`, `pkg/dns/config.go`).

## Where it is read

The `dns:` section is part of the platform configuration file. platformd
reads exactly one file: the one `--config` names, or else the first
`config.yaml` it finds in this order (`pkg/app/app.go:1549`):

| Location | Description |
|----------|-------------|
| `etc/config/trusted-platform/config.yaml` | Relative to the working directory |
| `<platform-dir>/etc/config.yaml` | Platform home (`--platform-dir`) |
| `~/.trusted-platform/config.yaml` | User-specific configuration |
| `<config-dir>/config.yaml` | `--config-dir`, default `/etc/trusted-platform` |
| `./config.yaml` | Working directory |

Files are not merged: the first one found is the whole configuration. Only
when no `config.yaml` exists in any of these locations does platformd look
for `config.<env>.yaml` (`--env`, default `dev`) in the same locations.

The file is decoded with `viper.Unmarshal` (`pkg/app/app.go:1572`), so the key
names below are the structs' `mapstructure` tags. Where a `yaml` tag differs
(SOA `min_ttl`, DS `digest_type` / `key_tag`, TLSA `matching_type`, zone
`tenant_id`), the `mapstructure` name is the one the file must use.

No `dns.*` key is read from the environment: only the daemon listener keys
are ([docs/daemon/configuration.md](../daemon/configuration.md)).

## Top-level keys

| Key | Type | Default | Read by |
|-----|------|---------|---------|
| `allow-registration` | bool | `false` | Master switch for the `Register` route (`pkg/dns/service.go:364`) |
| `allow-external-registration` | bool | `false` | `Register` into a public zone (`service.go:420`) |
| `allow-internal-registration` | bool | `false` | `Register` into an internal zone (`service.go:424`) |
| `default-ttl` | int | `0` | TTL of every record and zone the service creates without one: `Register`, the network sub-zone records, `CreateZone`, and an `AddRecord` with TTL 0 (`Config.RecordTTL`, `pkg/dns/config.go`). `0` means 3600. `dns.Run` refuses a value outside 0 to 2147483647 (RFC 2181 §8) with `ErrInvalidTTL` |
| `private-ipv4`, `private-ipv6` | string | detected | `${PRIVATE_IPv4}` / `${PRIVATE_IPv6}`, and the internal-zone record each webservice registers. Empty means the host's detected address (`pkg/app/app.go:1225`) |
| `public-ipv4`, `public-ipv6` | string | detected | `${PUBLIC_IPv4}` / `${PUBLIC_IPv6}`, and the public-zone record each webservice registers |
| `zone-subdomains` | bool | `false` | One internal sub-zone per SDN network zone; see [user.md](user.md) |
| `quicbaas` | map | below | Zone storage |
| `public`, `internal` | map | below | The two listeners and their zones |
| `resolver` | map | below | The daemon's own resolver |
| `dnssec` | map | off | [Signing](#dnssec) |
| `dane` | map | off | [TLSA generation](#dane) |
| `transfer` | map | off | [AXFR](#zone-transfer) |
| `dns64` | map | off | [DNS64](#dns64) |
| `attestation` | map | off | [Parsed, not read](#attestation) |

Anything else under `dns:` is ignored. There is no `shard-id`, `partition`,
`ddns` or `scheduler` key.

## quicbaas

Zones are stored through go-quicbaas (`quicbaas.NewFactory`,
`pkg/dns/plugin.go:474`) under the `dns/zones` partition. The keys are the
`quicbaas.Config` struct (`pkg/storage/quicbaas/config.go`). The defaults:

```yaml
dns:
  quicbaas:
    storage-backend: pebble
    data-dir: trusted-data/quicbaas
    wal-dir: trusted-data/quicbaas/wal
    spiffe-trust-domain: example.internal
    node-id: 1
    cache-size: 67108864       # 64 MiB
    log-level: warn
    consistency-level: linearizable
```

The other keys (`transport`, `address`, `unix-socket`, `raft-address`,
`raft-listen-address`, `join-addresses`, `deployment-id`,
`raft-tls-cert-file` / `-key-file` / `-ca-file`, `compression`, `sync-writes`,
`request-timeout`, `startup-timeout`) select a remote or clustered store.

## Servers

`public` and `internal` have the same three keys:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `port` | int | `8053` public, `9053` internal | UDP/TCP listen port |
| `forwarders` | list | public `4.4.4.4`, `8.8.8.8`; internal `198.51.100.1`, `198.51.100.2`, `198.51.100.3` | Upstreams for names outside the server's zones |
| `zone` | map | `example.com.` / `example.internal.` | The server's zone, below |

The internal server answers internal zones; the public server drops queries for
them and logs a security event ([security.md](security.md)). Resolution and
forwarding are in [resolution.md](resolution.md).

## Zones

A zone (`entities.Zone`) has `id`, `name`, `tenant_id`, `ttl`, `description`,
`internal`, optional per-zone `ksk` / `zsk` key configs, and `records`.
`records` holds one list per type: `a`, `aaaa`, `cname`, `mx`, `ns`, `srv`,
`txt`, `caa`, `tlsa`, `ds`, `key` (DNSKEY), `rrsig`, `nsec`, `nsec3`,
`nsec3param`, and a single `soa`.

```yaml
dns:
  internal:
    port: 9053
    forwarders: ["192.0.2.1"]
    zone:
      name: example.internal.
      ttl: 3600
      internal: true
      records:
        soa:
          name: example.internal.
          mname: ns1.example.internal.
          rname: hostmaster.example.internal.
          serial: 1
          refresh: 86400
          retry: 7200
          expire: 86400
          min_ttl: 3600
          ttl: 3600
        ns:
          - {name: example.internal., value: ns1.example.internal., ttl: 3600}
        a:
          - {name: ns1, value: "${PRIVATE_IPv4}", ttl: 3600}
          - {name: "${HOSTNAME}", value: "${PRIVATE_IPv4}", ttl: 3600}
```

Each record type's fields are in [records.md](records.md); owner names (`@`,
relative and fully qualified) are in [records.md](records.md#owner-names). The
zone model is in [zones.md](zones.md).

## Macros

At startup the configured zones are expanded (`Expand`, `pkg/dns/macros.go:90`,
called from `pkg/dns/plugin.go:623`). If the local hostname cannot be read,
startup fails with `ErrHostnameLookup`. `${NAME}` is replaced in the name and
value of A, AAAA, CNAME, MX, NS and TXT records and in the name and target of
SRV records. SOA, CAA, TLSA and DNSSEC records are not expanded.

| Macro | Value |
|-------|-------|
| `${PRIVATE_IPv4}`, `${PRIVATE_IPv6}` | `dns.private-ipv4` / `-ipv6` |
| `${PUBLIC_IPv4}`, `${PUBLIC_IPv6}` | `dns.public-ipv4` / `-ipv6` |
| `${PREFERRED_IP}` | The host's preferred IPv4 address |
| `${HOSTNAME}` | `os.Hostname()` |
| `${PUBLIC_DOMAIN}`, `${PRIVATE_DOMAIN}` | `dns.public.zone.name` / `dns.internal.zone.name` |
| `${PUBLIC_FQDN}`, `${PRIVATE_FQDN}` | `<hostname>.<zone name>` |

Macros are not environment variables: an unknown `${NAME}` expands to the
empty string.

## DNSSEC

`dnssec:` has `enabled`, `default-key` (the platform `KeyConfig`), `ksk` and
`zsk` (`key`, `lifetime`, `ttl`), `signature-expiry`, `nsec-mode`,
`nsec3-iterations` and `nsec3-salt`. Every key, its default and what reads it
is in [dnssec.md](dnssec.md#configuration). Two rules from the code:

- With `enabled`, every zone save re-signs the zone.
- Under FIPS mode, `nsec-mode: nsec3` stops startup with
  `ErrFIPSNSEC3Unsupported` (`DNSSECConfig.Validate`, `pkg/dns/config.go`).

`ksk.lifetime` and `zsk.lifetime` are validated but not acted on: with
`enabled`, a lifetime that is not a positive duration (`365d`, `720h`) stops
startup with `ErrInvalidKeyLifetime`, and there is no automatic rollover
([dnssec-rollover.md](dnssec-rollover.md)).

## DANE

| Key | Type | Read by |
|-----|------|---------|
| `enabled` | bool | TLSA publication for webservice certificates (`pkg/app/app.go:4287`) and BMC certificates |
| `auto-generate` | bool | TLSA records generated on certificate issuance |
| `default-port` | uint16 | Port label of the TLSA owner name (`_443._tcp`) |
| `ttl` | uint32 | TTL of generated TLSA records. The ACME hook defaults 0 to 3600; the other paths publish it as set |
| `default-usage` | uint8 | TLSA usage (0 PKIX-TA, 1 PKIX-EE, 2 DANE-TA, 3 DANE-EE), ACME hook only; the publisher always writes 2, and 3 for DANE-EE |
| `default-selector` | uint8 | 0 full certificate, 1 SPKI |
| `default-matching-type` | uint8 | 0 full, 1 SHA-256, 2 SHA-512 |
| `publish-dane-ee` | bool | Also publish a DANE-EE record from the leaf (`pkg/bootstrap/dane_publisher.go`) |
| `rollover-ttl` | uint32 | TTL of a pre-published BMC rollover record; 0 means 2 × `ttl` |
| `key-reuse` | bool | **Parsed, no effect**: its only reader, `RolloverManager`, is never constructed |

See [dane.md](dane.md).

## Zone transfer

```yaml
dns:
  transfer:
    enabled: true
    tsig-keys:
      - {name: secondary1., algorithm: hmac-sha256, secret: "<base64>"}
```

AXFR to TSIG-authenticated secondaries; absent or disabled refuses every
transfer. See [zone-transfer.md](zone-transfer.md).

## DNS64

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `false` | Synthesise AAAA answers (RFC 6147) |
| `prefix` | `64:ff9b::/96` | RFC 6052 prefix; must match the NAT64 translator's |
| `translate-all` | `false` | Synthesise even when the name has AAAA records |
| `allow-ipv4` | `false` | Synthesise for queries that arrive over IPv4 |
| `servers` | internal only | `internal`, `public`, or both |

See [user.md](user.md) for the NAT64 half.

## Resolver

The daemon's own resolver (`ResolverConfig`, `pkg/dns/resolver.go`):

```yaml
dns:
  resolver:
    servers:
      - {address: 127.0.0.1, port: 8053}
    fallback:
      - {address: 1.1.1.1, port: 53}
      - {address: 8.8.8.8, port: 53}
    search-domains: []
    local-forwarder:
      enabled: false
      listen: 127.0.0.1:53
      cache-size: 1000
```

See [resolution.md](resolution.md).

## Attestation

`attestation:` (`enabled`, `required`, `max-age`, `default-pcr-policy`,
`fallback`, `pcr-policies`) is parsed into `Config.Attestation`, but no runtime
code reads it: the `pkg/dns/attestation` package is not wired into any route.
Setting it has no effect.

## Planned

DNS-over-TLS and DNS-over-HTTPS have no configuration yet; their proposed keys
are in [dot-doh.md](dot-doh.md).

## See Also

- [Zones](zones.md) · [Records](records.md) · [Resolution](resolution.md)
- [DNSSEC](dnssec.md) · [DNSSEC rollover](dnssec-rollover.md) · [DANE](dane.md)
- [Zone transfer](zone-transfer.md) · [Security](security.md)
