# BGP Configuration Reference

## Overview

This document provides a comprehensive configuration reference for the go-trusted-platform BGP service, covering speaker configuration, EVPN settings, transit options, and security parameters.

## Decoded schema (normative since #556, 2026-09-08)

The `bgp:` block gatewayd actually decodes is `bgp.BGPConfig`
(`pkg/sdn/bgp/types.go`), read from the gateway configuration's `gateway.bgp`
key through viper/mapstructure with a TextUnmarshaler hook
(`pkg/sdn/gateway/commands/assembly.go`). Every key below is a struct tag on
that type; a key not listed here is not decoded. The examples further down
this file predate the tags (they use `neighbors:`, `md5_secret`, underscore
keys) and are **superseded** where they disagree with this section.

```yaml
gateway:
  bgp:
    asn: 64512
    router-id: 203.0.113.4
    listen-port: 179                 # default 179
    listen-addresses: []             # default: every address
    tier: datacenter                 # backbone | datacenter | coordinator | (unset)
    graceful-restart: true           # RFC 4724; default ON when absent
    graceful-restart-time: 120       # seconds, default 120
    multipath: false
    families: [ipv4-unicast, ipv6-unicast]
    route-reflector: false
    cluster-id: ""
    announce:                        # prefixes this speaker originates
      ipv4: [203.0.113.0/24]
      ipv6: [2001:db8::/36]
    keychains:                       # TCP-AO keychains peers reference by name
      - name: vps
        keys:
          - send-id: 1
            receive-id: 1
            algorithm: hmac-sha256-128   # hmac-sha256-96 | aes-128-cmac-96 | hmac-sha1-96
            master-key-ref: kms://platform/bgp/vps-key-1
    peers:
      - name: popa-ispa
        address: 10.4.255.2
        asn: 64512
        auth-type: md5               # none | md5 (!fips builds only) | tcp-ao
        auth-key-ref: kms://platform/bgp/popa-ispa
        hold-time: 30
        keepalive-interval: 10
        connect-retry: 120
        passive: false
        ebgp-multihop: 0
        route-reflector-client: false
        remove-private-as: false
        admin-down: false
        families: [ipv4-unicast, ipv6-unicast]
        max-prefixes: 10             # each unicast family; default 1000; session torn down at the limit
        max-evpn-prefixes: 100000    # l2vpn-evpn; default 100000 (VTEPs x MACs, not 1000)
        bfd:
          enabled: true
          port: 3784
          desired-min-tx-interval: 300ms
          required-min-rx-interval: 300ms
          detection-multiplier: 3
        policy:                      # RFC 8212: reject by default, both directions
          import-allow:
            - prefix: 0.0.0.0/0      # exact match unless max-length widens it
            - prefix: ::/0
          export-allow: []           # empty = exactly the announce prefixes
          import-route-targets: []   # l2vpn-evpn: admit a route carrying one of these; empty = none
          export-route-targets: []   # l2vpn-evpn: announce a route carrying one of these; empty = none
          import-default-accept: false
          export-default-accept: false
          import:                    # traffic engineering on paths received
            local-pref: 200
            large-communities:
              action: add            # add | remove | replace
              values: ["64512:1:200"]
          export:                    # traffic engineering on paths announced
            med: 50
            prepend:
              count: 3               # 1..10; asn defaults to the speaker's own
              asn: 64512
            communities:
              action: add
              values: ["no-export"]
```

**Secrets are references, never values** (`configuration.md` §4). `auth-key-ref`
and `master-key-ref` name a secret reference URI (`kms://`, `file://`,
`idevid://`, …) that the daemon resolves at boot through
`BGPConfig.ResolveSecrets(ctx, resolver)`; the `bgp` package never resolves a
reference itself and never decodes a secret from YAML. An unresolved reference
stops the boot.

**Session authentication.** TCP-AO (RFC 5925) is the standard (ruling R1,
2026-09-07). TCP-MD5 (`auth-type: md5`) is the compatibility path for peers
that speak nothing newer and is **compiled out of FIPS builds**: under the
`fips` build tag a peer with `auth-type: md5` is refused at validation with
`ErrAuthTypeUnavailableInFIPS`. TCP-AO keychains are registered with GoBGP at
start; GoBGP v4.9.0 stores keychains but carries no field binding one to a
neighbor session, so a peer with `auth-type: tcp-ao` is currently **refused**
with `ErrTCPAOSessionBindingUnsupported` rather than run unauthenticated. The
refusal is lifted the moment the linked GoBGP release binds keychains to
neighbors.

**Policy.** Both directions default to reject (RFC 8212). `import-allow` is the
only way a unicast prefix from a peer enters the RIB; `export-allow` defaults to
the `announce` prefixes. An l2vpn-evpn route is admitted by route target instead:
it is imported when it carries one of `import-route-targets` and announced when
it carries one of `export-route-targets`. Both lists are empty by default, so a
peer with EVPN enabled and no route targets exchanges no EVPN routes. A route
target is `<asn>:<number>` (an AS up to 65535 takes a 32-bit number, a larger AS
a 16-bit one) or `<ipv4>:<number>` (16-bit number); anything else, including a
number too large for its form, is refused at load with `ErrRouteTargetInvalid`.

**How the policy is installed (#717).** GoBGP honours a per-peer policy
assignment only on a route-server client: `ApplyPolicy` looks the assignment up
by `peer.TableID()`, which is the global RIB for every other peer, and
`setPeerPolicy` discards the per-peer one (GoBGP v4.9.0 `server.go`). The
speaker used to attach each peer's policy that way, so on every session — transit
included — nothing was filtered and none of the `import:` / `export:` attributes
applied. The policy is now **two global policies**, `tp-import` and `tp-export`,
assigned once to the global RIB at start with a reject default. Each peer
contributes statements to both, every one conditioned on a neighbor set holding
only that peer's address; GoBGP matches it against the peer a path came from on
import and the peer it is going to on export. The import policy opens with one
statement accepting locally originated paths, because GoBGP runs those through
the global import policy too; what leaves the speaker is still decided by the
export statements. `import-default-accept` / `export-default-accept` become a
last per-peer statement that accepts anything from or to that peer. The two
policy names never change, so a peer added at runtime re-installs the
definitions and the assignment keeps resolving to them.

**Prefix limits.** `max-prefixes` applies to each unicast family separately
(default 1000). `max-evpn-prefixes` applies to l2vpn-evpn (default 100000). It is
a separate field because an EVPN session carries a Type-2 route per MAC/IP
binding and a Type-3 route per VTEP and EVI: the route-reflector sessions are
sized by the fabric, and the unicast default would tear a healthy one down at its
thousand-and-first MAC. Size it to VTEPs x MACs plus headroom. GoBGP warns at
80 % of a limit and tears the session down when the peer exceeds it.

**Traffic engineering.** `policy.import` and `policy.export` carry the path
attributes that rank one session against another. Without them a speaker with
two relays reachable establishes correct sessions and lets GoBGP's tie-breaks
decide which one carries traffic, which is not a choice an operator made.

| Field | Direction it belongs in | Effect |
|---|---|---|
| `local-pref` | import (export only on an iBGP session) | Ranks this session ahead of the others carrying the same prefix. Highest wins, before every other tie-break. |
| `med` | export | The hint the neighbouring AS uses to pick an entry point into this one. Replaces whatever arrived; it does not offset it. |
| `prepend` | export | Repeats an AS number `count` times, lengthening the path so it loses wherever AS-path length decides. `asn` defaults to the speaker's own. |
| `communities` | either | Standard communities (RFC 1997). |
| `large-communities` | either | Large communities (RFC 8092). |

Each direction of a peer becomes an attribute statement with no route action
and only the peer's neighbor set as its condition, followed by one prefix filter
per unicast family and, when route targets are configured, one route-target
filter restricted to l2vpn-evpn. GoBGP applies the attribute statement's actions
and falls through, so the attributes hold for everything the peer sends or is
sent rather than only for the allowlist — which is what keeps them correct when a
direction is opted into accept-by-default.

The filter is split per family because GoBGP refuses a prefix set holding both
(#620); a path is only ever admitted by its own family's statement, and anything
outside every list falls through to the reject default.

A community block names **one** `action` and its `values`, because GoBGP carries
one community action per direction; parallel add and remove lists would mean
programming one and dropping the other. A `remove` value is matched as a regular
expression, so `"^64512:1:"` clears a whole block.

**A 32-bit AS number cannot be written as a standard community.** RFC 1997 packs
two 16-bit halves into one 32-bit attribute, so an AS above 65535 does not fit; tagging
from a 32-bit ASN uses large communities.

**Anything the speaker cannot program is refused at configuration load**, never
accepted and dropped on the wire. `AddPeer` applies the same gate, so a peer
added at runtime cannot install what a configured one could not:

| Refused | Reason |
|---|---|
| `local-pref: 0` | GoBGP treats a zero local-pref action as no action at all. Omit the field to leave LOCAL_PREF alone. |
| `prepend.count` of 0, or above 10 | Zero repeats nothing; GoBGP narrows the count to a byte, so a large value wraps silently. |
| `prepend.asn` of 23456, 65535 or 4294967295 | Reserved; must not appear in an AS_PATH (RFC 6793 §9, RFC 7300). |
| A community action with no values, or an unknown action | Installs an action that changes nothing. |
| A malformed community | Validated against the same spellings GoBGP accepts — a 32-bit number, `asn:value`, or a well-known name such as `no-export` — but anchored, so a value with text around it is an error rather than a silently truncated community. |
| `export.local-pref` toward an eBGP peer | RFC 4271 §5.1.5: LOCAL_PREF is never sent to an external peer, so the field would read as applied and do nothing. |

**BFD** is GoBGP's native single-hop implementation (RFC 5881); intervals are
durations with a 50 ms floor.

## Configuration Structure

### YAML Configuration

```yaml
bgp:
  # Global BGP settings
  global:
    asn: 65001
    router_id: "203.0.113.1"
    listen_port: 179
    listen_addresses:
      - "0.0.0.0"
      - "::"

  # Speaker role configuration
  speaker:
    role: "backbone"  # backbone, datacenter, coordinator
    cluster_id: "1.1.1.1"  # For route reflection

  # Neighbor/peer configuration
  neighbors:
    - address: "198.51.100.1"
      remote_asn: 64500
      description: "ISP-Primary"
      type: "ebgp"
      md5_secret: "${BGP_ISP_PRIMARY_SECRET}"
      families:
        - afi: "ipv4"
          safi: "unicast"
        - afi: "ipv6"
          safi: "unicast"
      timers:
        hold_time: 90
        keepalive_interval: 30
      bfd:
        enabled: true
        interval: 300  # milliseconds
        multiplier: 3

  # EVPN configuration
  evpn:
    enabled: true
    rd_type: "type1"  # ASN:assigned
    rt_auto: true
    vni_range:
      start: 10000
      end: 19999

  # Transit configuration
  transit:
    enabled: true
    prefixes:
      ipv6:
        - "2001:db8::/36"
      ipv4:
        - "203.0.113.0/24"
    rpki:
      enabled: true
      servers:
        - address: "rpki-validator.example.com"
          port: 8323
      policy:
        valid: "accept"
        invalid: "reject"
        not_found: "accept"
    dampening:
      enabled: true
      half_life: "15m"
      suppress_threshold: 2000
      reuse_threshold: 750
      max_suppress_time: "60m"

  # Route signing
  signing:
    enabled: true
    quorum: 3
    coordinators:
      - "coordinator-1.example.com:9443"
      - "coordinator-2.example.com:9443"
      - "coordinator-3.example.com:9443"

  # Logging and monitoring
  logging:
    level: "info"
    format: "json"
  metrics:
    enabled: true
    port: 9179
```

## Global Configuration

### ASN (Autonomous System Number)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `asn` | uint32 | Yes | - | Platform AS number |
| `router_id` | string | Yes | - | BGP router ID (IPv4 format) |
| `listen_port` | uint16 | No | 179 | BGP listen port |
| `listen_addresses` | []string | No | ["0.0.0.0", "::"] | Listen addresses |

```go
type GlobalConfig struct {
    ASN             uint32   `yaml:"asn"`
    RouterID        string   `yaml:"router_id"`
    ListenPort      uint16   `yaml:"listen_port"`
    ListenAddresses []string `yaml:"listen_addresses"`
}
```

### Router ID Selection

Router ID should be:
- Unique within the AS
- Stable (does not change)
- Typically the loopback IP or a routable IP

```yaml
# Recommended: Use a stable, routable IPv4 address
global:
  router_id: "203.0.113.1"  # From platform IPv4 block
```

## Speaker Configuration

### Role Types

| Role | Description | Use Case |
|------|-------------|----------|
| `backbone` | Core speaker for ISP peering | Aggregate announcements |
| `datacenter` | Regional speaker for local routing | Regional /48 prefixes |
| `coordinator` | Control plane for route signing | No direct BGP peering |

```yaml
speaker:
  role: "backbone"

  # Route reflector settings (optional)
  route_reflector:
    enabled: false
    cluster_id: "1.1.1.1"
    clients:
      - "10.0.0.2"
      - "10.0.0.3"
```

### Speaker-Specific Settings

```go
type SpeakerConfig struct {
    Role           SpeakerRole `yaml:"role"`
    ClusterID      string      `yaml:"cluster_id"`
    RouteReflector *RRConfig   `yaml:"route_reflector"`
}

type SpeakerRole string

const (
    RoleBackbone    SpeakerRole = "backbone"
    RoleDatacenter  SpeakerRole = "datacenter"
    RoleCoordinator SpeakerRole = "coordinator"
)
```

## Neighbor Configuration

### Peer Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `address` | string | Yes | - | Peer IP address |
| `remote_asn` | uint32 | Yes | - | Peer AS number |
| `description` | string | No | "" | Human-readable description |
| `type` | string | No | "ebgp" | Peer type (ebgp/ibgp) |
| `md5_secret` | string | No | "" | MD5 authentication secret |
| `passive` | bool | No | false | Wait for incoming connection |
| `enabled` | bool | No | true | Enable/disable peer |

```yaml
neighbors:
  # eBGP peer (ISP)
  - address: "198.51.100.1"
    remote_asn: 64500
    description: "ISP-Primary-Transit"
    type: "ebgp"
    md5_secret: "${BGP_ISP_PRIMARY_SECRET}"
    enabled: true

  # iBGP peer (internal)
  - address: "10.0.0.2"
    remote_asn: 65001  # Same AS
    description: "Backbone-Speaker-2"
    type: "ibgp"
    md5_secret: "${BGP_IBGP_SECRET}"
```

### Address Families

| AFI | SAFI | Description |
|-----|------|-------------|
| ipv4 | unicast | IPv4 unicast routing |
| ipv6 | unicast | IPv6 unicast routing |
| l2vpn | evpn | EVPN for overlay |

```yaml
neighbors:
  - address: "198.51.100.1"
    families:
      - afi: "ipv4"
        safi: "unicast"
        enabled: true
      - afi: "ipv6"
        safi: "unicast"
        enabled: true
      - afi: "l2vpn"
        safi: "evpn"
        enabled: false  # No EVPN with ISP
```

### Timer Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hold_time` | int | 90 | Hold timer (seconds) |
| `keepalive_interval` | int | 30 | Keepalive interval (seconds) |
| `connect_retry` | int | 30 | Connection retry interval |
| `min_advertisement_interval` | int | 30 | Min time between UPDATE messages |

```yaml
neighbors:
  - address: "198.51.100.1"
    timers:
      hold_time: 90
      keepalive_interval: 30
      connect_retry: 30
      min_advertisement_interval: 30
```

### BFD (Bidirectional Forwarding Detection)

Fast failure detection for BGP sessions:

```yaml
neighbors:
  - address: "198.51.100.1"
    bfd:
      enabled: true
      interval: 300        # Detection interval (ms)
      multiplier: 3        # Failure after 3 missed packets
      min_rx: 300          # Minimum receive interval (ms)
      min_tx: 300          # Minimum transmit interval (ms)
```

### Graceful Restart

Maintain forwarding during BGP restart:

```yaml
neighbors:
  - address: "198.51.100.1"
    graceful_restart:
      enabled: true
      restart_time: 120          # Restart time (seconds)
      stale_routes_time: 300     # Stale route retention (seconds)
      long_lived_enabled: true   # Long-lived graceful restart
      notification_enabled: true # Hard reset notification
```

## EVPN Configuration

### Basic EVPN Settings

```yaml
evpn:
  enabled: true

  # Route Distinguisher configuration
  rd_type: "type1"  # type0, type1, type2
  rd_value: ""      # Auto-generated if empty

  # Route Target auto-derivation
  rt_auto: true
  rt_import: []     # Manual import RTs
  rt_export: []     # Manual export RTs

  # VNI allocation
  vni_range:
    start: 10000
    end: 19999

  # VTEP configuration
  vtep:
    address: "10.0.0.1"
    source_interface: "lo"
```

### Route Distinguisher Types

| Type | Format | Example |
|------|--------|---------|
| type0 | 2-byte ASN : 4-byte assigned | 65001:10000 |
| type1 | 4-byte IPv4 : 2-byte assigned | 203.0.113.1:100 |
| type2 | 4-byte ASN : 2-byte assigned | 65001:100 |

```yaml
evpn:
  rd_type: "type1"
  rd_value: "203.0.113.1:100"  # IPv4:assigned format
```

### VRF Configuration

```yaml
evpn:
  vrfs:
    - name: "tenant-a"
      rd: "65001:100"
      rt_import:
        - "65001:100"
        - "65001:999"  # Shared services
      rt_export:
        - "65001:100"
      l3_vni: 10000

    - name: "tenant-b"
      rd: "65001:200"
      rt_import:
        - "65001:200"
        - "65001:999"
      rt_export:
        - "65001:200"
      l3_vni: 20000

    - name: "shared-services"
      rd: "65001:999"
      rt_import:
        - "65001:100"
        - "65001:200"
      rt_export:
        - "65001:999"
      l3_vni: 99900
```

### MAC Mobility Settings

```yaml
evpn:
  mac_mobility:
    enabled: true
    sequence_number_start: 0
    duplicate_detection:
      enabled: true
      max_moves: 5           # Max moves per MAC
      detection_window: "180s"
      freeze_time: "30s"     # Time to freeze after detection
```

## Transit Configuration

### Prefix Announcements

```yaml
transit:
  enabled: true

  # Prefixes to announce
  prefixes:
    ipv6:
      - prefix: "2001:db8::/36"
        description: "Platform IPv6 aggregate"
        announce_level: "backbone"  # backbone, datacenter
      - prefix: "2001:DB8:0001::/48"
        description: "Region 1"
        announce_level: "datacenter"

    ipv4:
      - prefix: "203.0.113.0/24"
        description: "Platform IPv4 block"
        announce_level: "backbone"

  # Route aggregation
  aggregation:
    enabled: true
    summary_only: true  # Suppress more-specifics
```

### RPKI Configuration

```yaml
transit:
  rpki:
    enabled: true

    # RTR servers
    servers:
      - address: "rpki-validator.example.com"
        port: 8323
        prefer: true
      - address: "rpki-backup.example.com"
        port: 8323
        prefer: false

    # Validation policy
    policy:
      valid: "accept"       # Accept with preference
      invalid: "reject"     # Reject invalid origins
      not_found: "accept"   # Accept if no ROA exists

    # Cache settings
    cache:
      lifetime: "3600s"
      refresh_interval: "300s"
```

### BGP Dampening

```yaml
transit:
  dampening:
    enabled: true

    # Dampening parameters
    half_life: "15m"           # Penalty decay half-life
    suppress_threshold: 2000   # Penalty to suppress route
    reuse_threshold: 750       # Penalty to reuse route
    max_suppress_time: "60m"   # Maximum suppression duration

    # Per-prefix overrides
    overrides:
      - prefix: "2001:db8::/36"
        enabled: false  # Never dampen aggregate
```

## Security Configuration

### MD5 Authentication

> Superseded by **Decoded schema** above: the key is `auth-type: md5` with
> `auth-key-ref`, MD5 is `!fips` only, and TCP-AO is the standard.

```yaml
neighbors:
  - address: "198.51.100.1"
    md5_secret: "${BGP_ISP_PRIMARY_SECRET}"  # Environment variable

# Or direct value (not recommended for production)
neighbors:
  - address: "198.51.100.1"
    md5_secret: "my_secret_key"
```

### TTL Security

Prevent remote attacks by requiring specific TTL values:

```yaml
neighbors:
  - address: "198.51.100.1"
    ttl_security:
      enabled: true
      hops: 1  # Require TTL >= 254 (directly connected)
```

### Prefix Limits

Per neighbor, per family. The unicast families share `max-prefixes`, counted
separately for IPv4 and IPv6; l2vpn-evpn has its own:

```yaml
peers:
  - address: 10.4.255.2
    families: [ipv4-unicast, ipv6-unicast]
    max-prefixes: 10            # default 1000
  - address: 10.4.0.1
    families: [evpn]
    max-evpn-prefixes: 250000   # default 100000
```

See **Prefix limits** under the decoded schema above for why EVPN is separate.
The warning threshold (80 %) is fixed; exceeding a limit always tears the
session down.

### Route Signing

```yaml
signing:
  enabled: true

  # Quorum requirement
  quorum: 3  # Minimum signatures required

  # Coordinator endpoints
  coordinators:
    - address: "coordinator-1.example.com:9443"
      tls:
        enabled: true
        ca_cert: "/etc/platform/ca.crt"
    - address: "coordinator-2.example.com:9443"
      tls:
        enabled: true
        ca_cert: "/etc/platform/ca.crt"
    - address: "coordinator-3.example.com:9443"
      tls:
        enabled: true
        ca_cert: "/etc/platform/ca.crt"

  # Timeout settings
  timeout: "10s"
  retry_count: 3
  retry_interval: "1s"
```

## Routing Policies

Routing policy is **per peer**, under `gateway.bgp.peers[].policy`, and is
described in [Decoded schema](#decoded-schema-normative-since-556-2026-09-08)
above: `import-allow` / `export-allow` for the prefix filters, `import:` /
`export:` for the traffic-engineering attributes.

> **The top-level `policies:` / `prefix_lists:` block that this section used to
> document was never decoded by anything.** `bgp.BGPConfig` has no such field,
> so a configuration written that way loaded silently and filtered nothing — the
> defect class of #556, #567 and #607. It is removed here rather than left as a
> second, non-working spelling beside the real one. Its capabilities all exist
> in the per-peer schema: prefix lists as `import-allow` / `export-allow`,
> `set_local_pref` as `import.local-pref`, `as_path_prepend` as
> `export.prepend`, and `set_community_add` as
> `export.communities: {action: add}`.


## Logging and Monitoring

### Logging Configuration

```yaml
logging:
  level: "info"  # debug, info, warn, error
  format: "json" # json, text

  # Per-component levels
  components:
    peer: "info"
    route: "debug"
    policy: "info"

  # Output
  output:
    stdout: true
    file:
      enabled: true
      path: "/var/log/platform/bgp.log"
      max_size: "100M"
      max_age: "7d"
      compress: true
```

### Metrics Configuration

```yaml
metrics:
  enabled: true
  port: 9179
  path: "/metrics"

  # Metric types
  types:
    peer_state: true
    route_counts: true
    update_counts: true
    error_counts: true
    rpki_stats: true
    dampening_stats: true
```

## Environment Variables

Configuration values can be sourced from environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `BGP_ASN` | AS number | 65001 |
| `BGP_ROUTER_ID` | Router ID | 203.0.113.1 |
| `BGP_ISP_PRIMARY_SECRET` | Primary ISP MD5 secret | (secret) |
| `BGP_ISP_BACKUP_SECRET` | Backup ISP MD5 secret | (secret) |
| `BGP_IBGP_SECRET` | iBGP MD5 secret | (secret) |
| `BGP_RPKI_ENABLED` | Enable RPKI validation | true |
| `BGP_DAMPENING_ENABLED` | Enable route dampening | true |

```yaml
# Using environment variables in config
bgp:
  global:
    asn: ${BGP_ASN}
    router_id: ${BGP_ROUTER_ID}

  neighbors:
    - address: "198.51.100.1"
      md5_secret: ${BGP_ISP_PRIMARY_SECRET}
```

## Complete Example

```yaml
bgp:
  global:
    asn: 65001
    router_id: "203.0.113.1"
    listen_port: 179
    listen_addresses:
      - "0.0.0.0"
      - "::"

  speaker:
    role: "backbone"

  neighbors:
    # Primary ISP
    - address: "198.51.100.1"
      remote_asn: 64500
      description: "ISP-Primary"
      type: "ebgp"
      md5_secret: "${BGP_ISP_PRIMARY_SECRET}"
      families:
        - afi: "ipv4"
          safi: "unicast"
        - afi: "ipv6"
          safi: "unicast"
      timers:
        hold_time: 90
        keepalive_interval: 30
      bfd:
        enabled: true
        interval: 300
        multiplier: 3
      graceful_restart:
        enabled: true
        restart_time: 120
      prefix_limits:
        ipv6_unicast:
          max_prefixes: 5000
          warning_threshold: 80

    # Backup ISP
    - address: "203.0.113.1"
      remote_asn: 64501
      description: "ISP-Backup"
      type: "ebgp"
      md5_secret: "${BGP_ISP_BACKUP_SECRET}"
      families:
        - afi: "ipv6"
          safi: "unicast"

    # iBGP peer
    - address: "10.0.0.2"
      remote_asn: 65001
      description: "Backbone-2"
      type: "ibgp"
      md5_secret: "${BGP_IBGP_SECRET}"
      families:
        - afi: "ipv6"
          safi: "unicast"
        - afi: "l2vpn"
          safi: "evpn"

  evpn:
    enabled: true
    rd_type: "type1"
    rt_auto: true
    vni_range:
      start: 10000
      end: 19999
    vtep:
      address: "10.0.0.1"

  transit:
    enabled: true
    prefixes:
      ipv6:
        - prefix: "2001:db8::/36"
          announce_level: "backbone"
      ipv4:
        - prefix: "203.0.113.0/24"
          announce_level: "backbone"
    rpki:
      enabled: true
      servers:
        - address: "rpki-validator.example.com"
          port: 8323
      policy:
        valid: "accept"
        invalid: "reject"
        not_found: "accept"
    dampening:
      enabled: true
      half_life: "15m"
      suppress_threshold: 2000
      reuse_threshold: 750
      max_suppress_time: "60m"

  signing:
    enabled: true
    quorum: 3
    coordinators:
      - address: "coordinator-1.example.com:9443"
      - address: "coordinator-2.example.com:9443"
      - address: "coordinator-3.example.com:9443"

  policies:
    export:
      - name: "export-to-isp-primary"
        statements:
          - conditions:
              prefix_list: "platform-aggregates"
            actions:
              accept: true
              set_community: ["65001:100"]

      - name: "export-to-isp-backup"
        statements:
          - conditions:
              prefix_list: "platform-aggregates"
            actions:
              accept: true
              as_path_prepend:
                asn: 65001
                count: 3

  prefix_lists:
    - name: "platform-aggregates"
      entries:
        - prefix: "2001:db8::/36"
          match: "exact"
        - prefix: "203.0.113.0/24"
          match: "exact"

  logging:
    level: "info"
    format: "json"

  metrics:
    enabled: true
    port: 9179
```
