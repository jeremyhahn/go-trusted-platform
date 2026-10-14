# BGP Speaker — Engineering

> **Status: NORMATIVE** · Scope: `pkg/sdn/bgp/` and the gatewayd services that run it · Last verified: 2026-10-14
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

All paths are relative to `pkg/sdn/bgp/` unless they say otherwise.

## 1. Exported surface

### Speaker (`speaker.go`)

| Symbol | Line | Behaviour |
|---|---|---|
| `NewSpeaker(cfg, logger, opts...)` | 402 | Builds a speaker. The options are `WithPeerStateCallback`, `WithRouteReceivedCallback` and `WithBGPServer` |
| `Start` | 434 | Starts GoBGP, then sets up the global config, graceful restart, keychains, policies and policy assignments. It adds no peers and originates no paths (434–522). A second call returns `ErrSpeakerAlreadyRunning` (435) |
| `Stop` | 525 | Stops BGP and the server. On a stopped speaker it returns `ErrSpeakerNotStarted` (526). A `StopBgp` failure is logged, not returned (535–537) |
| `AddPeer` / `DeletePeer` / `GetPeer` / `ListPeers` / `GetPeerState` | 550 / 663 / 691 / 725 / 746 | Neighbor management |
| `ResetPeer` / `EnablePeer` / `DisablePeer` | 755 / 785 / 821 | Session control |
| `AddPath` / `DeletePath` / `GetRIB` | 856 / 893 / 929 | RIB access |
| `WatchEvent` | 964 | Best-path and peer event stream |
| `GetServerInfo` / `IsStarted` / `Config` | 1027 / 1092 / 1097 | Introspection |

### EVPN (`evpn.go`, `evpn_rt.go`)

| Symbol | Line |
|---|---|
| `NewEVPNManager` / `Start` / `Stop` / `RegisterHandler` | 192 / 225 / 243 / 257 |
| `JoinVNI` / `LeaveVNI` | 552 / 694 |
| `AdvertiseMACIP` / `WithdrawMACIP` | 774 / 843 |
| `AdvertisePrefix` / `WithdrawPrefix` | 976 / 1004 |
| `LookupMACForIP` / `RemoteMAC` / `RemoteVTEPs` / `ReplayVTEP` / `ActiveVTEPs` / `RouteDistinguisher` | 1039 / 1047 / 1059 / 1078 / 1098 / 1131 |
| `AutoRouteTarget` | `evpn_rt.go:107` |
| `MinOverlayASN` / `MaxOverlayASN` (64512 / 65534) | `evpn_rt.go:35-36` |

### Library code with no production caller

- `NewDampeningManager` (`dampening.go:240`);
- `NewRPKIValidator` (`rpki.go:204`);
- `NewPeerManager` (`peer.go:244`);
- `NewTransitManager` (`transit.go:198`).

They are tested in the package but nothing in gatewayd or platformd builds
them.

## 2. Invariants

- **Policy rejects by default** (RFC 8212). Both global policies, `tp-import`
  and `tp-export`, are assigned with a reject default (`policy.go:56-57`,
  `:170`). A peer exchanges only what its allowlists admit
  (`policy.go:110-135`).
- **Policy is global, conditioned on the neighbor.** GoBGP stores per-peer
  policy only for route-server clients, so a per-peer assignment would filter
  nothing (`policy.go:34-39`, #717).
- **`announce:` is a default, not an origination.** When a peer has no
  `export-allow`, the `announce` prefixes become its export allowlist
  (`policy.go:118-121`). Nothing announces them.
- **An outbound-only speaker opens no listener.** `OutboundOnly` sets GoBGP's
  listen port to -1 (`speaker.go:460-461`). A passive peer on such a speaker
  is refused with `ErrPassivePeerWithoutListener` at validation (`types.go:696`)
  and again at `AddPeer` (`speaker.go:572`).
- **Secrets are references.** `AuthKey` and `MasterKey` carry `yaml:"-"`
  (`types.go:735`, `:961`). They are filled only by `ResolveSecrets`
  (`types.go:1050`) on a clone of the config (`pkg/sdn/gateway/handlers.go:1117-1128`).
- **A refused peer stops the speaker.** If one `AddPeer` fails, gatewayd stops
  the speaker it just started and returns the error. This holds for transit
  (`pkg/sdn/gateway/handlers.go:1146-1153`) and overlay (`:1010-1017`).

## 3. Errors

All are typed values in `errors.go`.

| Error | Line | Raised when |
|---|---|---|
| `ErrSpeakerNotStarted` | 27 | An operation runs on a stopped speaker |
| `ErrSpeakerAlreadyRunning` | 30 | `Start` runs twice |
| `ErrDampeningActive` | 75 | A local advertisement of a MAC frozen by MAC mobility (`evpn.go:796`, `:808`) |
| `ErrPeerNotFound` | 48 | A peer operation names an unknown neighbor |
| `ErrConfigurationInvalid` | 84 | Config validation |
| `ErrRouteTargetInvalid` / `ErrInvalidVNI` | 379 / 392 | `AutoRouteTarget` input out of range |
| `ErrPrefixInvalid` | 428 | A prefix does not parse |
| `ErrRouteDecodingFailed` / `ErrTreatAsWithdraw` | 498 / 585 | Received EVPN path rejected or withdrawn (§7) |
| `ErrRouteWithdrawalFailed` | 532 | A local withdrawal failed |
| `ErrUnsupportedRouteType` | 574 | Received Type-1 or Type-4 |
| `ErrVNINotJoined` | 606 | `LeaveVNI` / `AdvertiseMACIP` / `AdvertisePrefix` on a VNI not joined |
| `ErrPeerOperationFailed` / `ErrServerOperationFailed` | 643 / 679 | A GoBGP call failed |
| `ErrAuthTypeUnavailableInFIPS` | 913 | MD5 in a FIPS build (§4) |
| `ErrAuthSecretRequired` | 925 | MD5 without `auth-key-ref` |
| `ErrDuplicateKeychain` / `ErrKeychainNotFound` | 952 / 963 | Keychain validation |
| `ErrPassivePeerWithoutListener` | 976 | Passive peer on an outbound-only speaker |
| `ErrSecretResolverRequired` / `ErrSecretResolutionFailed` / `ErrSecretEmpty` | 987 / 998 / 1005 | Secret resolution |
| `ErrBFDIntervalTooShort` | 1024 | A BFD interval below 50 ms |
| `ErrTCPAOSessionBindingUnsupported` | 1037 | `AddPeer` of a `tcp-ao` peer (§4) |
| `ErrLocalPrefInvalid` / `ErrPrependInvalid` / `ErrCommunityInvalid` / `ErrAttributeDirectionInvalid` | 1050 / 1062 / 1074 / 1119 | Attribute policy validation |

gatewayd wraps speaker failures in its own service errors:

- `ErrServiceUnavailable`: no `bgp:` section (`pkg/sdn/gateway/handlers.go:1199`),
  or an overlay ASN above 65535 (`:976-978`);
- `ErrServiceAlreadyActive`: transit started twice (`:1115`);
- `ErrServiceStartFailed`: any start error (`:116`);
- `ErrServiceNotActive`: a health check on a stopped or unhealthy service
  (`:148`).

## 4. Authentication and secrets

| `auth-type` | Behaviour |
|---|---|
| `none` | No authentication |
| `md5` | RFC 2385. Requires `auth-key-ref` (`types.go:1108-1109`). Refused in FIPS builds with `ErrAuthTypeUnavailableInFIPS` (`types.go:1105-1106`; the build switch is `auth_fips.go:23` / `auth_nofips.go:22`) |
| `tcp-ao` | RFC 5925. Requires `keychain`, naming a `keychains` entry (`types.go:1111-1113`, `:693`). **`AddPeer` refuses it** with `ErrTCPAOSessionBindingUnsupported` (`speaker.go:580`), because GoBGP v4.9.0 cannot bind a keychain to a neighbor. **Planned**, blocked upstream; no issue number is recorded |

`auth-type` also accepts `tcpao` and `tcp_ao` (`types.go:244-252`).

Secret flow in gatewayd:

1. The config is cloned (`pkg/sdn/gateway/handlers.go:1117`).
2. `defer zeroizeBGPSecrets(cfg)` is armed before resolution (`:1127`).
3. `ResolveSecrets` fills `AuthKey` and `MasterKey` from the references (`:1128`).

The comment at `handlers.go:1124-1126` records the one limit: GoBGP takes an
MD5 password as a Go string, which cannot be wiped. See also
[protected memory](../security/protected-memory.md).

## 5. Configuration

The transit speaker reads `gateway.bgp:` (`pkg/sdn/gateway/types.go:1265`),
decoded into `bgp.BGPConfig` (`types.go:549`). The overlay speaker is built
from the overlay section's `overlay-asn` (`pkg/sdn/gateway/types.go:472`) and
`rr-peers` (`:476`), each a `NeighborConfig`.

### `bgp:` (BGPConfig)

| Key | Line | Default | Effect |
|---|---|---|---|
| `router-id` | 551 | — | Required, a valid non-unspecified IPv4 (`ErrInvalidRouterID`, 640–642) |
| `asn` | 554 | — | 1–4294967295 (`ErrInvalidASN`, 643–645) |
| `listen-port` | 557 | 179 | (646–648) |
| `listen-addresses` | 560 | all | Programmed (`speaker.go:462-468`) |
| `graceful-restart` | 582 | on | `*bool`; only an explicit `false` disables it (`types.go:624`). Programmed globally and per peer (`speaker.go:472-482`, `:1173-1178`) |
| `graceful-restart-time` | 585 | 120 s | (699–701) |
| `route-reflector` | 603 | false | Enables `cluster-id` on reflector-client peers (`speaker.go:1149-1155`) |
| `cluster-id` | 606 | — | Required as an IPv4 dotted quad when `route-reflector` is set (663–669) |
| `announce` | 610 | empty | `ipv4` / `ipv6` prefix lists. They are the default export allowlist only (§2) |
| `peers` | 615 | — | The neighbor list (`Neighbors` field) |
| `keychains` | 619 | — | TCP-AO keychains (§4) |
| `tier` | 574 | — | **Validated only** (649–651) |
| `capabilities` | 577 | — | **Decoded, not programmed.** Keys `evpn`, `ipv4-unicast`, `ipv6-unicast`, `rpki-validation`, `announce-ipv6-block`, `announce-ipv4-block` (511–526) |
| `multipath` | 588 | — | **Decoded, not programmed** |
| `families` | 591 | — | **Decoded, not programmed** globally; the per-peer `families` is what counts |
| `dampening`, `dampening-half-life`, `dampening-max-suppress` | 594 / 597 / 600 | — | **Validated only** (652–662) |

`OutboundOnly` and `SessionSource` have `yaml:"-"` (566, 571). Only the
overlay speaker sets them, in code.

### `peers[]` and `rr-peers[]` (NeighborConfig, `types.go:712`)

| Key | Line | Default |
|---|---|---|
| `name`, `description` | 714, 723 | — |
| `address` | 717 | required (`ErrInvalidPeerAddress`) |
| `asn` | 720 | required (`ErrInvalidPeerASN`) |
| `auth-type`, `auth-key-ref`, `keychain` | 726, 731, 739 | `none` (§4) |
| `hold-time` | 742 | 90 s; must be 0 or ≥ 3 (`ErrInvalidHoldTime`, 1116) |
| `keepalive-interval` | 745 | 30 s |
| `connect-retry` | 748 | 120 s |
| `passive` | 751 | false |
| `route-reflector-client` | 754 | false |
| `ebgp-multihop` | 757 | — |
| `families` | 761 | `ipv4-unicast`/`ipv4`, `ipv6-unicast`/`ipv6`, `evpn`/`l2vpn-evpn` (300–304); merged with the booleans `ipv4-unicast` 770, `ipv6-unicast` 773, `evpn` 776 (1142+) |
| `remove-private-as` | 764 | false |
| `admin-down` | 767 | false |
| `bfd` | 780 | off (below) |
| `max-prefixes` | 785 | 1000 per unicast family |
| `max-evpn-prefixes` | 791 | 100000 |
| `policy` | 795 | reject both ways (below) |

The defaults are applied in `NeighborConfig.Validate` (`types.go:1119-1132`).

At the prefix limit GoBGP shuts the session down. It logs a warning at 80%
(`speaker.go:1193-1196`, `prefixLimitWarnPct` at 1213).

### `bfd:` (BFDConfig)

| Key | Line | Default |
|---|---|---|
| `enabled` | 801 | false |
| `port` | 804 | 3784 (`types.go:55`) |
| `desired-min-tx-interval`, `required-min-rx-interval` | 807, 810 | 300 ms (`types.go:58`); minimum 50 ms (`ErrBFDIntervalTooShort`) |
| `detection-multiplier` | 814 | 3 |

### `policy:` (PeerPolicyConfig)

| Key | Line | Effect |
|---|---|---|
| `import-allow`, `export-allow` | 851, 855 | Unicast `PrefixMatch` lists: `prefix` (888), `max-length` (892) |
| `import-route-targets`, `export-route-targets` | 860, 864 | EVPN route-target allowlists in `as:value` form (§7) |
| `import-default-accept`, `export-default-accept` | 868, 871 | Turn the default from reject to accept for that peer (`policy.go:127`, `:135`) |
| `import`, `export` | 876, 881 | Attribute actions (`attributes.go`): `local-pref` 130, `med` 134, `prepend` 137 (`count` 115, `asn` 119), `communities` 140 and `large-communities` 143 (`action` 103, `values` 108). Direction rules are in `validateAttributeDirections` (`attributes.go:383`) |

### `keychains:` (TCPAOKeychainConfig, `types.go:938`)

`name` (938), `keys` (941). Each key has `send-id` (947), `receive-id` (950),
`algorithm` (954), `master-key-ref` (957) and `exclude-tcp-options` (964).

### The overlay speaker

`overlay-asn` must be 64512–65534 (`pkg/sdn/gateway/types.go:531-536`). A
`passive` rr-peer is refused, because the speaker cannot listen
(`types.go:540-544`). gatewayd builds the speaker with:

- the router ID and session source set to the local VTEP;
- the ASN set to `overlay-asn`;
- `OutboundOnly`;
- the `evpn` capability and family only;
- the `rr-peers` as neighbors.

See `pkg/sdn/gateway/handlers.go:986-994`.

## 6. Persistence

None. The package writes nothing to disk. The RIB and the EVPN state are in
memory. After a restart they are rebuilt from the peers, and graceful restart
keeps the peers' forwarding state meanwhile (§8).

## 7. EVPN

`EVPNManager` originates through the speaker. It imports what the speaker's
best-path watch delivers.

| Type | Name | Status |
|---|---|---|
| 1 | Ethernet Auto-Discovery | Not used (single-homed VTEPs); dropped with `ErrUnsupportedRouteType` |
| 2 | MAC/IP Advertisement | Symmetric IRB; originated from the overlay handler's learned MACs (`pkg/sdn/gateway/modes/overlay.go:911`) |
| 3 | Inclusive Multicast Ethernet Tag | Ingress replication; originated per joined VNI (`overlay.go:777`) |
| 4 | Ethernet Segment | Not used; dropped |
| 5 | IP Prefix (RFC 9136) | Interface-less. Implemented (`evpn.go:976`) but not originated by any production caller |

- **RD.** Type-1, `VTEP-IPv4:index`. Each EVI (L2VNI) and IP-VRF (L3VNI) gets
  an index in join order, reused after a leave. A received route with another
  RD type is dropped.
- **RT.** Auto-derived (RFC 8365 §5.1.2.1) by `AutoRouteTarget`
  (`evpn_rt.go:107`) as `ASN:value`, where
  `value = 1<<28 | DomainID<<24 | VNI`. VNI 10100 in domain 0 under ASN 65000
  is `65000:268445556`. The overlay ASN must fit two octets
  (`pkg/sdn/gateway/handlers.go:976-978`).
- **Labels.** The VNI travels in the 24-bit label field unshifted
  (RFC 8365 §5.1.3). Every route carries the VXLAN encapsulation community.
- **Import.** A Type-2 route is imported by its MAC-VRF route target. Its
  L3VNI label and Router's MAC are taken only when it also carries the IP-VRF
  route target (RFC 9135 §5.1). Routes the VTEP originated are ignored.
- **MAC mobility** (RFC 7432 §15).
  - A VTEP taking over a MAC uses the holder's sequence number plus one.
  - The highest sequence wins; a tie goes to the lowest VTEP address.
  - A MAC that moves 5 times in 180 s is frozen for 180 s
    (`evpn_mobility.go:28-32`). While frozen, received routes are ignored and
    local advertisement fails with `ErrDampeningActive`.
- **RFC 7606.**
  - A path whose NLRI does not parse, is not EVPN, or has a non-Type-1 RD is
    dropped (`ErrRouteDecodingFailed`).
  - A parsed path whose attributes are unusable is treated as a withdrawal
    (`ErrTreatAsWithdraw`). Unusable means any of:
    - no next hop, or no VXLAN community;
    - conflicting Router's MAC or MAC Mobility communities;
    - a non-unicast Router's MAC;
    - an out-of-range label;
    - an L3VNI label without a Router's MAC;
    - a Type-3 route without an ingress-replication PMSI tunnel;
    - an interface-less Type-5 route without a Router's MAC.
- **Handlers.** `RegisterHandler` subscribers are told changes one at a
  time, in order, under one ordering lock. A route that moves VTEP is reported
  as a withdrawal at the old VTEP followed by the add at the new one. A
  handler must not call `JoinVNI`, `LeaveVNI` or `WithdrawMACIP`. The overlay
  data plane's handler is `handleEVPNRoute`
  (`pkg/sdn/gateway/modes/overlay_evpn.go:43`), described in
  [the overlay handler](../gateway/engineering.md#the-overlay-handler-overlaymodehandler).
- **Session policy.** An `evpn` peer exchanges only the routes that carry at
  least one route target in its `import-route-targets` /
  `export-route-targets`. An empty list exchanges nothing, with one exception:
  gatewayd fills an overlay rr-peer's empty list with the route target of
  every configured VNI (`pkg/sdn/gateway/handlers.go:1033-1053`).

## 8. Failure handling and restart

| Event | Behaviour |
|---|---|
| A session drops | GoBGP retries every `connect-retry` (default 120 s, programmed at `speaker.go:1117`). With graceful restart, the peer keeps the routes for `graceful-restart-time` (default 120 s) |
| A peer exceeds `max-prefixes` / `max-evpn-prefixes` | GoBGP shuts the session down; warning at 80% (§5) |
| BFD detection fails | Counted by `bfd_failure_transitions_total` (§9) |
| A peer is refused at start | gatewayd stops the speaker and the service start fails (§2) |
| The transit service starts twice | `ErrServiceAlreadyActive` (`pkg/sdn/gateway/handlers.go:1115`) |
| Overlay handler or VNI join fails after the speaker started | The overlay EVPN speaker is stopped (`handlers.go:855`, `:859`, `:864`) |
| Service stop | Transit `Stop` with no speaker returns nil (`handlers.go:1167`). Overlay `Stop` stops its speaker (`:924`) |

**Supervised mode.** The gateway can run the transit service in a separate
`routing` process class that holds `CAP_NET_BIND_SERVICE`
(`pkg/sdn/gateway/process/class.go:99-102`). The supervisor restarts a child
that exits:

- with backoff from 500 ms to 30 s;
- within a budget of 5 restarts per 5 minutes, after which
  `ErrRestartBudgetExhausted` is raised (`supervisor.go:43-50`).

The design is in [gateway architecture](../gateway/architecture.md); this
folder does not repeat it.

## 9. Observability

The gateway snapshot (`pkg/sdn/gateway/snapshot.go:151`) reports:

- `LocalASN` and `RouterID` from the config;
- for each transit peer, its state, `EstablishedPeers` and `ReceivedPrefixes`
  (`snapshot.go:163-190`).

In supervised mode, the BGP section comes from the routing child
(`snapshot.go:160-161`). **The overlay EVPN speaker is not in the snapshot.**

Prometheus metrics, namespace `gatewayd` (`pkg/sdn/gateway/metrics.go:25`):

| Metric | Labels | Line |
|---|---|---|
| `gatewayd_bgp_peer_established` | gateway, peer, asn | 72–73 |
| `gatewayd_bgp_peer_uptime_seconds` | gateway, peer | 74–75 |
| `gatewayd_bgp_peer_prefixes` | gateway, peer, direction | 76–77 |
| `gatewayd_bfd_session_up` | gateway, peer | 78–79 |
| `gatewayd_bfd_failure_transitions_total` | gateway, peer | 80–81 |

## 10. Tests

Run them with `make test-pkg PKG=./pkg/sdn/bgp/`.

| File | Proves |
|---|---|
| `evpn_session_test.go` | Three in-process GoBGP speakers (a reflector and two VTEPs on loopback): Type-2/3/5 exchange, derived RDs and RTs, 24-bit labels, symmetric-IRB labels, MAC mobility A→B→A, 1200 reflected MACs |
| `evpn_codec_test.go` | Wire label bytes; `FuzzDecodeEVPNPath` fuzzes the decoder |
| `policy_session_test.go`, `policy_gobgp_test.go` | The default-reject policy and allowlists against live GoBGP sessions |
| `rtc_dynamic_gobgp_test.go` | Against real GoBGP: RT-constrain filtering of EVPN routes, and dynamic neighbors admitting only the fabric prefix |
| `speaker_test.go`, `peer_test.go`, `peer_extended_test.go` | Speaker lifecycle and peer management |
| `v4_migration_test.go` | Config validation and defaults, `ResolveSecrets`, keychains and policy installed at start, the peer's policy, BFD and prefix limit, and the TCP-AO refusal (`TestSpeaker_TCPAOPeerIsRefusedUntilGoBGPBindsIt`) |
| `attributes_test.go`, `announce_test.go`, `bfd_state_test.go` | Attribute actions, `announce` defaults, BFD state |
| `evpn_test.go`, `evpn_rt_test.go`, `evpn_mobility_test.go` | EVPN manager, route-target derivation, MAC mobility |
| `dampening_test.go`, `rpki_test.go`, `transit_test.go` | The library-only managers (§1) |

The transport side is proved in `pkg/api/daemon`.
`gateway_bgp_withdraw_rest_sdk_test.go` drives the SDK's REST client against
the webservice gateway router and a `GatewayService` holding a recording
speaker: an IPv4 and an IPv6 withdraw reach the speaker
(`TestGatewayBGPWithdraw_RESTSDKReachesServer`), and a bad prefix is refused
with gRPC's reason (`TestGatewayBGPWithdraw_RESTSDKRefusesBadPrefixLikeGRPC`).
Run it with `make test-pkg PKG=./pkg/api/daemon/ TESTFLAGS='-run BGPWithdraw'`.
