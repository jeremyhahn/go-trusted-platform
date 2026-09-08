# Edge Gateway — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/sdn/gateway/`, `pkg/proxy/`, `cmd/gatewayd` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Design and boundaries: [architecture.md](architecture.md). Transport matrix:
> [api.md](api.md).

---

## 1. Service sections — the configuration model

`pkg/sdn/gateway/node.go` declares the service-name constants. These strings
are the configuration contract:

```go
ServiceOverlay       = "overlay"
ServiceEdge          = "edge"
ServiceTransit       = "transit"
ServiceFirewall      = "firewall"
ServiceBGP           = "bgp"            // a bgp: section enables transit
ServiceDHCP          = "dhcp"
ServicePXE           = "pxe"
ServiceLoadBalancer  = "load-balancer"
ServiceNAT           = "nat"
ServiceTunnels       = "tunnels"
ServiceProxy         = "proxy"
ServiceHostFW        = "hostfw"         // #569
ServiceManagementVPN = "management-vpn" // design only, refused
```

**`load-balancer` and `management-vpn` are hyphenated; the others are single
words.** Configuration that writes `loadbalancer` or `load_balancer` will not
match, and the failure is a service that silently does not start.

### Handlers — `handlers.go`

`NewGateway` registers one handler per enabled section from two tables:

| Table | Type | `Start` | `IsActive` / `Health` |
|---|---|---|---|
| `serviceBuilders` (`firewall`, `nat`, `load-balancer`, `hostfw`, `tunnels`, `transit`) | `backedServiceHandler` | builds the backend; a build or start failure returns the backend's error and leaves nothing registered | the built backend's own `Active` / `Healthy` |
| `serviceRefusals` (`overlay`, `edge`, `dhcp`, `pxe`, `management-vpn`) | `refusedServiceHandler` | `ErrServiceUnavailable{Service, Reason}` | `false` / `ErrServiceUnavailable` |

`proxy` is registered by `gatewayd serve` assembly through
`RegisterServiceHandler`, which appends to the same start order. Adding a
service means adding a builder (and a `backedService` adapter if the backend's
lifecycle does not already fit) — never a handler type of its own, and never a
handler that reports active without a backend.

The builder ordering is `enabledServices()` in `types.go`: firewall, nat,
load-balancer, hostfw, tunnels, transit, then the refused sections. Tunnels
start before transit so BGP sessions have their interfaces; a refused section
fails startup before any datapath service has to be rolled back for it.

`HostRuntime` (`runtime.go`, `GatewayConfig.Host`, never from YAML) carries what
the builders need beyond OVS:

| Field | Default when nil | Used by |
|---|---|---|
| `Listeners hostfw.ListenerInventory` | `hostfw.StaticInventory{}` (no daemon listener admitted) | `hostfw` |
| `HostFWApplier hostfw.Applier` | `hostfw.NewNetlinkApplier()` | `hostfw` |
| `TunnelManager` | `tunnel.NewManager(logger)` | `tunnels`; its tunnel names are appended to `hostfw.Config.Tunnels` |
| `BGPServer bgp.BGPServerInterface` | in-process GoBGP server | `transit` |
| `SecretResolver bgp.SecretResolver` | none — a neighbour with a `secret-ref` fails with `bgp.ErrSecretResolverRequired` (fail closed) | `transit` |
| `Logger` | `Runtime.Logger`, else `slog.Default()` | all |

`gatewayd serve` builds it in `commands/assembly.go` (`buildHostRuntime`): the
enabled proxy listeners become the host filter inventory through
`ProxyListenerInventory` (TCP, every interface; a `:0` kernel-assigned port is
omitted because it is unknown before the bind). A listener address that is not
`host:port` fails assembly with `ErrConfigSection{Section: "proxy.listeners"}`
wrapping `ErrListenerInventory{Listener, Address, Cause}`. The KMS-backed
`SecretResolver` is not assembled yet; until it is, transit neighbours must
carry no `secret-ref`.

### `GatewayMode` — deprecated, do not build on it

`pkg/sdn/gateway/compat.go:26` declares `GatewayMode uint8` as a three-bit
bitmask (`GatewayModeOverlay`, `GatewayModeEdge`, `GatewayModeTransit`) with an
explicit deprecation notice. `serviceToMode` and `modeToService` translate in
both directions — for **three of the services only**. The rest have
no bit and cannot be expressed. Retained for API compatibility during migration;
new code uses service sections.

## 2. Exported surface — gateway

| Package | Key files | Role |
|---|---|---|
| `pkg/sdn/gateway` | `node.go`, `types.go`, `runtime.go`, `pipeline.go`, `zone_service.go` | Node model, service registry, runtime lifecycle, the base OpenFlow pipeline (`EnsurePipeline` / `RemovePipeline` / `BasePipelineRules` / `ReadPipelineOwner`, #567), zones |
| `pkg/sdn/gateway/modes` | `edge.go`, `edge_p2p.go`, `edge_pxe.go`, `overlay.go`, `transit.go` | Mode implementations |
| `pkg/sdn/gateway/services` | `firewall/`, `loadbalancer/`, `perf/`, `hostfw/` | Service implementations; `hostfw` is the nftables host packet filter (`Ruleset`, `Render`, `Service`, `NetlinkApplier`, `ListenerInventory`) |
| `pkg/sdn/gateway/controlplane` | `reporter.go`, `reconciler.go`, `config.go` | Reports state up, fetches and applies desired config down; `gatewayd serve` starts both loops when the `control-plane:` section is enabled |
| `pkg/sdn/gateway/state` | | Local gateway state |
| `pkg/sdn/gateway/proxysvc` | | Proxy service adapter |
| `pkg/sdn/gateway/p2p` | | libp2p discovery, **build-tag gated `platform_p2p`** |

### Pipeline errors (`pkg/sdn/gateway/pipeline.go`)

| Error | Meaning |
|---|---|
| `ErrPipelineBridgeMissing` | the runtime names no bridge |
| `ErrPipelineOwned{Bridge, Owner}` | another gateway's pipeline holds the bridge; two owners would replace each other's table-0 flow silently |
| `ErrPipelineTerminalUnavailable{Terminal, Reason}` | `overlay` asked for before the overlay service owns egress |
| `ErrPipelineTerminalUnknown{Terminal}` | not `normal` or `overlay` |
| `ErrPipelineInstallFailed{Bridge, Step, Cause}` | a failed install step; flows and `fail_mode` are rolled back |
| `ErrPipelineRemoveFailed{Bridge, Step, Cause}` | a failed removal; the record is kept so a retry can finish |
| `ErrPipelineOwnerReadFailed{Bridge, Cause}` | `ReadPipelineOwner` could not read `external_ids` |

`Gateway.Start` surfaces the first as `ErrStartupFailed{Phase: "pipeline"}`
and `Gateway.Stop` the second as `ErrShutdownFailed{Phase: "pipeline"}`.

### Gateway errors (`pkg/sdn/gateway/errors.go`)

Typed structs, twenty of them. Grouped by what they tell you:

**Service lifecycle:** `ErrServiceStartFailed`, `ErrServiceStopFailed`,
`ErrServiceAlreadyActive`, `ErrServiceNotActive`, `ErrServiceNotFound`,
`ErrStartupFailed`, `ErrShutdownFailed`, `ErrInvalidState`.

**Operation failures:** `ErrBGPOperationFailed`, `ErrUplinkOperationFailed`,
`ErrIPPoolOperationFailed`, `ErrGatewayOperationFailed`, `ErrHealthCheckFailed`,
`ErrOnboardingFailed`, `ErrRequirementsNotMet`, `ErrContextCanceled`,
`ErrTimeout`.

**Peer admission:** `ErrReputationTooLow`, `ErrAgeTooYoung`, `ErrUptimeTooLow`.
These three are reputation-gate errors for peer admission — they belong to the
edge/P2P path and will only fire where that is enabled.

**`ErrServiceAlreadyActive` and `ErrServiceNotActive` are both real errors.**
Starting a running service and stopping a stopped one are both bugs in the
caller, and the gateway says so rather than treating either as a no-op.

## 3. Exported surface — the trusted reverse proxy

`pkg/proxy/` is the security-critical half. Its interfaces are the seams:

| Interface | Purpose |
|---|---|
| `AuthChain` | The ordered chain of authentication mechanisms |
| `MTLSAuthenticator` | Client-certificate authentication |
| `TokenAuthenticator` | Broker-token validation |
| `AttestationGate` | Requires the *client machine* to be attested |
| `TrustResolver` | Resolves a backend pool's trust class |
| `PolicyEvaluator` | Route authorization decision |
| `ZoneExtractor` | Derives the SDN zone of a request; `PolicyZoneExtractor` is the implementation |
| `Balancer` | Backend selection |
| `AuditSink` | Receives `AuditEvent` |
| `CapabilityReporter` | Reports `ChainCapabilities` |

Constructors: `NewAuthChain(cfg AuthChainConfig) (*Chain, error)` and
`NewPolicyZoneExtractor() *PolicyZoneExtractor`.

Configuration types: `Config`, `ListenerConfig`, `RouteConfig`,
`BackendPoolConfig`, `BackendConfig`, `BackendTLSConfig`, `AuthChainConfig`,
`AuthDefaults`, `AuthRequirements`, `Deps`.
Runtime types: `Engine`, `CompiledRoute`, `ClientIdentity`, `AuthDecision`,
`TokenPrincipal`, `TokenAuthRequest`, `Status`, `ListenerStatus`,
`MetricsSnapshot`, `RouteMetrics`, `AuditEvent`.
Error types: `ConfigError`, `ListenerError`, `TrustResolveError`.

## 4. Proxy invariants — the fail-closed set

`pkg/proxy/errors.go` is a sentinel-error package (`errors.New`, compared with
`errors.Is`), unlike the gateway's typed structs. Several of its errors encode
invariants that must not be relaxed:

1. **`ErrAuthChainRequired` — a non-public route must have an auth chain.**
   There is no "route with authentication configured later".
2. **`ErrTLSRequiredForAuth` — a non-public route requires server TLS.**
   Authenticating over plaintext is refused at configuration time, not
   negotiated at request time.
3. **`ErrMTLSAuthNotConfigured` / `ErrTokenAuthNotConfigured` — a route that
   requires a mechanism the chain cannot perform is a configuration error.**
   The route is not silently downgraded to whatever the chain *can* do. This is
   the single most important behaviour in the package: the alternative failure
   mode is a route that believes it requires mTLS and does not.
4. **`ErrTrustResolverRequired` — a pool with a trust class needs a resolver.**
   A trust class with nothing to resolve it would be decorative.
5. **`ErrZoneConfigIncomplete` — the zone extractor and the zone matrix must be
   configured together.** Half a zone configuration would evaluate routes
   against an empty matrix.
6. **`ErrUnknownPoolID` — a route referencing a missing pool fails validation**,
   not at first request.
7. **`ErrEngineStarted` — configuration is not hot-swapped by mutation.**
   Reconfiguration goes through `ReloadProxyConfig`, which versions the config
   store.

Structural validation errors: `ErrNoListeners`, `ErrListenerIDRequired`,
`ErrListenerAddressRequired`, `ErrDuplicateListenerID`, `ErrUnknownProtocol`,
`ErrRouteIDRequired`, `ErrDuplicateRouteID`, `ErrInvalidPathPrefix` (a route
prefix must start with `/`), `ErrRouteAuthModeRequired`, `ErrInvalidAuthMode`,
`ErrRoutePoolRequired`, `ErrPoolIDRequired`, `ErrDuplicatePoolID`,
`ErrNoBackends`, `ErrInvalidBackendURL`, `ErrInvalidBackendScheme` (http or
https only), `ErrInvalidBackendWeight` (non-negative), `ErrUnknownBalancer`,
`ErrNilRequest`, `ErrNilRoute`.

`ErrTCPPassthroughUnsupported` records a deliberate scope fence: the proxy
terminates and inspects; it does not pass TCP through opaquely. A passthrough
route could not run the auth chain.

## 5. Configuration

Gateway-side, in `pkg/sdn/config.go`:

| Type | Keys | Notes |
|---|---|---|
| `GatewayConfig` | `enabled` | Master switch |
| `TransitConfig` | `vlan` (default `vlan.DefaultTransit`, **10**), `p2p` (default `172.16.0.0/24`) | Transit carries **no data-zone traffic**; the VLAN is a plain L2 segment id and the P2P prefix supplies `/31` link addresses. `EffectiveVLAN()` / `EffectiveP2P()` apply the defaults; `Validate()` returns `ErrInvalidTransitVLAN` for an out-of-range 802.1Q id |
| `ManagementVPNConfig` | `enabled`, `type` (only `wireguard` is defined), `allow_to` | Administrators reach management endpoints through this tunnel so operator workstations are **never dual-homed onto a data zone**. Gateways should expose it by default |

`ManagementVPNConfig.Type` exists for extensibility and has exactly one defined
value today. Treat an unrecognised value as a configuration error, not as a
plugin point.

The proxy's own configuration is `pkg/proxy/config.go` — `Config` with
`ListenerConfig`, `RouteConfig` and `BackendPoolConfig` collections, validated
against the invariants in §4 before the engine starts.

### gatewayd daemon configuration (`gatewayd serve`)

`LoadServeConfig` (`pkg/sdn/gateway/commands/assembly.go`) reads five
top-level sections: `gateway:`, `proxy:`, `trust:`, `sdn:`, and
`control-plane:`. Those five names are `tpconfig.GatewaydConfigSections`
(`pkg/config/gateway_role.go`), and they are the whole contract between the
platform config and gatewayd's: firstboot's `renderGatewaydConfig`
(`pkg/firstboot/gatewayd.go`) projects exactly those sections out of
`/etc/trusted-platform/config.yaml` into `/etc/gatewayd/config.yaml`, so a
gateway node keeps one source of truth.

**Packaging (#66).** The role signal is `gateway.enabled: true` in the
platform config (`tpconfig.GatewayRoleEnabled`); nothing else decides it.
`iso create` stages `gatewayd` under `platformd-bin/` beside `platformd`
(`Customizer.CopyGatewaydBinary`) — boot-critical for an ISO whose bundled
config enables the role (`ErrBootCriticalBinaryMissing`), optional otherwise.
The installer places it at `/usr/bin/gatewayd` with the `/usr/sbin/gatewayd`
symlink (`installer.installGatewaydBinary`; `ErrGatewaydBinaryMissing` for a
gateway role without it). Firstboot writes the OpenRC script
`/etc/init.d/gatewayd` (`gatewaydOpenRCScript`: `need localmount networking`,
`after platformd`), renders the config with mode 0600 in a 0700 directory,
runs `rc-update add gatewayd default` and starts it. When the `control-plane:`
identity files are absent the section is rendered `enabled: false` and
`ErrGatewaydIdentityMissing` is logged — the datapath services run, the
reporter waits for an identity the repo cannot yet issue (#149, #431).

**`sdn:`** reuses the platform `sdn.Config` shape (`pkg/sdn/config.go`) and
supplies the OVS datapath runtime for the firewall, NAT, and load-balancer
services: `ovs:` (OVSDB `socket` + `bridge`, both required), optional
`zones:` overrides (built-in defaults otherwise), and `networks:` (VLAN /
subnet / zone bindings that feed the per-zone network summaries).
`buildGatewayRuntime` assembles one `ovs.Client` (it satisfies the OVS,
Groups, and — via `policy.NewOVSFlowController` — Controller dependencies),
the zone/network provider closures, and a conntrack `ct.ZoneAllocator`,
then injects the result as `GatewayConfig.Runtime` before `NewGateway`.
The runtime is assembled **only when a datapath service is enabled** — a
proxy-only gatewayd never dials OVSDB even with an `sdn:` section present
— the OVSDB dial is bounded by a 30s timeout, and the runtime owns the
OVSDB connection: `GatewayRuntime.Close` releases it on every assembly
error path and at daemon shutdown. All five config sections decode with
the TextUnmarshaler hook set, so `netip.Prefix`/`netip.Addr` fields
(`networks[].subnet`, IPAM addresses) parse from plain YAML strings.

Three fail-closed rules:

1. **A datapath service section enabled without `sdn:` fails assembly**
   with the typed `ErrSDNRequiredForService` — before `Start`, with a
   config-shaped error rather than `ErrRuntimeMissing`.
2. **A zone-matrix service (firewall, NAT) with no VLAN-bearing
   `networks:` entries fails assembly** with `ErrNoZoneNetworks`: an
   empty per-zone summary map would compile a matrix with no flows and
   pass all cross-zone traffic while reporting healthy.
3. **gatewayd verifies the bridge; it does not create it.** Datapath
   bring-up (bridge creation, `other_config`, uplinks) belongs to the
   node's installer or to platformd on a gateway-role node. A missing
   bridge fails assembly with `ErrBridgeNotProvisioned`.

**`control-plane:`** (`pkg/sdn/gateway/controlplane/config.go`) enables the
telemetry reporter and the desired-config reconciler (`reconcile-interval`,
default 60s): `base-url`, `cert-file`, and `key-file` are required —
the gateway's IDevID-derived client certificate **is** the telemetry
identity claim, so an enabled section without it is refused at load time
rather than reporting unauthenticated. For the same reason `base-url`
must be an absolute `https://` URL with a host and no embedded userinfo:
net/http runs no TLS handshake for any other scheme, so an `http://` base
would ship telemetry in cleartext with the mandated client certificate
never presented, while the config still read as mTLS-protected. It must
also carry **no path, query or fragment**, and the reporter reduces it to
its `scheme://host` prefix before appending a route. The reporter builds
endpoints by appending to this value, so anything past the host silently
re-targets the request rather than failing: a base of
`https://cp.example.com?tenant=x` parses with an *empty* path, so the
appended `/api/v1/gateway/telemetry` lands inside the query and every
push goes to `/` — the daemon starts, logs nothing unusual, and never
reaches the control plane. A bare trailing slash is the mild form
(`//api/v1/...`, which servers commonly answer with a redirect that turns
the POST into a GET); it is normalized away rather than refused, since it
is the same base written differently. A path prefix is refused because
none is supported — the routes are absolute under `/api/v1/gateway`.
`gateway-id` defaults to the
gateway node ID; `interval` defaults to 30s and rejects values below 1s
(a unitless YAML `interval: 30` would otherwise decode as nanoseconds and
hot-loop); `ca-file` anchors server verification, falling back to the
trust resolver's internal-class pool when a `trust:` section is
configured, then to the OS trust store. The reporter POSTs
`gwstate.Snapshot` (assembled by `Gateway.Snapshot`,
`pkg/sdn/gateway/snapshot.go`) to `/api/v1/gateway/telemetry` over mTLS.
**The reported `gateway_id` is bound to the client certificate.** The
control plane derives the calling gateway's identity from the **Subject
Common Name of the verified mTLS client certificate** and refuses any
request whose `gateway_id` is not that principal: 401 when no verified
certificate was presented, 403 when a verified certificate names someone
else's gateway. It applies to both gatewayd-facing routes — the telemetry
POST body's `gateway_id` and the desired-config GET's `{id}` path segment
(`pkg/webservice/v1/rest/gateway/identity.go`). Without it, possession of
any single valid gateway certificate was enough to overwrite every other
gateway's snapshot, or to read the control plane's intended BGP ASN, IPAM
pools and PXE posture for the whole fleet, just by naming another ID.

The CN is read directly, not through the CN→DNS-SAN→serialNumber fallback
chain in `pkg/webservice/v1/middleware/mtls.go`: accepting a DNS SAN would
widen the binding to a name any CA in the client bundle can also put in a
*server* certificate, which is the substitution the check exists to
prevent. Identity is read from `VerifiedChains`, never `PeerCertificates`
— only the former is populated after the TLS stack has chained the peer
certificate to the configured `ClientCAs`. The comparison is exact and
case-sensitive; a gateway ID is an opaque configured identifier, not a
hostname.

**The CN is used verbatim and never normalized.** A certificate whose CN
has leading or trailing whitespace is refused (401) rather than trimmed:
trimming would make a certificate issued for `" lab-node-1 "` authenticate
as `lab-node-1`, which is an aliasing path into another gateway's record —
precisely what an exact binding exists to close. A CN that is only
whitespace falls under the same rule. gatewayd reads its own certificate
CN verbatim for the startup check for the matching reason: trimming there
would hide a padded CN from the local comparison while the control plane
refuses that very certificate, turning a clear startup error into a
permanent 403.

gatewayd enforces the same contract at assembly. `BuildReporter` refuses
to start when the resolved gateway ID (the `gateway-id` field, or the
gateway node ID) is not the CN of the configured `cert-file`, with
`ErrGatewayIDCertMismatch`. A mismatch cannot degrade gracefully — it
403s on every push and every fetch, forever — so it fails once with a
precise message instead of warning on a ticker. It separately refuses a
resolved ID that is padded or whitespace-only with
`ErrGatewayIDNotReportable`: a bare CN comparison would wave through the
case where the certificate CN and the gateway ID are *identically*
padded, and the control plane refuses that CN regardless, so the reporter
would 401 forever with both halves agreeing.

The three `state` routes are the WebUI's fleet-wide read/admin surface,
not gatewayd's, and are deliberately **not** cert-bound; the operator
authorization they should carry is tracked separately.

### Desired-config reconciliation (#555)

The pull half of the control loop is `controlplane.Reconciler`
(`pkg/sdn/gateway/controlplane/reconciler.go`), started by `gatewayd serve`
beside the reporter whenever the `control-plane:` section is enabled. On
start and then every `reconcile-interval` (default 60s, minimum 1s, same
unitless-YAML guard as `interval`) it calls `Reporter.FetchDesiredConfig`,
which decodes the response as the typed wire contract
`gwstate.DesiredConfig` (`pkg/sdn/gateway/state/desired.go`), and hands it
to `Gateway.Apply` (`pkg/sdn/gateway/reconcile.go`).

- **The document is typed and closed.** Its sections are exactly what a
  running gateway can bring to a desired state through a live service:
  `load_balancer.vips` (the complete VIP set — absent VIPs are removed,
  changed backends replaced, a changed algorithm re-created) and `nat`
  (`snat_internal_cidr`, empty disables SNAT; `dnat`, the complete
  port-forward set, retargets included). A top-level key this build does
  not know is `ErrDesiredSectionUnsupported`, a malformed document is
  `ErrDesiredConfigMalformed`, a bad address is `ErrDesiredConfigInvalid` —
  refused before any section is touched, never narrowed silently.
- **Apply is declarative and idempotent.** `version` is the control
  plane's revision; when it is empty the gateway derives one from the
  content (`ContentVersion`), so an unchanged document is a no-op and a
  changed one is always applied. A gateway that restarts converges on its
  first pass without the control plane doing anything.
- **A section for a service this node does not run is a typed failure**
  (`ErrDesiredApplyFailed{Section}` wrapping `ErrServiceNotActive`), the
  other sections are still applied, and the version is recorded as applied
  only when every section succeeded.
- **The outcome is reported, not just logged.** `Snapshot.DesiredConfig`
  (`gwstate.DesiredConfigState`: `version`, `applied_at`, `attempted_at`,
  `last_error`) rides the next telemetry push, so the control plane sees
  whether what it authored took effect.

On the control plane the document comes from `DesiredConfigSource`
(`pkg/webservice/v1/rest/gateway/control_plane.go`), which now returns the
typed document; platformd's implementation reads the `gateway.desired:`
block of its own configuration (`pkg/daemon/commands/gateway_control_init.go`)
and validates it before serving, so a control plane authoring intent the
gateway would refuse learns it from its own log. The same document goes to
every gateway until per-gateway overrides exist.

### Host packet filter (`hostfw:`)

The section is `hostfw.Config`; the daemon's own listeners are not configured
here — they come from `ListenerInventory`, which gatewayd fills from its
resolved config. Every field validates at load (`Config.Validate`): interface
names must be valid Linux names, ports non-zero, protocols `tcp`/`udp`
(listeners) or `esp`/`gre` (peers), peer allowances need at least one address,
and two listeners on the same interface, protocol and port are a
`ValidationError` (two inventories disagreeing, never merged silently).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Turn the service on |
| `extra[]` | `{interface, protocol, port, sources[], comment}` | — | Operator-declared listeners the daemons do not own (sshd) |
| `peers[]` | `{interface, protocol: esp\|gre, addresses[]}` | — | WAN peer allowances |
| `tunnels[]` | string | — | Interfaces on which TCP 179 and UDP 3784 are accepted |
| `unfiltered[]` | string | — | Interfaces left open on purpose (rollout aid; visible in the ruleset) |
| `icmp.rate`, `icmp.burst` | uint | 50 / 100 | ICMP and ICMPv6 limit (packets/second, burst); neighbour discovery is never limited |
| `base-ruleset-path` | path | empty | Where the install-time `.nft` file is written (`0600`, atomic rename); empty writes none |

`Render` is pure and deterministic — entries are sorted, so the same policy in
any order yields the same bytes and the same `Fingerprint` — and the netlink
builder consumes the same `Rule` list the text renderer does, so the boot file
and the live table cannot drift. `NewNetlinkApplier` takes `nftables.ConnOption`
values (a caller pins a network namespace with `nftables.WithNetNSFd`).

The `hostfw` handler (`handlers.go`, #568) builds `hostfw.New` from the
`hostfw:` section with `HostRuntime.Listeners` as the inventory and
`HostRuntime.HostFWApplier` as the applier; a section that fails
`hostfw.Config.Validate` is reported as `ErrHostFWConfigInvalid` at start.

### Tunnels and uplinks (`tunnels:`, `uplinks:`)

`pkg/sdn/tunnel` (#582). Field reference:
[`docs/sdn/tunnel/configuration.md`](../sdn/tunnel/configuration.md).

| Invariant | Where |
|---|---|
| A transport's prerequisites are checked before any netlink call: `ipsec`/`wireguard` need a `KeyProvider` (`ErrKeyProviderRequired`), a named uplink must be managed (`ErrUplinkUnknown`) | `Manager.checkPrerequisites` |
| Key material is exactly the length the transport needs (36 / 32 bytes), zeroized after the kernel holds it, and never printed — errors name the reference only (`ErrKeyMaterial`) | `fetchKey`, `zeroize` |
| `ipsec`: SAs before policies before the carrier; any failure unwinds; removal is the reverse; `Rekey` updates SAs in place, outbound first | `installIPsec`, `removeIPsec`, `rekeyIPsec` |
| `wireguard` is `ErrTransportUnavailable` under the `fips` build tag, at validation and at create/rekey | `wireguard_fips.go` |
| Uplink tables are 100–252; source rules at `priority` (default 1000), tunnel pins at `priority - 100` (clamped at 1); rules already in the kernel are adopted, not duplicated | `UplinkManager` |
| A tunnel bound to an uplink is unbound before its interface is removed; a bind failure removes the tunnel just created | `Manager.EnsureTunnel`, `removeTunnelLocked` |

The `backedServiceHandler` (#568) builds both managers from these sections and
hands the tunnel manager a KMS-backed `KeyProvider` from the SDK.

## 6. Persistence

Proxy routes and pools live in a versioned config store; `ReloadProxyConfig`
bumps the version and `GetProxyConfig` reads it. `platformctl proxy reload` is
the CLI form and its help text is literally "Bump the proxy config version" —
it does not re-read a file from disk.

Gateway state is reported to the control plane
(`POST /api/v1/gateway/telemetry`) by the `controlplane.Reporter`, started
from `gatewayd serve` when the `control-plane:` section is enabled, and
desired configuration is fetched from it
(`GET /api/v1/gateway/desired-config/{id}`). **The control plane is the
author.** A gateway that writes its own desired configuration has inverted the
model.

## 7. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/sdn/gateway/**/*_test.go`, `pkg/proxy/*_test.go` | Service lifecycle, config validation, auth-chain capability checks, balancer selection |
| Unit (hostfw) | `pkg/sdn/gateway/services/hostfw/*_test.go` | Golden `.nft` text (`testdata/fixture.nft`), render stability, the undeclared-listener gate, the expression builder against a recording connection, reconcile/rollback with a fake applier |
| Integration (tunnel) | `test/integration/sdn/tunnel_netns_test.go` | Two namespaces over a veth pair: a managed GRE tunnel pinned to an uplink table carries TCP and its pin rule leaves with it; an `ipsec` tunnel carries nothing with mismatched ESP keys, carries traffic with matching keys, survives a lockstep `Rekey`, and leaves no SA behind. Requires root; fails rather than skips without it |
| Integration (hostfw) | `test/integration/sdn/hostfw_netns_test.go` | Two network namespaces over a veth pair and a GRE tunnel: only declared ports answer, an undeclared port times out, GRE from an undeclared source is dropped and admitted once allowed. Requires root; fails rather than skips without it |
| Integration | `test/integration/proxy/`, `test/integration/network/` | Real listeners, real backends |
| **Architecture** | `pkg/arch/gatewayguard_test.go` | `gatewayd`'s import closure |

`pkg/arch/gatewayguard_test.go` runs in `make test` and is **normative**: a
failure is an architecture violation, not a flaky test. It exists so the binary
that terminates untrusted traffic does not silently acquire the whole platform's
dependency tree. Never weaken it to make a build pass.

The proxy's ten interfaces are the fault-injection points: substitute
`AttestationGate` to force an attestation denial, `TokenAuthenticator` to force
a token rejection, `TrustResolver` to force `TrustResolveError`.

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide.

## 8. Observability

`pkg/proxy/audit.go` emits `AuditEvent` to an `AuditSink` — every
authentication and policy decision is auditable, which is the point of putting
the auth chain in the proxy rather than in each backend. `metrics.go` provides
`MetricsSnapshot` and per-route `RouteMetrics`.

Gateway-side: `GetPerfFlows`, `GetPerfDatapath` and `GetPerfConntrack`, surfaced
as `platformctl sdn perf flows|datapath|conntrack`. When the perf backend is not
wired, these return `StatusUnavailable` rather than zeroes — an important
distinction when you are trying to work out whether the datapath is idle or the
instrumentation is off.

## 9. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/sdn/`](../sdn/) — bridges, ports, flows, port authentication, overlay
- Deep dives carried over and not re-verified in this pass:
  [`docs/sdn/gateway/`](../sdn/gateway/) — `edge-mode.md`, `overlay-mode.md`,
  `transit-mode.md`, `loadbalancer.md`, `operations.md`, `configuration.md`
- [`docs/proxy/`](../proxy/) — additional reverse-proxy material
