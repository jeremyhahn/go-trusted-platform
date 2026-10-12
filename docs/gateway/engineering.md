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

`NewGateway` registers one handler per enabled section from two tables — or,
when `GatewayConfig.Supervisor` is set, one `supervisedServiceHandler` per
section from neither (see *Supervised handlers* below):

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

Owner design decision (2026-09-26): the EVPN `overlay` service is required, not
optional; it is on the roadmap as #709, and lighting a public address block
depends on it plus gateway HA (#596, #710). Until #709 lands it stays in
`serviceRefusals`.

`HostRuntime` (`runtime.go`, `GatewayConfig.Host`, never from YAML) carries what
the builders need beyond OVS:

| Field | Default when nil | Used by |
|---|---|---|
| `Listeners hostfw.ListenerInventory` | `hostfw.StaticInventory{}` (no daemon listener admitted) | `hostfw` |
| `HostFWApplier hostfw.Applier` | `hostfw.NewNetlinkApplier()` | `hostfw` |
| `TunnelManager` | `tunnel.NewManager(logger, WithKeyProvider(SecretResolver), WithUplinks(tunnel.NewUplinkManager(logger)))` | `tunnels`; its tunnel names are appended to `hostfw.Config.Tunnels` |
| `UplinkManager` | the `tunnel.UplinkManager` built with the default manager (this field is ignored then) | `tunnels`; required alongside an injected `TunnelManager` when `routing-uplinks:` is set (`ErrServiceUnavailable` otherwise) |
| `BGPServer bgp.BGPServerInterface` | in-process GoBGP server | `transit` |
| `SecretResolver bgp.SecretResolver` | none — a neighbour or tunnel that names a reference fails closed (`bgp.ErrSecretResolverRequired`, `tunnel.ErrKeyProviderRequired`) | `transit`, `tunnels` |
| `Logger` | `Runtime.Logger`, else `slog.Default()` | all |

`gatewayd serve` builds it in `commands/assembly.go` (`buildHostRuntime`): the
enabled proxy listeners become the host filter inventory through
`ProxyListenerInventory` (TCP, every interface; a `:0` kernel-assigned port is
omitted because it is unknown before the bind). A listener address that is not
`host:port` fails assembly with `ErrConfigSection{Section: "proxy.listeners"}`
wrapping `ErrListenerInventory{Listener, Address, Cause}`.

### The secret store (`secret-store:`, #592)

One field serves both consumers of key material. `buildSecretResolver`
(`commands/assembly.go`) turns the `secret-store:` section into
`pkg/sdn/gateway/secrets.Store.Resolve` and puts it in
`HostRuntime.SecretResolver`; `buildTunnels` adapts the same function as the
tunnel package's `KeyProvider` (`resolverKeyProvider`). One store, one field,
two consumers.

| Invariant | Where |
|---|---|
| A reference is `kms://<path>` or `secret://<path>`, optionally `?enc=raw\|base64\|hex` and `#<field>`; both schemes name the same store | `parseRef` |
| A bare value is not a reference and never resolves (`ErrSchemeUnsupported`); nor does any other scheme, `?ensure=` included — the gateway reads keys, it does not mint them | `parseRef` |
| A secret with one field needs no `#<field>`; more than one without it is `ErrFieldAmbiguous` | `selectField` |
| An empty secret, an empty field, or a field that decodes to no bytes is `ErrSecretEmpty` — an empty key is a fail-open in every consumer | `decode` |
| Errors name the reference, never the material | every error in `secrets/errors.go` |
| The SDK session is verified against the platform anchor; a `secret-store:` without `platform-ca-file:` is `secrets.ErrTrustRequired` at assembly, not a dial failure later | `buildSecretResolver` |
| One platform anchor and one trust resolver serve the whole daemon. The anchor verifies platform services — the store's session, platformd grpc dials, the proxy's client CAs and `trust-class: platform` backends, the control-plane reporter; the resolver verifies what the platform did not issue (`trust-class: bmc`) | `BuildGateway` → `buildPlatformAnchor`, `buildTrustResolver` |
| gatewayd runs no CA and holds no IDevID, so its anchor is `trust.FileAnchorSource` over the top-level `platform-ca-file:` — the platform CA bundle provisioning projects onto the node, re-read at every verification | `buildPlatformAnchor` |
| A class listing `tofu` gets a **file-backed** pin store at `<--data-dir>/trust/tofu-pins`, created 0700. tofu only means anything if the pin outlives the process, and the shipped templates say it "captures and PERSISTS the pin itself"; an in-memory store would re-trust every BMC after a restart. gatewayd deliberately does NOT reach the platform's pin store for this — BMC trust must not depend on the control plane being up | `buildTrustResolver` → `newGatewayTOFUPinStore` |
| No `--data-dir` while a class lists `tofu` is `ErrTOFUPinDirUnset` at assembly, not a silent downgrade | `newGatewayTOFUPinStore` |
| The session is dialed per resolution and closed after it; a close failure logs and does not refuse the key | `Store.Resolve` |
| Resolved TCP-AO master keys are wiped after `speaker.Start` (GoBGP clones them into its keychain store); tunnel keys are wiped by `pkg/sdn/tunnel` once the kernel holds them | `zeroizeBGPSecrets`, `fetchKey` |

The section is optional. Without it `HostRuntime.SecretResolver` is nil and any
service whose configuration names a reference fails closed at start. The
section is deliberately **not** `secrets:` — that key is platformd's resolver
switchboard (`pkg/app.SecretsConfig`) and a gateway node's file carries both.

### Supervised handlers — `supervised.go` (#557)

`GatewayConfig.Supervisor` (a `ServiceSupervisor`, `yaml:"-"`) switches the
whole registration walk: every enabled section becomes a
`supervisedServiceHandler{name, supervisor}` and neither table is consulted,
because the backend is built in the child process that owns the service.

| Method | Delegates to | Error it returns |
|---|---|---|
| `Start` | `StartService(ctx, name)` | `ErrServiceStartFailed{Service, Cause}` |
| `Stop` | `StopService(ctx, name)` | `ErrServiceStopFailed{Service, Cause}` |
| `IsActive` | `ServiceActive(name)` | — |
| `Health` | `ServiceHealth(name)` | `ErrServiceUnhealthy{Service, Cause}` |

`Gateway.Apply` also switches: with a supervisor it calls
`Supervisor.Apply(ctx, desired)` and stores the returned
`gwstate.DesiredConfigState` as its own, stamping its attempt time over it.
The parent installs no pipeline in this mode — `Runtime` is nil there — and
`needsPipeline()` is false because the datapath child holds the OVS runtime.

`ServiceReports() []ServiceReport` returns `{Name, Active, Health}` per
registered handler in registration order. `Snapshot().Health.Components` is
derived from it, and the IPC `Status` RPC returns the same list, so a service
reads identically from either side of the socket.

**No supervisor is wired into `gatewayd serve` yet**: with `Supervisor` nil —
which is every configuration today — registration is unchanged and the daemon
runs single-process. The interface lives beside the handler so the process
layer that implements it depends on `pkg/sdn/gateway`, never the other way
round (epic #553, R14).

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
| `pkg/sdn/gateway/modes` | `edge.go`, `edge_p2p.go`, `edge_pxe.go`, `overlay.go`, `transit.go` | Handler libraries named after the deprecated modes. **No production code constructs any of them**; only tests do. See [§5a](#5a-handler-libraries-in-modes) |
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
| `ErrPipelineTerminalUnavailable{Terminal, Reason}` | `overlay` asked for before the overlay service owns egress (the overlay is required by owner design decision 2026-09-26; #709) |
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
`ErrStartupFailed`, `ErrShutdownFailed`, `ErrInvalidState`,
`ErrServiceUnhealthy` (a supervised service whose child is down or over its
restart budget; it unwraps to the supervisor's own error).

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
| (transit) | none | Transit is the environment's x00 zone: its VLAN and subnet come from `sdn.environment` like every zone's, and transit point-to-point links take `/31`s from the `tunnel-p2p` IPAM range ([`../architecture/reference-network.md`](../architecture/reference-network.md)). There is no transit section |
| `ManagementVPNConfig` | `enabled`, `type` (only `wireguard` is defined), `allow_to` | Administrators reach management endpoints through this tunnel so operator workstations are **never dual-homed onto a data zone**. Gateways should expose it by default. The section is refused today (#558, [`docs/vpn/`](../vpn/)); owner design decision (2026-09-26): IPsec in FIPS builds, WireGuard only in non-FIPS builds |

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
[platform anchor](../trust/architecture.md#21-platform-anchor) when
`platform-ca-file:` is configured, then to the OS trust store. The reporter POSTs
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
trimming would make a certificate issued for `" gw-01 "` authenticate
as `gw-01`, which is an aliasing path into another gateway's record —
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
- **NAT is per uplink when `uplinks:` is set (#586).** `firewall.NATConfig`
  validates a `natPlan` (pools as inclusive IPv4 ranges with a port range,
  destination prefixes per uplink, exactly one default, statics bound to a
  named or the default uplink; `ErrInvalidNATUplink` / `ErrInvalidStaticNAT`
  / `ErrStaticNeedsUplink` are typed). The compiler keys SNAT on `reg0`
  loaded at the table-20 divert; statics and hairpin are compiled per entry;
  `NATHealth.Uplinks` reports the pools and static counts, and its
  `PoolExhaustion` is always false because OVS has no per-pool counter (see
  `docs/sdn/firewall/architecture.md` §Table 25). The gateway-side
  `NATConfig.Uplinks`/`Static` YAML fields exist; `natServiceHandler`'s
  `natDeps()` maps them into `firewall.NATConfig` — that mapping lands with
  the `backedServiceHandler` rewrite (#568), so until then the YAML fields
  validate but only the single-address path is wired.
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

### IPv6-only clients — NAT64 packet path (`nat64:`)

Decision and trade-off table: [architecture.md](architecture.md) "IPv6-only
clients".

**State.** The translator, its gate and its health are implemented (#601);
`pkg/sdn/gateway/services/nat64` owns the instance. DNS64 (#602) and the
OpenRC packaging (#603) are not yet in, so today the prefix must be resolved
by an upstream DNS64 or a client CLAT, and the module has to be present
before gatewayd starts. The Go userspace fallback (#604) is unbuilt.

OVS `ct(nat)` cannot rewrite between address families, so the translator is
never an OpenFlow action; the pipeline only hands frames to it.

**Packet path, client → IPv4 server.**

1. The IPv6-only client resolves a name. `pkg/dns` with the `dns64` plugin
   (#602) returns the upstream AAAA when one exists; when only an A record
   exists it synthesises `<prefix>::<a.b.c.d>` (RFC 6052 embedding, prefix
   `64:ff9b::/96` or the site prefix). A CLAT on the client learns the prefix
   from `ipv4only.arpa` (RFC 7050) through the same answer.
2. The frame arrives on the client zone port and walks the base pipeline to
   the conntrack gate (table 20). The service's own table-10 gate (priority
   4) admits it there even when neither the firewall nor NAT is running. A
   table-20 divert at priority 210 matches
   `dl_type=0x86dd[,dl_vlan=V],ipv6_dst=<prefix>` and sends it to the
   **table-27 gate** (`TableNAT64`, between `TableLoadBalancer` 26 and
   `TableMACLearning` 30), which rewrites the destination MAC to the
   translator port's own, strips an 802.1Q tag, and outputs to that port
   (unrewritten, the kernel drops the frame as addressed to another host
   before Jool's hook sees it); the table-27 miss continues to table 30 so the
   table is never a black hole. Every frame the divert does not claim meets
   the pipeline's table-20 miss and continues to table 30, so a gateway
   running `nat64:` alone forwards everything else as before. The divert
   outranks the firewall's zone gate on the DNAT precedent — nothing routes
   the translation prefix, so the alternative to translating is dropping —
   and `client-zones:` is where the operator expresses which zones get it.
   Full table in [docs/sdn/firewall/architecture.md](../sdn/firewall/architecture.md)
   §"Table 27".
3. The translator is a **Jool instance** the `nat64:` section owns, in
   netfilter mode: it hooks `PREROUTING` on every host interface. `pool6` is
   the prefix; `pool4` uses the NAT service's pool spelling (`firewall.NATConfig`
   pools — one model, not a second). Jool rewrites the IPv6 header to IPv4
   (RFC 7915 rules, ICMPv6 ↔ ICMP included), allocates a `pool4`
   address:port for the session and sends the IPv4 packet straight to
   `POSTROUTING`, routed by the host like any host-originated packet.
4. A `pool4` address must be one the host answers ARP for on the egress
   side (typically an address of the uplink interface, on a port range the
   host's own sockets do not use), so the IPv4 server's reply reaches the
   host; Jool matches it to the session in `PREROUTING`, translates it back,
   and the host routes the IPv6 reply to the client through the zone's
   router interface.

**Section shape.**

```yaml
nat64:
  enabled: true
  prefix: "64:ff9b::/96"      # RFC 6052; /32,/40,/48,/56,/64 or /96
  instance: tp-nat64          # the kernel instance name
  translator-port: nat640     # the OVS port the table-27 gate outputs to
  pool4:
    uplink: primary                          # optional: the nat.uplinks entry these addresses belong to
    addresses: ["203.0.113.64-203.0.113.71"] # must NOT overlap any NAT44 pool or static external
    port-range-start: 61001
    port-range-end: 65535
  session-timeouts:           # RFC 6146 §3.5 defaults when omitted
    udp: 5m
    tcp-established: 2h4m
    tcp-transitory: 4m
    icmp: 1m
  client-zones:               # empty diverts every frame addressed to the prefix
    - name: iot
      vlan: 300
```

`pool4` reuses the NAT service's pool spelling rather than inventing a second
one, but its ranges must be **disjoint** from every address:port the NAT
service translates to — each uplink's pool, the single-address
`external-ip`, and every static 1:1 external address, which owns all of its
ports: Jool and the OVS conntrack NAT each keep their own allocation table,
and handing both the same address and port produces a collision that looks
like packet loss and explains itself nowhere. The gateway runs that check at
build time because only the gateway sees both sections. `pool4.uplink`, when
set, must name an uplink of an enabled `nat:` section
(`ErrNAT64UplinkUnknown`); it is carried into status and does not steer
egress, which is the host's routing.

jool takes a pool4 entry as a CIDR prefix and refuses the `a-b` range
spelling, so the driver tiles each configured range with the fewest prefixes
that cover it exactly. jool lists pool4 one address per row and one protocol
table per call (`pool4 display` with no protocol shows TCP alone), and the
driver compares at that grain.

Session lifetimes take the RFC 6146 §3.5 defaults when omitted, and the §3.5
minimums are enforced rather than quietly raised — an operator who wrote a
number meant it. `tcp-established` is 2h4m in both cases (REQ-7), not 2h.

The section is a **running backend or a refused start**, like every other:
module not loadable → `ErrNAT64ModuleUnavailable`; prefix not one of the
RFC 6052 lengths → `ErrInvalidNAT64Prefix`; `pool4` overlapping a NAT44 pool
→ `ErrNAT64PoolOverlap`; `pool4` naming more than 65536 addresses (a /16)
→ `ErrPool4TooLarge`; no `translator-port` → `ErrEmptyTranslatorPort`,
because a gate with nowhere to send frames is a black hole. The `fips` build
carries the section unchanged — the translator is not cryptographic.

**Health** is what the kernel said, never the configuration echoed back:
instance presence, session count, `pool4` usage and module version as the
driver read them. `Healthy()` is `Active && InstancePresent && LastError ==
nil`, so a started service whose instance has disappeared underneath it
reports unhealthy, and the section appears in the snapshot's health
components either way.

**Health is kept current by the service itself.** Start reads the kernel's
answer before it reports the service started, and a reconcile loop
(`ReconcileInterval`, 30s) re-converges the instance and the flows and
re-reads the counters; a vanished instance is `ErrInstanceVanished` in
`LastError` and the section turns unhealthy within one interval.

**Reconcile does not flush.** `Driver.Apply` converges an instance that is
already present: only the `pool4` entries that differ are removed and added
(removals first — jool merges an added port range into an overlapping one,
and the removal would then take both) and the timeouts are re-set, because
recreating it would drop every live translation. The one exception is a
changed prefix: jool refuses to change a NAT64 instance's `pool6`, and every
session maps a client through it, so the instance is recreated.

**Stop and restart.** `Stop` is the same clean shutdown every gateway
datapath service performs on a gateway `Stop` — the firewall and NAT delete
their flows, the runtime its pipeline: the flows go first, so no frame is
diverted to a translator that is going away, then the instance. A control
process that exits *without* stopping leaves both in place, and the next
`Start` adopts them. The instance is converged in place, keeping its
sessions. The flows that reach it are left alone until the current set is
installed. The cookie's low 32 bits carry a flow generation, fresh on every
start, so the new set replaces every flow of the same identity. Only then is
each flow still carrying an older generation deleted, by its exact cookie. So
flows rendered from an older configuration (another prefix, a zone no longer
listed) do not survive the start, and the old ones carry traffic until the
new ones are in. A sweep that fails leaves the service running, with the
failure in health, and the reconcile loop retries it.

A start that fails after creating the instance removes it, along with every
flow under the NAT64 owner. A start that fails over an adopted instance
touches neither the instance nor its flows: both carry the previous process's
sessions (#614 review).

**Host filter: nothing to open.** The `hostfw:` input chain never sees
translator traffic. Jool hooks `PREROUTING`, and what it translates goes
straight to `POSTROUTING`, skipping `INPUT` and `FORWARD`; what it does not
translate is not addressed to the host. The translator port is therefore not
an unfiltered interface: leaving it open, as the first cut of #601 did,
exposed every local listener to anything arriving on it.

**Packaging (#603).** gatewayd is not an apk; the installer lays down its
binary and firstboot writes its init script (docs/installer/engineering.md §8),
so the Jool packages arrive the way every other package does:

- `tpconfig.GatewaydPackages` (`pkg/config/gateway_role.go`) names Alpine's
  `jool-modules-lts`, `jool-tools` and `jool-tools-openrc`. The gateway
  templates list them in `os.packages` and the installer's `InstallPackages`
  installs them; a test pins the gateway templates to the list and keeps it
  off control-plane and compute templates.
- A gateway-role ISO (`isoTargetsGatewayRole`) prefetches the same list into
  its offline repository (`CollectRequiredPackages`, `PreFetchConfig.GatewayRole`),
  but only beside the stock `linux-lts` kernel: `jool-modules-lts` depends on
  one exact `linux-lts` build, so a FIPS, kernel-less or non-lts ISO would
  otherwise drag `linux-lts` in beside the kernel it actually boots.
- The init script (`renderGatewaydInitScript`, `pkg/firstboot/gatewayd.go`)
  gains `modprobe jool` in `start_pre` only when the rendered config has
  `gateway.nat64.enabled: true`, decided in Go when firstboot writes it. A
  failed modprobe is an `ewarn`, not a failed `start_pre`: gatewayd is
  launched and the driver refuses the section with `ErrNAT64ModuleUnavailable`
  (`driver.go`), so the reason reaches gatewayd's log instead of OpenRC's.

A kernel upgrade that lags the module package therefore shows up as a refused
section, never as a silent pass-through.

**Fallback (#604).** A Go userspace driver behind the same `Driver` interface,
per-core workers over an OVS internal port. The spike that bounded it is
`test/spike/nat64/main.go` (`//go:build spike`, never in `make test`); its
numbers are in the architecture table. It is filed at `priority:low` and built
only if a deployment needs it.

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

### Tunnels and routing uplinks (`tunnels:`, `routing-uplinks:`)

`pkg/sdn/tunnel` (#582, reachable from configuration since #606). Field
reference: [`docs/sdn/tunnel/configuration.md`](../sdn/tunnel/configuration.md).

**Schema decision (#606).** `gateway.TunnelConfig` is a type alias of
`tunnel.TunnelConfig`, not a gateway-side struct mapped field by field. The
section decodes straight into the type the manager consumes, so there is one
schema and no copy function to fall behind: the old six-field copy silently
dropped `uplink`, `mtu`, `ttl` and `key`, and had to be taught every new
field by hand. The YAML/mapstructure keys of the two types were already
identical, so nothing conflicted. The cost is that validation is the tunnel
package's (`*tunnel.ErrInvalidTunnelConfig`, `*tunnel.ErrTransportUnavailable`
for `wireguard` under the `fips` tag) rather than `ErrConfigurationInvalid`,
and is stricter: `tunnel-ip` and `tunnel-ipv6` must be CIDR, the name at most 15
characters, `local`/`remote` parseable IPs.

**`routing-uplinks:` is a sibling section, not an overload of `uplinks:`.**
`uplinks:` (`gateway.UplinkConfig`) describes the NICs the NAT and
load-balancer services bind to; `routing-uplinks:` (`gateway.RoutingUplinkConfig`,
an alias of `tunnel.UplinkConfig`) describes a policy-routing table (`name`,
`interface`, `table`, `gateway-v4`/`gateway-v6`, `addresses`, `priority`).
A tunnel's `uplink:` names an entry of `routing-uplinks:`.

| Invariant | Where |
|---|---|
| A tunnel naming an `uplink:` not declared under `routing-uplinks:` fails `GatewayConfig.Validate` with `*tunnel.ErrUplinkUnknown`; so does a duplicate uplink name or table (`*tunnel.ErrInvalidUplinkConfig`) | `GatewayConfig.validateTunnels` |
| Start programs every routing uplink first, then the tunnels; a failure at either step removes whatever was created (tunnels in reverse, then the uplink manager's state) | `tunnelsBackend.Start` |
| Stop removes the tunnels, closes the tunnel manager, then closes the `UplinkManager`, so tables go after the tunnels pinned to them | `tunnelsBackend.Stop` |
| A `routing-uplinks:` section alone enables the `tunnels` service | `GatewayConfig.EnabledServices` |

| Invariant | Where |
|---|---|
| A transport's prerequisites are checked before any netlink call: `ipsec`/`wireguard` need a `KeyProvider` (`ErrKeyProviderRequired`), a named uplink must be managed (`ErrUplinkUnknown`) | `Manager.checkPrerequisites` |
| Key material is exactly the length the transport needs (36 / 32 bytes), zeroized after the kernel holds it, and never printed — errors name the reference only (`ErrKeyMaterial`) | `fetchKey`, `zeroize` |
| `ipsec`: SAs before policies before the carrier; any failure unwinds; removal is the reverse; `Rekey` updates SAs in place, outbound first | `installIPsec`, `removeIPsec`, `rekeyIPsec` |
| `wireguard` is `ErrTransportUnavailable` under the `fips` build tag, at validation and at create/rekey | `wireguard_fips.go` |
| Uplink tables are 100–252; source rules at `priority` (default 1000), tunnel pins at `priority - 100` (clamped at 1); rules already in the kernel are adopted, not duplicated | `UplinkManager` |
| A tunnel bound to an uplink is unbound before its interface is removed; a bind failure removes the tunnel just created | `Manager.EnsureTunnel`, `removeTunnelLocked` |

The `backedServiceHandler` (#568) builds both managers from these sections and
hands the tunnel manager the `HostRuntime` secret resolver as its
`KeyProvider` (#592, see the secret store above), so an `ipsec` or `wireguard`
tunnel resolves its key references through the same store the transit speaker
uses, and the `UplinkManager` via `tunnel.WithUplinks`.

Beside the point-to-point `Manager`, the package carries the two remote-access
devices the VPN data planes own (#584 PR 2): `WireGuardHub` — one interface,
one server key from the same `KeyProvider`, and peers added and removed at
runtime without touching the others — and `TUN`, the layer-3 device the MASQUE
plane forwards packets through. Both are documented with the planes in
[`docs/vpn/engineering.md`](../vpn/engineering.md).

### First-hop redundancy (`fhrp:`)

The section is `fhrp.Config`; `Config.Validate` refuses: VRID 0, a missing
interface, an advertisement interval above 4095 cs, no addresses, an address
without a prefix length or that is multicast/loopback/unspecified, mixed
families in one group (one group per family), a missing or wrong-family
`source`, and the same VRID twice on one interface in one family
(`ErrDuplicateGroup`).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Turn the speaker on |
| `groups[].vrid` | 1–255 | — | Virtual router ID; selects the virtual MAC `00:00:5e:00:01:{vrid}` (IPv4) / `00:00:5e:00:02:{vrid}` (IPv6) |
| `groups[].interface` | string | — | Interface the group advertises on and the addresses are programmed on |
| `groups[].priority` | 1–255 | `100` | 255 = address owner (master at once); otherwise the election priority |
| `groups[].advert-interval-cs` | 1–4095 | `100` | Master_Adver_Interval in centiseconds |
| `groups[].preempt` | bool | `true` | A higher-priority backup takes over a lower-priority master |
| `groups[].accept-mode` | bool | `false` | Master answers packets addressed to virtual addresses it does not own |
| `groups[].addresses[]` | `addr/len` | — | Virtual addresses, one family per group |
| `groups[].source` | address | — | Source of advertisements and the §6.4.3 tie-breaker; an address of `interface` in the group's family |

Timers: `Skew_Time = ((256 − priority) × Master_Adver_Interval) / 256`,
`Master_Down_Interval = 3 × Master_Adver_Interval + Skew_Time`, where the
interval is the local one until a master is heard and the master's thereafter
(`Group.SkewTime`, `Group.MasterDownInterval`). Receive checks (`§7.1`): TTL /
hop limit 255, version 3, checksum over the RFC 2460 §8.1 pseudo-header for
both families, our VRID, our address list; anything else is counted in
`Health.Dropped` and ignored.

Typed errors: `ErrInvalidGroupConfig`, `ErrDuplicateGroup`, `ErrInvalidPacket`,
`ErrTransportRequired`, `ErrTransportFailed`, `ErrAddressOperationFailed`,
`ErrSpeakerNotRunning`, `ErrSpeakerAlreadyRunning`, `ErrGroupNotFound`
(`pkg/sdn/fhrp/errors.go`). A failed claim or release is reported in the
group's `LastError` and the state still advances (so the peer does not also
claim); a socket that cannot be opened fails `Start` and stops the groups
already started.

The handler wiring in `node.go` (a `backedServiceHandler` building
`fhrp.New(cfg, fhrp.Deps{Transport: fhrp.NewRawTransport(), Programmer:
fhrp.NewNetlinkProgrammer()})`) is not in gatewayd yet; it is tracked in #596,
together with stateless NAT failover. Conntrack/NAT state sync is #710.

### The process model — `pkg/sdn/gateway/process` (#557)

| Type | What it is |
|---|---|
| `Class`, `Definition` | a privilege class (`ClassKernel`, `ClassParser`) and one process: name, class, hosted services, capabilities, `MemoryMax`, `CPUMax`, `Unprivileged` |
| `DefinitionForService`, `DefinitionByName`, `Definitions`, `Processes` | the class table's lookups; `Processes(enabled)` returns only the processes those services need, each carrying only the enabled ones |
| `Supervisor` | implements `gateway.ServiceSupervisor`: `StartService`, `StopService`, `ServiceActive`, `ServiceHealth`, `Apply`, plus `Snapshot` and `Shutdown` |
| `Config`, `Settings` | the supervisor's wiring, and the `process:` YAML section that builds it |
| `Launcher`, `Spec`, `Child`, `ExecLauncher` | how a child is started; tests substitute a launcher whose children are in-process IPC servers |
| `CgroupManager` | one cgroup v2 leaf per process, `memory.max` and `cpu.max` written before the child exists |
| `Harden` | the child-side privilege drop |

**The class table is not configuration.** `definitions` in `class.go` is the
one place a service's class, capabilities and limits are decided. An operator
turns the model on and tunes its timings; nothing in YAML can give a parser
process `CAP_NET_ADMIN`. Adding a service means adding it to a definition's
`Services` — a service with no process is `ErrServiceUnplaced`, refused at
assembly rather than placed somewhere by default.
`TestClassTable_EveryGatewayServiceIsPlaced` checks the table against
`GatewayConfig.EnabledServices` over a configuration that has every section
switched on by reflection. A section added to the configuration without a
process therefore fails the test, which is how `nat64` was caught after it
landed (#631 review); it runs in `datapath`, the one process holding
`CAP_NET_ADMIN`.

**The privilege drop is split across the exec on purpose.** The parent sets
the ambient capability set and the cgroup at clone time (`SysProcAttr`:
`AmbientCaps`, `UseCgroupFD`, `Pdeathsig`). The child calls `Harden` before it
reads the configuration or opens a socket, in the order the kernel requires:

1. `no_new_privs`, so nothing it later execs can regain privilege.
2. the bounding set reduced to the class's capabilities — **before** the uid
   drop, because `PR_CAPBSET_DROP` needs `CAP_SETPCAP` in the effective set
   and a parser class keeps at most `CAP_NET_BIND_SERVICE`. A reduction placed
   after the drop `EPERM`s, and since a hardening failure is fatal, every
   unprivileged process would fail to start.
3. for an unprivileged class only: the supplementary groups reduced to the
   service group (Linux keeps the inherited list across `setresgid` /
   `setresuid`), `PR_SET_KEEPCAPS` so the uid change does not clear the
   permitted set and with it the ambient capabilities the parent granted, then
   gid and uid — gid first, because dropping the uid first takes away the
   privilege needed to drop the gid.
4. the capability sets rewritten to exactly the class's capabilities —
   permitted, effective and inheritable — and those raised back into the
   ambient set. **This runs for both classes.** Reducing the bounding set does
   not take a capability out of the permitted or effective set, so a
   kernel-class child that skipped this would still hold everything root
   started with — `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`, `CAP_SYS_MODULE` —
   while the class table says it has two. For an unprivileged class this is
   also what takes back the root permitted set that `PR_SET_KEEPCAPS`
   deliberately carried across the uid drop.
5. the parent-death signal re-armed. `commit_creds()` clears a task's
   `pdeath_signal` whenever its euid, egid or capability set changes, so every
   step above that drops privilege also disarms the `Pdeathsig` the parent set
   at clone time — and `Pdeathsig` is the guarantee that a dead supervisor
   never leaves a child programming the kernel. If the supervisor exited
   inside that disarmed window the child is already reparented, the kernel has
   nothing to deliver, and the child refuses to continue
   (`ErrSupervisorExited`) rather than becoming the orphan the signal exists
   to prevent.

A failure at any step is fatal to the child. The syscalls go through the
unexported `hardenOps` seam so the ordering is a unit test rather than a
hope — the drop is irreversible, so a test that made the real calls would
strip the test binary for the rest of the run.

> **Known gap, [#657](http://git.example.internal/jeremyhahn/go-trusted-platform/issues/657).**
> `prctl` and `capset` apply to the calling thread only, while Go routes
> `setresuid`/`setresgid`/`setgroups` through all-thread syscalls. `Harden`
> therefore hardens one OS thread out of however many the Go runtime has
> started. Nothing calls `Harden` yet — PR 3 is what wires it — and closing it
> is an owner call between `syscall.AllThreadsSyscall` (which returns
> `ENOTSUP` under cgo, and gatewayd is built both ways), libcap's Go bindings,
> and dropping before the runtime starts threads.

Hardening before the config read also means a parser never opens a file as
root that it could not open as itself, so a permission bug surfaces on the
first start rather than the first restart.

**Restarts.** A child that exits while the parent still wants services from it
is relaunched after a doubling backoff (`RestartBackoff` → `RestartBackoffMax`),
and the supervisor keeps trying while the budget holds. A *failed* relaunch
spends budget exactly like a crash does: without that, one transient launch
failure would leave still-wanted services down for good, because the watch
goroutine that would have tried again has already returned — and with it,
nothing would ever stop a process that can never start from retrying at the
backoff cap forever. A relaunched child must also answer on its control socket
within `ReadyTimeout` before it counts: `ipc.Dial` is lazy (`grpc.NewClient`
does not connect), so a child that starts and never listens would otherwise be
published as live. One that does not answer is stopped before the next attempt.
A process that stayed up longer than `RestartWindow`
before dying has its crash history and backoff cleared — a daily crash is not
a crash loop. More than `RestartBudget` crashes inside `RestartWindow` and the
supervisor stops: the services stay unhealthy with `ErrRestartBudgetExhausted` in their
health, which an operator sees in the snapshot. An endless crash loop at an
internet edge is worse than a loud stop.

**One launch per process, claimed under the lock.** Deciding to launch and
assigning the child are separate critical sections — the launch itself must not
hold the supervisor's mutex, because it execs — so a `launching` flag is
claimed before the lock is released. Without it, two callers starting two
services of the same process (`firewall` and `nat` both live in `datapath`)
both see no child and both launch; the second launch overwrites `child`,
`client`, `cancel` and `done`, leaving the first child running with nothing
watching it and nothing able to stop it. `Pdeathsig` does not help there — the
supervisor is still alive — so the result is an orphan holding
`CAP_NET_ADMIN`, which is the failure this package exists to prevent. A caller
that does not win the claim falls through to the readiness poll, which already
tolerates a process mid-launch.

**A launch publishes only if the process is still wanted.** The launch runs
unlocked, so a stop can release the process's last service while a child is
starting; that stop finds no child to signal — this one is not published yet —
and tears the process down. Publishing afterwards would leave a live child with
a watch goroutine for a service nobody wants, so the publish re-checks
`stopped`/`stopping`/`wanted` under the lock and, when it has lost, signals and
reaps the child, closes its client, drops the cgroup leaf and returns
`ErrLaunchAbandoned`. A start that loses to a stop is a failed start.

**A start that fails releases what it claimed.** `StartService` is only
successful when the child reports the service active, and the paths that fail
after a launch — the child answering that the service is inactive or
unhealthy, a readiness timeout, an unreachable socket — used to return the
error with the child still running. The gateway's own start rollback
(`node.go`) unwinds the handlers it already started and the failing one is not
among them, so nothing else would have stopped it: for the kernel class, a
live `CAP_NET_ADMIN` child for a startup that failed. `releaseFailedStart`
drops the service from `wanted` and stops the process when it was the last
one; a service another caller still wants keeps its process running. The
teardown does not inherit the caller's cancellation — a start that failed
because its context was cancelled still has a child to stop, and `StopTimeout`
already bounds the wait.

**A stop cleans up whether or not there is a child to signal.** A process
whose restart budget ran out has no child left, and the teardown still has to
run: the cgroup leaf outlives the child that was born into it, and the crash
history has to go so a later start is not judged by the previous run's budget.

**An ambiguous datapath is refused, not resolved.** `Apply` and `Snapshot` go
to the kernel-class process through `datapathClient()`. The class table has one
today, but it is data rather than a type: two would make map iteration order
decide where the desired configuration lands. Two live kernel-class processes
are `ErrAmbiguousDatapath` naming both.

**The supervisor creates `runtime-dir`** before the first launch, group-owned
by the service account at mode `1770`, so a hand-started supervisor works
without the packaged init script; the packaged script creates it too, and both
are idempotent. An existing directory has its mode set rather than assumed,
and one the service group still cannot write is a refusal naming the
directory.

Group **write** is the part that is easy to get wrong and fatal when it is:
every unprivileged child binds its own control socket *after* dropping to the
service uid, and creating an entry needs write on the directory. At 0750 —
the directory still owned by the root supervisor with only its group
changed — routing, proxy, provisioning and vpn all take `EACCES` from bind and
time out in readiness, which reads as four broken children rather than as one
directory permission. The sticky bit is what makes group write safe: the
parsers share one account, so without it any one of them could unlink
another's control socket and take over the name.

**A stop signals before it cancels.** The launch context is what
`exec.CommandContext` watches, and its default cancellation is `Process.Kill`.
Cancelling before `SIGTERM` would race an immediate `SIGKILL` against every
production stop and collapse the whole `StopTimeout` window, so the child would
never withdraw its flows, tunnels or routes. `ExecLauncher` overrides
`cmd.Cancel` to send `SIGTERM` — escalating is the supervisor's job, bounded by
`StopTimeout` — and `stopProcess` releases the context only once the child has
been reaped. Every path that ends a child goes through the same
graceful-then-kill `terminate`, so none of them can wait on a wedged child
forever.

**Nothing launches a child yet.** The `process:` configuration section, the
`gatewayd service run` command and the `serve` wiring that builds a supervisor
land next; until then this package is complete, tested, and referenced by
nothing in the daemon.

### Supervisor IPC — `pkg/sdn/gateway/ipc` (#557)

The contract is `ipc/proto/ipc.proto`, generated into `ipc/gen` with
`buf generate` from `pkg/sdn/gateway/ipc` (its own `buf.gen.yaml`; the output
stays beside the contract rather than going to `sdk/go/gen`, because it is
internal to one binary and no SDK consumer may depend on it).

```
ProcessControlService   Status(StatusRequest) -> StatusResponse
                        Snapshot(SnapshotRequest) -> SnapshotResponse
DatapathService         ApplyDesired(ApplyDesiredRequest) -> ApplyDesiredResponse
```

| Type | Purpose |
|---|---|
| `Server` | serves both services for one child; `Listen(path, mode, gid)`, `Serve()`, `Stop()`, `SetStartError(err)` |
| `Client` | `Status`, `Snapshot`, `ApplyDesired`, `Close` |
| `Node` | what the server drives: `GetState`, `ServiceReports`, `Snapshot`, `Apply`, `DesiredConfigState` — `*gateway.Gateway` satisfies it |
| `Policy` | `ControlUIDs` / `DatapathUIDs`; empty means uid 0 only |

Authentication is `SO_PEERCRED` and nothing else, through
`pkg/util/peercred` (moved there from `pkg/api/grpc` so both platformd's Unix
transport and this IPC share one implementation). The transport credentials
require peer credentials, the required interceptor puts them in the context,
and `Policy.unaryInterceptor` admits per service; an unknown service is
`ErrUnknownService`, so the table fails closed.

`Listen` removes a **stale socket file** (a crashed child's) and refuses to
replace anything that is not a socket, then chmods to the requested mode.
Documents cross as JSON (`gwstate.Snapshot`, `gwstate.DesiredConfig`,
`gwstate.DesiredConfigState`) rather than being redeclared in proto.
`ApplyDesired` always returns the child's state; a child-side apply failure
comes back as `*ErrRemoteApply` with that state beside it.

### The conntrack stage classifies tagged ingress only (open question)

The firewall's stateful pipeline (`zoneflows.CompileStatefulMatrixRules`)
gates a zone's IP traffic through conntrack by matching `dl_vlan=<zone VLAN>`
at table 20. That is the shape of the gateway's port class: a trunk with no
native VLAN, so every frame from the switch arrives tagged. Frames that enter
the OpenFlow tables **untagged** — the gateway's own `zone<VLAN>` internal ports,
which is where its kernel-routed traffic re-enters the bridge — match no gate
rule and take the priority-1 bypass to table 30. The verdict for routed
traffic is therefore given once, on the tagged ingress side, and the routed
egress is not tracked on the bridge. Whether routed traffic is enforced in the
OVS pipeline or in the gateway's own nftables forward chain is an
architecture decision that is still open; it is recorded here rather than
changed silently.

### The load balancer datapath (`load-balancer:`)

The load balancer (`pkg/sdn/gateway/services/loadbalancer`) is an OVS-native
L4 balancer. All balancing happens in the datapath. VIP traffic is spread
across backends by an OpenFlow **select group**, which picks a bucket by hash,
and is translated by **conntrack DNAT** committed in the group buckets. The Go
service compiles VIPs into flows and groups, probes backend health and manages
lifecycle. No packet traverses userspace.

| Feature | Implementation |
|---|---|
| VIP management | `tcp`/`udp` IPv4 VIPs, config-driven at start plus runtime CRUD ([api.md §5](api.md#5-load-balancer)) |
| Algorithms | `hash` and `round-robin`, both mapped to select-group `dp_hash` selection |
| Session persistence | Per-connection stickiness via conntrack (committed DNAT state) |
| Health probes | TCP connect probes with rise/fall hysteresis |
| Weighted backends | Select-group bucket weights (`weight`, default 1) |
| Fail-closed | Zero healthy backends → bucketless group → new connections drop |
| Reply translation | A backend's replies are reverse-translated so the client hears from the VIP |
| Hairpin | Clients on a `hairpin-prefixes` network are source-NATed to the VIP, so a backend on their segment answers through the gateway |
| Recovery | Deterministic group IDs plus `GetGroupDesc` reconciliation on start |

**Not supported:** `least-conn` is rejected with `ErrAlgorithmUnsupported`,
because per-connection bookkeeping cannot be expressed in the OVS group
datapath. UDP VIPs are **unprobed**: there is no protocol-agnostic UDP
liveness signal, so their backends are treated as always healthy and a
warning is logged when a UDP VIP is installed.

Both algorithm names program an `OFPGT_SELECT` group, and OVS picks the bucket
from the datapath flow hash, weighted by bucket weight. Selection is therefore
**per connection**, not per packet: `round-robin` is an accepted alias with no
strict rotation. Once a connection is committed, conntrack pins it to its
backend for its lifetime, and that stickiness survives group rebuilds.

#### Tables, cookie and priorities

The load balancer shares the conntrack pipeline with the firewall (tables
20/21) and NAT (table 25). It owns tables 26, 28 and 29; table 27 is the NAT64
hand-off. Its cookie is `0xF1BE000300000000` under mask `0xFFFFFFFF00000000`
(firewall `0xF1BE0001…`, NAT `0xF1BE0002…`).

```
table 10 (gate)      priority 3: goto_table:20            [LB gate]
                     (firewall gate = prio 2, NAT gate = prio 1; all
                      three are distinct flows and tear down independently)

table 20 (ct gate)   priority 260 per backend B:P of every VIP (reply divert):
                       reg1=0/0x1,ip,nw_proto=P,nw_src=B,tp_src=P
                         -> load:1->reg1[0], ct(table=29,zone=Zhairpin,nat)
                     priority 250 per VIP (request divert):
                       ip,nw_proto=P,nw_dst=VIP,tp_dst=PORT
                         -> ct(table=26,zone=Zvip,nat)
                     (the table-20 miss belongs to the base pipeline,
                      not to the load balancer)

table 26 (dispatch)  priority 400: ct_state=+inv+trk           -> drop
                     priority 300: ct_state=+est+trk           -> goto_table:28
                     priority 300: ct_state=+rel+trk           -> goto_table:28
                     priority 200 per VIP:
                       ct_state=+new+trk,ip,nw_proto=P,nw_dst=VIP,tp_dst=PORT
                         -> group:G
                     priority 0 miss:                          -> drop

group G (select)     one bucket per healthy backend, weight = backend weight
                       ct(commit,zone=Zvip,nat(dst=B:P),table=28)

table 28 (hairpin)   priority 200 per VIP per hairpin prefix H:
                       ct_state=+new+trk,ct_zone=Zvip,ip,nw_src=H
                         -> ct(commit,zone=Zhairpin,nat(src=VIP),table=30)
                       ct_state=+est+trk,ct_zone=Zvip,ip,nw_src=H
                         -> ct(zone=Zhairpin,nat,table=30)
                     priority 0 miss:                          -> goto_table:30

table 29 (reply)     priority 200 per backend B:P (back from the hairpin zone):
                       ct_zone=Zhairpin,ip,nw_proto=P,nw_src=B,tp_src=P
                         -> ct(table=29,zone=Zvip,nat)
                     priority 100: ct_state=+est+rpl+trk       -> goto_table:30
                     priority 0 miss:                          -> resubmit(,20)
```

The load balancer's table-20 diverts (250, 260) outrank every NAT divert
(SNAT 90, SNAT select 95, DNAT 200, static 210, hairpin 220 —
`services/firewall/nat.go`), so a VIP flow is never captured by NAT first.
Each subsystem tears down only its own flows, by its own cookie-masked delete,
and draws its own conntrack zones from the shared allocator, so VIP DNAT state
never leaks into firewall verdicts.

#### Replies are reverse-translated

A VIP connection is DNATed: the client sends to `VIP:PORT` and the backend
receives from the client. The backend's reply carries the backend's address,
`B:P -> client`, so the request divert, which matches `nw_dst=VIP`, never sees
it. Without a reply path the client would hear from `B:P`, an address it never
connected to, and reset the connection.

The service therefore installs a **reply divert per backend**. It is keyed on
the backend's source address and port, and runs `ct(nat)` in the hairpin zone
(table 20), then in the VIP's zone (table 29). Conntrack reverses whatever
translations the connection was committed with, so the client receives
`VIP:PORT -> client`. Both lookups recirculate into table 29, and `ct_zone`
tells them apart: the per-backend flow takes a packet back from the hairpin
zone; a packet back from the VIP zone falls to the verdicts.

**A backend's own traffic is left alone.** The divert matches by source
address:port, so it also catches traffic the backend sends from its service
port that has nothing to do with the VIP, such as a reply to a client that
connected to the backend directly. Table 29 lets only `+est+rpl` (a reply of a
committed VIP connection) continue. Everything else is resubmitted to table 20
with register 1 bit 0 set. The reply divert matches only packets with that bit
clear, so the packet then meets the firewall and NAT gates exactly as if the
load balancer were not installed. The NAT service owns register 0.

**One backend endpoint, one VIP.** Because the reply divert is keyed on the
backend's address:port alone, that endpoint's replies can be steered into one
VIP zone only. A backend `address:port` that already serves another VIP of the
same protocol is refused with `ErrBackendInUse`, at configuration validation,
in `AddVIP` and in `SetBackends`. The same endpoint behind a TCP VIP and a UDP
VIP is fine: they are different tuples.

#### Hairpin source NAT

A client on the same segment as its backend is the case reply translation
alone cannot fix. The gateway forwards the DNATed request back out the port it
arrived on, and the backend sees the client's own address on-link, so it
answers the client directly and the reply never passes the gateway. The fix is
to also **source-NAT the connection to the VIP**: the backend then answers the
VIP, which is the gateway, and the reply is reversed on the way back. Only
clients inside `hairpin-prefixes` get this treatment; everyone else keeps their
own address, so a backend still sees the real client for north-south traffic.

OVS permits NAT arguments only on a committing `ct`, and a committed connection
cannot take a second translation. So the source NAT lives in a **second
conntrack zone**, `Zhairpin`, which every VIP shares:

- **The first packet** of a hairpin connection is committed there with
  `nat(src=VIP)` after the bucket has committed the DNAT in `Zvip`.
- **Later packets** have the same translation applied by
  `ct(zone=Zhairpin,nat)`. That is why table 26 sends established and related
  packets through table 28 rather than straight to table 30.
- **On a reply**, the hairpin zone is consulted first (un-SNAT: the
  destination returns to the client), then the VIP zone (un-DNAT: the source
  becomes the VIP).

Entries in `Zhairpin` are keyed by the backend address:port, which belongs to
one VIP only, so sharing the zone between VIPs cannot collide.

#### Bucket action: commit, DNAT and recirculate in one step

Group buckets carry **actions**, not instructions, so a bucket cannot
`goto_table`. The standard OVS pattern is a single conntrack action that
commits, DNATs and recirculates: `ct(commit,zone=Z,nat(dst=B:P),table=28)`,
with `RecircTable` and `NXCTFCommit` set together on `nx_action_conntrack`.
The encoding produced by `openflow.NewActionCT(NXCTFCommit, zone, 28,
NewActionNATDst(addr, port))`:

```
ffff0030000023200023000100000000002a1c0000000000
ffff00180000232000240000000200110a0001051f900000
  = ct(commit,table=28,zone=42,nat(dst=10.0.1.5:8080))
```

`TestBucketActionEncoding` (`services/loadbalancer/service_test.go`) pins
this byte sequence. `TestParseCTActionBareNAT` (`pkg/sdn/ovs/group_test.go`)
pins the bare `nat` argument of the table-20 divert.

#### Conntrack zones and group IDs

- Each VIP gets its own conntrack zone from the shared `ct.ZoneAllocator`
  (owner `lb`, key `<proto>/<vip>:<port>`, e.g. `tcp/10.100.0.10:443`). The
  hairpin source NAT has one more zone, shared by every VIP (owner `lb`, key
  `hairpin`), allocated at `Start` and released at `Stop`.
- OpenFlow group IDs carry no cookie, so the load balancer owns the dedicated
  range `0x4C420000–0x4C42FFFF` ("LB"). The ID is derived deterministically
  from the VIP key (xxhash low 16 bits, linear probing on collision). On
  `Start` the service lists the bridge groups via `GetGroupDesc`: surviving
  groups in the range are reused with `OFPGC_MODIFY`, stale ones are deleted,
  and groups outside the range are never touched.

#### Lifecycle ordering

- **Start** allocates the hairpin zone first (every VIP's reply divert names
  it), then the groups (flows referencing `group:G` need the group to exist),
  then scaffolding and VIP flows in one batch, then the table-10 gate last, so
  packets never enter an incomplete pipeline. Health probing starts after the
  datapath is programmed. **Start is transactional**: the gateway registers
  the service only after `Start` succeeds, so a failed `Start` has no `Stop`
  to clean up after it. Any failure after the hairpin zone is allocated rolls
  back every load-balancer flow (one cookie-masked delete), the installed
  VIPs' groups and zones, and the hairpin zone, continuing past a failed step.
  The configuration is validated as a whole first: `ValidateVIPSet` refuses a
  duplicate VIP (`ErrVIPExists`) and a backend shared between VIPs
  (`ErrBackendInUse`).
- **AddVIP** installs a VIP whole or not at all. A failed group or flow
  install takes back the group, any flows of the refused batch, and the VIP's
  zone.
- **SetBackends** installs the new set's flows (its reply diverts among them)
  before the group can select a new backend, and deletes the removed
  backends' flows after it no longer can. A removed backend's established
  connections stop being translated, as a removed VIP's do.
- **Stop** cancels probing, strict-deletes the gate first (traffic falls back
  to the base pipeline), removes all LB flows in one cookie-masked delete,
  removes the groups and releases the conntrack zones, the hairpin zone
  included.
- **Reconcile** re-installs all flows (`OFPFC_ADD` replaces identical
  match+priority entries) and rebuilds every group from its current healthy
  set.

The first packet of a new connection takes the slower path through the group
select and conntrack commit. Established connections are plain conntrack
lookups (`+est+trk -> goto_table:28 -> goto_table:30`, plus one lookup in the
hairpin zone for a hairpin client) and are megaflow-cache and offload
friendly. A backend's reply costs two conntrack lookups, the hairpin zone then
the VIP zone, each a recirculation.

#### Health probing

`prober.go` runs a ticker loop (interval `health-check-interval`) that dials
every **TCP** backend concurrently each tick (`net.DialTimeout`, timeout
`health-check-timeout`) and feeds a per-backend rise/fall state machine:

- A healthy backend becomes **unhealthy** after `health-check-fall`
  consecutive failures (default 3), and an unhealthy one becomes **healthy**
  after `health-check-rise` consecutive successes (default 2). Any opposite
  result resets the counter, so flapping never accumulates.
- Every transition rebuilds the VIP's select group from the healthy set and
  is logged.
- **All backends down fails closed:** the group is modified to zero buckets,
  so new connections drop in table 26 while established connections continue
  through conntrack until they expire.
- Backends start healthy at install; the prober demotes unreachable ones. UDP
  backends are never probed.

`Service.SetBackendHealth` forces a backend's health; the prober uses it and
it is available for operational overrides.

#### Configuration and wiring

`gateway.LoadBalancerConfig` (`pkg/sdn/gateway/types.go`) validates the
section as a whole: `health-check-interval` must be positive,
`health-check-timeout` positive and shorter than the interval, `max-backends`
positive, every `hairpin-prefixes` entry an IPv4 prefix
(`ErrInvalidHairpinPrefix`), and the declared `vips` a valid set. The
service library itself defaults zero rise/fall/max-backends (2/3/64), but the
section does not leave `max-backends` to that default. `bridge` optionally
overrides the runtime bridge. The operator-facing example is in
[user.md](user.md#load-balancing).

The service needs the daemon-injected `GatewayRuntime` (flow controller, OVS
client, group client, conntrack zone allocator), assembled by `gatewayd serve`
from its `sdn:` section. Enabling `load-balancer:` without `sdn:` fails
assembly with `ErrSDNRequiredForService`; a runtime-less `Start` fails with
`ErrRuntimeMissing`. `gateway.Gateway` exposes `AddVIP`, `RemoveVIP`, `GetVIP`,
`ListVIPs`, `SetVIPBackends` and `LBStatus`, plus the `LBHealth()` and
`LBService()` accessors; with the service not running every one returns
`ErrServiceNotActive`.

`make integration-test-lb` runs `TestGroupLoadBalancer`
(`test/integration/sdn/group_lb_test.go`) in the devcontainer against real
Open vSwitch, kernel conntrack and network namespaces, with no platformd. The
harness supplies only the table-0 hand-off and a table 30 that forwards a
DNATed packet to its backend's port (and a hairpinned packet back out its
ingress port). It deliberately supplies **no reply flow**, so a load balancer
that failed to reverse-translate replies would fail the test. It asserts a TCP
exchange through a VIP, that a backend stays reachable directly on its service
port, a hairpin handshake in which the backend sees the VIP as its peer, and
distribution, stickiness, prober-driven failover and fail-closed behaviour.

## 5a. Handler libraries in `modes/`

`pkg/sdn/gateway/modes` holds three handlers named after the deprecated
modes: `OverlayModeHandler`, `EdgeModeHandler` and `TransitModeHandler`.
**None of them is constructed by production code.** The `overlay` and `edge`
sections are refused at start ([architecture.md](architecture.md#a-service-section-is-a-running-backend-or-a-refused-start)),
and the `transit` section is built from the `pkg/sdn/bgp` speaker, not from
`TransitModeHandler` (`buildTransit`, `handlers.go`). They are library code
with unit tests. They are documented here so that nobody mistakes them for
the gateway's model, and so the overlay design survives until the `overlay`
section is wired (planned).

### The overlay handler (`OverlayModeHandler`)

The overlay handler makes a node a VXLAN Tunnel Endpoint. It forwards between
one local access port, which carries every local VNI as a VLAN, and remote
VTEPs. Everything is driven by EVPN routes:

| Route | Becomes |
|---|---|
| Type-2 MAC/IP | MAC forwarding to the VTEP; the binding's ARP reply; its IRB host route |
| Type-3 IMET | ingress replication to the VTEP; decap authorisation of the VTEP on the VNI |
| Type-5 IP prefix | a prefix route through the VTEP over the L3VNI |

The route formats, RD/RT derivation and MAC Mobility rules are in
[`docs/sdn/bgp/evpn.md`](../sdn/bgp/evpn.md); the VXLAN port is described in
[`docs/sdn/overlay/architecture.md`](../sdn/overlay/architecture.md).
Everything the handler does is OpenFlow on one bridge: there is no packet-in
path, no controller-side ARP handling and no kernel VXLAN device per peer.

#### One flow-based VXLAN port

`Start` creates one VXLAN port per bridge with `remote_ip=flow` and
`key=flow`. Flows set the tunnel destination (`set_field:tun_dst`) and VNI
(`set_field:tun_id`) of each frame they send to it, and match the VNI
(`tun_id`) and source VTEP (`tun_src`) of each frame received on it. A new
remote VTEP is a flow change, never a port change.

The underlay must carry 9000-byte inner frames: the VTEP config refuses an
underlay MTU below `vxlan.MinimumUnderlayMTU`, the 9000-byte
`vxlan.OverlayMTU` plus 50 bytes of encapsulation.

#### Pipeline

| Table | Name | Function |
|---|---|---|
| 0 | Ingress | everything → 10 |
| 10 | VXLAN decap | access ingress (VLAN → VNI); decap authorisation; every other tunnelled frame dropped |
| 20–29 | Services | firewall, NAT, load balancer (gatewayd services); miss → 30 |
| 30 | MAC | anycast MAC from the access port, or router MAC on the L3VNI → 50; anycast MAC from a VTEP → drop; known MAC → its VTEP or 70; miss → 40 |
| 40 | ARP | ARP replies in the switch; miss → 60 |
| 50 | L3 | host and prefix routes (symmetric IRB); miss → drop |
| 60 | Egress | flood: the access port, then every VTEP on the VNI; miss → drop |
| 70 | Local delivery | out the access port (`IN_PORT` when it came from there) |

The table constants are in `modes/overlay.go`. Every overlay flow carries
`OverlayCookie` (`0xF1BE000000000005`); `Start` and `Stop` remove them with
one cookie-scoped delete.

#### Decap authorisation

A tunnelled frame enters the pipeline only through a table-10 flow matching
`in_port=vxlan, tun_id=<VNI>, tun_src=<VTEP>` (priority 300). Any other frame
from the VXLAN port hits the drop at priority 200. A VTEP is authorised:

- on an L2VNI, while its Type-3 route places it there;
- on the L3VNI, while one of its Type-2 IRB bindings or a Type-5 route it
  carries is installed.

So a VTEP can inject only into the VNIs EVPN says it serves. Before a route is
installed the handler asks the configured `VTEPAdmitter` whether the VTEP may
carry the VNI; a refusal leaves the route uninstalled and is returned as
`ErrVTEPOperationFailed{Operation: "admit"}`. The admitter is required with
EVPN: a config with `EVPNConfig` and no `Admitter` is refused with
`ErrAdmitterNil`, so no route is ever installed unvetted.

A Type-2 route may not claim an address this VTEP answers for, because its ARP
reply and host route would share a flow identity with the gateway's or a local
host's and take their traffic.

- A route claiming the anycast gateway's MAC or IP is refused whole and never
  retried. The handler logs a warning, counts it in
  `OverlayModeStatus.RefusedBindings`, and returns
  `ErrMACOperationFailed{Operation: "install remote"}` wrapping an
  `ErrBindingConflict` that names the owner.
- A route claiming an IP a local host holds on any VNI is held back, not
  refused. It still bridges its MAC to the advertising VTEP; only its ARP
  reply and host route wait. It is logged and counted the same way, and
  `LookupMAC` lists the MAC without the held IP. When the local host goes
  (`ForgetMAC`, `RemoveVNI` of its VNI, or the MAC moving to a remote VTEP),
  every held binding no local host still answers for is applied. A failure to
  apply one is returned as `ErrMACOperationFailed{Operation: "release held"}`,
  and the binding stays held until the next route for that MAC. A withdrawal
  drops a held binding like any other.

This keeps a VM that comes back on another VTEP with a new MAC (a rebuilt VM,
a failover VIP) reachable before its old local entry is forgotten. A route for
a MAC local on the same VNI is no conflict: that is the MAC moving away, which
MAC Mobility has already settled.

#### BUM traffic, ARP suppression and symmetric IRB

**BUM traffic** uses ingress replication from Type-3 routes: the VNI's
table-60 flow outputs the frame to the access port (VLAN-tagged), then once
per remote VTEP on the VNI. OpenFlow never outputs to a frame's ingress port,
which gives split horizon: a flooded frame from a VTEP is never sent back into
the fabric, and a local one never back to the access port.

**ARP requests** from the access port for the anycast gateway — and, with
`ARPSuppression`, for every known IPv4 binding, local or remote — are answered
by a table-40 flow that rewrites the request into the reply and sends it back
out `IN_PORT`. Unanswered ARP floods like other BUM traffic.

**Symmetric IRB:** with `AnycastGatewayIP`/`AnycastGatewayMAC`, every VTEP is
the same gateway, and frames from the access port to the anycast MAC go to
table 50. A tunnelled frame to the anycast MAC is dropped: its ingress VTEP
routes it, so it never needs this one's gateway, and routing it here would let
any VTEP authorised on an L2VNI reach table 50 without the L3VNI's decap
authorisation.

- A local host route rewrites the MACs (anycast MAC → host MAC), tags the
  host's VLAN and delivers locally.
- With an `L3VNI` and the EVPN router MAC, a remote host route (from a Type-2
  route naming the same L3VNI and a router MAC) or a Type-5 prefix route sends
  the frame router MAC to router MAC on the L3VNI to the remote VTEP, which
  routes the last hop. Frames arriving on the L3VNI for this VTEP's router MAC
  go to table 50.

Host routes outrank prefix routes; among prefixes the longest wins. When
several VTEPs advertise one prefix, the lowest VTEP address carries it and a
withdrawal falls back to the next. Only IPv4 is routed.

#### Control plane

| Handler call | EVPN action |
|---|---|
| `AddVNI(vni, vlan)` | segment flows installed, then `JoinVNI(vni, L3VNI)`: the Type-3 route is originated and the routes already received are replayed. A refused join removes the segment again |
| `RemoveVNI(vni)` | `LeaveVNI(vni)`, then everything on the VNI is removed — and the Type-5 prefixes with the last VNI |
| `LearnMAC(vni, mac, ip)` | local delivery flows installed, then `AdvertiseMACIP`. A failed advertisement leaves the flows; learning again retries it |
| `ForgetMAC(vni, mac)` | local flows removed, then `WithdrawMACIP` for each binding. A withdrawal BGP refuses fails the call and is remembered; forgetting the MAC again retries it until BGP takes it, and `RemoveVNI` or `Stop` withdraws it with the VNI. Learning the binding again drops it |
| imported route change | the registered handler installs or removes the flows above |

A switch can apply part of a flow batch and refuse the rest
(`openflow.ErrBatchPartialFailure`). When it refuses any of a change, the
handler sends the mods that put every flow the batch touched back to what it
had committed, so the switch and the handler's state are as they were and the
operation or route can be applied again. A refused start flushes the overlay
flows instead. If the switch refuses the put-back too, the error carries an
`ErrFlowResyncFailed`: the switch may then hold flows the handler does not
track. The handler marks its flows drifted, and the next change of any kind
first flushes the overlay's flows (by cookie) and installs every flow it has
committed, so stale flows such as a decap authorisation do not survive. A
switch refusing that rebuild fails the change with an `ErrFlowResyncFailed`,
and the rebuild is tried again on the change after. The OpenFlow client has no
reconnect hook, so a reconnect alone does not trigger the rebuild; the next
change does.

OVS applies a batch one mod at a time, not atomically, and the OpenFlow client
has no bundle support. So the start and the rebuild send the flows after the
flush in a fail-closed order, the same on every rebuild: the pipeline's last
table first, so a goto only ever reaches a table that is already complete and
the table-0 goto that admits frames comes last; and within a table the highest
priority first, so the table-10 drop of unauthorised tunnelled frames is in
place before the table's miss. No tunnelled frame from an unauthorised VTEP
passes while a batch is landing.

Flows several objects need — every host behind one VTEP needs that VTEP's
L3VNI decap flow — are reference counted: installed with the first holder and
deleted with the last. Holders of one flow can disagree on what it does; the
handler keeps each holder's version, installs the newest, and when the
installed version's last holder lets go, installs the newest version still
held rather than deleting the flow.

#### Configuration (`OverlayModeConfig`)

| Field | Meaning |
|---|---|
| `VTEPConfig` | local IPv4 VTEP, underlay interface and MTU, VXLAN UDP port |
| `EVPNConfig` | EVPN manager; nil bridges local hosts only |
| `BridgeName`, `AccessPort` | the bridge, and the port carrying the VNIs as VLANs |
| `ARPSuppression` | answer ARP for every known binding |
| `AnycastGatewayIP`, `AnycastGatewayMAC` | both or neither; turns on routing |
| `L3VNI` | the IP-VRF of symmetric IRB; needs the anycast gateway and `EVPNConfig.RouterMAC` |
| `Admitter` | vets remote VTEPs; required with `EVPNConfig` (`ErrAdmitterNil`) |

#### Why gatewayd refuses `overlay` today

gatewayd refuses `ServiceOverlay`: its `overlay:` config section has no VTEP
or access-port fields to build the handler from, and VTEP admission is not yet
backed by anything. Wiring it is planned. There is also a pipeline conflict to
resolve first: the overlay's base flows (the table misses of 0, 10, 20 and 30)
have the same table, priority and match as gatewayd's own pipeline flows, so
installing them replaces gatewayd's and the overlay's flush then removes them.
Running both on one bridge needs the gatewayd pipeline to hand those tables to
the overlay first.

### The edge and transit handlers

`EdgeModeHandler` (`modes/edge.go`; `modes/edge_p2p.go` under the
`platform_p2p` build tag; `modes/edge_pxe.go`) and `TransitModeHandler`
(`modes/transit.go`) are unwired library code. Do not read their features as
gateway capabilities:

- **Edge.** IPv6 address pool and leases, per-peer rate limiting, and — only
  under `platform_p2p` — device onboarding and DHT bootstrap over libp2p.
  Without the tag, `OnboardDevice` and `BootstrapDHT` return
  `ErrP2PNotEnabled`. With it, onboarding's TPM steps are placeholders:
  `validateTPMEK` and `verifyTPMQuote` accept any non-empty input and
  `issueIDevID` returns no certificate. The `DDOSProtection` type only flips a
  running flag. The `edge` section is refused at start.
- **Transit.** Prefix announcement over a BGP manager, an RPKI validator,
  route-flap dampening and per-route signing (`RouteSigningKey`,
  `SignRoute` / `VerifyRouteSignature`). The `transit` section does not use
  any of it: `buildTransit` drives the `pkg/sdn/bgp` speaker directly.

The P2P trusted network these handlers anticipate is planned, not
implemented.

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
| Unit (supervisor IPC) | `pkg/sdn/gateway/ipc/ipc_test.go` | A real Unix socket and a real gRPC server per test: status/snapshot/apply round trips, the apply error travelling beside the state, uid admission per service on the live socket, stale-socket takeover |
| Unit (nat64) | `pkg/sdn/gateway/services/nat64/*_test.go`, `pkg/sdn/gateway/nat64_test.go` | Config validation, the Jool command lines and pool4 convergence against a runner scripted with jool 4.1.14's real output, the flow set, start/stop/rollback/adoption and the reconcile loop over fakes |
| Unit (pipeline) | `pkg/sdn/gateway/pipeline_test.go` | Every table a gate or `goto` routes into has an empty-match miss, each datapath service started alone; exactly one table-20 miss and it is the pipeline's; `fail_mode` is set before the pipeline is installed |
| Integration (nat64) | `test/integration/nat64/` (harness) running `test/integration/sdn/nat64_*_test.go` (`nat64vm` tag) | `make integration-test-nat64`: an Alpine VM under QEMU/KVM in the devcontainer, with linux-lts and jool-modules-lts from one repository snapshot (`build/docker/nat64-vm`). The Jool driver against the real module (range tiling, idempotent converge, pool change, prefix change, refusal) and the datapath end to end: an IPv6-only client pings an IPv4-only server through a real gateway running `nat64:` alone, untagged and in a tagged client zone, with ARP/IPv4 and neighbour discovery crossing the same bridge. Fails, never skips, when KVM, the module or a guest test is missing |
| Integration (nat64 surface) | `test/integration/sdn/nat64_surface_test.go` | `GetNAT64Status` against the integration platformd over the CLI, gRPC, Unix, REST, QUIC and MCP: each answers with its "not configured" mapping (the translator is gatewayd-resident and its control-plane wiring is #660), never an unknown method, a 404 or an unmapped opcode |
| Integration | `test/integration/proxy/`, `test/integration/network/` | Real listeners, real backends |
| Spike (not a test) | `test/spike/nat64/main.go` (`//go:build spike`) | The #595 NAT64 throughput measurement: two TUNs in an unprivileged user namespace, one goroutine per direction over a lock-guarded binding table, UDP blast. Run by hand with `unshare -rn go run -tags spike ./test/spike/nat64`; excluded from every `make` target by its tag |
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
as `platformctl sdn gateway perf flows|datapath|conntrack`. When the perf backend is not
wired, these return `StatusUnavailable` rather than zeroes — an important
distinction when you are trying to work out whether the datapath is idle or the
instrumentation is off.

### The telemetry snapshot is the observability surface (#594)

`Gateway.Snapshot` (`pkg/sdn/gateway/snapshot.go`) assembles one document
describing what this gateway's services actually programmed, and everything
else reads it: the control-plane reporter POSTs it, the snapshot RPCs serve
it on every transport, the WebUI renders it and the Prometheus endpoint
exports it. There is one derivation, so the picture cannot disagree with
itself.

**Every section is derived from the service's own status, never from a
handler's bookkeeping.** The rule of #568 — a handler is active only because
the service it drives says so — extends to telemetry:

| Section | Derived from |
|---|---|
| `services[]` | `ServiceHandler.IsActive()` / `Health()`, plus the refusal text of a `refusedServiceHandler` |
| `bgp.peers[]` | `bgp.Speaker.ListPeers` — the FSM state, per-family prefix counters (`received` / `accepted` / `advertised`) and the neighbour's BFD session GoBGP reports |
| `bgp.peers[].bfd` | the peer's `BfdPeerConfig` + `BfdPeerState`; **absent** when BFD is not configured toward that neighbour |
| `tunnels[]` | `tunnel.Manager.ListTunnels` — transport, link state, the uplink pin, link counters and the last successful `Rekey` |
| `uplinks[]` | `tunnel.UplinkManager.List` — the routing table, next hops, source rules and the tunnels pinned into it (#582) |
| `host_firewall` | `hostfw.Service.Health()` — installed, fingerprint, rule count, last reconcile and last error (#569) |
| `firewall` | `firewall.Service.Health()` — flow count and conntrack zones |
| `nat` | `firewall.NAT.Health()` — SNAT/DNAT and the per-uplink pools (#586) |
| `pipeline` | `GatewayRuntime.PipelineStatus()` — owner, terminal and the held fail mode (#567) |

Two invariants make the document readable:

- **A section a gateway does not run is absent, not zeroed.** `nat: null`
  means the NAT service is not running; a NAT section with `dnat_rules: 0`
  means it runs and has no bindings. Collapsing those two into a zero value
  is exactly the report that sends an operator to a shell on the box.
- **A section that cannot be read is omitted and logged, never guessed.**
  When the speaker or netlink refuses, the snapshot carries no peers rather
  than a peer count of zero, and the reason is logged. Live reads are bounded
  by `snapshotTimeout` (5s) so a reporter tick cannot block on a wedged
  speaker.

### Prometheus

`gateway.NewCollector` (`pkg/sdn/gateway/metrics.go`) is a pull collector over
the same snapshot: one scrape takes one snapshot, so the metrics and the
control plane's telemetry always agree and there is no second copy of the
state to keep current. Series are named `gatewayd_<subsystem>_<metric>` and
carry the `gateway` label; the sections above map to `service_active`,
`service_healthy`, `bgp_peer_established`, `bgp_peer_uptime_seconds`,
`bgp_peer_prefixes{direction}`, `bfd_session_up`,
`bfd_failure_transitions_total`, `tunnel_up`, `tunnel_bytes_total`,
`tunnel_packets_total`, `tunnel_last_rekey_timestamp_seconds`,
`uplink_policy_rules`, `uplink_bound_tunnels`, `hostfw_installed`,
`hostfw_rules`, `firewall_flows`, `nat_dnat_rules`, `nat_pool_addresses` and
`pipeline_installed`. An absent section emits **no series** for the same
reason it is absent from the document.

The endpoint is the gatewayd `metrics:` section (`enabled`, `listen`,
default `127.0.0.1:9169`, path `/metrics`), prepared before the datapath
starts: a scrape port the operator asked for and cannot have fails the boot
instead of leaving a gateway running unscraped.

## 9. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/sdn/`](../sdn/) — bridges, ports, flows, port authentication, overlay
- [`docs/sdn/overlay/architecture.md`](../sdn/overlay/architecture.md) — the VXLAN port and VTEP manager
- [`docs/sdn/bgp/evpn.md`](../sdn/bgp/evpn.md) — EVPN route formats, RD/RT derivation, MAC Mobility
- [`docs/proxy/`](../proxy/) — additional reverse-proxy material
- [`docs/dns/`](../dns/) — the DNS service that carries DNS64 for IPv6-only client zones (#602)
