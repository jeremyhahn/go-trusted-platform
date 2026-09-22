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

`HostRuntime` (`runtime.go`, `GatewayConfig.Host`, never from YAML) carries what
the builders need beyond OVS:

| Field | Default when nil | Used by |
|---|---|---|
| `Listeners hostfw.ListenerInventory` | `hostfw.StaticInventory{}` (no daemon listener admitted) | `hostfw` |
| `HostFWApplier hostfw.Applier` | `hostfw.NewNetlinkApplier()` | `hostfw` |
| `TunnelManager` | `tunnel.NewManager(logger, WithKeyProvider(SecretResolver))` | `tunnels`; its tunnel names are appended to `hostfw.Config.Tunnels` |
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
| The SDK session is authenticated by the trust resolver's internal class; a `secret-store:` without a `trust:` is `secrets.ErrTrustRequired` | `buildSecretResolver` |
| One trust resolver serves the whole daemon — the proxy's pools and dials and the store's session — so the internal class is settled once | `BuildGateway` → `buildTrustResolver` |
| The internal class's only strategy, `platform-ca`, resolves through an injected provider; gatewayd has no CA, so it injects `trust.FileCABundleProvider` over `trust: internal: ca-file:`. No path is `ErrPlatformCABundleSourceMissing` at assembly, not a dial failure later | `buildTrustResolver` |
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

### IPv6-only clients — NAT64 packet path (`nat64:`, planned: #601–#604)

Decision and trade-off table: [architecture.md](architecture.md) "IPv6-only
clients". Nothing below is implemented yet; the identifiers that exist today
are named as such, the rest is the contract the follow-up issues build to.

**Today.** The NAT service is NAT44 only. Its table-20 gate passes every
IPv6 frame untranslated (`prioIPv6Pass`, `dl_type=0x86dd`, in
`services/firewall/nat.go`), and `dnsserver.Directives` in
`pkg/dns/service.go` is `trustedPlatform, log, chaos, forward` — no `dns64`.
OVS `ct(nat)` cannot rewrite between address families, so the translator is
never an OpenFlow action.

**Planned path, client → IPv4 server.**

1. The IPv6-only client resolves a name. `pkg/dns` with the `dns64` plugin
   (#602) returns the upstream AAAA when one exists; when only an A record
   exists it synthesises `<prefix>::<a.b.c.d>` (RFC 6052 embedding, prefix
   `64:ff9b::/96` or the site prefix). A CLAT on the client learns the prefix
   from `ipv4only.arpa` (RFC 7050) through the same answer.
2. The frame arrives on the client zone port and walks the base pipeline to
   the conntrack gate (table 20). A new **table-27 gate** (`TableNAT64`,
   between `TableLoadBalancer` 26 and `TableMACLearning` 30; #601) matches
   `dl_type=0x86dd, ipv6_dst=<prefix>/96` and outputs to the translator's
   port. Every other IPv6 frame keeps the `prioIPv6Pass` behaviour.
3. The translator is a **Jool instance** the `nat64:` section owns (#601):
   `pool6` is the prefix, `pool4` is drawn from the NAT service's uplink pool
   model (`firewall.NATConfig` pools — one model, not a second). Jool rewrites
   the IPv6 header to IPv4 (RFC 7915 rules, ICMPv6 ↔ ICMP included),
   allocates a `pool4` address:port for the session and emits the IPv4
   packet on the host side.
4. The IPv4 packet enters the uplink's existing NAT44 path only if `pool4`
   is private; when `pool4` is a public range on the uplink (the intended
   shape) it leaves the uplink directly. Return traffic matches the Jool
   session and is translated back to the client's IPv6 address.

**Section shape (#601).**

```yaml
nat64:
  enabled: true
  prefix: 64:ff9b::/96        # RFC 6052; /32,/40,/48,/56,/64 or /96
  pool4:
    uplink: primary            # a named uplink from uplinks:; its pool ranges
  session-timeouts:            # RFC 6146 §4 defaults when omitted
    udp: 5m
    tcp-established: 2h
    tcp-transitory: 4m
    icmp: 1m
```

The section is a **running backend or a refused start**, like every other:
module not loadable → `ErrNAT64ModuleUnavailable`; prefix not one of the
RFC 6052 lengths → `ErrInvalidNAT64Prefix`; `pool4` overlapping a NAT44 pool
→ `ErrNAT64PoolOverlap`. The `fips` build carries the section unchanged — the
translator is not cryptographic. Health rides `Snapshot` (instance present,
`pool4` usage, session count, module version).

**Host filter.** The Jool instance is host-side, so `hostfw:` (`services/hostfw`)
needs an explicit rule admitting the translator's traffic; the undeclared-listener
gate does not cover it (#601).

**Packaging (#603).** The gatewayd OpenRC package depends on Alpine's
`jool-modules-lts`, `jool-tools`, `jool-tools-openrc`; the init script's
`start_pre` runs `modprobe jool` when a `nat64:` section is configured. A
kernel upgrade that lags the module package shows up as a refused section,
never as a silent pass-through.

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
hands the tunnel manager the `HostRuntime` secret resolver as its
`KeyProvider` (#592, see the secret store above), so an `ipsec` or `wireguard`
tunnel resolves its key references through the same store the transit speaker
uses.

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
fhrp.NewNetlinkProgrammer()})`) lands with #568.

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
as `platformctl sdn perf flows|datapath|conntrack`. When the perf backend is not
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
- Deep dives carried over and not re-verified in this pass:
  [`docs/sdn/gateway/`](../sdn/gateway/) — `edge-mode.md`, `overlay-mode.md`,
  `transit-mode.md`, `loadbalancer.md`, `operations.md`, `configuration.md`
- [`docs/proxy/`](../proxy/) — additional reverse-proxy material
- [`docs/dns/`](../dns/) — the DNS service that carries DNS64 for IPv6-only client zones (#602)
