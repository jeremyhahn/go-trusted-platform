# Edge Gateway — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/sdn/gateway/`, `pkg/proxy/`, `cmd/gatewayd` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Design and boundaries: [architecture.md](architecture.md). Transport matrix:
> [api.md](api.md).

---

## 1. Service sections — the configuration model

`pkg/sdn/gateway/node.go:29-39` declares eleven service-name constants. These
strings are the configuration contract:

```go
ServiceOverlay      = "overlay"
ServiceEdge         = "edge"
ServiceTransit      = "transit"
ServiceFirewall     = "firewall"
ServiceBGP          = "bgp"
ServiceDHCP         = "dhcp"
ServicePXE          = "pxe"
ServiceLoadBalancer = "load-balancer"
ServiceNAT          = "nat"
ServiceTunnels      = "tunnels"
ServiceProxy        = "proxy"
```

**`load-balancer` is hyphenated; the other ten are single words.** Configuration
that writes `loadbalancer` or `load_balancer` will not match, and the failure is
a service that silently does not start.

### `GatewayMode` — deprecated, do not build on it

`pkg/sdn/gateway/compat.go:26` declares `GatewayMode uint8` as a three-bit
bitmask (`GatewayModeOverlay`, `GatewayModeEdge`, `GatewayModeTransit`) with an
explicit deprecation notice. `serviceToMode` and `modeToService` translate in
both directions — for **three of the eleven services only**. Eight services have
no bit and cannot be expressed. Retained for API compatibility during migration;
new code uses service sections.

## 2. Exported surface — gateway

| Package | Key files | Role |
|---|---|---|
| `pkg/sdn/gateway` | `node.go`, `types.go`, `runtime.go`, `zone_service.go` | Node model, service registry, runtime lifecycle, zones |
| `pkg/sdn/gateway/modes` | `edge.go`, `edge_p2p.go`, `edge_pxe.go`, `overlay.go`, `transit.go` | Mode implementations |
| `pkg/sdn/gateway/services` | `firewall/`, `loadbalancer/`, `perf/` | Service implementations |
| `pkg/sdn/gateway/controlplane` | `reporter.go`, `config.go` | Reports state up, fetches desired config down; `gatewayd serve` starts the reporter when the `control-plane:` section is enabled |
| `pkg/sdn/gateway/state` | | Local gateway state |
| `pkg/sdn/gateway/proxysvc` | | Proxy service adapter |
| `pkg/sdn/gateway/p2p` | | libp2p discovery, **build-tag gated `platform_p2p`** |

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
telemetry reporter: `base-url`, `cert-file`, and `key-file` are required —
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

Desired-config *application* is not implemented: `FetchDesiredConfig`
exists, but no reconcile loop consumes it yet — only the proxy's own sync
loop pulls configuration down today.

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
