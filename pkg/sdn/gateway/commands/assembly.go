// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package commands

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"os"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/controlplane"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/proxysvc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/secrets"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	sdkattestation "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/attestation"
	sdkproxy "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/proxy"

	// Register the sdk/go transports gatewayd uses to reach platformd:
	// Unix (gRPC over UDS, the default) and gRPC over TLS.
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
)

// defaultGatewayID names the gateway node when the configuration does not
// set one.
const defaultGatewayID = "gatewayd"

// trustResolveTimeout bounds trust-resolver CA pool resolution during
// assembly.
const trustResolveTimeout = 30 * time.Second

// ServeConfig is the parsed gatewayd configuration: the gateway node
// section, the proxy service section, the platform trust section, the SDN
// section carrying the OVS datapath runtime, and the control-plane
// telemetry section. Any section may be nil when absent from the file.
type ServeConfig struct {
	// Gateway is the `gateway:` section (SDN node services).
	Gateway *gateway.GatewayConfig

	// Proxy is the `proxy:` section (the authenticating reverse proxy).
	Proxy *proxysvc.Config

	// Trust is the `trust:` section (platform trust resolver classes).
	Trust *trust.Config

	// SDN is the `sdn:` section (OVSDB socket, bridge, zones, networks).
	// It supplies the OVS runtime the datapath services (firewall, NAT,
	// load balancer) require.
	SDN *sdn.Config

	// ControlPlane is the `control-plane:` section (telemetry reporting
	// toward platformd's gateway control-plane REST routes).
	ControlPlane *controlplane.Config

	// Secrets is the `secret-store:` section (where the platform secret
	// store is). It backs every kms:// and secret:// reference the gateway
	// configuration carries; without it those references fail closed. The
	// name is not `secrets:` because that key is platformd's resolver
	// switchboard (pkg/app.SecretsConfig) and the same file carries both.
	Secrets *secrets.Config

	// Metrics is the `metrics:` section (the Prometheus endpoint exporting
	// the same telemetry snapshot the control plane receives).
	Metrics *MetricsConfig
}

// serveDecodeHook enables TextUnmarshaler-aware decoding (netip.Addr,
// netip.Prefix, time.Duration) for the gatewayd configuration sections,
// matching platformd's config decoding — without it, viper's default
// hooks cannot decode YAML strings into the sdn: section's subnet and
// address fields.
var serveDecodeHook = viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
	mapstructure.TextUnmarshallerHookFunc(),
	mapstructure.StringToTimeDurationHookFunc(),
	mapstructure.StringToSliceHookFunc(","),
))

// LoadServeConfig extracts the gatewayd configuration sections from a viper
// instance.
func LoadServeConfig(v *viper.Viper) (*ServeConfig, error) {
	cfg := &ServeConfig{}
	if v.IsSet("gateway") {
		gc := &gateway.GatewayConfig{}
		if err := v.UnmarshalKey("gateway", gc, serveDecodeHook); err != nil {
			return nil, &ErrConfigSection{Section: "gateway", Cause: err}
		}
		cfg.Gateway = gc
	}
	if v.IsSet("proxy") {
		pc := &proxysvc.Config{}
		if err := v.UnmarshalKey("proxy", pc, serveDecodeHook); err != nil {
			return nil, &ErrConfigSection{Section: "proxy", Cause: err}
		}
		cfg.Proxy = pc
	}
	if v.IsSet("trust") {
		tc := &trust.Config{}
		if err := v.UnmarshalKey("trust", tc, serveDecodeHook); err != nil {
			return nil, &ErrConfigSection{Section: "trust", Cause: err}
		}
		cfg.Trust = tc
	}
	if v.IsSet("sdn") {
		sc := &sdn.Config{}
		if err := v.UnmarshalKey("sdn", sc, serveDecodeHook); err != nil {
			return nil, &ErrConfigSection{Section: "sdn", Cause: err}
		}
		cfg.SDN = sc
	}
	if v.IsSet("secret-store") {
		sc := &secrets.Config{}
		if err := v.UnmarshalKey("secret-store", sc, serveDecodeHook); err != nil {
			return nil, &ErrConfigSection{Section: "secret-store", Cause: err}
		}
		if err := sc.Validate(); err != nil {
			return nil, &ErrConfigSection{Section: "secret-store", Cause: err}
		}
		cfg.Secrets = sc
	}
	if v.IsSet("control-plane") {
		cc := &controlplane.Config{}
		if err := v.UnmarshalKey("control-plane", cc, serveDecodeHook); err != nil {
			return nil, &ErrConfigSection{Section: "control-plane", Cause: err}
		}
		if err := cc.Validate(); err != nil {
			return nil, &ErrConfigSection{Section: "control-plane", Cause: err}
		}
		cfg.ControlPlane = cc
	}
	if v.IsSet("metrics") {
		mc := &MetricsConfig{}
		if err := v.UnmarshalKey("metrics", mc, serveDecodeHook); err != nil {
			return nil, &ErrConfigSection{Section: "metrics", Cause: err}
		}
		if err := mc.Validate(); err != nil {
			return nil, &ErrConfigSection{Section: "metrics", Cause: err}
		}
		cfg.Metrics = mc
	}
	return cfg, nil
}

// BuildGateway assembles the gateway node from the parsed configuration:
// the config-driven SDN service handlers (overlay, edge, BGP, firewall,
// NAT, ...) plus the proxysvc reverse-proxy handler when the proxy section
// is enabled.
//
// The datapath services (firewall, NAT, load balancer) require the OVS
// runtime (gateway.GatewayRuntime), assembled here from the `sdn:`
// configuration section. Enabling a datapath service without that section
// fails assembly with the typed ErrSDNRequiredForService.
func BuildGateway(ctx context.Context, cfg *ServeConfig, logger *slog.Logger) (*gateway.Gateway, error) {
	if cfg == nil {
		return nil, ErrConfigLoadFailed
	}
	if logger == nil {
		logger = slog.Default()
	}

	gwCfg := cfg.Gateway
	if gwCfg == nil {
		gwCfg = &gateway.GatewayConfig{Enabled: true}
	}
	if !gwCfg.Enabled {
		if cfg.Proxy == nil || !cfg.Proxy.Enabled {
			return nil, ErrNothingEnabled
		}
		return nil, ErrGatewayDisabled
	}
	if gwCfg.ID == "" {
		gwCfg.ID = defaultGatewayID
	}

	// The OVS runtime is assembled only when a datapath service needs it;
	// a proxy-only gatewayd never dials OVSDB even with an sdn: section
	// present. The runtime owns a live OVSDB connection, so every error
	// path below must release it — the deferred close runs unless
	// assembly reaches the success return.
	if service := datapathService(gwCfg); service != "" {
		runtime, err := buildGatewayRuntime(ctx, cfg.SDN, zoneMatrixService(gwCfg), logger)
		if err != nil {
			return nil, err
		}
		if runtime == nil {
			return nil, &ErrSDNRequiredForService{Service: service}
		}
		gwCfg.Runtime = runtime
	}
	assembled := false
	defer func() {
		if !assembled && gwCfg.Runtime != nil {
			if cerr := gwCfg.Runtime.Close(); cerr != nil {
				logger.Warn("gatewayd: closing OVS runtime after failed assembly", slog.Any("error", cerr))
			}
		}
	}()

	// One trust resolver serves the whole daemon: the proxy's client-CA
	// pool and platformd dials, and the secret store's session. Building it
	// once here (rather than per consumer) is what keeps the classes, and
	// the collaborators injected into them, identical everywhere.
	trustResolver, err := buildTrustResolver(cfg.Trust, logger)
	if err != nil {
		return nil, err
	}

	// The host-programming services (host filter, tunnels, transit) take
	// their dependencies from HostRuntime rather than the OVS runtime: the
	// gateway's own listeners for the host filter come from the proxy
	// section, the netlink applier and tunnel manager are the real ones,
	// the secret resolver is the platform secret store from the
	// `secret-store:` section, and the logger is shared.
	host, err := buildHostRuntime(cfg, trustResolver, logger)
	if err != nil {
		return nil, err
	}
	gwCfg.Host = host

	gw, err := gateway.NewGateway(gwCfg)
	if err != nil {
		return nil, err
	}

	// The reputation/age/uptime requirement gates are DHT-mesh admission
	// criteria whose live values are fed by the control-plane telemetry
	// loop. A locally provisioned gatewayd admits itself at its configured
	// minimums so a fresh daemon can start; mesh admission still re-checks
	// against control-plane-reported metrics.
	gw.SetNodeMetrics(
		gwCfg.MinReputation,
		time.Duration(gwCfg.MinAgeDays)*24*time.Hour,
		gwCfg.MinUptimePct,
	)

	if cfg.Proxy != nil && cfg.Proxy.Enabled {
		handler, err := BuildProxyHandler(cfg.Proxy, trustResolver, logger)
		if err != nil {
			return nil, err
		}
		if err := gw.RegisterServiceHandler(handler); err != nil {
			return nil, err
		}
	}
	assembled = true
	return gw, nil
}

// BuildProxyHandler composes the pkg/proxy engine and its trusted-computing
// collaborators from the proxy and trust configuration sections:
//
//   - Server TLS from the configured certificate/key pair, with client
//     verification anchored on client-ca-file or the trust resolver's
//     internal-class CA pool.
//
//   - The production auth chain (pkg/auth mTLS adapter + canonical zone
//     extractor + hot-swappable zone matrix from the platformd sync loop).
//
//   - The pkg/trust resolver adapted behind proxy.TrustResolver for backend
//     pool TLS.
//
//   - The platformd control-plane sync loop over the sdk/go proxy client
//     (lazy-dialed so gatewayd starts on static config when platformd is
//     down, retrying in the background).
//
//   - The trusted-computing collaborators of the auth chain when their
//     config sections are enabled: the platformd-backed attestation gate
//     (proxy attestation:), the platform-token authenticator
//     (proxy token-auth:), and the OPA policy evaluator (proxy opa:).
//
// The proxy never mints or injects credentials toward backends: backends
// authenticate the proxy through its mTLS platform identity and read the
// caller's identity from the trusted X-TP-* headers.
//
// The trust resolver is the daemon-wide instance BuildGateway assembles
// (buildTrustResolver); a nil resolver means the configuration carries no
// `trust:` section, which the grpc platformd protocol refuses.
func BuildProxyHandler(pcfg *proxysvc.Config, resolver trust.Resolver, logger *slog.Logger) (*proxysvc.Handler, error) {
	if pcfg == nil || !pcfg.Enabled {
		return nil, &proxysvc.ErrProxyDisabled{}
	}
	if err := pcfg.Validate(); err != nil {
		return nil, err
	}
	staticCfg := pcfg.EngineConfig()
	needsAuth := configNeedsAuth(&staticCfg)

	if pcfg.Sync.Enabled && pcfg.Platformd.Protocol == proxysvc.PlatformdProtocolGRPC && resolver == nil {
		return nil, ErrTrustRequiredForGRPC
	}

	clientCAs, err := loadClientCAs(pcfg, resolver, needsAuth)
	if err != nil {
		return nil, err
	}
	serverTLS, err := buildServerTLS(pcfg, clientCAs)
	if err != nil {
		return nil, err
	}
	if needsAuth && serverTLS == nil {
		return nil, &proxysvc.ErrServerTLSRequired{}
	}
	if needsAuth && clientCAs == nil {
		return nil, &proxysvc.ErrClientCARequired{}
	}

	deps := proxy.Deps{
		ServerTLS: serverTLS,
		Logger:    logger,
		Audit:     buildAuditSink(pcfg.Audit, logger),
	}

	var matrixProvider *proxysvc.ZoneMatrixProvider
	if pcfg.Sync.Enabled {
		matrixProvider = proxysvc.NewZoneMatrixProvider()
	}

	if clientCAs != nil {
		collabs, err := buildChainCollaborators(pcfg, resolver, logger)
		if err != nil {
			return nil, err
		}
		chain, err := buildAuthChain(clientCAs, matrixProvider, collabs, logger)
		if err != nil {
			return nil, err
		}
		deps.Auth = chain
	}

	if resolver != nil {
		trustAdapter, err := proxysvc.NewTrustResolverAdapter(resolver)
		if err != nil {
			return nil, err
		}
		deps.Trust = trustAdapter
	}

	engine, err := proxy.New(staticCfg, deps)
	if err != nil {
		return nil, err
	}

	var syncer *proxysvc.ConfigSyncer
	if pcfg.Sync.Enabled {
		lazy, err := proxysvc.NewLazyControlPlaneClient(platformdDial(pcfg.Platformd, resolver))
		if err != nil {
			return nil, err
		}
		syncer, err = proxysvc.NewConfigSyncer(proxysvc.SyncerConfig{
			Client:   lazy,
			Reloader: engine,
			Static:   staticCfg,
			Matrix:   matrixProvider,
			Interval: pcfg.Sync.Interval,
			Logger:   logger,
		})
		if err != nil {
			return nil, err
		}
	}

	return proxysvc.NewHandler(proxysvc.HandlerConfig{
		Engine: engine,
		Syncer: syncer,
		Logger: logger,
	})
}

// configNeedsAuth reports whether any static route requires authentication.
// Runtime-synced routes that add auth requirements later are handled by the
// engine's fail-closed Reload checks.
func configNeedsAuth(cfg *proxy.Config) bool {
	for i := range cfg.Routes {
		if cfg.Routes[i].Auth.Mode != proxy.AuthModePublic {
			return true
		}
	}
	return false
}

// buildTrustResolver constructs the platform trust resolver when the trust
// section is configured. It is the ONE place gatewayd assembles a resolver:
// BuildGateway builds it once and hands the same instance to every consumer
// (the proxy's client-CA pool and platformd dials, and the secret store's
// session), so a collaborator injected here reaches all of them.
//
// The internal class permits only the platform-ca strategy, which takes its
// bundle from an injected CABundleProvider rather than from configuration.
// platformd injects an adapter over its own CA; gatewayd has none — it runs
// no CA and reaches the control plane over the network — so its bundle is
// the PEM the provisioning flow projects onto the node, named by
// `trust: internal: ca-file:` and served by trust.FileCABundleProvider.
// Without that path the internal class can never resolve, so assembly fails
// here naming the missing source instead of at the first dial with "no
// strategy succeeded".
func buildTrustResolver(trustCfg *trust.Config, logger *slog.Logger) (trust.Resolver, error) {
	if trustCfg == nil {
		return nil, nil
	}
	var opts []trust.Option
	if internal := trustCfg.Scope(trust.ClassInternal); internal != nil && usesPlatformCA(internal) {
		if internal.CAFile == "" {
			return nil, &ErrPlatformCABundleSourceMissing{}
		}
		opts = append(opts, trust.WithPlatformCA(trust.NewFileCABundleProvider(internal.CAFile)))
	}
	return trust.NewResolver(trustCfg, logging.NewFromSlog(logger), opts...)
}

// usesPlatformCA reports whether a scope's strategy chain lists platform-ca.
func usesPlatformCA(scope *trust.ScopeConfig) bool {
	for _, strategy := range scope.Strategies {
		if strategy == trust.StrategyPlatformCA {
			return true
		}
	}
	return false
}

// loadClientCAs resolves the client-certificate verification pool: an
// explicit client-ca-file wins; otherwise the trust resolver's
// internal-class CA pool is used when authentication is needed.
func loadClientCAs(pcfg *proxysvc.Config, resolver trust.Resolver, needsAuth bool) (*x509.CertPool, error) {
	if pcfg.TLS.ClientCAFile != "" {
		pem, err := os.ReadFile(pcfg.TLS.ClientCAFile)
		if err != nil {
			return nil, &proxysvc.ErrClientCALoadFailed{Path: pcfg.TLS.ClientCAFile, Cause: err}
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, &proxysvc.ErrClientCALoadFailed{Path: pcfg.TLS.ClientCAFile}
		}
		return pool, nil
	}
	if resolver == nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), trustResolveTimeout)
	defer cancel()
	pool, err := resolver.CAPool(ctx, trust.ClassInternal, "")
	if err != nil {
		if needsAuth {
			return nil, err
		}
		return nil, nil
	}
	return pool, nil
}

// buildServerTLS loads the front-door server TLS configuration. Client
// certificates are requested and, when presented, verified against the
// client CA pool at the TLS layer; the auth chain re-validates and extracts
// identity fail-closed at the HTTP layer.
func buildServerTLS(pcfg *proxysvc.Config, clientCAs *x509.CertPool) (*tls.Config, error) {
	if pcfg.TLS.CertFile == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(pcfg.TLS.CertFile, pcfg.TLS.KeyFile)
	if err != nil {
		return nil, &proxysvc.ErrCertificateLoadFailed{CertFile: pcfg.TLS.CertFile, Cause: err}
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
	if clientCAs != nil {
		cfg.ClientCAs = clientCAs
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return cfg, nil
}

// buildAuditSink constructs the production proxy.AuditSink from the proxy
// `audit:` configuration section: a lazily-dialed quicbaas SDK client
// reaching quicbaasd directly for the fire-and-forget RecordAsync
// audit-chain write (pkg/sdn/gateway/proxysvc/audit.go — the same
// quicbaassdk.NewClient plumbing platformd's IAMService.Audit() resolves
// to, reached here without a platformd hop since gatewayd has no
// in-process DAOFactory to source it from).
//
// Unlike the trusted-computing collaborators, audit wiring never fails
// BuildProxyHandler: a disabled section, or any construction error, is
// logged (the latter as a warning) and leaves deps.Audit nil, which
// proxy.New defaults to its no-op sink. The proxy always serves regardless
// of the audit plane's health; SDKAuditSink additionally fails open at
// runtime when quicbaasd itself is unreachable (see audit.go's Record).
func buildAuditSink(acfg proxysvc.AuditConfig, logger *slog.Logger) proxy.AuditSink {
	if !acfg.Enabled {
		return nil
	}
	lazy, err := proxysvc.NewLazyAuditClient(proxysvc.QuicBaaSAuditDial(acfg.QuicBaaSAddr, acfg.QuicBaaSTransport))
	if err != nil {
		logger.Warn("gatewayd: audit sink unavailable, routing decisions will not be recorded", "error", err)
		return nil
	}
	sink, err := proxysvc.NewSDKAuditSink(proxysvc.SDKAuditSinkConfig{
		Client:  lazy,
		Service: acfg.Service,
		Logger:  logger,
	})
	if err != nil {
		logger.Warn("gatewayd: audit sink construction failed, routing decisions will not be recorded", "error", err)
		return nil
	}
	return sink
}

// chainCollaborators bundles the optional trusted-computing collaborators
// the auth chain composes: each nil member leaves the matching chain
// capability disabled and the engine rejects routes that demand it.
type chainCollaborators struct {
	attestation proxy.AttestationGate
	token       proxy.TokenAuthenticator
	policy      proxy.PolicyEvaluator
}

// buildChainCollaborators constructs the enabled trusted-computing
// collaborators from the proxy configuration sections: the platformd-backed
// attestation gate (lazy-dialed like the sync loop so gatewayd starts, and
// fails closed, while platformd is down), the platform-token authenticator,
// and the OPA policy evaluator.
func buildChainCollaborators(pcfg *proxysvc.Config, resolver trust.Resolver, logger *slog.Logger) (chainCollaborators, error) {
	var collabs chainCollaborators
	if pcfg.Attestation.Enabled {
		lazy, err := proxysvc.NewLazyAttestationClient(platformdAttestationDial(pcfg.Platformd, resolver))
		if err != nil {
			return collabs, err
		}
		gate, err := proxysvc.NewSDKAttestationGate(proxysvc.SDKAttestationGateConfig{
			Client:           lazy,
			CacheTTL:         pcfg.Attestation.CacheTTL,
			NegativeCacheTTL: pcfg.Attestation.NegativeCacheTTL,
			Logger:           logger,
		})
		if err != nil {
			return collabs, err
		}
		collabs.attestation = gate
	}
	if pcfg.TokenAuth.Enabled {
		authn, err := proxysvc.NewPlatformTokenAuthenticator(&pcfg.TokenAuth)
		if err != nil {
			return collabs, err
		}
		collabs.token = authn
	}
	if pcfg.OPA.Enabled {
		evaluator, err := proxysvc.NewOPAEvaluator(context.Background(), &pcfg.OPA)
		if err != nil {
			return collabs, err
		}
		collabs.policy = evaluator
	}
	return collabs, nil
}

// buildAuthChain composes the production proxy auth chain: the pkg/auth
// mTLS adapter anchored on the client CA pool, the canonical zone extractor
// plus the hot-swappable zone matrix when the sync loop runs, and the
// enabled trusted-computing collaborators (attestation gate, platform-token
// authenticator, OPA evaluator).
func buildAuthChain(clientCAs *x509.CertPool, matrixProvider *proxysvc.ZoneMatrixProvider, collabs chainCollaborators, logger *slog.Logger) (*proxy.Chain, error) {
	mtlsAdapter, err := auth.NewMTLSAdapterFromRoots(
		logging.NewFromSlog(logger),
		clientCAs,
		auth.WithIdentityField(auth.IdentityFieldCN),
		auth.WithDefaultTenant("default"),
	)
	if err != nil {
		return nil, err
	}
	chainCfg := proxy.AuthChainConfig{
		MTLS:        mtlsAdapter,
		Logger:      logger,
		Attestation: collabs.attestation,
		Token:       collabs.token,
		Policy:      collabs.policy,
	}
	if matrixProvider != nil {
		chainCfg.ZoneExtractor = proxy.NewPolicyZoneExtractor()
		chainCfg.Matrix = matrixProvider.Matrix
	}
	return proxy.NewAuthChain(chainCfg)
}

// dialPlatformd establishes an sdk/go connection to platformd per the
// configured transport. Control-plane interactions go through sdk/go
// exclusively (see cmd/gatewayd/CLAUDE.md); connections live for the
// process lifetime.
func dialPlatformd(ctx context.Context, pcfg proxysvc.PlatformdConfig, resolver trust.Resolver) (platform.Client, error) {
	var opts []platform.Option
	switch pcfg.Protocol {
	case proxysvc.PlatformdProtocolUnix:
		opts = append(opts,
			platform.WithOnlyProtocol(platform.ProtocolUnix),
			platform.WithUnixSocket(pcfg.Socket),
		)
	case proxysvc.PlatformdProtocolGRPC:
		if resolver == nil {
			return nil, ErrTrustRequiredForGRPC
		}
		tlsCfg, err := resolver.TLSConfig(ctx, trust.ClassInternal, pcfg.GRPCAddr)
		if err != nil {
			return nil, err
		}
		opts = append(opts,
			platform.WithOnlyProtocol(platform.ProtocolGRPC),
			platform.WithGRPCAddr(pcfg.GRPCAddr),
			platform.WithTLSConfig(tlsCfg),
		)
	default:
		return nil, &proxysvc.ErrConfigInvalid{Field: "platformd.protocol", Reason: "must be unix or grpc"}
	}
	return platform.Connect(ctx, platform.NewOptions(opts...))
}

// platformdDial returns the lazy dial function the sync loop uses to reach
// the platformd proxy control-plane service.
func platformdDial(pcfg proxysvc.PlatformdConfig, resolver trust.Resolver) proxysvc.DialFunc {
	return func(ctx context.Context) (proxysvc.ControlPlaneClient, error) {
		client, err := dialPlatformd(ctx, pcfg, resolver)
		if err != nil {
			return nil, err
		}
		return sdkproxy.NewClientFromGRPC(client.Proxy()), nil
	}
}

// platformdAttestationDial returns the lazy dial function the attestation
// gate uses to reach the platformd attestation service.
func platformdAttestationDial(pcfg proxysvc.PlatformdConfig, resolver trust.Resolver) proxysvc.AttestationDialFunc {
	return func(ctx context.Context) (proxysvc.AttestationClient, error) {
		client, err := dialPlatformd(ctx, pcfg, resolver)
		if err != nil {
			return nil, err
		}
		return sdkattestation.NewClientFromGRPC(client.Attestation()), nil
	}
}

// buildHostRuntime assembles the dependencies of the host-programming
// services from the serve configuration. The host filter's inventory is
// gatewayd's own listeners: every proxy listener the proxy section binds.
// A proxy listener address that cannot be turned into a rule is a
// configuration error, not a silently open port.
func buildHostRuntime(cfg *ServeConfig, trustResolver trust.Resolver, logger *slog.Logger) (*gateway.HostRuntime, error) {
	host := &gateway.HostRuntime{Logger: logger}
	if cfg.Proxy != nil && cfg.Proxy.Enabled && len(cfg.Proxy.Listeners) > 0 {
		addresses := make(map[string]string, len(cfg.Proxy.Listeners))
		for _, l := range cfg.Proxy.Listeners {
			addresses[l.ID] = l.Address
		}
		inventory, err := gateway.ProxyListenerInventory(addresses)
		if err != nil {
			return nil, &ErrConfigSection{Section: "proxy.listeners", Cause: err}
		}
		host.Listeners = inventory
	}
	resolver, err := buildSecretResolver(cfg, trustResolver, logger)
	if err != nil {
		return nil, err
	}
	host.SecretResolver = resolver
	return host, nil
}

// buildSecretResolver constructs the platform secret store from the
// `secret-store:` section. It serves both consumers of key material: the transit
// speaker's neighbour passwords and TCP-AO master keys, and the tunnel
// manager's ipsec/wireguard keys (the gateway adapts it as the tunnel
// package's KeyProvider). Without the section there is no resolver, and a
// service that references a secret fails closed at start rather than
// running with a reference where a key belongs.
//
// The store session is verified against the daemon-wide trust resolver's
// internal class, so the gateway reads a peer the platform CA vouches for;
// a `secret-store:` section without a `trust:` section is a configuration
// error. The resolver is the one BuildGateway assembled — the internal
// class's CA bundle source is settled there, once, for every consumer.
// The session presents no client certificate of its own (see
// secrets.TLSFunc and #658).
func buildSecretResolver(cfg *ServeConfig, trustResolver trust.Resolver, logger *slog.Logger) (bgp.SecretResolver, error) {
	if cfg.Secrets == nil {
		return nil, nil
	}
	if trustResolver == nil {
		return nil, &ErrConfigSection{Section: "secret-store", Cause: &secrets.ErrTrustRequired{}}
	}
	tlsFn := func(ctx context.Context, endpoint string) (*tls.Config, error) {
		return trustResolver.TLSConfig(ctx, trust.ClassInternal, endpoint)
	}
	store, err := secrets.NewStore(
		secrets.QuicBaaSDial(*cfg.Secrets, tlsFn),
		cfg.Secrets.EffectiveTimeout(),
		logger,
	)
	if err != nil {
		return nil, &ErrConfigSection{Section: "secret-store", Cause: err}
	}
	return store.Resolve, nil
}
