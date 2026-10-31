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
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmsbootstrap "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/trust/bootstrap"

	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/controlplane"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/process"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/proxysvc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/secrets"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec"
	ipsecconfig "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	sdkattestation "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/attestation"
	sdkdevice "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
	sdkgateway "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gateway"
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

	// Trust is the `trust:` section: the verification policy for peers the
	// platform CA did not issue (BMCs). Platform-issued peers are verified
	// against the platform anchor instead, which PlatformCAFile supplies.
	Trust *trust.Config

	// PlatformCAFile is the `platform-ca-file:` key: the platform CA bundle
	// the provisioning flow projects onto the node. gatewayd runs no CA of
	// its own, so this file is its platform anchor — what the proxy's client
	// CAs, the platformd grpc dial, the secret store session and the
	// control-plane reporter verify platform services against.
	PlatformCAFile string

	// SDN is the `sdn:` section (OVSDB socket, bridge, zones, networks).
	// It supplies the OVS runtime the datapath services (firewall, NAT,
	// load balancer) require.
	SDN *sdn.Config

	// ControlPlane is the `control-plane:` section (telemetry reporting
	// toward platformd's gateway control-plane REST routes).
	ControlPlane *controlplane.Config

	// Secrets is the `secret-store:` section (where the platform secret
	// store is). It backs every kms:// reference the gateway
	// configuration carries; without it those references fail closed. The
	// name is not `secrets:` because that key is platformd's resolver
	// switchboard (pkg/app.SecretsConfig) and the same file carries both.
	Secrets *secrets.Config

	// Metrics is the `metrics:` section (the Prometheus endpoint exporting
	// the same telemetry snapshot the control plane receives).
	Metrics *MetricsConfig

	// Process is the `process:` section (the supervised process model,
	// #557). Absent or disabled, every service runs in this process.
	Process *process.Settings

	// DataDir is gatewayd's state directory (--data-dir). It is a flag
	// rather than a configuration section, so it is carried here to reach
	// the collaborators that need somewhere durable to write. The TOFU pin
	// store is the first of those.
	DataDir string
}

// serveDecodeHook is platformd's own configuration decode (config.DecodeHook):
// gatewayd reads sections of the same platform config, so it must decode them
// identically — netip addresses and prefixes, durations, lists and secret
// fields alike.
var serveDecodeHook = config.DecodeHook()

// LoadServeConfig extracts the gatewayd configuration sections from a viper
// instance.
func LoadServeConfig(v *viper.Viper) (*ServeConfig, error) {
	cfg := &ServeConfig{
		DataDir:        v.GetString("data-dir"),
		PlatformCAFile: v.GetString("platform-ca-file"),
	}
	if v.IsSet("gateway") {
		gc := &gateway.GatewayConfig{}
		if err := v.UnmarshalKey("gateway", gc, serveDecodeHook); err != nil {
			return nil, &ErrConfigSection{Section: "gateway", Cause: err}
		}
		cfg.Gateway = gc
	}
	if v.IsSet("proxy") {
		pc := &proxysvc.Config{}
		// Strict, like sdn below: a removed proxy key (a route's
		// required-roles, #926) fails the load instead of being ignored.
		if err := config.CheckViperSection(v, "proxy", pc); err != nil {
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
		// The same strict decode platformd applies: an sdn key the schema
		// no longer has (sdn.networks, sdn.transit) fails the load.
		if err := config.CheckViperSection(v, "sdn", sc); err != nil {
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
	if v.IsSet("process") {
		pc := &process.Settings{}
		if err := v.UnmarshalKey("process", pc, serveDecodeHook); err != nil {
			return nil, &ErrConfigSection{Section: "process", Cause: err}
		}
		cfg.Process = pc
	}
	return cfg, nil
}

// BuildSupervisor assembles the process supervisor the `process:` section
// enables (#557) and attaches it to the gateway configuration, so
// BuildGateway hands every supervised service to a child process. It
// returns nil when the section is absent or disabled, or when there is no
// `gateway:` section whose services could move. The children are started
// with inherited, the part of this process's command line they resolve the
// same way (see childInheritance).
func BuildSupervisor(cfg *ServeConfig, inherited process.Inherited, logger *slog.Logger) (*process.Supervisor, error) {
	if cfg == nil {
		return nil, ErrConfigLoadFailed
	}
	if cfg.Process == nil || !cfg.Process.Enabled || cfg.Gateway == nil {
		return nil, nil
	}
	processCfg, err := cfg.Process.Config(inherited, logger)
	if err != nil {
		return nil, &ErrConfigSection{Section: "process", Cause: err}
	}
	supervisor := process.New(processCfg)
	cfg.Gateway.Supervisor = supervisor
	return supervisor, nil
}

// enabledServices are the services this gatewayd configuration runs: the
// gateway's enabled sections, then the proxy, whose section is gatewayd's
// own rather than the gateway's. A supervised child picks its own process's
// services out of this list.
func enabledServices(cfg *ServeConfig) []string {
	var out []string
	if cfg.Gateway != nil {
		out = cfg.Gateway.EnabledServices()
	}
	if cfg.Proxy != nil && cfg.Proxy.Enabled {
		out = append(out, gateway.ServiceProxy)
	}
	return out
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
	// present, and neither does a supervisor: the datapath child holds the
	// runtime and this process relays to it (#557). The runtime owns a live OVSDB connection, so every error
	// path below must release it — the deferred close runs unless
	// assembly reaches the success return.
	if service := datapathService(gwCfg); service != "" {
		runtime, err := buildGatewayRuntime(ctx, cfg.SDN, zoneMatrixService(gwCfg), runsOverlay(gwCfg), logger)
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

	// One trust resolver and one platform anchor serve the whole daemon.
	// The anchor verifies platform services — the proxy's client-CA pool,
	// platformd dials, the secret store's session; the resolver verifies
	// what the platform did not issue (BMC backends). Building each once
	// here keeps every consumer on the same trust.
	// The resolver serves the proxy alone, so a supervised child that does
	// not host the proxy neither builds it nor touches its pin directory,
	// and neither does a supervisor whose proxy runs in its own child.
	proxyEnabled := cfg.Proxy != nil && cfg.Proxy.Enabled
	proxySupervised := supervised(gwCfg, gateway.ServiceProxy)
	runsProxy := runs(gwCfg, proxyEnabled, gateway.ServiceProxy)
	var trustResolver trust.Resolver
	if runsProxy {
		resolver, err := buildTrustResolver(cfg.Trust, cfg.DataDir, logger)
		if err != nil {
			return nil, err
		}
		trustResolver = resolver
	}
	anchor, err := buildPlatformAnchor(cfg)
	if err != nil {
		return nil, err
	}
	if err := wireOverlayRuntime(ctx, cfg, anchor, gwCfg.Runtime); err != nil {
		return nil, err
	}

	// The host-programming services (host filter, tunnels, transit) take
	// their dependencies from HostRuntime rather than the OVS runtime: the
	// gateway's own listeners for the host filter come from the proxy
	// section, the netlink applier and tunnel manager are the real ones,
	// the secret resolver is the platform secret store from the
	// `secret-store:` section, and the logger is shared.
	host, err := buildHostRuntime(cfg, anchor, logger)
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

	switch {
	case proxyEnabled && proxySupervised:
		// The proxy parses untrusted TLS from the internet; it runs in its
		// own unprivileged child and this process only relays to it (#557).
		if err := gw.RegisterSupervisedService(gateway.ServiceProxy); err != nil {
			return nil, err
		}
	case runsProxy:
		handler, err := BuildProxyHandler(cfg.Proxy, trustResolver, anchor, logger)
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
//     verification anchored on client-ca-file or the platform anchor.
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
// The trust resolver and platform anchor are the daemon-wide instances
// BuildGateway assembles. A nil resolver means the configuration carries no
// `trust:` section, so no backend may use the bmc trust class; a nil anchor
// means no `platform-ca-file:`, which the grpc platformd protocol refuses.
func BuildProxyHandler(pcfg *proxysvc.Config, resolver trust.Resolver, anchor *trust.Anchor, logger *slog.Logger) (*proxysvc.Handler, error) {
	if pcfg == nil || !pcfg.Enabled {
		return nil, &proxysvc.ErrProxyDisabled{}
	}
	if err := pcfg.Validate(); err != nil {
		return nil, err
	}
	staticCfg := pcfg.EngineConfig()
	needsAuth := configNeedsAuth(&staticCfg)

	if pcfg.Sync.Enabled && pcfg.Platformd.Protocol == proxysvc.PlatformdProtocolGRPC && anchor == nil {
		return nil, ErrPlatformAnchorRequiredForGRPC
	}

	clientCAs, err := loadClientCAs(pcfg, anchor, needsAuth)
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
		collabs, err := buildChainCollaborators(pcfg, anchor, logger)
		if err != nil {
			return nil, err
		}
		chain, err := buildAuthChain(clientCAs, matrixProvider, collabs, logger)
		if err != nil {
			return nil, err
		}
		deps.Auth = chain
	}

	if resolver != nil || anchor != nil {
		trustAdapter, err := proxysvc.NewTrustResolverAdapter(resolver, anchor)
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
		lazy, err := proxysvc.NewLazyControlPlaneClient(platformdDial(pcfg.Platformd, anchor))
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
// that verifies a peer the platform CA did not issue.
func buildTrustResolver(trustCfg *trust.Config, dataDir string, logger *slog.Logger) (trust.Resolver, error) {
	if trustCfg == nil {
		return nil, nil
	}
	var opts []trust.Option
	// The tofu strategy pins a BMC's leaf SPKI on first contact and enforces
	// it afterwards, which is only a guarantee if the pin OUTLIVES the
	// process -- an in-memory store would re-trust blindly after every
	// restart, and the shipped templates promise tofu "captures and PERSISTS
	// the pin itself". gatewayd runs no platform storage and must not depend
	// on the control plane to decide whether it trusts a BMC, so the pins are
	// a file under its own state directory.
	if tofuScopes(trustCfg) {
		pinStore, err := newGatewayTOFUPinStore(dataDir)
		if err != nil {
			return nil, err
		}
		opts = append(opts, trust.WithTOFUPinStore(pinStore))
	}
	return trust.NewResolver(trustCfg, logging.NewFromSlog(logger), opts...)
}

// buildPlatformAnchor constructs gatewayd's platform anchor from
// `platform-ca-file:`. gatewayd runs no CA and holds no IDevID, so the
// anchor is the platform CA bundle the provisioning flow projects onto the
// node. Without the key there is no anchor, and every consumer that needs
// one refuses at assembly with its own typed error.
func buildPlatformAnchor(cfg *ServeConfig) (*trust.Anchor, error) {
	if cfg == nil || cfg.PlatformCAFile == "" {
		return nil, nil
	}
	return trust.NewAnchor(trust.NewFileAnchorSource(cfg.PlatformCAFile))
}

// loadClientCAs resolves the client-certificate verification pool: an
// explicit client-ca-file wins; otherwise the platform anchor is used when
// authentication is needed, since the proxy's callers are platform-issued.
func loadClientCAs(pcfg *proxysvc.Config, anchor *trust.Anchor, needsAuth bool) (*x509.CertPool, error) {
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
	if anchor == nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), trustResolveTimeout)
	defer cancel()
	pool, err := anchor.CAPool(ctx)
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
func buildChainCollaborators(pcfg *proxysvc.Config, anchor *trust.Anchor, logger *slog.Logger) (chainCollaborators, error) {
	var collabs chainCollaborators
	if pcfg.Attestation.Enabled {
		lazy, err := proxysvc.NewLazyAttestationClient(platformdAttestationDial(pcfg.Platformd, anchor))
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
func dialPlatformd(ctx context.Context, pcfg proxysvc.PlatformdConfig, anchor *trust.Anchor) (platform.Client, error) {
	opts, err := platformdOptions(ctx, pcfg, anchor)
	if err != nil {
		return nil, err
	}
	return platform.Connect(ctx, opts)
}

// platformdOptions builds the sdk/go connection options for the configured
// transport. Over grpc the connection verifies platformd against the
// platform anchor and presents gatewayd's client identity, because
// platformd's gRPC listener refuses callers without an mTLS certificate or
// a bearer token. The identity files are read on every dial, so a rotated
// credential is used once the connection is re-established.
func platformdOptions(ctx context.Context, pcfg proxysvc.PlatformdConfig, anchor *trust.Anchor) (*platform.Options, error) {
	switch pcfg.Protocol {
	case proxysvc.PlatformdProtocolUnix:
		return platform.NewOptions(
			platform.WithOnlyProtocol(platform.ProtocolUnix),
			platform.WithUnixSocket(pcfg.Socket),
		), nil
	case proxysvc.PlatformdProtocolGRPC:
	default:
		return nil, &proxysvc.ErrConfigInvalid{Field: "platformd.protocol", Reason: "must be unix or grpc"}
	}
	if anchor == nil {
		return nil, ErrPlatformAnchorRequiredForGRPC
	}
	anchorTLS, err := anchor.TLSConfig(ctx)
	if err != nil {
		return nil, err
	}
	if err := pcfg.Validate(); err != nil {
		return nil, err
	}
	tlsCfg := anchorTLS.Clone()
	opts := []platform.Option{
		platform.WithOnlyProtocol(platform.ProtocolGRPC),
		platform.WithGRPCAddr(pcfg.GRPCAddr),
	}
	if pcfg.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(pcfg.CertFile, pcfg.KeyFile)
		if err != nil {
			return nil, &proxysvc.ErrPlatformdIdentityLoadFailed{Path: pcfg.CertFile, Cause: err}
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	if pcfg.TokenFile != "" {
		token, err := readPlatformdToken(pcfg.TokenFile)
		if err != nil {
			return nil, err
		}
		opts = append(opts, platform.WithBearerToken(token))
	}
	opts = append(opts, platform.WithTLSConfig(tlsCfg))
	return platform.NewOptions(opts...), nil
}

// readPlatformdToken reads the bearer token gatewayd presents to platformd.
// Surrounding whitespace, such as the trailing newline of a token written
// by a provisioning tool, is not part of the token.
func readPlatformdToken(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", &proxysvc.ErrPlatformdIdentityLoadFailed{Path: path, Cause: err}
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", &proxysvc.ErrPlatformdIdentityLoadFailed{Path: path}
	}
	return token, nil
}

// platformdDial returns the lazy dial function the sync loop uses to reach
// the platformd proxy control-plane service.
func platformdDial(pcfg proxysvc.PlatformdConfig, anchor *trust.Anchor) proxysvc.DialFunc {
	return func(ctx context.Context) (proxysvc.ControlPlaneClient, error) {
		client, err := dialPlatformd(ctx, pcfg, anchor)
		if err != nil {
			return nil, err
		}
		return sdkproxy.NewClientFromGRPC(client.Proxy()), nil
	}
}

// platformdAttestationDial returns the lazy dial function the attestation
// gate uses to reach the platformd attestation service.
func platformdAttestationDial(pcfg proxysvc.PlatformdConfig, anchor *trust.Anchor) proxysvc.AttestationDialFunc {
	return func(ctx context.Context) (proxysvc.AttestationClient, error) {
		client, err := dialPlatformd(ctx, pcfg, anchor)
		if err != nil {
			return nil, err
		}
		return sdkattestation.NewClientFromGRPC(client.Attestation()), nil
	}
}

// wireOverlayRuntime dials platformd for the overlay's admission inputs,
// only in the gatewayd that runs the overlay: a supervised child whose
// shared configuration enables the overlay but which hosts another service
// dials nothing.
func wireOverlayRuntime(ctx context.Context, cfg *ServeConfig, anchor *trust.Anchor, runtime *gateway.GatewayRuntime) error {
	if runtime == nil || cfg == nil || cfg.Gateway == nil || !runsOverlay(cfg.Gateway) {
		return nil
	}
	pcfg := overlayPlatformdConfig(cfg)
	client, err := dialPlatformd(ctx, pcfg, anchor)
	if err != nil {
		return err
	}
	WireOverlayPlatform(runtime, client)
	runtime.OverlayIPsec = newOverlayIPsec(anchor)
	return nil
}

// newOverlayIPsec returns the builder of the overlay's IPsec: an
// ipsec.Service that follows the overlay's flood lists, as platformd's
// follows its static peers. Its tunnel identity must chain to anchor; a
// gatewayd without a platform-ca-file builds none.
func newOverlayIPsec(anchor *trust.Anchor) func(*ipsecconfig.Config, modes.VTEPAdmitter, *slog.Logger) (gateway.OverlayIPsec, error) {
	return func(cfg *ipsecconfig.Config, admitter modes.VTEPAdmitter, logger *slog.Logger) (gateway.OverlayIPsec, error) {
		if anchor == nil {
			return nil, ipsec.ErrMissingDependency
		}
		svc, err := ipsec.NewEVPNService(cfg, admitter, anchor, logger)
		if err != nil {
			return nil, err
		}
		return svc, nil
	}
}

// WireOverlayPlatform points the overlay admission inputs of runtime at
// platformd through client: the fabric allocations, the device records, the
// latest device verdicts and the device verdict stream. The serve command
// calls it with the platformd connection it dials.
func WireOverlayPlatform(runtime *gateway.GatewayRuntime, client platform.Client) {
	runtime.OverlayPlatform = client
	runtime.OverlayIPAM = &overlayRuntimeIPAM{client: sdkgateway.NewClientFromGRPC(client.Gateway()), now: time.Now}
	runtime.OverlayDevices = &overlayRuntimeDevices{client: sdkdevice.NewClientFromGRPC(client.Device())}
	attestation := sdkattestation.NewClientFromGRPC(client.Attestation())
	runtime.OverlayVerdicts = &overlayRuntimeVerdicts{client: attestation}
	runtime.OverlayVerdictStream = &overlayRuntimeVerdictStream{client: attestation}
}

func overlayPlatformdConfig(cfg *ServeConfig) proxysvc.PlatformdConfig {
	pcfg := proxysvc.PlatformdConfig{}
	if cfg != nil && cfg.Proxy != nil {
		pcfg = cfg.Proxy.Platformd
	}
	if pcfg.Protocol == "" {
		pcfg.Protocol = proxysvc.PlatformdProtocolUnix
	}
	if pcfg.Protocol == proxysvc.PlatformdProtocolUnix && pcfg.Socket == "" {
		pcfg.Socket = proxysvc.DefaultPlatformdSocket
	}
	return pcfg
}

// buildHostRuntime assembles the dependencies of the host-programming
// services from the serve configuration. The host filter's inventory is
// gatewayd's own listeners: every proxy listener the proxy section binds.
// A proxy listener address that cannot be turned into a rule is a
// configuration error, not a silently open port.
func buildHostRuntime(cfg *ServeConfig, anchor *trust.Anchor, logger *slog.Logger) (*gateway.HostRuntime, error) {
	host := &gateway.HostRuntime{Logger: logger, IPsecInventory: ipsecInventoryPath(cfg.DataDir)}
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
	resolver, err := buildSecretResolver(cfg, anchor, logger)
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
// The store session is mutually authenticated (#658). The gateway verifies
// the store against the platform anchor, so it reads a peer the platform CA
// vouches for; a `secret-store:` section without `platform-ca-file:` is a
// configuration error. The anchor is the one BuildGateway assembled, shared
// with every other consumer. The store authenticates the gateway by its
// provisioned node identity — the `control-plane:` cert-file/key-file pair
// the telemetry reporter presents, loaded through the same loadNodeIdentity
// and, like the reporter's, once at start. There is no second credential: a
// `secret-store:` section without that pair is a configuration error, never
// a one-way session.
func buildSecretResolver(cfg *ServeConfig, anchor *trust.Anchor, logger *slog.Logger) (bgp.SecretResolver, error) {
	if cfg.Secrets == nil {
		return nil, nil
	}
	tlsFn, err := secretStoreTLS(cfg, anchor)
	if err != nil {
		return nil, &ErrConfigSection{Section: "secret-store", Cause: err}
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

// secretStoreTLS builds the TLS configuration the secret-store session is
// dialled with: the platform anchor's roots to verify the store, and the
// node identity to present to it. A missing anchor or identity, or an
// identity that does not load, fails here, at service start.
func secretStoreTLS(cfg *ServeConfig, anchor *trust.Anchor) (secrets.TLSFunc, error) {
	if anchor == nil {
		return nil, &secrets.ErrTrustRequired{}
	}
	cp := cfg.ControlPlane
	if cp == nil || cp.CertFile == "" || cp.KeyFile == "" {
		return nil, &secrets.ErrClientIdentityRequired{}
	}
	identity, err := loadNodeIdentity(cp)
	if err != nil {
		return nil, err
	}
	server := func(ctx context.Context, _ string) (*tls.Config, error) {
		return anchor.TLSConfig(ctx)
	}
	return secrets.WithClientIdentity(server, identity), nil
}

// loadNodeIdentity loads the gateway's provisioned mTLS node identity, the
// `control-plane:` cert-file/key-file pair (/etc/gatewayd/client.pem and
// client-key.pem as provisioned). It is the one place the pair is read: the
// telemetry reporter presents it to the control plane and the secret store
// session presents it to the store.
func loadNodeIdentity(cp *controlplane.Config) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(cp.CertFile, cp.KeyFile)
	if err != nil {
		return tls.Certificate{}, &proxysvc.ErrCertificateLoadFailed{CertFile: cp.CertFile, Cause: err}
	}
	return cert, nil
}

// gatewayTOFUPinDir is where gatewayd keeps its TOFU pin records, relative to
// --data-dir.
const gatewayTOFUPinDir = "trust/tofu-pins"

// gatewayVPNRevocationJournal is where gatewayd journals the management
// VPN's revocations the control plane has not yet taken, relative to
// --data-dir.
const gatewayVPNRevocationJournal = "vpn/" + gateway.VPNRevocationJournalFile

// vpnRevocationJournal is the revocation journal under dataDir. Without a
// data directory it is nil, and a gateway hosting the management VPN refuses
// to build it rather than run without one.
func vpnRevocationJournal(dataDir string) *gateway.RevocationJournal {
	if dataDir == "" {
		return nil
	}
	return gateway.NewRevocationJournal(filepath.Join(dataDir, gatewayVPNRevocationJournal))
}

// gatewayIPsecInventory is the record, under --data-dir, of the ESP pairs
// the tunnel manager installed: the only state a later sweep removes.
const gatewayIPsecInventory = "ipsec-installed.json"

// ipsecInventoryPath is the tunnel manager's ESP inventory under dataDir, or
// "" without a data directory, where nothing is recorded and so nothing is
// swept.
func ipsecInventoryPath(dataDir string) string {
	if dataDir == "" {
		return ""
	}
	return filepath.Join(dataDir, gatewayIPsecInventory)
}

// tofuScopes reports whether any configured class lists the tofu strategy.
// The resolver refuses to construct when one does and no pin store was
// injected, so this decides whether the store has to exist at all.
func tofuScopes(trustCfg *trust.Config) bool {
	for _, class := range trust.Classes() {
		scope := trustCfg.Scope(class)
		if scope == nil {
			continue
		}
		for _, strategy := range scope.Strategies {
			if strategy == trust.StrategyTOFU {
				return true
			}
		}
	}
	return false
}

// newGatewayTOFUPinStore builds the file-backed TOFU pin store under dataDir.
// A pin is a public SPKI hash, not a secret, so the directory is 0700 for
// tamper resistance rather than confidentiality: an attacker who can rewrite
// it can redirect first-contact trust.
func newGatewayTOFUPinStore(dataDir string) (trust.TOFUPinStore, error) {
	if dataDir == "" {
		return nil, &ErrTOFUPinDirUnset{}
	}
	dir := filepath.Join(dataDir, gatewayTOFUPinDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, &ErrTOFUPinDirUnusable{Dir: dir, Cause: err}
	}
	backend, err := xkmssdk.NewFileStorageBackend(dir)
	if err != nil {
		return nil, &ErrTOFUPinDirUnusable{Dir: dir, Cause: err}
	}
	return xkmsbootstrap.NewStoragePinStore(backend)
}
