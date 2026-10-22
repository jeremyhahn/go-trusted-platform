// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict/feed"

	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-codec"
	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	grpccreds "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/barrier"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/orchestrator"
	platformservice "github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/perf"
	ipambackends "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vpn"
	bmcwebsvc "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// DaemonOption is a functional option for configuring the Daemon
type DaemonOption func(*Daemon)

// WithGRPCServer sets a custom gRPC server implementation
// TLSAttestor lets a replacement transport server (WithRESTServer,
// WithGRPCServer, WithQUICServer) declare that it terminates TLS. The
// daemon cannot inspect an arbitrary implementation's listener, so a
// replaced server starts only when it implements TLSAttestor and returns
// true — otherwise startup fails closed (#32). The servers New builds are
// governed by their own construction-time checks and need no attestation.
type TLSAttestor interface {
	// ServesTLS reports whether every network listener the server binds
	// terminates TLS.
	ServesTLS() bool
}

// attestsTLS reports whether a replacement server declares TLS service.
func attestsTLS(server any) bool {
	attestor, ok := server.(TLSAttestor)
	return ok && attestor.ServesTLS()
}

func WithGRPCServer(s GRPCServerInterface) DaemonOption {
	return func(d *Daemon) {
		d.grpcServer = s
		// Fail closed (#32): the replacement server's TLS state is unknown
		// to the daemon, and the construction-time grpcTLSCredsAttached
		// flag describes the server New built — not this one. Clearing it
		// means a replaced gRPC server binds the TCP listener only when it
		// attests TLS via TLSAttestor.
		d.grpcTLSCredsAttached = false
		d.grpcServerReplaced = true
	}
}

// WithQUICServer sets a custom QUIC server implementation
func WithQUICServer(s QUICServerInterface) DaemonOption {
	return func(d *Daemon) {
		d.quicServer = s
		// Fail closed (#32): a replacement server's TLS state is unknown.
		// It must attest via TLSAttestor to be allowed to start.
		d.quicServerReplaced = true
	}
}

// WithRESTServer sets a custom REST server implementation
func WithRESTServer(s RESTServerInterface) DaemonOption {
	return func(d *Daemon) {
		d.restServer = s
		// Fail closed (#32): a replacement server's TLS state is unknown.
		// It must attest via TLSAttestor to be allowed to start.
		d.restServerReplaced = true
	}
}

// WithMCPServer sets a custom MCP server implementation
func WithMCPServer(s MCPServerInterface) DaemonOption {
	return func(d *Daemon) {
		d.mcpServer = s
		d.mcpServerReplaced = true
	}
}

// WithGRPCUDSServer sets a custom gRPC UDS server implementation
func WithGRPCUDSServer(s GRPCServerInterface) DaemonOption {
	return func(d *Daemon) {
		d.grpcUDSServer = s
	}
}

// Daemon manages the platformd daemon lifecycle
type Daemon struct {
	config     *Config
	logger     *logging.Logger
	grpcServer GRPCServerInterface // gRPC server for TCP
	// grpcTLSCredsAttached records, immutably at construction, whether New
	// attached TLS transport credentials to grpcServer. Start refuses to
	// bind the TCP listener on this flag rather than by re-reading the
	// mutable config: material added to the config after New cannot make a
	// server that was BUILT plaintext acceptable (#32).
	grpcTLSCredsAttached bool
	// {grpc,rest,quic}ServerReplaced record that a With*Server option
	// swapped in an implementation the daemon did not build. A replaced
	// server starts only if it attests TLS via TLSAttestor — the daemon
	// cannot inspect an arbitrary implementation's listener, so it
	// requires the declaration and otherwise fails closed (#32).
	grpcServerReplaced bool
	restServerReplaced bool
	quicServerReplaced bool
	// mcpServerReplaced records that WithMCPServer swapped in an MCP
	// server. The built-in one is TLS-or-nothing by construction (#844),
	// so the preflight's MCP certificate check applies only to it.
	mcpServerReplaced bool
	// retryUnsafe is set by rollbackPartialStart after it had to stop a
	// gRPC server that had already served: grpc.Server.Stop is permanent,
	// so a Start retry on this instance cannot restore that transport and
	// must be refused (construct a new Daemon instead).
	retryUnsafe        bool
	grpcListener       net.Listener
	grpcUDSServer      GRPCServerInterface // gRPC server for Unix socket
	grpcUDSListener    net.Listener        // Unix socket listener for gRPC
	quicServer         QUICServerInterface
	quicHandler        *QUICServiceHandler
	restServer         RESTServerInterface
	service            *Service
	caService          *CAGRPCService
	sdnService         *SDNService
	kmsService         *KMSService
	kmsPlatformGRPC    *grpccreds.KMSGRPCService
	kmsPlatformBackend *PlatformKMSBackend
	iamService         *IAMService
	tenantService      *TenantService
	vtpmService        *VTPMServiceServer
	deviceService      *DeviceGRPCService
	computeService     *ComputeGRPCService
	idevidService      *IDevIDGRPCService
	tpmService         *TPMGRPCService
	barrierService     *BarrierGRPCService
	attestationService *AttestationServiceServer
	registryService    *grpccreds.RegistryGRPCService
	// dbKeySigner performs control-plane Secure Boot DB digest signing for
	// resign-mode "remote" nodes via the config delivery /provisioning/sign
	// endpoint. nil when no server-side KMS/CA is available.
	dbKeySigner configdelivery.DBKeySigner
	// configDeliveryService is the pre-enrollment config delivery service
	// shared by the REST handler and the platform.v1 ConfigDeliveryService
	// gRPC surface. nil when service construction failed.
	configDeliveryService *configdelivery.Service
	// configDeliveryGRPC serves platform.v1.ConfigDeliveryService on the
	// TCP and UDS gRPC servers; it guards a nil backing service with typed
	// Unavailable errors.
	configDeliveryGRPC *ConfigDeliveryGRPCService
	// grpcAuthValidator and quicAuthValidator are kept around so the
	// daemon can late-bind a platform JWT verifier after webservices
	// initialize (the JWT signing key isn't available at daemon.New).
	grpcAuthValidator *grpcTokenValidator
	quicAuthValidator *grpcTokenValidator
	// platformTokenValidatorShared is the broker platform-token validator
	// shared across gRPC/QUIC/MCP when config.PlatformToken.Enabled. Stored so
	// the lazily-built MCP server can reuse the same instance.
	platformTokenValidatorShared *platformTokenValidator
	iamTokenService              *IAMTokenService // IAM token operations on every transport
	tpm2Service                  xkmssdk.TrustedPlatformModule
	ceremonyService              *CeremonyGRPCService
	pivService                   *PIVGRPCService
	luksService                  *LUKSGRPCService
	fido2Service                 *FIDO2GRPCService
	mcpServer                    MCPServerInterface
	mcpProvider                  *MCPServiceProvider
	bmcGRPCService               *BMCGRPCService
	switchGRPCService            *SwitchGRPCService
	eabService                   EABServicer
	eabGRPCService               *EABGRPCService
	eabDelivery                  EABDeliveryServicer
	clusterGRPCService           platformv1.ClusterServiceServer
	clusterBackend               *clusterGRPCBackend
	invitationService            platformservice.InvitationServicer
	invitationGRPCService        *InvitationGRPCService
	gatewayGRPCService           *GatewayService
	// gatewayIPC is the live IPC client to gatewayd's datapath child behind
	// the gateway load-balancer, NAT64 and perf backends (#660); nil when no
	// datapath socket is configured. Closed by Stop.
	gatewayIPC *ipc.Client
	// proxyGRPCService is the shared reverse-proxy configuration service
	// backing the gRPC, REST, QUIC and MCP proxy transports.
	proxyGRPCService   *grpccreds.ProxyGRPCService
	overlayGRPCService *OverlayService
	// overlayCtrl is the overlay controller every overlay transport answers
	// from; nil when the overlay is disabled.
	overlayCtrl OverlayControllerInterface
	// overlayIPsec runs overlay IPsec between Start and Stop; its floor was
	// installed by New. nil when overlay.ipsec is disabled.
	overlayIPsec   *overlayIPsecRun
	dnsGRPCService *DNSServiceServer
	pxeGRPCService *PXEGRPCService
	ntpGRPCService *NTPGRPCService
	vpnGRPCService *VPNGRPCService
	// orchestratorGRPCService serves the go-quicbaas agent fleet on every
	// transport (docs/orchestrator/).
	orchestratorGRPCService *OrchestratorGRPCService
	// vpnControlPlane is the store behind vpnGRPCService, or nil when the
	// daemon runs without a platform store.
	vpnControlPlane *vpn.Service
	// appServices are the SDK-served Cache, Scheduler and Messaging services.
	appServices    appServiceServers
	healthRegistry health.Registry

	// healthGRPCService serves grpc.health.v1.Health. Held so the daemon can
	// flip it to NOT_SERVING on shutdown, draining load balancers before the
	// listeners go away.
	healthGRPCService *HealthGRPCService
	// verdictFeed serves StreamDeviceVerdicts and PollDeviceVerdicts on
	// every transport; nil when the attestation service cannot hand out its
	// verdicts. Closed on shutdown so the open streams and polls end before
	// the servers stop gracefully.
	verdictFeed *feed.Feed
	zoneSvc     gateway.ZoneService

	// Concrete server references for accessor methods (set only for real servers)
	concreteRestServer    *RESTServer
	concreteMcpServer     *mcp.Server
	concreteGrpcUDSServer *grpc.Server // Store concrete gRPC UDS server for service registration

	running atomic.Bool
	mu      sync.RWMutex

	// subsystemProbes holds, per platformv1.ServiceType, the func() bool
	// probes SetSubsystemProbe stored for the subsystems run outside the
	// daemon. Lock-free because status RPCs read it while Stop holds mu.
	subsystemProbes sync.Map

	// onAutoStart, when non-nil, is invoked by autoStartServices after it has
	// finished its pass over the configured services. It turns a background
	// goroutine — otherwise invisible — into a synchronisation point the
	// package's own tests can wait on instead of sleeping and hoping.
	//
	// It matters most for NEGATIVE assertions. A test that registers a
	// disabled service, sleeps, and finds startCount still zero cannot
	// distinguish "auto-start correctly skipped it" from "auto-start has not
	// run yet"; both look identical. Waiting for a completed pass makes the
	// zero mean something.
	//
	// Fixed at construction and never mutated, so the goroutine reads it
	// without synchronisation, and nil on every production path. It runs on
	// the auto-start goroutine while d.mu is held for reading, so it must not
	// block and must not touch the daemon.
	onAutoStart func()
}

// New creates a new platformd daemon
// withAutoStartObserver returns a DaemonOption that installs fn as the
// auto-start completion hook. Unexported: this is a test seam, not a
// configuration knob — production has no reason to observe the pass, and the
// exported surface does not mention it.
func withAutoStartObserver(fn func()) DaemonOption {
	return func(d *Daemon) {
		d.onAutoStart = fn
	}
}

func New(config *Config, opts ...DaemonOption) (*Daemon, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := config.validateGRPCAuthorization(); err != nil {
		return nil, err
	}

	// Set up logger
	logger := config.Logger
	if logger == nil {
		logger = logging.DefaultLogger()
	}

	// grpcAuthValidator + quicAuthValidator are populated later when the
	// gRPC TCP / QUIC servers configure their auth interceptors. The
	// outer scope holds the references so we can attach them to the
	// returned *Daemon (and late-bind a platform JWT verifier after
	// webservices initialize).
	var grpcAuthValidator *grpcTokenValidator
	var quicAuthValidator *grpcTokenValidator

	// Create the IAM service - MANDATORY for the platform (unless
	// SkipIAMValidation is set for testing). It is built before the transports
	// because the gRPC and QUIC token validators authorize tokens without scope
	// claims through its policy enforcement point (#767, #768). Its gRPC handler
	// is registered once the servers exist; a missing App is refused there.
	var iamService *IAMService
	if !config.SkipIAMValidation && config.App != nil {
		var iamErr error
		iamService, iamErr = NewIAMService(config.App, logger.Slog())
		if iamErr != nil {
			return nil, ErrInvalidConfig{Reason: "IAM service is mandatory: " + iamErr.Error()}
		}
		logger.Info("IAM service initialized (using QuicBaaS SDK clients)")
	}
	var iamPEP iamsdk.PEPClient
	if iamService != nil {
		iamPEP = iamService.PEP()
	}

	// Build the shared broker platform-token validator once when configured. It
	// is reused across the gRPC, QUIC, and MCP inbound transports so all of them
	// validate the same QuicBaaS OIDC tokens (JWKS-by-kid + aud + exp + DPoP
	// where applicable) and enforce scp -> RBAC + tenant_id -> RLS via the
	// AuthorizedContext, matching the HTTP path. nil means the legacy
	// per-transport validators are used (additive cutover).
	// Its CheckPermission is decided by the IAM PEP built above (#926).
	var platformTokenValidatorShared *platformTokenValidator
	if config.PlatformToken.Enabled {
		ptv, err := newPlatformTokenValidator(config.PlatformToken, iamPEP, logger)
		if err != nil {
			return nil, err
		}
		platformTokenValidatorShared = ptv
		logger.Info("Shared platform-token validator enabled for gRPC/QUIC/MCP",
			"issuer", config.PlatformToken.Issuer)
	}

	// Fail closed (#550, #312): the daemon REST server authenticates by mTLS
	// only, so enabling it without mTLS — the daemon-only `platformd serve`
	// default — would bind an anonymous listener serving BMC power control.
	// SkipIAMValidation (testing only) is the explicit opt-out;
	// RESTServer.Start repeats the check for servers injected through
	// WithRESTServer.
	if config.EnableREST && !config.SkipIAMValidation && !config.EnableMTLS {
		return nil, ErrTransportAuthRequired{
			Transport: transportREST,
			Reason:    "the daemon REST server authenticates by mTLS only and mTLS is disabled",
		}
	}

	// Create the daemon service implementation
	service, err := NewService(config)
	if err != nil {
		return nil, err
	}

	// Create gRPC TCP server if enabled
	var grpcServer *grpc.Server
	grpcTLSCredsAttached := false
	if config.EnableGRPCTCP {
		// Recover handler panics before anything else in the chain so a single
		// panicking RPC cannot take down the whole daemon (gRPC does not
		// recover handler panics on its own, unlike net/http and QUIC).
		var grpcOpts []grpc.ServerOption
		grpcOpts = append(grpcOpts,
			grpc.ChainUnaryInterceptor(RecoveryUnaryInterceptor(logger)),
			grpc.ChainStreamInterceptor(RecoveryStreamInterceptor(logger)),
		)

		tlsOpts, tlsErr := grpcTCPServerTLS(config, logger)
		if tlsErr != nil {
			return nil, tlsErr
		}
		grpcOpts = append(grpcOpts, tlsOpts...)
		grpcTLSCredsAttached = config.grpcTLSMaterialPresent()

		// Configure authentication interceptors. Fails closed (#550): with
		// SkipIAMValidation off, no authentication backend means no server.
		authSel, authErr := selectGRPCTCPAuth(config, platformTokenValidatorShared, iamPEP, logger, grpcTCPSkipMethods)
		if authErr != nil {
			return nil, authErr
		}
		grpcOpts = append(grpcOpts, authSel.options()...)
		grpcAuthValidator = authSel.validator

		grpcServer = grpc.NewServer(grpcOpts...)

		// Register platform daemon service with TCP gRPC server
		platformv1.RegisterPlatformDaemonServer(grpcServer, service)

		logger.Info("gRPC TCP server created", "addr", config.GRPCListenAddr)
	}

	// Create gRPC UDS server if enabled
	var grpcUDSServer *grpc.Server
	if config.EnableGRPCUDS {
		grpcOpts := []grpc.ServerOption{
			grpc.Creds(peercred.NewUnixTransportCredentials()),
			grpc.ChainUnaryInterceptor(RecoveryUnaryInterceptor(logger)),
			grpc.ChainStreamInterceptor(RecoveryStreamInterceptor(logger)),
			grpc.ChainUnaryInterceptor(peercred.UnixCredentialsUnaryInterceptor()),
			grpc.ChainStreamInterceptor(peercred.UnixCredentialsStreamInterceptor()),
		}
		grpcUDSServer = grpc.NewServer(grpcOpts...)

		// Register platform daemon service with UDS gRPC server
		platformv1.RegisterPlatformDaemonServer(grpcUDSServer, service)

		logger.Info("gRPC UDS server created", "path", config.GRPCSocketPath)
	}

	// Initialize optional services based on available backends
	var sdnService *SDNService
	var iamGRPCService *IAMGRPCService
	var tenantService *TenantService

	// Create zone service — always available (in-memory, no OVS dependency).
	var zoneSvcInstance gateway.ZoneService
	zoneSeed, zoneEnv := zoneServiceSeed(config.App)
	if zs, zErr := gateway.NewZoneService(zoneSeed, zoneEnv); zErr == nil {
		zoneSvcInstance = zs
		logger.Info("Zone service initialized")
	} else {
		logger.Warn("Zone service creation failed", "error", zErr)
	}

	// Create SDN service if OVS socket path is configured.
	// On failure (or when no socket path is set) create a zone-only stub so
	// gRPC/Unix zone RPCs remain available.
	if config.OVSSocketPath != "" {
		var sdnErr error
		sdnService, sdnErr = NewSDNService(config.OVSSocketPath)
		if sdnErr != nil {
			logger.Warn("SDN service creation failed; falling back to zone-only stub", "error", sdnErr)
			sdnService = &SDNService{}
		} else {
			logger.Info("SDN service initialized (connection deferred to first use)",
				"ovs_socket", config.OVSSocketPath)
		}
	} else {
		logger.Info("SDN service not available (OVSSocketPath not configured); zone service stub registered")
		sdnService = &SDNService{}
	}

	// Wire the zone service into the SDN gRPC implementation so
	// CreateNetworkZone/ListNetworkZones/etc. are served over gRPC/Unix.
	if zoneSvcInstance != nil {
		sdnService.WithZoneService(zoneSvcInstance)
	}
	// Register SDN gRPC service with TCP gRPC server if enabled
	if grpcServer != nil {
		platformv1.RegisterSDNServiceServer(grpcServer, sdnService)
	}
	// Register SDN gRPC service with UDS gRPC server if enabled
	if grpcUDSServer != nil {
		platformv1.RegisterSDNServiceServer(grpcUDSServer, sdnService)
	}

	// Create Overlay gRPC service (always available - gracefully handles nil controller)
	overlayService := NewOverlayService()
	if grpcServer != nil {
		platformv1.RegisterOverlayServiceServer(grpcServer, overlayService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterOverlayServiceServer(grpcUDSServer, overlayService)
	}
	logger.Info("Overlay service initialized and registered successfully")

	// Wire the overlay when the SDN overlay or its IPsec is enabled. With
	// overlay.ipsec enabled, its fail-closed floor is installed first, before
	// the overlay controller registers the local VTEP, and platformd refuses
	// to start without it. The controller is started synchronously here —
	// Start() only registers the local VTEP in memory and launches lightweight
	// background goroutines, so it does not block daemon startup. With IPsec
	// the VTEP is the IPsec local endpoint on the fabric interface, and a
	// VTEP the floor would not protect stops platformd; without it the VTEP
	// is sdn.overlay.vtep-address (else App.PublicIPv4) on
	// sdn.overlay.underlay-interface, and a missing one stops platformd
	// naming the key to set (resolveOverlayVTEP).
	//
	// overlayCtrl is hoisted so the QUIC overlay adapter can reference it below
	// when wiring quicHandler.SetOverlayHandler.
	var overlayCtrl OverlayControllerInterface
	var overlayIPsecSvc *overlayIPsecRun
	if config.App != nil && config.App.SDNConfig != nil {
		sec, ctrl, overlayErr := startOverlay(context.Background(), config.App.SDNConfig.Overlay,
			newOverlayStarters(config, logger), logger)
		if overlayErr != nil {
			logger.Error(overlayErr, "component", "overlay_ipsec")
			return nil, overlayErr
		}
		if sec != nil {
			overlayIPsecSvc = &overlayIPsecRun{svc: sec}
		}
		if ctrl != nil {
			overlayCtrl = ctrl
			overlayService.SetController(ctrl)
			logger.Info("overlay controller wired and running")
		}
	}

	// Create a default in-memory IPAM allocator. This allows IPAM pool CRUD to
	// work over all transports even when no persistent backend is configured.
	// Production deployments replace this with a QuicBaaS-backed allocator.
	defaultIPAM := ipambackends.NewMemoryBackend()

	// Build the local gateway perf backend when the daemon has OVS access.
	// The perf service measures REAL flow programming (timed
	// install/teardown on a live bridge) and reads live ovs-vswitchd
	// counters via ovs-appctl. A configured gatewayd datapath socket
	// replaces it below; with neither, every transport reports Unavailable
	// for the perf operations.
	var gatewayPerf GatewayPerfInterface
	if sdnService != nil && sdnService.OVSClient() != nil {
		perfDeps := perf.Deps{OVS: sdnService.OVSClient()}
		if runner, ok := sdnService.OVSClient().(ovs.AppCtlRunner); ok {
			perfDeps.AppCtl = runner
		}
		if perfSvc, perfErr := perf.New(perfDeps); perfErr != nil {
			logger.Warn("Gateway perf service creation failed; perf endpoints will return unavailable",
				"error", perfErr)
		} else {
			gatewayPerf = perfSvc
			logger.Info("Gateway perf service initialized")
		}
	}

	// Create Gateway gRPC service (always available - gracefully handles nil dependencies)
	// The load-balancer, NAT64 and perf backends live in gatewayd and are
	// served over live IPC when the datapath socket is configured (#660).
	gatewayOpts, gatewayIPC, gatewayIPCErr := gatewayBackendOptions(config.GatewayDatapathSocket, gatewayPerf)
	if gatewayIPCErr != nil {
		logger.Error(gatewayIPCErr, "component", "gateway_ipc")
		return nil, gatewayIPCErr
	}
	if gatewayIPC != nil {
		logger.Info("Gateway LB, NAT64 and perf served from gatewayd over IPC",
			"socket", config.GatewayDatapathSocket)
	}
	gatewayService := NewGatewayService(append(gatewayOpts, WithIPAMAllocator(defaultIPAM))...)
	if grpcServer != nil {
		platformv1.RegisterGatewayServiceServer(grpcServer, gatewayService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterGatewayServiceServer(grpcUDSServer, gatewayService)
	}
	logger.Info("Gateway service initialized and registered successfully")

	// Create the shared Proxy gRPC service. The store is persistent through
	// the platform DAO seam when the daemon has a DAO factory, and seeded
	// from the control plane's proxy: section; a section the engine would
	// refuse is a startup error, never a half-served proxy (#570). The zone
	// matrix degrades to Unavailable when no zone service exists. The same
	// instance backs the REST, QUIC and MCP proxy transports.
	proxyStore, err := buildProxyStore(config, logger)
	if err != nil {
		return nil, err
	}
	proxyService := NewProxyGRPCServiceWithStore(logger, proxyStore, zoneSvcInstance)
	if grpcServer != nil {
		platformv1.RegisterProxyServiceServer(grpcServer, proxyService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterProxyServiceServer(grpcUDSServer, proxyService)
	}
	logger.Info("Proxy service initialized and registered successfully")

	// Create CA gRPC service if CAService is configured
	var caService *CAGRPCService
	if config.CAService != nil {
		// Get the logging.Logger from the App if available
		var caLogger *logging.Logger
		if config.App != nil && config.App.Logger != nil {
			caLogger = config.App.Logger
		} else {
			caLogger = logging.DefaultLogger()
		}

		var caObjStorage objectstorage.Client
		if config.App != nil {
			caObjStorage = config.App.Storage
		}
		caService = NewCAGRPCService(caLogger, config.CAService, caObjStorage).WithKMS(config.csrKMS())

		// Register with TCP gRPC server if available
		if grpcServer != nil {
			platformv1.RegisterCAServiceServer(grpcServer, caService)
		}

		// Register with UDS gRPC server if available
		if grpcUDSServer != nil {
			platformv1.RegisterCAServiceServer(grpcUDSServer, caService)
		}

		logger.Info("CA service initialized and registered successfully")
	} else {
		logger.Info("CA service not available (CAService not configured)")
	}

	// Create KMS service if QuicBaaS backend is available
	var kmsService *KMSService
	var kmsPlatformGRPC *grpccreds.KMSGRPCService
	var kmsPlatformBackend *PlatformKMSBackend
	if config.App != nil && config.App.KMS() != nil {
		var kmsErr error
		kmsService, kmsErr = NewKMSService(config.App, logger.Slog())
		if kmsErr != nil {
			logger.Warn("KMS service creation failed", "error", kmsErr)
		} else {
			// Register KMS gRPC services with TCP gRPC server if enabled
			if grpcServer != nil {
				if grpcRegErr := kmsService.RegisterGRPCServices(grpcServer); grpcRegErr != nil {
					logger.Warn("KMS service TCP gRPC registration failed", "error", grpcRegErr)
				}
			}
			// Register KMS gRPC services with UDS gRPC server if enabled
			if grpcUDSServer != nil {
				if grpcRegErr := kmsService.RegisterGRPCServices(grpcUDSServer); grpcRegErr != nil {
					logger.Warn("KMS service UDS gRPC registration failed", "error", grpcRegErr)
				}
			}
			// Register the platform.v1 KeyManagementService backed by the
			// same SDK clients so the platform SDK (Client.KMS()) works over
			// gRPC-TCP, gRPC-UDS, REST, and the embedded transport.
			platformKMSBackend, backendErr := kmsService.PlatformKMSBackend()
			if backendErr != nil {
				logger.Warn("Platform KMS backend initialization failed", "error", backendErr)
			} else {
				kmsPlatformBackend = platformKMSBackend
				kmsPlatformGRPC = grpccreds.NewKMSGRPCService(logger, platformKMSBackend)
				if grpcServer != nil {
					platformv1.RegisterKeyManagementServiceServer(grpcServer, kmsPlatformGRPC)
				}
				if grpcUDSServer != nil {
					platformv1.RegisterKeyManagementServiceServer(grpcUDSServer, kmsPlatformGRPC)
				}
				logger.Info("Platform KMS gRPC service registered",
					"service", "platform.v1.KeyManagementService")
			}
			logger.Info("KMS service initialized and registered successfully")
		}
	} else {
		logger.Info("KMS service not available (QuicBaaS backend not configured)")
	}

	// Register the IAM service built above, before the transports.
	if !config.SkipIAMValidation {
		if iamService != nil {
			// Wire the PlatformIAMService gRPC handler so platformctl --transport
			// {unix,grpc,quic} iam … reaches IAM operations. Without this the
			// gRPC servers report "unknown service platform.v1.PlatformIAMService"
			// even though the REST router has IAM available via the embedded
			// transport.
			iamGRPCService = NewIAMGRPCService(logger.Slog(), iamService.Client(), iamService.PEP())
			iamGRPCService.SetSystemTenant(config.PlatformTenantID)
			if grpcServer != nil {
				platformv1.RegisterPlatformIAMServiceServer(grpcServer, iamGRPCService)
			}
			if grpcUDSServer != nil {
				platformv1.RegisterPlatformIAMServiceServer(grpcUDSServer, iamGRPCService)
			}

			// Create Tenant service (depends on IAM/QuicBaaS)
			var tenantErr error
			tenantService, tenantErr = NewTenantService(config.App, logger.Slog())
			if tenantErr != nil {
				logger.Warn("Tenant service creation failed", "error", tenantErr)
				// Tenant service is part of IAM but not critical for startup
			} else {
				// Register Tenant gRPC services with TCP gRPC server if enabled
				if grpcServer != nil {
					if regErr := tenantService.RegisterGRPCServices(grpcServer); regErr != nil {
						logger.Warn("Tenant service TCP gRPC registration failed", "error", regErr)
						tenantService = nil
					}
				}
				// Register Tenant gRPC services with UDS gRPC server if enabled
				if grpcUDSServer != nil {
					if regErr := tenantService.RegisterGRPCServices(grpcUDSServer); regErr != nil {
						logger.Warn("Tenant service UDS gRPC registration failed", "error", regErr)
					}
				}
				if tenantService != nil {
					logger.Info("Tenant service initialized and registered successfully")
				}
			}
		} else {
			return nil, ErrInvalidConfig{Reason: "IAM service is mandatory but App is not configured"}
		}
	} else {
		logger.Warn("IAM validation skipped (testing mode) - do not use in production")
	}

	// Create vTPM gRPC service if VTPMService is configured
	var vtpmService *VTPMServiceServer
	if config.VTPMService != nil {
		vtpmService = NewVTPMServiceServer(config.VTPMService, logger.Slog())

		// Register with TCP gRPC server if enabled
		if grpcServer != nil {
			platformv1.RegisterVTPMServiceServer(grpcServer, vtpmService)
		}

		// Register with UDS gRPC server if enabled
		if grpcUDSServer != nil {
			platformv1.RegisterVTPMServiceServer(grpcUDSServer, vtpmService)
		}

		logger.Info("vTPM service initialized and registered successfully")
	} else {
		logger.Info("vTPM service not available (VTPMService not configured)")
	}

	// Create Device gRPC service if DeviceService is configured
	var deviceService *DeviceGRPCService
	if config.DeviceService != nil {
		deviceService = NewDeviceGRPCService(
			config.DeviceService,
			config.DeviceProfileService,
			logger.Slog(),
			WithDeviceAKTrust(deviceAKTrust(config)),
			WithDeviceVerdictSink(deviceVerdictSink(config)),
			WithDeviceAttestCertRecorder(newDeviceAttestCertRecorder(config, logger.Slog())),
			WithDeviceLifecycle(config.DeviceLifecycle),
			WithDeviceTemplateService(config.DeviceTemplateService),
			WithDeviceBootCA(config.CAService),
		)

		// Register with TCP gRPC server if enabled
		if grpcServer != nil {
			platformv1.RegisterDeviceServiceServer(grpcServer, deviceService)
		}

		// Register with UDS gRPC server if enabled
		if grpcUDSServer != nil {
			platformv1.RegisterDeviceServiceServer(grpcUDSServer, deviceService)
		}

		logger.Info("Device service initialized and registered successfully")
	} else {
		logger.Info("Device service not available (DeviceService not configured)")
	}

	// Create Compute gRPC service if ComputeOrchestrator is configured
	var computeService *ComputeGRPCService
	if config.ComputeOrchestrator != nil {
		// Get the logging.Logger from the App if available
		var computeLogger *logging.Logger
		if config.App != nil && config.App.Logger != nil {
			computeLogger = config.App.Logger
		} else {
			computeLogger = logging.DefaultLogger()
		}

		computeService = NewComputeGRPCService(computeLogger, config.ComputeOrchestrator)

		// Register with TCP gRPC server if enabled
		if grpcServer != nil {
			platformv1.RegisterComputeServiceServer(grpcServer, computeService)
		}

		// Register with UDS gRPC server if enabled
		if grpcUDSServer != nil {
			platformv1.RegisterComputeServiceServer(grpcUDSServer, computeService)
		}

		logger.Info("Compute service initialized and registered successfully")
	} else {
		logger.Info("Compute service not available (ComputeOrchestrator not configured)")
	}

	// Always construct the Attestation gRPC service. When the
	// AttestationService backend is configured the server returns real
	// data; when it is nil every RPC returns a gRPC error via
	// requireService. Either way the gRPC method set is registered so
	// REST/CLI clients receive a proper status instead of a misleading
	// 404 from a missing route.
	attestationService := NewAttestationServiceServer(config.AttestationService, logger.Slog())
	attestationService.SetReporting(config.AttestationReporting)
	// Serve every recorded device verdict on StreamDeviceVerdicts, so the
	// overlay gateways withdraw a device whose quote fails (#709).
	verdictFeed := streamDeviceVerdicts(attestationService, config.AttestationService)
	if grpcServer != nil {
		platformv1.RegisterAttestationServiceServer(grpcServer, attestationService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterAttestationServiceServer(grpcUDSServer, attestationService)
	}
	if config.AttestationService != nil {
		logger.Info("Attestation service initialized with backend implementation")
	} else {
		logger.Info("Attestation gRPC service registered (stub - returns Unimplemented for all operations)")
	}

	// Create Registry gRPC service if RegistryService is configured
	var registryService *grpccreds.RegistryGRPCService
	if config.RegistryService != nil {
		registryService = grpccreds.NewRegistryGRPCService(logger, config.RegistryService)

		// Register with TCP gRPC server if enabled
		if grpcServer != nil {
			platformv1.RegisterRegistryServiceServer(grpcServer, registryService)
		}

		// Register with UDS gRPC server if enabled
		if grpcUDSServer != nil {
			platformv1.RegisterRegistryServiceServer(grpcUDSServer, registryService)
		}

		logger.Info("Registry service initialized and registered successfully")
	} else {
		logger.Info("Registry service not available (RegistryService not configured)")
	}

	// Create IDevID gRPC service and wire the live TPM from the App at
	// construction — the previous "inject later via SetTPM2Service"
	// pattern was never completed in the startup path, so every call
	// returned FailedPrecondition "TPM2 service not initialized" even
	// though app.TPM was alive. This mirrors the TPM gRPC service
	// wiring below so both services are ready to serve on first call.
	idevidService := NewIDevIDGRPCService(logger)
	if config.App != nil && config.App.TPM != nil {
		idevidService.SetTPM2Service(config.App.TPM)
		logger.Info("IDevID gRPC service wired to app.TPM")
	} else {
		logger.Warn("IDevID gRPC service created but app.TPM is nil; IDevID/IAK ops will return FailedPrecondition")
	}

	if config.CAService != nil {
		idevidService.SetCAService(config.CAService)
		logger.Info("IDevID gRPC service wired to CA for LDevID issuance")
	} else {
		logger.Warn("IDevID gRPC service created without CA; CreateLDevID will return FailedPrecondition")
	}

	// Register with TCP gRPC server if enabled
	if grpcServer != nil {
		platformv1.RegisterIDevIDServiceServer(grpcServer, idevidService)
	}

	// Register with UDS gRPC server if enabled
	if grpcUDSServer != nil {
		platformv1.RegisterIDevIDServiceServer(grpcUDSServer, idevidService)
	}

	logger.Info("IDevID service initialized and registered successfully")

	// Create TPM gRPC service and inject the live TPM from the App.
	// Without this injection every method returned
	// codes.Unavailable "TPM service not available" because the
	// internal tpm field was nil. Observed via `platformctl tpm info`
	// on node-02 2026-04-08 — the command returned "tpm service not
	// available" even though app.TPM was alive and the PlatformSRK
	// was present on the hardware TPM. The comment on the old line
	// claimed injection happened "later via SetTPM2Service" but no
	// such call existed anywhere in the daemon startup path, so the
	// service was permanently stuck in unavailable mode.
	tpmService := NewTPMGRPCService(logger)
	if config.App != nil && config.App.TPM != nil {
		tpmService.SetTPM2Service(config.App.TPM)
		logger.Info("TPM gRPC service wired to app.TPM")
	} else {
		logger.Warn("TPM gRPC service created but app.TPM is nil; Info/Quote/etc. will return Unavailable")
	}

	// Register with TCP gRPC server if enabled
	if grpcServer != nil {
		platformv1.RegisterTPMServiceServer(grpcServer, tpmService)
	}

	// Register with UDS gRPC server if enabled
	if grpcUDSServer != nil {
		platformv1.RegisterTPMServiceServer(grpcUDSServer, tpmService)
	}

	logger.Info("TPM service initialized and registered successfully")
	// Create Barrier gRPC service with barrier manager from App
	var barrierMgr *barrier.Manager
	if config.App != nil {
		barrierMgr = config.App.Barrier()
	}
	barrierService := NewBarrierGRPCService(logger, barrierMgr)
	if grpcServer != nil {
		platformv1.RegisterBarrierServiceServer(grpcServer, barrierService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterBarrierServiceServer(grpcUDSServer, barrierService)
	}
	if barrierMgr != nil {
		logger.Info("Barrier gRPC service registered with barrier manager")
	} else {
		logger.Warn("Barrier gRPC service registered without barrier manager (barrier not configured)")
	}

	// Create the EAB gRPC service backed by the canonical eab.Service from
	// the platform service registry (the same resolution path config
	// delivery uses for its EAB dependency). The delivery handler renders
	// QR codes / enrollment URLs against the platform FQDN + REST port.
	// When the registry (or its QuicBaaS backing) is absent the servicer
	// stays nil and every RPC returns a typed Unavailable error via the
	// requireService guard.
	var eabServicer EABServicer
	var eabDeliveryServicer EABDeliveryServicer
	if config.App != nil {
		reg, err := config.App.ServiceRegistry()
		if err != nil {
			return nil, err
		}
		eabServicer = reg.EABService()
		eabPort := 0
		if _, portStr, splitErr := net.SplitHostPort(config.RESTListenAddr); splitErr == nil {
			eabPort, _ = strconv.Atoi(portStr)
		}
		eabDeliveryServicer = eab.NewDelivery(eab.DeliveryConfig{
			BaseURL: configdelivery.ProvisionBaseURL(config.App.FQDN(), eabPort),
		})
	}
	eabGRPCService := NewEABGRPCService(logger, eabServicer, eabDeliveryServicer)
	if grpcServer != nil {
		platformv1.RegisterEABServiceServer(grpcServer, eabGRPCService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterEABServiceServer(grpcUDSServer, eabGRPCService)
	}
	logger.Info("EAB gRPC service registered",
		"service", "platform.v1.EABService",
		"configured", eabServicer != nil)

	// Create Invitation gRPC service. The InvitationServicer is injected
	// later (see createMCPServer) once the Daemon struct exists. Until
	// SetService is called the service returns Unimplemented per the
	// legacy stub.
	invitationService := NewInvitationGRPCService(logger, nil)
	if grpcServer != nil {
		platformv1.RegisterInvitationServiceServer(grpcServer, invitationService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterInvitationServiceServer(grpcUDSServer, invitationService)
	}
	logger.Info("Invitation gRPC service registered (stub)")

	// Register the Cluster gRPC service on the TCP listener and the Unix
	// socket. It is the pkg/api/grpc implementation over the daemon's
	// ClusterServicer — the same servicer the MCP cluster tools use, set
	// through Daemon.SetClusterService. Until one is set every RPC returns
	// Unavailable.
	clusterGRPCService, clusterBackend := registerClusterGRPCService(logger, grpcServer, grpcUDSServer)
	logger.Info("Cluster gRPC service registered")

	// Create the DNS gRPC service over the DNS service a dns: section with
	// a server starts (config.DNSService): the same instance the QUIC
	// handler, the MCP provider and the embedded SDK transport reach. A node
	// without one builds it with no backend, and every handler answers
	// Unavailable with SERVICE_NOT_CONFIGURED (requireService), as REST
	// answers 503.
	dnsGRPCService := NewDNSServiceServer(fullDNSService(config.DNSService), logger.Slog())
	if grpcServer != nil {
		platformv1.RegisterDNSServiceServer(grpcServer, dnsGRPCService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterDNSServiceServer(grpcUDSServer, dnsGRPCService)
	}
	logger.Info("DNS gRPC service registered")

	// Create the PXE gRPC service. Every transport serves this one
	// instance. platformd never sets its backend (PXE is a gateway-role
	// service and the platformd config has no pxe: section), so each call
	// answers Unavailable with SERVICE_NOT_CONFIGURED (requireService).
	pxeGRPCService := NewPXEGRPCService(logger, nil)
	if grpcServer != nil {
		platformv1.RegisterPXEServiceServer(grpcServer, pxeGRPCService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterPXEServiceServer(grpcUDSServer, pxeGRPCService)
	}
	logger.Info("PXE gRPC service registered")

	// Create the NTP gRPC service. The backend is the platform's
	// ntp.Service, which exists only when the node carries an `ntp:`
	// configuration section; without it every RPC returns a typed
	// Unavailable error on every transport.
	var ntpBackend NTPBackend
	if config.App != nil && config.App.NTPService != nil {
		ntpBackend = config.App.NTPService
	}
	ntpGRPCService := NewNTPGRPCService(logger, ntpBackend)
	if grpcServer != nil {
		platformv1.RegisterNTPServiceServer(grpcServer, ntpGRPCService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterNTPServiceServer(grpcUDSServer, ntpGRPCService)
	}
	logger.Info("NTP gRPC service registered")

	// Create the orchestrator gRPC service over the pkg/orchestrator service
	// layer. The go-quicbaas orchestrator client is resolved on every call;
	// until the quicbaas factory has an SDK client every RPC returns a typed
	// Unavailable error on every transport.
	orchestratorGRPCService := NewOrchestratorGRPCService(orchestrator.NewService(orchestratorClientResolver(config)))
	if grpcServer != nil {
		platformv1.RegisterOrchestratorServiceServer(grpcServer, orchestratorGRPCService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterOrchestratorServiceServer(grpcUDSServer, orchestratorGRPCService)
	}
	logger.Info("Orchestrator gRPC service registered")

	// Create the VPN control-plane gRPC service. It is backed by the
	// platform store; without one every RPC answers the typed
	// not-configured status on every transport.
	vpnControlPlane := buildVPNControlPlane(config, logger)
	vpnGRPCService := NewVPNGRPCService(logger, nil)
	if vpnControlPlane != nil {
		vpnGRPCService = NewVPNGRPCService(logger, vpnControlPlane)
	}
	if grpcServer != nil {
		platformv1.RegisterVPNServiceServer(grpcServer, vpnGRPCService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterVPNServiceServer(grpcUDSServer, vpnGRPCService)
	}
	logger.Info("VPN gRPC service registered")

	// Cache, Scheduler and Messaging are served by the composed go-quicbaas
	// SDK; one instance of each backs every transport.
	appServices := newAppServiceServers(config, logger)
	for _, server := range []*grpc.Server{grpcServer, grpcUDSServer} {
		if server == nil {
			continue
		}
		platformv1.RegisterCacheServiceServer(server, appServices.cache)
		platformv1.RegisterSchedulerServiceServer(server, appServices.scheduler)
		platformv1.RegisterMessagingServiceServer(server, appServices.messaging)
		platformv1.RegisterObjectStorageServiceServer(server, appServices.objectStorage)
	}
	logger.Info("Cache, Scheduler, Messaging and ObjectStorage gRPC services registered")

	// Create the Switch gRPC service. It has no switch backend yet, so every
	// method answers Unavailable (not configured); the QUIC opcodes, the MCP
	// tools and the embedded transport call this same servicer.
	switchGRPCService := NewSwitchGRPCService(logger, nil)
	if grpcServer != nil {
		platformv1.RegisterSwitchServiceServer(grpcServer, switchGRPCService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterSwitchServiceServer(grpcUDSServer, switchGRPCService)
	}
	logger.Info("Switch gRPC service registered")

	// Create Ceremony gRPC service (Phase 3.5 scaffolding).
	// Backend is wired post-construction via SetCeremonyBackend once the
	// app-level ceremony backend is available. Until then, handlers return
	// Unavailable with ErrCeremonyNotConfigured.
	ceremonySvc := NewCeremonyService(logger, nil)
	ceremonyGRPCService := NewCeremonyGRPCService(logger, ceremonySvc)
	if grpcServer != nil {
		platformv1.RegisterCeremonyServiceServer(grpcServer, ceremonyGRPCService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterCeremonyServiceServer(grpcUDSServer, ceremonyGRPCService)
	}
	logger.Info("Ceremony gRPC service registered (Phase 3.5)")

	// Create PIV gRPC service (Phase 3.5 scaffolding).
	pivSvc := NewPIVService(logger, nil)
	pivGRPCService := NewPIVGRPCService(logger, pivSvc)
	if grpcServer != nil {
		platformv1.RegisterPIVServiceServer(grpcServer, pivGRPCService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterPIVServiceServer(grpcUDSServer, pivGRPCService)
	}
	logger.Info("PIV gRPC service registered (Phase 3.5)")

	// Create LUKS gRPC service (Phase 3.5 scaffolding).
	// Root checker is conservative by default — no mutating operation
	// succeeds unless a real root-aware checker is injected later.
	luksSvc := NewLUKSService(logger, nil, nil)
	luksGRPCService := NewLUKSGRPCService(logger, luksSvc)
	if grpcServer != nil {
		platformv1.RegisterLUKSServiceServer(grpcServer, luksGRPCService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterLUKSServiceServer(grpcUDSServer, luksGRPCService)
	}
	logger.Info("LUKS gRPC service registered (Phase 3.5)")

	// Create FIDO2 gRPC service (Phase 3.5 scaffolding).
	fido2Svc := NewFIDO2Service(logger, nil)
	fido2GRPCService := NewFIDO2GRPCService(logger, fido2Svc)
	if grpcServer != nil {
		platformv1.RegisterFIDO2ServiceServer(grpcServer, fido2GRPCService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterFIDO2ServiceServer(grpcUDSServer, fido2GRPCService)
	}
	logger.Info("FIDO2 gRPC service registered (Phase 3.5)")

	logger.Info("Creating health registry...")
	// Create health registry
	healthRegistry := health.NewRegistry()

	// Create QUIC service handler and server if enabled
	var quicServerIntf QUICServerInterface // Use interface type to avoid typed nil issue
	var quicHandler *QUICServiceHandler
	// quicConstructErr is decided after the options are applied: a
	// WithQUICServer replacement supersedes the built-in server (#444).
	var quicConstructErr error
	if config.EnableQUIC {
		// Initialize QUIC protocol codec before creating server
		if codecErr := quicwire.SetDefaultCodecType(codec.MsgPack); codecErr != nil {
			logger.Warn("Failed to set MsgPack codec for QUIC, falling back to JSON", "error", codecErr)
			_ = quicwire.SetDefaultCodecType(codec.JSON)
		}
		// Get logging.Logger for QUIC handler
		var quicLogger *logging.Logger
		if config.App != nil && config.App.Logger != nil {
			quicLogger = config.App.Logger
		} else {
			quicLogger = logging.DefaultLogger()
		}

		// Configure QUIC authentication middleware. When mTLS is enabled the
		// TLS layer verifies the client certificate against this pool
		// (enforced below) and the middleware authenticates it as the
		// request's principal; otherwise a token validator is mandatory and
		// its absence refuses the transport (#550).
		quicClientCAPool, poolErr := resolveMTLSClientCAPool(config, transportQUIC)
		if poolErr != nil {
			return nil, poolErr
		}
		quicAuthMiddleware, quicLocalValidator, quicAuthErr := selectQUICAuth(config, platformTokenValidatorShared, quicClientCAPool, logger)
		if quicAuthErr != nil {
			return nil, quicAuthErr
		}
		quicAuthValidator = quicLocalValidator

		// Create the QUIC service handler with available services
		var quicHandlerErr error
		quicHandler, quicHandlerErr = NewQUICServiceHandler(
			quicLogger,
			WithQUICHealthRegistry(healthRegistry),
			WithQUICAuthMiddleware(quicAuthMiddleware),
		)
		if quicHandlerErr != nil {
			return nil, quicHandlerErr
		}

		// Set daemon service for QUIC daemon operations
		quicHandler.SetDaemonService(service)
		// Time synchronization: the same NTPGRPCService instance backs
		// REST, gRPC, MCP, and the Unix socket.
		quicHandler.SetNTPService(ntpGRPCService)
		quicHandler.SetVPNService(vpnGRPCService)
		quicHandler.SetAppServices(appServices)
		quicHandler.SetIDevIDService(idevidService)

		// Set CA handler if available
		if config.CAService != nil {
			var quicObjStorage objectstorage.Client
			if config.App != nil {
				quicObjStorage = config.App.Storage
			}
			quicHandler.SetCAHandler(quic.NewCAHandler(quicLogger, config.CAService, quicObjStorage).WithKMS(config.csrKMS()))
			quicHandler.SetDeviceAKTrust(config.CAService)
		}

		// Set vTPM service if available
		if config.VTPMService != nil {
			quicHandler.SetVTPMService(config.VTPMService)
		}

		// Set Device service if available
		if config.DeviceService != nil {
			quicHandler.SetDeviceService(config.DeviceService)
		}

		// Set Device Profile service if available so QUIC profile sub-opcodes
		// (Get/List/Create/Delete profile) return real data instead of
		// StatusUnavailable + ErrDeviceProfileServiceNotAvailable.
		if config.DeviceProfileService != nil {
			quicHandler.SetDeviceProfileService(config.DeviceProfileService)
			quicHandler.SetDeviceVerdictSink(deviceVerdictSink(config))
		}
		if config.DeviceTemplateService != nil {
			quicHandler.SetDeviceTemplateService(config.DeviceTemplateService)
		}
		if config.DeviceService != nil {
			quicHandler.SetDeviceAttestCertRecorder(newDeviceAttestCertRecorder(config, quicLogger.Slog()))
			quicHandler.SetDeviceLifecycle(config.DeviceLifecycle)
			if config.CAService != nil {
				quicHandler.SetDeviceBootCA(config.CAService)
			}
		}

		// Set Container orchestrator if available
		if config.ComputeOrchestrator != nil {
			// Use the adapter to bridge compute.Orchestrator to container.ContainerOrchestrator
			adapter, adapterErr := NewOrchestratorAdapter(config.ComputeOrchestrator)
			if adapterErr != nil {
				logger.Warn("QUIC container adapter creation failed", "error", adapterErr)
			} else {
				quicHandler.SetContainerOrchestrator(adapter)
				logger.Debug("Container orchestrator set for QUIC handler")
			}
		}

		// Set KMS service if available
		if kmsService != nil {
			if initErr := kmsService.initializeServers(); initErr != nil {
				logger.Warn("KMS service QUIC initialization failed", "error", initErr)
			} else {
				if kmsService.KMSServer() != nil && kmsService.CryptoServer() != nil {
					quicHandler.SetKMSService(newKMSQUICAdapter(
						kmsService.KMSServer(),
						kmsService.CryptoServer(),
					))
					logger.Debug("KMS service set for QUIC handler")
				}
				if kmsService.SecretsServer() != nil {
					quicHandler.SetSecretsService(kmsService.SecretsServer())
					logger.Debug("Secrets service set for QUIC handler")
				}
				if kmsService.DEKServer() != nil {
					quicHandler.SetDEKService(kmsService.DEKServer())
					logger.Debug("DEK service set for QUIC handler")
				}
			}
		}

		// Set SDN service if SDN service is available
		if sdnService != nil {
			quicHandler.SetSDNService(sdnService)
			logger.Debug("SDN service set for QUIC handler")
		}

		// Set DNS service if available
		if config.DNSService != nil {
			quicHandler.SetDNSService(config.DNSService)
			logger.Debug("DNS service set for QUIC handler")
		}

		// Wire the shared compute + attestation gRPC services into the QUIC
		// handler so container and quote ops delegate through the pb services.
		if computeService != nil {
			quicHandler.SetComputeGRPCService(computeService)
			logger.Debug("Compute gRPC service set for QUIC handler")
		}
		quicHandler.SetAttestationGRPCService(attestationService)
		quicHandler.SetAttestationService(newAttestationQUICAdapter(attestationService))

		// Set up overlay and gateway QUIC handlers for proper request routing.
		// Even without concrete service implementations, having these handlers
		// ensures overlay/gateway/IPAM requests are routed correctly rather
		// than colliding with other opcode ranges.
		// Wire the overlay QUIC adapter when the controller is available.
		// When overlayCtrl is nil (overlay disabled), nil is passed and the
		// handler emits StatusUnavailable for all overlay requests.
		var overlayQUICService quic.OverlayServiceInterface
		if overlayCtrl != nil {
			overlayQUICService = newOverlayControllerQUICAdapter(overlayCtrl)
		}
		quicHandler.SetOverlayHandler(quic.NewOverlayHandler(quicLogger, overlayQUICService))

		// Wire the full gateway QUIC adapter so that IPAM pool CRUD (sub-opcodes
		// 0x08, 0x0C-0x0F) and zone operations (0x10-0x14) are both served over QUIC.
		// defaultIPAM is the in-memory allocator created above. zoneSvcInstance may
		// be nil — zone methods degrade to StatusUnavailable in that case.
		quicGatewaySvc := newFullGatewayQUICAdapter(defaultIPAM, zoneSvcInstance, gatewayService, gatewayService, gatewayService, gatewayService)
		gatewayQUICHandler := quic.NewGatewayHandler(quicLogger, quicGatewaySvc)
		// The perf sub-opcodes (0x36-0x38) read the shared gateway service's
		// perf backend like every other transport; with none wired they
		// return StatusUnavailable.
		gatewayQUICHandler.SetPerfService(newGatewayPerfQUICAdapter(gatewayService))
		quicHandler.SetGatewayHandler(gatewayQUICHandler)

		// Wire the proxy handler so the proxy sub-opcodes (0x20-0x2D)
		// multiplexed under the gateway category are served over QUIC by
		// the same shared ProxyGRPCService as the other transports.
		quicHandler.SetProxyHandler(quic.NewProxyHandler(quicLogger, proxyService))
		logger.Debug("Overlay, gateway and proxy handlers set for QUIC handler")

		// Wire Phase 3.5 services into QUIC handler. The service layers have
		// nil backends until the app-level wiring is complete — handlers
		// return Unavailable until then.
		quicHandler.SetCeremonyService(ceremonySvc)
		quicHandler.SetPIVService(pivSvc)
		quicHandler.SetLUKSService(luksSvc)
		quicHandler.SetFIDO2Service(fido2Svc)

		// Wire the shared IAM gRPC delegate into the QUIC handler so IAM QUIC
		// operations dispatch through the pb service instead of returning
		// Unavailable. Reuses the instance registered on the gRPC servers.
		if iamGRPCService != nil {
			quicHandler.SetIAMGRPCService(iamGRPCService)
			logger.Info("IAM gRPC delegate wired into QUIC handler")
		}

		// Invitations ride the IAM category through the servicer the gRPC
		// servers registered, so QUIC answers and refuses as gRPC does.
		quicHandler.SetInvitationServer(invitationService)

		// The cluster category dispatches to the same ClusterService
		// servicer the gRPC servers carry, so QUIC answers as gRPC does.
		quicHandler.SetClusterServer(clusterGRPCService)

		// Prepare QUIC server configuration
		quicConfig := config.QUICConfig
		if quicConfig == nil {
			quicConfig = quic.DefaultServerConfig()
		}

		// Override listen address from daemon config if set
		if config.QUICListenAddr != "" {
			quicConfig.ListenAddr = config.QUICListenAddr
		}

		// Enable mTLS on the QUIC TLS config for client certificate
		// verification. mTLS is QUIC's only authentication when enabled, so
		// it fails closed: no TLS config to enforce it on, or no resolvable
		// client CA pool, refuses the transport instead of a Warn followed by
		// an unauthenticated listener (#550). The pool is the one resolved
		// above for the authenticator; the CA file is read once (#766).
		if err := quicServerMTLS(config, quicConfig.TLSConfig, quicClientCAPool, quicHandler, logger); err != nil {
			return nil, err
		}

		// Create QUIC server
		quicServer, quicErr := quic.NewServer(
			quicConfig,
			quic.WithHandler(quicHandler),
			quic.WithLogger(quicLogger),
		)
		if quicErr != nil {
			quicConstructErr = ErrTransportConstructionFailed{Transport: transportQUIC, Cause: quicErr}
			// quicServerIntf stays nil (interface nil, not typed nil)
			quicHandler = nil
		} else {
			quicServerIntf = quicServer // Assign to interface only on success
			logger.Info("QUIC server created", "addr", quicConfig.ListenAddr)
		}
	}

	logger.Info("Creating daemon instance...")

	// Only wrap grpcServer if it's not nil
	var grpcServerIntf GRPCServerInterface
	if grpcServer != nil {
		grpcServerIntf = &grpcServerWrapper{server: grpcServer}
	}

	// Only wrap grpcUDSServer if it's not nil
	var grpcUDSServerIntf GRPCServerInterface
	if grpcUDSServer != nil {
		grpcUDSServerIntf = &grpcServerWrapper{server: grpcUDSServer}
	}

	// One token service answers the IAM token operations on every transport:
	// gRPC (TCP and UDS), QUIC and the embedded transport through
	// iamGRPCService, MCP through createMCPServer. Servers start in Start(),
	// so wiring it here is race-free.
	iamTokenService := newIAMTokenService(
		selectIAMTokenVerifier(platformTokenValidatorShared, grpcAuthValidator, quicAuthValidator))
	if iamGRPCService != nil {
		iamGRPCService.SetTokenService(iamTokenService)
	}

	daemon := &Daemon{
		config:                       config,
		logger:                       logger,
		grpcAuthValidator:            grpcAuthValidator,
		quicAuthValidator:            quicAuthValidator,
		platformTokenValidatorShared: platformTokenValidatorShared,
		iamTokenService:              iamTokenService,
		grpcServer:                   grpcServerIntf,
		grpcTLSCredsAttached:         grpcTLSCredsAttached,
		grpcUDSServer:                grpcUDSServerIntf,
		clusterGRPCService:           clusterGRPCService,
		clusterBackend:               clusterBackend,
		concreteGrpcUDSServer:        grpcUDSServer,
		quicServer:                   quicServerIntf,
		quicHandler:                  quicHandler,
		service:                      service,
		caService:                    caService,
		sdnService:                   sdnService,
		kmsService:                   kmsService,
		kmsPlatformGRPC:              kmsPlatformGRPC,
		kmsPlatformBackend:           kmsPlatformBackend,
		iamService:                   iamService,
		tenantService:                tenantService,
		vtpmService:                  vtpmService,
		deviceService:                deviceService,
		computeService:               computeService,
		attestationService:           attestationService,
		registryService:              registryService,
		idevidService:                idevidService,
		tpmService:                   tpmService,
		barrierService:               barrierService,
		ceremonyService:              ceremonyGRPCService,
		pivService:                   pivGRPCService,
		luksService:                  luksGRPCService,
		fido2Service:                 fido2GRPCService,
		invitationGRPCService:        invitationService,
		eabService:                   eabServicer,
		eabDelivery:                  eabDeliveryServicer,
		eabGRPCService:               eabGRPCService,
		gatewayGRPCService:           gatewayService,
		gatewayIPC:                   gatewayIPC,
		proxyGRPCService:             proxyService,
		overlayGRPCService:           overlayService,
		overlayCtrl:                  overlayCtrl,
		overlayIPsec:                 overlayIPsecSvc,
		dnsGRPCService:               dnsGRPCService,
		pxeGRPCService:               pxeGRPCService,
		ntpGRPCService:               ntpGRPCService,
		orchestratorGRPCService:      orchestratorGRPCService,
		vpnGRPCService:               vpnGRPCService,
		vpnControlPlane:              vpnControlPlane,
		switchGRPCService:            switchGRPCService,
		appServices:                  appServices,
		healthRegistry:               healthRegistry,
		verdictFeed:                  verdictFeed,
		zoneSvc:                      zoneSvcInstance,
	}

	// Apply functional options (allows overriding servers with mocks)
	for _, opt := range opts {
		opt(daemon)
	}

	// An enabled transport that cannot be constructed stops the daemon
	// (#444); only a WithQUICServer replacement supersedes the failure.
	if quicConstructErr != nil && !daemon.quicServerReplaced {
		logger.Error(quicConstructErr, "component", "quic_server")
		return nil, quicConstructErr
	}

	// Wire the platform InvitationServicer from the App's service registry
	// so the gRPC/MCP/REST invitation surfaces all share one backend
	// instead of returning Unimplemented.
	if daemon.invitationService == nil && config.App != nil {
		reg, err := config.App.ServiceRegistry()
		if err != nil {
			return nil, err
		}
		if svc := reg.InvitationService(); svc != nil {
			daemon.invitationService = svc
			if daemon.invitationGRPCService != nil {
				daemon.invitationGRPCService.SetService(svc)
			}
		}
	}

	// Create REST server if enabled and not overridden by option
	if config.EnableREST && daemon.restServer == nil {
		restServer, restErr := newRESTServer(config, service, logger.Slog())
		if restErr != nil {
			constructErr := ErrTransportConstructionFailed{Transport: transportREST, Cause: restErr}
			logger.Error(constructErr, "component", "rest_server")
			return nil, constructErr
		}
		daemon.restServer = restServer
		daemon.concreteRestServer = restServer
		restServer.SetIDevIDService(idevidService)
		logger.Info("REST server created", "addr", config.RESTListenAddr)
	} else if !config.EnableREST {
		logger.Info("REST server not enabled")
	}

	// Wire vTPM service into REST server if both are available
	if daemon.concreteRestServer != nil && config.VTPMService != nil {
		daemon.concreteRestServer.SetVTPMService(config.VTPMService)
		logger.Info("vTPM service wired into REST server")
	}

	// Wire the time-synchronization, VPN control-plane and compute REST
	// handlers onto the daemon's own REST listener. Without them
	// /api/v1/ntp/*, /api/v1/vpn/* and /api/v1/compute/* would 404 there.
	// Each route requires the scope its RPC requires on gRPC, checked by one
	// guard: a platform token, else the verified client certificate. The
	// compute routes run the same ComputeGRPCService gRPC and QUIC serve.
	var restGuard *restapi.ScopeGuard
	if daemon.concreteRestServer != nil {
		var guardErr error
		restGuard, guardErr = newRESTScopeGuard(config, platformTokenValidatorShared, logger)
		if guardErr != nil {
			constructErr := ErrTransportConstructionFailed{Transport: transportREST, Cause: guardErr}
			logger.Error(constructErr, "component", "rest_server")
			return nil, constructErr
		}
		if ntpGRPCService != nil {
			daemon.concreteRestServer.SetNTPHandlers(ntpGRPCService, restGuard)
		}
		daemon.concreteRestServer.SetOrchestratorHandlers(orchestratorGRPCService, restGuard)
		daemon.concreteRestServer.SetVPNHandlers(vpnGRPCService, restGuard)
		daemon.concreteRestServer.SetAppServiceHandlers(appServices.restServers(), restGuard)
		if computeService != nil {
			daemon.concreteRestServer.SetComputeHandlers(computeService, restGuard)
		}
	}

	// Wire device + profile REST handlers if the services are available.
	// Without this, /api/v1/devices/* would not be served and the REST
	// adapter for `platformctl --protocol rest device list` would 404.
	if daemon.concreteRestServer != nil && (config.DeviceService != nil || config.DeviceProfileService != nil) {
		// deviceService is the in-process DeviceService gRPC implementation
		// built above; it carries the DeviceQuoteVerifier that every other
		// transport attests through. A nil deviceService (no DeviceService
		// configured) leaves the attest route unmounted rather than mounted
		// and unverifying.
		var attestSvc platformv1.DeviceServiceServer
		if deviceService != nil {
			attestSvc = deviceService
		}
		daemon.concreteRestServer.SetDeviceHandlers(config.DeviceService, config.DeviceProfileService, attestSvc)
	}

	// Wire CA REST handlers if the CA service is available. Without this,
	// /api/v1/ca/* would not be served and the REST adapter for
	// `platformctl --protocol rest ca list` would 404. The handlers share
	// the same CA instance as the gRPC, QUIC, MCP and Unix-socket adapters
	// so all transports return identical results.
	if daemon.concreteRestServer != nil && config.CAService != nil {
		daemon.concreteRestServer.SetCAHandlers(config.CAService, restGuard)
	}

	// Wire the physical TPM REST handlers. Quote and verify run on the same
	// TPM service gRPC and the Unix socket serve, so one quote verifies the
	// same way on every transport (#482).
	if daemon.concreteRestServer != nil {
		daemon.concreteRestServer.SetTPMHandlers(tpmService, restGuard)
	}

	// Wire KMS REST handlers when the platform KMS backend is available.
	// Without this, /api/v1/kms/* would not be served and the REST adapter
	// for `platformctl --protocol rest kms ...` would 404. The facade shares
	// the same QuicBaaS SDK clients as the gRPC and embedded transports so
	// all transports return identical results.
	if daemon.concreteRestServer != nil && kmsPlatformBackend != nil {
		daemon.concreteRestServer.SetKMSHandlers(NewPlatformKMSRESTFacade(kmsPlatformBackend))
	}

	// Wire platform tenant manager into REST handlers + gRPC server when
	// available. Without this, /api/v1/tenants/* would 404 and the gRPC
	// TenantService methods would return FailedPrecondition. The manager
	// instance is shared across REST, gRPC, QUIC, MCP, and Unix so every
	// transport sees identical per-tenant state including barrier lifecycle.
	// REST and gRPC both authorize the caller against the same system tenant.
	if config.PlatformTenantManager != nil {
		if daemon.concreteRestServer != nil {
			daemon.concreteRestServer.SetTenantHandlers(config.PlatformTenantManager, restGuard, config.PlatformTenantID)
		}
		if daemon.tenantService != nil && daemon.tenantService.grpcServer != nil {
			daemon.tenantService.grpcServer.SetManager(config.PlatformTenantManager)
			daemon.tenantService.grpcServer.SetSystemTenant(config.PlatformTenantID)
			logger.Info("Platform tenant manager wired into gRPC TenantService")

			// Share the same *TenantGRPCServer delegate with the QUIC handler so
			// tenant QUIC operations dispatch through the pb service instead of
			// returning Unavailable.
			if daemon.quicHandler != nil {
				daemon.quicHandler.SetTenantGRPCServer(daemon.tenantService.grpcServer)
				logger.Info("Platform tenant manager wired into QUIC handler")
			}
		}
	}

	// Wire SDN service into REST server if both are available
	if daemon.concreteRestServer != nil && daemon.sdnService != nil {
		daemon.concreteRestServer.SetSDNService(daemon.sdnService)
		logger.Info("SDN service wired into REST server")
	}

	// Wire zone service into REST server for zone CRUD endpoints.
	if daemon.concreteRestServer != nil && daemon.zoneSvc != nil {
		daemon.concreteRestServer.SetZoneService(daemon.zoneSvc)
		logger.Info("Zone service wired into REST server")
	}

	// Wire overlay REST handlers when the overlay controller was built.
	// Uses the same controller hoisted during QUIC wiring so all transports
	// share the same in-process overlay state.
	if daemon.concreteRestServer != nil && overlayCtrl != nil {
		daemon.concreteRestServer.SetOverlayHandlers(newOverlayControllerRESTAdapter(overlayCtrl))
		logger.Info("Overlay REST routes registered")
	}

	// Wire gateway IPAM REST handlers. Pass the same in-memory allocator
	// used by the gRPC service so REST and gRPC share the same state.
	if daemon.concreteRestServer != nil && daemon.gatewayGRPCService != nil {
		daemon.concreteRestServer.SetGatewayIPAMService(daemon.gatewayGRPCService.IPAMAllocator(), daemon.gatewayGRPCService)
		daemon.concreteRestServer.SetGatewaySnapshotService(daemon.gatewayGRPCService)
		daemon.concreteRestServer.SetGatewayBGPService(daemon.gatewayGRPCService)
		daemon.concreteRestServer.SetGatewayBackends(daemon.gatewayGRPCService)
		logger.Info("Gateway IPAM REST service wired into REST server")
	}

	// Wire proxy REST handlers over the same shared ProxyGRPCService.
	if daemon.concreteRestServer != nil && daemon.proxyGRPCService != nil {
		daemon.concreteRestServer.SetProxyService(daemon.proxyGRPCService)
		logger.Info("Proxy REST service wired into REST server")
	}

	// Wire Phase 3.5 services (ceremony/piv/luks/fido2) into REST server.
	if daemon.concreteRestServer != nil {
		if daemon.ceremonyService != nil && daemon.ceremonyService.service != nil {
			daemon.concreteRestServer.SetCeremonyService(daemon.ceremonyService.service)
		}
		if daemon.pivService != nil && daemon.pivService.service != nil {
			daemon.concreteRestServer.SetPIVService(daemon.pivService.service)
		}
		if daemon.luksService != nil && daemon.luksService.service != nil {
			daemon.concreteRestServer.SetLUKSService(daemon.luksService.service)
		}
		if daemon.fido2Service != nil && daemon.fido2Service.service != nil {
			daemon.concreteRestServer.SetFIDO2Service(daemon.fido2Service.service)
		}
		// Cluster REST always mounts; if no coordinator is wired the
		// handlers return 503 with a clear "not configured" body so the
		// dashboard can render an actionable empty state rather than 404.
		daemon.concreteRestServer.SetClusterService(clusterGRPCService)
	}

	// Wire config delivery for pre-enrollment provisioning across the REST and
	// gRPC (TCP + UDS) surfaces. Resolve the device profile service and EAB
	// credential service from the platform service registry so paradigm-B
	// config delivery resolves real configs by EK serial / MAC, enforces
	// External Account Binding, and binds the delivered config to the device's
	// hardware EK certificate. The concrete *device.ProfileService satisfies
	// configdelivery.ProfileResolver (FindConfigForDevice + Get); EK matching
	// defaults to enforced.
	cdParams := configdelivery.ServiceParams{
		Logger: logger,
	}
	if config.App != nil {
		reg, err := config.App.ServiceRegistry()
		if err != nil {
			return nil, err
		}
		if ps := reg.ProfileService(); ps != nil {
			cdParams.ProfileService = ps
		}
		cdParams.EABService = reg.EABService()
		port := 0
		if _, portStr, splitErr := net.SplitHostPort(config.RESTListenAddr); splitErr == nil {
			port, _ = strconv.Atoi(portStr)
		}
		cdParams.BaseURL = configdelivery.ProvisionBaseURL(config.App.FQDN(), port)

		// Wire the control-plane Secure Boot DB signer so resign-mode
		// "remote" nodes can have their UKI digest signed without the DB
		// private key ever leaving the control plane. Unavailable until the
		// server-side KMS/CA are ready; the sign endpoint then returns a
		// typed "unavailable" rather than failing daemon startup.
		if signer, signerErr := NewRemoteDBKeySignerFromApp(config.App, logger); signerErr != nil {
			logger.Warn("Remote DB key signer unavailable for config delivery sign endpoint", "error", signerErr)
		} else {
			cdParams.DBKeySigner = signer
			daemon.dbKeySigner = signer
		}
	}
	configDeliverySvc, cdErr := configdelivery.NewService(cdParams)
	if cdErr != nil {
		logger.Warn("Config delivery service creation failed", "error", cdErr)
	} else {
		daemon.configDeliveryService = configDeliverySvc
		if daemon.concreteRestServer != nil {
			respWriter := response.NewResponseWriter(logger, nil)
			handler, handlerErr := configdelivery.NewHandler(configdelivery.HandlerParams{
				Service:        configDeliverySvc,
				ResponseWriter: respWriter,
				Logger:         logger,
			})
			if handlerErr == nil {
				daemon.concreteRestServer.SetConfigDeliveryHandler(handler)
				logger.Info("Config delivery handler wired into REST server")
			} else {
				logger.Warn("Config delivery handler creation failed", "error", handlerErr)
			}
		}
	}

	// Register the platform.v1 ConfigDeliveryService on both gRPC servers so
	// config delivery has protocol parity over gRPC-TCP and gRPC-UDS. When the
	// backing service is nil (creation failed) every RPC returns a typed
	// Unavailable error via the service's requireService guard instead of
	// panicking.
	configDeliveryGRPC := NewConfigDeliveryGRPCService(configDeliverySvc, logger.Slog())
	daemon.configDeliveryGRPC = configDeliveryGRPC
	if grpcServer != nil {
		platformv1.RegisterConfigDeliveryServiceServer(grpcServer, configDeliveryGRPC)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterConfigDeliveryServiceServer(grpcUDSServer, configDeliveryGRPC)
	}
	logger.Info("Config delivery gRPC service registered",
		"service", "platform.v1.ConfigDeliveryService")

	// Wire the same ConfigDeliveryGRPCService into the QUIC handler so the
	// OpProvisioningCategory (0xCF) sub-operations share identical semantics
	// and error mapping with the gRPC transport. When the backing service is
	// nil the shared requireService guard returns a typed Unavailable error.
	if quicHandler != nil {
		quicHandler.SetConfigDeliveryService(configDeliveryGRPC)
		logger.Debug("Config delivery service set for QUIC handler")
	}

	// Wire the same EABGRPCService into the QUIC handler so the EAB
	// sub-opcodes multiplexed under OpProvisioningCategory (0xCF) share
	// identical semantics and error mapping with the gRPC transport.
	if quicHandler != nil {
		quicHandler.SetEABService(daemon.eabGRPCService)
		logger.Debug("EAB service set for QUIC handler")
	}

	// Create BMC service for bare metal management. The same service
	// powers the gRPC, REST and (when configured) the orchestrated
	// baremetal provisioning workflows.
	//
	// Resolve the BMC TLS provider from the App trust resolver. This wires
	// all daemon-side BMC HTTPS through the platform class-BMC trust chain.
	// When App is absent the provider is nil and BMC operates without a
	// custom TLS provider (factory / static TLS only).
	var bmcTLSProvider bmc.TLSProvider
	if config.App != nil {
		bmcTLSProvider = config.App.BMCTLSProvider()
	}

	// Build the profile store. When DeviceProfileService is absent the
	// store is nil; callers that require profile-backed config (enrollment)
	// will return ErrProfileNotFound. The TLS provider is injected so every
	// profile-resolved config routes through the trust resolver.
	var bmcProfileStore bmc.ProfileStore
	if config.DeviceProfileService != nil {
		bmcProfileStore = newDeviceProfileStore(config.DeviceProfileService, bmcTLSProvider)
	}

	bmcSvc, bmcErr := bmc.NewService(bmc.ServiceParams{
		Factory:  bmc.NewIPMIClientFactory(logger.Slog()),
		Profiles: bmcProfileStore,
		Logger:   logger.Slog(),
	})
	if bmcErr != nil {
		logger.Warn("BMC service creation failed", "error", bmcErr)
	} else {
		// Register BMC gRPC service with both TCP and UDS endpoints.
		// The baremetal service is left nil here; Provision and
		// ProvisionStatus return Unavailable (not configured) until a baremetal
		// orchestrator is wired via SetBaremetalService.
		bmcGRPCService := NewBMCGRPCService(bmcSvc, nil, logger.Slog())

		// Wire the BMCEnroller into the gRPC service so EnrollBMC RPCs
		// execute the real ceremony rather than returning Unimplemented.
		// guarded on both App and DeviceProfileService being present.
		if config.App != nil && config.DeviceProfileService != nil {
			bmcGRPCService.SetEnroller(config.App, config.DeviceProfileService)
			logger.Info("BMC gRPC enroller wired")
			bmcGRPCService.SetRestorer(config.App, config.DeviceProfileService)
			logger.Info("BMC gRPC restorer wired")
		}

		if grpcServer != nil {
			platformv1.RegisterBMCServiceServer(grpcServer, bmcGRPCService)
		}
		if grpcUDSServer != nil {
			platformv1.RegisterBMCServiceServer(grpcUDSServer, bmcGRPCService)
		}
		logger.Info("BMC gRPC service initialized and registered successfully")

		// Wire BMC handler into REST server for bare metal management.
		if daemon.concreteRestServer != nil {
			respWriter := response.NewResponseWriter(logger, nil)
			bmcHandler, bmcHandlerErr := bmcwebsvc.NewHandler(bmcwebsvc.HandlerParams{
				BMCService:     bmcSvc,
				ResponseWriter: respWriter,
				Logger:         logger,
			})
			if bmcHandlerErr == nil {
				// Wire the BMCEnrollerServicer adapter so the REST enroll
				// endpoint delegates to the real App enrollment ceremony.
				if config.App != nil && config.DeviceProfileService != nil {
					lookup := &profileLookupAdapter{profileSvc: config.DeviceProfileService}
					bmcHandler.SetEnroller(
						newRESTBMCEnrollerAdapter(config.App),
						lookup,
					)
					logger.Info("BMC REST enroller wired")
					bmcHandler.SetRestorer(
						newRESTBMCRestorerAdapter(config.App),
						lookup,
					)
					logger.Info("BMC REST restorer wired")
				}
				daemon.concreteRestServer.SetBMCHandler(bmcHandler)
				logger.Info("BMC management handler wired into REST server")
			} else {
				logger.Warn("BMC handler creation failed", "error", bmcHandlerErr)
			}
		}

		// Stash the BMC gRPC servicer so the MCP server (created below)
		// and the embedded transport serve BMCService through it, and
		// hand it to the QUIC handler: every transport then answers and
		// refuses alike.
		daemon.bmcGRPCService = bmcGRPCService
		if daemon.quicHandler != nil {
			daemon.quicHandler.SetBMCServer(bmcGRPCService)
		}
	}

	// The PXE opcodes delegate to the same PXEService servicer gRPC serves.
	if daemon.quicHandler != nil {
		daemon.quicHandler.SetPXEServer(daemon.pxeGRPCService)
	}

	// The switch sub-opcodes delegate to the same SwitchService servicer gRPC
	// serves. The nil check keeps a missing servicer a nil interface, so the
	// category answers unavailable.
	if daemon.quicHandler != nil && daemon.switchGRPCService != nil {
		daemon.quicHandler.SetSwitchServer(daemon.switchGRPCService)
	}

	// Create MCP server if enabled and not overridden by option
	if config.EnableMCP && daemon.mcpServer == nil {
		mcpServer, mcpErr := daemon.createMCPServer()
		if mcpErr != nil {
			constructErr := ErrTransportConstructionFailed{Transport: transportMCP, Cause: mcpErr}
			logger.Error(constructErr, "component", "mcp_server")
			return nil, constructErr
		}
		daemon.mcpServer = mcpServer
		daemon.concreteMcpServer = mcpServer
		mcpCfg := config.effectiveMCPConfig()
		logger.Info("MCP server created", "transport", mcpCfg.Transport, "addr", mcpCfg.HTTPAddr)
	} else if !config.EnableMCP {
		logger.Info("MCP server not enabled")
	}

	// Inject the live TPM into every protocol handler (REST, QUIC, MCP,
	// plus the IDevID/TPM gRPC services). Without this, handlers that
	// came up after the initial service construction (REST server, QUIC
	// handler, MCP provider) return FailedPrecondition "TPM2 service
	// not initialized". The gRPC IDevID/TPM services are already wired
	// in-line above; this call is a belt-and-suspenders pass that also
	// covers any handler created between service construction and now.
	if config.App != nil && config.App.TPM != nil {
		daemon.SetTPM2Service(config.App.TPM)
	}

	logger.Info("Registering health checkers...")
	// Register health checkers for available services
	daemon.registerHealthCheckers()

	// Replay any bridge-address conflicts the duplicate-address guard
	// recorded during App bring-up, which happens before any transport
	// exists (#508).
	daemon.publishBridgeAddressConflicts()

	logger.Info("Wiring health registry...")
	// Wire health registry into the service for gRPC health endpoint
	service.SetHealthRegistry(healthRegistry)

	// Register the standard gRPC health checking service
	// (grpc.health.v1.Health), which load balancers and orchestrators probe
	// by default. Until now this daemon implemented the protocol and served
	// it nowhere.
	//
	// SECURITY: this activates an exemption that was already in the tree.
	// "/grpc.health.v1.Health/Check" is in grpcTCPSkipMethods, so from this
	// point it answers UNAUTHENTICATED callers on the TCP listener. Only an
	// aggregate SERVING/NOT_SERVING is exposed: no service names are
	// registered, so Check returns NOT_FOUND for every name and the service
	// inventory stays undisclosed. Watch is NOT exempted and still requires
	// authentication. See #337.
	healthGRPCService := NewHealthGRPCService(logger)
	healthGRPCService.RegisterHealthChecker(
		daemonHealthCheckerName,
		NewRegistryHealthChecker(healthRegistry),
	)
	if grpcServer != nil {
		RegisterHealthService(grpcServer, healthGRPCService)
	}
	if grpcUDSServer != nil {
		RegisterHealthService(grpcUDSServer, healthGRPCService)
	}
	daemon.healthGRPCService = healthGRPCService
	logger.Info("gRPC health service registered (grpc.health.v1.Health)")

	// Set shutdown handler to stop the servers
	service.SetShutdownHandler(func() error {
		return daemon.stopServers()
	})

	logger.Info("Daemon created successfully")
	return daemon, nil
}

// grpcServerWrapper wraps *grpc.Server to implement GRPCServerInterface
type grpcServerWrapper struct {
	server *grpc.Server
}

// RegisterService implements GRPCServerInterface.RegisterService
func (w *grpcServerWrapper) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {
	if w.server != nil {
		w.server.RegisterService(desc, impl)
	}
}

// Serve implements GRPCServerInterface.Serve
func (w *grpcServerWrapper) Serve(lis net.Listener) error {
	if w.server == nil {
		return ErrGRPCServerNotConfigured{}
	}
	return w.server.Serve(lis)
}

// GracefulStop implements GRPCServerInterface.GracefulStop
func (w *grpcServerWrapper) GracefulStop() {
	if w.server != nil {
		w.server.GracefulStop()
	}
}

// Stop implements GRPCServerInterface.Stop
func (w *grpcServerWrapper) Stop() {
	if w.server != nil {
		w.server.Stop()
	}
}

// Unwrap returns the underlying *grpc.Server for service registration
func (w *grpcServerWrapper) Unwrap() *grpc.Server {
	return w.server
}

// createMCPServer creates and configures the MCP server.
func (d *Daemon) createMCPServer() (*mcp.Server, error) {
	// Create the MCP service provider that bridges MCP to daemon services.
	// The IAM tools answer through the same QuicBaaS IAM and PEP clients
	// as the gRPC IAM service; without IAM both are nil and the tools
	// answer ErrIAMServiceNotAvailable.
	serviceProvider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		IAMClient:             d.iamService.Client(),
		PEPClient:             d.iamService.PEP(),
		IAMTokens:             d.iamTokenService,
		PlatformTenantID:      d.config.PlatformTenantID,
		CAService:             d.caService,
		VTPMService:           d.config.VTPMService,
		DeviceService:         d.config.DeviceService,
		DeviceProfileService:  d.config.DeviceProfileService,
		DeviceTemplateService: d.config.DeviceTemplateService,
		VerdictSink:           deviceVerdictSink(d.config),
		AttestCertRecorder:    newDeviceAttestCertRecorder(d.config, d.logger.Slog()),
		DeviceLifecycle:       d.config.DeviceLifecycle,
		AttestationReporting:  d.config.AttestationReporting,
		AttestationServer:     d.attestationService,
		SDNService:            d.sdnService,
		HealthService:         d.service,
		Logger:                d.logger.Slog(),
		ComputeOrchestrator:   d.config.ComputeOrchestrator,
		RegistryService:       d.config.RegistryService,
		EABService:            d.eabService,
		EABDelivery:           d.eabDelivery,
		ZoneService:           d.zoneSvc,
		IPAMService:           d.gatewayGRPCService.IPAMAllocator(),
		GatewayBackends:       d.gatewayGRPCService,
		GatewaySnapshots:      d.gatewayGRPCService,
		GatewayStatus:         d.gatewayGRPCService,
		GatewayBGP:            d.gatewayGRPCService,
		Overlay:               d.overlayCtrl,
		ConfigDeliveryService: d.configDeliveryService,
		ProxyService:          d.proxyGRPCService,
		// The hash, HMAC, rewrap, batch, import, export and key-version
		// tools call the backend gRPC KeyManagementService, QUIC and the
		// daemon REST facade call, so every transport shares one method.
		KMSBackend: d.kmsPlatformBackend,
	})

	// Wire DNS service to MCP provider if available via App
	if d.config.App != nil && d.config.App.DNSService != nil {
		serviceProvider.dnsService = d.config.App.DNSService
	}

	// Wire time synchronization so the ntp_* tools delegate to the same
	// NTPGRPCService instance that backs REST, gRPC, QUIC, and Unix.
	if d.ntpGRPCService != nil {
		serviceProvider.SetNTPService(d.ntpGRPCService)
	}

	// Wire the VPN control plane so the vpn_* tools delegate to the same
	// VPNGRPCService instance that backs REST, gRPC, QUIC, and Unix.
	if d.vpnGRPCService != nil {
		serviceProvider.SetVPNService(d.vpnGRPCService)
	}

	// Wire the TenantService so the tenant tools delegate to the same
	// TenantGRPCServer that backs REST, gRPC, QUIC, and Unix. The nil check
	// keeps a typed-nil server out of the interface field.
	if tenantServer := d.TenantGRPCServer(); tenantServer != nil {
		serviceProvider.SetTenantService(tenantServer)
	}

	// Wire Cache, Scheduler and Messaging so their tools delegate to the
	// same servers that back REST, gRPC, QUIC, and Unix.
	serviceProvider.SetAppServiceServers(d.appServices.mcpServers())

	// Wire the QuicBaaS KMS / Crypto / Secrets service layer into the MCP
	// provider so the kms_* and secret_* tools delegate to the same
	// quicbaas services that back the gRPC, QUIC, and Unix transports.
	if d.config.App != nil {
		serviceProvider.kmsService = d.config.App.KMS()
		serviceProvider.cryptoService = d.config.App.CryptoService()
		serviceProvider.secretsService = d.config.App.Secrets()
	}
	// The dek_* tools call the gRPC DEKManagement adapter, the one the QUIC
	// DEK sub-opcodes call. initializeServers is idempotent.
	if d.kmsService != nil {
		if initErr := d.kmsService.initializeServers(); initErr != nil {
			d.logger.Warn("KMS service MCP initialization failed", "error", initErr)
		} else if d.kmsService.DEKServer() != nil {
			serviceProvider.SetDEKService(d.kmsService.DEKServer())
		}
	}

	// The platform_bmc_* tools call the gRPC BMC servicer, which already
	// carries the enroller and restorer. The nil check keeps a missing BMC
	// service a nil interface, so the tools refuse with ErrBMCNotConfigured.
	if d.bmcGRPCService != nil {
		serviceProvider.SetBMCServer(d.bmcGRPCService)
	}
	// The pxe_* tools call the PXEService servicer gRPC serves, under the
	// same nil check, so a missing PXE service refuses with
	// ErrPXENotConfigured.
	if d.pxeGRPCService != nil {
		serviceProvider.SetPXEServer(d.pxeGRPCService)
	}

	// The switch_* tools call the SwitchService servicer gRPC serves. The nil
	// check keeps a missing switch service a nil interface, so the tools
	// answer Unimplemented as a host without the service does.
	if d.switchGRPCService != nil {
		serviceProvider.SetSwitchServer(d.switchGRPCService)
	}

	// The platform_cluster_* tools call the gRPC ClusterService servicer, so
	// they answer Unavailable, as gRPC does, until SetClusterService wires a
	// cluster service behind it.
	serviceProvider.SetClusterServer(d.clusterGRPCService)

	// The platform_invitation_* tools call the gRPC InvitationService
	// servicer, as QUIC does. When d.invitationService is nil the servicer
	// answers Unimplemented on every transport alike.
	if d.invitationGRPCService != nil {
		if d.invitationService != nil {
			d.invitationGRPCService.SetService(d.invitationService)
		}
		serviceProvider.SetInvitationServer(d.invitationGRPCService)
	}

	// Store the provider for later service injection
	d.mcpProvider = serviceProvider

	// Wire the shared IDevID service so the idevid_create_ldevid tool
	// delegates to the same CA-backed IDevIDGRPCService as every transport.
	if d.idevidService != nil {
		serviceProvider.SetIDevIDService(d.idevidService)
	}

	// Wire Phase 3.5 services (ceremony/piv/luks/fido2) into the MCP provider
	// so MCP tools can delegate to the real backends set via Set*Backend.
	phase35Svcs := Phase35Services{}
	if d.ceremonyService != nil {
		phase35Svcs.Ceremony = d.ceremonyService.service
	}
	if d.pivService != nil {
		phase35Svcs.PIV = d.pivService.service
	}
	if d.luksService != nil {
		phase35Svcs.LUKS = d.luksService.service
	}
	if d.fido2Service != nil {
		phase35Svcs.FIDO2 = d.fido2Service.service
	}
	serviceProvider.SetPhase35Services(phase35Svcs)

	// Build MCP config from daemon MCPConfig
	mcpCfg := d.config.effectiveMCPConfig()

	mcpConfig := &mcp.Config{
		ServerName:            mcpCfg.ServerName,
		ServerVersion:         mcpCfg.ServerVersion,
		Transport:             mcpCfg.Transport,
		HTTPAddr:              mcpCfg.HTTPAddr,
		RequestTimeout:        mcpCfg.RequestTimeout,
		MaxConcurrentRequests: mcpCfg.MaxConcurrentRequests,
	}

	// The HTTP transport serves TLS 1.3 only, with the identity and mTLS
	// policy REST and gRPC serve (#844). There is no plaintext fallback:
	// without a usable certificate the server is not created, and
	// tlsPreflight refuses Start for the same configuration.
	if mcpCfg.Transport == "http" {
		inMemory := d.config.inMemoryCertificate()
		if !tlsCertificateUsable(inMemory) {
			return nil, ErrTLSConfigFailed{Reason: "MCP: no usable TLS certificate for the HTTP transport on " + mcpCfg.HTTPAddr}
		}
		tlsConfig, err := newServerTLSConfig(d.config, transportMCP, *inMemory)
		if err != nil {
			return nil, err
		}
		mcpConfig.TLSConfig = tlsConfig

		peers, err := newMCPPeerAuthenticator(d.config, d.logger)
		if err != nil {
			return nil, err
		}
		mcpConfig.PeerAuthenticator = peers
	}

	// Try to set up MCP auth. Prefer the shared broker platform-token
	// validator (claims path: scp -> RBAC, tenant_id -> RLS) when configured,
	// falling back to the legacy QuicBaaS adapter otherwise.
	// Skip authentication when SkipIAMValidation is set (testing mode).
	if !d.config.SkipIAMValidation {
		if d.platformTokenValidatorShared != nil {
			mcpConfig.AuthorizationService = d.platformTokenValidatorShared
			mcpConfig.AuthManager = d.platformTokenValidatorShared
			d.logger.Info("MCP server configured with platform-token validation")
		} else if authAdapter := d.createMCPAuthAdapter(); authAdapter != nil {
			mcpConfig.AuthorizationService = authAdapter
			mcpConfig.AuthManager = authAdapter
			d.logger.Info("MCP server configured with QuicBaaS authorization")
		} else {
			// Fail closed (#440). With no backend AuthorizeTool refuses every
			// tool that requires a permission, so a server started here would
			// be dark for everything but the explicitly open tools -- and the
			// old behaviour, a Warn followed by a server that allowed every
			// tool, is the defect. Refuse to create it; New fails with the
			// error (#444) rather than run without the enabled transport.
			return nil, ErrMCPAuthorizationBackendRequired{}
		}
	}

	// Get logging.Logger from App if available
	var mcpLogger *logging.Logger
	if d.config.App != nil && d.config.App.Logger != nil {
		mcpLogger = d.config.App.Logger
	} else {
		mcpLogger = logging.DefaultLogger()
	}

	// Create the MCP server
	mcpServer := mcp.NewServer(serviceProvider, mcpConfig, mcpLogger)

	return mcpServer, nil
}

// createMCPAuthAdapter attempts to create a QuicBaaS auth adapter for MCP.
// Returns nil if QuicBaaS is not available or not properly configured.
func (d *Daemon) createMCPAuthAdapter() *mcp.QuicBaaSAuthAdapter {
	// Check if we have an App with DAOFactory
	if d.config.App == nil {
		d.logger.Debug("No App configured for MCP auth")
		return nil
	}

	daoFactory := d.config.App.DAOFactory()
	if daoFactory == nil {
		d.logger.Debug("No DAOFactory configured for MCP auth")
		return nil
	}

	// Try to get QuicBaaS factory
	dbFactory, ok := daoFactory.(quicbaas.FactoryInterface)
	if !ok {
		d.logger.Debug("DAOFactory is not a QuicBaaS factory")
		return nil
	}

	client := dbFactory.QuicBaaSClient()
	if client == nil {
		d.logger.Debug("QuicBaaS client not available")
		return nil
	}

	if !client.IsStarted() {
		d.logger.Debug("QuicBaaS client not started")
		return nil
	}

	dbSvc := client.Service()
	if dbSvc == nil {
		d.logger.Debug("QuicBaaS service not available")
		return nil
	}

	// Adapt the QuicBaaS service to our ServiceInterface
	svcAdapter := &quicbaasServiceAdapter{svc: dbSvc}

	// Wrap the adapted service for token validation
	tokenValidator := &quicbaasServiceWrapper{service: svcAdapter}

	// Create the PEP client adapter if IAM service is available
	var pepClient iamsdk.PEPClient
	if d.iamService != nil {
		sdkPEP := d.iamService.PEP()
		if sdkPEP != nil {
			pepClient = sdkPEP
			d.logger.Debug("PEP client wired into MCP auth adapter")
		} else {
			d.logger.Debug("IAM PEP client not available")
		}
	} else {
		d.logger.Debug("IAM service not available for PEP authorization")
	}

	// Create the auth adapter with token validation and optional PEP authorization
	adapter := mcp.NewQuicBaaSAuthAdapter(&mcp.QuicBaaSAuthConfig{
		TokenValidator: tokenValidator,
		PEPClient:      pepClient,
	})

	d.logger.Debug("Created QuicBaaS auth adapter for MCP")
	return adapter
}

// quicbaasServiceWrapper wraps a QuicBaaS service to implement mcp.TokenValidator.
type quicbaasServiceWrapper struct {
	service quicbaas.ServiceInterface
}

// ValidateToken implements mcp.TokenValidator.
func (w *quicbaasServiceWrapper) ValidateToken(ctx context.Context, token string) (*mcp.TokenValidationResult, error) {
	if w.service == nil {
		return nil, &mcp.QuicBaaSAuthError{
			Code:    mcp.QuicBaaSAuthErrorServiceUnavailable,
			Message: "QuicBaaS service not available",
		}
	}

	resp, err := w.service.ValidateToken(ctx, &quicbaas.ValidateTokenRequest{
		AccessToken: token,
	})
	if err != nil {
		return nil, &mcp.QuicBaaSAuthError{
			Code:    mcp.QuicBaaSAuthErrorTokenValidation,
			Message: "token validation failed: " + err.Error(),
		}
	}

	return &mcp.TokenValidationResult{
		Valid:     resp.Valid,
		UserID:    resp.UserID,
		Roles:     resp.Roles,
		ExpiresAt: resp.ExpiresAt,
	}, nil
}

// quicbaasServiceAdapter adapts service.QuicBaaS to quicbaas.ServiceInterface.
type quicbaasServiceAdapter struct {
	svc service.QuicBaaS
}

func (a *quicbaasServiceAdapter) ValidateToken(ctx context.Context, req *quicbaas.ValidateTokenRequest) (*quicbaas.ValidateTokenResponse, error) {
	// Call the underlying QuicBaaS service's ValidateToken method
	resp, err := a.svc.ValidateToken(ctx, &service.ValidateTokenRequest{
		AccessToken: req.AccessToken,
	})
	if err != nil {
		return nil, err
	}

	return &quicbaas.ValidateTokenResponse{
		Valid:     resp.Valid,
		UserID:    resp.UserID,
		Username:  resp.Username,
		Roles:     resp.Roles,
		ExpiresAt: resp.ExpiresAt,
	}, nil
}

// =============================================================================
// gRPC/QUIC Token Validator Adapter
// =============================================================================

// grpcTokenValidator implements grpc.TokenValidator and quic.TokenValidator
// using QuicBaaS for token validation. This adapter returns (bool, error)
// as required by the gRPC and QUIC authentication interfaces.
type grpcTokenValidator struct {
	service      quicbaas.ServiceInterface
	jwtVerifier  PlatformJWTVerifier
	jwtVerifiers []PlatformJWTVerifier
	logger       *logging.Logger
}

// newGRPCTokenValidator creates a token validator for gRPC/QUIC authentication.
func newGRPCTokenValidator(service quicbaas.ServiceInterface, logger *logging.Logger) *grpcTokenValidator {
	return &grpcTokenValidator{
		service: service,
		logger:  logger,
	}
}

// ValidateToken implements grpc.TokenValidator and quic.TokenValidator.
//
// Validation order:
//  1. Try the platform-JWT verifier when configured (jwtVerifier). Tokens
//     issued by the webserver's /api/v1/login endpoint pass here. This
//     gives gRPC, QUIC, and MCP transports the same token surface as
//     REST without requiring callers to mint a separate QuicBaaS token.
//  2. Fall back to QuicBaaS service.ValidateToken for tokens minted by
//     the QuicBaaS auth provider (the legacy path).
//
// At least one verifier must be configured or every call returns an
// "authentication service not configured" error.
func (v *grpcTokenValidator) ValidateToken(ctx context.Context, token string) (bool, error) {
	if _, err := v.platformJWTClaims(token); err == nil {
		return true, nil
	}
	resp, err := v.validateWithQuicBaaS(ctx, token)
	if err != nil {
		return false, err
	}
	return resp.Valid, nil
}

// platformJWTClaims returns the claims of the first platform JWT verifier
// that accepts token. Multiple webservices may each mint tokens with their
// own signing key; the token is accepted if ANY verifier validates it.
// When none accepts it the error is ErrPlatformJWTRejected joining every
// verifier's rejection, or ErrNoPlatformJWTVerifier when none is attached.
func (v *grpcTokenValidator) platformJWTClaims(token string) (*jwt.TokenClaims, error) {
	verifiers := v.jwtVerifiers
	if len(verifiers) == 0 && v.jwtVerifier != nil {
		verifiers = []PlatformJWTVerifier{v.jwtVerifier}
	}
	var rejections []error
	for idx, vf := range verifiers {
		if vf == nil {
			continue
		}
		claims, err := vf.VerifyTokenClaims(token)
		if err == nil && claims != nil {
			return claims, nil
		}
		if err == nil {
			err = jwt.ErrInvalidToken
		}
		rejections = append(rejections, err)
		if v.logger != nil {
			v.logger.Debug("Platform JWT verifier rejected token",
				"verifier_index", idx,
				"verifier_count", len(verifiers),
				"err", err)
		}
	}
	if len(rejections) == 0 {
		return nil, ErrNoPlatformJWTVerifier{}
	}
	return nil, ErrPlatformJWTRejected{Cause: errors.Join(rejections...)}
}

// validateWithQuicBaaS validates a token minted by the QuicBaaS auth
// provider — the fallback when no platform JWT verifier accepts it.
func (v *grpcTokenValidator) validateWithQuicBaaS(ctx context.Context, token string) (*quicbaas.ValidateTokenResponse, error) {
	if v.service == nil {
		if v.logger != nil {
			v.logger.Debug("Token validation failed: QuicBaaS service not available")
		}
		return nil, ErrQuicBaaSServiceUnavailable{}
	}
	resp, err := v.service.ValidateToken(ctx, &quicbaas.ValidateTokenRequest{
		AccessToken: token,
	})
	if err != nil {
		if v.logger != nil {
			v.logger.Debug("Token validation failed", "error", err)
		}
		return nil, ErrTokenValidationFailed{Cause: err}
	}
	return resp, nil
}

// PlatformJWTVerifier is the minimal surface needed by grpcTokenValidator
// to verify a platform-issued JWT and read the principal it names. The
// webserver's jwt.Service satisfies it.
type PlatformJWTVerifier interface {
	VerifyTokenClaims(tokenString string) (*jwt.TokenClaims, error)
}

// SetPlatformJWTVerifier wires a platform JWT verifier into the daemon's
// existing gRPC TCP and QUIC auth interceptors. Call this after the
// webserver's JWT service is initialized so both transports accept
// /api/v1/login-issued tokens. Safe to call before or after Start();
// the validators are protected by atomic-pointer semantics.
func (d *Daemon) SetPlatformJWTVerifier(verifier PlatformJWTVerifier) {
	if d == nil || verifier == nil {
		return
	}
	if d.grpcAuthValidator != nil {
		d.grpcAuthValidator.SetJWTVerifier(verifier)
		d.logger.Info("Platform JWT verifier attached to gRPC TCP validator")
	}
	if d.quicAuthValidator != nil {
		d.quicAuthValidator.SetJWTVerifier(verifier)
		d.logger.Info("Platform JWT verifier attached to QUIC validator")
	}
}

// SetJWTVerifier wires the platform JWT verifier so gRPC/QUIC/MCP
// requests authenticated with platform-issued tokens (e.g. from
// /api/v1/login) succeed without requiring a separate QuicBaaS-issued
// token. Multiple verifiers can be registered (one per webservice the
// daemon serves); the validator accepts a token if ANY verifier
// validates it. This handles deployments with multiple webservices
// each minting JWTs with their own signing key.
func (v *grpcTokenValidator) SetJWTVerifier(verifier PlatformJWTVerifier) {
	v.jwtVerifier = verifier
	v.jwtVerifiers = append(v.jwtVerifiers, verifier)
}

// Start starts the daemon
// tlsPreflight decides every transport's fail-closed TLS refusal (#32)
// before Start touches anything. Each check mirrors the transport's start
// contract: gRPC TCP binds only with construction-time credentials or an
// attested replacement; QUIC needs a server whose TLS material (or
// attestation, when replaced) is present; a replacement REST server must
// attest TLS. The built-in REST server enforces its own material check at
// bind time — before any other network transport has started.
func (d *Daemon) tlsPreflight() error {
	// A nil replacement for an ENABLED transport is refused outright:
	// WithRESTServer(nil)/WithGRPCServer(nil) would otherwise make Start
	// report success while silently omitting the configured transport.
	if d.config.EnableREST && d.restServerReplaced && d.restServer == nil {
		return ErrRESTServerStartFailed{
			Reason: "REST is enabled but the replacement REST server is nil: refusing to start without the configured transport",
		}
	}
	if d.restServer != nil && d.restServerReplaced && !attestsTLS(d.restServer) {
		return ErrRESTServerStartFailed{
			Reason: "replacement REST server does not attest TLS (implement TLSAttestor with ServesTLS() == true): refusing to start it",
		}
	}

	if d.config.EnableGRPCTCP && d.grpcServerReplaced && d.grpcServer == nil {
		return ErrTLSConfigFailed{
			Reason: "gRPC TCP is enabled but the replacement gRPC server is nil: refusing to start without the configured transport",
		}
	}
	if d.grpcServer != nil && d.config.EnableGRPCTCP {
		grpcMayBind := d.grpcTLSCredsAttached || (d.grpcServerReplaced && attestsTLS(d.grpcServer))
		if !grpcMayBind {
			return ErrTLSConfigFailed{
				Reason: "gRPC TCP: TLS material absent (no in-memory certificate and no cert/key files): refusing to start a plaintext listener on " + d.config.GRPCListenAddr,
			}
		}
	}

	if d.config.EnableQUIC {
		quicRefused := d.quicServer == nil
		if !quicRefused {
			if d.quicServerReplaced {
				quicRefused = !attestsTLS(d.quicServer)
			} else {
				quicRefused = !d.config.quicTLSMaterialPresent()
			}
		}
		if quicRefused {
			return ErrQUICServerStartFailed{
				Cause: ErrTLSConfigFailed{
					Reason: "QUIC: server unavailable or TLS material absent (no tls.Config with a certificate or GetCertificate): refusing to start on " + d.config.QUICListenAddr,
				},
			}
		}
	}

	// MCP over HTTP serves TLS 1.3 only with the daemon certificate (#844).
	// Without one New refuses to build the daemon (#444); this check covers
	// a certificate removed from the shared config after New.
	if d.config.MCPServesHTTP() && !d.mcpServerReplaced && !tlsCertificateUsable(d.config.inMemoryCertificate()) {
		return ErrTLSConfigFailed{
			Reason: "MCP: TLS material absent (no usable in-memory certificate): refusing to start the HTTP transport on " + d.config.effectiveMCPConfig().HTTPAddr,
		}
	}

	return nil
}

// rollbackPartialStart stops, best-effort and in reverse start order,
// everything Start managed to bring up before a fatal startup failure.
// It exists because Stop/ForceStop guard on d.running, which is still
// false during Start — without this, a failure after the internal
// services (or any transport) started would leak them with no public
// cleanup path, and a retry could meet duplicate workers (#32). Stop
// errors are logged, never masked over the original startup error.
func (d *Daemon) rollbackPartialStart(ctx context.Context) {
	// QUIC first: a QUIC Start that acquired resources (bound its
	// listener, started workers) before returning an error can leave the
	// surface reachable; IsRunning gates the stop so an unstarted server
	// is untouched.
	if d.quicServer != nil && d.quicServer.IsRunning() {
		if err := d.quicServer.Stop(); err != nil {
			d.logger.Warn("startup rollback: QUIC server stop failed", "error", err)
		}
	}

	// gRPC servers are stopped ONLY when their listener was bound (Serve
	// was launched): grpc.Server.Stop is permanent, and stopping an
	// unstarted server would poison it — a later Start retry would bind a
	// listener whose Serve immediately returns ErrServerStopped in a
	// goroutine, reporting a "running" daemon whose gRPC transport is
	// dead. When a served server IS stopped here, the daemon is marked
	// retry-unsafe: the caller must construct a new Daemon.
	if d.grpcUDSListener != nil {
		_ = d.grpcUDSListener.Close()
		d.grpcUDSListener = nil
		if d.grpcUDSServer != nil {
			d.grpcUDSServer.Stop()
			d.retryUnsafe = true
		}
	}
	if d.grpcListener != nil {
		_ = d.grpcListener.Close()
		d.grpcListener = nil
		if d.grpcServer != nil {
			d.grpcServer.Stop()
			d.retryUnsafe = true
		}
	}
	if d.mcpServer != nil && d.mcpServer.IsRunning() {
		if err := d.mcpServer.Stop(); err != nil {
			d.logger.Warn("startup rollback: MCP server stop failed", "error", err)
		}
	}
	if d.restServer != nil && d.restServer.IsRunning() {
		if err := d.restServer.ForceStop(); err != nil {
			d.logger.Warn("startup rollback: REST server stop failed", "error", err)
		}
	}
	if d.tenantService != nil {
		if err := d.tenantService.Stop(ctx); err != nil {
			d.logger.Warn("startup rollback: tenant service stop failed", "error", err)
		}
	}
	if d.iamService != nil {
		if err := d.iamService.Stop(ctx); err != nil {
			d.logger.Warn("startup rollback: IAM service stop failed", "error", err)
		}
	}
	if d.kmsService != nil {
		if err := d.kmsService.Stop(ctx); err != nil {
			d.logger.Warn("startup rollback: KMS service stop failed", "error", err)
		}
	}
}

func (d *Daemon) Start(ctx context.Context) error {
	d.logger.Info("Daemon.Start() called")
	if d.running.Load() {
		return ErrDaemonAlreadyRunning{}
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Re-check under the lock: a concurrent Start that won the lock has
	// started every transport, and a second pass would fail on them and roll
	// the first one's servers back.
	if d.running.Load() {
		return ErrDaemonAlreadyRunning{}
	}

	// A prior failed Start that had to stop a served gRPC server left
	// that server permanently unusable (grpc.Server.Stop). Refuse the
	// retry rather than reporting a running daemon with a dead transport.
	if d.retryUnsafe {
		err := ErrDaemonRetryUnsafe{}
		d.logger.Error(err, "component", "startup")
		return err
	}

	// Fail-closed TLS preflight (#32): every transport's TLS refusal is
	// decided BEFORE anything starts, so a refusal never has to roll back
	// an already-serving listener — a rollback whose own failure could
	// leave a surface live behind a startup error.
	if err := d.tlsPreflight(); err != nil {
		d.logger.Error(err, "component", "tls_preflight")
		return err
	}

	d.logger.Info("Starting services...")

	// Start KMS service if available
	if d.kmsService != nil {
		if err := d.kmsService.Start(ctx); err != nil {
			d.logger.Warn("KMS service start failed", "error", err)
			// Log error but continue - KMS operations will fail
		}
	}

	// Start IAM service if available
	if d.iamService != nil {
		if err := d.iamService.Start(ctx); err != nil {
			d.logger.Warn("IAM service start failed", "error", err)
			// Log error but continue - IAM operations will fail
		}
	}

	// Start tenant service if available
	if d.tenantService != nil {
		if err := d.tenantService.Start(ctx); err != nil {
			d.logger.Warn("Tenant service start failed", "error", err)
			// Log error but continue - tenant operations will fail
		}
	}

	// Start REST server if enabled. Fail closed (#32): a REST transport
	// that cannot start — TLS material absent included — fails daemon
	// startup instead of degrading to a daemon without its advertised TLS
	// surface. Replacement-server attestation was decided in tlsPreflight.
	if d.restServer != nil {
		d.logger.Info("Starting REST server...", "addr", d.config.RESTListenAddr)
		if err := d.restServer.Start(); err != nil {
			d.logger.Error(err, "component", "rest_server")
			d.rollbackPartialStart(ctx)
			return err
		}
		d.logger.Info("REST server started successfully")
	}

	// Start MCP server if enabled
	if d.mcpServer != nil {
		d.logger.Info("Starting MCP server...")
		if err := d.mcpServer.Start(); err != nil {
			d.logger.Error(err, "component", "mcp_server")
			d.rollbackPartialStart(ctx)
			return &MCPServerStartError{Err: err}
		}
		d.logger.Info("MCP server started successfully")
	}

	// Start gRPC TCP server if enabled. Fail closed (#32): without TLS
	// material New built the server with no transport credentials, so
	// binding the TCP listener would serve plaintext HTTP/2 with bearer
	// tokens in the clear on the canonical TLS port. Refuse instead. The
	// immutable construction-time flag is authoritative — material added
	// to the config after New cannot retrofit credentials onto a server
	// that was built plaintext.
	if d.grpcServer != nil && d.config.EnableGRPCTCP {
		listener, err := net.Listen("tcp", d.config.GRPCListenAddr)
		if err != nil {
			d.logger.Error(err, "component", "grpc_listener")
			d.rollbackPartialStart(ctx)
			return err
		}
		d.grpcListener = listener
		d.logger.Info("gRPC TCP server starting...", "addr", d.config.GRPCListenAddr)

		go func() {
			if err := d.grpcServer.Serve(listener); err != nil {
				d.logger.Error(err, "component", "grpc_server")
			}
		}()
		d.logger.Info("gRPC TCP server started successfully")
	}

	// Start gRPC UDS server if enabled. SANCTIONED non-TLS carve-out (#32):
	// the Unix-domain-socket transport is filesystem-permission-scoped
	// (SocketMode/SocketGroup), not network-exposed, so it is the one
	// transport allowed to serve without TLS material. Every network
	// transport above fails closed instead.
	if d.grpcUDSServer != nil && d.config.EnableGRPCUDS {
		// Clean up existing socket file
		if err := os.RemoveAll(d.config.GRPCSocketPath); err != nil {
			d.logger.Warn("Failed to remove existing gRPC socket", "error", err)
		}

		listener, err := net.Listen("unix", d.config.GRPCSocketPath)
		if err != nil {
			d.logger.Error(err, "component", "grpc_uds_listener")
			d.rollbackPartialStart(ctx)
			return err
		}

		// Set socket permissions
		if err := os.Chmod(d.config.GRPCSocketPath, d.config.SocketMode); err != nil {
			d.logger.Warn("Failed to set gRPC socket permissions", "error", err)
		}

		d.grpcUDSListener = listener
		d.logger.Info("gRPC UDS server starting...", "path", d.config.GRPCSocketPath)

		go func() {
			if err := d.grpcUDSServer.Serve(listener); err != nil {
				d.logger.Error(err, "component", "grpc_uds_server")
			}
		}()
		d.logger.Info("gRPC UDS server started successfully")
	}

	// Start QUIC server if enabled. Fail closed (#32): QUIC requires TLS by
	// protocol; a missing or certificate-less tls.Config is refused here
	// with a typed error rather than left to fail (or improvise) deeper in
	// the stack. The check keys off EnableQUIC, not server non-nilness —
	// New refuses a QUIC server it cannot construct (#444), but a nil
	// WithQUICServer replacement still leaves quicServer nil, and a daemon
	// asked to serve QUIC that cannot must not start quietly without it.
	if d.config.EnableQUIC {
		d.logger.Info("Starting QUIC server...", "addr", d.config.QUICListenAddr)
		if err := d.quicServer.Start(); err != nil {
			d.logger.Error(err, "component", "quic_server")
			d.rollbackPartialStart(ctx)
			return ErrQUICServerStartFailed{Cause: err}
		}
		d.logger.Info("QUIC server started successfully", "addr", d.quicServer.ListenAddr())
	}

	d.running.Store(true)

	// Attach overlay IPsec to charon behind the floor New installed.
	d.overlayIPsec.start()

	// Register configured services so ListServices returns them
	d.registerConfiguredServices()

	// Auto-start configured services
	go d.autoStartServices(ctx)

	// Mark daemon as ready
	d.service.MarkReady()

	return nil
}

// Stop gracefully stops the daemon
func (d *Daemon) Stop(ctx context.Context) error {
	if !d.running.Load() {
		return ErrDaemonNotRunning{}
	}

	// Report NOT_SERVING before anything is torn down, so a load balancer
	// probing grpc.health.v1.Health drains this node instead of watching
	// requests fail against a listener that is on its way out.
	if d.healthGRPCService != nil {
		d.healthGRPCService.Shutdown()
	}
	if d.verdictFeed != nil {
		d.verdictFeed.Close()
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Re-check under the lock: a concurrent Stop or ForceStop that won the
	// lock has already torn everything down, and running only flips to false
	// at the end of that teardown.
	if !d.running.Load() {
		return ErrDaemonNotRunning{}
	}

	// Close health registry
	if d.healthRegistry != nil {
		if err := d.healthRegistry.Close(); err != nil {
			d.logger.Warn("Health registry close failed", "error", err)
		}
	}

	// Stop QUIC server if running
	if d.quicServer != nil && d.quicServer.IsRunning() {
		d.logger.Info("Stopping QUIC server...")
		if err := d.quicServer.Stop(); err != nil {
			d.logger.Warn("QUIC server stop failed", "error", err)
		} else {
			d.logger.Info("QUIC server stopped")
		}
	}

	// Stop REST server if running
	if d.restServer != nil && d.restServer.IsRunning() {
		d.logger.Info("Stopping REST server...")
		if err := d.restServer.Stop(ctx); err != nil {
			d.logger.Warn("REST server stop failed", "error", err)
		} else {
			d.logger.Info("REST server stopped successfully")
		}
	}

	// Stop MCP server if running
	if d.mcpServer != nil && d.mcpServer.IsRunning() {
		d.logger.Info("Stopping MCP server...")
		if err := d.mcpServer.Stop(); err != nil {
			d.logger.Warn("MCP server stop failed", "error", err)
		} else {
			d.logger.Info("MCP server stopped successfully")
		}
	}

	// Stop tenant service if available
	if d.tenantService != nil {
		if err := d.tenantService.Stop(ctx); err != nil {
			d.logger.Warn("Tenant service stop failed", "error", err)
		}
	}

	// Stop IAM service if available
	if d.iamService != nil {
		if err := d.iamService.Stop(ctx); err != nil {
			d.logger.Warn("IAM service stop failed", "error", err)
		}
	}

	// Stop KMS service if available
	if d.kmsService != nil {
		if err := d.kmsService.Stop(ctx); err != nil {
			d.logger.Warn("KMS service stop failed", "error", err)
		}
	}

	// Detach overlay IPsec from charon; its fail-closed floor stays.
	d.overlayIPsec.stop()

	d.closeGatewayIPC()

	// Disconnect SDN service if available
	if d.sdnService != nil {
		_ = d.sdnService.Disconnect()
	}

	// Stop gRPC UDS server if running
	if d.grpcUDSServer != nil {
		d.logger.Info("Stopping gRPC UDS server...")
		d.grpcUDSServer.GracefulStop()
		if d.grpcUDSListener != nil {
			_ = d.grpcUDSListener.Close()
		}
		d.logger.Info("gRPC UDS server stopped")
	}

	// Stop gRPC TCP server if running
	if d.grpcServer != nil {
		d.grpcServer.GracefulStop()
		d.logger.Info("gRPC TCP server stopped")
	}
	if d.grpcListener != nil {
		_ = d.grpcListener.Close()
	}

	// Trigger shutdown through the service
	_, err := d.service.Shutdown(ctx, &platformv1.ShutdownRequest{
		Graceful:       true,
		TimeoutSeconds: uint32(d.config.ShutdownTimeout.Seconds()),
	})

	d.running.Store(false)
	return err
}

// forceStopTimeoutSeconds is the deadline ForceStop hands each service's
// Stop. A forced stop ignores the error a failed or expired Stop returns.
const forceStopTimeoutSeconds = 5

// ForceStop immediately stops the daemon
func (d *Daemon) ForceStop() error {
	if !d.running.Load() {
		return ErrDaemonNotRunning{}
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Re-check under the lock, as Stop does.
	if !d.running.Load() {
		return ErrDaemonNotRunning{}
	}

	// Close health registry
	if d.healthRegistry != nil {
		_ = d.healthRegistry.Close()
	}

	// Force stop QUIC server if running
	if d.quicServer != nil && d.quicServer.IsRunning() {
		_ = d.quicServer.Stop()
	}

	// Force stop REST server if running
	if d.restServer != nil && d.restServer.IsRunning() {
		_ = d.restServer.ForceStop()
	}

	// Force stop MCP server if running
	if d.mcpServer != nil && d.mcpServer.IsRunning() {
		_ = d.mcpServer.Stop()
	}

	// Stop tenant service if available
	if d.tenantService != nil {
		_ = d.tenantService.Stop(context.Background())
	}

	// Stop IAM service if available
	if d.iamService != nil {
		_ = d.iamService.Stop(context.Background())
	}

	// Stop KMS service if available
	if d.kmsService != nil {
		_ = d.kmsService.Stop(context.Background())
	}

	// Detach overlay IPsec from charon; its fail-closed floor stays.
	d.overlayIPsec.stop()

	d.closeGatewayIPC()

	// Disconnect SDN service if available
	if d.sdnService != nil {
		_ = d.sdnService.Disconnect()
	}

	// Force stop gRPC UDS server if running
	if d.grpcUDSServer != nil {
		d.grpcUDSServer.Stop()
	}
	if d.grpcUDSListener != nil {
		_ = d.grpcUDSListener.Close()
	}

	// Force stop gRPC TCP server if running
	if d.grpcServer != nil {
		d.grpcServer.Stop()
	}
	if d.grpcListener != nil {
		_ = d.grpcListener.Close()
	}

	// Force shutdown through the service
	_, _ = d.service.Shutdown(context.Background(), &platformv1.ShutdownRequest{
		Graceful:       false,
		TimeoutSeconds: forceStopTimeoutSeconds,
	})

	d.running.Store(false)
	return nil
}

// IsRunning returns whether the daemon is running
func (d *Daemon) IsRunning() bool {
	return d.running.Load()
}

// RegisterService registers a managed service
func (d *Daemon) RegisterService(svc ManagedService) error {
	return d.service.RegisterService(svc)
}

// Service returns the daemon service implementation for direct access
func (d *Daemon) Service() *Service {
	return d.service
}

// CAGRPCService returns the CA gRPC service for direct access.
// Returns nil if CA service is not configured.
func (d *Daemon) CAGRPCService() *CAGRPCService {
	return d.caService
}

// SetCAGRPCService sets the CA gRPC service.
// This allows external initialization of the CA service.
func (d *Daemon) SetCAGRPCService(svc *CAGRPCService) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.caService = svc
}

// SDNService returns the SDN service implementation for direct access
func (d *Daemon) SDNService() *SDNService {
	return d.sdnService
}

// KMSService returns the KMS service implementation for direct access
func (d *Daemon) KMSService() *KMSService {
	return d.kmsService
}

// KMSGRPCService returns the platform.v1 KeyManagementService implementation
// backed by the QuicBaaS SDK clients.
// Returns nil if the KMS service is not configured.
func (d *Daemon) KMSGRPCService() *grpccreds.KMSGRPCService {
	return d.kmsPlatformGRPC
}

// IAMService returns the IAM service implementation for direct access
func (d *Daemon) IAMService() *IAMService {
	return d.iamService
}

// TenantService returns the tenant service implementation for direct access
func (d *Daemon) TenantService() *TenantService {
	return d.tenantService
}

// VTPMServiceServer returns the vTPM gRPC service server for direct access.
// Returns nil if vTPM service is not configured.
func (d *Daemon) VTPMServiceServer() *VTPMServiceServer {
	return d.vtpmService
}

// DeviceGRPCService returns the device gRPC service for direct access.
// Returns nil if device service is not configured.
func (d *Daemon) DeviceGRPCService() *DeviceGRPCService {
	return d.deviceService
}

// SetDeviceGRPCService sets the device gRPC service.
// This allows external initialization of the device service.
func (d *Daemon) SetDeviceGRPCService(svc *DeviceGRPCService) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deviceService = svc
}

// ComputeGRPCService returns the compute gRPC service for direct access.
// Returns nil if compute service is not configured.
func (d *Daemon) ComputeGRPCService() *ComputeGRPCService {
	return d.computeService
}

// SetComputeGRPCService sets the compute gRPC service.
// This allows external initialization of the compute service.
func (d *Daemon) SetComputeGRPCService(svc *ComputeGRPCService) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.computeService = svc
}

// AttestationGRPCService returns the attestation gRPC service for direct access.
// Returns nil if attestation service is not configured.
func (d *Daemon) AttestationGRPCService() *AttestationServiceServer {
	return d.attestationService
}

// SetAttestationGRPCService sets the attestation gRPC service.
// This allows external initialization of the attestation service.
func (d *Daemon) SetAttestationGRPCService(svc *AttestationServiceServer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.attestationService = svc
}

// DBKeySigner returns the control-plane Secure Boot DB key signer backing the
// config delivery /provisioning/sign endpoint. It returns nil when no
// server-side KMS / CA is available to perform remote signing.
func (d *Daemon) DBKeySigner() configdelivery.DBKeySigner {
	return d.dbKeySigner
}

// ConfigDeliveryService returns the pre-enrollment config delivery service
// for direct access by other transports (QUIC, MCP, SDK). Returns nil when
// the service could not be constructed.
func (d *Daemon) ConfigDeliveryService() *configdelivery.Service {
	return d.configDeliveryService
}

// ConfigDeliveryGRPCService returns the platform.v1 ConfigDeliveryService
// gRPC implementation registered on the TCP and UDS gRPC servers.
func (d *Daemon) ConfigDeliveryGRPCService() *ConfigDeliveryGRPCService {
	return d.configDeliveryGRPC
}

// IDevIDGRPCService returns the IDevID gRPC service for direct access.
// Returns nil if IDevID service is not configured.
func (d *Daemon) IDevIDGRPCService() *IDevIDGRPCService {
	return d.idevidService
}

// SetIDevIDGRPCService sets the IDevID gRPC service.
// This allows external initialization of the IDevID service.
func (d *Daemon) SetIDevIDGRPCService(svc *IDevIDGRPCService) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.idevidService = svc
}

// TPMGRPCService returns the TPM gRPC service for direct access.
// Returns nil if TPM service is not configured.
func (d *Daemon) TPMGRPCService() *TPMGRPCService {
	return d.tpmService
}

// SetTPMGRPCService sets the TPM gRPC service.
// This allows external initialization of the TPM service.
// BarrierGRPCService returns the Barrier gRPC service for direct access.
// Returns nil if the barrier service is not configured.
func (d *Daemon) BarrierGRPCService() *BarrierGRPCService {
	return d.barrierService
}

func (d *Daemon) SetTPMGRPCService(svc *TPMGRPCService) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tpmService = svc
}

// EABGRPCService returns the EAB gRPC service backing /api/v1/eab.
// Returns nil if not configured.
func (d *Daemon) EABGRPCService() *EABGRPCService {
	return d.eabGRPCService
}

// InvitationGRPCService returns the Invitation gRPC service backing
// /api/v1/invitations. Returns nil if not configured.
func (d *Daemon) InvitationGRPCService() *InvitationGRPCService {
	return d.invitationGRPCService
}

// GatewayGRPCService returns the Gateway gRPC service backing /api/v1/gateway.
// Returns nil if not configured.
func (d *Daemon) GatewayGRPCService() *GatewayService {
	return d.gatewayGRPCService
}

// OverlayGRPCService returns the Overlay gRPC service backing /api/v1/overlay.
// Returns nil if not configured.
func (d *Daemon) OverlayGRPCService() *OverlayService {
	return d.overlayGRPCService
}

// DNSGRPCServiceServer returns the DNS gRPC service registered on the gRPC
// and Unix servers and the embedded transport. It is never nil; on a node
// without a DNS backend every handler answers not-configured.
func (d *Daemon) DNSGRPCServiceServer() *DNSServiceServer {
	return d.dnsGRPCService
}

// PXEGRPCServiceServer returns the PXE gRPC service backing /api/v1/pxe.
// Returns nil if not configured.
func (d *Daemon) PXEGRPCServiceServer() *PXEGRPCService {
	return d.pxeGRPCService
}

// NTPGRPCServiceServer returns the NTP gRPC service backing /api/v1/ntp.
// Returns nil if not configured.
func (d *Daemon) NTPGRPCServiceServer() *NTPGRPCService {
	return d.ntpGRPCService
}

// OrchestratorGRPCServiceServer returns the orchestrator gRPC service backing
// /api/v1/orchestrator. It is never nil once New returns.
func (d *Daemon) OrchestratorGRPCServiceServer() *OrchestratorGRPCService {
	return d.orchestratorGRPCService
}

// VPNGRPCServiceServer returns the VPN gRPC service backing /api/v1/vpn.
func (d *Daemon) VPNGRPCServiceServer() *VPNGRPCService {
	return d.vpnGRPCService
}

// VPNControlPlane returns the control-plane VPN service, or nil when the
// daemon runs without a platform store.
func (d *Daemon) VPNControlPlane() *vpn.Service {
	return d.vpnControlPlane
}

// TenantGRPCServer returns the Tenant gRPC server backing /api/v1/tenants.
// Returns nil if the tenant service is not configured or has not registered
// its gRPC server yet.
func (d *Daemon) TenantGRPCServer() *TenantGRPCServer {
	if d.tenantService == nil {
		return nil
	}
	return d.tenantService.grpcServer
}

// RESTServer returns the REST server for direct access.
// Returns nil if REST is not enabled or if a mock was injected.
func (d *Daemon) RESTServer() *RESTServer {
	return d.concreteRestServer
}

// IsRESTEnabled returns true if REST is enabled and the server is available
func (d *Daemon) IsRESTEnabled() bool {
	return d.config.EnableREST && d.restServer != nil
}

// RESTListenAddr returns the REST HTTP listen address.
// Returns empty string if REST is not enabled.
func (d *Daemon) RESTListenAddr() string {
	if !d.config.EnableREST {
		return ""
	}
	return d.config.RESTListenAddr
}

// MCPServer returns the MCP server for direct access.
// Returns nil if MCP is not enabled or if a mock was injected.
func (d *Daemon) MCPServer() *mcp.Server {
	return d.concreteMcpServer
}

// IsMCPEnabled returns true if MCP is enabled and the server is available
func (d *Daemon) IsMCPEnabled() bool {
	return d.config.EnableMCP && d.mcpServer != nil
}

// MCPListenAddr returns the MCP HTTP listen address.
// Returns empty string if MCP is not enabled or using stdio transport.
func (d *Daemon) MCPListenAddr() string {
	if d.config.MCPConfig == nil {
		return ""
	}
	if d.config.MCPConfig.Transport != "http" {
		return ""
	}
	return d.config.MCPConfig.HTTPAddr
}

// MCPServiceProvider returns the MCP service provider for direct access.
// Returns nil if MCP is not enabled.
func (d *Daemon) MCPServiceProvider() *MCPServiceProvider {
	return d.mcpProvider
}

// SetClusterService injects the platform cluster servicer behind every
// cluster transport: the registered gRPC ClusterService (TCP and Unix
// socket), which the REST /cluster routes, the QUIC cluster category and the
// MCP cluster tools all call.
// A nil svc clears it.
//
// NOTHING CALLS THIS IN PRODUCTION, in any build. There is no tagged
// wiring that constructs a *ClusterService and injects it here, so every
// cluster operation reports the service as not configured — with -tags
// cluster exactly as without it. Do not read the build tag as the
// difference. See #334.
func (d *Daemon) SetClusterService(svc ClusterServicer) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.clusterBackend != nil {
		d.clusterBackend.set(svc)
	}
}

// SetTPM2Service sets the TPM2 service across all protocol handlers.
// This injects the TPM2 service into REST, QUIC, MCP, gRPC TCP, and Unix socket handlers
// for IDevID/IAK operations.
//
// The TPM2 service provides all IDevID/IAK operations directly:
//   - CreateIAK, CreateIDevID, IAKAttributes, IDevIDAttributes
//   - ProvisionIDevIDCert, IDevIDCertificate, DeleteIDevIDCertificate
//   - ProvisionIAKCert, IAKCertificate, DeleteIAKCertificate
//   - DiscoverPlatformAttributes, ActivateCredential
func (d *Daemon) SetTPM2Service(svc xkmssdk.TrustedPlatformModule) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if svc == nil {
		return
	}

	d.tpm2Service = svc

	// Set on REST server if available (concrete server only)
	if d.concreteRestServer != nil {
		d.concreteRestServer.SetTPM2Service(svc)
		d.logger.Debug("TPM2 service set on REST server")
	}

	// Set on QUIC handler if available
	if d.quicHandler != nil {
		d.quicHandler.SetTPM2Service(svc)
		d.logger.Debug("TPM2 service set on QUIC handler")
	}

	// Set on MCP provider if available
	if d.mcpProvider != nil {
		d.mcpProvider.SetTPM2Service(svc)
		d.logger.Debug("TPM2 service set on MCP provider")
	}

	// Set on IDevID gRPC service if available
	if d.idevidService != nil {
		d.idevidService.SetTPM2Service(svc)
		d.logger.Debug("TPM2 service set on IDevID gRPC service")
	}

	// Set on TPM gRPC service if available
	if d.tpmService != nil {
		d.tpmService.SetTPM2Service(svc)
		d.logger.Debug("TPM2 service set on TPM gRPC service")
	}

	d.logger.Info("TPM2 service injected into all protocol handlers")
}

// TPM2Service returns the TPM2 service for direct access.
// Returns nil if TPM2 service is not configured.
func (d *Daemon) TPM2Service() xkmssdk.TrustedPlatformModule {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.tpm2Service
}

// QUICServer returns the QUIC server for external access.
// Returns nil if QUIC is not enabled or server creation failed.
func (d *Daemon) QUICServer() *quic.Server {
	// Type assert to get the concrete type if available
	if qs, ok := d.quicServer.(*quic.Server); ok {
		return qs
	}
	return nil
}

// QUICServiceHandler returns the QUIC service handler for external access.
// Returns nil if QUIC is not enabled.
func (d *Daemon) QUICServiceHandler() *QUICServiceHandler {
	return d.quicHandler
}

// IsQUICEnabled returns true if QUIC is enabled and the server was created successfully
func (d *Daemon) IsQUICEnabled() bool {
	return d.config.EnableQUIC && d.quicServer != nil
}

// QUICListenAddr returns the QUIC listen address
func (d *Daemon) QUICListenAddr() string {
	if d.quicServer != nil {
		return d.quicServer.ListenAddr()
	}
	return d.config.QUICListenAddr
}

// SocketPath returns the path to the gRPC Unix Domain Socket
func (d *Daemon) SocketPath() string {
	return d.config.GRPCSocketPath
}

// GRPCListenAddr returns the gRPC TCP listen address
func (d *Daemon) GRPCListenAddr() string {
	return d.config.GRPCListenAddr
}

// GRPCServer returns the gRPC TCP server for external service registration.
// Returns nil if gRPC TCP is not enabled.
func (d *Daemon) GRPCServer() *grpc.Server {
	if wrapper, ok := d.grpcServer.(*grpcServerWrapper); ok {
		return wrapper.Unwrap()
	}
	return nil
}

// GRPCUDSServer returns the gRPC Unix Domain Socket server for external service registration.
// Returns nil if gRPC UDS is not enabled.
func (d *Daemon) GRPCUDSServer() *grpc.Server {
	return d.concreteGrpcUDSServer
}

// GRPCSocketPath returns the gRPC Unix Domain Socket path.
// Returns empty string if gRPC UDS is not enabled.
func (d *Daemon) GRPCSocketPath() string {
	if !d.config.EnableGRPCUDS {
		return ""
	}
	return d.config.GRPCSocketPath
}

// IsGRPCUDSEnabled returns true if gRPC UDS is enabled and the server was created successfully
func (d *Daemon) IsGRPCUDSEnabled() bool {
	return d.config.EnableGRPCUDS && d.grpcUDSServer != nil
}

// IsGRPCTCPEnabled returns true if gRPC TCP is enabled
func (d *Daemon) IsGRPCTCPEnabled() bool {
	return d.config.EnableGRPCTCP && d.grpcServer != nil
}

// registerConfiguredServices registers a subsystemService for each enabled
// entry in d.config.Services that names a platform subsystem, making it
// visible via ListServices on every protocol (gRPC, REST, CLI, QUIC, MCP,
// Unix). Its status is the subsystem's real state; start, stop and restart
// are refused with ErrServiceNotControllable because platformd owns the
// subsystem's lifecycle.
func (d *Daemon) registerConfiguredServices() {
	for name, cfg := range d.config.Services {
		if !cfg.Enabled {
			continue
		}
		// Only register services that have a valid protobuf ServiceType mapping.
		// Services without mappings (e.g., kms, vtpm, ca, mcp) cannot be
		// managed through gRPC/CLI which require ServiceType enum values.
		svcType := serviceTypeFromName(name)
		spec, known := subsystemSpecs[svcType]
		if !known {
			continue
		}
		svc := &subsystemService{
			name:    name,
			reason:  spec.reason,
			running: d.subsystemProbe(svcType, spec),
		}
		if err := d.RegisterService(svc); err != nil {
			d.logger.Warn("Failed to register configured service", "service", name, "error", err)
		}
	}
}

// subsystemProbe returns how a configured subsystem's state is observed.
// Start calls it with d.mu held, so a daemon-built subsystem's wiring is read
// once here. The returned probe never takes d.mu: Stop holds that lock while
// it drains in-flight status RPCs, which call the probe.
func (d *Daemon) subsystemProbe(svcType platformv1.ServiceType, spec subsystemSpec) func() bool {
	if spec.wired == nil {
		return func() bool {
			probe, ok := d.subsystemProbes.Load(svcType)
			if !ok {
				return false
			}
			running, ok := probe.(func() bool)
			return ok && running()
		}
	}
	wired := spec.wired(d)
	return func() bool { return wired }
}

// SetSubsystemProbe reports the live state of a subsystem the composition
// root runs outside the daemon: the web services and the ACME server they
// carry. Until a probe is set, or after a nil one, the subsystem reports
// stopped.
func (d *Daemon) SetSubsystemProbe(svcType platformv1.ServiceType, running func() bool) {
	if running == nil {
		d.subsystemProbes.Delete(svcType)
		return
	}
	d.subsystemProbes.Store(svcType, running)
}

// autoStartServices starts services configured for auto-start
func (d *Daemon) autoStartServices(ctx context.Context) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.onAutoStart != nil {
		defer d.onAutoStart()
	}

	// Start launches this pass in a goroutine, so a Stop can take the lock
	// first. Starting services on a daemon that has already stopped would
	// leave them running with nothing left to stop them.
	if !d.running.Load() {
		return
	}

	for name, svcConfig := range d.config.Services {
		if !svcConfig.Enabled || !svcConfig.AutoStart {
			continue
		}

		// Check if service is registered and get the state
		d.service.mu.RLock()
		state, exists := d.service.services[name]
		d.service.mu.RUnlock()

		if !exists {
			continue
		}
		// A process-owned subsystem came up with the process; there is
		// nothing to start, and its refusal is not a failure.
		if _, owned := processOwned(state.service); owned {
			continue
		}

		// Start the service directly using the state
		state.mu.Lock()
		if state.observedStatus() == platformv1.ServiceStatus_SERVICE_STATUS_RUNNING {
			state.mu.Unlock()
			continue
		}

		state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_STARTING))
		state.lastError = ""

		if err := state.service.Start(ctx); err != nil {
			state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_ERROR))
			state.lastError = err.Error()
			d.logger.Warn("Auto-start service failed", "service", name, "error", err)
			state.mu.Unlock()
			continue
		}

		state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_RUNNING))
		state.startedAt = time.Now()
		state.startCount.Add(1)
		state.mu.Unlock()

		d.logger.Info("Auto-started service", "service", name)
	}
}

// stopServers stops all server components
func (d *Daemon) stopServers() error {
	// Stop gRPC UDS server if running
	if d.grpcUDSServer != nil {
		d.grpcUDSServer.GracefulStop()
		if d.grpcUDSListener != nil {
			_ = d.grpcUDSListener.Close()
		}
	}

	// Stop gRPC TCP server if running
	if d.grpcServer != nil {
		d.grpcServer.GracefulStop()
	}
	if d.grpcListener != nil {
		_ = d.grpcListener.Close()
	}

	return nil
}

// HealthRegistry returns the health registry for direct access.
// Returns nil if health checking is not configured.
func (d *Daemon) HealthRegistry() health.Registry {
	return d.healthRegistry
}

// HealthCheck performs a system-wide health check using the health registry.
// Returns the aggregated health status of all registered components.
func (d *Daemon) HealthCheck(ctx context.Context) (*health.SystemHealth, error) {
	if d.healthRegistry == nil {
		return nil, ErrHealthRegistryNotConfigured{}
	}
	result := d.healthRegistry.Check(ctx)
	return &result, nil
}

// HealthCheckComponent performs a health check on a specific component.
// Returns the health status of the named component.
func (d *Daemon) HealthCheckComponent(ctx context.Context, name string) (*health.ComponentHealth, error) {
	if d.healthRegistry == nil {
		return nil, ErrHealthRegistryNotConfigured{}
	}
	result, err := d.healthRegistry.CheckComponent(ctx, name)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// RegisterHealthChecker registers a custom health checker with the daemon.
// This allows external components to participate in health checks.
func (d *Daemon) RegisterHealthChecker(checker health.HealthChecker) error {
	if d.healthRegistry == nil {
		return ErrHealthRegistryNotConfigured{}
	}
	return d.healthRegistry.Register(checker)
}

// registerHealthCheckers registers health checkers for all available services.
func (d *Daemon) registerHealthCheckers() {
	if d.healthRegistry == nil {
		return
	}

	// Register CA service health checker if available
	if d.caService != nil {
		checker := NewCAServiceHealthChecker(d.caService)
		if checker != nil {
			if err := d.healthRegistry.Register(checker); err != nil {
				d.logger.Warn("Failed to register CA health checker", "error", err)
			}
		}
	}

	// Register SDN service health checker if available
	if d.sdnService != nil {
		checker := NewSDNServiceHealthChecker(d.sdnService)
		if checker != nil {
			if err := d.healthRegistry.Register(checker); err != nil {
				d.logger.Warn("Failed to register SDN health checker", "error", err)
			}
		}
	}

	// Register the time-synchronization health checker. A node that boots
	// past the startup gate unsynchronized stays visible here instead of
	// silently corrupting attestation, ACME, DANE, and JWT validity.
	if d.ntpGRPCService != nil && d.ntpGRPCService.Backend() != nil {
		checker := NewNTPServiceHealthChecker(d.ntpGRPCService.Backend())
		if checker != nil {
			if err := d.healthRegistry.Register(checker); err != nil {
				d.logger.Warn("Failed to register NTP health checker", "error", err)
			}
		}
	}

	// Register KMS service health checker if available
	if d.kmsService != nil {
		checker := NewKMSServiceHealthChecker(d.kmsService)
		if checker != nil {
			if err := d.healthRegistry.Register(checker); err != nil {
				d.logger.Warn("Failed to register KMS health checker", "error", err)
			}
		}
	}

	// Register IAM service health checker if available
	if d.iamService != nil {
		checker := NewIAMServiceHealthChecker(d.iamService)
		if checker != nil {
			if err := d.healthRegistry.Register(checker); err != nil {
				d.logger.Warn("Failed to register IAM health checker", "error", err)
			}
		}
	}

	// Register tenant service health checker if available
	if d.tenantService != nil {
		checker := NewTenantServiceHealthChecker(d.tenantService)
		if checker != nil {
			if err := d.healthRegistry.Register(checker); err != nil {
				d.logger.Warn("Failed to register tenant health checker", "error", err)
			}
		}
	}

	// Register QUIC server health checker if available
	if d.quicServer != nil {
		// Type assert to get the concrete type for health checker
		if qs, ok := d.quicServer.(*quic.Server); ok {
			checker := NewQUICServerHealthChecker(qs)
			if checker != nil {
				if err := d.healthRegistry.Register(checker); err != nil {
					d.logger.Warn("Failed to register QUIC health checker", "error", err)
				}
			}
		}
	}

	// Register REST server health checker if available
	if d.concreteRestServer != nil {
		checker := NewRESTServiceHealthChecker(d.concreteRestServer)
		if checker != nil {
			if err := d.healthRegistry.Register(checker); err != nil {
				d.logger.Warn("Failed to register REST health checker", "error", err)
			}
		}
	}

	// Register the bridge-addressing health checker. A node that refused a
	// configured bridge address because another station already answered
	// for it stays visible here (#508) instead of looking healthy while an
	// address it was supposed to own is missing from the wire.
	if d.config != nil && d.config.App != nil {
		checker := NewSDNAddressingHealthChecker(d.config.App)
		if checker != nil {
			if err := d.healthRegistry.Register(checker); err != nil {
				d.logger.Warn("Failed to register SDN addressing health checker", "error", err)
			}
		}
	}

	// Register MCP server health checker if available
	if d.concreteMcpServer != nil {
		checker := NewMCPServiceHealthChecker(d.concreteMcpServer)
		if checker != nil {
			if err := d.healthRegistry.Register(checker); err != nil {
				d.logger.Warn("Failed to register MCP health checker", "error", err)
			}
		}
	}

	d.logger.Info("Health checkers registered", "count", d.healthRegistry.Count())
}

// CeremonyService returns the Ceremony gRPC service, or nil when not wired.
func (d *Daemon) CeremonyService() *CeremonyGRPCService {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.ceremonyService
}

// SetCeremonyBackend wires a backend into the ceremony service. Passing nil
// is a no-op so tests and partial wirings do not accidentally clear an
// already-configured backend.
func (d *Daemon) SetCeremonyBackend(b CeremonyBackend) {
	d.mu.RLock()
	svc := d.ceremonyService
	d.mu.RUnlock()
	if svc == nil || svc.service == nil || b == nil {
		return
	}
	svc.service.SetBackend(b)
	d.logger.Info("Ceremony backend wired")
}

// PIVService returns the PIV gRPC service, or nil when not wired.
func (d *Daemon) PIVService() *PIVGRPCService {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.pivService
}

// SwitchService returns the Switch gRPC service, or nil when not wired.
func (d *Daemon) SwitchService() *SwitchGRPCService {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.switchGRPCService
}

// BMCService returns the BMC gRPC service, or nil when not wired.
func (d *Daemon) BMCService() *BMCGRPCService {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.bmcGRPCService
}

// SetPIVBackend wires a backend into the PIV service.
func (d *Daemon) SetPIVBackend(b PIVBackend) {
	d.mu.RLock()
	svc := d.pivService
	d.mu.RUnlock()
	if svc == nil || svc.service == nil || b == nil {
		return
	}
	svc.service.SetBackend(b)
	d.logger.Info("PIV backend wired")
}

// LUKSService returns the LUKS gRPC service, or nil when not wired.
func (d *Daemon) LUKSService() *LUKSGRPCService {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.luksService
}

// SetLUKSBackend wires a backend into the LUKS service.
func (d *Daemon) SetLUKSBackend(b LUKSBackend) {
	d.mu.RLock()
	svc := d.luksService
	d.mu.RUnlock()
	if svc == nil || svc.service == nil || b == nil {
		return
	}
	svc.service.SetBackend(b)
	d.logger.Info("LUKS backend wired")
}

// SetLUKSRootChecker replaces the LUKS root checker. The default checker
// always reports non-root, so installations that run as root must inject a
// real checker (for example RootCheckerFunc(func() bool { return os.Geteuid() == 0 })).
func (d *Daemon) SetLUKSRootChecker(rc RootChecker) {
	d.mu.RLock()
	svc := d.luksService
	d.mu.RUnlock()
	if svc == nil || svc.service == nil || rc == nil {
		return
	}
	svc.service.mu.Lock()
	svc.service.root = rc
	svc.service.mu.Unlock()
}

// FIDO2Service returns the FIDO2 gRPC service, or nil when not wired.
func (d *Daemon) FIDO2Service() *FIDO2GRPCService {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.fido2Service
}

// SetFIDO2Backend wires a backend into the FIDO2 service.
func (d *Daemon) SetFIDO2Backend(b FIDO2Backend) {
	d.mu.RLock()
	svc := d.fido2Service
	d.mu.RUnlock()
	if svc == nil || svc.service == nil || b == nil {
		return
	}
	svc.service.SetBackend(b)
	d.logger.Info("FIDO2 backend wired")
}

// deviceAKTrust returns the platform CA as the trust anchor for device
// attestation certificates, or nil when no CA is configured so that device
// quotes fail closed rather than chain against nothing.
func deviceAKTrust(config *Config) AKTrustAnchor {
	if config == nil || config.CAService == nil {
		return nil
	}
	return config.CAService
}

// deviceVerdictSink returns the attestation service as the sink for device
// quote verdicts when it implements one; verdicts are otherwise only logged.
func deviceVerdictSink(config *Config) verdict.Sink {
	if config == nil || config.AttestationService == nil {
		return nil
	}
	sink, ok := config.AttestationService.(verdict.Sink)
	if !ok {
		return nil
	}
	return sink
}
