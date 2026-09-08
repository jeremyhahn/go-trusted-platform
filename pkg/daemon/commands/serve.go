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

package commands

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	noiseapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/noise"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	_ "github.com/jeremyhahn/go-trusted-platform/pkg/compute/container" // registers the local-container orchestrator factory
	"github.com/jeremyhahn/go-trusted-platform/pkg/log/jsonfile"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
	platformrest "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/platform"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/spf13/cobra"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	certclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/certificate"
	acmequicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/acme/storage/quicbaas"
	platformquicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

var (
	serveSocketPath string
	serveRESTPort   int
	serveGRPCPort   int
	serveQUICPort   int
	serveMCPPort    int
	serveEnableREST bool
	serveEnableGRPC bool
	serveEnableQUIC bool
	serveEnableMCP  bool
	serveSkipIAM    bool
	serveEnableMTLS bool
)

func init() {
	serveCmd.Flags().StringVar(&serveSocketPath, "socket-path", "/run/platformd.sock", "Unix socket path")
	serveCmd.Flags().IntVar(&serveRESTPort, "rest-port", 8443, "REST API port")
	serveCmd.Flags().IntVar(&serveGRPCPort, "grpc-port", 10443, "gRPC port")
	serveCmd.Flags().IntVar(&serveQUICPort, "quic-port", 9444, "QUIC port")
	serveCmd.Flags().IntVar(&serveMCPPort, "mcp-port", 9445, "MCP port")
	serveCmd.Flags().BoolVar(&serveEnableREST, "enable-rest", true, "Enable REST API (daemon-only mode: requires --enable-mtls, its only authentication; refused otherwise)")
	serveCmd.Flags().BoolVar(&serveEnableGRPC, "enable-grpc", true, "Enable gRPC")
	serveCmd.Flags().BoolVar(&serveEnableQUIC, "enable-quic", true, "Enable QUIC")
	serveCmd.Flags().BoolVar(&serveEnableMCP, "enable-mcp", true, "Enable MCP")
	serveCmd.Flags().BoolVar(&serveSkipIAM, "skip-iam-validation", false, "Skip IAM validation (testing only)")
	serveCmd.Flags().BoolVar(&serveEnableMTLS, "enable-mtls", false, "Enable mutual TLS authentication")
}

// =============================================================================
// CA helper interfaces (M5: SDK-only dependency)
// =============================================================================
//
// These minimal interfaces let serve.go consume the platform CA without
// importing go-xkms types. Any value that satisfies the methods we actually
// use (App.CA does) can be threaded through. The SDK-only dependency rule
// (08-bootstrap-auth-architecture.md §5d) requires that pkg/daemon never
// references go-xkms directly; pkg/app keeps that bridge so the daemon can
// stay portable.

// tcgEnrollmentCA is the minimal CA surface required by the enroll-01
// challenge verifier: TCG MakeCredential challenge generation plus the CA's
// default signature algorithm.
type tcgEnrollmentCA interface {
	VerifyTCG_CSR_IDevIDBytes(packedCSR []byte, sigAlg x509.SignatureAlgorithm) ([]byte, []byte, []byte, error)
	DefaultSignatureAlgorithm() x509.SignatureAlgorithm
}

// caTrustPoolProvider is the minimal CA surface required to populate the
// mTLS client trust pool. App.CA satisfies this surface natively.
type caTrustPoolProvider interface {
	CABundleCertPool() (*x509.CertPool, error)
}

// =============================================================================
// daemonSANs / daemonServerSANs (used by provisionDaemonIdentity)
// =============================================================================

// daemonSANs carries the Subject Alternative Names baked into the daemon's
// gRPC TCP / QUIC server certificate. Loopback names are added by the
// issuer; this struct holds the additional platform-facing identities so
// remote platformctl invocations can verify the daemon by FQDN or IP.
type daemonSANs struct {
	DNS []string
	IPs []string
}

// daemonServerSANs derives the platform-facing DNS / IP SANs to attach to
// the daemon's TLS server certificate from the running App. The host's
// short hostname and FQDN (hostname.domain) are always included; the
// caller's external interface IPs and any "internal" webservice hostnames
// are added when discoverable. Empty values are skipped.
func daemonServerSANs(a *app.App) daemonSANs {
	if a == nil {
		return daemonSANs{}
	}
	var sans daemonSANs
	seen := map[string]struct{}{}
	addDNS := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		sans.DNS = append(sans.DNS, name)
	}
	addDNS(a.Hostname)
	if a.Domain != "" {
		addDNS(a.Hostname + "." + a.Domain)
		addDNS(a.Domain)
	}
	for _, ws := range a.WebServices {
		if ws == nil {
			continue
		}
		addDNS(ws.Certificate.Subject.CommonName)
		for _, dns := range ws.Certificate.SANS.DNS {
			addDNS(dns)
		}
	}
	if ws := a.WebServiceConfig; ws != nil {
		addDNS(ws.Certificate.Subject.CommonName)
		for _, dns := range ws.Certificate.SANS.DNS {
			addDNS(dns)
		}
	}
	addrs, _ := net.InterfaceAddrs()
	ipSeen := map[string]struct{}{}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		s := ip.String()
		if _, ok := ipSeen[s]; ok {
			continue
		}
		ipSeen[s] = struct{}{}
		sans.IPs = append(sans.IPs, s)
	}
	return sans
}

// =============================================================================
// ACME challenge wiring
// =============================================================================

// buildChallengeMap creates a challenge verifier map from configured
// challenge types. Each challenge type (e.g., "http-01", "dns-01",
// "enroll-01") is mapped to its corresponding verifier function that
// performs the ACME challenge validation.
func buildChallengeMap(challenges []string, ca tcgEnrollmentCA) map[string]quicbaassdk.ACMEChallengeVerifierFunc {
	challengeMap := make(map[string]quicbaassdk.ACMEChallengeVerifierFunc)

	for _, challengeType := range challenges {
		switch challengeType {
		case "http-01":
			challengeMap["http-01"] = func(resolver *net.Resolver, caInterface quicbaassdk.ACMECertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
				return quicbaassdk.ACMEVerifyHTTP01(resolver, authzValue, challengePort, challengeToken, expectedKeyAuth)
			}
		case "dns-01":
			challengeMap["dns-01"] = func(resolver *net.Resolver, caInterface quicbaassdk.ACMECertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
				return quicbaassdk.ACMEVerifyDNS01(resolver, authzValue, challengePort, challengeToken, expectedKeyAuth)
			}
		case "enroll-01":
			challengeMap["enroll-01"] = func(resolver *net.Resolver, caInterface quicbaassdk.ACMECertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
				return quicbaassdk.ACMEVerifyEnroll01(resolver, ca, authzValue, challengePort, challengeToken, expectedKeyAuth)
			}
		case "endorse-01":
			// endorse-01 is used to provision EK certificates for TPMs without manufacturer certs.
			// Verification is handled by EAB and server policy, so the verifier returns nil.
			challengeMap["endorse-01"] = func(resolver *net.Resolver, caInterface quicbaassdk.ACMECertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
				return quicbaassdk.ACMEVerifyEndorse01(resolver, authzValue, challengePort, challengeToken, expectedKeyAuth)
			}
		}
	}

	return challengeMap
}

// =============================================================================
// applyDaemonTLSIdentity
// =============================================================================

// newComputeOrchestrator constructs the consolidated container compute
// orchestrator (pkg/compute/container.ComputeOrchestrator). The rich engine
// contributes TPM attestation, OPA policy, image verification, and log
// access; the compute surface contributes OVS networking and 802.1X port
// authentication. When the host TPM is available, container workload
// measurement and quote attestation are enabled; otherwise the orchestrator
// runs without attestation (Attest returns a typed error). OVS networking is
// enabled only when the OVS socket was detected (ovsSocketPath non-empty),
// mirroring the SDN service gating.
func newComputeOrchestrator(logger *logging.Logger, a *app.App, ovsSocketPath string, vtpmSvc vtpm.VTPMService) (compute.Orchestrator, error) {
	computeConfig := &compute.OrchestratorConfig{
		Type:            compute.ComputeTypeContainer,
		MaxInstances:    100,
		Debug:           InitParams.Debug,
		WorkDir:         "/var/lib/platformd/compute",
		DefaultMemory:   512,
		DefaultCPUs:     1,
		DefaultDiskSize: "10G",
		OVSSocketPath:   ovsSocketPath,
	}

	// Provider selection is explicit: operators opt into a cloud provider via
	// the `compute:` config section. When unset, Provider is empty and the
	// factory resolves to the local container orchestrator, preserving the
	// historical default so nothing breaks. Naming a cloud provider whose
	// build tag was not compiled in fails closed with a typed
	// compute.ErrComputeProviderNotCompiled.
	if a != nil && a.ComputeConfig != nil {
		computeConfig.Provider = a.ComputeConfig.Provider
		computeConfig.AWS = a.ComputeConfig.AWS
		computeConfig.GCP = a.ComputeConfig.GCP
		computeConfig.Azure = a.ComputeConfig.Azure
	}

	// When the operator selects the local QEMU/VM provider, switch the
	// orchestrator configuration to VM and fill the QEMU/OVMF fields the QEMU
	// orchestrator requires. This is config-gated (default stays container, so
	// nothing breaks) per the explicit-config rule.
	if computeConfig.Provider.IsVM() {
		computeConfig.ApplyLocalQEMUDefaults()
		if a != nil && a.ComputeConfig != nil {
			if a.ComputeConfig.QEMUBinary != "" {
				computeConfig.QEMUBinary = a.ComputeConfig.QEMUBinary
			}
			if a.ComputeConfig.OVMFCode != "" {
				computeConfig.OVMFCode = a.ComputeConfig.OVMFCode
			}
			if a.ComputeConfig.OVMFCodeSecure != "" {
				computeConfig.OVMFCodeSecure = a.ComputeConfig.OVMFCodeSecure
			}
			if a.ComputeConfig.OVMFVars != "" {
				computeConfig.OVMFVars = a.ComputeConfig.OVMFVars
			}
			if a.ComputeConfig.WorkDir != "" {
				computeConfig.WorkDir = a.ComputeConfig.WorkDir
			}
			if a.ComputeConfig.NetworkBridge != "" {
				computeConfig.NetworkBridge = a.ComputeConfig.NetworkBridge
			}
			if a.ComputeConfig.EnableKVM {
				computeConfig.EnableKVM = true
			}
			if a.ComputeConfig.DefaultMemory > 0 {
				computeConfig.DefaultMemory = a.ComputeConfig.DefaultMemory
			}
			if a.ComputeConfig.DefaultCPUs > 0 {
				computeConfig.DefaultCPUs = a.ComputeConfig.DefaultCPUs
			}
		}

		// Wire the inter-daemon VM migration seams for the local QEMU provider.
		// Both are backed by the platform CA (reached through the QuicBaaS SDK):
		// the coordinator dials peer daemons over mTLS to drive the prepare/
		// finalize handshake, and the TLS provider issues the short-lived
		// migration tls-creds. Both constructors return nil for a nil CA, so
		// MigrateVM stays gated (ErrMigration*NotConfigured) until a CA exists;
		// the explicit non-nil guards avoid storing a typed-nil interface.
		if a != nil && a.CA != nil {
			if coord := newGRPCMigrationCoordinator(a.CA, logger); coord != nil {
				computeConfig.MigrationCoordinator = coord
			}
			if tlsProv := newCAMigrationTLS(a.CA, filepath.Join(computeConfig.WorkDir, "migration-tls"), logger); tlsProv != nil {
				computeConfig.MigrationTLS = tlsProv
			}
		}
	}

	deps := &compute.Deps{Logger: logger}
	if a != nil {
		deps.HostTPM = a.TPM
	}
	if vtpmSvc != nil {
		gen, genErr := vtpm.NewGenerator(nil, vtpmSvc, logger)
		if genErr != nil {
			logger.Warn("failed to construct vTPM generator for compute; VMs fall back to identity-less swtpm unless their profile requires an identity", "error", genErr)
		} else {
			deps.VTPMGenerator = gen
		}
	}

	return compute.NewOrchestratorForConfig(context.Background(), computeConfig, deps)
}

// applyDaemonTLSIdentity provisions the daemon's mTLS material via the
// quicbaas SDK CertificateService and binds it to the supplied
// daemon.Config so that gRPC TCP, QUIC and REST listeners present a
// CA-signed server certificate (and optionally require client mTLS).
//
// Both runDaemonOnly and runWithWebservices call this helper so the gRPC
// TCP listener never falls back to plaintext when webservices are enabled.
// The provisioner reuses on-disk bundles when valid, otherwise issues
// fresh ones; on issuance failure the daemon continues without a server
// cert (the gRPC listener will start without TLS, surfacing the error to
// remote clients) so the platform stays observable rather than failing
// to come up entirely.
// seedSDNVLANsFromConfig walks app.SDNConfig.Networks (already derived
// from installer subnets that carry a vlan-id) and calls SeedVLAN on
// the running SDN service for each one. The bridge name + UUID come
// from the live OVS state so the seeded entries link back to the
// actual bridge the operator's bond materialized.
//
// SeedVLAN registers the VLAN in the in-memory map only; port-tag
// application still happens via CreateVLAN or a future controller.
// This shortest-path reconciliation makes the Networking → VLANs page
// non-empty after a deploy, which is what operators expect when they
// declared `vlan-id: 200` in their config.
func seedSDNVLANsFromConfig(logger *logging.Logger, a *app.App, sdnSvc *daemon.SDNService) {
	if a == nil || sdnSvc == nil {
		return
	}
	if a.SDNConfig == nil || len(a.SDNConfig.Networks) == 0 {
		return
	}

	// Look up the configured OVS bridge. The platform's installer
	// always materializes exactly one OVS bridge per node (a.SDNConfig
	// .OVS.Bridge), so we don't need to round-trip OVS to enumerate.
	bridgeName := ""
	if a.SDNConfig.OVS != nil {
		bridgeName = a.SDNConfig.OVS.Bridge
	}
	if bridgeName == "" {
		logger.Warn("SDN VLAN seeding skipped: no OVS bridge configured")
		return
	}

	// Pull the live bridges so we know the UUID to attach VLANs to.
	listResp, err := sdnSvc.ListBridges(context.Background(), &platformv1.ListBridgesRequest{})
	if err != nil {
		logger.Warn("SDN VLAN seeding: failed to list bridges",
			"error", err)
		return
	}
	var bridgeID string
	for _, b := range listResp.GetBridges() {
		if b.GetConfig().GetName() == bridgeName {
			bridgeID = b.GetId()
			break
		}
	}
	if bridgeID == "" {
		logger.Warn("SDN VLAN seeding: configured bridge not found in OVS",
			"bridge", bridgeName)
		return
	}

	for _, net := range a.SDNConfig.Networks {
		if net.VLAN == 0 {
			continue
		}
		if _, err := sdnSvc.SeedVLAN(bridgeName, bridgeID, uint32(net.VLAN), net.Name); err != nil {
			logger.Warn("SDN VLAN seeding: SeedVLAN failed",
				"subnet", net.Name, "vlan", net.VLAN, "error", err)
			continue
		}
		logger.Info("SDN VLAN seeded from config",
			"subnet", net.Name, "vlan", net.VLAN, "bridge", bridgeName)
	}
}

// initVTPMServiceOnConfig populates cfg.VTPMService from App.VTPMConfig,
// defaulting to a fresh &vtpm.Config{} when no explicit `vtpm:` block is
// present in config.yaml. vtpm.Config.ApplyDefaults fills BaseDir
// (/var/lib/trusted-platform/vtpm) so the surface no longer requires
// operator boilerplate to be reachable.
//
// Both runWithWebservices and runDaemonOnly call this. The webservices
// path used to leave cfg.VTPMService nil, which the REST router (lines
// 821-823) then read back as nil — surfacing as a permanently dark
// /api/v1/vtpm/* surface even though the service + handlers + SDK
// methods were all in tree.
func initVTPMServiceOnConfig(logger *logging.Logger, a *app.App, cfg *daemon.Config) {
	if a == nil || cfg == nil {
		return
	}
	if cfg.VTPMService != nil {
		// Already wired (e.g. test injection). Don't clobber.
		return
	}
	vtpmCfg := a.VTPMConfig
	if vtpmCfg == nil {
		vtpmCfg = &vtpm.Config{}
	}
	vtpmCfg.ApplyDefaults()
	// Wire the platform TCG CA (reached through the QuicBaaS SDK as a.CA) so
	// profile-bound pre-assigned bundles receive a TCG-conformant EK
	// certificate from the same issuer as physical-TPM endorsement
	// (app.CA.IssueEKCertificate). newVTPMCAAdapter returns a nil interface
	// when a.CA is unset, keeping the service fail-closed: bundles still get
	// profile binding and EK-cert injection is simply skipped.
	vtpmCA := newVTPMCAAdapter(a.CA)
	svc, err := vtpm.NewService(vtpmCfg, logger, vtpmCA)
	if err != nil {
		logger.Warn("vTPM service creation failed (vTPM operations will fail)",
			"error", err)
		return
	}
	cfg.VTPMService = svc
	logger.Info("vTPM service initialized",
		"base_dir", vtpmCfg.BaseDir,
		"ek_ca_wired", vtpmCA != nil)
}

func applyDaemonTLSIdentity(ctx context.Context, logger *logging.Logger, a *app.App, cfg *daemon.Config, requireClientCert bool) error {
	// Fail closed (#32): a daemon that will terminate TLS on a network
	// transport either gets a provisioned identity or refuses to start.
	// The one carve-out is Unix-domain-socket-only mode — filesystem-
	// permission-scoped, not network-exposed — which needs no identity.
	if cfg != nil && !cfg.EnableGRPCTCP && !cfg.EnableQUIC && !cfg.EnableREST {
		logger.Info("Daemon TLS identity skipped: no TLS-terminating transport enabled (UDS-only mode)")
		return nil
	}
	switch {
	case a == nil:
		return ErrTLSIdentityRequiresApp{}
	case cfg == nil:
		return ErrTLSIdentityRequiresConfig{}
	case a.CA == nil:
		return ErrProvisionMissingCA{}
	}
	mtlsDir := "/tmp/platformd-integration/tls"
	if mkErr := os.MkdirAll(mtlsDir, 0700); mkErr != nil {
		return ErrProvisionPersist{Path: mtlsDir, Cause: mkErr}
	}
	// Prefer the SDK-based issuer (matches the documented architecture
	// where all cert issuance flows through QuicBaaS), but fall back to
	// the local CA when the embedded transport doesn't register a
	// Certificate service. This keeps daemon TLS bootstrap working in
	// the current stack where the platform CA is loaded in-process but
	// QuicBaaS Certificate is not yet wired into embedded.
	var issuer = newSDKCertIssuer(a.QuicBaaSSDKClient())
	if localIssuer := newLocalCACertIssuer(a.CA); localIssuer != nil {
		issuer = localIssuer
	}
	identity, mtlsErr := provisionDaemonIdentity(ctx, logger, issuer, a.CA, mtlsDir, daemonServerSANs(a))
	if mtlsErr != nil {
		return mtlsErr
	}
	if identity == nil {
		// provisionDaemonIdentity returning (nil, nil) is an internal
		// contract violation; treat it as a missing identity, not success.
		return ErrProvisionIssue{Role: "server", Cause: ErrTLSIdentityNotProvisioned{}}
	}
	cfg.TLSCertificate = &identity.ServerCert
	cfg.MTLSClientCAPool = identity.AdminTrustPool
	cfg.MTLSClientCAFile = identity.CABundlePath
	if cfg.QUICConfig != nil && cfg.QUICConfig.TLSConfig != nil {
		cfg.QUICConfig.TLSConfig.Certificates = []tls.Certificate{identity.ServerCert}
	}
	cfg.EnableMTLS = requireClientCert
	logger.Info("Daemon TLS identity provisioned",
		"server_bundle", identity.ServerBundlePath,
		"admin_bundle", identity.AdminBundlePath,
		"ca_bundle", identity.CABundlePath,
		"client_cert_required", requireClientCert,
		"reused", identity.Reused,
	)
	return nil
}

// =============================================================================
// bridgePlatformTokenConfig
// =============================================================================

// bridgePlatformTokenConfig projects the operator's webservice
// JWT.PlatformToken block (pkg/webservice/v1.PlatformTokenConfig) onto the
// daemon-layer daemon.PlatformTokenConfig consumed by daemon.New to build the
// shared gRPC/QUIC/MCP broker-token validator.
//
// The mapping is field-for-field with the HTTP middleware path
// (pkg/webservice/v1.HandlerRegistry.PlatformTokenMiddleware): the same
// Issuer/JWKSURL/Audience/AllowBearer fields are carried through, and
// CacheTTLSeconds (an int64 second count) is converted to the daemon's
// CacheTTL time.Duration. ClockSkewSeconds is not carried because the daemon
// validator seam (newPlatformTokenValidator -> platformtoken.Options) does not
// expose a clock-skew input, matching the HTTP path which also drops it.
//
// A disabled (Enabled == false) input yields a zero-Enabled daemon config, so
// an absent webservice JWT.PlatformToken section keeps daemon.New on its legacy
// per-transport validators and does not fail boot.
func bridgePlatformTokenConfig(src v1.PlatformTokenConfig) daemon.PlatformTokenConfig {
	return daemon.PlatformTokenConfig{
		Enabled:     src.Enabled,
		Issuer:      src.Issuer,
		JWKSURL:     src.JWKSURL,
		Audience:    src.Audience,
		AllowBearer: src.AllowBearer,
		CacheTTL:    time.Duration(src.CacheTTLSeconds) * time.Second,
	}
}

// =============================================================================
// serveCmd
// =============================================================================

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the platform daemon",
	Long: `Starts the platform daemon with multi-protocol API support.

The daemon provides:
  - Unix socket for local IPC (platformctl communication)
  - REST API for HTTP clients
  - gRPC for high-performance service-to-service communication
  - QUIC for low-latency connections
  - MCP for AI/LLM integration

When webservices are configured in the platform config, the full webservice
stack is started with ACME, WebAuthn, and JWT authentication support.

Example:
  platformd serve
  platformd serve --socket-path=/run/platformd.sock --rest-port=8443
  platformd serve --enable-quic=false --enable-mcp=false
`,
	// A startup failure is not a usage error. Without this, cobra prints the
	// full usage block after the error, which buries the actual cause in a
	// service manager's journal and reads as "you typed it wrong" when the
	// daemon simply could not start (#53).
	SilenceUsage: true,

	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		sigChan := make(chan os.Signal, 1)

		level := slog.LevelInfo
		if InitParams.Debug {
			level = slog.LevelDebug
		}
		logger := logging.NewLogger(level, nil)

		// Initialize the app. Errors here are FATAL — the daemon will not
		// run in a "limited functionality" mode where critical services
		// (CA, key store, DNSSEC signing) are silently broken.
		var appErr error
		if _, appErr = App.Init(ctx, InitParams); appErr != nil {
			if errors.Is(appErr, app.ErrTPMNotInitialized) {
				logger.Info("Platform not initialized, auto-provisioning...")
				InitParams.Initialize = true
				if _, appErr = App.Init(ctx, InitParams); appErr != nil {
					logger.Error(appErr, "App initialization FAILED during auto-provisioning")
					cmd.PrintErrln(fmt.Sprintf("FATAL: App initialization failed during auto-provisioning: %v", appErr))
					return ErrServeStartup{Phase: "app initialization during auto-provisioning", Cause: appErr}
				}
				logger.Info("Platform provisioned successfully")
			} else {
				logger.Error(appErr, "App initialization FAILED")
				cmd.PrintErrln(fmt.Sprintf("FATAL: App initialization failed: %v", appErr))
				return ErrServeStartup{Phase: "app initialization", Cause: appErr}
			}
		}

		if App != nil && App.Logger != nil {
			logger = App.Logger
		}

		// Install a JSON-lines structured-log sink so the WebUI Logs
		// page (and any future cluster-wide forwarder) has data to
		// surface. The handler fans out alongside the existing
		// stderr/file logger via MultiHandler so nothing about the
		// existing logging story changes — every record continues to
		// land where it always did, plus a structured copy lands in
		// <LogDir>/jsonl/.
		jsonlQuerier := installJSONLLogging(logger)

		// First-run escrow consumer.
		if App != nil && appErr == nil {
			if result, hoErr := App.ConsumeFirstbootHandoff(ctx); hoErr != nil {
				logger.Warnf("firstboot-handoff consumer: %v", hoErr)
			} else if result != nil && result.Present {
				logger.Info("firstboot-handoff consumer: recovery passphrase escrowed",
					"tenant", App.TenantID,
					"node", App.Hostname,
					"secret_path", result.SecretPath,
					"escrowed_at", result.EscrowedAt.Format(time.RFC3339),
				)
			}
		}

		// Bootstrap self-registration.
		if App != nil && appErr == nil {
			App.RunBootstrapRegistration()
		}

		webservicesEnabled := App != nil && len(App.WebServices) > 0

		logger.Info("Webservice mode check",
			"app_not_nil", App != nil,
			"webservices_count", len(App.WebServices),
			"webservices_enabled", webservicesEnabled)

		if webservicesEnabled {
			logger.Info("Starting webservices mode")
			return runWithWebservices(cmd, ctx, sigChan, logger, jsonlQuerier)
		} else {
			logger.Info("Starting daemon-only mode", "app_err", appErr)
			return runDaemonOnly(cmd, ctx, sigChan, logger, appErr)
		}
	},
}

// runWithWebservices starts the platform with full webservice support
// (ACME, WebAuthn, JWT). This mode requires the CA to be initialized.
//
// jsonlQuerier is the JSON-lines log surface installed at daemon boot
// (pkg/daemon/commands/log_sink.go). It is threaded into the REST
// router via HandlerRegistry params so /api/v1/platform/logs has data
// to read. When nil — for example when LogDir is unwritable — the
// /logs endpoints return 503 with a structured "not configured"
// envelope instead of pretending to be functional.
func runWithWebservices(cmd *cobra.Command, ctx context.Context, sigChan chan os.Signal, logger *logging.Logger, jsonlQuerier *jsonfile.Querier) error {
	logger.Info("runWithWebservices: starting CA initialization")

	if App.CA == nil {
		logger.Info("runWithWebservices: CA is nil, parsing PINs")
		soPIN, userPIN, err := App.ParsePINs(InitParams.SOPin, InitParams.Pin)
		if err != nil {
			logger.Error(err, "runWithWebservices: PIN parsing failed")
			cmd.PrintErrln(err)
			return ErrServeStartup{Phase: "PIN parsing", Cause: err}
		}
		logger.Info("runWithWebservices: loading CA")
		if err := App.LoadCA(ctx, soPIN, userPIN); err != nil {
			logger.Warn("CA not found, attempting to initialize", "error", err)
			if _, initErr := App.InitCA(ctx, soPIN, userPIN, InitParams); initErr != nil {
				logger.Error(initErr)
				cmd.PrintErrln(fmt.Sprintf("Failed to load or initialize CA: load error: %v, init error: %v", err, initErr))
				return ErrServeStartup{Phase: "CA initialization", Cause: initErr}
			}
			logger.Info("CA initialized successfully")
		} else {
			logger.Info("runWithWebservices: CA loaded successfully")
		}
	} else {
		logger.Info("runWithWebservices: CA already initialized")
	}

	logger.Info("runWithWebservices: initializing web server")
	if App.WebServiceKeyAttributes == nil {
		if err := App.InitWebServer(ctx); err != nil {
			logger.Error(err, "runWithWebservices: InitWebServer failed")
			cmd.PrintErrln(err)
			return ErrServeStartup{Phase: "web server initialization", Cause: err}
		}
		logger.Info("runWithWebservices: web server initialized successfully")
	} else {
		logger.Info("runWithWebservices: web service key attributes already set")
	}

	// Wire certificate renewal.
	//
	// This call is why the platform renews certificates at all. Until it was
	// added, InitCertManagement had ZERO production callers: the renewal
	// machinery — the platform.cert-renewal handler, the 0 2 * * * job, the
	// 30-day threshold, per-node NodeAffinity — was complete and never invoked,
	// so webservice and BMC certificates were issued and then ran to expiry.
	// Webservice targets register themselves during issueWebServiceCertificate,
	// which is what made the gap easy to miss: the registry filled up and was
	// never read.
	//
	// The call itself is made further down, once App.ServiceRegistry() has
	// materialized the scheduler engine and App.DNSService.
	acmeDAOFactory, err := acmequicbaas.NewFactory(App.Storage)
	if err != nil {
		logger.Error(err)
		cmd.PrintErrln(err)
		return ErrServeStartup{Phase: "ACME DAO factory", Cause: err}
	}

	daemonConfig := daemon.DefaultConfig()
	daemonConfig.App = App
	daemonConfig.Logger = logger
	daemonConfig.SocketPath = serveSocketPath
	daemonConfig.GRPCSocketPath = serveSocketPath
	daemonConfig.SocketGroup = ""

	if serveSkipIAM {
		daemonConfig.SkipIAMValidation = true
		logger.Warn("WARNING: IAM validation is DISABLED. All transports will accept unauthenticated requests. DO NOT USE IN PRODUCTION.",
			"transports", "gRPC,QUIC,MCP,Unix")
	}

	daemonConfig.EnableREST = false
	daemonConfig.EnableGRPCTCP = serveEnableGRPC
	daemonConfig.GRPCListenAddr = fmt.Sprintf("0.0.0.0:%d", serveGRPCPort)

	daemonConfig.EnableQUIC = serveEnableQUIC
	daemonConfig.QUICListenAddr = fmt.Sprintf("0.0.0.0:%d", serveQUICPort)
	if serveEnableQUIC {
		quicConfig, quicErr := quic.DefaultServerConfigWithTLS()
		if quicErr != nil {
			logger.Error(quicErr, "Failed to generate QUIC TLS configuration")
			cmd.PrintErrln(fmt.Sprintf("Failed to generate QUIC TLS configuration: %v", quicErr))
			return ErrServeStartup{Phase: "QUIC TLS configuration", Cause: quicErr}
		}
		quicConfig.ListenAddr = fmt.Sprintf("0.0.0.0:%d", serveQUICPort)
		daemonConfig.QUICConfig = quicConfig
		logger.Debug("QUIC TLS configuration generated with self-signed certificate")
	}

	daemonConfig.EnableMCP = serveEnableMCP
	if daemonConfig.MCPConfig == nil {
		daemonConfig.MCPConfig = daemon.DefaultMCPConfig()
	}
	daemonConfig.MCPConfig.HTTPAddr = fmt.Sprintf("127.0.0.1:%d", serveMCPPort)

	ovsSocketPathWS := "/var/run/openvswitch/db.sock"
	if envPath := os.Getenv("SDN_OVS_SOCKET"); envPath != "" {
		ovsSocketPathWS = envPath
	}
	if _, statErr := os.Stat(ovsSocketPathWS); statErr == nil {
		daemonConfig.OVSSocketPath = ovsSocketPathWS
		logger.Info("OVS socket detected, SDN service will be enabled", "path", ovsSocketPathWS)
	} else {
		logger.Info("OVS socket not found, SDN service will not be available", "path", ovsSocketPathWS)
	}

	// vTPM service must exist before compute so the QEMU orchestrator can be
	// wired with the profile-aware generator. Idempotent — the call later in
	// this function no-ops when already set.
	initVTPMServiceOnConfig(logger, App, daemonConfig)
	computeOrchestrator, computeErr := newComputeOrchestrator(logger, App, daemonConfig.OVSSocketPath, daemonConfig.VTPMService)
	if computeErr != nil {
		logger.Info("Compute orchestrator not available (container operations will fail)",
			"reason", computeErr.Error())
	} else {
		daemonConfig.ComputeOrchestrator = computeOrchestrator
		logger.Info("Compute orchestrator initialized successfully")
	}

	if App != nil && App.DNSService != nil {
		daemonConfig.DNSService = App.DNSService
		logger.Info("DNS service configured for daemon")
	}

	// Surface platform services into the daemon config so each gRPC
	// service registers handlers on both the TCP and Unix-socket gRPC
	// servers. Without these wirings, `platformctl --transport unix …`
	// reports "unknown service" for Device, CA, vTPM, etc. — even though
	// the REST router reaches them through the registry.
	if App != nil {
		reg, err := App.ServiceRegistry()
		if err != nil {
			return err
		}
		if devSvc := reg.DeviceService(); devSvc != nil {
			daemonConfig.DeviceService = devSvc
			logger.Info("device service wired for daemon gRPC")
		}
		if profileSvc := reg.ProfileService(); profileSvc != nil {
			daemonConfig.DeviceProfileService = profileSvc
			logger.Info("device profile service wired for daemon gRPC")
		}
		if App.CA != nil {
			daemonConfig.CAService = App.CA
			logger.Info("CA service wired for daemon gRPC")
		}
	}

	// A BMC configured for ACME needs a client before cert management runs.
	// InitWebServer only initializes one as a side effect of ISSUING a
	// webservice certificate, which an ordinary restart skips.
	initACMEClientForCertManagement(ctx, logger, App)

	// Schedule certificate renewal.
	//
	// Ordering is load-bearing, and in two directions:
	//   - AFTER InitWebServer / LoadCA, so webservice targets are already in the
	//     registry and there is a CA to reissue with.
	//   - AFTER App.ServiceRegistry(), which is what lazily materializes both the
	//     DAO factory (and therefore the scheduler engine) and App.DNSService.
	//     BMC cert init passes App.DNSService as its dns-01 updater, so calling
	//     this earlier hands BMC ACME issuance a nil updater.
	initCertManagement(ctx, logger, App)

	// Construct the platform tenant.Manager so the daemon's tenant gRPC
	// service (and the dashboard's GET /api/v1/tenants/{id}) can resolve
	// tenants. The dashboard otherwise renders 400
	// "tenant manager not initialized" on every page load. We use the
	// QuicBaaS SDK IAM TenantClient (already wired via App.QuicBaaSSDKClient)
	// and disable optional features (DEK isolation, VLAN/quota/bridge
	// management) until the corresponding subsystems are also instantiated
	// during startup. The daemon's TenantService gracefully accepts a
	// minimal manager — list/get/create against IAM still work.
	if App != nil {
		if sdk := App.QuicBaaSSDKClient(); sdk != nil {
			if iamClient := sdk.IAM(); iamClient != nil {
				if tc := iamClient.Tenant(); tc != nil {
					tenantCfg := tenant.DefaultConfig()
					// Optional subsystems are not yet wired in this serve
					// path; turn them off so NewManager() doesn't reject
					// the construction for a missing DEK/VLAN/Bridge dep.
					tenantCfg.EnableDEKIsolation = false
					mgr, mgrErr := tenant.NewManager(&tenant.ManagerConfig{
						IAMTenantClient: tc,
						Config:          tenantCfg,
						Logger:          slog.Default(),
					})
					if mgrErr != nil {
						logger.Warn("failed to construct platform tenant manager",
							"error", mgrErr)
					} else {
						daemonConfig.PlatformTenantManager = mgr
						logger.Info("platform tenant manager wired (IAM-only)")
					}
				}
			}
		}
	}

	// Provision daemon mTLS identity for the gRPC TCP / QUIC listeners. In
	// webservices mode this used to be skipped, leaving the gRPC TCP server
	// to start with no TLS at all. Mirroring the daemon-only path keeps
	// remote platformctl invocations TLS-authenticated regardless of mode.
	// Fail closed (#32): a provisioning failure aborts startup — the safe
	// response to "I cannot serve TLS" is to not serve.
	if tlsErr := applyDaemonTLSIdentity(ctx, logger, App, daemonConfig, serveEnableMTLS); tlsErr != nil {
		logger.Error(tlsErr, "Failed to provision daemon TLS identity — refusing to start")
		cmd.PrintErrln(fmt.Sprintf("FATAL: failed to provision daemon TLS identity — refusing to start: %v", tlsErr))
		// FATAL exit, matching this command's app-init convention: a bare
		// return would unwind to a SUCCESSFUL cobra Run exit, and a service
		// manager with Restart=on-failure would treat the refused startup
		// as a clean shutdown and never retry (#32).
		return ErrServeStartup{Phase: "daemon TLS identity provisioning", Cause: tlsErr}
	}

	// Wire the vTPM service into daemonConfig before daemon.New runs.
	// The runDaemonOnly path does the same; both paths need it because
	// the REST router reads daemonConfig.VTPMService back through the
	// daemon.Service handle. Skipping it here is what left
	// /api/v1/vtpm/* dark on the webservices-mode CP.
	initVTPMServiceOnConfig(logger, App, daemonConfig)

	// Wire the OCI artifact registry. Backed by a local file store
	// under <PlatformDir>/registry for Phase 5's first ship; cluster-
	// replicated QuicBaaS storage lands as a follow-up. The
	// daemonConfig.RegistryService field plumbs the same handle into
	// gRPC + MCP transports so platformctl + the WebUI both see the
	// real registry contents instead of a dark surface.
	initRegistryServiceOnConfig(logger, App, daemonConfig)

	// Snapshot store backs /api/v1/platform/config/snapshots and the
	// automatic pre-reload snapshot capture in
	// Service.ReloadConfigWithSnapshot. Single-node file-backed for
	// today; replicated storage lands alongside the equivalent
	// switch in the registry.
	snapshotStore := initSnapshotStore(logger, App)
	_ = snapshotStore // installed onto the daemon Service below

	// Attestation store + service backs /api/v1/attestation/manifests
	// and the per-enrollment capture hook below. When no attestation
	// backend is configured this is a no-op and the REST surface
	// returns 503 via the service registry.
	attestationSvcs := initAttestationServices(logger, App)
	attachAttestationServiceToDaemonConfig(daemonConfig, attestationSvcs)

	// Build the shared SDN flow-policy machinery (engine + zone flow manager)
	// once; the quarantine observer and the SDN enrollment hook below both
	// consume it so port-policy state lives in a single engine. Nil when SDN
	// or OVS is unavailable.
	sdnPolicy := initSDNPolicy(App, logger.Slog())

	// Wire the quarantine observer: when both attestation and SDN-OVS are
	// available, failed attestations move devices to the quarantine zone and
	// successful re-attestations restore them. No-op when either subsystem is
	// absent so boot behavior is unchanged on nodes without OVS.
	wireQuarantineObserver(attestationSvcs, sdnPolicy, daemonConfig.DeviceService, logger)

	// Attestation reporting (#226): the collector on a control plane, and
	// on every node the caller policy for the quote routes. The policy is
	// built after the collector so the any-attested strategy can consult
	// this node's own report cache. One surface, shared by every listener
	// and by the gRPC/Unix and MCP transports.
	// The control plane is a device in its own registry (#472): it writes
	// its own record from its own TPM through the same registration the
	// ACME finalize hook uses, so the collector below attests it exactly
	// like a node. Runs before the collector because the collector needs
	// the resulting device id to resolve the control plane's own endpoint.
	controlPlaneDevice := initControlPlaneDevice(ctx, logger.Slog(), App, daemonConfig)

	reportingRest := initCallerPolicy(logger.Slog(), App, attestationSvcs)
	if rep := initReportingCollector(ctx, logger.Slog(), App, daemonConfig, attestationSvcs, controlPlaneDevice); rep != nil {
		defer rep.Stop()
		reportingRest = withCollectorSurface(logger.Slog(), reportingRest, rep, App, attestationSvcs)
		daemonConfig.AttestationReporting = rep.Handles
		if reportingRest != nil && reportingRest.Policy != nil {
			rep.Handles.Policy = reportingRest.Policy
		}
	} else if reportingRest != nil && reportingRest.Policy != nil {
		daemonConfig.AttestationReporting = &daemon.ReportingHandles{Policy: reportingRest.Policy}
	}

	// Construct the SDN enrollment hook on the same engine. The webservice
	// registry registers it as an ACME order-finalization hook; on device
	// activation it applies the port policy and stamps device.NetworkPortID
	// (via the PortBinder) so the quarantine observer can act on real ports.
	var sdnEnrollmentHook *policy.SDNEnrollmentHook
	if sdnPolicy != nil && App != nil {
		reg, err := App.ServiceRegistry()
		if err != nil {
			return err
		}
		sdnEnrollmentHook = initSDNEnrollmentHook(
			sdnPolicy.Engine, daemonConfig.DeviceService, reg.ProfileService(),
			sdnPolicy.ResolvedZones, logger)
	}

	// Gateway control-plane state cache backs /api/v1/gateway/state,
	// /api/v1/gateway/telemetry, and /api/v1/gateway/desired-config.
	// Single-node file-backed for today; gatewayd reports here and
	// reads its desired config from here.
	gwControl := initGatewayControlPlane(logger, App)

	// Bridge the operator's webservice JWT.PlatformToken block into the
	// daemon-side validator config so the gRPC/QUIC/MCP transports enforce
	// the same broker-token liveness/revocation policy as the HTTP path. The
	// primary webservice config is the canonical source (it owns the broker
	// issuer/JWKS/audience). When the section is absent or disabled the bridge
	// produces a zero/disabled daemon config, so boot behavior is unchanged
	// (the daemon retains its legacy per-transport validators).
	if primary := App.PrimaryWebService(); primary != nil {
		daemonConfig.PlatformToken = bridgePlatformTokenConfig(primary.JWT.PlatformToken)
		if daemonConfig.PlatformToken.Enabled {
			logger.Info("Bridged webservice JWT.PlatformToken into daemon validator config",
				"issuer", daemonConfig.PlatformToken.Issuer,
				"jwks_url", daemonConfig.PlatformToken.JWKSURL,
				"allow_bearer", daemonConfig.PlatformToken.AllowBearer)
		}
	}

	// M6 barrier-unseal gate: bind only the Unix socket + a loopback
	// /healthz + /init + /unseal HTTP listener and block until the
	// barrier is unsealed. Production transports (gRPC TCP, REST, QUIC,
	// MCP) are NOT bound while this runs. On a subsequent restart where
	// the barrier is already unsealed the gate returns immediately.
	if gateErr := invokeBarrierGate(ctx, App, logger); gateErr != nil {
		logger.Error(gateErr, "init-only mode gate failed")
		cmd.PrintErrln(fmt.Sprintf("init-only mode gate failed: %v", gateErr))
		return ErrServeStartup{Phase: "barrier gate", Cause: gateErr}
	}

	platformDaemon, err := daemon.New(daemonConfig)
	if err != nil {
		logger.Error(err, "Failed to create platform daemon")
		cmd.PrintErrln(fmt.Sprintf("Failed to create platform daemon: %v", err))
		return ErrServeStartup{Phase: "platform daemon creation", Cause: err}
	}

	// Plug snapshot store into the daemon Service so reload captures
	// a pre-reload snapshot automatically and rollback is reachable
	// from REST + gRPC.
	if snapshotStore != nil {
		if svc := platformDaemon.Service(); svc != nil {
			svc.SetSnapshotStore(snapshotStore)
		}
	}

	if err := platformDaemon.Start(ctx); err != nil {
		logger.Error(err, "Failed to start platform daemon")
		cmd.PrintErrln(fmt.Sprintf("Failed to start platform daemon: %v", err))
		return ErrServeStartup{Phase: "platform daemon start", Cause: err}
	}
	logger.Info("Platform daemon started", "socket", platformDaemon.SocketPath())

	var wg sync.WaitGroup
	for _, wsConfig := range App.WebServices {
		wg.Add(1)

		wsName := wsConfig.Name
		if wsName == "" {
			wsName = "default"
		}
		logger.Info("Starting webservice", "name", wsName, "port", wsConfig.Port, "tls-port", wsConfig.TLSPort)

		wsKeyAttrs := App.WebServiceKeyAttributes[wsName]
		if wsKeyAttrs == nil {
			logger.Error(&MessageError{Msg: "key attributes not found"}, "Failed to get key attributes for webservice", "name", wsName)
			cmd.PrintErrln(fmt.Sprintf("Failed to get key attributes for webservice %s: key attributes not initialized", wsName))
			wg.Done()
			continue
		}

		var acmeServerConfig *v1.ACMEServerConfig
		if wsConfig.ACME != nil && wsConfig.ACME.Enabled {
			baseRESTURI := strings.TrimSuffix(wsConfig.ACME.DirectoryURL, "/acme/directory")
			logger.Info("ACME server enabled for webservice", "name", wsName, "directory", wsConfig.ACME.DirectoryURL, "baseURI", baseRESTURI)

			challengeMap := buildChallengeMap(wsConfig.ACME.Challenges, App.CA)
			logger.Info("ACME challenges configured", "count", len(challengeMap), "challenges", wsConfig.ACME.Challenges)

			var internalDomain string
			switch {
			case App.DNSConfig == nil:
				logger.Warn("DNS config is nil - DNS registration disabled")
			case App.DNSConfig.InternalServer == nil:
				logger.Warn("DNS InternalServer config is nil - DNS registration disabled")
			default:
				internalDomain = App.DNSConfig.InternalServer.Zone.Name
				logger.Info("ACME DNS registration enabled", "internal_domain", internalDomain)
			}

			acmeServerConfig = &v1.ACMEServerConfig{
				Enabled:                 true,
				BaseRESTURI:             baseRESTURI,
				ChallengeMap:            challengeMap,
				InternalDomain:          internalDomain,
				TermsOfService:          wsConfig.ACME.TermsOfService,
				ExternalAccountRequired: wsConfig.ACME.ExternalAccountRequired,
			}
		}

		sdkRPID := ""
		if App != nil && App.QuicBaaSConfig != nil {
			sdkRPID = App.QuicBaaSConfig.WebAuthnRPID
		}
		webauthnConfig := listenerWebAuthnConfig(wsConfig, sdkRPID, logger)

		ks, ok := App.CA.KeyStore().(v1.XKMSSigner)
		if !ok {
			logger.Warn("CA does not implement XKMSSigner interface")
			cmd.PrintErrln("CA does not implement XKMSSigner interface")
			return ErrServeStartup{Phase: "CA key store does not implement XKMSSigner"}
		}

		if App.DNSService != nil {
			ctx := context.Background()

			if wsConfig.Certificate.Subject.CommonName != "" {
				cn := wsConfig.Certificate.Subject.CommonName
				if err := App.DNSService.RegisterWebservice(ctx, cn); err != nil {
					logger.Warn("Failed to register DNS record for webservice",
						slog.String("name", wsName),
						slog.String("cn", cn),
						slog.String("error", err.Error()))
				} else {
					logger.Info("Registered DNS A record for webservice",
						slog.String("name", wsName),
						slog.String("cn", cn))
				}
			}

			if wsConfig.VirtualHosts != nil {
				for _, vhost := range *wsConfig.VirtualHosts {
					if vhost.Certificate != nil && vhost.Certificate.Subject.CommonName != "" {
						cn := vhost.Certificate.Subject.CommonName
						if err := App.DNSService.RegisterWebservice(ctx, cn); err != nil {
							logger.Warn("Failed to register DNS record for virtual host certificate",
								slog.String("webservice", wsName),
								slog.String("cn", cn),
								slog.String("error", err.Error()))
						} else {
							logger.Info("Registered DNS A record for virtual host certificate",
								slog.String("webservice", wsName),
								slog.String("cn", cn))
						}
					}

					for _, host := range vhost.Hosts {
						if host != "" {
							if err := App.DNSService.RegisterWebservice(ctx, host); err != nil {
								logger.Warn("Failed to register DNS record for virtual host",
									slog.String("webservice", wsName),
									slog.String("host", host),
									slog.String("error", err.Error()))
							} else {
								logger.Info("Registered DNS A record for virtual host",
									slog.String("webservice", wsName),
									slog.String("host", host))
							}
						}
					}
				}
			}
		}

		var servicesManager platformrest.ServicesManager
		// Wrap the QuicBaaS IAM SDK as restiam.IAMClient/PEPClient. The
		// daemon owns the IAM service; we just adapt its nested per-resource
		// SDK clients to the wide IAMClient interface the REST router
		// consumes. Without this adapter /api/v1/iam/* never registered.
		var iamClient restiam.IAMClient
		var pepClient restiam.PEPClient
		if platformDaemon != nil {
			if iamSvc := platformDaemon.IAMService(); iamSvc != nil {
				if c := iamSvc.Client(); c != nil {
					iamClient = restiam.NewQuicBaaSIAMAdapter(c)
				}
				if p := iamSvc.PEP(); p != nil {
					pepClient = restiam.NewQuicBaaSPEPAdapter(p)
				}
			}
		}
		// QuicBaaS SDK clients for KMS REST routes. Per project
		// convention every REST handler consumes the go-quicbaas SDK
		// directly; raw proto/gRPC interfaces are forbidden.
		var kmsSDK kmsclient.Client
		var cryptoSDK cryptoclient.Client
		var dekSDK dekclient.Client
		var secretsSDK secretsclient.Client
		var fido2SDK quicbaassdk.FIDO2Client
		var authSDK quicbaassdk.AuthService
		var factorsSDK quicbaassdk.AuthFactorsClient
		if App != nil {
			if sdkClient := App.QuicBaaSSDKClient(); sdkClient != nil {
				kmsSDK = sdkClient.Security().KMS()
				cryptoSDK = sdkClient.Security().Crypto()
				dekSDK = sdkClient.Security().DEK()
				secretsSDK = sdkClient.Security().Secrets()
				if security := sdkClient.Security(); security != nil {
					if auth := security.Auth(); auth != nil {
						fido2SDK = auth.FIDO2()
						// Unified login surface consumed by the /login REST
						// endpoint (BeginLogin/FinishLogin + OIDC bearer).
						authSDK = auth
						// Auth-factor surface the admin-claim ceremony reads
						// to decide whether the system admin is claimed.
						factorsSDK = auth.Factors()
					}
				}
			}
		}
		// The firstboot admin bundle and the CA that issued it are written
		// by the embedded QuicBaaS server under its own data directory, so
		// the claim ceremony's trust anchor is derived from it rather than
		// carried as a separate config key that could drift out of sync.
		adminTrustAnchorPath := ""
		if App != nil && App.QuicBaaSConfig != nil && App.QuicBaaSConfig.DataDir != "" {
			adminTrustAnchorPath = filepath.Join(
				App.QuicBaaSConfig.DataDir, "certs", "ca-chain.crt")
		}
		// The WebAuthn ceremony tenant must be the ADOPTED operating
		// tenant, not the bootstrap config placeholder; fail closed if
		// adoption cannot complete with IAM present.
		if App != nil {
			ensureCtx, ensureCancel := context.WithTimeout(context.Background(), 15*time.Second)
			if err := App.EnsureOperatingTenant(ensureCtx); err != nil {
				ensureCancel()
				logger.FatalError(err)
			}
			ensureCancel()
		}
		svcRegistry, err := App.ServiceRegistry()
		if err != nil {
			return err
		}

		params := v1.RegistryParams{
			ACMEServerConfig:          acmeServerConfig,
			ACMEStorageFactory:        acmeDAOFactory,
			CA:                        App.CA,
			CAConfig:                  App.CAConfig,
			Debug:                     App.DebugFlag,
			HTTPWriter:                response.NewResponseWriter(logger, nil),
			IAMClient:                 iamClient,
			XKMS:                      ks,
			KMSClient:                 kmsSDK,
			CryptoClient:              cryptoSDK,
			DEKClient:                 dekSDK,
			SecretsClient:             secretsSDK,
			JWTAudience:               wsConfig.Certificate.Subject.CommonName,
			JWTClaimsIssuer:           app.Name,
			JWTExpiration:             3600,
			Logger:                    logger,
			PEPClient:                 pepClient,
			ServerKeyAttributes:       wsKeyAttrs,
			ServiceRegistry:           svcRegistry,
			TPM:                       App.TPM,
			WebServiceConfig:          wsConfig,
			WebAuthnConfig:            webauthnConfig,
			FIDO2SDKClient:            fido2SDK,
			TenantID:                  App.TenantID,
			AuthSDKClient:             authSDK,
			FactorsSDKClient:          factorsSDK,
			AdminTrustAnchorPath:      adminTrustAnchorPath,
			AdminClaimMultiInstance:   isMultiInstanceDeployment(App.QuicBaaSConfig),
			SDNEnrollmentHook:         sdnEnrollmentHook,
			TenantManager:             daemonConfig.PlatformTenantManager,
			PublicRegistrationEnabled: App.QuicBaaSConfig != nil && App.QuicBaaSConfig.SelfServiceRegistration.Active(),
		}
		if App != nil && App.SDNConfig != nil {
			params.SDNIdentityConfig = App.SDNConfig.Identity
		}
		if platformDaemon != nil {
			if svc := platformDaemon.Service(); svc != nil {
				servicesManager = svc
			}
			// Plumb in-process gRPC server implementations so the new REST
			// routers can delegate via sdk/go service patterns. Each accessor
			// returns nil when the corresponding service is not configured;
			// the routers register only when the server is non-nil.
			if svc := platformDaemon.AttestationGRPCService(); svc != nil {
				params.AttestationServiceServer = svc
			}
			// Bridge the daemon's control-plane DB signer to the webservice
			// config delivery handler (POST /api/v1/provisioning/sign).
			if signer := platformDaemon.DBKeySigner(); signer != nil {
				params.DBKeySigner = signer
			}
			if svc := platformDaemon.ComputeGRPCService(); svc != nil {
				params.ComputeServiceServer = svc
			}
			if svc := platformDaemon.DeviceGRPCService(); svc != nil {
				params.DeviceServiceServer = svc
			}
			if svc := platformDaemon.EABGRPCService(); svc != nil {
				params.EABServiceServer = svc
			}
			if svc := platformDaemon.GatewayGRPCService(); svc != nil {
				params.GatewayServiceServer = svc
			}
			if svc := platformDaemon.IDevIDGRPCService(); svc != nil {
				params.IDevIDServiceServer = svc
			}
			if svc := platformDaemon.InvitationGRPCService(); svc != nil {
				params.InvitationServiceServer = svc
			}
			if svc := platformDaemon.OverlayGRPCService(); svc != nil {
				params.OverlayServiceServer = svc
			}
			if svc := platformDaemon.PXEGRPCServiceServer(); svc != nil {
				params.PXEServiceServer = svc
			}
			if svc := platformDaemon.NTPGRPCServiceServer(); svc != nil {
				params.NTPServiceServer = svc
			}
			if svc := platformDaemon.TenantGRPCServer(); svc != nil {
				params.TenantServiceServer = svc
			}
			if svc := platformDaemon.TPMGRPCService(); svc != nil {
				params.TPMServiceServer = svc
			}
			// Pre-existing routers that were nil-fielded in the v1 router
			// registry — surface their daemon-side server impls so REST
			// /api/v1/{sdn,vtpm,switches} stop returning the
			// "endpoint does not exist" envelope.
			if svc := platformDaemon.SDNService(); svc != nil {
				params.SDNService = svc
				// Reconcile configured VLANs into the in-memory SDN
				// service so ListVLANs reflects the operator's intent.
				// Without this seeding the WebUI Networking → VLANs
				// page shows an empty table even when subnets define
				// vlan-id values that the platform has already turned
				// into IPAM pools.
				seedSDNVLANsFromConfig(logger, App, svc)
			}
		}
		// vtpm.VTPMService is wired by the daemon-only path (config.VTPMService)
		// — surface the same instance to the REST router by reading it back
		// from the daemon configuration that was already populated above.
		if daemonConfig.VTPMService != nil {
			params.VTPMService = daemonConfig.VTPMService
		}
		// Physical switch service: not yet wired through *app.App in the
		// production startup path; nothing to plumb here today. Adding the
		// switch backend requires a separate App field and config block —
		// tracked separately. The REST router already nil-guards.
		params.ServicesManager = servicesManager
		// Surface bound listener addresses so /api/v1/platform/protocols
		// returns 200 instead of "daemon config not configured".
		params.ProtocolConfig = &platformrest.ProtocolConfig{
			EnableREST:     daemonConfig.EnableREST,
			RESTListenAddr: daemonConfig.RESTListenAddr,
			RESTTLSEnabled: daemonConfig.EnableREST,
			EnableGRPCTCP:  daemonConfig.EnableGRPCTCP,
			GRPCListenAddr: daemonConfig.GRPCListenAddr,
			GRPCTLSEnabled: daemonConfig.EnableGRPCTCP,
			SocketPath:     daemonConfig.SocketPath,
			EnableQUIC:     daemonConfig.EnableQUIC,
			QUICListenAddr: daemonConfig.QUICListenAddr,
			EnableMCP:      daemonConfig.EnableMCP,
		}
		if daemonConfig.MCPConfig != nil {
			params.ProtocolConfig.MCPHTTPAddr = daemonConfig.MCPConfig.HTTPAddr
		}
		// VersionInfo populates /api/v1/platform/{status,version}.
		params.VersionInfo = &platformrest.VersionInfo{
			Version:   app.Version,
			BuildDate: app.BuildDate,
			GitHash:   app.GitHash,
		}
		// HealthRegistry powers /api/v1/platform/{health,metrics}.
		if platformDaemon != nil {
			params.HealthRegistry = platformDaemon.HealthRegistry()
		}
		// /platform/config/reload delegates to the running daemon
		// Service. /platform/logs is fed by the JSON-lines sink we
		// installed earlier.
		if platformDaemon != nil {
			if svc := platformDaemon.Service(); svc != nil {
				params.ConfigReloader = svc
			}
		}
		if jsonlQuerier != nil {
			params.LogQuerier = jsonlQuerier
		}
		// RegistryService is wired by initRegistryServiceOnConfig (called
		// before daemon.New). Surface it on the REST router so
		// /api/v1/compute/images has a backend to delegate to.
		if daemonConfig.RegistryService != nil {
			params.RegistryService = daemonConfig.RegistryService
		}
		// The OCI Distribution-spec /v2/ surface needs richer access
		// to the same *Registry (blob/manifest CRUD with raw bytes).
		// initRegistryServiceOnConfig stashes the backend pointer on
		// the daemonConfig via the same field type the REST layer
		// consumes, so callers don't need to know about the
		// pkg/registry concrete type.
		if backend := registryDistBackend(daemonConfig); backend != nil {
			params.OCIDistBackend = backend
		}
		// AttestationCapture surfaces the platform attestation service
		// into the WebAuthn / ACME registry hook chain so each TCG CSR
		// enrollment writes a HostManifest + manifest_captured event.
		if cap := attestationCaptureAdapter(attestationSvcs); cap != nil {
			params.AttestationCapture = cap
		}
		if reader := attestationEventReader(attestationSvcs); reader != nil {
			params.AttestationEventReader = reader
		}
		// Caller admission and reports (#226): the one surface built above,
		// so every listener enforces the same policy and requests
		// certificates from the same anchors.
		params.AttestationReporting = reportingRest
		if gwControl != nil {
			if gwControl.Store != nil {
				params.GatewayStateStore = gwControl.Store
			}
			if gwControl.DesiredCfg != nil {
				params.GatewayDesiredConfig = gwControl.DesiredCfg
			}
		}
		restHandlerRegistry := v1.NewHandlerRegistry(ctx, params)

		// Wire the webserver's JWT service into the daemon's gRPC TCP /
		// QUIC / MCP auth interceptors so platformctl --transport
		// {grpc,quic,mcp} accepts /api/v1/login-issued JWTs (the same
		// token the WebUI already uses). Without this the daemon
		// validators return "authentication service not configured" or
		// "token validation failed" for valid platform tokens.
		if hr, ok := restHandlerRegistry.(interface {
			JWTService() *jwt.Service
		}); ok && platformDaemon != nil {
			if jwtSvc := hr.JWTService(); jwtSvc != nil {
				platformDaemon.SetPlatformJWTVerifier(jwtSvc)
			}
		}

		webserver := webservice.NewWebServerV1(
			ctx,
			App.DebugFlag,
			logger,
			App.CA,
			App.CAConfig,
			wsConfig,
			restHandlerRegistry,
			wsKeyAttrs)

		// Let certificate renewal put a new certificate into service on this
		// listener. Without it the sweep issues certificates the endpoint never
		// serves, and TLS breaks when the one it IS serving expires.
		App.RegisterWebServiceCertInstaller(wsName, webserver.ReloadCertificate)

		go func(ws *webservice.WebServerV1) {
			defer wg.Done()
			ws.Run()
		}(webserver)
	}

	var noiseServer *noiseapi.Server
	if App.BootstrapConfig != nil && App.BootstrapConfig.Noise != nil && App.BootstrapConfig.Noise.Enabled {
		bundler := bootstrap.NewCABundleAdapter(App.CA)
		var noiseErr error
		noiseServer, noiseErr = noiseapi.NewServer(App.BootstrapConfig.Noise, bundler, logger)
		if noiseErr != nil {
			logger.Warn("failed to create Noise bootstrap server", "error", noiseErr)
		} else {
			if startErr := noiseServer.Start(ctx); startErr != nil {
				logger.Warn("failed to start Noise bootstrap server", "error", startErr)
				noiseServer = nil
			} else {
				logger.Info("Noise bootstrap server started",
					"addr", noiseServer.Addr().String(),
					"public_key_hex", hex.EncodeToString(noiseServer.PublicKey()))
			}
		}
	}

	logger.Info("Platform daemon started with webservices",
		"socket", serveSocketPath,
		"grpc", fmt.Sprintf(":%d", serveGRPCPort),
		"quic", fmt.Sprintf(":%d", serveQUICPort),
		"mcp", fmt.Sprintf(":%d", serveMCPPort),
		"webservices", len(App.WebServices),
	)
	cmd.Println("Platform daemon running with webservices. Press Ctrl+C to stop.")

	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutdown signal received")
	cmd.Println("\nShutting down...")

	if noiseServer != nil {
		if stopErr := noiseServer.Stop(ctx); stopErr != nil {
			logger.Warn("failed to stop Noise bootstrap server", "error", stopErr)
		}
	}

	if platformDaemon != nil {
		if err := platformDaemon.Stop(ctx); err != nil {
			logger.Warn("Error stopping platform daemon", "error", err)
		}
	}

	logger.Info("Graceful shutdown complete")
	cmd.Println("Platform daemon stopped.")

	// The ONLY nil return in this function. Reaching here means the signal
	// wait above returned, so the daemon ran and was asked to stop — a clean
	// shutdown, which must keep exiting 0. Every other exit from here is a
	// startup failure and returns ErrServeStartup (#53).
	return nil
}

// runDaemonOnly starts the platform daemon without webservices.
// This mode can run with limited functionality even if the CA is not available.
func runDaemonOnly(cmd *cobra.Command, ctx context.Context, sigChan chan os.Signal, logger *logging.Logger, appErr error) error {
	config := daemon.DefaultConfig()
	if App != nil {
		config.App = App
	}
	config.Logger = logger
	config.SocketPath = serveSocketPath
	config.GRPCSocketPath = serveSocketPath
	config.SocketGroup = ""

	if serveSkipIAM {
		config.SkipIAMValidation = true
		logger.Warn("WARNING: IAM validation is DISABLED. All transports will accept unauthenticated requests. DO NOT USE IN PRODUCTION.",
			"transports", "gRPC,QUIC,MCP,Unix")
	}

	config.EnableREST = serveEnableREST
	config.RESTListenAddr = fmt.Sprintf("0.0.0.0:%d", serveRESTPort)

	config.EnableGRPCTCP = serveEnableGRPC
	config.GRPCListenAddr = fmt.Sprintf("0.0.0.0:%d", serveGRPCPort)

	config.EnableQUIC = serveEnableQUIC
	config.QUICListenAddr = fmt.Sprintf("0.0.0.0:%d", serveQUICPort)
	if serveEnableQUIC {
		quicConfig, quicErr := quic.DefaultServerConfigWithTLS()
		if quicErr != nil {
			logger.Error(quicErr, "Failed to generate QUIC TLS configuration")
			cmd.PrintErrln(fmt.Sprintf("Failed to generate QUIC TLS configuration: %v", quicErr))
			return ErrServeStartup{Phase: "QUIC TLS configuration", Cause: quicErr}
		}
		quicConfig.ListenAddr = fmt.Sprintf("0.0.0.0:%d", serveQUICPort)
		config.QUICConfig = quicConfig
		logger.Debug("QUIC TLS configuration generated with self-signed certificate")
	}

	config.EnableMCP = serveEnableMCP
	if config.MCPConfig == nil {
		config.MCPConfig = daemon.DefaultMCPConfig()
	}
	config.MCPConfig.HTTPAddr = fmt.Sprintf("127.0.0.1:%d", serveMCPPort)

	if App != nil && App.CAConfig != nil && App.CA == nil {
		soPIN, userPIN, pinErr := App.ParsePINs(InitParams.SOPin, InitParams.Pin)
		if pinErr != nil {
			logger.Warn("CA PIN parsing failed (CA will not be available)", "error", pinErr)
		} else {
			if loadErr := App.LoadCA(ctx, soPIN, userPIN); loadErr != nil {
				logger.Warn("CA not found, attempting to initialize", "error", loadErr)
				if _, initErr := App.InitCA(ctx, soPIN, userPIN, InitParams); initErr != nil {
					logger.Warn("CA initialization failed (CA will not be available)",
						"load_error", loadErr, "init_error", initErr)
				} else {
					logger.Info("CA initialized successfully")
				}
			} else {
				logger.Info("CA loaded successfully")
			}
		}
	}
	if App != nil && App.CA != nil {
		config.CAService = App.CA
		logger.Info("CA service configured for daemon")
	}

	// Inject the platform CA into the running embedded QuicBaaS server so
	// that SDK CertificateService calls (Security().Certificate().*) issue
	// certificates against the platform CA, not against QuicBaaS's bootstrap
	// CA. QuicBaaS starts during App.Init() (before the CA is available) to
	// serve early KMS/Secrets requests; this call completes the wiring so
	// provisionDaemonIdentity issues platform-CA-signed identity certs.
	// See docs/architecture/daemon-identity.md for the full boot sequencing.
	if App != nil && App.CA != nil {
		if caInjectErr := App.SetQuicBaaSCA(App.CA); caInjectErr != nil {
			logger.Warn("Failed to inject platform CA into QuicBaaS CertificateService (TLS may be disabled)",
				"error", caInjectErr)
		} else {
			logger.Info("Platform CA injected into QuicBaaS CertificateService")
		}
	}

	// Always present a server certificate on gRPC TCP / QUIC so remote
	// platformctl can negotiate TLS; --enable-mtls additionally requires the
	// client to present a CA-signed client certificate. Shared with
	// runWithWebservices via applyDaemonTLSIdentity to keep the gRPC TCP
	// listener TLS-protected in both modes. Fail closed (#32): a
	// provisioning failure aborts startup — the safe response to "I cannot
	// serve TLS" is to not serve.
	if tlsErr := applyDaemonTLSIdentity(ctx, logger, App, config, serveEnableMTLS); tlsErr != nil {
		logger.Error(tlsErr, "Failed to provision daemon TLS identity — refusing to start")
		cmd.PrintErrln(fmt.Sprintf("FATAL: failed to provision daemon TLS identity — refusing to start: %v", tlsErr))
		// FATAL exit, matching this command's app-init convention: a bare
		// return would unwind to a SUCCESSFUL cobra Run exit, and a service
		// manager with Restart=on-failure would treat the refused startup
		// as a clean shutdown and never retry (#32).
		return ErrServeStartup{Phase: "daemon TLS identity provisioning", Cause: tlsErr}
	}

	initVTPMServiceOnConfig(logger, App, config)

	if App != nil && App.DNSService != nil {
		config.DNSService = App.DNSService
		logger.Info("DNS service configured for daemon")
	}

	// Surface device + profile services into the daemon config so the BMC,
	// Device, and PXE gRPC services can resolve profile-backed configuration.
	// runWithWebservices wires these the same way; without them the daemon-only
	// path leaves bmc.Service with a nil profile store, so every profile-based
	// BMC operation reports ErrProfileNotFound.
	if App != nil {
		reg, err := App.ServiceRegistry()
		if err != nil {
			return err
		}
		if devSvc := reg.DeviceService(); devSvc != nil {
			config.DeviceService = devSvc
			logger.Info("device service wired for daemon gRPC")
		}
		if profileSvc := reg.ProfileService(); profileSvc != nil {
			config.DeviceProfileService = profileSvc
			logger.Info("device profile service wired for daemon gRPC")
		}
	}

	// A BMC configured for ACME needs a client before cert management runs.
	initACMEClientForCertManagement(ctx, logger, App)

	// Schedule certificate renewal on the daemon-only path too: a node with a
	// bmc: block and no webservices boots through here, and its BMC certificate
	// needs renewing just the same. Same ordering constraint as above — this must
	// follow the App.ServiceRegistry() call directly above it.
	initCertManagement(ctx, logger, App)

	ovsSocketPath := "/var/run/openvswitch/db.sock"
	if envPath := os.Getenv("SDN_OVS_SOCKET"); envPath != "" {
		ovsSocketPath = envPath
	}
	if _, statErr := os.Stat(ovsSocketPath); statErr == nil {
		config.OVSSocketPath = ovsSocketPath
		logger.Info("OVS socket detected, SDN service will be enabled", "path", ovsSocketPath)
	} else {
		logger.Info("OVS socket not found, SDN service will not be available", "path", ovsSocketPath)
	}

	computeOrchestrator, computeErr := newComputeOrchestrator(logger, App, config.OVSSocketPath, config.VTPMService)
	if computeErr != nil {
		logger.Info("Compute orchestrator not available (container operations will fail)",
			"reason", computeErr.Error())
	} else {
		config.ComputeOrchestrator = computeOrchestrator
		logger.Info("Compute orchestrator initialized successfully")
	}

	// M6 barrier-unseal gate: bind only the Unix socket + a loopback
	// /healthz + /init + /unseal HTTP listener and block until the
	// barrier is unsealed. Production transports (gRPC TCP, REST, QUIC,
	// MCP) are NOT bound while this runs. On a subsequent restart where
	// the barrier is already unsealed the gate returns immediately.
	if gateErr := invokeBarrierGate(ctx, App, logger); gateErr != nil {
		logger.Error(gateErr, "init-only mode gate failed")
		cmd.PrintErrln(fmt.Sprintf("init-only mode gate failed: %v", gateErr))
		return ErrServeStartup{Phase: "barrier gate", Cause: gateErr}
	}

	d, err := daemon.New(config)
	if err != nil {
		logger.Error(err, "Failed to create daemon")
		cmd.PrintErrln(fmt.Sprintf("Failed to create daemon: %v", err))
		return ErrServeStartup{Phase: "daemon creation", Cause: err}
	}

	if App != nil && App.TPM != nil {
		logger.Info("TPM available for IDevID/IAK operations")

		if App.TPMConfig.IDevID != nil && App.TPMConfig.IDevID.Handle != 0 {
			logger.Debug("IDevID handle configured", "handle", fmt.Sprintf("0x%08X", App.TPMConfig.IDevID.Handle))
		}
		if App.TPMConfig.IAK != nil && App.TPMConfig.IAK.Handle != 0 {
			logger.Debug("IAK handle configured", "handle", fmt.Sprintf("0x%08X", App.TPMConfig.IAK.Handle))
		}
	} else {
		logger.Info("TPM not available (IDevID/IAK operations will not be available)")
	}

	logger.Info("Starting platform daemon",
		"socket", serveSocketPath,
		"rest", fmt.Sprintf(":%d", serveRESTPort),
		"grpc", fmt.Sprintf(":%d", serveGRPCPort),
		"quic", fmt.Sprintf(":%d", serveQUICPort),
		"mcp", fmt.Sprintf(":%d", serveMCPPort),
	)

	if err := d.Start(ctx); err != nil {
		logger.Error(err, "Failed to start daemon")
		cmd.PrintErrln(fmt.Sprintf("Failed to start daemon: %v", err))
		return ErrServeStartup{Phase: "daemon start", Cause: err}
	}

	logger.Info("Platform daemon started successfully")
	cmd.Println("Platform daemon running. Press Ctrl+C to stop.")

	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutdown signal received")
	cmd.Println("\nShutting down...")

	if err := d.Stop(ctx); err != nil {
		logger.Error(err, "Error during shutdown")
	}

	logger.Info("Platform daemon stopped")
	cmd.Println("Platform daemon stopped.")

	// See runWithWebservices: the only clean exit, and it stays exit 0.
	return nil
}

// =============================================================================
// Daemon TLS identity provisioning (M5)
// =============================================================================

// ProvisionedIdentity describes the TLS material the daemon needs to bind
// remote transports. ServerCert is the in-memory cert+key for the daemon's
// gRPC TCP / QUIC / REST listeners; AdminTrustPool gates incoming mTLS
// client certificates; the *Path fields point at on-disk PEM bundles for
// operator pickup (admin-bundle.pem, server-bundle.pem, ca-bundle.crt).
type ProvisionedIdentity struct {
	ServerCert       tls.Certificate
	AdminTrustPool   *x509.CertPool
	ServerBundlePath string
	AdminBundlePath  string
	CABundlePath     string
	Reused           bool
}

// renewalThreshold is the minimum time-to-expiry below which a persisted
// daemon certificate is considered stale and re-issued. 30 days matches
// the convention used elsewhere in the platform for renewal headroom.
const renewalThreshold = 30 * 24 * time.Hour

// =============================================================================
// Typed errors
// =============================================================================

// ErrProvisionMissingSDK is returned when the quicbaas SDK client is nil.
// The SDK is the only authorised path for daemon cert issuance per §5d /
// §7 of 08-bootstrap-auth-architecture.md.
type ErrProvisionMissingSDK struct{}

// Error returns a human-readable description of the error.
func (ErrProvisionMissingSDK) Error() string {
	return "provisionDaemonIdentity: quicbaas SDK client is required"
}

// ErrProvisionMissingCA is returned when no CA trust-pool provider is
// supplied. Without it the daemon cannot validate persisted certs or
// configure the mTLS client trust pool.
type ErrProvisionMissingCA struct{}

// Error returns a human-readable description of the error.
func (ErrProvisionMissingCA) Error() string {
	return "provisionDaemonIdentity: CA trust pool provider is required"
}

// ErrProvisionIssue wraps a SDK certificate-issuance failure. The Cause
// retains the underlying SDK error for errors.Is / errors.As inspection.
type ErrProvisionIssue struct {
	Role  string
	Cause error
}

// Error returns a human-readable description of the error.
func (e ErrProvisionIssue) Error() string {
	return fmt.Sprintf("provisionDaemonIdentity: %s certificate issuance failed: %v", e.Role, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrProvisionIssue) Unwrap() error { return e.Cause }

// ErrTLSIdentityRequiresApp is returned when applyDaemonTLSIdentity is
// invoked without an initialized App while a TLS-terminating transport is
// enabled.
type ErrTLSIdentityRequiresApp struct{}

// Error returns a human-readable description of the error.
func (ErrTLSIdentityRequiresApp) Error() string {
	return "daemon TLS identity requires an initialized app"
}

// ErrTLSIdentityRequiresConfig is returned when applyDaemonTLSIdentity is
// invoked without a daemon config.
type ErrTLSIdentityRequiresConfig struct{}

// Error returns a human-readable description of the error.
func (ErrTLSIdentityRequiresConfig) Error() string {
	return "daemon TLS identity requires a daemon config"
}

// ErrTLSIdentityNotProvisioned is returned when identity provisioning
// reports success without producing an identity.
type ErrTLSIdentityNotProvisioned struct{}

// Error returns a human-readable description of the error.
func (ErrTLSIdentityNotProvisioned) Error() string {
	return "daemon TLS identity was not provisioned"
}

// ErrProvisionPersist wraps a disk-write failure for one of the on-disk
// bundles produced by the provisioner.
type ErrProvisionPersist struct {
	Path  string
	Cause error
}

// Error returns a human-readable description of the error.
func (e ErrProvisionPersist) Error() string {
	return fmt.Sprintf("provisionDaemonIdentity: failed to persist %s: %v", e.Path, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrProvisionPersist) Unwrap() error { return e.Cause }

// =============================================================================
// provisionDaemonIdentity
// =============================================================================

// provisionDaemonIdentity returns the daemon's TLS material, reusing a
// persisted bundle when valid (§8 #7) and otherwise issuing a fresh pair
// via the quicbaas SDK CertificateService (§5d / §7). The function never
// imports go-xkms directly: the platform CA is consumed via local
// interfaces (caTrustPoolProvider for the admin trust pool) and the SDK
// transport is provided by the caller.
//
// On success it writes:
//   - <dir>/server-bundle.pem  (cert + key, mode 0600)
//   - <dir>/client-bundle.pem  (admin cert + key, mode 0600)
//   - <dir>/ca-bundle.crt      (CA trust bundle, mode 0644)
//
// and populates ProvisionedIdentity. The daemon caller wires ServerCert
// into config.TLSCertificate / QUICConfig.TLSConfig.Certificates and
// AdminTrustPool into config.MTLSClientCAPool.
func provisionDaemonIdentity(
	ctx context.Context,
	logger *logging.Logger,
	issuer daemonCertIssuer,
	ca caTrustPoolProvider,
	outputDir string,
	sans daemonSANs,
) (*ProvisionedIdentity, error) {

	if ca == nil {
		return nil, ErrProvisionMissingCA{}
	}

	trustPool, err := ca.CABundleCertPool()
	if err != nil {
		return nil, ErrProvisionIssue{Role: "trust-pool", Cause: err}
	}

	serverBundlePath := filepath.Join(outputDir, "server-bundle.pem")
	adminBundlePath := filepath.Join(outputDir, "client-bundle.pem")
	caBundlePath := filepath.Join(outputDir, "ca-bundle.crt")

	dnsNames, ipStrings := daemonCertSANs(sans)

	// Reuse existing on-disk bundles when both are valid. The CA trust
	// pool is the single source of truth for chain verification.
	if reused, ok := loadPersistedIdentity(logger, serverBundlePath, adminBundlePath, caBundlePath, trustPool, dnsNames); ok {
		reused.AdminTrustPool = trustPool
		logger.Info("provisionDaemonIdentity: reusing persisted daemon identity",
			"server_bundle", serverBundlePath,
			"admin_bundle", adminBundlePath,
			"server_not_after", reused.ServerCert.Leaf.NotAfter.Format(time.RFC3339),
		)
		return reused, nil
	}

	if issuer == nil {
		return nil, ErrProvisionMissingSDK{}
	}

	// --- Server certificate (gRPC TCP / QUIC / REST listeners) ---------------
	serverReq := &certclient.IssueCertificateRequest{
		CommonName:   "platformd.localhost",
		Organization: "Trusted Platform",
		DNSNames:     dnsNames,
		IPAddresses:  ipStrings,
		Usage:        "server",
		KeyAlgorithm: "ecdsa",
		ValidityDays: 365,
	}
	serverResp, err := issuer.IssueCertificate(ctx, serverReq)
	if err != nil {
		return nil, ErrProvisionIssue{Role: "server", Cause: err}
	}

	serverCert, err := tlsCertificateFromPEM(serverResp.CertificatePEM, serverResp.PrivateKeyPEM)
	if err != nil {
		return nil, ErrProvisionIssue{Role: "server", Cause: err}
	}

	if err := writeBundle(serverBundlePath, serverResp.CertificatePEM, serverResp.PrivateKeyPEM, 0600); err != nil {
		return nil, ErrProvisionPersist{Path: serverBundlePath, Cause: err}
	}

	// --- Admin client certificate (one-shot per init: §8 #7) -----------------
	adminReq := &certclient.IssueCertificateRequest{
		CommonName:   "admin",
		Organization: "Trusted Platform",
		Usage:        "client",
		KeyAlgorithm: "ecdsa",
		ValidityDays: 365,
	}
	adminResp, err := issuer.IssueCertificate(ctx, adminReq)
	if err != nil {
		return nil, ErrProvisionIssue{Role: "admin", Cause: err}
	}

	if err := writeBundle(adminBundlePath, adminResp.CertificatePEM, adminResp.PrivateKeyPEM, 0600); err != nil {
		return nil, ErrProvisionPersist{Path: adminBundlePath, Cause: err}
	}

	// --- CA bundle (operator pickup) ----------------------------------------
	caResp, err := issuer.GetCABundle(ctx, &certclient.GetCABundleRequest{})
	if err != nil {
		return nil, ErrProvisionIssue{Role: "ca-bundle", Cause: err}
	}
	if err := os.WriteFile(caBundlePath, []byte(caResp.BundlePEM), 0644); err != nil {
		return nil, ErrProvisionPersist{Path: caBundlePath, Cause: err}
	}

	logger.Info("provisionDaemonIdentity: issued fresh daemon identity",
		"server_serial", serverResp.SerialNumber,
		"admin_serial", adminResp.SerialNumber,
		"server_not_after", serverResp.NotAfter.Format(time.RFC3339),
	)

	return &ProvisionedIdentity{
		ServerCert:       serverCert,
		AdminTrustPool:   trustPool,
		ServerBundlePath: serverBundlePath,
		AdminBundlePath:  adminBundlePath,
		CABundlePath:     caBundlePath,
		Reused:           false,
	}, nil
}

// daemonCertSANs composes the loopback + caller-supplied SAN sets into the
// SDK request shape (DNS names and string-form IP addresses).
func daemonCertSANs(extra daemonSANs) (dnsNames []string, ipStrings []string) {
	dnsNames = append(dnsNames, "localhost", "platformd.localhost")
	dnsNames = append(dnsNames, extra.DNS...)
	ipStrings = append(ipStrings, "127.0.0.1", "::1")
	ipStrings = append(ipStrings, extra.IPs...)
	return
}

// loadPersistedIdentity attempts to reuse an existing daemon identity from
// disk. The bundles must exist, be parseable, contain a non-expired cert
// (with renewalThreshold headroom), and the server cert's SAN set must
// still cover the supplied dnsNames. The chain is verified against the
// supplied trust pool.
func loadPersistedIdentity(
	logger *logging.Logger,
	serverBundlePath, adminBundlePath, caBundlePath string,
	trustPool *x509.CertPool,
	dnsNames []string,
) (*ProvisionedIdentity, bool) {

	serverCert, err := tlsCertificateFromFile(serverBundlePath)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Debug("provisionDaemonIdentity: server bundle invalid, will reissue",
				"path", serverBundlePath, "error", err.Error())
		}
		return nil, false
	}
	if !certWithinRenewalWindow(serverCert.Leaf, renewalThreshold) {
		logger.Debug("provisionDaemonIdentity: server bundle expired or near-expiry, will reissue",
			"path", serverBundlePath,
			"not_after", serverCert.Leaf.NotAfter.Format(time.RFC3339))
		return nil, false
	}
	if !certCoversDNSNames(serverCert.Leaf, dnsNames) {
		logger.Debug("provisionDaemonIdentity: server bundle SANs no longer cover required hostnames, will reissue",
			"path", serverBundlePath,
			"required", dnsNames,
			"present", serverCert.Leaf.DNSNames)
		return nil, false
	}
	if err := verifyChain(serverCert.Leaf, trustPool); err != nil {
		logger.Debug("provisionDaemonIdentity: server bundle chain invalid, will reissue",
			"path", serverBundlePath, "error", err.Error())
		return nil, false
	}

	adminCert, err := tlsCertificateFromFile(adminBundlePath)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Debug("provisionDaemonIdentity: admin bundle invalid, will reissue",
				"path", adminBundlePath, "error", err.Error())
		}
		return nil, false
	}
	if !certWithinRenewalWindow(adminCert.Leaf, renewalThreshold) {
		logger.Debug("provisionDaemonIdentity: admin bundle expired or near-expiry, will reissue",
			"path", adminBundlePath,
			"not_after", adminCert.Leaf.NotAfter.Format(time.RFC3339))
		return nil, false
	}
	if err := verifyChain(adminCert.Leaf, trustPool); err != nil {
		logger.Debug("provisionDaemonIdentity: admin bundle chain invalid, will reissue",
			"path", adminBundlePath, "error", err.Error())
		return nil, false
	}

	if _, err := os.Stat(caBundlePath); err != nil {
		// CA bundle is operator-facing; if missing we still reuse the
		// in-memory material but the caller will see an empty path.
		caBundlePath = ""
	}

	return &ProvisionedIdentity{
		ServerCert:       serverCert,
		ServerBundlePath: serverBundlePath,
		AdminBundlePath:  adminBundlePath,
		CABundlePath:     caBundlePath,
		Reused:           true,
	}, true
}

// tlsCertificateFromFile loads a PEM cert+key bundle (concatenated) from
// disk and returns the parsed tls.Certificate with Leaf populated.
func tlsCertificateFromFile(path string) (tls.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tlsCertificateFromBundle(pemBytes)
}

// tlsCertificateFromPEM parses PEM cert and key strings into a populated
// tls.Certificate. The Leaf is parsed for downstream callers.
func tlsCertificateFromPEM(certPEM, keyPEM string) (tls.Certificate, error) {
	bundle := append([]byte(certPEM), []byte(keyPEM)...)
	return tlsCertificateFromBundle(bundle)
}

// tlsCertificateFromBundle parses a single PEM blob containing one or more
// CERTIFICATE blocks followed by a key block.
func tlsCertificateFromBundle(pemBytes []byte) (tls.Certificate, error) {
	cert, err := tls.X509KeyPair(pemBytes, pemBytes)
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, errors.New("provisionDaemonIdentity: bundle contained no certificates")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	cert.Leaf = leaf
	return cert, nil
}

// writeBundle persists a single PEM cert+key bundle file with the given
// mode. The format (CERTIFICATE block(s) followed by an EC PRIVATE KEY
// block) is compatible with tls.LoadX509KeyPair(bundle, bundle).
func writeBundle(path, certPEM, keyPEM string, mode os.FileMode) error {
	bundle := bytesJoin(certPEM, keyPEM)
	return os.WriteFile(path, bundle, mode)
}

// bytesJoin concatenates two PEM strings, ensuring exactly one newline
// separator between them.
func bytesJoin(a, b string) []byte {
	out := []byte(a)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return append(out, []byte(b)...)
}

// certWithinRenewalWindow returns true when the certificate's NotAfter is
// at least `headroom` away from now (i.e., not expired and not due for
// renewal yet).
func certWithinRenewalWindow(leaf *x509.Certificate, headroom time.Duration) bool {
	if leaf == nil {
		return false
	}
	return time.Until(leaf.NotAfter) > headroom
}

// certCoversDNSNames returns true when every entry in required is present
// in the certificate's DNSNames SAN list. Empty required slices trivially
// match.
func certCoversDNSNames(leaf *x509.Certificate, required []string) bool {
	if leaf == nil {
		return false
	}
	if len(required) == 0 {
		return true
	}
	have := make(map[string]struct{}, len(leaf.DNSNames))
	for _, n := range leaf.DNSNames {
		have[n] = struct{}{}
	}
	for _, n := range required {
		if _, ok := have[n]; !ok {
			return false
		}
	}
	return true
}

// verifyChain verifies the leaf certificate against the supplied trust
// pool. Intermediates embedded in the bundle would normally feed
// VerifyOptions.Intermediates; the daemon pipeline currently relies on a
// flat root pool because the platform CA self-signs.
func verifyChain(leaf *x509.Certificate, roots *x509.CertPool) error {
	if leaf == nil {
		return errors.New("provisionDaemonIdentity: nil leaf certificate")
	}
	if roots == nil {
		return errors.New("provisionDaemonIdentity: nil trust pool")
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err
}

// isMultiInstanceDeployment reports whether several platformd instances
// serve one store — the shape the admin-claim ceremony cannot make safe,
// because its one-time state is process-local and SDK factor enrolment
// is not conditional (#170). The ceremony is refused when this is true.
//
// The signal is deliberately NOT "a raft address is configured".
// quicbaas.DefaultConfig() is an explicitly single-node configuration
// and still sets RaftAddress to a LOOPBACK address (127.0.0.1:63000),
// so keying off its presence would refuse the claim on the default
// deployment and strand the initial administrator — the exact failure
// this gate exists to avoid causing.
//
// What actually distinguishes the two shapes is reachability by peers:
//   - join-addresses set  -> this node joins peers; multi-instance.
//   - raft-address that is ROUTABLE (not loopback/unspecified) -> this
//     node advertises itself to peers, which is how the cluster
//     bootstrap member is configured (it has an EMPTY join-addresses
//     list, per configs/platform/cluster/README.md §Raft Bootstrap, so
//     join-addresses alone would miss exactly the node an operator
//     claims from).
//   - loopback/empty raft-address and no join-addresses -> single node.
func isMultiInstanceDeployment(cfg *platformquicbaas.Config) bool {
	if cfg == nil {
		return false
	}
	if len(cfg.JoinAddresses) > 0 {
		return true
	}
	return isRoutableRaftAddress(cfg.RaftAddress)
}

// isRoutableRaftAddress reports whether addr advertises this node to
// peers on the network, as opposed to the loopback/unspecified defaults
// a single-node deployment carries. A host that cannot be parsed is
// treated as routable: an unparseable advertise address is not evidence
// of a single-node deployment, and this gate fails closed.
func isRoutableRaftAddress(addr string) bool {
	if strings.TrimSpace(addr) == "" {
		return false
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsLoopback() && !ip.IsUnspecified()
	}
	return true
}
