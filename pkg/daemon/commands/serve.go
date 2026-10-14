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
	"log"
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
	appbackends "github.com/jeremyhahn/go-trusted-platform/pkg/app/backends"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	_ "github.com/jeremyhahn/go-trusted-platform/pkg/compute/container" // registers the local-container orchestrator factory
	"github.com/jeremyhahn/go-trusted-platform/pkg/log/jsonfile"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
	platformrest "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/platform"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	acmequicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/acme/storage/quicbaas"
	tpconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
	platformquicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

var (
	serveSocketPath string
	serveEnableREST bool
	serveEnableGRPC bool
	serveEnableQUIC bool
	serveEnableMCP  bool
	serveSkipIAM    bool
	serveEnableMTLS bool
)

func init() {
	serveCmd.Flags().StringVar(&serveSocketPath, "socket-path", "/run/platformd.sock", "Unix socket path")
	// The transports' bind hosts and ports are config, not flag literals
	// (#552, #93): --<transport>-bind-host / --<transport>-port here, the
	// `daemon:` section in the file, PLATFORMD_DAEMON_* in the environment,
	// and loopback on the canonical ports as the defaults layer. A flag left
	// alone falls through; it never shadows the file or the environment.
	tpconfig.SetDaemonListenerDefaults(viper.GetViper())
	if err := tpconfig.BindDaemonListenerFlags(viper.GetViper(), serveCmd.Flags()); err != nil {
		log.Fatal(err)
	}
	// The Raft advertise and listen addresses take the same three paths
	// (quicbaas.raft-address / raft-listen-address, PLATFORMD_QUICBAAS_RAFT_*,
	// --raft-address / --raft-listen-address); quicbaas.Config.Validate
	// refuses a joining node without a routable advertise address.
	if err := tpconfig.BindRaftAddressFlags(viper.GetViper(), serveCmd.Flags()); err != nil {
		log.Fatal(err)
	}
	serveCmd.Flags().BoolVar(&serveEnableREST, "enable-rest", true, "Enable REST API (daemon-only mode: requires --enable-mtls, its only authentication; refused otherwise)")
	serveCmd.Flags().BoolVar(&serveEnableGRPC, "enable-grpc", true, "Enable gRPC")
	serveCmd.Flags().BoolVar(&serveEnableQUIC, "enable-quic", true, "Enable QUIC")
	serveCmd.Flags().BoolVar(&serveEnableMCP, "enable-mcp", true, "Enable MCP")
	serveCmd.Flags().BoolVar(&serveSkipIAM, "skip-iam-validation", false, "Skip IAM validation (testing only)")
	serveCmd.Flags().BoolVar(&serveEnableMTLS, "enable-mtls", false, "Enable mutual TLS authentication")
}

// resolveDaemonListeners reads the transports' bind hosts and ports through
// viper — flags > env > file > defaults — and turns an invalid value into
// the serve command's startup error so the operator sees which
// daemon.<transport> field is wrong instead of a listener that never opens.
func resolveDaemonListeners(cmd *cobra.Command) (tpconfig.DaemonListeners, error) {
	listeners, err := tpconfig.ResolveDaemonListeners(viper.GetViper())
	if err != nil {
		cmd.PrintErrln(fmt.Sprintf("Invalid daemon listener configuration: %v", err))
		return tpconfig.DaemonListeners{}, ErrServeStartup{Phase: "daemon listener configuration", Cause: err}
	}
	return listeners, nil
}

// applyDaemonListeners writes the resolved listener addresses into cfg. It
// is the one place either serve path sets a transport address, so the
// `daemon:` section (file, env, flag) always reaches the listeners and no
// path can pin a literal over it (#93). REST is written only when the
// daemon serves it: in webservice mode the webservice owns REST and its
// own bind host. Call it after cfg.QUICConfig is built so the QUIC
// server's own address matches.
func applyDaemonListeners(cfg *daemon.Config, listeners tpconfig.DaemonListeners) {
	if cfg.EnableREST {
		cfg.RESTListenAddr = listeners.REST.Address()
	}
	cfg.GRPCListenAddr = listeners.GRPC.Address()
	cfg.QUICListenAddr = listeners.QUIC.Address()
	if cfg.QUICConfig != nil {
		cfg.QUICConfig.ListenAddr = listeners.QUIC.Address()
	}
	if cfg.MCPConfig == nil {
		cfg.MCPConfig = daemon.DefaultMCPConfig()
	}
	cfg.MCPConfig.HTTPAddr = listeners.MCP.Address()
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
			applyLocalQEMUSettings(computeConfig, a.ComputeConfig)
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

// applyLocalQEMUSettings copies the operator's `compute:` settings for the
// local QEMU provider over dst, which already holds the defaults layer
// (ApplyLocalQEMUDefaults). An unset field keeps its default.
func applyLocalQEMUSettings(dst, src *compute.OrchestratorConfig) {
	if src.QEMUBinary != "" {
		dst.QEMUBinary = src.QEMUBinary
	}
	if src.OVMFCode != "" {
		dst.OVMFCode = src.OVMFCode
	}
	if src.OVMFCodeSecure != "" {
		dst.OVMFCodeSecure = src.OVMFCodeSecure
	}
	if src.OVMFVars != "" {
		dst.OVMFVars = src.OVMFVars
	}
	if src.WorkDir != "" {
		dst.WorkDir = src.WorkDir
	}
	if src.NetworkBridge != "" {
		dst.NetworkBridge = src.NetworkBridge
	}
	if src.EnableKVM {
		dst.EnableKVM = true
	}
	if src.DefaultMemory > 0 {
		dst.DefaultMemory = src.DefaultMemory
	}
	if src.DefaultCPUs > 0 {
		dst.DefaultCPUs = src.DefaultCPUs
	}
	if src.MigrationListenAddress != "" {
		dst.MigrationListenAddress = src.MigrationListenAddress
	}
	dst.SharedStorage = src.SharedStorage
}

// seedSDNVLANsFromConfig walks the zones of the network plan and calls
// SeedVLAN on the running SDN service for each zone VLAN. The bridge name +
// UUID come from the live OVS state so the seeded entries link back to the
// actual bridge the operator's bond materialized.
//
// SeedVLAN registers the VLAN in the in-memory map only; port-tag
// application still happens via CreateVLAN or a future controller.
// This shortest-path reconciliation makes the Networking → VLANs page
// list the environment's zone VLANs after a deploy.
func seedSDNVLANsFromConfig(logger *logging.Logger, a *app.App, sdnSvc *daemon.SDNService) {
	if a == nil || sdnSvc == nil {
		return
	}
	if a.SDNConfig == nil || a.SDNConfig.Plan() == nil {
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

	for _, z := range a.SDNConfig.Plan().Zones() {
		if _, err := sdnSvc.SeedVLAN(bridgeName, bridgeID, uint32(z.VLAN), string(z.Zone)); err != nil {
			logger.Warn("SDN VLAN seeding: SeedVLAN failed",
				"zone", z.Zone, "vlan", z.VLAN, "error", err)
			continue
		}
		logger.Info("SDN VLAN seeded from the network plan",
			"zone", z.Zone, "vlan", z.VLAN, "bridge", bridgeName)
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

// applyDaemonTLSIdentity provisions the daemon's mTLS material via the
// quicbaas SDK CertificateService and binds it to the supplied
// daemon.Config so that gRPC TCP, QUIC, REST and MCP HTTP listeners present a
// CA-signed server certificate (and optionally require client mTLS).
//
// Both runDaemonOnly and runWithWebservices call this helper so the gRPC
// TCP listener never falls back to plaintext when webservices are enabled.
// The provisioner reuses on-disk bundles when valid, otherwise issues
// fresh ones; on issuance failure the daemon continues without a server
// cert (the gRPC listener will start without TLS, surfacing the error to
// remote clients) so the platform stays observable rather than failing
// to come up entirely.
func applyDaemonTLSIdentity(ctx context.Context, logger *logging.Logger, a *app.App, cfg *daemon.Config, requireClientCert bool) error {
	// Fail closed (#32): a daemon that will terminate TLS on a network
	// transport either gets a provisioned identity or refuses to start.
	// The one carve-out is Unix-domain-socket-only mode — filesystem-
	// permission-scoped, not network-exposed — which needs no identity.
	// MCP over HTTP terminates TLS too (#844); MCP over stdio does not.
	if cfg != nil && !cfg.EnableGRPCTCP && !cfg.EnableQUIC && !cfg.EnableREST && !cfg.MCPServesHTTP() {
		logger.Info("Daemon TLS identity skipped: no TLS-terminating transport enabled (UDS-only mode)")
		return nil
	}
	switch {
	case a == nil:
		return ErrTLSIdentityRequiresApp{}
	case cfg == nil:
		return ErrTLSIdentityRequiresConfig{}
	case a.PlatformDir == "":
		return ErrTLSIdentityRequiresPlatformDir{}
	case a.CA == nil:
		return ErrProvisionMissingCA{}
	}
	// The server key lives in the CA keystore (#33). Only the public CA
	// bundle is written, under <platform-dir>/tls.
	tlsDir := daemonTLSDir(a.PlatformDir)
	if mkErr := os.MkdirAll(tlsDir, 0700); mkErr != nil {
		return ErrProvisionPersist{Path: tlsDir, Cause: mkErr}
	}
	sans := daemonServerSANs(a)
	identity, mtlsErr := provisionDaemonIdentity(ctx, logger, a.CA, tlsDir, sans)
	if mtlsErr != nil {
		return mtlsErr
	}
	if identity == nil {
		// provisionDaemonIdentity returning (nil, nil) is an internal
		// contract violation; treat it as a missing identity, not success.
		return ErrProvisionIssue{Role: "server", Cause: ErrTLSIdentityNotProvisioned{}}
	}
	// Only a binary built with the integration tag sets this hook: the
	// devcontainer harness has no /init step, so it takes its admin
	// credential from here. A production binary mints no admin key.
	if harnessAdminBundle != nil {
		issuer := appbackends.PlatformCertIssuer(a.CA, a.QuicBaaSSDKClient())
		if harnessErr := harnessAdminBundle(ctx, logger, issuer, tlsDir); harnessErr != nil {
			return harnessErr
		}
	}
	// Every TLS listener reads the identity through serving at handshake
	// time, so the renewal sweep can replace it while they run (#36).
	serving, servingErr := daemon.NewServingCertificate(identity.ServerCert)
	if servingErr != nil {
		return ErrProvisionIssue{Role: "server", Cause: servingErr}
	}
	cfg.TLSIdentity = serving
	cfg.MTLSClientCAPool = identity.AdminTrustPool
	cfg.MTLSClientCAFile = identity.CABundlePath
	if cfg.QUICConfig != nil && cfg.QUICConfig.TLSConfig != nil {
		// Certificates stays empty: crypto/tls prefers it over
		// GetCertificate when a client sends no SNI.
		cfg.QUICConfig.TLSConfig.Certificates = nil
		cfg.QUICConfig.TLSConfig.GetCertificate = serving.GetCertificate
	}
	cfg.EnableMTLS = requireClientCert
	dnsNames, ipStrings := daemonCertSANs(sans)
	target := daemonIdentityCertTarget(logger, a.CA, serving, dnsNames, ipStrings)
	if regErr := a.RegisterCertTarget(target); regErr != nil {
		// Not fatal: the identity serves; it just renews at the next
		// restart instead of while running.
		logger.Warn("cert renewal: cannot register the daemon TLS identity cert target; "+
			"it will not renew while running, only at the next restart",
			"target", daemonIdentityCertTargetName, "error", regErr.Error())
	}
	logger.Info("Daemon TLS identity provisioned",
		"server_key", "ca-keystore:"+identity.ServerCert.Leaf.Subject.CommonName,
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

gRPC TCP needs --enable-mtls unless platform tokens are enabled (webservice
jwt.platform-token) or quicbaas runs remotely: the embedded SDK cannot answer
the IAM policy checks plain tokens rely on, so the daemon refuses to start.

Example:
  platformd serve --enable-mtls
  platformd serve --enable-mtls --socket-path=/run/platformd.sock --rest-port=8443
  platformd serve --enable-mtls --enable-quic=false --enable-mcp=false
  platformd serve --enable-grpc=false --enable-rest=false
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
		// <LogDir>/jsonl/. Everything built from here on takes the teed
		// logger, or its records never reach the console Logs page.
		var jsonlQuerier *jsonfile.Querier
		logger, jsonlQuerier = installJSONLLogging(App, logger)

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

	if err := App.LoadOrInitCA(ctx, InitParams); err != nil {
		logger.Error(err, "runWithWebservices: CA unavailable")
		cmd.PrintErrln(err)
		return ErrServeStartup{Phase: "CA initialization", Cause: err}
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

	listeners, err := resolveDaemonListeners(cmd)
	if err != nil {
		return err
	}

	// The webservice serves REST in this mode, on its own bind host.
	daemonConfig.EnableREST = false
	daemonConfig.EnableGRPCTCP = serveEnableGRPC
	daemonConfig.EnableQUIC = serveEnableQUIC
	daemonConfig.EnableMCP = serveEnableMCP
	if serveEnableQUIC {
		quicConfig, quicErr := quic.DefaultServerConfigWithTLS()
		if quicErr != nil {
			logger.Error(quicErr, "Failed to generate QUIC TLS configuration")
			cmd.PrintErrln(fmt.Sprintf("Failed to generate QUIC TLS configuration: %v", quicErr))
			return ErrServeStartup{Phase: "QUIC TLS configuration", Cause: quicErr}
		}
		daemonConfig.QUICConfig = quicConfig
		logger.Debug("QUIC TLS configuration generated with self-signed certificate")
	}

	applyDaemonListeners(daemonConfig, listeners)

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
		if templateSvc := reg.TemplateService(); templateSvc != nil {
			daemonConfig.DeviceTemplateService = templateSvc
			logger.Info("device template service wired for daemon gRPC")
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

	// The platform tenant.Manager behind every tenant transport (and the
	// dashboard's GET /api/v1/tenants/{id}, which otherwise renders 400
	// "tenant manager not initialized" on every page load).
	daemonConfig.PlatformTenantManager = platformTenantManager(logger, App)

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

	// Attestation backend, quarantine observer, caller policy and reporting
	// collector: built by the one helper both run paths call (#544). The
	// REST-only consumers below read the services, the SDN policy and the
	// REST reporting surface back out of it.
	attestation := wireAttestationOnConfig(ctx, logger, App, daemonConfig)
	defer attestation.Stop()
	attestationSvcs := attestation.Services
	sdnPolicy := attestation.SDNPolicy
	reportingRest := attestation.ReportingRest

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
	if err := appbackends.WireSDKBackends(platformDaemon, platformSDKBackendSources(App), logger); err != nil {
		logger.Error(err, "Failed to wire the SDK backends")
		cmd.PrintErrln(fmt.Sprintf("Failed to wire the SDK backends: %v", err))
		return ErrServeStartup{Phase: "SDK backends", Cause: err}
	}

	// The gateway telemetry store backs the snapshot RPCs on every
	// transport, so the control plane answers `GetGatewaySnapshot` from the
	// same reports POST /gateway/telemetry writes (#594).
	if gwControl != nil && gwControl.Store != nil {
		if svc := platformDaemon.GatewayGRPCService(); svc != nil {
			svc.SetGatewaySnapshotStore(gwControl.Store)
		}
		// VPN session status reads the vpn section of the same reports.
		// The enrolment set and the posture policies reach the gateways as
		// the vpn section of their desired configuration.
		if vpnControl := platformDaemon.VPNControlPlane(); vpnControl != nil {
			vpnControl.SetGatewaySnapshotStore(gwControl.Store)
			if gwControl.DesiredCfg != nil {
				gwControl.DesiredCfg.SetVPNSource(vpnControl)
			}
		}
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
			AdminEmail:                App.AdminEmail,
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
				params.AttestationVerdicts = svc
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
			if svc := platformDaemon.VPNGRPCServiceServer(); svc != nil {
				params.VPNServiceServer = svc
			}
			params.AppServiceServers = platformDaemon.AppServiceRESTServers()
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
			// The gateways write their VPN leases through to the same
			// service that renders them back in the desired configuration.
			if vpnControl := platformDaemon.VPNControlPlane(); vpnControl != nil {
				params.GatewayVPNLeases = vpnControl
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
		"grpc", listeners.GRPC.Address(),
		"quic", listeners.QUIC.Address(),
		"mcp", listeners.MCP.Address(),
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

	listeners, err := resolveDaemonListeners(cmd)
	if err != nil {
		return err
	}

	config.EnableREST = serveEnableREST
	config.EnableGRPCTCP = serveEnableGRPC
	config.EnableQUIC = serveEnableQUIC
	config.EnableMCP = serveEnableMCP
	if serveEnableQUIC {
		quicConfig, quicErr := quic.DefaultServerConfigWithTLS()
		if quicErr != nil {
			logger.Error(quicErr, "Failed to generate QUIC TLS configuration")
			cmd.PrintErrln(fmt.Sprintf("Failed to generate QUIC TLS configuration: %v", quicErr))
			return ErrServeStartup{Phase: "QUIC TLS configuration", Cause: quicErr}
		}
		config.QUICConfig = quicConfig
		logger.Debug("QUIC TLS configuration generated with self-signed certificate")
	}

	applyDaemonListeners(config, listeners)

	if err := daemon.AttachNodeCA(ctx, config, InitParams); err != nil {
		logger.Warn("CA will not be available", "error", err)
	} else {
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

	// The same platform tenant.Manager the webservices path wires: without
	// it a daemon-only node registers TenantService but cannot serve it.
	config.PlatformTenantManager = platformTenantManager(logger, App)

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
		if templateSvc := reg.TemplateService(); templateSvc != nil {
			config.DeviceTemplateService = templateSvc
			logger.Info("device template service wired for daemon gRPC")
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

	// The OCI registry and the attestation backend are served over gRPC,
	// Unix and MCP on this path too. Without them daemon.New registers a
	// dark registry and the attestation stub, whose every RPC answers
	// FailedPrecondition (#544). Same helpers as runWithWebservices.
	initRegistryServiceOnConfig(logger, App, config)
	attestation := wireAttestationOnConfig(ctx, logger, App, config)
	defer attestation.Stop()

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
	if err := appbackends.WireSDKBackends(d, platformSDKBackendSources(App), logger); err != nil {
		logger.Error(err, "Failed to wire the SDK backends")
		cmd.PrintErrln(fmt.Sprintf("Failed to wire the SDK backends: %v", err))
		return ErrServeStartup{Phase: "SDK backends", Cause: err}
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
		"rest", listeners.REST.Address(),
		"grpc", listeners.GRPC.Address(),
		"quic", listeners.QUIC.Address(),
		"mcp", listeners.MCP.Address(),
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
// remote transports. ServerCert is the daemon's gRPC TCP / QUIC / REST / MCP
// HTTP server certificate; its PrivateKey is the CA keystore's crypto.Signer,
// so the server key never leaves the keystore (#33). AdminTrustPool gates
// incoming mTLS client certificates. CABundlePath points at the public CA
// bundle under <platform-dir>/tls for operator pickup. There is no admin
// bundle: the one-shot /init reply is the only admin credential. Reused
// reports that the keystore already held a current server certificate.
type ProvisionedIdentity struct {
	ServerCert     tls.Certificate
	AdminTrustPool *x509.CertPool
	CABundlePath   string
	Reused         bool
}

// daemonTLSDirName is the directory, under the platform directory, that
// holds the public CA bundle. The server key stays in the CA keystore.
const daemonTLSDirName = "tls"

// daemonTLSDir returns where the daemon persists its TLS bundles.
func daemonTLSDir(platformDir string) string {
	return filepath.Join(platformDir, daemonTLSDirName)
}

// harnessAdminBundleFunc mints an admin client bundle into dir.
type harnessAdminBundleFunc func(ctx context.Context, logger *logging.Logger, issuer appbackends.CertIssuer, dir string) error

// harnessAdminBundle is nil in every production build. Only the
// integration build tag sets it (harness_admin_bundle_integration.go).
var harnessAdminBundle harnessAdminBundleFunc

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

// ErrTLSIdentityRequiresPlatformDir is returned when the app has no
// platform directory to hold the public CA bundle.
type ErrTLSIdentityRequiresPlatformDir struct{}

// Error returns a human-readable description of the error.
func (ErrTLSIdentityRequiresPlatformDir) Error() string {
	return "daemon TLS identity requires a platform directory"
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

// ErrTLSIdentityKeystore is returned when the CA keystore that holds the
// daemon's server key cannot issue, supersede or load the server identity.
// The daemon starts no TLS listener without it.
type ErrTLSIdentityKeystore struct {
	Op    string
	Cause error
}

// Error returns a human-readable description of the error.
func (e ErrTLSIdentityKeystore) Error() string {
	return fmt.Sprintf("daemon TLS identity: keystore %s failed: %v", e.Op, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrTLSIdentityKeystore) Unwrap() error { return e.Cause }

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

// writeBundle persists a single PEM cert+key bundle file with the given
// mode. The format (CERTIFICATE block(s) followed by an EC PRIVATE KEY
// block) is compatible with tls.LoadX509KeyPair(bundle, bundle).
// bytesJoin concatenates two PEM strings, ensuring exactly one newline
// separator between them.
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
	return platformquicbaas.IsRoutableRaftAddress(cfg.RaftAddress)
}
