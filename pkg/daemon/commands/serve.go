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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	noiseapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/noise"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/webauthn"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"

	trustedca "github.com/jeremyhahn/go-trusted-ca/sdk/go"
	acmequicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/acme/storage/quicbaas"
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
	serveCmd.Flags().BoolVar(&serveEnableREST, "enable-rest", true, "Enable REST API")
	serveCmd.Flags().BoolVar(&serveEnableGRPC, "enable-grpc", true, "Enable gRPC")
	serveCmd.Flags().BoolVar(&serveEnableQUIC, "enable-quic", true, "Enable QUIC")
	serveCmd.Flags().BoolVar(&serveEnableMCP, "enable-mcp", true, "Enable MCP")
	serveCmd.Flags().BoolVar(&serveSkipIAM, "skip-iam-validation", false, "Skip IAM validation (testing only)")
	serveCmd.Flags().BoolVar(&serveEnableMTLS, "enable-mtls", false, "Enable mutual TLS authentication")
}

// enroll01CAAdapter wraps the CA to satisfy the trustedca.ACMECertificateAuthority interface
type enroll01CAAdapter struct {
	ca trustedca.CACertificateAuthority
}

func (a *enroll01CAAdapter) VerifyTCG_CSR_IDevIDBytes(packedCSR []byte, sigAlg interface{}) ([]byte, []byte, []byte, error) {
	return a.ca.VerifyTCG_CSR_IDevIDBytes(packedCSR, sigAlg)
}

func (a *enroll01CAAdapter) DefaultSignatureAlgorithm() x509.SignatureAlgorithm {
	return a.ca.DefaultSignatureAlgorithm()
}

// buildChallengeMap creates a challenge verifier map from configured challenge types.
// Each challenge type (e.g., "http-01", "dns-01", "enroll-01") is mapped to its
// corresponding verifier function that performs the ACME challenge validation.
func buildChallengeMap(challenges []string, ca trustedca.CACertificateAuthority) map[string]trustedca.ACMEChallengeVerifierFunc {
	challengeMap := make(map[string]trustedca.ACMEChallengeVerifierFunc)

	// Create adapter for enroll-01 challenge
	enroll01CA := &enroll01CAAdapter{ca: ca}

	for _, challengeType := range challenges {
		switch challengeType {
		case "http-01":
			challengeMap["http-01"] = func(resolver *net.Resolver, caInterface trustedca.ACMECertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
				return trustedca.ACMEVerifyHTTP01(resolver, nil, authzValue, challengePort, challengeToken, expectedKeyAuth)
			}
		case "dns-01":
			challengeMap["dns-01"] = func(resolver *net.Resolver, caInterface trustedca.ACMECertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
				return trustedca.ACMEVerifyDNS01(resolver, nil, authzValue, challengePort, challengeToken, expectedKeyAuth)
			}
		case "enroll-01":
			challengeMap["enroll-01"] = func(resolver *net.Resolver, caInterface trustedca.ACMECertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
				return trustedca.ACMEVerifyEnroll01(resolver, enroll01CA, authzValue, challengePort, challengeToken, expectedKeyAuth)
			}
		case "endorse-01":
			// endorse-01 is used to provision EK certificates for TPMs without manufacturer certs
			// The verification is handled by EAB and server policy, so the verifier returns nil
			challengeMap["endorse-01"] = func(resolver *net.Resolver, caInterface trustedca.ACMECertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
				return trustedca.ACMEVerifyEndorse01(resolver, nil, authzValue, challengePort, challengeToken, expectedKeyAuth)
			}
		}
	}

	return challengeMap
}

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
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()
		sigChan := make(chan os.Signal, 1)

		// Initialize logging - will be replaced with App.Logger if available
		level := slog.LevelInfo
		if InitParams.Debug {
			level = slog.LevelDebug
		}
		logger := logging.NewLogger(level, nil)

		// Initialize the app. Errors here are FATAL — the daemon will not
		// run in a "limited functionality" mode where critical services
		// (CA, key store, DNSSEC signing) are silently broken. Previous
		// behaviour logged the failure and proceeded to start webservices
		// and subsystems that depend on App.CA / platform key store, which
		// then produced confusing second-order errors in every caller.
		// Removed 2026-04-08 on operator demand: no silent fallbacks.
		var appErr error
		if _, appErr = App.Init(InitParams); appErr != nil {
			if errors.Is(appErr, xkmssdk.ErrTPMNotInitialized) {
				logger.Info("Platform not initialized, auto-provisioning...")
				InitParams.Initialize = true
				if _, appErr = App.Init(InitParams); appErr != nil {
					logger.Error(appErr, "App initialization FAILED during auto-provisioning")
					cmd.PrintErrln(fmt.Sprintf("FATAL: App initialization failed during auto-provisioning: %v", appErr))
					os.Exit(2)
				}
				logger.Info("Platform provisioned successfully")
			} else {
				logger.Error(appErr, "App initialization FAILED")
				cmd.PrintErrln(fmt.Sprintf("FATAL: App initialization failed: %v", appErr))
				os.Exit(2)
			}
		}

		// Use App.Logger if available
		if App != nil && App.Logger != nil {
			logger = App.Logger
		}

		// First-run escrow consumer: if platform-initrd staged a LUKS
		// recovery passphrase at /run/platform/firstboot-handoff/recovery.key
		// (recovery-key-strategy=escrow), pull it into the tenant secret
		// store and shred the tmpfs copy. Non-fatal: any failure is
		// logged but does not block daemon startup, because the operator
		// can always recover via the TPM-sealed LUKS slot.
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

		// Bootstrap self-registration: if the kernel cmdline contains
		// platform_debug_sink=<host:port>, POST this node's runtime state
		// (hostname, IP, MAC) to the bootstrap server so the orchestrator
		// can discover it for health checks. Non-blocking: runs in a
		// background goroutine with a 10-second timeout.
		if App != nil && appErr == nil {
			App.RunBootstrapRegistration()
		}

		// Check if webservices are configured
		webservicesEnabled := App != nil && len(App.WebServices) > 0

		// Debug logging for webservice mode decision
		logger.Info("Webservice mode check",
			"app_not_nil", App != nil,
			"webservices_count", len(App.WebServices),
			"webservices_enabled", webservicesEnabled)

		if webservicesEnabled {
			// Webservices mode: requires CA, full REST API stack
			logger.Info("Starting webservices mode")
			runWithWebservices(cmd, ctx, sigChan, logger)
		} else {
			// Daemon-only mode: can run without CA
			// Also used in test mode to skip CA/IAM dependencies
			logger.Info("Starting daemon-only mode", "app_err", appErr)
			runDaemonOnly(cmd, ctx, sigChan, logger, appErr)
		}
	},
}

// runWithWebservices starts the platform with full webservice support (ACME, WebAuthn, JWT).
// This mode requires the CA to be initialized.
func runWithWebservices(cmd *cobra.Command, ctx context.Context, sigChan chan os.Signal, logger *logging.Logger) {
	logger.Info("runWithWebservices: starting CA initialization")

	// CA is required for webservices
	if App.CA == nil {
		logger.Info("runWithWebservices: CA is nil, parsing PINs")
		soPIN, userPIN, err := App.ParsePINs(InitParams.SOPin, InitParams.Pin)
		if err != nil {
			logger.Error(err, "runWithWebservices: PIN parsing failed")
			cmd.PrintErrln(err)
			return
		}
		logger.Info("runWithWebservices: loading CA")
		// Try to load existing CA first
		if err := App.LoadCA(soPIN, userPIN); err != nil {
			// If CA doesn't exist (not initialized), try to initialize it
			logger.Warn("CA not found, attempting to initialize", "error", err)
			if _, initErr := App.InitCA(soPIN, userPIN, InitParams); initErr != nil {
				logger.Error(initErr)
				cmd.PrintErrln(fmt.Sprintf("Failed to load or initialize CA: load error: %v, init error: %v", err, initErr))
				return
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
		if err := App.InitWebServer(); err != nil {
			logger.Error(err, "runWithWebservices: InitWebServer failed")
			cmd.PrintErrln(err)
			return
		}
		logger.Info("runWithWebservices: web server initialized successfully")
	} else {
		logger.Info("runWithWebservices: web service key attributes already set")
	}

	// Create ACME storage using QuicBaaS ObjectStorage from the app's storage client
	acmeDAOFactory, err := acmequicbaas.NewFactory(App.Storage)
	if err != nil {
		logger.Error(err)
		cmd.PrintErrln(err)
		return
	}

	// Create and start the Unix socket daemon for platformctl communication
	daemonConfig := daemon.DefaultConfig()
	daemonConfig.App = App
	daemonConfig.Logger = logger
	daemonConfig.SocketPath = serveSocketPath
	daemonConfig.SocketGroup = "" // Don't require specific group

	// Disable daemon's REST server when webservices are enabled to avoid port
	// conflicts (webservices use 8443 for TLS). Keep gRPC enabled on alternate
	// port for CLI commands that require streaming RPCs (e.g., db dump).
	daemonConfig.EnableREST = false
	daemonConfig.EnableGRPCTCP = serveEnableGRPC
	daemonConfig.GRPCListenAddr = fmt.Sprintf("0.0.0.0:%d", serveGRPCPort)

	// QUIC configuration - still available for webservice mode
	daemonConfig.EnableQUIC = serveEnableQUIC
	daemonConfig.QUICListenAddr = fmt.Sprintf("0.0.0.0:%d", serveQUICPort)
	if serveEnableQUIC {
		quicConfig, quicErr := quic.DefaultServerConfigWithTLS()
		if quicErr != nil {
			logger.Error(quicErr, "Failed to generate QUIC TLS configuration")
			cmd.PrintErrln(fmt.Sprintf("Failed to generate QUIC TLS configuration: %v", quicErr))
			return
		}
		quicConfig.ListenAddr = fmt.Sprintf("0.0.0.0:%d", serveQUICPort)
		daemonConfig.QUICConfig = quicConfig
		logger.Debug("QUIC TLS configuration generated with self-signed certificate")
	}

	// MCP configuration
	daemonConfig.EnableMCP = serveEnableMCP
	if daemonConfig.MCPConfig == nil {
		daemonConfig.MCPConfig = daemon.DefaultMCPConfig()
	}
	daemonConfig.MCPConfig.HTTPAddr = fmt.Sprintf("127.0.0.1:%d", serveMCPPort)

	// Configure SDN service if OVS socket is available
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

	// Create Compute Orchestrator for container/VM operations
	computeConfig := &compute.OrchestratorConfig{
		Type:            compute.ComputeTypeContainer,
		MaxInstances:    100,
		Debug:           InitParams.Debug,
		WorkDir:         "/var/lib/platformd/compute",
		DefaultMemory:   512,
		DefaultCPUs:     1,
		DefaultDiskSize: "10G",
	}
	computeOrchestrator, computeErr := compute.NewContainerOrchestrator(computeConfig, logger)
	if computeErr != nil {
		logger.Info("Compute orchestrator not available (container operations will fail)",
			"reason", computeErr.Error())
	} else {
		daemonConfig.ComputeOrchestrator = computeOrchestrator
		logger.Info("Compute orchestrator initialized successfully")
	}

	// Wire DNS service if available
	if App != nil && App.DNSService != nil {
		daemonConfig.DNSService = App.DNSService
		logger.Info("DNS service configured for daemon")
	}

	platformDaemon, err := daemon.New(daemonConfig)
	if err != nil {
		logger.Error(err, "Failed to create platform daemon")
		cmd.PrintErrln(fmt.Sprintf("Failed to create platform daemon: %v", err))
		return
	}

	// Start the daemon (Unix socket server)
	if err := platformDaemon.Start(ctx); err != nil {
		logger.Error(err, "Failed to start platform daemon")
		cmd.PrintErrln(fmt.Sprintf("Failed to start platform daemon: %v", err))
		return
	}
	logger.Info("Platform daemon started", "socket", platformDaemon.SocketPath())

	// Start all configured webservices
	var wg sync.WaitGroup
	for _, wsConfig := range App.WebServices {
		wg.Add(1)

		wsName := wsConfig.Name
		if wsName == "" {
			wsName = "default"
		}
		logger.Info("Starting webservice", "name", wsName, "port", wsConfig.Port, "tls-port", wsConfig.TLSPort)

		// Retrieve key attributes from the map (populated by InitWebServer)
		wsKeyAttrs := App.WebServiceKeyAttributes[wsName]
		if wsKeyAttrs == nil {
			logger.Error(fmt.Errorf("key attributes not found"), "Failed to get key attributes for webservice", "name", wsName)
			cmd.PrintErrln(fmt.Sprintf("Failed to get key attributes for webservice %s: key attributes not initialized", wsName))
			wg.Done()
			continue
		}

		// Build ACME server config from webservice config if enabled
		var acmeServerConfig *v1.ACMEServerConfig
		if wsConfig.ACME != nil && wsConfig.ACME.Enabled {
			// Derive base REST URI from directory URL by stripping /acme/directory suffix
			// DirectoryURL: https://server.example.com:9443/api/v1/acme/directory
			// BaseRESTURI:  https://server.example.com:9443/api/v1
			baseRESTURI := strings.TrimSuffix(wsConfig.ACME.DirectoryURL, "/acme/directory")
			logger.Info("ACME server enabled for webservice", "name", wsName, "directory", wsConfig.ACME.DirectoryURL, "baseURI", baseRESTURI)

			// Build challenge map from configured challenges
			challengeMap := buildChallengeMap(wsConfig.ACME.Challenges, App.CA)
			logger.Info("ACME challenges configured", "count", len(challengeMap), "challenges", wsConfig.ACME.Challenges)

			// Get internal domain for DNS registration during device enrollment
			var internalDomain string
			if App.DNSConfig == nil {
				logger.Warn("DNS config is nil - DNS registration disabled")
			} else if App.DNSConfig.InternalServer == nil {
				logger.Warn("DNS InternalServer config is nil - DNS registration disabled")
			} else {
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

		// Build WebAuthn config if available
		var webauthnConfig *webauthn.Config
		if wsConfig.WebAuthn != nil {
			webauthnConfig = &webauthn.Config{
				RPDisplayName: wsConfig.WebAuthn.RPDisplayName,
				RPID:          wsConfig.WebAuthn.RPID,
				RPOrigins:     wsConfig.WebAuthn.RPOrigins,
			}
		}

		// Get XKMS from CA - it returns xkms.Backend which implements XKMSSigner
		ks, ok := App.CA.KeyStore().(v1.XKMSSigner)
		if !ok {
			logger.Warn("CA does not implement XKMSSigner interface")
			cmd.PrintErrln("CA does not implement XKMSSigner interface")
			return
		}

		// Register DNS A records for this webservice and all its virtual hosts
		if App.DNSService != nil {
			ctx := context.Background()

			// Register main webservice certificate CN
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

			// Register DNS records for all virtual hosts
			if wsConfig.VirtualHosts != nil {
				for _, vhost := range *wsConfig.VirtualHosts {
					// Register virtual host certificate CN if configured
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

					// Register each host in the virtual host's Hosts list
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

		restHandlerRegistry := v1.NewHandlerRegistry(v1.RegistryParams{
			ACMEServerConfig:    acmeServerConfig,
			ACMEStorageFactory:  acmeDAOFactory,
			CA:                  App.CA,
			CAConfig:            App.CAConfig,
			Debug:               App.DebugFlag,
			HTTPWriter:          response.NewResponseWriter(logger, nil),
			IAMClient:           nil,
			XKMS:                ks,
			JWTAudience:         wsConfig.Certificate.Subject.CommonName,
			JWTClaimsIssuer:     app.Name,
			JWTExpiration:       3600,
			Logger:              logger,
			PEPClient:           nil,
			ServerKeyAttributes: wsKeyAttrs,
			ServiceRegistry:     App.ServiceRegistry(),
			TPM:                 App.TPM,
			WebServiceConfig:    wsConfig,
			WebAuthnConfig:      webauthnConfig,
		})

		webserver := webservice.NewWebServerV1(
			App.DebugFlag,
			logger,
			App.CA,
			App.CAConfig,
			wsConfig,
			restHandlerRegistry,
			wsKeyAttrs)

		// Capture webserver in closure to avoid loop variable capture bug
		go func(ws *webservice.WebServerV1) {
			defer wg.Done()
			ws.Run()
		}(webserver)
	}

	// Start Noise bootstrap server if enabled
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

	// Wait for shutdown signal
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutdown signal received")
	cmd.Println("\nShutting down...")

	// Stop the Noise bootstrap server if it was started
	if noiseServer != nil {
		if stopErr := noiseServer.Stop(ctx); stopErr != nil {
			logger.Warn("failed to stop Noise bootstrap server", "error", stopErr)
		}
	}

	// Stop the platform daemon
	if platformDaemon != nil {
		if err := platformDaemon.Stop(ctx); err != nil {
			logger.Warn("Error stopping platform daemon", "error", err)
		}
	}

	logger.Info("Graceful shutdown complete")
	cmd.Println("Platform daemon stopped.")
}

// runDaemonOnly starts the platform daemon without webservices.
// This mode can run with limited functionality even if the CA is not available.
func runDaemonOnly(cmd *cobra.Command, ctx context.Context, sigChan chan os.Signal, logger *logging.Logger, appErr error) {
	// Build daemon configuration
	config := daemon.DefaultConfig()
	if App != nil {
		config.App = App
	}
	config.Logger = logger
	config.SocketPath = serveSocketPath
	config.SocketGroup = "" // Don't require specific group

	// Skip IAM validation if requested
	if serveSkipIAM {
		config.SkipIAMValidation = true
		logger.Warn("IAM validation disabled. DO NOT USE IN PRODUCTION!")
	}

	// REST configuration
	config.EnableREST = serveEnableREST
	config.RESTListenAddr = fmt.Sprintf("0.0.0.0:%d", serveRESTPort)

	// gRPC configuration
	config.EnableGRPCTCP = serveEnableGRPC
	config.GRPCListenAddr = fmt.Sprintf("0.0.0.0:%d", serveGRPCPort)

	// QUIC configuration - QUIC requires TLS
	config.EnableQUIC = serveEnableQUIC
	config.QUICListenAddr = fmt.Sprintf("0.0.0.0:%d", serveQUICPort)
	if serveEnableQUIC {
		// Generate a self-signed TLS configuration for QUIC
		// In production, this should use CA-signed certificates
		quicConfig, quicErr := quic.DefaultServerConfigWithTLS()
		if quicErr != nil {
			logger.Error(quicErr, "Failed to generate QUIC TLS configuration")
			cmd.PrintErrln(fmt.Sprintf("Failed to generate QUIC TLS configuration: %v", quicErr))
			return
		}
		quicConfig.ListenAddr = fmt.Sprintf("0.0.0.0:%d", serveQUICPort)
		config.QUICConfig = quicConfig
		logger.Debug("QUIC TLS configuration generated with self-signed certificate")
	}

	// MCP configuration
	config.EnableMCP = serveEnableMCP
	if config.MCPConfig == nil {
		config.MCPConfig = daemon.DefaultMCPConfig()
	}
	config.MCPConfig.HTTPAddr = fmt.Sprintf("127.0.0.1:%d", serveMCPPort)

	// Initialize CA from App config if available
	// App may be partially initialized (e.g., TPM not available) but CA config
	// is loaded from the config file and software-keystore CA works without TPM.
	if App != nil && App.CAConfig != nil && App.CA == nil {
		soPIN, userPIN, pinErr := App.ParsePINs(InitParams.SOPin, InitParams.Pin)
		if pinErr != nil {
			logger.Warn("CA PIN parsing failed (CA will not be available)", "error", pinErr)
		} else {
			if loadErr := App.LoadCA(soPIN, userPIN); loadErr != nil {
				logger.Warn("CA not found, attempting to initialize", "error", loadErr)
				if _, initErr := App.InitCA(soPIN, userPIN, InitParams); initErr != nil {
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

	// Enable mTLS if requested
	if serveEnableMTLS && App != nil && App.CA != nil {
		mtlsDir := "/tmp/platformd-integration/tls"
		if mkErr := os.MkdirAll(mtlsDir, 0700); mkErr != nil {
			logger.Error(mkErr, "Failed to create mTLS directory")
		} else {
			mtlsErr := issueMTLSCertificates(logger, App.CA, config, mtlsDir)
			if mtlsErr != nil {
				logger.Error(mtlsErr, "Failed to issue mTLS certificates")
			}
		}
	}

	// Initialize vTPM service from App config if available
	// App may be partially initialized but vTPM config is loaded from config file.
	if App != nil && App.VTPMConfig != nil {
		vtpmConfig := App.VTPMConfig
		vtpmConfig.ApplyDefaults()

		vtpmService, vtpmErr := vtpm.NewService(vtpmConfig, logger, nil)
		if vtpmErr != nil {
			logger.Warn("vTPM service creation failed (vTPM operations will fail)",
				"error", vtpmErr)
		} else {
			config.VTPMService = vtpmService
			logger.Info("vTPM service initialized", "base_dir", vtpmConfig.BaseDir)
		}
	}

	// Wire DNS service if available
	if App != nil && App.DNSService != nil {
		config.DNSService = App.DNSService
		logger.Info("DNS service configured for daemon")
	}

	// Configure SDN service if OVS socket is available
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

	// Create Compute Orchestrator for container/VM operations
	computeConfig := &compute.OrchestratorConfig{
		Type:            compute.ComputeTypeContainer,
		MaxInstances:    100,
		Debug:           InitParams.Debug,
		WorkDir:         "/var/lib/platformd/compute",
		DefaultMemory:   512,
		DefaultCPUs:     1,
		DefaultDiskSize: "10G",
	}
	computeOrchestrator, computeErr := compute.NewContainerOrchestrator(computeConfig, logger)
	if computeErr != nil {
		logger.Info("Compute orchestrator not available (container operations will fail)",
			"reason", computeErr.Error())
	} else {
		config.ComputeOrchestrator = computeOrchestrator
		logger.Info("Compute orchestrator initialized successfully")
	}

	// Create the daemon
	d, err := daemon.New(config)
	if err != nil {
		logger.Error(err, "Failed to create daemon")
		cmd.PrintErrln(fmt.Sprintf("Failed to create daemon: %v", err))
		return
	}

	// Log TPM availability for IDevID/IAK operations
	if App != nil && App.TPM != nil {
		logger.Info("TPM available for IDevID/IAK operations")

		// Log configured handles from platform config if available
		if App.TPMConfig.IDevID != nil && App.TPMConfig.IDevID.Handle != 0 {
			logger.Debug("IDevID handle configured", "handle", fmt.Sprintf("0x%08X", App.TPMConfig.IDevID.Handle))
		}
		if App.TPMConfig.IAK != nil && App.TPMConfig.IAK.Handle != 0 {
			logger.Debug("IAK handle configured", "handle", fmt.Sprintf("0x%08X", App.TPMConfig.IAK.Handle))
		}
	} else {
		logger.Info("TPM not available (IDevID/IAK operations will not be available)")
	}

	// Start the daemon
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
		return
	}

	logger.Info("Platform daemon started successfully")
	cmd.Println("Platform daemon running. Press Ctrl+C to stop.")

	// Wait for shutdown signal
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutdown signal received")
	cmd.Println("\nShutting down...")

	// Graceful shutdown
	if err := d.Stop(ctx); err != nil {
		logger.Error(err, "Error during shutdown")
	}

	logger.Info("Platform daemon stopped")
	cmd.Println("Platform daemon stopped.")
}

// issueMTLSCertificates generates server and admin client TLS certificates,
// signs them with the platform CA via CSR (keys generated in memory, never
// stored in KMS), and configures the daemon for mutual TLS authentication.
//
// This follows the same bootstrap pattern as QuicBaaS: on first start,
// generate an admin certificate so operators can connect immediately.
func issueMTLSCertificates(
	logger *logging.Logger,
	caService trustedca.CACertificateAuthority,
	config *daemon.Config,
	outputDir string,
) error {

	// Generate server ECDSA P-256 key pair in memory (never touches KMS)
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate server key: %w", err)
	}

	// Create server CSR
	serverCSRDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "platformd.localhost",
			Organization: []string{"Trusted Platform"},
		},
		DNSNames:    []string{"localhost", "platformd.localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}, serverKey)
	if err != nil {
		return fmt.Errorf("failed to create server CSR: %w", err)
	}
	serverCSRPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: serverCSRDER,
	})

	// Sign server CSR with platform CA
	serverCert, err := caService.SignCSR(serverCSRPEM, &trustedca.CACertificateRequest{
		Subject: trustedca.CASubject{
			CommonName:   "platformd.localhost",
			Organization: "Trusted Platform",
		},
		SANS: &trustedca.CASubjectAlternativeNames{
			DNS: []string{"localhost", "platformd.localhost"},
			IPs: []string{"127.0.0.1", "::1"},
		},
		Valid:       365,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("failed to sign server CSR: %w", err)
	}
	logger.Info("mTLS server certificate issued",
		"cn", serverCert.Subject.CommonName,
		"serial", serverCert.SerialNumber.String())

	// Create in-memory TLS certificate for the daemon
	serverTLSCert := tls.Certificate{
		Certificate: [][]byte{serverCert.Raw},
		PrivateKey:  serverKey,
		Leaf:        serverCert,
	}

	// Write server bundle (cert+key PEM) for file-based consumers
	serverBundlePEM, err := encodeCertKeyBundle(serverCert.Raw, serverKey)
	if err != nil {
		return fmt.Errorf("failed to encode server bundle: %w", err)
	}
	serverBundlePath := filepath.Join(outputDir, "server-bundle.pem")
	if err := os.WriteFile(serverBundlePath, serverBundlePEM, 0600); err != nil {
		return fmt.Errorf("failed to write server bundle: %w", err)
	}

	// Generate admin client ECDSA P-256 key pair in memory (never touches KMS)
	adminKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate admin key: %w", err)
	}

	// Create admin client CSR
	adminCSRDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "admin",
			Organization: []string{"Trusted Platform"},
		},
	}, adminKey)
	if err != nil {
		return fmt.Errorf("failed to create admin CSR: %w", err)
	}
	adminCSRPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: adminCSRDER,
	})

	// Sign admin CSR with platform CA
	adminCert, err := caService.SignCSR(adminCSRPEM, &trustedca.CACertificateRequest{
		Subject: trustedca.CASubject{
			CommonName:   "admin",
			Organization: "Trusted Platform",
		},
		Valid:       365,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return fmt.Errorf("failed to sign admin CSR: %w", err)
	}
	logger.Info("mTLS admin certificate issued",
		"cn", adminCert.Subject.CommonName,
		"serial", adminCert.SerialNumber.String())

	// Write admin bundle (cert+key PEM) for client authentication
	adminBundlePEM, err := encodeCertKeyBundle(adminCert.Raw, adminKey)
	if err != nil {
		return fmt.Errorf("failed to encode admin bundle: %w", err)
	}
	clientBundlePath := filepath.Join(outputDir, "client-bundle.pem")
	if err := os.WriteFile(clientBundlePath, adminBundlePEM, 0600); err != nil {
		return fmt.Errorf("failed to write admin bundle: %w", err)
	}

	// Export CA bundle for client trust verification
	caBundle, err := caService.CABundle(xkmssdk.StoreSoftware, x509.ECDSA)
	if err != nil {
		return fmt.Errorf("failed to export CA bundle: %w", err)
	}
	caBundlePath := filepath.Join(outputDir, "ca-bundle.crt")
	if err := os.WriteFile(caBundlePath, caBundle, 0644); err != nil {
		return fmt.Errorf("failed to write CA bundle: %w", err)
	}

	// Get CA cert pool for mTLS client verification
	caBundlePool, err := caService.CABundleCertPool(xkmssdk.StoreSoftware, x509.ECDSA)
	if err != nil {
		return fmt.Errorf("failed to create CA bundle cert pool: %w", err)
	}

	// Configure daemon for mTLS
	config.EnableMTLS = true
	config.MTLSClientCAFile = caBundlePath
	config.MTLSClientCAPool = caBundlePool
	config.TLSCertificate = &serverTLSCert

	// Set QUIC TLS config with server cert
	if config.QUICConfig != nil && config.QUICConfig.TLSConfig != nil {
		config.QUICConfig.TLSConfig.Certificates = []tls.Certificate{serverTLSCert}
	}

	logger.Info("mTLS certificates issued and daemon configured",
		"server_bundle", serverBundlePath,
		"client_bundle", clientBundlePath,
		"ca_bundle", caBundlePath,
	)
	logger.Info("Admin certificate generated for CLI/API authentication",
		"cert", clientBundlePath,
		"key", clientBundlePath,
		"ca", caBundlePath,
	)

	return nil
}

// encodeCertKeyBundle PEM-encodes a DER certificate and ECDSA private key
// into a single bundle file. This format is compatible with
// tls.LoadX509KeyPair(bundle, bundle) where both args point to the same file.
func encodeCertKeyBundle(certDER []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EC private key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return append(certPEM, keyPEM...), nil
}
