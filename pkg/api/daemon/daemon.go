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
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/jeremyhahn/go-codec"
	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	grpccreds "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/barrier"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	bmcwebsvc "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// DaemonOption is a functional option for configuring the Daemon
type DaemonOption func(*Daemon)

// WithGRPCServer sets a custom gRPC server implementation
func WithGRPCServer(s GRPCServerInterface) DaemonOption {
	return func(d *Daemon) {
		d.grpcServer = s
	}
}

// WithQUICServer sets a custom QUIC server implementation
func WithQUICServer(s QUICServerInterface) DaemonOption {
	return func(d *Daemon) {
		d.quicServer = s
	}
}

// WithRESTServer sets a custom REST server implementation
func WithRESTServer(s RESTServerInterface) DaemonOption {
	return func(d *Daemon) {
		d.restServer = s
	}
}

// WithMCPServer sets a custom MCP server implementation
func WithMCPServer(s MCPServerInterface) DaemonOption {
	return func(d *Daemon) {
		d.mcpServer = s
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
	config             *Config
	logger             *logging.Logger
	grpcServer         GRPCServerInterface // gRPC server for TCP
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
	tpm2Service        xkmssdk.TrustedPlatformModule
	mcpServer          MCPServerInterface
	mcpProvider        *MCPServiceProvider
	healthRegistry     health.Registry

	// Concrete server references for accessor methods (set only for real servers)
	concreteRestServer    *RESTServer
	concreteMcpServer     *mcp.Server
	concreteGrpcUDSServer *grpc.Server // Store concrete gRPC UDS server for service registration

	running atomic.Bool
	mu      sync.RWMutex
}

// New creates a new platformd daemon
func New(config *Config, opts ...DaemonOption) (*Daemon, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Set up logger
	logger := config.Logger
	if logger == nil {
		logger = logging.DefaultLogger()
	}

	// Create the daemon service implementation
	service, err := NewService(config)
	if err != nil {
		return nil, err
	}

	// Create gRPC TCP server if enabled
	var grpcServer *grpc.Server
	if config.EnableGRPCTCP {
		var grpcOpts []grpc.ServerOption

		// Configure TLS: prefer in-memory certificate, fall back to files
		if config.TLSCertificate != nil || (config.GRPCTLSCertFile != "" && config.GRPCTLSKeyFile != "") {
			var cert tls.Certificate
			if config.TLSCertificate != nil {
				cert = *config.TLSCertificate
			} else {
				var err error
				cert, err = tls.LoadX509KeyPair(config.GRPCTLSCertFile, config.GRPCTLSKeyFile)
				if err != nil {
					return nil, ErrTLSConfigFailed{Reason: "gRPC: " + err.Error()}
				}
			}
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}

			// Enable mutual TLS if configured
			if config.EnableMTLS {
				clientCAPool := config.MTLSClientCAPool
				if clientCAPool == nil && config.MTLSClientCAFile != "" {
					caCert, readErr := os.ReadFile(config.MTLSClientCAFile)
					if readErr != nil {
						return nil, ErrTLSConfigFailed{Reason: "gRPC: failed to read mTLS client CA file: " + readErr.Error()}
					}
					clientCAPool = x509.NewCertPool()
					if !clientCAPool.AppendCertsFromPEM(caCert) {
						return nil, ErrTLSConfigFailed{
							Reason: "gRPC: failed to parse mTLS client CA certificates",
						}
					}
				}
				if clientCAPool != nil {
					tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
					tlsConfig.ClientCAs = clientCAPool
					logger.Info("gRPC TCP server mTLS enabled", "addr", config.GRPCListenAddr)
				}
			}

			grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
		}

		// Skip health check methods from authentication
		skipMethods := []string{
			"/platform.v1.PlatformDaemon/HealthCheck",
			"/grpc.health.v1.Health/Check",
		}

		// Configure authentication interceptors
		if config.EnableMTLS && config.CAService != nil {
			// Use mTLS interceptors for client certificate authentication
			var mtlsOpts []auth.MTLSOption
			if config.MTLSClientCAPool != nil {
				mtlsOpts = append(mtlsOpts, auth.WithTrustedRoots(config.MTLSClientCAPool))
			}
			mtlsAuth, err := auth.NewMTLSAdapter(logger, config.CAService, mtlsOpts...)
			if err != nil {
				return nil, ErrTLSConfigFailed{Reason: "gRPC mTLS auth: " + err.Error()}
			}
			interceptorCfg := &MTLSInterceptorConfig{
				Authenticator: mtlsAuth,
				Logger:        logger,
				SkipMethods:   skipMethods,
			}
			grpcOpts = append(grpcOpts,
				grpc.ChainUnaryInterceptor(MTLSUnaryInterceptor(interceptorCfg)),
				grpc.ChainStreamInterceptor(MTLSStreamInterceptor(interceptorCfg)),
			)
			logger.Info("gRPC TCP server: mTLS authentication enabled")
		} else {
			// Configure OIDC authentication interceptors if QuicBaaS is available
			// Skip authentication when SkipIAMValidation is set (testing mode)
			var tokenValidator grpccreds.TokenValidator
			if !config.SkipIAMValidation && config.App != nil {
				dbSvc := config.App.QuicBaaSService()
				if dbSvc != nil {
					// Adapt QuicBaaS service to ServiceInterface for token validation
					svcAdapter := &quicbaasServiceAdapter{svc: dbSvc}
					tokenValidator = newGRPCTokenValidator(svcAdapter, logger)
					logger.Info("gRPC TCP server: OIDC authentication enabled via QuicBaaS")
				}
			}

			grpcOpts = append(grpcOpts,
				grpc.ChainUnaryInterceptor(grpccreds.OIDCUnaryInterceptor(
					grpccreds.WithTokenValidator(tokenValidator),
					grpccreds.WithSkipMethods(skipMethods...),
					grpccreds.WithRequireAuth(tokenValidator != nil),
				)),
				grpc.ChainStreamInterceptor(grpccreds.OIDCStreamInterceptor(
					grpccreds.WithTokenValidator(tokenValidator),
					grpccreds.WithSkipMethods(skipMethods...),
					grpccreds.WithRequireAuth(tokenValidator != nil),
				)),
			)
		}

		grpcServer = grpc.NewServer(grpcOpts...)

		// Register platform daemon service with TCP gRPC server
		platformv1.RegisterPlatformDaemonServer(grpcServer, service)

		logger.Info("gRPC TCP server created", "addr", config.GRPCListenAddr)
	}

	// Create gRPC UDS server if enabled
	var grpcUDSServer *grpc.Server
	if config.EnableGRPCUDS {
		grpcOpts := []grpc.ServerOption{
			grpc.Creds(grpccreds.NewUnixTransportCredentials()),
			grpc.ChainUnaryInterceptor(grpccreds.UnixCredentialsUnaryInterceptor()),
			grpc.ChainStreamInterceptor(grpccreds.UnixCredentialsStreamInterceptor()),
		}
		grpcUDSServer = grpc.NewServer(grpcOpts...)

		// Register platform daemon service with UDS gRPC server
		platformv1.RegisterPlatformDaemonServer(grpcUDSServer, service)

		logger.Info("gRPC UDS server created", "path", config.GRPCSocketPath)
	}

	// Initialize optional services based on available backends
	var sdnService *SDNService
	var iamService *IAMService
	var tenantService *TenantService

	// Create SDN service if OVS socket path is configured
	if config.OVSSocketPath != "" {
		var sdnErr error
		sdnService, sdnErr = NewSDNService(config.OVSSocketPath)
		if sdnErr != nil {
			logger.Warn("SDN service creation failed", "error", sdnErr)
		} else {
			// Register SDN gRPC service with TCP gRPC server if enabled
			if grpcServer != nil {
				platformv1.RegisterSDNServiceServer(grpcServer, sdnService)
			}
			// Register SDN gRPC service with UDS gRPC server if enabled
			if grpcUDSServer != nil {
				platformv1.RegisterSDNServiceServer(grpcUDSServer, sdnService)
			}
			logger.Info("SDN service initialized (connection deferred to first use)",
				"ovs_socket", config.OVSSocketPath)
		}
	} else {
		logger.Info("SDN service not available (OVSSocketPath not configured)")
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

	// Create Gateway gRPC service (always available - gracefully handles nil dependencies)
	gatewayService := NewGatewayService()
	if grpcServer != nil {
		platformv1.RegisterGatewayServiceServer(grpcServer, gatewayService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterGatewayServiceServer(grpcUDSServer, gatewayService)
	}
	logger.Info("Gateway service initialized and registered successfully")

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

		caService = NewCAGRPCService(caLogger, config.CAService)

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
			logger.Info("KMS service initialized and registered successfully")
		}
	} else {
		logger.Info("KMS service not available (QuicBaaS backend not configured)")
	}

	// Create IAM service - MANDATORY for the platform (unless SkipIAMValidation is set for testing)
	// IAM provides authentication, authorization, tenant management, and policy enforcement
	if !config.SkipIAMValidation {
		if config.App != nil {
			var iamErr error
			iamService, iamErr = NewIAMService(config.App, logger.Slog())
			if iamErr != nil {
				// IAM is mandatory - fail if it cannot be initialized
				return nil, ErrInvalidConfig{Reason: "IAM service is mandatory: " + iamErr.Error()}
			}

			logger.Info("IAM service initialized (using QuicBaaS SDK clients)")

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

	// Create Attestation gRPC service if AttestationService is configured
	var attestationService *AttestationServiceServer
	if config.AttestationService != nil {
		attestationService = NewAttestationServiceServer(config.AttestationService, logger.Slog())

		// Register with TCP gRPC server if enabled
		if grpcServer != nil {
			platformv1.RegisterAttestationServiceServer(grpcServer, attestationService)
		}

		// Register with UDS gRPC server if enabled
		if grpcUDSServer != nil {
			platformv1.RegisterAttestationServiceServer(grpcUDSServer, attestationService)
		}

		logger.Info("Attestation service initialized and registered successfully")
	} else {
		logger.Info("Attestation service not available (AttestationService not configured)")
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

	// Create IDevID gRPC service - always created, TPM2 service injected later via SetTPM2Service
	idevidService := NewIDevIDGRPCService(logger)

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
	// on lab-node-2 2026-04-08 — the command returned "tpm service not
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

	// Create EAB gRPC service - stub returning Unimplemented
	eabService := NewEABGRPCService(logger)
	if grpcServer != nil {
		platformv1.RegisterEABServiceServer(grpcServer, eabService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterEABServiceServer(grpcUDSServer, eabService)
	}
	logger.Info("EAB gRPC service registered (stub)")

	// Create Invitation gRPC service - stub returning Unimplemented
	invitationService := NewInvitationGRPCService(logger)
	if grpcServer != nil {
		platformv1.RegisterInvitationServiceServer(grpcServer, invitationService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterInvitationServiceServer(grpcUDSServer, invitationService)
	}
	logger.Info("Invitation gRPC service registered (stub)")

	// Create Cluster gRPC service - stub returning Unimplemented
	// Full implementation available when built with -tags cluster
	clusterGRPCService := NewClusterGRPCService(logger)
	if grpcServer != nil {
		platformv1.RegisterClusterServiceServer(grpcServer, clusterGRPCService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterClusterServiceServer(grpcUDSServer, clusterGRPCService)
	}
	logger.Info("Cluster gRPC service registered (stub)")

	// Create DNS gRPC service - stub returning Unimplemented
	// Full implementation wired when DNS service is available
	dnsGRPCService := NewDNSServiceServer(nil, logger.Slog())
	if grpcServer != nil {
		platformv1.RegisterDNSServiceServer(grpcServer, dnsGRPCService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterDNSServiceServer(grpcUDSServer, dnsGRPCService)
	}
	logger.Info("DNS gRPC service registered")

	// Create PXE gRPC service - stub returning Unimplemented
	// Full implementation wired when PXE service is available
	pxeGRPCService := NewPXEGRPCService(logger, nil)
	if grpcServer != nil {
		platformv1.RegisterPXEServiceServer(grpcServer, pxeGRPCService)
	}
	if grpcUDSServer != nil {
		platformv1.RegisterPXEServiceServer(grpcUDSServer, pxeGRPCService)
	}
	logger.Info("PXE gRPC service registered")

	logger.Info("Creating health registry...")
	// Create health registry
	healthRegistry := health.NewRegistry()

	// Create QUIC service handler and server if enabled
	var quicServerIntf QUICServerInterface // Use interface type to avoid typed nil issue
	var quicHandler *QUICServiceHandler
	if config.EnableQUIC {
		// Initialize QUIC protocol codec before creating server
		if codecErr := quic.SetDefaultCodecType(codec.MsgPack); codecErr != nil {
			logger.Warn("Failed to set MsgPack codec for QUIC, falling back to JSON", "error", codecErr)
			_ = quic.SetDefaultCodecType(codec.JSON)
		}
		// Get logging.Logger for QUIC handler
		var quicLogger *logging.Logger
		if config.App != nil && config.App.Logger != nil {
			quicLogger = config.App.Logger
		} else {
			quicLogger = logging.DefaultLogger()
		}

		// Configure QUIC authentication middleware
		// When mTLS is enabled, QUIC uses TLS 1.3 natively so client cert verification
		// happens at the TLS layer. No additional application-level auth middleware needed.
		var quicAuthMiddleware *quic.AuthMiddleware
		if config.EnableMTLS {
			logger.Info("QUIC server: mTLS authentication enabled (TLS layer)")
		} else if !config.SkipIAMValidation && config.App != nil {
			// Fall back to OIDC token authentication via QuicBaaS
			dbSvc := config.App.QuicBaaSService()
			if dbSvc != nil {
				// Adapt QuicBaaS service to ServiceInterface for token validation
				svcAdapter := &quicbaasServiceAdapter{svc: dbSvc}
				quicTokenValidator := newGRPCTokenValidator(svcAdapter, logger)
				quicAuthMiddleware = quic.NewAuthMiddleware(
					quic.WithQUICTokenValidator(quicTokenValidator),
					quic.WithQUICRequireAuth(true),
				)
				logger.Info("QUIC server: OIDC authentication enabled via QuicBaaS")
			}
		}

		// Create the QUIC service handler with available services
		quicHandler = NewQUICServiceHandler(
			quicLogger,
			WithQUICHealthRegistry(healthRegistry),
			WithQUICAuthMiddleware(quicAuthMiddleware),
		)

		// Set daemon service for QUIC daemon operations
		quicHandler.SetDaemonService(service)

		// Set CA handler if available
		if config.CAService != nil {
			quicHandler.SetCAHandler(quic.NewCAHandler(quicLogger, config.CAService))
		}

		// Set vTPM service if available
		if config.VTPMService != nil {
			quicHandler.SetVTPMService(config.VTPMService)
		}

		// Set Device service if available
		if config.DeviceService != nil {
			quicHandler.SetDeviceService(config.DeviceService)
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
			} else if kmsService.KMSServer() != nil && kmsService.CryptoServer() != nil {
				quicHandler.SetKMSService(newKMSQUICAdapter(
					kmsService.KMSServer(),
					kmsService.CryptoServer(),
				))
				logger.Debug("KMS service set for QUIC handler")
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

		// Set up overlay and gateway QUIC handlers for proper request routing.
		// Even without concrete service implementations, having these handlers
		// ensures overlay/gateway/IPAM requests are routed correctly rather
		// than colliding with other opcode ranges.
		quicHandler.SetOverlayHandler(quic.NewOverlayHandler(quicLogger, nil))
		quicHandler.SetGatewayHandler(quic.NewGatewayHandler(quicLogger, nil))
		logger.Debug("Overlay and gateway handlers set for QUIC handler")

		// Prepare QUIC server configuration
		quicConfig := config.QUICConfig
		if quicConfig == nil {
			quicConfig = quic.DefaultServerConfig()
		}

		// Override listen address from daemon config if set
		if config.QUICListenAddr != "" {
			quicConfig.ListenAddr = config.QUICListenAddr
		}

		// Enable mTLS on QUIC TLS config for client certificate verification
		if config.EnableMTLS && quicConfig.TLSConfig != nil {
			clientCAPool := config.MTLSClientCAPool
			if clientCAPool == nil && config.MTLSClientCAFile != "" {
				caCert, readErr := os.ReadFile(config.MTLSClientCAFile)
				if readErr != nil {
					logger.Warn("QUIC mTLS: failed to read client CA file", "error", readErr)
				} else {
					clientCAPool = x509.NewCertPool()
					if !clientCAPool.AppendCertsFromPEM(caCert) {
						logger.Warn("QUIC mTLS: failed to parse client CA certificates")
						clientCAPool = nil
					}
				}
			}
			if clientCAPool != nil {
				quicConfig.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
				quicConfig.TLSConfig.ClientCAs = clientCAPool
				logger.Info("QUIC server mTLS enabled on TLS config")
			}
		}

		// Create QUIC server
		quicServer, quicErr := quic.NewServer(
			quicConfig,
			quic.WithHandler(quicHandler),
			quic.WithLogger(quicLogger),
		)
		if quicErr != nil {
			logger.Warn("QUIC server creation failed", "error", quicErr)
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

	daemon := &Daemon{
		config:                config,
		logger:                logger,
		grpcServer:            grpcServerIntf,
		grpcUDSServer:         grpcUDSServerIntf,
		concreteGrpcUDSServer: grpcUDSServer,
		quicServer:            quicServerIntf,
		quicHandler:           quicHandler,
		service:               service,
		caService:             caService,
		sdnService:            sdnService,
		kmsService:            kmsService,
		iamService:            iamService,
		tenantService:         tenantService,
		vtpmService:           vtpmService,
		deviceService:         deviceService,
		computeService:        computeService,
		attestationService:    attestationService,
		registryService:       registryService,
		idevidService:         idevidService,
		tpmService:            tpmService,
		barrierService:        barrierService,
		healthRegistry:        healthRegistry,
	}

	// Apply functional options (allows overriding servers with mocks)
	for _, opt := range opts {
		opt(daemon)
	}

	// Create REST server if enabled and not overridden by option
	if config.EnableREST && daemon.restServer == nil {
		restServer, restErr := NewRESTServer(config, service, logger.Slog())
		if restErr != nil {
			logger.Warn("REST server creation failed", "error", restErr)
		} else {
			daemon.restServer = restServer
			daemon.concreteRestServer = restServer
			logger.Info("REST server created", "addr", config.RESTListenAddr)
		}
	} else if !config.EnableREST {
		logger.Info("REST server not enabled")
	}

	// Wire vTPM service into REST server if both are available
	if daemon.concreteRestServer != nil && config.VTPMService != nil {
		daemon.concreteRestServer.SetVTPMService(config.VTPMService)
		logger.Info("vTPM service wired into REST server")
	}

	// Wire SDN service into REST server if both are available
	if daemon.concreteRestServer != nil && daemon.sdnService != nil {
		daemon.concreteRestServer.SetSDNService(daemon.sdnService.OVSClient())
		logger.Info("SDN service wired into REST server")
	}

	// Wire config delivery handler into REST server for pre-enrollment provisioning
	if daemon.concreteRestServer != nil {
		svc, svcErr := configdelivery.NewService(configdelivery.ServiceParams{
			Logger: logger,
		})
		if svcErr == nil {
			respWriter := response.NewResponseWriter(logger, nil)
			handler, handlerErr := configdelivery.NewHandler(configdelivery.HandlerParams{
				Service:        svc,
				ResponseWriter: respWriter,
				Logger:         logger,
			})
			if handlerErr == nil {
				daemon.concreteRestServer.SetConfigDeliveryHandler(handler)
				logger.Info("Config delivery handler wired into REST server")
			} else {
				logger.Warn("Config delivery handler creation failed", "error", handlerErr)
			}
		} else {
			logger.Warn("Config delivery service creation failed", "error", svcErr)
		}
	}

	// Wire BMC handler into REST server for bare metal management
	if daemon.concreteRestServer != nil {
		bmcSvc, bmcErr := bmc.NewService(bmc.ServiceParams{
			Factory: bmc.NewIPMIClientFactory(logger.Slog()),
			Logger:  logger.Slog(),
		})
		if bmcErr == nil {
			respWriter := response.NewResponseWriter(logger, nil)
			bmcHandler, bmcHandlerErr := bmcwebsvc.NewHandler(bmcwebsvc.HandlerParams{
				BMCService:     bmcSvc,
				ResponseWriter: respWriter,
				Logger:         logger,
			})
			if bmcHandlerErr == nil {
				daemon.concreteRestServer.SetBMCHandler(bmcHandler)
				logger.Info("BMC management handler wired into REST server")
			} else {
				logger.Warn("BMC handler creation failed", "error", bmcHandlerErr)
			}
		} else {
			logger.Warn("BMC service creation failed", "error", bmcErr)
		}
	}

	// Create MCP server if enabled and not overridden by option
	if config.EnableMCP && daemon.mcpServer == nil {
		mcpServer, mcpErr := daemon.createMCPServer()
		if mcpErr != nil {
			logger.Warn("MCP server creation failed", "error", mcpErr)
		} else {
			daemon.mcpServer = mcpServer
			daemon.concreteMcpServer = mcpServer
			logger.Info("MCP server created", "transport", config.MCPConfig.Transport, "addr", config.MCPConfig.HTTPAddr)
		}
	} else if !config.EnableMCP {
		logger.Info("MCP server not enabled")
	}

	logger.Info("Registering health checkers...")
	// Register health checkers for available services
	daemon.registerHealthCheckers()

	logger.Info("Wiring health registry...")
	// Wire health registry into the service for gRPC health endpoint
	service.SetHealthRegistry(healthRegistry)

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
	// Create the MCP service provider that bridges MCP to daemon services
	serviceProvider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CAService:           d.caService,
		VTPMService:         d.config.VTPMService,
		DeviceService:       d.config.DeviceService,
		SDNService:          d.sdnService,
		HealthService:       d.service,
		Logger:              d.logger.Slog(),
		ComputeOrchestrator: d.config.ComputeOrchestrator,
	})

	// Wire DNS service to MCP provider if available via App
	if d.config.App != nil && d.config.App.DNSService != nil {
		serviceProvider.dnsService = d.config.App.DNSService
	}

	// Store the provider for later service injection
	d.mcpProvider = serviceProvider

	// Build MCP config from daemon MCPConfig
	mcpCfg := d.config.MCPConfig
	if mcpCfg == nil {
		mcpCfg = DefaultMCPConfig()
	}

	mcpConfig := &mcp.Config{
		ServerName:            mcpCfg.ServerName,
		ServerVersion:         mcpCfg.ServerVersion,
		Transport:             mcpCfg.Transport,
		HTTPAddr:              mcpCfg.HTTPAddr,
		RequestTimeout:        mcpCfg.RequestTimeout,
		MaxConcurrentRequests: mcpCfg.MaxConcurrentRequests,
	}

	// Try to set up QuicBaaS auth adapter if available
	// Skip authentication when SkipIAMValidation is set (testing mode)
	if !d.config.SkipIAMValidation {
		authAdapter := d.createMCPAuthAdapter()
		if authAdapter != nil {
			mcpConfig.AuthorizationService = authAdapter
			mcpConfig.AuthManager = authAdapter
			d.logger.Info("MCP server configured with QuicBaaS authorization")
		} else {
			d.logger.Warn("MCP server running without QuicBaaS authorization")
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
	var pepClient iampb.PEPServiceClient
	if d.iamService != nil {
		sdkPEP := d.iamService.PEP()
		if sdkPEP != nil {
			pepClient = NewSDKPEPClientAdapter(sdkPEP)
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
	service quicbaas.ServiceInterface
	logger  *logging.Logger
}

// newGRPCTokenValidator creates a token validator for gRPC/QUIC authentication.
func newGRPCTokenValidator(service quicbaas.ServiceInterface, logger *logging.Logger) *grpcTokenValidator {
	return &grpcTokenValidator{
		service: service,
		logger:  logger,
	}
}

// ValidateToken implements grpc.TokenValidator and quic.TokenValidator.
func (v *grpcTokenValidator) ValidateToken(ctx context.Context, token string) (bool, error) {
	if v.service == nil {
		if v.logger != nil {
			v.logger.Debug("Token validation failed: QuicBaaS service not available")
		}
		return false, ErrQuicBaaSServiceUnavailable{}
	}

	resp, err := v.service.ValidateToken(ctx, &quicbaas.ValidateTokenRequest{
		AccessToken: token,
	})
	if err != nil {
		if v.logger != nil {
			v.logger.Debug("Token validation failed", "error", err)
		}
		return false, ErrTokenValidationFailed{Cause: err}
	}

	return resp.Valid, nil
}

// Start starts the daemon
func (d *Daemon) Start(ctx context.Context) error {
	d.logger.Info("Daemon.Start() called")
	if d.running.Load() {
		return ErrDaemonAlreadyRunning{}
	}

	d.mu.Lock()
	defer d.mu.Unlock()

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

	// Start REST server if enabled
	if d.restServer != nil {
		d.logger.Info("Starting REST server...", "addr", d.config.RESTListenAddr)
		if err := d.restServer.Start(); err != nil {
			d.logger.Warn("REST server start failed", "error", err)
			// Log error but continue - REST operations will fail
		} else {
			d.logger.Info("REST server started successfully")
		}
	}

	// Start MCP server if enabled
	if d.mcpServer != nil {
		d.logger.Info("Starting MCP server...")
		if err := d.mcpServer.Start(); err != nil {
			d.logger.Warn("MCP server start failed", "error", err)
			// Log error but continue - MCP operations will fail
		} else {
			d.logger.Info("MCP server started successfully")
		}
	}

	// Start gRPC TCP server if enabled
	if d.grpcServer != nil && d.config.EnableGRPCTCP {
		listener, err := net.Listen("tcp", d.config.GRPCListenAddr)
		if err != nil {
			d.logger.Error(err, "component", "grpc_listener")
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

	// Start gRPC UDS server if enabled
	if d.grpcUDSServer != nil && d.config.EnableGRPCUDS {
		// Clean up existing socket file
		if err := os.RemoveAll(d.config.GRPCSocketPath); err != nil {
			d.logger.Warn("Failed to remove existing gRPC socket", "error", err)
		}

		listener, err := net.Listen("unix", d.config.GRPCSocketPath)
		if err != nil {
			d.logger.Error(err, "component", "grpc_uds_listener")
			// Stop the TCP gRPC server since we're failing startup
			if d.grpcListener != nil {
				_ = d.grpcListener.Close()
			}
			if d.grpcServer != nil {
				d.grpcServer.Stop()
			}
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

	// Start QUIC server if enabled
	if d.quicServer != nil && d.config.EnableQUIC {
		d.logger.Info("Starting QUIC server...", "addr", d.config.QUICListenAddr)
		if err := d.quicServer.Start(); err != nil {
			d.logger.Error(err, "component", "quic_server")
			// Stop other servers since we're failing startup
			if d.grpcListener != nil {
				_ = d.grpcListener.Close()
			}
			if d.grpcServer != nil {
				d.grpcServer.Stop()
			}
			if d.grpcUDSListener != nil {
				_ = d.grpcUDSListener.Close()
			}
			if d.grpcUDSServer != nil {
				d.grpcUDSServer.Stop()
			}
			if d.restServer != nil && d.restServer.IsRunning() {
				_ = d.restServer.ForceStop()
			}
			if d.mcpServer != nil && d.mcpServer.IsRunning() {
				_ = d.mcpServer.Stop()
			}
			return ErrQUICServerStartFailed{Cause: err}
		}
		d.logger.Info("QUIC server started successfully", "addr", d.quicServer.ListenAddr())
	}

	d.running.Store(true)

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

	d.mu.Lock()
	defer d.mu.Unlock()

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

// ForceStop immediately stops the daemon
func (d *Daemon) ForceStop() error {
	if !d.running.Load() {
		return ErrDaemonNotRunning{}
	}

	d.mu.Lock()
	defer d.mu.Unlock()

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
		TimeoutSeconds: 5,
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

// registerConfiguredServices registers a configManagedService for each
// enabled entry in d.config.Services that has a valid protobuf ServiceType
// mapping, making them visible via ListServices and manageable through
// all protocols (gRPC, REST, CLI, QUIC, MCP, Unix).
func (d *Daemon) registerConfiguredServices() {
	for name, cfg := range d.config.Services {
		if !cfg.Enabled {
			continue
		}
		// Only register services that have a valid protobuf ServiceType mapping.
		// Services without mappings (e.g., kms, vtpm, ca, mcp) cannot be
		// managed through gRPC/CLI which require ServiceType enum values.
		if serviceTypeFromName(name) == platformv1.ServiceType_SERVICE_TYPE_UNSPECIFIED {
			continue
		}
		svc := newConfigManagedService(name, cfg)
		if err := d.RegisterService(svc); err != nil {
			d.logger.Warn("Failed to register configured service", "service", name, "error", err)
		}
	}
}

// autoStartServices starts services configured for auto-start
func (d *Daemon) autoStartServices(ctx context.Context) {
	d.mu.RLock()
	defer d.mu.RUnlock()

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

		// Start the service directly using the state
		state.mu.Lock()
		currentStatus := platformv1.ServiceStatus(state.status.Load())
		if currentStatus == platformv1.ServiceStatus_SERVICE_STATUS_RUNNING {
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
