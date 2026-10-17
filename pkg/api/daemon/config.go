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
	"crypto/tls"
	"crypto/x509"
	"os"
	"time"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	tpconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	restattestation "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/attestation"
)

// Config holds daemon configuration
type Config struct {
	// Application instance
	App *app.App

	// Logger for daemon operations
	Logger *logging.Logger

	// Socket configuration
	SocketPath  string
	SocketGroup string
	SocketMode  os.FileMode

	// gRPC TCP configuration
	EnableGRPCTCP   bool
	GRPCListenAddr  string
	GRPCTLSCertFile string
	GRPCTLSKeyFile  string

	// In-memory TLS certificate (takes precedence over cert/key files)
	// When set, the daemon uses this directly instead of loading from disk.
	TLSCertificate *tls.Certificate

	// TLSIdentity is a renewable in-memory certificate and takes precedence
	// over TLSCertificate. Listeners present whatever it holds at handshake
	// time, so storing a renewed certificate reaches gRPC, QUIC, REST and
	// MCP-HTTP without a restart (#36).
	TLSIdentity *ServingCertificate

	// gRPC Unix Domain Socket configuration
	EnableGRPCUDS  bool   `yaml:"enable_grpc_uds"`
	GRPCSocketPath string `yaml:"grpc_socket_path"`

	// QUIC configuration
	EnableQUIC     bool
	QUICListenAddr string
	QUICConfig     *quic.ServerConfig

	// MCP configuration
	EnableMCP bool
	MCPConfig *MCPConfig

	// REST configuration
	EnableREST      bool
	RESTListenAddr  string
	RESTTLSCertFile string
	RESTTLSKeyFile  string
	RESTConfig      RESTServerConfig

	// Daemon behavior
	ShutdownTimeout   time.Duration
	EnableMetrics     bool
	EnableEvents      bool
	SkipIAMValidation bool // For testing only - skips mandatory IAM check

	// mTLS configuration for mutual TLS authentication
	EnableMTLS       bool           // Enable mutual TLS client certificate authentication
	MTLSClientCAFile string         // Path to CA certificate file for validating client certs
	MTLSClientCAPool *x509.CertPool // Pre-loaded CA cert pool (takes precedence over MTLSClientCAFile)

	// Service configurations
	Services map[string]ServiceConfig

	// CAService is the certificate authority implementation.
	// When set, the daemon will register the CA gRPC service.
	CAService quicbaasca.CACertificateAuthority

	// VTPMService is the vTPM service implementation.
	// When set, the daemon will register the vTPM gRPC service.
	VTPMService vtpm.VTPMService

	// DeviceService is the device service implementation.
	// When set, the daemon will register the device gRPC service.
	DeviceService device.DeviceService

	// DeviceLifecycle is the operator Enable/Disable Device flow (#250).
	// Nil on a control plane without an SDN policy engine: DisableDevice and
	// EnableDevice then answer FailedPrecondition on every transport, since
	// nothing would enforce the state they record.
	DeviceLifecycle DeviceLifecycle

	// DeviceProfileService is the device profile service implementation.
	// Used for device provisioning and profile management.
	DeviceProfileService device.DeviceProfileService

	// DeviceTemplateService is the device template service the REST
	// template handlers use. It backs DeviceService.CreateTemplate and
	// CreateProfileFromTemplate on gRPC, Unix, QUIC and MCP; nil answers
	// Unavailable.
	DeviceTemplateService device.DeviceTemplateService

	// PlatformToken configures the shared broker platform-token validator used
	// across the gRPC, QUIC, and MCP inbound transports. When Enabled, those
	// transports validate the same QuicBaaS OIDC tokens the HTTP path validates
	// (JWKS-by-kid + aud + exp + DPoP where applicable) and enforce scp -> RBAC
	// + tenant_id -> RLS via the AuthorizedContext. When disabled, the legacy
	// per-transport validators are used, so the cutover is additive.
	PlatformToken PlatformTokenConfig

	// PlatformJWTVerifier verifies platform-issued JWT bearer tokens for
	// gRPC TCP / QUIC / MCP transports. When set, the daemon's auth
	// interceptor accepts the same JWTs minted by the webserver's
	// /api/v1/login endpoint, giving non-Unix transports parity with
	// REST. Leave nil to require QuicBaaS-issued OIDC tokens only.
	PlatformJWTVerifier PlatformJWTVerifier

	// PlatformTenantManager is the platform's per-tenant lifecycle manager
	// (CRUD, quotas, VLAN, OVS bridge, DEK, per-tenant cryptographic
	// barrier). When set, the daemon wires it into both the gRPC
	// TenantService server (via SetManager) and the REST tenant handlers
	// (via SetTenantHandlers) so every transport — REST, gRPC, QUIC, MCP,
	// Unix — shares the same tenant manager instance.
	PlatformTenantManager *tenant.Manager

	// PlatformTenantID is the platform's operating (system) tenant: the one
	// tenant the TenantService lets act on other tenants and call its
	// cross-tenant methods, as the REST tenant guards do. Empty admits no
	// tenant-bound caller as the system tenant.
	PlatformTenantID string

	// DNSService is the DNS service implementation.
	// When set, the daemon will register DNS operations on QUIC and MCP.
	DNSService DNSService

	// ComputeOrchestrator is the compute orchestrator for VM and container operations.
	// When set, the daemon will register the Compute gRPC service.
	ComputeOrchestrator compute.Orchestrator

	// AttestationService is the attestation service implementation.
	// When set, the daemon will register the Attestation gRPC service.
	AttestationService AttestationService

	// AttestationReporting carries the reporting service's report view,
	// refresh trigger and caller policy for the gRPC/Unix and MCP
	// transports (#226). Nil on a node without the reporting service.
	AttestationReporting *ReportingHandles

	// AttestationREST is the reporting surface (caller policy, clock, report
	// cache) the daemon's REST listener serves under /api/v1/attestation:
	// the value the webservice registry gets, so both listeners enforce one
	// caller policy. Nil leaves the quote routes operator-only.
	AttestationREST *restattestation.Reporting

	// AttestationEvents backs GET /api/v1/attestation/events on the daemon's
	// REST listener. Nil leaves the route answering unavailable.
	AttestationEvents restattestation.EventReader

	// RegistryService is the artifact registry service implementation.
	// When set, the daemon will register the Registry gRPC service.
	RegistryService grpcapi.RegistryService

	// OVSSocketPath is the path to the Open vSwitch OVSDB socket.
	// When set, the daemon will initialize the SDN service and register
	// SDN, Overlay, and Gateway gRPC services.
	OVSSocketPath string `yaml:"ovs_socket_path"`
}

// csrKMS returns the platform KMS a CSR's key is checked against before the
// CA certifies it, or nil when the daemon runs without one — CSR signing then
// fails closed.
func (c *Config) csrKMS() issuance.KMS {
	if c.App == nil {
		return nil
	}
	if kms := c.App.KMS(); kms != nil {
		return kms
	}
	return nil
}

// MCPConfig holds MCP server configuration
type MCPConfig struct {
	// ServerName is the MCP server name displayed to clients
	ServerName string

	// ServerVersion is the platform version
	ServerVersion string

	// Transport is the transport type: "stdio" or "http"
	Transport string

	// HTTPAddr is the HTTP listen address (for HTTP transport)
	HTTPAddr string

	// RequestTimeout is the default timeout for MCP operations
	RequestTimeout time.Duration

	// MaxConcurrentRequests limits concurrent MCP requests
	MaxConcurrentRequests int
}

// DefaultMCPConfig returns default MCP configuration
func DefaultMCPConfig() *MCPConfig {
	return &MCPConfig{
		ServerName:            "Trusted Platform MCP Server",
		ServerVersion:         "1.0.0",
		Transport:             "http",
		HTTPAddr:              tpconfig.DefaultDaemonListeners().MCP.Address(),
		RequestTimeout:        30 * time.Second,
		MaxConcurrentRequests: 100,
	}
}

// RESTServerConfig holds REST server specific configuration
type RESTServerConfig struct {
	// ReadTimeout is the maximum duration for reading the entire request
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out writes of the response
	WriteTimeout time.Duration

	// IdleTimeout is the maximum amount of time to wait for the next request
	IdleTimeout time.Duration

	// MaxHeaderBytes controls the maximum number of bytes the server will
	// read parsing the request header
	MaxHeaderBytes int

	// EnableCORS enables Cross-Origin Resource Sharing headers
	EnableCORS bool

	// AllowedOrigins specifies which origins are allowed for CORS
	AllowedOrigins []string

	// AllowedMethods specifies which HTTP methods are allowed for CORS
	AllowedMethods []string

	// AllowedHeaders specifies which headers are allowed for CORS
	AllowedHeaders []string

	// EnableCompression enables gzip compression for responses
	EnableCompression bool

	// RateLimitRequests is the maximum number of requests per second (0 = disabled)
	RateLimitRequests int

	// RateLimitBurst is the maximum burst size for rate limiting
	RateLimitBurst int
}

// DefaultRESTServerConfig returns default REST server configuration
func DefaultRESTServerConfig() RESTServerConfig {
	return RESTServerConfig{
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
		EnableCORS:        false,
		AllowedOrigins:    []string{"*"},
		AllowedMethods:    []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:    []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"},
		EnableCompression: true,
		RateLimitRequests: 0, // disabled by default
		RateLimitBurst:    100,
	}
}

// ServiceConfig holds individual service configuration
type ServiceConfig struct {
	Enabled    bool
	AutoStart  bool
	Timeout    time.Duration
	MaxRetries int
}

// DefaultConfig returns default daemon configuration.
//
// The listen addresses are the defaults layer of the 2026-08-26 ruling
// (configuration.md §3, #93): loopback on every transport, as the MCP
// default already was. `platformd serve` replaces them with the resolved
// `daemon:` section (file, environment, flags); a transport reaches an
// interface only because an operator named it (#552).
func DefaultConfig() *Config {
	listeners := tpconfig.DefaultDaemonListeners()
	return &Config{
		SocketPath:      "/run/platformd.sock",
		SocketGroup:     "trusted-platform",
		SocketMode:      0660,
		EnableGRPCTCP:   true,
		GRPCListenAddr:  listeners.GRPC.Address(),
		GRPCTLSCertFile: "",
		GRPCTLSKeyFile:  "",
		EnableGRPCUDS:   true,
		GRPCSocketPath:  "/run/platformd.sock",
		EnableQUIC:      false,
		QUICListenAddr:  listeners.QUIC.Address(),
		QUICConfig:      nil,
		EnableMCP:       false,
		MCPConfig:       DefaultMCPConfig(),
		EnableREST:      true,
		RESTListenAddr:  listeners.REST.Address(),
		RESTTLSCertFile: "",
		RESTTLSKeyFile:  "",
		RESTConfig:      DefaultRESTServerConfig(),
		ShutdownTimeout: 30 * time.Second,
		EnableMetrics:   true,
		EnableEvents:    true,
		EnableMTLS:      false,
		Services: map[string]ServiceConfig{
			"tpm": {
				Enabled:    true,
				AutoStart:  true,
				Timeout:    10 * time.Second,
				MaxRetries: 3,
			},
			"sdn": {
				Enabled:    true,
				AutoStart:  false,
				Timeout:    15 * time.Second,
				MaxRetries: 3,
			},
			"compute": {
				Enabled:    true,
				AutoStart:  false,
				Timeout:    20 * time.Second,
				MaxRetries: 3,
			},
			"dns": {
				Enabled:    true,
				AutoStart:  false,
				Timeout:    10 * time.Second,
				MaxRetries: 3,
			},
			"acme": {
				Enabled:    true,
				AutoStart:  false,
				Timeout:    10 * time.Second,
				MaxRetries: 3,
			},
			"webservice": {
				Enabled:    true,
				AutoStart:  false,
				Timeout:    15 * time.Second,
				MaxRetries: 3,
			},
			"attestation": {
				Enabled:    true,
				AutoStart:  false,
				Timeout:    10 * time.Second,
				MaxRetries: 3,
			},
			"kms": {
				Enabled:    true,
				AutoStart:  true,
				Timeout:    10 * time.Second,
				MaxRetries: 3,
			},
			"vtpm": {
				Enabled:    true,
				AutoStart:  true,
				Timeout:    10 * time.Second,
				MaxRetries: 3,
			},
			"ca": {
				Enabled:    true,
				AutoStart:  true,
				Timeout:    10 * time.Second,
				MaxRetries: 3,
			},
			"mcp": {
				Enabled:    true,
				AutoStart:  true,
				Timeout:    10 * time.Second,
				MaxRetries: 3,
			},
		},
	}
}

// Validate checks if the configuration is valid
// tlsCertificateUsable reports whether an in-memory certificate can
// actually complete a TLS handshake: a non-nil struct with at least one
// certificate in the chain and a private key. A bare &tls.Certificate{}
// would let a listener bind and report success while every handshake
// fails — structurally unusable material is treated as absent (#32).
func tlsCertificateUsable(cert *tls.Certificate) bool {
	return cert != nil && len(cert.Certificate) > 0 && cert.PrivateKey != nil
}

// grpcTLSMaterialPresent reports whether the gRPC TCP transport has TLS
// material to serve with: a USABLE in-memory certificate or a cert/key
// file pair. New uses it to decide whether transport credentials can be
// built and the preflight uses it to refuse a plaintext TCP listener
// (#32) — both sides of the fail-closed contract share one definition of
// "material present".
func (c *Config) grpcTLSMaterialPresent() bool {
	return tlsCertificateUsable(c.inMemoryCertificate()) || (c.GRPCTLSCertFile != "" && c.GRPCTLSKeyFile != "")
}

// inMemoryCertificate returns the in-memory certificate the listeners serve:
// the one TLSIdentity currently holds when it is set, else TLSCertificate.
func (c *Config) inMemoryCertificate() *tls.Certificate {
	if c.TLSIdentity != nil {
		return c.TLSIdentity.Current()
	}
	return c.TLSCertificate
}

// quicTLSMaterialPresent reports whether the QUIC transport has a TLS
// configuration that can actually serve: a tls.Config carrying at least one
// USABLE certificate (tlsCertificateUsable — a structurally empty entry
// cannot complete a handshake), a GetCertificate callback, or a
// GetConfigForClient callback (crypto/tls's third certificate-supplying
// mechanism — the returned per-client config carries the certificate).
func (c *Config) quicTLSMaterialPresent() bool {
	if c.QUICConfig == nil || c.QUICConfig.TLSConfig == nil {
		return false
	}
	tlsConfig := c.QUICConfig.TLSConfig
	for i := range tlsConfig.Certificates {
		if tlsCertificateUsable(&tlsConfig.Certificates[i]) {
			return true
		}
	}
	return tlsConfig.GetCertificate != nil ||
		tlsConfig.GetConfigForClient != nil
}

func (c *Config) Validate() error {
	if c.SocketPath == "" {
		return ErrInvalidConfig{Reason: "socket path cannot be empty"}
	}

	if c.ShutdownTimeout <= 0 {
		return ErrInvalidConfig{Reason: "shutdown timeout must be positive"}
	}

	// Validate gRPC UDS configuration if enabled
	if c.EnableGRPCUDS {
		if c.GRPCSocketPath == "" {
			return ErrInvalidConfig{Reason: "gRPC socket path cannot be empty when gRPC UDS is enabled"}
		}
	}

	// Validate QUIC configuration if enabled
	if c.EnableQUIC {
		if c.QUICListenAddr == "" {
			return ErrInvalidConfig{Reason: "QUIC listen address cannot be empty when QUIC is enabled"}
		}
		if c.QUICConfig != nil {
			if err := c.QUICConfig.Validate(); err != nil {
				return ErrInvalidConfig{Reason: "invalid QUIC configuration: " + err.Error()}
			}
		}
	}

	// Validate MCP configuration if enabled
	if c.EnableMCP {
		if err := c.validateMCPConfig(); err != nil {
			return err
		}
	}

	// Validate REST configuration if enabled
	if c.EnableREST {
		if c.RESTListenAddr == "" {
			return ErrInvalidConfig{Reason: "REST listen address cannot be empty when REST is enabled"}
		}
		if err := c.RESTConfig.Validate(); err != nil {
			return err
		}
	}

	// Validate mTLS configuration if enabled
	if c.EnableMTLS {
		if c.MTLSClientCAFile == "" && c.MTLSClientCAPool == nil {
			return ErrInvalidConfig{Reason: "mTLS enabled but no client CA file or cert pool configured"}
		}
	}

	for name, svc := range c.Services {
		if svc.Timeout <= 0 {
			return ErrInvalidConfig{Reason: "service " + name + " timeout must be positive"}
		}
		if svc.MaxRetries < 0 {
			return ErrInvalidConfig{Reason: "service " + name + " max retries cannot be negative"}
		}
	}

	return nil
}

// validateGRPCAuthorization refuses a gRPC TCP listener that could authorize
// nothing: one that would send every scoped call to the IAM policy
// enforcement point while that point is the embedded quicbaas SDK, which
// answers every Check ServiceNotConfigured. daemon.New runs it at startup;
// NewService does not, because it serves no listener.
func (c *Config) validateGRPCAuthorization() error {
	if c.grpcAuthorizesThroughPEP() && c.quicbaasEmbedded() {
		return ErrEmbeddedPEPUnavailable{Transport: transportGRPCTCP}
	}
	return nil
}

// grpcAuthorizesThroughPEP reports whether the gRPC TCP listener will hand
// every scoped call to the IAM policy enforcement point. That is the
// selectGRPCTCPAuth path left when neither mTLS, platform tokens nor the
// testing-only SkipIAMValidation opt-out is in force.
func (c *Config) grpcAuthorizesThroughPEP() bool {
	return c.EnableGRPCTCP && !c.EnableMTLS && !c.SkipIAMValidation && !c.PlatformToken.Enabled
}

// quicbaasEmbedded reports whether the IAM service, and so its policy
// enforcement point, runs on the embedded quicbaas SDK. An absent quicbaas
// section is the embedded default. Without an App there is no IAM service at
// all, which selectGRPCTCPAuth refuses on its own.
func (c *Config) quicbaasEmbedded() bool {
	if c.App == nil {
		return false
	}
	return c.App.QuicBaaSConfig == nil || c.App.QuicBaaSConfig.IsEmbedded()
}

// MCPServesHTTP reports whether the MCP server is enabled on its HTTP
// transport. That transport binds a network listener and serves TLS 1.3
// only, so it needs the daemon TLS identity just as REST and gRPC do
// (#844); stdio does not. A nil MCPConfig means the default, which is HTTP.
func (c *Config) MCPServesHTTP() bool {
	if !c.EnableMCP {
		return false
	}
	return c.effectiveMCPConfig().Transport == "http"
}

// effectiveMCPConfig returns the MCP configuration the daemon runs with:
// MCPConfig when set, otherwise DefaultMCPConfig.
func (c *Config) effectiveMCPConfig() *MCPConfig {
	if c.MCPConfig == nil {
		return DefaultMCPConfig()
	}
	return c.MCPConfig
}

// validateMCPConfig validates MCP-specific configuration
func (c *Config) validateMCPConfig() error {
	if c.MCPConfig == nil {
		c.MCPConfig = DefaultMCPConfig()
		return nil
	}

	if c.MCPConfig.Transport != "stdio" && c.MCPConfig.Transport != "http" {
		return ErrInvalidConfig{Reason: "MCP transport must be 'stdio' or 'http'"}
	}

	if c.MCPConfig.Transport == "http" && c.MCPConfig.HTTPAddr == "" {
		return ErrInvalidConfig{Reason: "MCP HTTP address cannot be empty when transport is 'http'"}
	}

	if c.MCPConfig.RequestTimeout <= 0 {
		return ErrInvalidConfig{Reason: "MCP request timeout must be positive"}
	}

	if c.MCPConfig.MaxConcurrentRequests <= 0 {
		return ErrInvalidConfig{Reason: "MCP max concurrent requests must be positive"}
	}

	return nil
}

// Validate checks if the REST server configuration is valid
func (c *RESTServerConfig) Validate() error {
	if c.ReadTimeout <= 0 {
		return ErrInvalidConfig{Reason: "REST read timeout must be positive"}
	}
	if c.WriteTimeout <= 0 {
		return ErrInvalidConfig{Reason: "REST write timeout must be positive"}
	}
	if c.IdleTimeout <= 0 {
		return ErrInvalidConfig{Reason: "REST idle timeout must be positive"}
	}
	if c.MaxHeaderBytes <= 0 {
		return ErrInvalidConfig{Reason: "REST max header bytes must be positive"}
	}
	if c.RateLimitRequests < 0 {
		return ErrInvalidConfig{Reason: "REST rate limit requests cannot be negative"}
	}
	if c.RateLimitBurst < 0 {
		return ErrInvalidConfig{Reason: "REST rate limit burst cannot be negative"}
	}
	return nil
}
