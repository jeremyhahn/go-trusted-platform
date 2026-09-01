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

// Package quicbaas provides a QuicBaaS-backed datastore implementation for the
// Trusted Platform. It implements the datastore.Factory interface and provides
// GenericDAO implementations backed by QuicBaaS's embedded or distributed storage.
package quicbaas

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// Transport defines the transport type for QuicBaaS connections.
// This enables multi-transport support while maintaining backward
// compatibility with the default embedded mode.
type Transport int

const (
	// TransportEmbedded uses in-process direct service access (default).
	// This is the original behavior - QuicBaaS runs embedded in the same process.
	TransportEmbedded Transport = iota
	// TransportUnix uses gRPC over Unix Domain Socket for local IPC.
	TransportUnix
	// TransportGRPC uses gRPC protocol for high-performance remote connections.
	TransportGRPC
	// TransportREST uses REST/HTTP protocol for web clients.
	TransportREST
	// TransportQUIC uses QUIC protocol for low-latency connections.
	TransportQUIC
)

// String returns the string representation of the transport type.
func (t Transport) String() string {
	switch t {
	case TransportEmbedded:
		return "embedded"
	case TransportUnix:
		return "unix"
	case TransportGRPC:
		return "grpc"
	case TransportREST:
		return "rest"
	case TransportQUIC:
		return "quic"
	default:
		return "unknown"
	}
}

// ParseTransport parses a string into a Transport type.
// Returns TransportEmbedded as the default for empty or unrecognized values.
func ParseTransport(s string) (Transport, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "embedded":
		return TransportEmbedded, nil
	case "unix":
		return TransportUnix, nil
	case "grpc":
		return TransportGRPC, nil
	case "rest":
		return TransportREST, nil
	case "quic":
		return TransportQUIC, nil
	default:
		return TransportEmbedded, ErrInvalidTransport{Value: s}
	}
}

// Config holds the configuration for the QuicBaaS storage backend.
// This is the primary database configuration for go-trusted-platform.
//
// Transport configuration supports the following modes:
//   - embedded: In-process direct service access (default, original behavior)
//   - unix: gRPC over Unix Domain Socket for local IPC
//   - grpc: gRPC protocol for high-performance remote connections
//   - rest: REST/HTTP protocol for web clients
//   - quic: QUIC protocol for low-latency connections
//
// Example YAML configuration:
//
//	quicbaas:
//	  transport: embedded  # embedded, unix, grpc, rest, quic
//	  address: "localhost:10443"  # for remote transports
//	  unix-socket: "/var/run/quicbaas.sock"  # for unix transport
//	  storage-backend: pebble
//	  data-dir: /var/lib/platform/quicbaas
type Config struct {
	// TransportStr is the string representation of the transport type for YAML/config parsing.
	// Use this field in config files. Valid values: embedded, unix, grpc, rest, quic.
	// This field is parsed into Transport during config processing.
	TransportStr string `yaml:"transport" json:"transport" mapstructure:"transport"`

	// Transport specifies the transport type for QuicBaaS connections (parsed from TransportStr).
	// Default: TransportEmbedded (in-process, original behavior).
	// This field is set programmatically after parsing TransportStr.
	Transport Transport `yaml:"-" json:"-" mapstructure:"-"`

	// Address is the address for remote transports (gRPC, REST, QUIC).
	// Format depends on transport: "host:port" for gRPC/QUIC, "http://host:port" for REST.
	// Ignored for embedded and unix transports.
	Address string `yaml:"address" json:"address" mapstructure:"address"`

	// UnixSocket is the Unix socket path for TransportUnix.
	// Example: "/var/run/quicbaas.sock"
	// Ignored for other transports.
	UnixSocket string `yaml:"unix-socket" json:"unix_socket" mapstructure:"unix-socket"`

	// StorageBackend specifies the storage backend type:
	//   - "memory": In-memory storage, no persistence (testing/ephemeral workloads)
	//   - "file": Simple file-based storage (development/low-volume)
	//   - "pebble": PebbleDB for high-performance local storage (recommended)
	// Default: "pebble" for high-performance local storage.
	// Raft consensus is enabled separately via server mode, not storage backend.
	// Use quicbaas.StorageBackendPebble, quicbaas.StorageBackendMemory, etc.
	StorageBackend string `yaml:"storage-backend" json:"storage_backend" mapstructure:"storage-backend"`

	// DataDir is the directory where QuicBaaS stores its data files.
	// Required in embedded mode.
	DataDir string `yaml:"data-dir" json:"data_dir" mapstructure:"data-dir"`

	// WALDir is the directory for write-ahead log files.
	// Defaults to DataDir/wal if not specified.
	WALDir string `yaml:"wal-dir" json:"wal_dir" mapstructure:"wal-dir"`

	// SPIFFETrustDomain is the SPIFFE trust domain handed to the embedded
	// QuicBaaS server's IAM (iam.spiffe_trust_domain). qrdb's first-boot
	// REQUIRES it to issue the tenant-scoped SPIFFE admin certificate;
	// without it the entire IAM bootstrap fails on every boot — no system
	// tenant, no built-in roles, no platform admin — and every
	// tenant-scoped surface (WebAuthn ceremonies, operating-tenant
	// adoption) is dead. Role templates set it to the deployment's
	// internal domain.
	SPIFFETrustDomain string `yaml:"spiffe-trust-domain" json:"spiffe_trust_domain" mapstructure:"spiffe-trust-domain"`

	// SelfServiceRegistration mirrors the canonical stack-wide flag
	// iam.self_service_registration (docs/08-bootstrap-auth-contract.md,
	// amended 2026-09-01): enabled, an anonymous registrant may
	// self-register, which creates a new tenant with them as its admin;
	// disabled (the DEFAULT — invite-only), tenants are provisioned by
	// the system admin and registration requires an invitation. The
	// platform enforces the flag on its own console registration surface
	// and passes it through to the embedded server's IAM config.
	SelfServiceRegistration *SelfServiceRegistrationConfig `yaml:"self-service-registration,omitempty" json:"self_service_registration,omitempty" mapstructure:"self-service-registration"`

	// WebAuthnRPID, WebAuthnRPDisplayName and WebAuthnRPOrigins configure
	// the embedded server's IAM WebAuthn relying party (iam.webauthn.*).
	// They are populated programmatically from the platform's primary
	// webservice webauthn section — the single YAML source for RP
	// identity — before the factory starts; they are NOT platform YAML
	// keys. Left empty, quicbaas derives a localhost issuer default and
	// browsers reject every ceremony on a real origin.
	WebAuthnRPID          string   `yaml:"-" json:"-" mapstructure:"-"`
	WebAuthnRPDisplayName string   `yaml:"-" json:"-" mapstructure:"-"`
	WebAuthnRPOrigins     []string `yaml:"-" json:"-" mapstructure:"-"`

	// RaftAddress is the address for Raft consensus communication.
	// Required when StorageBackend is "raft".
	// Format: "host:port"
	RaftAddress string `yaml:"raft-address" json:"raft_address" mapstructure:"raft-address"`

	// JoinAddresses is a list of peer addresses to join for multi-node clusters.
	// Only used with "raft" backend for production clusters.
	JoinAddresses []string `yaml:"join-addresses" json:"join_addresses" mapstructure:"join-addresses"`

	// NodeID is the unique identifier for this node in the cluster.
	// Must be unique across all nodes.
	NodeID uint64 `yaml:"node-id" json:"node_id" mapstructure:"node-id"`

	// CacheSize is the size of the in-memory cache in bytes.
	// Defaults to 128MB.
	CacheSize int64 `yaml:"cache-size" json:"cache_size" mapstructure:"cache-size"`

	// LogLevel controls the verbosity of QuicBaaS logging.
	// Valid values: "debug", "info", "warn", "error"
	LogLevel string `yaml:"log-level" json:"log_level" mapstructure:"log-level"`

	// ConsistencyLevel sets the default consistency for read operations.
	// Can be overridden per-operation.
	ConsistencyLevel ConsistencyLevel `yaml:"consistency-level" json:"consistency_level" mapstructure:"consistency-level"`

	// Compression enables data compression.
	// Valid values: "none", "snappy", "zstd"
	Compression string `yaml:"compression" json:"compression" mapstructure:"compression"`

	// SyncWrites enables synchronous writes to disk.
	// Improves durability at the cost of performance.
	SyncWrites bool `yaml:"sync-writes" json:"sync_writes" mapstructure:"sync-writes"`

	// RequestTimeout is the timeout for QuicBaaS operations.
	RequestTimeout time.Duration `yaml:"request-timeout" json:"request_timeout" mapstructure:"request-timeout"`
}

// ConsistencyLevel defines read consistency guarantees.
type ConsistencyLevel int

const (
	// ConsistencyLinearizable provides linearizable reads (recommended default).
	// Uses Raft ReadIndex optimization for low latency (1-5ms).
	ConsistencyLinearizable ConsistencyLevel = iota

	// ConsistencyStrong requires full Raft consensus on every read.
	// Strongest guarantee but highest latency (10-50ms).
	ConsistencyStrong

	// ConsistencyEventual allows reading from local node without coordination.
	// Fastest (<1ms) but may return stale data.
	ConsistencyEventual
)

// String returns the string representation of the consistency level.
func (c ConsistencyLevel) String() string {
	switch c {
	case ConsistencyLinearizable:
		return "linearizable"
	case ConsistencyStrong:
		return "strong"
	case ConsistencyEventual:
		return "eventual"
	default:
		return "unknown"
	}
}

// ParseConsistencyLevel parses a string into a ConsistencyLevel.
// Returns ConsistencyLinearizable as the default for unrecognized values.
func ParseConsistencyLevel(s string) ConsistencyLevel {
	switch strings.ToLower(s) {
	case "strong":
		return ConsistencyStrong
	case "eventual":
		return ConsistencyEventual
	case "linearizable":
		return ConsistencyLinearizable
	default:
		return ConsistencyLinearizable
	}
}

// UnmarshalText implements encoding.TextUnmarshaler for ConsistencyLevel.
// This enables YAML/JSON/mapstructure to decode string values like "linearizable"
// into the ConsistencyLevel enum.
func (c *ConsistencyLevel) UnmarshalText(text []byte) error {
	*c = ParseConsistencyLevel(string(text))
	return nil
}

// MarshalText implements encoding.TextMarshaler for ConsistencyLevel.
// This enables YAML/JSON/mapstructure to encode the ConsistencyLevel enum
// as a human-readable string.
func (c ConsistencyLevel) MarshalText() ([]byte, error) {
	return []byte(c.String()), nil
}

// DefaultConfig returns a configuration suitable for embedded single-node usage.
// Uses PebbleDB backend for high-performance local storage (fastest, single-node only).
// KMS is supported in all backends.
func DefaultConfig() *Config {
	return &Config{
		TransportStr:      "embedded",
		Transport:         TransportEmbedded,
		StorageBackend:    quicbaas.StorageBackendPebble, // High-performance local storage (fastest)
		SPIFFETrustDomain: "example.internal",
		DataDir:           "./data/quicbaas",
		WALDir:            "./data/quicbaas/wal",
		RaftAddress:       "127.0.0.1:63000",
		NodeID:            1,
		CacheSize:         128 * 1024 * 1024, // 128MB
		LogLevel:          "info",
		ConsistencyLevel:  ConsistencyLinearizable,
		Compression:       "snappy",
		SyncWrites:        true,
		RequestTimeout:    5 * time.Second,
	}
}

// TestConfig returns a configuration optimized for unit testing.
// Uses minimal resources and fast timeouts. Creates a temporary
// directory that will be cleaned up when the test completes.
// Uses PebbleDB backend for high-performance local storage without Raft.
// For faster unit tests that don't need persistence, use MemoryTestConfig instead.
func TestConfig(t TestingT) *Config {
	t.Helper()
	dataDir := t.TempDir()
	port := getFreePort()
	return &Config{
		TransportStr:      "embedded",
		Transport:         TransportEmbedded,
		StorageBackend:    quicbaas.StorageBackendPebble, // High-performance local storage, no Raft
		SPIFFETrustDomain: "example.internal",
		DataDir:           dataDir,
		WALDir:            dataDir + "/wal",
		RaftAddress:       fmt.Sprintf("127.0.0.1:%d", port),
		NodeID:            1,
		CacheSize:         8 * 1024 * 1024, // 8MB
		LogLevel:          "error",         // Reduce log noise in tests
		ConsistencyLevel:  ConsistencyLinearizable,
		Compression:       "none",
		SyncWrites:        false,
		RequestTimeout:    30 * time.Second,
	}
}

// MemoryTestConfig returns a configuration using in-memory storage.
// This is the fastest option for unit tests that don't need persistence.
// Data is lost when the server stops - ideal for isolated test cases.
func MemoryTestConfig(t TestingT) *Config {
	t.Helper()
	dataDir := t.TempDir() // Still needed for some internal operations
	return &Config{
		TransportStr:      "embedded",
		Transport:         TransportEmbedded,
		StorageBackend:    quicbaas.StorageBackendMemory,
		SPIFFETrustDomain: "example.internal",
		DataDir:           dataDir,
		WALDir:            dataDir + "/wal",
		RaftAddress:       "",              // Not needed for memory backend
		NodeID:            0,               // Not needed for memory backend
		CacheSize:         4 * 1024 * 1024, // 4MB - smaller for tests
		LogLevel:          "error",
		ConsistencyLevel:  ConsistencyEventual, // Memory is always consistent
		Compression:       "none",
		SyncWrites:        false,
		RequestTimeout:    10 * time.Second,
	}
}

// FileTestConfig returns a configuration using file-based storage.
// Each key-value pair is stored as a separate file, making it easy
// to inspect and debug data. Slower than Pebble but human-readable.
func FileTestConfig(t TestingT) *Config {
	t.Helper()
	dataDir := t.TempDir()
	return &Config{
		TransportStr:      "embedded",
		Transport:         TransportEmbedded,
		StorageBackend:    quicbaas.StorageBackendFile,
		SPIFFETrustDomain: "example.internal",
		DataDir:           dataDir,
		WALDir:            dataDir + "/wal",
		RaftAddress:       "",              // Not needed for file backend
		NodeID:            0,               // Not needed for file backend
		CacheSize:         4 * 1024 * 1024, // 4MB
		LogLevel:          "debug",         // Debug level for visibility
		ConsistencyLevel:  ConsistencyLinearizable,
		Compression:       "none", // No compression for readability
		SyncWrites:        true,   // Sync for debugging reliability
		RequestTimeout:    30 * time.Second,
	}
}

// RaftTestConfig returns a configuration suitable for Raft cluster testing.
// Uses PebbleDB storage with Raft-related settings configured.
// Note: Raft consensus is enabled via server mode, not storage backend.
// This config just ensures Raft address and NodeID are set for cluster tests.
func RaftTestConfig(t TestingT) *Config {
	t.Helper()
	dataDir := t.TempDir()
	port := getFreePort()
	return &Config{
		TransportStr:      "embedded",
		Transport:         TransportEmbedded,
		StorageBackend:    quicbaas.StorageBackendPebble, // Raft uses pebble for storage
		SPIFFETrustDomain: "example.internal",
		DataDir:           dataDir,
		WALDir:            dataDir + "/wal",
		RaftAddress:       fmt.Sprintf("127.0.0.1:%d", port),
		NodeID:            1,
		CacheSize:         8 * 1024 * 1024, // 8MB
		LogLevel:          "error",
		ConsistencyLevel:  ConsistencyLinearizable,
		Compression:       "snappy",
		SyncWrites:        true,
		RequestTimeout:    30 * time.Second,
	}
}

// RemoteConfig returns a configuration for connecting to a remote QuicBaaS server.
// This is useful for client mode where the database runs externally.
func RemoteConfig(transport Transport, address string) *Config {
	return &Config{
		TransportStr:     transport.String(),
		Transport:        transport,
		Address:          address,
		RequestTimeout:   30 * time.Second,
		ConsistencyLevel: ConsistencyLinearizable,
	}
}

// UnixSocketConfig returns a configuration for connecting via Unix socket.
// This is the preferred transport for local CLI tools and services.
func UnixSocketConfig(socketPath string) *Config {
	return &Config{
		TransportStr:     "unix",
		Transport:        TransportUnix,
		UnixSocket:       socketPath,
		RequestTimeout:   30 * time.Second,
		ConsistencyLevel: ConsistencyLinearizable,
	}
}

// ParseTransportFromConfig parses the TransportStr field and sets the Transport field.
// This should be called after loading config from YAML/JSON to ensure the Transport
// enum is properly set from the string value.
// Returns an error if the transport string is invalid.
func (c *Config) ParseTransportFromConfig() error {
	if c.TransportStr == "" {
		// Default to embedded if not specified
		c.Transport = TransportEmbedded
		c.TransportStr = "embedded"
		return nil
	}

	transport, err := ParseTransport(c.TransportStr)
	if err != nil {
		return err
	}
	c.Transport = transport
	return nil
}

// SetTransport sets both the Transport enum and TransportStr string fields.
// Use this method when setting transport programmatically to ensure consistency.
func (c *Config) SetTransport(transport Transport) {
	c.Transport = transport
	c.TransportStr = transport.String()
}

// getFreePort returns an available TCP port by briefly binding to port 0.
// Returns 0 if no port can be found (e.g., loopback interface not available).
func getFreePort() int {
	// Try localhost first
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		// Try binding to any interface as fallback
		listener, err = net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			// In initrd/early boot, network may not be available
			// Return a default port instead of panicking
			return 17001
		}
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

// GetFreeAddress returns a free localhost address in the format "127.0.0.1:PORT".
// This is useful for embedded mode when no specific Raft address is configured.
// Falls back to a default port if network is unavailable (e.g., during initrd boot).
func GetFreeAddress() string {
	return fmt.Sprintf("127.0.0.1:%d", getFreePort())
}

// TestingT is a minimal interface for testing helpers.
// Satisfied by *testing.T and *testing.B.
type TestingT interface {
	TempDir() string
	Name() string
	Helper()
}

// ToQuicBaaSConfig converts our Config to go-quicbaas's native config.Config.
// This is only applicable for embedded transport mode.
func (c *Config) ToQuicBaaSConfig() *quicbaas.ServerFullConfig {
	cfg := quicbaas.EmbeddedServerConfig()

	// Storage backend - default to pebble (high-performance local storage)
	if c.StorageBackend != "" {
		cfg.Storage.Backend = c.StorageBackend
	} else {
		cfg.Storage.Backend = quicbaas.StorageBackendPebble // High-performance local storage (fastest)
	}

	// Storage settings
	cfg.Storage.DataDir = c.DataDir
	if c.WALDir != "" {
		cfg.Storage.WALDir = c.WALDir
	} else {
		cfg.Storage.WALDir = c.DataDir + "/wal"
	}
	cfg.Storage.CacheSize = c.CacheSize
	cfg.Storage.SyncWrites = c.SyncWrites
	cfg.Storage.CompressionType = c.Compression

	// Raft settings (only used in cluster/node modes)
	cfg.Raft.NodeID = c.NodeID
	cfg.Raft.RaftAddress = c.RaftAddress
	cfg.Raft.ListenAddress = c.RaftAddress
	cfg.Raft.RequestTimeout = c.RequestTimeout

	// Join addresses for multi-node production clusters
	if len(c.JoinAddresses) > 0 {
		cfg.Raft.JoinAddresses = c.JoinAddresses
	}

	// Logging
	cfg.Logging.Level = c.LogLevel
	cfg.Logging.Format = "json"

	// IAM: the SPIFFE trust domain gates qrdb's first-boot admin
	// certificate — and with it the creation of the system tenant and
	// built-in roles. Left empty, first-boot IAM bootstrap fails (WARN)
	// and the server runs without a system tenant or admin.
	cfg.IAM.SPIFFETrustDomain = c.SPIFFETrustDomain

	// Canonical registration flag → the embedded server's
	// iam.self_service_registration (go-quicbaas#358 wires the consumer
	// side; passing it through now means the platform is already correct
	// when that lands).
	if c.SelfServiceRegistration != nil {
		cfg.IAM.SelfServiceRegistration.Enabled = c.SelfServiceRegistration.Enabled
	}

	// IAM WebAuthn relying party: mirrors the platform webservice
	// webauthn section so the per-tenant RP the SDK builds matches the
	// origin the console is actually served on.
	cfg.IAM.WebAuthn.RPID = c.WebAuthnRPID
	cfg.IAM.WebAuthn.RPDisplayName = c.WebAuthnRPDisplayName
	cfg.IAM.WebAuthn.RPOrigins = c.WebAuthnRPOrigins

	// Enable KMS for key management operations
	// This is required for DNSSEC key management and other crypto operations.
	// Use DefaultKMSConfig() to ensure all sub-configs (Cache, Safety, Defaults, etc.)
	// are properly initialized, as EmbeddedConfig() doesn't include a KMS section.
	cfg.KMS = quicbaas.DefaultKMSConfig()
	cfg.KMS.Enabled = true
	cfg.KMS.Backend = quicbaas.KMSBackendSoftware

	// Enable ObjectStorage with a default local backend.
	// This is required for CA cert storage, ACME state, and platform objects.
	// The local backend stores objects at DataDir/objectstorage/.
	cfg.ObjectStorage.Enabled = true
	if cfg.ObjectStorage.Backends == nil {
		cfg.ObjectStorage.Backends = make(map[string]*quicbaas.StorageBackendConfig)
	}
	if len(cfg.ObjectStorage.Backends) == 0 {
		cfg.ObjectStorage.Backends["default"] = &quicbaas.StorageBackendConfig{
			Type: "local",
			Config: map[string]string{
				"path": c.DataDir + "/objectstorage",
			},
			Description: "Default local object storage backend",
		}
	}

	return cfg
}

// SelfServiceRegistrationConfig is the platform's carrier for the
// canonical iam.self_service_registration flag. Only Enabled is
// consumed today; the remaining upstream sub-keys
// (require_admin_approval, default_role, allowed_isolation_modes)
// join when go-quicbaas#358 wires their consumer side.
type SelfServiceRegistrationConfig struct {
	// Enabled turns anonymous self-registration (and with it
	// self-service tenant creation) on. Default false: invite-only.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
}

// Active reports whether self-service registration is enabled. A nil
// receiver is the absent section and means disabled — the secure
// default.
func (c *SelfServiceRegistrationConfig) Active() bool {
	return c != nil && c.Enabled
}

// spiffeTrustDomainPattern matches a valid SPIFFE trust domain name:
// lowercase alphanumerics, dots, hyphens and underscores, starting and
// ending with an alphanumeric (per the SPIFFE ID specification's trust
// domain charset).
var spiffeTrustDomainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)

// validateSPIFFETrustDomain rejects an absent or malformed SPIFFE trust
// domain for embedded-server configurations.
func validateSPIFFETrustDomain(domain string) error {
	if domain == "" {
		return ErrInvalidConfig{Field: "SPIFFETrustDomain", Reason: "spiffe-trust-domain is required for the embedded server: qrdb first-boot cannot seed IAM (system tenant, roles, admin certificate) without it"}
	}
	if len(domain) > 255 || !spiffeTrustDomainPattern.MatchString(domain) {
		return ErrInvalidConfig{Field: "SPIFFETrustDomain", Reason: "spiffe-trust-domain must be a lowercase name of alphanumerics, dots, hyphens and underscores (max 255 chars), without scheme, port or path"}
	}
	return nil
}

// SetDefaults sets default values for zero-valued fields.
// This ensures the config has sensible defaults when fields are omitted from YAML/JSON.
func (c *Config) SetDefaults() {
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 30 * time.Second // Default 30s timeout
	}
	if c.CacheSize <= 0 {
		c.CacheSize = 128 * 1024 * 1024 // Default 128MB cache
	}
	// Note: ConsistencyLevel defaults to ConsistencyLinearizable (0) which is the Go zero value
	if c.StorageBackend == "" {
		c.StorageBackend = quicbaas.StorageBackendPebble // Default to pebble
	}
	// Default WALDir to DataDir/wal if not specified but DataDir is set
	if c.WALDir == "" && c.DataDir != "" {
		c.WALDir = c.DataDir + "/wal"
	}
}

// Validate checks that the configuration is valid.
// This method also parses TransportStr into Transport if not already done.
// It also sets default values for zero-valued fields.
func (c *Config) Validate() error {
	// Set defaults for zero-valued fields first
	c.SetDefaults()

	// Parse transport from string if needed
	if c.Transport == TransportEmbedded && c.TransportStr != "" && c.TransportStr != "embedded" {
		if err := c.ParseTransportFromConfig(); err != nil {
			return err
		}
	}

	// Validate common fields (after defaults are applied, these should always pass)
	if c.RequestTimeout <= 0 {
		return ErrInvalidConfig{Field: "RequestTimeout", Reason: "request timeout must be positive"}
	}

	// Validate transport-specific requirements
	switch c.Transport {
	case TransportEmbedded:
		// Embedded mode requires storage configuration
		return c.validateEmbeddedConfig()
	case TransportUnix:
		// Unix socket mode requires socket path
		if c.UnixSocket == "" {
			return ErrInvalidConfig{Field: "UnixSocket", Reason: "unix socket path is required for unix transport"}
		}
	case TransportGRPC, TransportQUIC:
		// gRPC and QUIC require address
		if c.Address == "" {
			return ErrInvalidConfig{Field: "Address", Reason: fmt.Sprintf("address is required for %s transport", c.Transport)}
		}
	case TransportREST:
		// REST requires address (URL)
		if c.Address == "" {
			return ErrInvalidConfig{Field: "Address", Reason: "address (URL) is required for rest transport"}
		}
	default:
		return ErrInvalidConfig{Field: "Transport", Reason: fmt.Sprintf("unsupported transport type: %d", c.Transport)}
	}

	return nil
}

// validateEmbeddedConfig validates configuration for embedded mode.
func (c *Config) validateEmbeddedConfig() error {
	// Validate storage backend-specific requirements
	switch c.StorageBackend {
	case quicbaas.StorageBackendMemory:
		// Memory backend: no persistence, no Raft
		// DataDir/WALDir still needed for some internal operations but can be minimal
		// RaftAddress and NodeID not required
	case quicbaas.StorageBackendFile:
		// File backend: simple file-based storage, no Raft
		// Requires DataDir for storing files
		if c.DataDir == "" {
			return ErrInvalidConfig{Field: "DataDir", Reason: "data directory is required for file backend"}
		}
	case quicbaas.StorageBackendPebble:
		// Pebble backend: high-performance local storage
		// Requires DataDir and WALDir
		if c.DataDir == "" {
			return ErrInvalidConfig{Field: "DataDir", Reason: "data directory is required for pebble backend"}
		}
		if c.WALDir == "" {
			return ErrInvalidConfig{Field: "WALDir", Reason: "WAL directory is required for pebble backend"}
		}
	case "":
		// Empty defaults to pebble, validate same as pebble
		if c.DataDir == "" {
			return ErrInvalidConfig{Field: "DataDir", Reason: "data directory is required"}
		}
		if c.WALDir == "" {
			return ErrInvalidConfig{Field: "WALDir", Reason: "WAL directory is required"}
		}
	default:
		return ErrInvalidConfig{Field: "StorageBackend", Reason: "invalid storage backend: must be 'memory', 'file', or 'pebble'"}
	}

	if c.CacheSize < 0 {
		return ErrInvalidConfig{Field: "CacheSize", Reason: "cache size cannot be negative"}
	}

	// The embedded server runs qrdb first-boot, whose IAM seeding (system
	// tenant, built-in roles, admin certificate) requires the SPIFFE
	// trust domain. An empty value would start a partially initialized
	// security service — every tenant-scoped surface dead — so it fails
	// closed here instead.
	if err := validateSPIFFETrustDomain(c.SPIFFETrustDomain); err != nil {
		return err
	}

	return nil
}

// IsEmbedded returns true if the transport is embedded mode.
func (c *Config) IsEmbedded() bool {
	return c.Transport == TransportEmbedded
}

// IsRemote returns true if the transport connects to a remote server.
func (c *Config) IsRemote() bool {
	return c.Transport != TransportEmbedded
}
