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
	"strconv"
	"strings"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/barrier"
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
	// There is no "raft" backend: Raft consensus is enabled by JoinAddresses,
	// and a clustered node keeps its replicated state on this backend.
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

	// BarrierSealStrategy, BarrierShamirThreshold and BarrierShamirShares
	// select the embedded server's data-plane barrier strategy. Only
	// "shamir" is passed through (seal.strategy: shamir, with the M-of-N
	// when set; quicbaas defaults 2-of-3 otherwise), because the Shamir
	// strategy is the one the SDK registers from config alone. They are
	// populated programmatically from the platform's barrier section — they
	// are NOT platform YAML keys. Without them the barrier is single-key,
	// and a shamir /init would split only the user PIN while that PIN alone
	// still unseals.
	BarrierSealStrategy    string `yaml:"-" json:"-" mapstructure:"-"`
	BarrierShamirThreshold int    `yaml:"-" json:"-" mapstructure:"-"`
	BarrierShamirShares    int    `yaml:"-" json:"-" mapstructure:"-"`

	// BootstrapAdminCSRPath, BootstrapAdminPIVCertPath, AdminFactors and
	// PasskeyDevice select how the FIRST administrator is enrolled at first
	// boot, and are passed straight through to the embedded server's
	// auth.* section. The vocabulary belongs to go-qrdb and the ceremonies
	// to go-xkms; the platform names none of it itself.
	//
	// Three enrollment paths, in increasing order of key hygiene:
	//
	//   A. Neither path set (the DEFAULT). The node generates the admin
	//      keypair and writes the certificate AND the private key under
	//      <data-dir>/admin for the operator to collect and remove. Simple,
	//      and the only path where a private key lands on the node.
	//   B. BootstrapAdminCSRPath. The admin generates their own keypair
	//      off-host and supplies a PKCS#10 CSR; the platform CA signs it and
	//      binds the certificate's SPKI thumbprint to the admin user. The
	//      private key NEVER reaches this host — first-boot returns no key
	//      on this path at all, so there is nothing on disk to protect or
	//      delete afterwards.
	//   C. BootstrapAdminPIVCertPath. Adopt a certificate the admin already
	//      holds, typically on a PIV card; its SHA-256 thumbprint is bound
	//      to the user as a PIV-attested certificate binding.
	//
	// AdminFactors is a distinct concern from the enrollment path: it is the
	// ordered set of LOGIN factors enrolled for that administrator — any of
	// "mtls", "fido2", "piv" — and empty means the mTLS baseline alone. A
	// seal strategy answers "how is the barrier key protected at rest"; a
	// login factor answers "how does a human prove who they are". Do not
	// conflate them, or you get an init that can unseal a database nobody
	// can log into.
	//
	// PasskeyDevice picks one FIDO2 authenticator when several are attached
	// to the host running first boot; empty auto-selects the only one.
	//
	// These are NOT validated here. go-qrdb owns the factor vocabulary via
	// qrdbsdk.ParseAdminFactors, which the embedded server calls during
	// enrollment; that function is not re-exported through the quicbaas SDK,
	// and duplicating its list locally would drift from the owner. An
	// unknown factor therefore fails at first boot rather than at config
	// load.
	BootstrapAdminCSRPath     string   `yaml:"bootstrap-admin-csr-path,omitempty" json:"bootstrap_admin_csr_path,omitempty" mapstructure:"bootstrap-admin-csr-path"`
	BootstrapAdminPIVCertPath string   `yaml:"bootstrap-admin-piv-cert-path,omitempty" json:"bootstrap_admin_piv_cert_path,omitempty" mapstructure:"bootstrap-admin-piv-cert-path"`
	AdminFactors              []string `yaml:"admin-factors,omitempty" json:"admin_factors,omitempty" mapstructure:"admin-factors"`
	PasskeyDevice             string   `yaml:"passkey-device,omitempty" json:"passkey_device,omitempty" mapstructure:"passkey-device"`

	// StartupTimeout bounds how long Start waits for the embedded server to
	// report itself started. It is deliberately its OWN budget and not
	// derived from RequestTimeout.
	//
	// RequestTimeout is how long ONE DAO operation may take. Startup is not
	// one operation: first boot constructs the data-plane barrier, opens and
	// closes the TPM, creates the system tenant and seeds five roles. Before
	// #270 this budget was RequestTimeout*3, so lowering the request timeout
	// silently retuned startup in a ratio nobody chose — a live trap even
	// though it was not what fired in the reported failure.
	//
	// Note this budget is a liveness backstop, not the usual constraint. The
	// embedded server's Start is synchronous, so the CALLER's context is
	// normally what bounds startup; pass one that allows for first-boot work
	// on a loaded host. Zero means DefaultStartupTimeout.
	StartupTimeout time.Duration `yaml:"startup-timeout,omitempty" json:"startup_timeout,omitempty" mapstructure:"startup-timeout"`

	// RaftAddress is the Raft address this node ADVERTISES to its peers
	// ("host:port"). Peers dial it, so a node with JoinAddresses must set a
	// routable one: Validate refuses a loopback, unspecified or empty value
	// there with ErrRaftAdvertiseAddress rather than publish an unreachable
	// peer. A single node may leave it loopback.
	RaftAddress string `yaml:"raft-address" json:"raft_address" mapstructure:"raft-address"`

	// RaftListenAddress is the local address the Raft transport binds
	// ("host:port"). Empty binds RaftAddress itself; set it when the bind
	// differs from the advertised address (NAT, a wildcard bind, a
	// container port mapping).
	RaftListenAddress string `yaml:"raft-listen-address" json:"raft_listen_address" mapstructure:"raft-listen-address"`

	// JoinAddresses is the cluster's full member list, one "id=host:port"
	// entry per member, this node included ("<node-id>=<raft-address>").
	// Every member carries the same list and they bootstrap the cluster
	// together. Setting it makes the node clustered: ToQuicBaaSConfig runs
	// go-quicbaas in cluster mode, and Validate requires DeploymentID and
	// the three Raft TLS files. Empty means a standalone node.
	JoinAddresses []string `yaml:"join-addresses" json:"join_addresses" mapstructure:"join-addresses"`

	// NodeID is the unique identifier for this node in the cluster.
	// Must be unique across all nodes.
	NodeID uint64 `yaml:"node-id" json:"node_id" mapstructure:"node-id"`

	// DeploymentID identifies the cluster; every member must carry the same
	// non-zero value. Required with JoinAddresses: left unset, go-quicbaas
	// derives it from each node's own NodeID, so no two members would agree.
	DeploymentID uint64 `yaml:"deployment-id,omitempty" json:"deployment_id,omitempty" mapstructure:"deployment-id"`

	// RaftTLSCertFile, RaftTLSKeyFile and RaftTLSCAFile are the PEM files
	// for mutually authenticated TLS between Raft peers: this node's
	// certificate, its private key, and the CA that issued every member's
	// certificate. All three are required with JoinAddresses; the operator
	// supplies them.
	RaftTLSCertFile string `yaml:"raft-tls-cert-file,omitempty" json:"raft_tls_cert_file,omitempty" mapstructure:"raft-tls-cert-file"`
	RaftTLSKeyFile  string `yaml:"raft-tls-key-file,omitempty" json:"raft_tls_key_file,omitempty" mapstructure:"raft-tls-key-file"`
	RaftTLSCAFile   string `yaml:"raft-tls-ca-file,omitempty" json:"raft_tls_ca_file,omitempty" mapstructure:"raft-tls-ca-file"`

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
// KMS is supported in all backends. RaftAddress is left empty, as it is for a
// platformd config file that omits quicbaas.raft-address: a single node
// advertises nothing to peers, and a node that joins them must set one.
func DefaultConfig() *Config {
	return &Config{
		TransportStr:      "embedded",
		Transport:         TransportEmbedded,
		StorageBackend:    quicbaas.StorageBackendPebble, // High-performance local storage (fastest)
		SPIFFETrustDomain: "example.internal",
		DataDir:           "./data/quicbaas",
		WALDir:            "./data/quicbaas/wal",
		NodeID:            1,
		CacheSize:         128 * 1024 * 1024, // 128MB
		LogLevel:          "info",
		ConsistencyLevel:  ConsistencyLinearizable,
		Compression:       "snappy",
		SyncWrites:        true,
		RequestTimeout:    5 * time.Second,
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

	// Raft settings (only used in cluster mode)
	cfg.Raft.NodeID = c.NodeID
	cfg.Raft.RaftAddress = c.RaftAddress
	cfg.Raft.ListenAddress = c.EffectiveRaftListenAddress()
	cfg.Raft.RequestTimeout = c.RequestTimeout

	// A clustered node runs go-quicbaas in cluster mode, which forms
	// go-qrdb's Raft cluster from the member list. The platform only passes
	// the configuration through; formation is go-qrdb's.
	if c.IsClustered() {
		cfg.Server.Mode = quicbaas.ServerModeCluster
		cfg.Raft.JoinAddresses = c.JoinAddresses
		cfg.Raft.DeploymentID = c.DeploymentID
		cfg.Raft.TLSCertFile = c.RaftTLSCertFile
		cfg.Raft.TLSKeyFile = c.RaftTLSKeyFile
		cfg.Raft.TLSCAFile = c.RaftTLSCAFile
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

	// Admin enrollment and login factors: passed through verbatim to the
	// embedded server's auth.* section, which is where first-boot reads
	// them (pkg/server/iam_init.go for the CSR / PIV paths,
	// pkg/server/admin_factor_enrollment.go for the factors). The platform
	// adds no policy of its own here — an empty value means the same thing
	// it means upstream.
	cfg.Auth.BootstrapAdminCSRPath = c.BootstrapAdminCSRPath
	cfg.Auth.BootstrapAdminPIVCertPath = c.BootstrapAdminPIVCertPath
	cfg.Auth.AdminFactors = c.AdminFactors
	cfg.Auth.PasskeyDevice = c.PasskeyDevice

	// IAM WebAuthn relying party: mirrors the platform webservice
	// webauthn section so the per-tenant RP the SDK builds matches the
	// origin the console is actually served on.
	cfg.IAM.WebAuthn.RPID = c.WebAuthnRPID
	cfg.IAM.WebAuthn.RPDisplayName = c.WebAuthnRPDisplayName
	cfg.IAM.WebAuthn.RPOrigins = c.WebAuthnRPOrigins

	// Data-plane barrier: a shamir barrier must be sealed by the Shamir
	// strategy, or InitializeShamir runs in credential mode and the quorum
	// is not enforced. Every other strategy keeps the embedded default.
	if c.BarrierSealStrategy == barrier.SealStrategyShamir {
		cfg.Seal.Strategy = barrier.SealStrategyShamir
		if c.BarrierShamirThreshold > 0 {
			cfg.Seal.Threshold = c.BarrierShamirThreshold
		}
		if c.BarrierShamirShares > 0 {
			cfg.Seal.TotalShares = c.BarrierShamirShares
		}
	}

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

// EffectiveStartupTimeout returns the startup budget to use, falling back to
// DefaultStartupTimeout when none is configured.
//
// It exists because SetDefaults is NOT called on every Config that reaches
// startup — pkg/app builds its QuicBaaSConfig straight from YAML and calls
// only Validate, which does not require StartupTimeout. Reading the field
// directly would therefore hand a zero to context.WithTimeout on the daemon's
// boot path, which expires immediately: the exact fatal-on-healthy-boot
// failure #270 is about, reintroduced by the fix for it. Always go through
// this accessor.
func (c *Config) EffectiveStartupTimeout() time.Duration {
	if c == nil || c.StartupTimeout <= 0 {
		return DefaultStartupTimeout
	}
	return c.StartupTimeout
}

// EffectiveRaftListenAddress returns the address the Raft transport binds:
// RaftListenAddress when set, otherwise the advertised RaftAddress.
func (c *Config) EffectiveRaftListenAddress() string {
	if c.RaftListenAddress != "" {
		return c.RaftListenAddress
	}
	return c.RaftAddress
}

// IsRoutableRaftAddress reports whether addr advertises a node to peers on
// the network, as opposed to the loopback, unspecified or empty values a
// single-node deployment carries. A host that is not an IP literal (a DNS
// name other than localhost) is treated as routable: it is not evidence of
// a single node, so callers gating on it fail closed.
func IsRoutableRaftAddress(addr string) bool {
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

// SetDefaults sets default values for zero-valued fields.
// This ensures the config has sensible defaults when fields are omitted from YAML/JSON.
func (c *Config) SetDefaults() {
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 30 * time.Second // Default 30s timeout
	}
	if c.StartupTimeout <= 0 {
		c.StartupTimeout = DefaultStartupTimeout
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

	if c.IsClustered() {
		if err := c.validateCluster(); err != nil {
			return err
		}
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

// IsClustered reports whether this node is a member of a multi-node Raft
// cluster, which is what a non-empty JoinAddresses declares.
func (c *Config) IsClustered() bool {
	return len(c.JoinAddresses) > 0
}

// validateCluster checks a clustered node's configuration before go-quicbaas
// sees it: go-quicbaas drops malformed members silently and cannot tell a
// missing TLS file from a deliberate one, so the platform refuses both here.
func (c *Config) validateCluster() error {
	// Peers dial the address this node advertises: loopback would publish
	// an unreachable peer.
	if !IsRoutableRaftAddress(c.RaftAddress) {
		return ErrRaftAdvertiseAddress{Address: c.RaftAddress}
	}
	if c.NodeID == 0 {
		return ErrRaftClusterField{Field: "node-id", Reason: "every member needs a non-zero node ID"}
	}
	if c.DeploymentID == 0 {
		return ErrRaftClusterField{Field: "deployment-id", Reason: "every member must carry the same non-zero deployment ID"}
	}

	members := make(map[uint64]string, len(c.JoinAddresses))
	for _, entry := range c.JoinAddresses {
		id, addr, err := parseRaftMember(entry)
		if err != nil {
			return err
		}
		if _, seen := members[id]; seen {
			return ErrRaftDuplicatePeer{NodeID: id}
		}
		members[id] = addr
	}
	if members[c.NodeID] != c.RaftAddress {
		return ErrRaftSelfPeer{NodeID: c.NodeID, RaftAddress: c.RaftAddress}
	}

	var missing []string
	if c.RaftTLSCertFile == "" {
		missing = append(missing, "quicbaas.raft-tls-cert-file")
	}
	if c.RaftTLSKeyFile == "" {
		missing = append(missing, "quicbaas.raft-tls-key-file")
	}
	if c.RaftTLSCAFile == "" {
		missing = append(missing, "quicbaas.raft-tls-ca-file")
	}
	if len(missing) > 0 {
		return ErrRaftTLSRequired{Missing: missing}
	}
	return nil
}

// parseRaftMember splits a join-addresses entry in go-quicbaas's
// "id=host:port" member form into its node ID and address.
func parseRaftMember(entry string) (uint64, string, error) {
	idText, addr, found := strings.Cut(entry, "=")
	if !found {
		return 0, "", ErrRaftPeerAddress{Entry: entry, Reason: "missing the \"id=\" prefix"}
	}
	id, err := strconv.ParseUint(idText, 10, 64)
	if err != nil || id == 0 {
		return 0, "", ErrRaftPeerAddress{Entry: entry, Reason: "the node ID must be a positive integer"}
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return 0, "", ErrRaftPeerAddress{Entry: entry, Reason: "the address must be host:port"}
	}
	if portNum, err := strconv.ParseUint(port, 10, 16); err != nil || portNum == 0 {
		return 0, "", ErrRaftPeerAddress{Entry: entry, Reason: "the port must be 1-65535"}
	}
	return id, addr, nil
}

// ValidateSPIFFETrustDomain checks spiffe-trust-domain the way the
// embedded server will, without constructing anything, so config load can
// reject a config the factory would refuse later. A nil Config is an absent
// quicbaas: section, which selects the embedded server with no trust
// domain, so it fails too. Remote transports run no first boot and need no
// trust domain; an unknown transport string is ErrInvalidTransport.
func (c *Config) ValidateSPIFFETrustDomain() error {
	if c == nil {
		return validateSPIFFETrustDomain("")
	}
	transport := c.Transport
	if c.TransportStr != "" {
		parsed, err := ParseTransport(c.TransportStr)
		if err != nil {
			return err
		}
		transport = parsed
	}
	if transport != TransportEmbedded {
		return nil
	}
	return validateSPIFFETrustDomain(c.SPIFFETrustDomain)
}

// IsEmbedded returns true if the transport is embedded mode.
func (c *Config) IsEmbedded() bool {
	return c.Transport == TransportEmbedded
}

// IsRemote returns true if the transport connects to a remote server.
func (c *Config) IsRemote() bool {
	return c.Transport != TransportEmbedded
}
