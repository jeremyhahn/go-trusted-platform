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

package registry

import (
	"crypto/tls"
	"time"
)

// RegistryConfig holds configuration for the trusted container registry
type RegistryConfig struct {
	// ListenAddr is the address for the registry to listen on (e.g., ":5000")
	ListenAddr string `yaml:"listen_addr" json:"listen_addr"`

	// TLS holds TLS configuration for secure connections
	TLS TLSConfig `yaml:"tls" json:"tls"`

	// Attestation holds attestation requirements for clients
	Attestation RegistryAttestationConfig `yaml:"attestation" json:"attestation"`

	// Storage holds QuicBaaS storage configuration
	Storage StorageConfig `yaml:"storage" json:"storage"`

	// Encryption holds encryption configuration for images
	Encryption EncryptionConfig `yaml:"encryption" json:"encryption"`

	// ReadTimeout is the maximum duration for reading requests
	ReadTimeout time.Duration `yaml:"read_timeout" json:"read_timeout"`

	// WriteTimeout is the maximum duration for writing responses
	WriteTimeout time.Duration `yaml:"write_timeout" json:"write_timeout"`

	// IdleTimeout is the maximum idle connection duration
	IdleTimeout time.Duration `yaml:"idle_timeout" json:"idle_timeout"`

	// MaxConcurrentPulls limits concurrent pull operations
	MaxConcurrentPulls int `yaml:"max_concurrent_pulls" json:"max_concurrent_pulls"`

	// MaxConcurrentPushes limits concurrent push operations
	MaxConcurrentPushes int `yaml:"max_concurrent_pushes" json:"max_concurrent_pushes"`
}

// TLSConfig holds TLS configuration for the registry
type TLSConfig struct {
	// Enabled indicates whether TLS is enabled
	Enabled bool `yaml:"enabled" json:"enabled"`

	// CertFile is the path to the TLS certificate file
	CertFile string `yaml:"cert_file" json:"cert_file"`

	// KeyFile is the path to the TLS private key file
	KeyFile string `yaml:"key_file" json:"key_file"`

	// CAFile is the path to the CA certificate for client verification
	CAFile string `yaml:"ca_file" json:"ca_file"`

	// ClientAuth specifies the TLS client authentication policy
	ClientAuth tls.ClientAuthType `yaml:"client_auth" json:"client_auth"`

	// MinVersion is the minimum TLS version (e.g., tls.VersionTLS12)
	MinVersion uint16 `yaml:"min_version" json:"min_version"`

	// CipherSuites is the list of allowed cipher suites
	CipherSuites []uint16 `yaml:"cipher_suites" json:"cipher_suites"`
}

// RegistryAttestationConfig holds attestation requirements for registry clients
type RegistryAttestationConfig struct {
	// RequireAttestation indicates whether clients must provide attestation evidence
	RequireAttestation bool `yaml:"require_attestation" json:"require_attestation"`

	// RequiredPCRs maps PCR indices to their required values
	// Clients must have matching PCR values to access the registry
	RequiredPCRs map[int][]byte `yaml:"required_pcrs" json:"required_pcrs"`

	// AllowedAIKs is a list of allowed Attestation Identity Key fingerprints
	// If empty, any valid AIK is accepted
	AllowedAIKs []string `yaml:"allowed_aiks" json:"allowed_aiks"`

	// AttestationPolicy is the OPA policy path for attestation evaluation
	AttestationPolicy string `yaml:"attestation_policy" json:"attestation_policy"`

	// NonceValidityDuration is how long attestation nonces remain valid
	NonceValidityDuration time.Duration `yaml:"nonce_validity_duration" json:"nonce_validity_duration"`

	// QuoteMaxAge is the maximum age of a TPM quote before it is rejected
	QuoteMaxAge time.Duration `yaml:"quote_max_age" json:"quote_max_age"`

	// CacheSessionDuration is how long authenticated sessions are cached
	CacheSessionDuration time.Duration `yaml:"cache_session_duration" json:"cache_session_duration"`
}

// StorageConfig holds QuicBaaS storage configuration
// QuicBaaS is the only supported storage backend for the trusted registry
type StorageConfig struct {
	// Addr is the QuicBaaS server address (e.g., "localhost:9000")
	Addr string `yaml:"addr" json:"addr"`

	// Namespace is the QuicBaaS namespace for registry blobs
	Namespace string `yaml:"namespace" json:"namespace"`

	// Encrypted indicates whether blobs should be encrypted at rest
	Encrypted bool `yaml:"encrypted" json:"encrypted"`

	// KeyID is the encryption key ID in QuicBaaS for blob encryption
	KeyID string `yaml:"key_id" json:"key_id"`

	// ConnectionTimeout is the timeout for connecting to QuicBaaS
	ConnectionTimeout time.Duration `yaml:"connection_timeout" json:"connection_timeout"`

	// RequestTimeout is the timeout for individual QuicBaaS requests
	RequestTimeout time.Duration `yaml:"request_timeout" json:"request_timeout"`

	// MaxRetries is the maximum number of retries for failed operations
	MaxRetries int `yaml:"max_retries" json:"max_retries"`

	// RetryBackoff is the initial backoff duration between retries
	RetryBackoff time.Duration `yaml:"retry_backoff" json:"retry_backoff"`
}

// EncryptionConfig holds encryption configuration for images
type EncryptionConfig struct {
	// QuicBaaSAddr is the QuicBaaS address for key management
	QuicBaaSAddr string `yaml:"quicbaas_addr" json:"quicbaas_addr"`

	// KeyNamespace is the QuicBaaS namespace for encryption keys
	KeyNamespace string `yaml:"key_namespace" json:"key_namespace"`

	// Algorithm is the encryption algorithm (e.g., "AES-256-GCM")
	Algorithm string `yaml:"algorithm" json:"algorithm"`

	// EncryptByDefault indicates whether to encrypt all images by default
	EncryptByDefault bool `yaml:"encrypt_by_default" json:"encrypt_by_default"`

	// KeyRotationInterval is how often to rotate encryption keys
	KeyRotationInterval time.Duration `yaml:"key_rotation_interval" json:"key_rotation_interval"`

	// DEKCacheSize is the size of the data encryption key cache
	DEKCacheSize int `yaml:"dek_cache_size" json:"dek_cache_size"`

	// DEKCacheTTL is the time-to-live for cached DEKs
	DEKCacheTTL time.Duration `yaml:"dek_cache_ttl" json:"dek_cache_ttl"`
}

// DefaultRegistryConfig returns a RegistryConfig with sensible defaults
func DefaultRegistryConfig() RegistryConfig {
	return RegistryConfig{
		ListenAddr:          ":5000",
		TLS:                 DefaultTLSConfig(),
		Attestation:         DefaultAttestationConfig(),
		Storage:             DefaultStorageConfig(),
		Encryption:          DefaultEncryptionConfig(),
		ReadTimeout:         30 * time.Second,
		WriteTimeout:        60 * time.Second,
		IdleTimeout:         120 * time.Second,
		MaxConcurrentPulls:  100,
		MaxConcurrentPushes: 50,
	}
}

// DefaultTLSConfig returns a TLSConfig with sensible defaults
func DefaultTLSConfig() TLSConfig {
	return TLSConfig{
		Enabled:    true,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

// DefaultAttestationConfig returns a RegistryAttestationConfig with sensible defaults
func DefaultAttestationConfig() RegistryAttestationConfig {
	return RegistryAttestationConfig{
		RequireAttestation:    true,
		RequiredPCRs:          make(map[int][]byte),
		AllowedAIKs:           nil,
		AttestationPolicy:     "",
		NonceValidityDuration: 5 * time.Minute,
		QuoteMaxAge:           10 * time.Minute,
		CacheSessionDuration:  1 * time.Hour,
	}
}

// DefaultStorageConfig returns a StorageConfig with sensible defaults
func DefaultStorageConfig() StorageConfig {
	return StorageConfig{
		Addr:              "localhost:9000",
		Namespace:         "registry",
		Encrypted:         true,
		KeyID:             "",
		ConnectionTimeout: 10 * time.Second,
		RequestTimeout:    30 * time.Second,
		MaxRetries:        3,
		RetryBackoff:      100 * time.Millisecond,
	}
}

// DefaultEncryptionConfig returns an EncryptionConfig with sensible defaults
func DefaultEncryptionConfig() EncryptionConfig {
	return EncryptionConfig{
		QuicBaaSAddr:        "localhost:9000",
		KeyNamespace:        "registry-keys",
		Algorithm:           "AES-256-GCM",
		EncryptByDefault:    true,
		KeyRotationInterval: 30 * 24 * time.Hour, // 30 days
		DEKCacheSize:        1000,
		DEKCacheTTL:         1 * time.Hour,
	}
}

// Validate checks if the configuration is valid
func (c *RegistryConfig) Validate() error {
	if c.ListenAddr == "" {
		return ErrInvalidConfig{Field: "listen_addr", Reason: "cannot be empty"}
	}

	if err := c.TLS.Validate(); err != nil {
		return err
	}

	if err := c.Attestation.Validate(); err != nil {
		return err
	}

	if err := c.Storage.Validate(); err != nil {
		return err
	}

	if err := c.Encryption.Validate(); err != nil {
		return err
	}

	if c.ReadTimeout <= 0 {
		return ErrInvalidConfig{Field: "read_timeout", Reason: "must be positive"}
	}

	if c.WriteTimeout <= 0 {
		return ErrInvalidConfig{Field: "write_timeout", Reason: "must be positive"}
	}

	if c.MaxConcurrentPulls <= 0 {
		return ErrInvalidConfig{Field: "max_concurrent_pulls", Reason: "must be positive"}
	}

	if c.MaxConcurrentPushes <= 0 {
		return ErrInvalidConfig{Field: "max_concurrent_pushes", Reason: "must be positive"}
	}

	return nil
}

// Validate checks if the TLS configuration is valid
func (c *TLSConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.CertFile == "" {
		return ErrInvalidConfig{Field: "tls.cert_file", Reason: "cannot be empty when TLS is enabled"}
	}

	if c.KeyFile == "" {
		return ErrInvalidConfig{Field: "tls.key_file", Reason: "cannot be empty when TLS is enabled"}
	}

	if c.MinVersion < tls.VersionTLS12 {
		return ErrInvalidConfig{Field: "tls.min_version", Reason: "minimum TLS version must be TLS 1.2 or higher"}
	}

	return nil
}

// Validate checks if the attestation configuration is valid
func (c *RegistryAttestationConfig) Validate() error {
	if !c.RequireAttestation {
		return nil
	}

	if c.NonceValidityDuration <= 0 {
		return ErrInvalidConfig{Field: "attestation.nonce_validity_duration", Reason: "must be positive"}
	}

	if c.QuoteMaxAge <= 0 {
		return ErrInvalidConfig{Field: "attestation.quote_max_age", Reason: "must be positive"}
	}

	if c.CacheSessionDuration <= 0 {
		return ErrInvalidConfig{Field: "attestation.cache_session_duration", Reason: "must be positive"}
	}

	return nil
}

// Validate checks if the storage configuration is valid
func (c *StorageConfig) Validate() error {
	if c.Addr == "" {
		return ErrInvalidConfig{Field: "storage.addr", Reason: "QuicBaaS address cannot be empty"}
	}

	if c.Namespace == "" {
		return ErrInvalidConfig{Field: "storage.namespace", Reason: "namespace cannot be empty"}
	}

	if c.Encrypted && c.KeyID == "" {
		return ErrInvalidConfig{Field: "storage.key_id", Reason: "key ID required when encryption is enabled"}
	}

	if c.ConnectionTimeout <= 0 {
		return ErrInvalidConfig{Field: "storage.connection_timeout", Reason: "must be positive"}
	}

	if c.RequestTimeout <= 0 {
		return ErrInvalidConfig{Field: "storage.request_timeout", Reason: "must be positive"}
	}

	if c.MaxRetries < 0 {
		return ErrInvalidConfig{Field: "storage.max_retries", Reason: "cannot be negative"}
	}

	return nil
}

// Validate checks if the encryption configuration is valid
func (c *EncryptionConfig) Validate() error {
	if c.QuicBaaSAddr == "" {
		return ErrInvalidConfig{Field: "encryption.quicbaas_addr", Reason: "QuicBaaS address cannot be empty"}
	}

	if c.KeyNamespace == "" {
		return ErrInvalidConfig{Field: "encryption.key_namespace", Reason: "key namespace cannot be empty"}
	}

	if c.Algorithm == "" {
		return ErrInvalidConfig{Field: "encryption.algorithm", Reason: "algorithm cannot be empty"}
	}

	// Validate supported algorithms
	switch c.Algorithm {
	case "AES-256-GCM", "AES-128-GCM":
		// Valid algorithms
	default:
		return ErrInvalidConfig{Field: "encryption.algorithm", Reason: "unsupported algorithm: " + c.Algorithm}
	}

	if c.DEKCacheSize <= 0 {
		return ErrInvalidConfig{Field: "encryption.dek_cache_size", Reason: "must be positive"}
	}

	if c.DEKCacheTTL <= 0 {
		return ErrInvalidConfig{Field: "encryption.dek_cache_ttl", Reason: "must be positive"}
	}

	return nil
}
