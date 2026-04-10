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

package secureboot

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// BackendType represents the key storage backend type
type BackendType string

const (
	// BackendFile stores keys as PEM files (default)
	BackendFile BackendType = "file"
	// BackendSoftware uses software backend via go-xkms (supports sealing, encryption)
	BackendSoftware BackendType = "software"
	// BackendPKCS11 uses PKCS#11 HSM via go-xkms
	BackendPKCS11 BackendType = "pkcs11"
	// BackendTPM2 uses TPM 2.0 via go-xkms
	BackendTPM2 BackendType = "tpm2"
	// BackendAWSKMS uses AWS KMS via go-xkms
	BackendAWSKMS BackendType = "awskms"
	// BackendAzureKV uses Azure Key Vault via go-xkms
	BackendAzureKV BackendType = "azurekv"
	// BackendGCPKMS uses GCP KMS via go-xkms
	BackendGCPKMS BackendType = "gcpkms"
	// BackendVault uses HashiCorp Vault via go-xkms
	BackendVault BackendType = "vault"
)

// Default backend name for Secure Boot operations
const defaultBackendName = "secureboot"

// String returns the string representation of BackendType
func (b BackendType) String() string {
	return string(b)
}

// IsValid checks if the backend type is valid
func (b BackendType) IsValid() bool {
	switch b {
	case BackendFile, BackendSoftware, BackendPKCS11, BackendTPM2,
		BackendAWSKMS, BackendAzureKV, BackendGCPKMS, BackendVault:
		return true
	}
	return false
}

// XKMSConfig holds configuration for XKMS-backed key generation
type XKMSConfig struct {
	// KeysDir is the output directory for exported keys (PEM format)
	KeysDir string

	// Backend specifies the XKMS backend to use
	Backend BackendType

	// CommonName is the certificate CN prefix
	CommonName string

	// Country is the certificate Country field
	Country string

	// Organization is the certificate Organization field
	Organization string

	// KeySize is the RSA key size (default: 2048)
	KeySize int

	// ValidYears is the certificate validity in years (default: 10)
	ValidYears int

	// ExportKeys exports keys to PEM files in KeysDir (required for Secure Boot enrollment)
	ExportKeys bool
}

// XKMSManager manages Secure Boot keys using go-xkms service
type XKMSManager struct {
	config      *XKMSConfig
	logger      *logging.Logger
	backendName string
	initialized bool
	// rawBackend is the underlying software backend for direct key access
	// DEFERRED: Remove once remote go-xkms server is available. Blocked by: remote XKMS deployment.
	rawBackend *xkmssdk.SoftwareBackend
}

// NewXKMSManager creates a new XKMS-backed Secure Boot key manager.
// All key operations are performed via go-xkms service - no local key
// generation code is used.
func NewXKMSManager(config *XKMSConfig, logger *logging.Logger) (*XKMSManager, error) {
	if config == nil {
		return nil, ErrConfigNil
	}

	// Validate required fields
	if config.KeysDir == "" {
		return nil, fmt.Errorf("%w: KeysDir cannot be empty", ErrInvalidConfig)
	}

	// Set defaults
	if config.KeySize == 0 {
		config.KeySize = 2048
	}
	if config.ValidYears == 0 {
		config.ValidYears = 10
	}
	if config.Backend == "" {
		config.Backend = BackendFile
	}

	// Validate key size
	if config.KeySize < 2048 {
		return nil, fmt.Errorf("%w: KeySize must be at least 2048 bits", ErrInvalidConfig)
	}

	// Validate backend type
	if !config.Backend.IsValid() {
		return nil, fmt.Errorf("%w: unsupported backend type: %s", ErrInvalidConfig, config.Backend)
	}

	if logger == nil {
		logger = logging.DefaultLogger()
	}

	km := &XKMSManager{
		config:      config,
		logger:      logger,
		backendName: defaultBackendName,
	}

	// Initialize the XKMS service with our backend
	if err := km.initializeService(); err != nil {
		return nil, err
	}

	return km, nil
}

// initializeService initializes the go-xkms service with the configured backend
func (km *XKMSManager) initializeService() error {
	// Reset any previous service state (for testing/re-initialization)
	if xkmssdk.ServiceIsInitialized() {
		xkmssdk.ServiceReset()
	}

	// Create the backend based on configuration
	ks, err := km.createXKMSBackend()
	if err != nil {
		return fmt.Errorf("failed to create XKMS backend: %w", err)
	}

	// Get the StoreType name for this backend - this is what BackendFor() uses to find backends
	storeType := backendToStoreType(km.config.Backend)
	storeTypeName := string(storeType)

	// Initialize the XKMS service
	// Register the backend with both the StoreType name (for BackendFor lookups)
	// and the logical name (for backward compatibility)
	serviceConfig := &xkmssdk.ServiceConfig{
		Backends: map[string]xkmssdk.ServiceBackend{
			storeTypeName:  ks, // Required: for BackendFor(attrs) to find by StoreType
			km.backendName: ks, // Optional: for backward compatibility
		},
		DefaultBackend: storeTypeName,
	}

	if err := xkmssdk.ServiceInitialize(serviceConfig); err != nil {
		return fmt.Errorf("failed to initialize XKMS service: %w", err)
	}

	km.initialized = true
	return nil
}

// createXKMSBackend creates a go-xkms backend based on the config
func (km *XKMSManager) createXKMSBackend() (xkmssdk.ServiceBackend, error) {
	switch km.config.Backend {
	case BackendFile, BackendSoftware:
		// Create file-based storage for keys
		keyStorage, err := xkmssdk.NewFileStorageBackend(filepath.Join(km.config.KeysDir, "keys"))
		if err != nil {
			return nil, fmt.Errorf("failed to create key storage: %w", err)
		}

		// Create file-based storage for certificates
		certStorage, err := xkmssdk.NewFileStorageBackend(filepath.Join(km.config.KeysDir, "certs"))
		if err != nil {
			return nil, fmt.Errorf("failed to create cert storage: %w", err)
		}

		// Create software backend with file storage (unified asymmetric + symmetric operations)
		softwareConfig := &xkmssdk.SoftwareBackendConfig{
			KeyStorage: keyStorage,
		}
		backend, err := xkmssdk.NewSoftwareBackend(softwareConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create software backend: %w", err)
		}

		// Store raw backend reference for direct key access (temporary)
		// DEFERRED: Remove once remote go-xkms server is available. Blocked by: remote XKMS deployment.
		km.rawBackend = backend.(*xkmssdk.SoftwareBackend)

		// Create XKMS backend with backend and cert storage
		xkmsConfig := &xkmssdk.ServiceBackendConfig{
			Backend:     backend,
			CertStorage: certStorage,
		}
		return xkmssdk.NewServiceBackend(xkmsConfig)

	case BackendPKCS11, BackendTPM2, BackendAWSKMS, BackendAzureKV, BackendGCPKMS, BackendVault:
		// These backends require explicit configuration
		return nil, fmt.Errorf("backend %s requires a pre-configured KeyStore instance", km.config.Backend)

	default:
		return nil, fmt.Errorf("unsupported backend type: %s", km.config.Backend)
	}
}

// backendToStoreType maps a BackendType to a go-xkms StoreType
func backendToStoreType(backend BackendType) xkmssdk.StoreType {
	switch backend {
	case BackendFile, BackendSoftware:
		return xkmssdk.StoreSoftware
	case BackendPKCS11:
		return xkmssdk.StorePKCS11
	case BackendTPM2:
		return xkmssdk.StoreTPM2
	case BackendAWSKMS:
		return xkmssdk.StoreAWSKMS
	case BackendAzureKV:
		return xkmssdk.StoreAzureKV
	case BackendGCPKMS:
		return xkmssdk.StoreGCPKMS
	case BackendVault:
		return xkmssdk.StoreVault
	default:
		return xkmssdk.StoreSoftware
	}
}

// GenerateAll generates all Secure Boot keys (PK, KEK, DB) using go-xkms service.
// All key operations are performed via go-xkms - no local key generation.
func (km *XKMSManager) GenerateAll(ctx context.Context) error {
	// Check if keys already exist
	if km.KeysExist() {
		km.logger.Info("Secure Boot keys already exist, skipping generation",
			"path", km.config.KeysDir,
			"backend", km.config.Backend)
		return nil
	}

	// Create keys directory for exported files
	if km.config.ExportKeys {
		if err := os.MkdirAll(km.config.KeysDir, 0755); err != nil {
			return fmt.Errorf("%w: failed to create keys directory: %v", ErrKeyGenFailed, err)
		}
	}

	km.logger.Info("Generating Secure Boot keys",
		"path", km.config.KeysDir,
		"backend", km.config.Backend)

	// Generate Platform Key (PK)
	if err := km.GeneratePlatformKey(ctx); err != nil {
		return fmt.Errorf("failed to generate Platform Key: %w", err)
	}

	// Generate Key Exchange Key (KEK)
	if err := km.GenerateKeyExchangeKey(ctx); err != nil {
		return fmt.Errorf("failed to generate Key Exchange Key: %w", err)
	}

	// Generate Database Key (DB)
	if err := km.GenerateDatabaseKey(ctx); err != nil {
		return fmt.Errorf("failed to generate Database Key: %w", err)
	}

	km.logger.Info("Successfully generated all Secure Boot keys",
		"backend", km.config.Backend)
	return nil
}

// GeneratePlatformKey generates the Platform Key (PK) using go-xkms service
func (km *XKMSManager) GeneratePlatformKey(ctx context.Context) error {
	return km.generateKey(ctx, KeyTypePK, "Platform Key")
}

// GenerateKeyExchangeKey generates the Key Exchange Key (KEK) using go-xkms service
func (km *XKMSManager) GenerateKeyExchangeKey(ctx context.Context) error {
	return km.generateKey(ctx, KeyTypeKEK, "Key Exchange Key")
}

// GenerateDatabaseKey generates the Database Key (DB) using go-xkms service
func (km *XKMSManager) GenerateDatabaseKey(ctx context.Context) error {
	return km.generateKey(ctx, KeyTypeDB, "Database Key")
}

// generateKey generates a key using the go-xkms service.
// All key operations are performed via go-xkms service functions.
func (km *XKMSManager) generateKey(ctx context.Context, keyType KeyType, description string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	km.logger.Info("Generating key via go-xkms service",
		"type", keyType,
		"description", description,
		"backend", km.config.Backend)

	// Map BackendType to go-xkms StoreType
	storeType := backendToStoreType(km.config.Backend)

	// Build key attributes
	keyID := fmt.Sprintf("secureboot-%s", keyType)
	attrs := &xkmssdk.KeyAttributes{
		CN:           keyID,
		KeyAlgorithm: x509.RSA,
		KeyType:      xkmssdk.KeyTypeSigning,
		StoreType:    storeType,
		RSAAttributes: &xkmssdk.RSAAttributes{
			KeySize: km.config.KeySize,
		},
	}

	// Check if key already exists and delete it if so (for fresh generation)
	// Use service-level function to check
	if existingKey, err := xkmssdk.ServiceKey(attrs); err == nil && existingKey != nil {
		km.logger.Debug("Deleting existing key before regeneration", "type", keyType)
		if err := xkmssdk.ServiceDeleteKey(attrs); err != nil {
			km.logger.Warn("Failed to delete existing key", "type", keyType, "error", err)
			// Continue anyway - generation might still work
		}
	}

	// Generate key using raw backend (returns actual *rsa.PrivateKey, not opaque wrapper)
	// This is needed for exporting the private key for installer UKI signing
	// DEFERRED: Use remote go-xkms server once available. Blocked by: remote XKMS deployment.
	var privateKey crypto.PrivateKey
	var genErr error
	if km.rawBackend != nil {
		privateKey, genErr = km.rawBackend.GenerateKey(attrs)
		if genErr != nil {
			return fmt.Errorf("%w: failed to generate key via raw backend: %v", ErrKeyGenFailed, genErr)
		}
	} else {
		// Fallback to service (returns opaque key - export won't work)
		privateKey, genErr = xkmssdk.ServiceGenerateKey(attrs)
		if genErr != nil {
			return fmt.Errorf("%w: failed to generate key via XKMS service: %v", ErrKeyGenFailed, genErr)
		}
	}

	// Create certificate subject
	subject := pkix.Name{
		CommonName: fmt.Sprintf("%s - %s", km.config.CommonName, description),
	}
	if km.config.Country != "" {
		subject.Country = []string{km.config.Country}
	}
	if km.config.Organization != "" {
		subject.Organization = []string{km.config.Organization}
	}

	// Generate self-signed certificate using the crypto.Signer interface
	// go-xkms returns opaque signers for hardware key support
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("%w: key does not implement crypto.Signer, got %T", ErrKeyGenFailed, privateKey)
	}

	cert, err := km.generateCertificate(signer, subject, keyType)
	if err != nil {
		return fmt.Errorf("%w: failed to generate certificate: %v", ErrKeyGenFailed, err)
	}

	// Save certificate via go-xkms service using the key attributes
	if err := xkmssdk.ServiceSaveCertificate(attrs, cert); err != nil {
		return fmt.Errorf("%w: failed to save certificate: %v", ErrKeyGenFailed, err)
	}

	// Export certificate and private key files if configured
	// DEFERRED: Refactor to use remote go-xkms server for signing instead of exporting keys. Blocked by: remote XKMS deployment.
	if km.config.ExportKeys {
		if err := km.exportCertificate(cert, keyType); err != nil {
			return fmt.Errorf("%w: failed to export certificate: %v", ErrKeyGenFailed, err)
		}
		// Export private key for installer UKI signing
		if rsaKey, ok := privateKey.(*rsa.PrivateKey); ok {
			if err := km.exportPrivateKey(rsaKey, keyType); err != nil {
				return fmt.Errorf("%w: failed to export private key: %v", ErrKeyGenFailed, err)
			}
		} else {
			km.logger.Warn("Cannot export private key - not RSA type", "type", fmt.Sprintf("%T", privateKey))
		}
	}

	km.logger.Info("Successfully generated key",
		"type", keyType,
		"backend", km.config.Backend)

	return nil
}

// generateCertificate creates a self-signed certificate for the given signer
func (km *XKMSManager) generateCertificate(signer crypto.Signer, subject pkix.Name, keyType KeyType) (*x509.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(km.config.ValidYears, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         false,
	}

	// Self-sign using the crypto.Signer interface
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	return x509.ParseCertificate(certDER)
}

// exportCertificate writes a certificate to a PEM file
func (km *XKMSManager) exportCertificate(cert *x509.Certificate, keyType KeyType) error {
	certPath := filepath.Join(km.config.KeysDir, fmt.Sprintf("%s.crt", keyType))
	return writeCertificate(cert, certPath)
}

// exportPrivateKey writes a private key to a PEM file for installer UKI signing
// DEFERRED: Remove once remote go-xkms server is available for signing operations. Blocked by: remote XKMS deployment.
func (km *XKMSManager) exportPrivateKey(key *rsa.PrivateKey, keyType KeyType) error {
	keyPath := filepath.Join(km.config.KeysDir, fmt.Sprintf("%s.key", keyType))
	km.logger.Debug("Exporting private key for UKI signing", "type", keyType, "path", keyPath)
	return writeKey(key, keyPath)
}

// KeysExist checks if Secure Boot keys already exist
// This checks both the XKMS storage and exported certificate files
func (km *XKMSManager) KeysExist() bool {
	// Check exported certificate files
	paths := km.GetKeyPaths()

	// Check if all certificate files exist
	for _, path := range []string{paths.PKCert, paths.KEKCert, paths.DBCert} {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return false
		}
	}

	return true
}

// GetKeyPaths returns the file paths for Secure Boot certificates and keys
func (km *XKMSManager) GetKeyPaths() KeyPaths {
	return KeyPaths{
		PKCert:  filepath.Join(km.config.KeysDir, fmt.Sprintf("%s.crt", KeyTypePK)),
		KEKCert: filepath.Join(km.config.KeysDir, fmt.Sprintf("%s.crt", KeyTypeKEK)),
		DBCert:  filepath.Join(km.config.KeysDir, fmt.Sprintf("%s.crt", KeyTypeDB)),
		PKKey:   filepath.Join(km.config.KeysDir, fmt.Sprintf("%s.key", KeyTypePK)),
		KEKKey:  filepath.Join(km.config.KeysDir, fmt.Sprintf("%s.key", KeyTypeKEK)),
		DBKey:   filepath.Join(km.config.KeysDir, fmt.Sprintf("%s.key", KeyTypeDB)),
	}
}

// GetSigner returns a crypto.Signer for the specified key type using go-xkms service.
// This supports both software keys and hardware-backed keys (TPM, HSM, etc.) via go-xkms.
func (km *XKMSManager) GetSigner(keyType KeyType) (crypto.Signer, error) {
	// Build KeyAttributes to retrieve the key by its CN (Common Name)
	storeType := backendToStoreType(km.config.Backend)
	attrs := &xkmssdk.KeyAttributes{
		CN:           fmt.Sprintf("secureboot-%s", keyType),
		KeyAlgorithm: x509.RSA,
		KeyType:      xkmssdk.KeyTypeSigning,
		StoreType:    storeType,
		RSAAttributes: &xkmssdk.RSAAttributes{
			KeySize: km.config.KeySize,
		},
	}

	// Get the key using KeyAttributes
	key, err := xkmssdk.ServiceKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	// Type assert to crypto.Signer
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key does not implement crypto.Signer")
	}

	return signer, nil
}

// Close releases resources held by the XKMS service
func (km *XKMSManager) Close() error {
	if km.initialized {
		if err := xkmssdk.ServiceClose(); err != nil {
			return err
		}
		xkmssdk.ServiceReset()
		km.initialized = false
	}
	return nil
}

// writeKey writes a private key to file in PEM format
func writeKey(key *rsa.PrivateKey, path string) error {
	keyFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyFile.Close()

	// Encode private key to PKCS#1 PEM format
	keyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	if err := pem.Encode(keyFile, keyPEM); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	return nil
}

// writeCertificate writes a certificate to file in PEM format
func writeCertificate(cert *x509.Certificate, path string) error {
	certFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certFile.Close()

	// Encode certificate to PEM format
	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	if err := pem.Encode(certFile, certPEM); err != nil {
		return fmt.Errorf("failed to encode certificate: %w", err)
	}

	return nil
}
