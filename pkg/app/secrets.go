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

package app

import (
	"context"
	"crypto"
	"io"
	"log/slog"

	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config/secrets"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// PlatformConfigKeyID is the well-known KMS key identifier used for
// encrypting and decrypting platform configuration values with AES-256-GCM.
const PlatformConfigKeyID = "platform-config-key"

// SecretsConfig controls secret resolution and migration during platform bootstrap.
// When enabled, secrets referenced in configuration using special URI schemes
// (kms://, idevid://, encrypted://, dynamic://, xkms://, etc.) are resolved to
// their plaintext values and optionally migrated to the local KMS for unified access.
//
// To add this to the App struct, add the following field:
//
//	SecretsConfig *SecretsConfig `yaml:"secrets" json:"secrets" mapstructure:"secrets"`
type SecretsConfig struct {
	// Enabled controls whether secret resolution is active during bootstrap.
	// When false, secret URIs in configuration are left as-is.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// LocalKMS enables the kms:// resolver which retrieves secrets from the
	// local QuicBaaS KMS. This is the canonical scheme for persistent
	// auto-generation via EnsureSecret (?ensure=true&len=N&enc=base64).
	LocalKMS bool `yaml:"local-kms" json:"local_kms" mapstructure:"local-kms"`

	// RemoteKMS enables the remote-kms:// resolver which retrieves secrets from
	// a remote KMS endpoint (e.g., another QuicBaaS instance or cloud KMS).
	RemoteKMS bool `yaml:"remote-kms" json:"remote_kms" mapstructure:"remote-kms"`

	// Encrypted enables the idevid:// resolver which decrypts secrets that
	// have been encrypted to the node's IDevID certificate using RSA-OAEP.
	Encrypted bool `yaml:"encrypted" json:"encrypted" mapstructure:"encrypted"`

	// ConfigEncryption enables the encrypted:// resolver which decrypts
	// AES-256-GCM encrypted configuration values using the platform
	// config-encryption key held in the KMS. The key is automatically
	// provisioned during platform initialization if it does not exist.
	//
	// Use the platformctl encrypt command to produce encrypted:// URIs:
	//   platformctl encrypt --value "my-secret"
	ConfigEncryption bool `yaml:"config-encryption" json:"config_encryption" mapstructure:"config-encryption"`

	// DynamicSecrets enables the dynamic:// resolver which generates temporary
	// credentials via the QuicBaaS DynamicSecrets service with role-based generation
	// and TTL-based lease management.
	// Example: dynamic://database-readonly/1h generates a database credential with 1h TTL.
	DynamicSecrets bool `yaml:"dynamic-secrets" json:"dynamic_secrets" mapstructure:"dynamic-secrets"`

	// XKMS enables the xkms:// resolver which retrieves secrets from the XKMS
	// service. For hardware backends (TPM2), it uses the Unseal operation. For
	// software backends, it retrieves key information via GetKey.
	// Example: xkms://tpm2/srk-auth unseals a TPM-sealed secret.
	XKMS bool `yaml:"xkms" json:"xkms" mapstructure:"xkms"`

	// MigrateToKMS controls whether resolved secrets should be stored in the
	// local KMS after resolution. This enables unified secret access via kms://
	// URIs regardless of the original secret source.
	MigrateToKMS bool `yaml:"migrate-to-kms" json:"migrate_to_kms" mapstructure:"migrate-to-kms"`

	// UpdateConfigFile controls whether the configuration file should be updated
	// with kms:// references after secrets are migrated to local KMS.
	// This makes the migration permanent and removes the original secret sources.
	UpdateConfigFile bool `yaml:"update-config-file" json:"update_config_file" mapstructure:"update-config-file"`
}

// DefaultSecretsConfig returns a SecretsConfig with sensible defaults.
// By default, secret resolution is disabled to preserve backward compatibility.
func DefaultSecretsConfig() *SecretsConfig {
	return &SecretsConfig{
		Enabled:          false,
		LocalKMS:         true,
		RemoteKMS:        false,
		Encrypted:        true,
		ConfigEncryption: true,
		DynamicSecrets:   false,
		XKMS:             false,
		MigrateToKMS:     true,
		UpdateConfigFile: false,
	}
}

// Secrets returns the QuicBaaS SecretsService for secret storage operations.
// Returns nil if the datastore backend is not QuicBaaS or if SecretsService is not available.
func (app *App) Secrets() baasservice.SecretsService {
	dbSvc := app.QuicBaaSService()
	if dbSvc == nil {
		app.Logger.Debug("Secrets: QuicBaaS service is nil")
		return nil
	}

	secretsSvc := dbSvc.Secrets()
	if secretsSvc == nil {
		app.Logger.Debug("Secrets: QuicBaaS Secrets service is nil - Secrets may not be enabled in QuicBaaS config")
	}
	return secretsSvc
}

// CryptoService returns the QuicBaaS CryptoService for encrypt/decrypt operations.
// Returns nil if the datastore backend is not QuicBaaS or if CryptoService is not available.
func (app *App) CryptoService() baasservice.CryptoService {
	dbSvc := app.QuicBaaSService()
	if dbSvc == nil {
		app.Logger.Debug("CryptoService: QuicBaaS service is nil")
		return nil
	}

	cryptoSvc := dbSvc.Crypto()
	if cryptoSvc == nil {
		app.Logger.Debug("CryptoService: QuicBaaS Crypto service is nil")
	}
	return cryptoSvc
}

// SetupSecretResolvers creates and configures a ResolverRegistry based on the
// SecretsConfig and available platform capabilities. Only resolvers for enabled
// and available features are registered.
//
// The method logs warnings for resolvers that cannot be enabled due to missing
// dependencies (e.g., no IDevID available for encrypted resolver).
//
// Returns a configured ResolverRegistry or an error if setup fails.
func (app *App) SetupSecretResolvers(ctx context.Context, cfg *SecretsConfig) (*bootstrap.ResolverRegistry, error) {
	if cfg == nil {
		return nil, ErrNilSecretsConfig{}
	}

	logger := app.Logger.Slog()
	registry := bootstrap.NewResolverRegistry(logger)

	// Register LocalSecrets resolver if enabled and QuicBaaS SecretsService is available.
	// The resolver is configured with the current node's identity so
	// kms://... URIs can use {{tenant}} / {{node}} placeholders that
	// expand to this node's persistent-secret keyspace.
	if cfg.LocalKMS {
		secretsSvc := app.Secrets()
		if secretsSvc != nil {
			resolver := NewLocalSecretsResolver(secretsSvc, logger).
				WithIdentity(app.TenantID, app.Hostname)
			registry.Register(resolver)
			logger.Debug("registered local secrets resolver",
				slog.String("tenant", app.TenantID),
				slog.String("node", app.Hostname))
		} else {
			logger.Warn("local-kms resolver enabled but QuicBaaS SecretsService is not available")
		}
	}

	// Register IDevID resolver if enabled and IDevID decrypter is available
	if cfg.Encrypted {
		decrypter, err := app.getIDevIDDecrypter(ctx)
		if err != nil {
			logger.Warn("idevid resolver enabled but IDevID decrypter not available",
				slog.String("error", err.Error()))
		} else if decrypter != nil {
			resolver := secrets.NewIDevIDResolver(decrypter, logger)
			// Wrap the secrets.IDevIDResolver to adapt it to bootstrap.SecretResolver
			registry.Register(NewIDevIDResolverAdapter(resolver, logger))
			logger.Debug("registered idevid resolver")
		} else {
			logger.Warn("idevid resolver enabled but IDevID is not configured")
		}
	}

	// Register encrypted:// (AES-256-GCM config encryption) resolver if enabled
	if cfg.ConfigEncryption {
		cryptoSvc := app.CryptoService()
		if cryptoSvc != nil {
			decryptFn := app.configDecryptFunc(cryptoSvc)
			resolver := secrets.NewEncryptedResolver(decryptFn, logger)
			registry.Register(NewEncryptedResolverAdapter(resolver, logger))
			logger.Debug("registered encrypted config resolver")
		} else {
			logger.Warn("config-encryption resolver enabled but CryptoService is not available")
		}
	}

	// Register DynamicSecrets resolver if enabled and QuicBaaS SDK client is available
	if cfg.DynamicSecrets {
		sdkClient := app.QuicBaaSSDKClient()
		if sdkClient != nil {
			dynClient := sdkClient.DynamicSecrets()
			if dynClient != nil {
				resolver := NewDynamicSecretsResolver(dynClient, logger)
				registry.Register(resolver)
				logger.Debug("registered dynamic secrets resolver")
			} else {
				logger.Warn("dynamic-secrets resolver enabled but DynamicSecrets client is not available")
			}
		} else {
			logger.Warn("dynamic-secrets resolver enabled but QuicBaaS SDK client is not available")
		}
	}

	// Register XKMS resolver if enabled and XKMS SDK client is available
	if cfg.XKMS {
		sdkClient := app.QuicBaaSSDKClient()
		if sdkClient != nil {
			// Use the XKMS client from the QuicBaaS SDK if available
			xkmsClient := sdkClient.KMS()
			if xkmsClient != nil {
				// Create an adapter that satisfies XKMSClient from the KMS client
				resolver := NewXKMSSecretsResolver(&xkmsKMSClientAdapter{kms: xkmsClient}, logger)
				registry.Register(resolver)
				logger.Debug("registered XKMS secrets resolver")
			} else {
				logger.Warn("xkms resolver enabled but XKMS client is not available")
			}
		} else {
			logger.Warn("xkms resolver enabled but QuicBaaS SDK client is not available")
		}
	}

	return registry, nil
}

// configDecryptFunc returns a DecryptFunc closure that decrypts AES-256-GCM
// ciphertext using the platform config-encryption key via the QuicBaaS
// CryptoService. The ciphertext format is nonce || ciphertext+tag as
// produced by the platformctl encrypt command.
func (app *App) configDecryptFunc(cryptoSvc baasservice.CryptoService) secrets.DecryptFunc {
	return func(ctx context.Context, ciphertext []byte) ([]byte, error) {
		// AES-256-GCM nonce is 12 bytes. The encrypted:// wire format
		// concatenates nonce || ciphertext (where ciphertext includes
		// the GCM authentication tag).
		const nonceSize = 12
		if len(ciphertext) <= nonceSize {
			return nil, ErrConfigDecryptFailed{
				Cause: ErrInvalidCiphertextLength{
					Length:   len(ciphertext),
					MinBytes: nonceSize + 1,
				},
			}
		}

		nonce := ciphertext[:nonceSize]
		encData := ciphertext[nonceSize:]

		resp, err := cryptoSvc.Decrypt(ctx, &baasservice.DecryptRequest{
			KeyID:      PlatformConfigKeyID,
			Ciphertext: encData,
			Nonce:      nonce,
		})
		if err != nil {
			return nil, ErrConfigDecryptFailed{Cause: err}
		}

		if resp == nil || len(resp.Plaintext) == 0 {
			return nil, ErrConfigDecryptFailed{
				Cause: ErrEmptyDecryptResult{},
			}
		}

		return resp.Plaintext, nil
	}
}

// EnsurePlatformConfigKey ensures the platform config-encryption key exists
// in the KMS. If the key does not exist, a new AES-256-GCM key is generated.
// This method should be called during platform initialization after the KMS
// service is available.
//
// The key is used by the encrypted:// resolver to decrypt configuration
// values and by the platformctl encrypt command to encrypt them.
func (app *App) EnsurePlatformConfigKey(ctx context.Context) error {
	kmsSvc := app.KMS()
	if kmsSvc == nil {
		return ErrKMSNotAvailable{}
	}

	// Check if the key already exists
	_, err := kmsSvc.GetKey(ctx, &baasservice.GetKeyRequest{
		KeyID: PlatformConfigKeyID,
	})
	if err == nil {
		app.Logger.Slog().Debug("platform config-encryption key already exists",
			slog.String("key_id", PlatformConfigKeyID))
		return nil
	}

	// Key does not exist -- generate it.
	app.Logger.Slog().Info("generating platform config-encryption key",
		slog.String("key_id", PlatformConfigKeyID))

	_, genErr := kmsSvc.GenerateKey(ctx, &baasservice.GenerateKeyRequest{
		KeyAttributes: &xkmssdk.KeyAttributes{
			CN:                 PlatformConfigKeyID,
			SymmetricAlgorithm: xkmssdk.SymmetricAES256GCM,
		},
		Name:               PlatformConfigKeyID,
		Description:        "Platform config-encryption key for encrypted:// secrets",
		Usage:              []baasservice.KeyUsage{baasservice.KeyUsageEncrypt, baasservice.KeyUsageDecrypt},
		DeletionProtection: true,
		Owner:              "platform",
		Tags: map[string]string{
			"purpose": "config-encryption",
			"managed": "platform",
		},
	})
	if genErr != nil {
		return ErrConfigKeyGenerateFailed{Cause: genErr}
	}

	app.Logger.Slog().Info("platform config-encryption key created",
		slog.String("key_id", PlatformConfigKeyID))

	return nil
}

// ProcessSecrets resolves secret URIs in the application configuration and
// optionally migrates them to the local KMS. This method should be called
// during platform bootstrap after the App is initialized but before services
// start using configuration values.
//
// The processing flow is:
//  1. Setup resolvers based on SecretsConfig
//  2. Create SecretManager with the resolver registry
//  3. Process the App config struct to resolve all secret URIs
//  4. If MigrateToKMS is enabled, store resolved secrets in local KMS
//  5. If UpdateConfigFile is enabled, update config file with kms:// references
//
// Returns a MigrationResult containing information about processed secrets,
// or an error if processing fails.
func (app *App) ProcessSecrets(ctx context.Context, cfg *SecretsConfig, configFilePath string) (*bootstrap.MigrationResult, error) {
	if cfg == nil {
		return nil, ErrNilSecretsConfig{}
	}

	if !cfg.Enabled {
		return &bootstrap.MigrationResult{
			Migrated:      []bootstrap.MigratedSecret{},
			AutoGenerated: []string{},
			Errors:        []error{},
		}, nil
	}

	logger := app.Logger.Slog()
	logger.Info("processing secrets in configuration")

	// Ensure the platform config-encryption key exists before resolving
	// encrypted:// URIs.
	if cfg.ConfigEncryption {
		if err := app.EnsurePlatformConfigKey(ctx); err != nil {
			logger.Warn("failed to ensure platform config-encryption key, encrypted:// resolver may fail",
				slog.String("error", err.Error()))
		}
	}

	// Setup resolvers
	registry, err := app.SetupSecretResolvers(ctx, cfg)
	if err != nil {
		return nil, ErrSetupSecretResolvers{Cause: err}
	}

	// Get SecretsService client for migration
	var secretsClient bootstrap.SecretsClient
	if cfg.MigrateToKMS {
		secretsSvc := app.Secrets()
		if secretsSvc != nil {
			secretsClient = NewSecretsServiceClient(secretsSvc, logger)
		} else {
			logger.Warn("migrate-to-kms enabled but QuicBaaS SecretsService is not available, skipping migration")
		}
	}

	// If no secrets client available for migration, create a no-op client
	if secretsClient == nil {
		secretsClient = &noOpSecretsClient{}
	}

	// Create secret manager
	manager, err := bootstrap.NewSecretManager(registry, secretsClient, "config", logger)
	if err != nil {
		return nil, ErrCreateSecretManager{Cause: err}
	}

	// Process the App config
	result, err := manager.ProcessConfig(ctx, app)
	if err != nil {
		return result, ErrProcessSecrets{Cause: err}
	}

	logger.Info("secrets processing complete",
		slog.Int("migrated", result.MigratedCount()),
		slog.Int("auto_generated", result.AutoGeneratedCount()),
		slog.Int("errors", result.ErrorCount()))

	// Update config file if enabled and we have migrated secrets
	if cfg.UpdateConfigFile && len(result.Migrated) > 0 && configFilePath != "" {
		if err := app.updateConfigWithKMSReferences(result, configFilePath, logger); err != nil {
			result.Errors = append(result.Errors, ErrUpdateConfigFile{Cause: err})
			logger.Error("failed to update config file with KMS references",
				slog.String("error", err.Error()))
		}
	}

	return result, nil
}

// updateConfigWithKMSReferences updates the configuration file with kms:// references
// for all migrated secrets.
func (app *App) updateConfigWithKMSReferences(result *bootstrap.MigrationResult, configFilePath string, logger *slog.Logger) error {
	writer, err := bootstrap.NewConfigWriter(configFilePath, logger)
	if err != nil {
		return err
	}

	// Create backup before modifying
	backupPath, err := writer.Backup()
	if err != nil {
		return err
	}
	logger.Info("created config backup", slog.String("path", backupPath))

	// Build updates from migration result
	updates := make([]bootstrap.SecretUpdate, 0, len(result.Migrated))
	for _, migrated := range result.Migrated {
		updates = append(updates, bootstrap.SecretUpdate{
			Path:          migrated.ConfigPath,
			KMSReference:  migrated.KMSPath,
			OriginalValue: migrated.OriginalURI,
		})
	}

	// Apply updates
	if err := writer.UpdateSecretReferences(updates); err != nil {
		// Attempt to restore from backup on failure
		if restoreErr := writer.Restore(backupPath); restoreErr != nil {
			logger.Error("failed to restore config from backup",
				slog.String("error", restoreErr.Error()))
		}
		return err
	}

	logger.Info("updated config file with KMS references",
		slog.Int("count", len(updates)),
		slog.String("config", configFilePath))

	return nil
}

// tpmDecrypter implements crypto.Decrypter using the TPM's RSADecrypt method.
type tpmDecrypter struct {
	tpm   xkmssdk.TrustedPlatformModule
	attrs *xkmssdk.KeyAttributes
}

// Public returns the public key associated with the decrypter.
func (d *tpmDecrypter) Public() crypto.PublicKey {
	pubKey, err := d.tpm.IDevID()
	if err != nil {
		return nil
	}
	return pubKey
}

// Decrypt decrypts ciphertext using the TPM-backed IDevID key.
// The rand parameter is ignored as the TPM handles randomness internally.
// The opts parameter is currently ignored; RSA-OAEP with SHA-256 is used.
func (d *tpmDecrypter) Decrypt(_ io.Reader, ciphertext []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	if d.attrs == nil || d.attrs.TPMAttributes == nil {
		return nil, ErrIDevIDNotConfigured{}
	}
	return d.tpm.RSADecrypt(
		d.attrs.TPMAttributes.Handle,
		d.attrs.TPMAttributes.Name,
		ciphertext,
	)
}

// getIDevIDDecrypter returns a crypto.Decrypter for the IDevID key if available.
// Returns nil if IDevID is not configured or not accessible.
func (app *App) getIDevIDDecrypter(_ context.Context) (crypto.Decrypter, error) {
	// Check if TPM and IDevID are configured
	if app.TPM == nil {
		return nil, ErrTPMNotAvailable{}
	}

	if app.TPMConfig.IDevID == nil {
		return nil, ErrIDevIDNotConfigured{}
	}

	// Get the IDevID key attributes from TPM
	idevidAttrs, err := app.TPM.IDevIDAttributes()
	if err != nil {
		return nil, ErrGetIDevIDAttrs{Cause: err}
	}

	// Create TPM-backed decrypter
	decrypter := &tpmDecrypter{
		tpm:   app.TPM,
		attrs: idevidAttrs,
	}

	return decrypter, nil
}

// noOpSecretsClient is a no-op implementation of bootstrap.SecretsClient
// used when KMS migration is disabled or unavailable.
type noOpSecretsClient struct{}

func (c *noOpSecretsClient) StoreSecret(ctx context.Context, path string, data []byte, metadata map[string]string) error {
	return nil
}

func (c *noOpSecretsClient) GetSecret(ctx context.Context, path string) ([]byte, error) {
	return nil, bootstrap.ErrSecretNotFound{Path: path}
}

// Ensure tpmDecrypter implements crypto.Decrypter at compile time.
var _ crypto.Decrypter = (*tpmDecrypter)(nil)

// xkmsKMSClientAdapter adapts the QuicBaaS KMSClient to the XKMSClient interface
// required by XKMSSecretsResolver. This provides access to key operations via
// the QuicBaaS SDK's KMS service when a standalone XKMS adapter is not available.
type xkmsKMSClientAdapter struct {
	kms interface{}
}

// CanSeal checks if a backend supports sealing operations.
// When using the QuicBaaS KMS client, sealing capability depends on the
// backend type. Returns false by default, causing the resolver to use GetKey.
func (a *xkmsKMSClientAdapter) CanSeal(ctx context.Context, backend string) (*xkmssdk.CanSealResponse, error) {
	// QuicBaaS KMS client doesn't expose CanSeal directly.
	// Return false to default to GetKey resolution path.
	return &xkmssdk.CanSealResponse{CanSeal: false, Backend: backend}, nil
}

// Unseal is not directly supported through the QuicBaaS KMS client adapter.
// Returns ErrXKMSNotAvailable since unsealing requires direct XKMS access.
func (a *xkmsKMSClientAdapter) Unseal(ctx context.Context, req *xkmssdk.UnsealRequest) (*xkmssdk.UnsealResponse, error) {
	return nil, ErrXKMSNotAvailable{}
}

// GetKey retrieves key information. This is a placeholder that returns not-found
// since the QuicBaaS KMS client interface may differ from the XKMS GetKey format.
// When full XKMS integration is available, this should delegate to the XKMS adapter.
func (a *xkmsKMSClientAdapter) GetKey(ctx context.Context, backend, keyID string) (*xkmssdk.GetKeyResponse, error) {
	return nil, bootstrap.ErrSecretNotFound{Path: backend + "/" + keyID}
}
