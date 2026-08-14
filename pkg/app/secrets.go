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
	"strings"

	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	quicbaassecret "github.com/jeremyhahn/go-quicbaas/sdk/go/secret"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config/secrets"
)

// SecretsConfig controls secret resolution during platform bootstrap.
// When enabled, secrets referenced in configuration using special URI schemes
// (kms://, idevid://, file://, dynamic://, xkms://, credential://, etc.) are
// resolved to their plaintext values in place via the unified qrdb-SDK
// ResolverRegistry / ConfigProcessor.
type SecretsConfig struct {
	// Enabled controls whether secret resolution is active during bootstrap.
	// When false, secret URIs in configuration are left as-is.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// LocalKMS enables the kms:// resolver backed by the QuicBaaS SecretsService.
	// When quicbaas is absent and LocalKMS is true, kms:// URIs fail-closed with
	// ErrSecretsServiceNotAvailableButKMSRequired.
	LocalKMS bool `yaml:"local-kms" json:"local_kms" mapstructure:"local-kms"`

	// RemoteKMS enables the remote-kms:// resolver.
	RemoteKMS bool `yaml:"remote-kms" json:"remote_kms" mapstructure:"remote-kms"`

	// Encrypted enables the idevid:// resolver which decrypts secrets encrypted
	// to the node's IDevID certificate using RSA-OAEP.
	Encrypted bool `yaml:"encrypted" json:"encrypted" mapstructure:"encrypted"`

	// File enables the file:// resolver which reads a secret's raw bytes from a
	// path on the local filesystem. This is an opt-in escape hatch for Secure
	// Boot airgap provisioning, offline development, and recovery flows where
	// the KMS-backed kms:// resolver is unavailable. It must never be enabled on
	// nodes that can reach a KMS, since the secret lives in plaintext on disk.
	File bool `yaml:"file" json:"file" mapstructure:"file"`

	// DynamicSecrets enables the dynamic:// resolver which generates temporary
	// credentials via the QuicBaaS DynamicSecrets service.
	// Example: dynamic://database-readonly/1h generates a database credential with 1h TTL.
	DynamicSecrets bool `yaml:"dynamic-secrets" json:"dynamic_secrets" mapstructure:"dynamic-secrets"`

	// XKMS enables the xkms:// resolver which retrieves secrets from the XKMS service.
	// For hardware backends (TPM2), it uses the Unseal operation.
	// Example: xkms://tpm2/srk-auth unseals a TPM-sealed secret.
	XKMS bool `yaml:"xkms" json:"xkms" mapstructure:"xkms"`
}

// DefaultSecretsConfig returns a SecretsConfig with sensible defaults.
// By default, secret resolution is disabled to preserve backward compatibility.
func DefaultSecretsConfig() *SecretsConfig {
	return &SecretsConfig{
		Enabled:        false,
		LocalKMS:       true,
		RemoteKMS:      false,
		Encrypted:      true,
		File:           false,
		DynamicSecrets: false,
		XKMS:           false,
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

// SetupSecretResolvers returns the unified qrdb ResolverRegistry for this App.
//
// When a QuicBaaS SDK client is available, the registry exposed via
// Security().SecretResolver() is used as the base (credential://, kms://,
// remote-kms://, autogen). TP-specific adapters (idevid://, file://,
// dynamic://, xkms://) are registered on top.
//
// When no QuicBaaS SDK client is available (standalone mode), a fresh
// registry is built. A fail-closed kms:// stub is registered so that any
// kms:// URI encountered during config walking produces a clear typed error
// rather than falling through to a raw literal.
//
// Only resolvers for enabled and available features are registered.
func (app *App) SetupSecretResolvers(ctx context.Context, cfg *SecretsConfig) (*quicbaassecret.ResolverRegistry, error) {
	if cfg == nil {
		return nil, ErrNilSecretsConfig{}
	}

	logger := app.Logger.Slog()

	// Source the base registry.
	var registry *quicbaassecret.ResolverRegistry
	sdkClient := app.QuicBaaSSDKClient()
	if sdkClient != nil {
		if reg := sdkClient.Security().SecretResolver(); reg != nil {
			// QuicBaaS present: use its registry (has credential://, kms://,
			// remote-kms://, autogen). TP adapters are added below.
			registry = reg
			logger.Debug("using quicbaas unified secret resolver registry")
		}
	}

	if registry == nil {
		// Standalone mode (no quicbaas SDK client, or SecretResolver not wired).
		// Build a fresh registry. If kms:// URIs exist in config but the
		// SecretsService is not reachable, they must fail-closed rather than
		// being treated as literal strings and silently passed downstream.
		registry = quicbaassecret.NewResolverRegistry()
		if cfg.LocalKMS {
			registry.Register(&kmsNotAvailableResolver{})
			logger.Warn("kms:// resolver requested but QuicBaaS not available; kms:// URIs will fail-closed")
		}
		logger.Debug("built standalone secret resolver registry")
	}

	// Register IDevID resolver if enabled and IDevID decrypter is available.
	if cfg.Encrypted {
		decrypter, err := app.getIDevIDDecrypter(ctx)
		switch {
		case err != nil:
			logger.Warn("idevid resolver enabled but IDevID decrypter not available",
				slog.String("error", err.Error()))
		case decrypter != nil:
			registry.Register(secrets.NewIDevIDResolver(decrypter, logger))
			logger.Debug("registered idevid resolver")
		default:
			logger.Warn("idevid resolver enabled but IDevID is not configured")
		}
	}

	// Register file:// resolver if enabled. This is the airgap/dev escape hatch
	// and reads secret bytes verbatim from the local filesystem.
	if cfg.File {
		registry.Register(secrets.NewFileResolver(logger))
		logger.Debug("registered file secret resolver")
	}

	// Register DynamicSecrets resolver if enabled and QuicBaaS SDK client is available.
	if cfg.DynamicSecrets {
		if sdkClient != nil {
			dynClient := sdkClient.Security().DynamicSecrets()
			if dynClient != nil {
				registry.Register(NewDynamicSecretsResolver(dynClient, logger))
				logger.Debug("registered dynamic secrets resolver")
			} else {
				logger.Warn("dynamic-secrets resolver enabled but DynamicSecrets client is not available")
			}
		} else {
			logger.Warn("dynamic-secrets resolver enabled but QuicBaaS SDK client is not available")
		}
	}

	// Register XKMS resolver if enabled and QuicBaaS SDK client is available.
	if cfg.XKMS {
		if sdkClient != nil {
			xkmsClient := sdkClient.Security().KMS()
			if xkmsClient != nil {
				registry.Register(NewXKMSSecretsResolver(&xkmsKMSClientAdapter{kms: xkmsClient}, logger))
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

// ProcessSecrets resolves secret URIs in the application configuration in place
// using the unified qrdb ConfigProcessor. This should be called during platform
// bootstrap after the App is initialized but before services consume config values.
//
// WithFailClosed is always applied: any unresolved or erroring secret URI causes
// Process to return ErrUnresolvedSecretURI alongside the ProcessResult so callers
// can inspect diagnostics before deciding to refuse startup.
//
// Returns (result, nil) on clean resolution and (result, ErrUnresolvedSecretURI)
// when any secret URI could not be resolved.
func (app *App) ProcessSecrets(ctx context.Context, cfg *SecretsConfig) (*quicbaassecret.ProcessResult, error) {
	if cfg == nil {
		return nil, ErrNilSecretsConfig{}
	}

	if !cfg.Enabled {
		return &quicbaassecret.ProcessResult{}, nil
	}

	logger := app.Logger.Slog()
	logger.Info("processing secrets in configuration")

	registry, err := app.SetupSecretResolvers(ctx, cfg)
	if err != nil {
		return nil, ErrSetupSecretResolvers{Cause: err}
	}

	processor := quicbaassecret.NewConfigProcessor(registry, quicbaassecret.WithFailClosed())
	result, err := processor.Process(ctx, app)
	if err != nil {
		// Fail-closed returns a generic sentinel; the ProcessResult carries the
		// diagnostics. Log WHICH references failed — without this the operator
		// only sees "unresolved secret reference remains" with no way to tell
		// which URI (of dozens of kms:// refs) blocked startup.
		if result != nil {
			for _, u := range result.Unresolved {
				logger.Error("secret reference unresolved", slog.String("field", u))
			}
			for _, rerr := range result.Errors {
				logger.Error("secret resolution error", slog.String("error", rerr.Error()))
			}
			logger.Error("secrets processing failed",
				slog.Int("resolved", result.Resolved),
				slog.Int("unresolved", len(result.Unresolved)),
				slog.Int("errors", len(result.Errors)))
		}
		return result, ErrProcessSecrets{Cause: err}
	}

	logger.Info("secrets processing complete",
		slog.Int("resolved", result.Resolved),
		slog.Int("unresolved", len(result.Unresolved)),
		slog.Int("errors", len(result.Errors)))

	return result, nil
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
	// Check if TPM and IDevID are configured.
	if app.TPM == nil {
		return nil, ErrTPMNotAvailable{}
	}

	if app.TPMConfig.IDevID == nil {
		return nil, ErrIDevIDNotConfigured{}
	}

	// Get the IDevID key attributes from TPM.
	idevidAttrs, err := app.TPM.IDevIDAttributes()
	if err != nil {
		return nil, ErrGetIDevIDAttrs{Cause: err}
	}

	// Create TPM-backed decrypter.
	decrypter := &tpmDecrypter{
		tpm:   app.TPM,
		attrs: idevidAttrs,
	}

	return decrypter, nil
}

// xkmsKMSClientAdapter adapts the QuicBaaS KMSClient to the XKMSClient interface
// required by XKMSSecretsResolver.
type xkmsKMSClientAdapter struct {
	kms interface{}
}

// CanSeal returns false by default, causing the resolver to use GetKey.
func (a *xkmsKMSClientAdapter) CanSeal(ctx context.Context, backend string) (*xkmssdk.CanSealResponse, error) {
	return &xkmssdk.CanSealResponse{CanSeal: false, Backend: backend}, nil
}

// Unseal is not directly supported through the QuicBaaS KMS client adapter.
func (a *xkmsKMSClientAdapter) Unseal(ctx context.Context, req *xkmssdk.UnsealRequest) (*xkmssdk.UnsealResponse, error) {
	return nil, ErrXKMSNotAvailable{}
}

// GetKey is a placeholder that returns not-found.
func (a *xkmsKMSClientAdapter) GetKey(ctx context.Context, backend, keyID string) (*xkmssdk.GetKeyResponse, error) {
	return nil, ErrXKMSNotAvailable{}
}

// kmsNotAvailableResolver is registered in standalone mode (no QuicBaaS) when
// LocalKMS is requested. Any kms:// URI causes a fail-closed error so the
// raw URI string is never passed downstream as a literal password or auth value.
type kmsNotAvailableResolver struct{}

// Compile-time interface check.
var _ quicbaassecret.SecretResolver = (*kmsNotAvailableResolver)(nil)

func (r *kmsNotAvailableResolver) Scheme() string { return "kms" }

func (r *kmsNotAvailableResolver) CanResolve(raw string) bool {
	return strings.HasPrefix(strings.ToLower(raw), "kms://")
}

func (r *kmsNotAvailableResolver) Resolve(_ context.Context, raw string) (*quicbaassecret.SecretValue, error) {
	return nil, ErrSecretsServiceNotAvailableButKMSRequired{URICount: 1}
}

// Ensure tpmDecrypter implements crypto.Decrypter at compile time.
var _ crypto.Decrypter = (*tpmDecrypter)(nil)
