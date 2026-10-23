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
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	quicbaassecret "github.com/jeremyhahn/go-quicbaas/sdk/go/secret"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
)

// XKMSClient defines the minimal XKMS operations required for secret resolution.
// This interface is satisfied by the internal/xkms.Adapter and the go-xkms SDK client.
type XKMSClient interface {
	// CanSeal checks if a backend supports sealing operations.
	CanSeal(ctx context.Context, backend string) (*xkmssdk.CanSealResponse, error)

	// Unseal unseals previously sealed data from a backend.
	Unseal(ctx context.Context, req *xkmssdk.UnsealRequest) (*xkmssdk.UnsealResponse, error)

	// GetKey retrieves key information from a backend.
	GetKey(ctx context.Context, backend, keyID string) (*xkmssdk.GetKeyResponse, error)
}

// DynamicSecretsResolver resolves dynamic:// URIs via QuicBaaS DynamicSecrets.
// It generates temporary credentials using role-based generation with optional TTL.
//
// URI format: dynamic://role-name[/ttl]
//
// Examples:
//   - dynamic://database-readonly/1h  - Generate credential for role with 1 hour TTL
//   - dynamic://api-key               - Generate credential using the role's default TTL
//   - dynamic://cache-access/30m      - Generate credential with 30 minute TTL
//
// The resolver returns the credential data serialized as JSON bytes, containing
// the credential ID, type, data map, lease ID, and expiration timestamps.
type DynamicSecretsResolver struct {
	client quicbaassdk.DynamicSecretsClient
	logger *slog.Logger
}

// Compile-time interface check.
var _ quicbaassecret.SecretResolver = (*DynamicSecretsResolver)(nil)

// NewDynamicSecretsResolver creates a new DynamicSecretsResolver.
// The client parameter is the QuicBaaS DynamicSecrets client, accessible
// via app.QuicBaaSSDKClient().DynamicSecrets().
func NewDynamicSecretsResolver(client quicbaassdk.DynamicSecretsClient, logger *slog.Logger) *DynamicSecretsResolver {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &DynamicSecretsResolver{
		client: client,
		logger: logger,
	}
}

// Scheme returns the URI scheme this resolver handles.
func (r *DynamicSecretsResolver) Scheme() string {
	return bootstrap.SchemeDynamic
}

// CanResolve returns true if this resolver can handle the given URI.
func (r *DynamicSecretsResolver) CanResolve(uri string) bool {
	return strings.HasPrefix(strings.ToLower(uri), bootstrap.SchemeDynamic)
}

// Resolve generates a dynamic credential based on the URI parameters.
// The URI path component specifies the role name. An optional second path
// segment specifies the TTL duration (e.g., "1h", "30m", "24h").
// Returns the credential data as a JSON SecretValue.
func (r *DynamicSecretsResolver) Resolve(ctx context.Context, uri string) (*quicbaassecret.SecretValue, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Cause: ctx.Err()}
	default:
	}

	if !r.CanResolve(uri) {
		return nil, ErrInvalidDynamicURI{URI: uri, Reason: "invalid scheme"}
	}

	if r.client == nil {
		return nil, ErrDynamicSecretsNotAvailable{}
	}

	// Parse URI: dynamic://role-name[/ttl]
	path := strings.TrimPrefix(uri, bootstrap.SchemeDynamic)
	if path == "" {
		return nil, ErrInvalidDynamicURI{URI: uri, Reason: "empty role name"}
	}

	parts := strings.SplitN(path, "/", 2)
	roleName := parts[0]
	if roleName == "" {
		return nil, ErrInvalidDynamicURI{URI: uri, Reason: "empty role name"}
	}

	req := &quicbaassdk.GenerateCredentialRequest{
		RoleName: roleName,
	}

	// Parse optional TTL
	if len(parts) > 1 && parts[1] != "" {
		ttl, err := time.ParseDuration(parts[1])
		if err != nil {
			return nil, ErrInvalidDynamicURI{
				URI:    uri,
				Reason: "invalid TTL duration: " + parts[1],
			}
		}
		if ttl <= 0 {
			return nil, ErrInvalidDynamicURI{
				URI:    uri,
				Reason: "TTL must be positive",
			}
		}
		req.TTL = ttl
	}

	resp, err := r.client.GenerateCredential(ctx, req)
	if err != nil {
		return nil, ErrDynamicSecretGenerateFailed{RoleName: roleName, Cause: err}
	}

	if resp == nil || resp.Credential == nil {
		return nil, ErrDynamicSecretGenerateFailed{
			RoleName: roleName,
			Cause:    bootstrap.ErrSecretNotFound{Path: roleName},
		}
	}

	// Serialize the credential data as JSON for the caller.
	data, err := json.Marshal(resp.Credential)
	if err != nil {
		return nil, ErrDynamicSecretGenerateFailed{RoleName: roleName, Cause: err}
	}

	r.logger.Debug("generated dynamic credential",
		slog.String("role", roleName),
		slog.String("credential_id", resp.Credential.CredentialID),
		slog.String("lease_id", resp.LeaseID))

	return quicbaassecret.NewSecretValue(uri, data, quicbaassecret.StrategyLiteral), nil
}

// XKMSSecretsResolver resolves xkms:// URIs via the XKMS service.
// It retrieves secrets that are stored as key material in XKMS backends,
// using the Unseal operation for hardware-backed (TPM) secrets or
// GetKey for software backend key metadata.
//
// URI format: xkms://backend/key-id
//
// Examples:
//   - xkms://software/platform-seal-key  - Retrieve key from software backend
//   - xkms://tpm2/srk-auth               - Unseal secret from TPM2 backend
//
// The resolver accepts any XKMSClient implementation, including the
// internal/xkms.Adapter and the go-xkms SDK client directly.
type XKMSSecretsResolver struct {
	client XKMSClient
	logger *slog.Logger
}

// Compile-time interface check.
var _ quicbaassecret.SecretResolver = (*XKMSSecretsResolver)(nil)

// NewXKMSSecretsResolver creates a new XKMSSecretsResolver.
// The client parameter provides access to the XKMS service operations.
func NewXKMSSecretsResolver(client XKMSClient, logger *slog.Logger) *XKMSSecretsResolver {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &XKMSSecretsResolver{
		client: client,
		logger: logger,
	}
}

// Scheme returns the URI scheme this resolver handles.
func (r *XKMSSecretsResolver) Scheme() string {
	return bootstrap.SchemeXKMS
}

// CanResolve returns true if this resolver can handle the given URI.
func (r *XKMSSecretsResolver) CanResolve(uri string) bool {
	return strings.HasPrefix(strings.ToLower(uri), bootstrap.SchemeXKMS)
}

// Resolve retrieves a secret from the XKMS service.
// For backends that support sealing (e.g., TPM2), the resolver uses
// the Unseal operation. For other backends, it retrieves key information
// via GetKey and returns the key material as JSON bytes.
func (r *XKMSSecretsResolver) Resolve(ctx context.Context, uri string) (*quicbaassecret.SecretValue, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Cause: ctx.Err()}
	default:
	}

	if !r.CanResolve(uri) {
		return nil, ErrInvalidXKMSURI{URI: uri, Reason: "invalid scheme"}
	}

	if r.client == nil {
		return nil, ErrXKMSNotAvailable{}
	}

	// Parse URI: xkms://backend/key-id
	path := strings.TrimPrefix(uri, bootstrap.SchemeXKMS)
	if path == "" {
		return nil, ErrInvalidXKMSURI{URI: uri, Reason: "empty path"}
	}

	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return nil, ErrInvalidXKMSURI{
			URI:    uri,
			Reason: "expected format: xkms://backend/key-id",
		}
	}

	backend := parts[0]
	keyID := parts[1]

	// Check if backend supports sealing (TPM2, hardware).
	canSealResp, err := r.client.CanSeal(ctx, backend)
	if err != nil {
		// If CanSeal fails, fall back to GetKey.
		r.logger.Debug("CanSeal check failed, falling back to GetKey",
			slog.String("backend", backend),
			slog.String("error", err.Error()))
		return r.resolveViaGetKey(ctx, uri, backend, keyID)
	}

	if canSealResp != nil && canSealResp.CanSeal {
		return r.resolveViaUnseal(ctx, uri, backend, keyID)
	}

	return r.resolveViaGetKey(ctx, uri, backend, keyID)
}

// resolveViaUnseal retrieves a sealed secret using the XKMS Unseal operation.
func (r *XKMSSecretsResolver) resolveViaUnseal(ctx context.Context, uri, backend, keyID string) (*quicbaassecret.SecretValue, error) {
	resp, err := r.client.Unseal(ctx, &xkmssdk.UnsealRequest{
		Backend: backend,
		KeyID:   keyID,
	})
	if err != nil {
		return nil, ErrXKMSUnsealFailed{Backend: backend, KeyID: keyID, Cause: err}
	}

	if resp == nil || len(resp.Plaintext) == 0 {
		return nil, bootstrap.ErrSecretNotFound{Path: backend + "/" + keyID}
	}

	r.logger.Debug("resolved secret via XKMS unseal",
		slog.String("backend", backend),
		slog.String("key_id", keyID),
		slog.Int("length", len(resp.Plaintext)))

	return quicbaassecret.NewSecretValue(uri, resp.Plaintext, quicbaassecret.StrategyLiteral), nil
}

// resolveViaGetKey retrieves key information using the XKMS GetKey operation.
// Returns the key response serialized as JSON bytes.
func (r *XKMSSecretsResolver) resolveViaGetKey(ctx context.Context, uri, backend, keyID string) (*quicbaassecret.SecretValue, error) {
	resp, err := r.client.GetKey(ctx, backend, keyID)
	if err != nil {
		return nil, ErrXKMSGetKeyFailed{Backend: backend, KeyID: keyID, Cause: err}
	}

	if resp == nil {
		return nil, bootstrap.ErrSecretNotFound{Path: backend + "/" + keyID}
	}

	data, err := json.Marshal(resp)
	if err != nil {
		return nil, ErrXKMSGetKeyFailed{Backend: backend, KeyID: keyID, Cause: err}
	}

	r.logger.Debug("resolved secret via XKMS GetKey",
		slog.String("backend", backend),
		slog.String("key_id", keyID),
		slog.Int("length", len(data)))

	return quicbaassecret.NewSecretValue(uri, data, quicbaassecret.StrategyLiteral), nil
}
