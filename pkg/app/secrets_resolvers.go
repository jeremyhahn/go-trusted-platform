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
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config/secrets"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
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

// AutoGenResolver generates random secrets based on URI parameters.
// It supports the autogen:// scheme with format: autogen://length/encoding
//
// Supported encodings:
//   - base64: Standard base64 encoding
//   - hex: Hexadecimal encoding
//   - numeric: Digit-only string (0-9), each digit uniformly selected via crypto/rand
//   - raw: Raw bytes (default)
//
// Examples:
//   - autogen://32/base64 - 32 random bytes, base64 encoded
//   - autogen://16/hex - 16 random bytes, hex encoded
//   - autogen://6/numeric - 6-digit random PIN like "847293"
//   - autogen://64 - 64 raw bytes
type AutoGenResolver struct {
	logger *slog.Logger
}

// NewAutoGenResolver creates a new AutoGenResolver.
func NewAutoGenResolver(logger *slog.Logger) *AutoGenResolver {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &AutoGenResolver{logger: logger}
}

// Scheme returns the URI scheme this resolver handles.
func (r *AutoGenResolver) Scheme() string {
	return bootstrap.SchemeAutoGen
}

// CanResolve returns true if this resolver can handle the given URI.
func (r *AutoGenResolver) CanResolve(uri string) bool {
	return strings.HasPrefix(strings.ToLower(uri), bootstrap.SchemeAutoGen)
}

// Resolve generates a random secret based on the URI parameters.
func (r *AutoGenResolver) Resolve(ctx context.Context, uri string) ([]byte, error) {
	// Check context
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Cause: ctx.Err()}
	default:
	}

	// Parse URI: autogen://length/encoding
	if !r.CanResolve(uri) {
		return nil, ErrInvalidAutoGenURI{URI: uri, Reason: "invalid scheme"}
	}

	// Remove scheme prefix
	params := strings.TrimPrefix(strings.ToLower(uri), bootstrap.SchemeAutoGen)
	parts := strings.Split(params, "/")

	// Default values
	length := 32
	encoding := "raw"

	// Parse length
	if len(parts) > 0 && parts[0] != "" {
		var err error
		length, err = strconv.Atoi(parts[0])
		if err != nil || length <= 0 {
			return nil, ErrInvalidAutoGenURI{URI: uri, Reason: "invalid length: " + parts[0]}
		}
	}

	// Parse encoding
	if len(parts) > 1 && parts[1] != "" {
		encoding = parts[1]
	}

	// Numeric encoding uses bootstrap.GenerateNumericPIN for uniform digit selection
	if encoding == "numeric" {
		result, err := bootstrap.GenerateNumericPIN(length)
		if err != nil {
			return nil, ErrAutoGenFailed{URI: uri, Cause: err}
		}
		r.logger.Debug("auto-generated secret",
			slog.Int("length", length),
			slog.String("encoding", encoding),
			slog.Int("result_length", len(result)))
		return result, nil
	}

	// Generate random bytes
	randomBytes := make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, ErrAutoGenFailed{URI: uri, Cause: err}
	}

	// Encode based on requested format
	var result []byte
	switch encoding {
	case "base64":
		result = []byte(base64.StdEncoding.EncodeToString(randomBytes))
	case "hex":
		result = []byte(hex.EncodeToString(randomBytes))
	case "raw", "":
		result = randomBytes
	default:
		return nil, ErrInvalidAutoGenURI{URI: uri, Reason: "unsupported encoding: " + encoding}
	}

	r.logger.Debug("auto-generated secret",
		slog.Int("length", length),
		slog.String("encoding", encoding),
		slog.Int("result_length", len(result)))

	return result, nil
}

// LocalSecretsResolver retrieves secrets from the local QuicBaaS SecretsService.
// It supports the kms:// scheme with format: kms://path/to/secret
//
// Placeholder substitution: the resolver rewrites two well-known
// placeholders in the URI path BEFORE dispatching the call to the
// secrets service, so templates can use stable identifiers that
// expand to the current node's tenant and hostname at resolution
// time:
//
//	{{tenant}} -> LocalSecretsResolver.TenantID
//	{{node}}   -> LocalSecretsResolver.NodeID
//
// Short path expansion: if the resolved path does NOT start with
// "tenants/", the resolver automatically prepends
// tenants/{tenantID}/nodes/{nodeID}/secrets/ using the configured
// identity. This allows compact URIs like kms://bmc/password to
// resolve to the full keyspace path without requiring every config
// field to spell out the tenant/node prefix.
//
// This lets a single control-plane template be shared across all
// nodes of a tenant -- each node gets its own persistent secret
// keyspace without needing per-node YAML copies.
type LocalSecretsResolver struct {
	secrets  baasservice.SecretsService
	logger   *slog.Logger
	tenantID string
	nodeID   string
}

// NewLocalSecretsResolver creates a new LocalSecretsResolver. The
// tenantID and nodeID parameters are substituted into kms:// URIs at
// resolution time wherever the {{tenant}} and {{node}} placeholders
// appear. Pass empty strings to disable substitution.
func NewLocalSecretsResolver(secrets baasservice.SecretsService, logger *slog.Logger) *LocalSecretsResolver {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &LocalSecretsResolver{
		secrets: secrets,
		logger:  logger,
	}
}

// WithIdentity returns a copy of the resolver configured with the
// given tenant ID and node ID. These values are substituted into
// {{tenant}} and {{node}} placeholders in kms:// URIs. The original
// resolver is not modified.
func (r *LocalSecretsResolver) WithIdentity(tenantID, nodeID string) *LocalSecretsResolver {
	cp := *r
	cp.tenantID = tenantID
	cp.nodeID = nodeID
	return &cp
}

// Scheme returns the URI scheme this resolver handles.
func (r *LocalSecretsResolver) Scheme() string {
	return bootstrap.SchemeKMS
}

// CanResolve returns true if this resolver can handle the given URI.
func (r *LocalSecretsResolver) CanResolve(uri string) bool {
	return strings.HasPrefix(strings.ToLower(uri), bootstrap.SchemeKMS)
}

// Resolve retrieves a secret from the SecretsService.
//
// The kms:// URI has two modes based on query parameters:
//
//	kms://path/to/secret
//	    Strict read. Returns ErrSecretNotFound if the secret does
//	    not exist at the given path. This is the legacy behavior
//	    for operator-managed secrets that must exist before boot.
//
//	kms://path/to/secret?ensure=true&len=32&enc=base64
//	    Vault-style generate-on-first-access (ensure mode). On the
//	    first boot that resolves this URI, the QuicBaaS SecretsService
//	    generates a fresh random value of the requested shape
//	    (length + encoding), persists it at the path, and returns the
//	    bytes. On every subsequent resolution the same stable bytes
//	    are returned. Concurrent resolvers racing on the same path
//	    are serialized by a distributed lock in QuicBaaS so only one
//	    generator runs.
//
//	    This replaces the deprecated autogen:// scheme which
//	    regenerated new random bytes on every boot and made it
//	    impossible to bind a persistent secret to a configuration
//	    field. Any TPM PIN, SRK auth, recovery passphrase, or signing
//	    key that needs to remain stable across reboots MUST use this
//	    form.
//
//	    Supported encodings: base64, hex, numeric, raw.
//	    Spec mismatch between the request and a previously-stored
//	    value at the same path is a hard error (no silent rotation).
//
// Short path expansion: if the resolved path does NOT start with
// "tenants/", the resolver automatically prepends
// tenants/{tenantID}/nodes/{nodeID}/secrets/ when both tenantID and
// nodeID are configured. This makes kms://bmc/password resolve to
// tenants/{tenant}/nodes/{node}/secrets/bmc/password.
//
// Example full URIs:
//
//	kms://tenants/default/nodes/lab-node-2/secrets/platform/so-pin?ensure=true&len=8&enc=numeric
//	kms://tenants/default/nodes/lab-node-2/secrets/tpm/platform-srk/srk-auth?ensure=true&len=32&enc=base64
//	kms://bmc/password  (short form, auto-expanded with identity)
func (r *LocalSecretsResolver) Resolve(ctx context.Context, uri string) ([]byte, error) {
	// Check context first - if cancelled, return immediately
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Cause: ctx.Err()}
	default:
	}

	// Validate URI scheme first to provide better error messages
	if !r.CanResolve(uri) {
		return nil, ErrInvalidKMSURI{URI: uri, Reason: "invalid scheme"}
	}

	// Split the URI into path + query. We cannot use net/url.Parse
	// directly because kms:// paths contain characters (slashes,
	// tenant IDs) that net/url's opaque-vs-hierarchical detection
	// handles inconsistently. Split manually on the first '?'.
	raw := strings.TrimPrefix(uri, bootstrap.SchemeKMS)
	var rawPath, rawQuery string
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		rawPath = raw[:i]
		rawQuery = raw[i+1:]
	} else {
		rawPath = raw
	}
	if rawPath == "" {
		return nil, ErrInvalidKMSURI{URI: uri, Reason: "empty path"}
	}

	// Expand {{tenant}} and {{node}} placeholders against the
	// resolver's identity. An unexpanded placeholder that remains
	// after substitution (because identity is empty) is a hard
	// error -- config templates must be rendered against a node
	// that has an identity.
	rawPath = r.expandIdentityPlaceholders(rawPath)
	if strings.Contains(rawPath, "{{tenant}}") || strings.Contains(rawPath, "{{node}}") {
		return nil, ErrInvalidKMSURI{URI: uri, Reason: "unresolved {{tenant}} or {{node}} placeholder -- resolver was constructed without identity"}
	}

	// Short path expansion: if the path does not start with "tenants/",
	// automatically prepend tenants/{tenantID}/nodes/{nodeID}/secrets/
	// so that compact URIs like kms://bmc/password resolve to the full
	// multi-tenant keyspace path.
	rawPath = bootstrap.ExpandShortKMSPath(rawPath, r.tenantID, r.nodeID)

	// Parse the query string into a flat map. We only support
	// known keys so a typo becomes a loud error, not a silent
	// fall-through to strict-read mode.
	q, qErr := parseKMSQuery(rawQuery)
	if qErr != nil {
		return nil, ErrInvalidKMSURI{URI: uri, Reason: qErr.Error()}
	}

	// Check if secrets service is available
	if r.secrets == nil {
		return nil, ErrSecretsServiceNotAvailable{}
	}

	// Ensure mode: generate-on-first-access with a persistent
	// spec. Every subsequent resolution returns the same bytes.
	if q.ensure {
		if q.length <= 0 {
			return nil, ErrInvalidKMSURI{URI: uri, Reason: "ensure=true requires len>0"}
		}
		if q.encoding == "" {
			return nil, ErrInvalidKMSURI{URI: uri, Reason: "ensure=true requires enc=base64|hex|numeric|raw"}
		}
		resp, err := r.secrets.EnsureSecret(ctx, &baasservice.EnsureSecretRequest{
			SecretID: rawPath,
			Length:   q.length,
			Encoding: q.encoding,
			TenantID: q.tenantID,
		})
		if err != nil {
			return nil, ErrSecretsGetFailed{Path: rawPath, Cause: err}
		}
		if resp == nil || len(resp.Data) == 0 {
			return nil, bootstrap.ErrSecretNotFound{Path: rawPath}
		}
		r.logger.Debug("ensured secret from SecretsService",
			slog.String("path", rawPath),
			slog.Bool("generated", resp.Generated),
			slog.Int("length", len(resp.Data)),
		)
		return resp.Data, nil
	}

	// Strict-read mode: the secret must already exist. This is
	// the pre-existing behaviour used by operator-managed config
	// values that reference pre-stored secrets.
	resp, err := r.secrets.GetSecret(ctx, &baasservice.GetSecretRequest{
		SecretID: rawPath,
	})
	if err != nil {
		return nil, ErrSecretsGetFailed{Path: rawPath, Cause: err}
	}

	if resp == nil || len(resp.Data) == 0 {
		return nil, bootstrap.ErrSecretNotFound{Path: rawPath}
	}

	r.logger.Debug("resolved secret from SecretsService",
		slog.String("secret_id", rawPath),
		slog.Int("length", len(resp.Data)))

	return resp.Data, nil
}

// expandIdentityPlaceholders rewrites {{tenant}} and {{node}}
// placeholders in a kms:// URI path to the resolver's configured
// identity values. If a value is empty the placeholder is left in
// place so the caller's Resolve can surface a clear error rather
// than silently producing a nonsense path.
func (r *LocalSecretsResolver) expandIdentityPlaceholders(path string) string {
	if r.tenantID != "" {
		path = strings.ReplaceAll(path, "{{tenant}}", r.tenantID)
	}
	if r.nodeID != "" {
		path = strings.ReplaceAll(path, "{{node}}", r.nodeID)
	}
	return path
}

// kmsQuery is the parsed form of the kms:// query string. Only the
// listed keys are accepted; unknown keys return an error so a typo
// cannot accidentally fall through to strict-read mode.
type kmsQuery struct {
	ensure   bool
	length   int
	encoding string
	tenantID string // optional override; empty = use context tenant
}

// parseKMSQuery parses a raw query string into a kmsQuery. Empty
// input produces a zero value (strict-read mode).
func parseKMSQuery(raw string) (kmsQuery, error) {
	var q kmsQuery
	if raw == "" {
		return q, nil
	}
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			return q, fmt.Errorf("query param %q has no value", pair)
		}
		key := strings.ToLower(pair[:eq])
		val := pair[eq+1:]
		switch key {
		case "ensure":
			switch strings.ToLower(val) {
			case "true", "1", "yes":
				q.ensure = true
			case "false", "0", "no":
				q.ensure = false
			default:
				return q, fmt.Errorf("ensure must be true|false, got %q", val)
			}
		case "len", "length":
			n, err := strconv.Atoi(val)
			if err != nil {
				return q, fmt.Errorf("len must be a positive integer, got %q: %w", val, err)
			}
			if n <= 0 {
				return q, fmt.Errorf("len must be a positive integer, got %d", n)
			}
			q.length = n
		case "enc", "encoding":
			switch strings.ToLower(val) {
			case "base64", "hex", "numeric", "raw":
				q.encoding = strings.ToLower(val)
			default:
				return q, fmt.Errorf("enc must be base64|hex|numeric|raw, got %q", val)
			}
		case "tenant", "tenant_id", "tenantid":
			q.tenantID = val
		default:
			return q, fmt.Errorf("unknown query parameter %q (supported: ensure, len, enc, tenant)", key)
		}
	}
	return q, nil
}

// SecretsServiceClient adapts the QuicBaaS SecretsService to the bootstrap.SecretsClient interface.
type SecretsServiceClient struct {
	secrets baasservice.SecretsService
	logger  *slog.Logger
}

// NewSecretsServiceClient creates a new SecretsServiceClient.
func NewSecretsServiceClient(secrets baasservice.SecretsService, logger *slog.Logger) *SecretsServiceClient {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &SecretsServiceClient{
		secrets: secrets,
		logger:  logger,
	}
}

// StoreSecret stores a secret in the SecretsService.
func (c *SecretsServiceClient) StoreSecret(ctx context.Context, path string, data []byte, metadata map[string]string) error {
	if c.secrets == nil {
		return ErrSecretsServiceNotAvailable{}
	}

	// Store the secret using SecretsService
	_, err := c.secrets.StoreSecret(ctx, &baasservice.StoreSecretRequest{
		Name:     path,
		Data:     data,
		Metadata: metadata,
	})
	if err != nil {
		return ErrSecretsStoreFailed{Path: path, Cause: err}
	}

	c.logger.Debug("stored secret in SecretsService",
		slog.String("path", path),
		slog.Int("length", len(data)))

	return nil
}

// GetSecret retrieves a secret from the SecretsService.
func (c *SecretsServiceClient) GetSecret(ctx context.Context, path string) ([]byte, error) {
	if c.secrets == nil {
		return nil, ErrSecretsServiceNotAvailable{}
	}

	resp, err := c.secrets.GetSecret(ctx, &baasservice.GetSecretRequest{
		SecretID: path,
	})
	if err != nil {
		return nil, ErrSecretsGetFailed{Path: path, Cause: err}
	}

	if resp == nil || len(resp.Data) == 0 {
		return nil, bootstrap.ErrSecretNotFound{Path: path}
	}

	return resp.Data, nil
}

// EncryptedResolverAdapter adapts the config/secrets.EncryptedResolver to
// the bootstrap.SecretResolver interface.
type EncryptedResolverAdapter struct {
	resolver *secrets.EncryptedResolver
	logger   *slog.Logger
}

// NewEncryptedResolverAdapter creates a new EncryptedResolverAdapter.
func NewEncryptedResolverAdapter(resolver *secrets.EncryptedResolver, logger *slog.Logger) *EncryptedResolverAdapter {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &EncryptedResolverAdapter{
		resolver: resolver,
		logger:   logger,
	}
}

// Scheme returns the URI scheme this resolver handles.
func (a *EncryptedResolverAdapter) Scheme() string {
	return bootstrap.SchemeEncrypted
}

// CanResolve returns true if this resolver can handle the given URI.
func (a *EncryptedResolverAdapter) CanResolve(uri string) bool {
	return a.resolver.CanResolve(uri)
}

// Resolve decrypts the encrypted secret and returns the plaintext.
func (a *EncryptedResolverAdapter) Resolve(ctx context.Context, uri string) ([]byte, error) {
	secretValue, err := a.resolver.Resolve(ctx, uri)
	if err != nil {
		return nil, err
	}

	if secretValue == nil {
		return nil, bootstrap.ErrSecretNotFound{Path: uri}
	}

	// Return the decrypted value
	// Note: The caller is responsible for clearing the secret from memory
	return secretValue.Value, nil
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
// Returns the credential data as JSON bytes.
func (r *DynamicSecretsResolver) Resolve(ctx context.Context, uri string) ([]byte, error) {
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

	// Serialize the credential data as JSON for the caller
	data, err := json.Marshal(resp.Credential)
	if err != nil {
		return nil, ErrDynamicSecretGenerateFailed{RoleName: roleName, Cause: err}
	}

	r.logger.Debug("generated dynamic credential",
		slog.String("role", roleName),
		slog.String("credential_id", resp.Credential.CredentialID),
		slog.String("lease_id", resp.LeaseID))

	return data, nil
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
func (r *XKMSSecretsResolver) Resolve(ctx context.Context, uri string) ([]byte, error) {
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

	// Check if backend supports sealing (TPM2, hardware)
	canSealResp, err := r.client.CanSeal(ctx, backend)
	if err != nil {
		// If CanSeal fails, fall back to GetKey
		r.logger.Debug("CanSeal check failed, falling back to GetKey",
			slog.String("backend", backend),
			slog.String("error", err.Error()))
		return r.resolveViaGetKey(ctx, backend, keyID)
	}

	if canSealResp != nil && canSealResp.CanSeal {
		return r.resolveViaUnseal(ctx, backend, keyID)
	}

	return r.resolveViaGetKey(ctx, backend, keyID)
}

// resolveViaUnseal retrieves a sealed secret using the XKMS Unseal operation.
func (r *XKMSSecretsResolver) resolveViaUnseal(ctx context.Context, backend, keyID string) ([]byte, error) {
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

	return resp.Plaintext, nil
}

// resolveViaGetKey retrieves key information using the XKMS GetKey operation.
// Returns the key response serialized as JSON bytes.
func (r *XKMSSecretsResolver) resolveViaGetKey(ctx context.Context, backend, keyID string) ([]byte, error) {
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

	return data, nil
}
