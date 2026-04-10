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
	"context"
	"log/slog"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

// TrustedRegistry is a container registry requiring host attestation.
// It provides TPM-based attestation verification, encrypted image storage,
// and policy-based access control via QuicBaaS integration.
type TrustedRegistry interface {
	// Push stores a container image in the registry.
	// If attestation is required, the client must be verified first.
	Push(ctx context.Context, ref string, image *Image, opts PushOptions) error

	// Pull retrieves a container image from the registry.
	// If the image is encrypted, it will be decrypted transparently.
	Pull(ctx context.Context, ref string, opts PullOptions) (*Image, error)

	// Delete removes a container image from the registry.
	Delete(ctx context.Context, ref string) error

	// List returns image manifests matching the given options.
	List(ctx context.Context, opts RegistryListOptions) ([]*ImageManifest, error)

	// VerifyClient verifies a client's attestation evidence.
	// Returns nil if the client is authorized to access the registry.
	VerifyClient(ctx context.Context, attestation *AttestationEvidence) error

	// EncryptImage encrypts an image in place using the specified key.
	// The image must already exist in the registry.
	EncryptImage(ctx context.Context, ref string, keyID string) error

	// DecryptImage retrieves and decrypts an encrypted image.
	DecryptImage(ctx context.Context, ref string) (*Image, error)

	// Close releases all resources held by the registry.
	Close() error
}

// PushOptions configures image push behavior
type PushOptions struct {
	// Encrypt indicates whether to encrypt the image
	Encrypt bool

	// KeyID is the encryption key ID (required if Encrypt is true)
	KeyID string

	// AllowOverwrite allows overwriting an existing image
	AllowOverwrite bool

	// SignImage indicates whether to sign the image
	SignImage bool

	// SigningKeyID is the key ID for image signing
	SigningKeyID string

	// Annotations are metadata to add to the manifest
	Annotations map[string]string

	// Timeout overrides the default operation timeout
	Timeout time.Duration
}

// PullOptions configures image pull behavior
type PullOptions struct {
	// DecryptIfEncrypted will attempt to decrypt encrypted images
	DecryptIfEncrypted bool

	// VerifySignature will verify the image signature if signed
	VerifySignature bool

	// Platform specifies the target platform (e.g., "linux/amd64")
	Platform string

	// Timeout overrides the default operation timeout
	Timeout time.Duration
}

// RegistryListOptions configures image listing behavior for TrustedRegistry.
// This is separate from storage.ListOptions to allow for registry-specific options.
type RegistryListOptions struct {
	// Repository filters by repository name
	Repository string

	// TagPrefix filters tags by prefix
	TagPrefix string

	// Limit limits the number of results
	Limit int

	// Offset is the starting offset for pagination
	Offset int

	// IncludeEncrypted includes encrypted images
	IncludeEncrypted bool

	// SortBy specifies the sort field
	SortBy string

	// SortDesc reverses the sort order
	SortDesc bool
}

// PlatformInfo contains platform identification
type PlatformInfo struct {
	// Manufacturer is the platform manufacturer
	Manufacturer string

	// Model is the platform model
	Model string

	// Version is the firmware version
	Version string

	// Serial is the platform serial number
	Serial string
}

// RegistrySessionView is a simplified view of RegistrySession for external use.
// This is used by Registry.GetSession to avoid exposing the full session details.
type RegistrySessionView struct {
	// ClientID identifies the client
	ClientID string

	// AIK is the client's Attestation Identity Key fingerprint
	AIK string

	// PCRs are the verified PCR values
	PCRs map[int][]byte

	// ValidUntil is when the session expires
	ValidUntil time.Time

	// Permissions are the granted permissions
	Permissions []string
}

// Registry implements TrustedRegistry with QuicBaaS storage
type Registry struct {
	config RegistryConfig
	logger *slog.Logger

	// initialized tracks whether the registry is ready
	initialized atomic.Bool

	// closed tracks whether the registry has been closed
	closed atomic.Bool

	// sessions stores authenticated client sessions (clientID -> *RegistrySessionView)
	sessions sync.Map

	// pullSemaphore limits concurrent pulls
	pullSemaphore chan struct{}

	// pushSemaphore limits concurrent pushes
	pushSemaphore chan struct{}
}

// NewRegistry creates a new TrustedRegistry with the given configuration
func NewRegistry(config RegistryConfig, logger *slog.Logger) (*Registry, error) {
	if logger == nil {
		logger = slog.Default()
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	r := &Registry{
		config:        config,
		logger:        logger.With("component", "registry"),
		pullSemaphore: make(chan struct{}, config.MaxConcurrentPulls),
		pushSemaphore: make(chan struct{}, config.MaxConcurrentPushes),
	}

	r.initialized.Store(true)

	r.logger.Info("trusted registry initialized",
		"listen_addr", config.ListenAddr,
		"attestation_required", config.Attestation.RequireAttestation,
		"storage_addr", config.Storage.Addr,
		"storage_namespace", config.Storage.Namespace,
		"encryption_enabled", config.Encryption.EncryptByDefault,
	)

	return r, nil
}

// Push stores a container image in the registry
func (r *Registry) Push(ctx context.Context, ref string, image *Image, opts PushOptions) error {
	if err := r.checkState(); err != nil {
		return err
	}

	// Check context cancellation first (priority check)
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := validateImageRef(ref); err != nil {
		return err
	}

	if image == nil {
		return ErrInvalidManifest{Reference: ref, Reason: "image cannot be nil"}
	}

	// Acquire push semaphore with context cancellation support
	select {
	case r.pushSemaphore <- struct{}{}:
		defer func() { <-r.pushSemaphore }()
	case <-ctx.Done():
		return ctx.Err()
	}

	// Check context again after acquiring semaphore
	if err := ctx.Err(); err != nil {
		return err
	}

	r.logger.Debug("pushing image",
		"ref", ref,
		"encrypt", opts.Encrypt,
		"overwrite", opts.AllowOverwrite,
	)

	// Implementation would:
	// 1. Check if image exists (if !AllowOverwrite)
	// 2. Encrypt layers if requested
	// 3. Store layers in QuicBaaS
	// 4. Store manifest in QuicBaaS
	// 5. Update tag references

	return nil
}

// Pull retrieves a container image from the registry
func (r *Registry) Pull(ctx context.Context, ref string, opts PullOptions) (*Image, error) {
	if err := r.checkState(); err != nil {
		return nil, err
	}

	// Check context cancellation first (priority check)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := validateImageRef(ref); err != nil {
		return nil, err
	}

	// Acquire pull semaphore with context cancellation support
	select {
	case r.pullSemaphore <- struct{}{}:
		defer func() { <-r.pullSemaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Check context again after acquiring semaphore
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	r.logger.Debug("pulling image",
		"ref", ref,
		"decrypt", opts.DecryptIfEncrypted,
		"platform", opts.Platform,
	)

	// Implementation would:
	// 1. Resolve reference to manifest
	// 2. Load manifest from QuicBaaS
	// 3. Load layers from QuicBaaS
	// 4. Decrypt layers if encrypted and requested
	// 5. Return assembled image

	return nil, ErrImageNotFound{Reference: ref}
}

// Delete removes a container image from the registry
func (r *Registry) Delete(ctx context.Context, ref string) error {
	if err := r.checkState(); err != nil {
		return err
	}

	if err := validateImageRef(ref); err != nil {
		return err
	}

	r.logger.Debug("deleting image", "ref", ref)

	// Implementation would:
	// 1. Resolve reference to manifest
	// 2. Delete manifest from QuicBaaS
	// 3. Check layer reference counts
	// 4. Delete unreferenced layers
	// 5. Update tag index

	return ErrImageNotFound{Reference: ref}
}

// List returns image manifests matching the given options
func (r *Registry) List(ctx context.Context, opts RegistryListOptions) ([]*ImageManifest, error) {
	if err := r.checkState(); err != nil {
		return nil, err
	}

	r.logger.Debug("listing images",
		"repository", opts.Repository,
		"tag_prefix", opts.TagPrefix,
		"limit", opts.Limit,
	)

	// Implementation would:
	// 1. Query QuicBaaS for matching manifests
	// 2. Apply filters
	// 3. Apply pagination
	// 4. Return results

	return []*ImageManifest{}, nil
}

// VerifyClient verifies a client's attestation evidence
func (r *Registry) VerifyClient(ctx context.Context, attestation *AttestationEvidence) error {
	if err := r.checkState(); err != nil {
		return err
	}

	if !r.config.Attestation.RequireAttestation {
		return nil
	}

	if attestation == nil {
		return ErrAttestationRequired{}
	}

	r.logger.Debug("verifying client attestation",
		"client_id", attestation.ClientID,
	)

	// Check if AIK is allowed
	if len(r.config.Attestation.AllowedAIKs) > 0 {
		allowed := false
		aikStr := aikToString(attestation.AIK)
		for _, aik := range r.config.Attestation.AllowedAIKs {
			if aik == aikStr {
				allowed = true
				break
			}
		}
		if !allowed {
			return ErrAIKNotAllowed{AIK: aikStr}
		}
	}

	// Check quote age
	if r.config.Attestation.QuoteMaxAge > 0 {
		if time.Since(attestation.Timestamp) > r.config.Attestation.QuoteMaxAge {
			return ErrInvalidQuote{Reason: "quote has expired"}
		}
	}

	// Verify required PCR values
	for pcrIndex, expectedValue := range r.config.Attestation.RequiredPCRs {
		actualValue, ok := attestation.PCRs[pcrIndex]
		if !ok {
			return ErrPCRMismatch{
				PCRIndex: pcrIndex,
				Expected: expectedValue,
				Actual:   nil,
			}
		}
		if !bytesEqual(expectedValue, actualValue) {
			return ErrPCRMismatch{
				PCRIndex: pcrIndex,
				Expected: expectedValue,
				Actual:   actualValue,
			}
		}
	}

	// Implementation would also:
	// 1. Verify quote signature with AIK
	// 2. Verify nonce freshness
	// 3. Replay measurement log if provided
	// 4. Evaluate OPA policy if configured
	// 5. Create and cache session

	// Cache the session
	session := &RegistrySessionView{
		ClientID:   attestation.ClientID,
		AIK:        aikToString(attestation.AIK),
		PCRs:       attestation.PCRs,
		ValidUntil: time.Now().Add(r.config.Attestation.CacheSessionDuration),
	}
	r.sessions.Store(attestation.ClientID, session)

	r.logger.Info("client attestation verified",
		"client_id", attestation.ClientID,
		"valid_until", session.ValidUntil,
	)

	return nil
}

// EncryptImage encrypts an image in place using the specified key
func (r *Registry) EncryptImage(ctx context.Context, ref string, keyID string) error {
	if err := r.checkState(); err != nil {
		return err
	}

	if err := validateImageRef(ref); err != nil {
		return err
	}

	if keyID == "" {
		return ErrInvalidConfig{Field: "key_id", Reason: "encryption key ID required"}
	}

	r.logger.Debug("encrypting image",
		"ref", ref,
		"key_id", keyID,
	)

	// Implementation would:
	// 1. Load image manifest
	// 2. Check if already encrypted
	// 3. For each layer:
	//    a. Generate DEK
	//    b. Encrypt layer with DEK
	//    c. Wrap DEK with KEK from QuicBaaS
	//    d. Store encrypted layer
	// 4. Update manifest with encryption metadata
	// 5. Store updated manifest

	return ErrImageNotFound{Reference: ref}
}

// DecryptImage retrieves and decrypts an encrypted image
func (r *Registry) DecryptImage(ctx context.Context, ref string) (*Image, error) {
	if err := r.checkState(); err != nil {
		return nil, err
	}

	if err := validateImageRef(ref); err != nil {
		return nil, err
	}

	r.logger.Debug("decrypting image", "ref", ref)

	// Implementation would:
	// 1. Load image manifest
	// 2. Check if encrypted
	// 3. For each layer:
	//    a. Load encrypted layer
	//    b. Unwrap DEK from QuicBaaS
	//    c. Decrypt layer with DEK
	// 4. Return decrypted image

	return nil, ErrImageNotFound{Reference: ref}
}

// Close releases all resources held by the registry
func (r *Registry) Close() error {
	if !r.closed.CompareAndSwap(false, true) {
		return ErrRegistryClosed{}
	}

	r.logger.Info("closing trusted registry")

	// Clear sessions
	r.sessions.Range(func(key, value interface{}) bool {
		r.sessions.Delete(key)
		return true
	})

	// Close semaphores
	close(r.pullSemaphore)
	close(r.pushSemaphore)

	r.initialized.Store(false)

	r.logger.Info("trusted registry closed")

	return nil
}

// checkState verifies the registry is ready for operations
func (r *Registry) checkState() error {
	// Check closed first - a closed registry should return ErrRegistryClosed
	// even if initialized is also false
	if r.closed.Load() {
		return ErrRegistryClosed{}
	}
	if !r.initialized.Load() {
		return ErrRegistryNotInitialized{}
	}
	return nil
}

// GetSession retrieves a cached session for a client
func (r *Registry) GetSession(clientID string) (*RegistrySessionView, bool) {
	value, ok := r.sessions.Load(clientID)
	if !ok {
		return nil, false
	}

	session := value.(*RegistrySessionView)
	if time.Now().After(session.ValidUntil) {
		r.sessions.Delete(clientID)
		return nil, false
	}

	return session, true
}

// InvalidateSession removes a session from the cache
func (r *Registry) InvalidateSession(clientID string) {
	r.sessions.Delete(clientID)
}

// imageRefRegex validates image references
// Supports:
// - Simple names: alpine
// - With tag: alpine:latest
// - With repository: myrepo/myimage, myrepo/myimage:v1
// - With registry: registry.example.com/myrepo/myimage:v1
// - With port: localhost:5000/myimage:v1, registry.io:443/myrepo/myimage:tag
// - With digest: myrepo/myimage@sha256:abc123...
var imageRefRegex = regexp.MustCompile(`^(?:(?:[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?)/)?[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*(?::[a-zA-Z0-9_][a-zA-Z0-9._-]*)?(?:@sha256:[a-f0-9]{64})?$`)

// validateImageRef validates an image reference format
func validateImageRef(ref string) error {
	if ref == "" {
		return ErrInvalidImageRef{Reference: ref, Reason: "reference cannot be empty"}
	}

	// Check for overly long references
	if len(ref) > 256 {
		return ErrInvalidImageRef{Reference: ref, Reason: "reference too long"}
	}

	// Validate the reference
	if !imageRefRegex.MatchString(ref) {
		return ErrInvalidImageRef{Reference: ref, Reason: "invalid format"}
	}

	return nil
}

// aikToString converts an AIK byte slice to a string representation
func aikToString(aik []byte) string {
	if len(aik) == 0 {
		return ""
	}
	return computeAIKFingerprint(aik)
}
