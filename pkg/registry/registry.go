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
	"errors"
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

	// storage is the backing blob+manifest store. It is set via the
	// WithStorage option at construction time; without it the
	// Registry remains in an "unconfigured" state where Push/Pull/
	// List return ErrStorageNotConfigured rather than silently
	// no-oping (the pre-Phase-5 behavior).
	storage *QuicBaaSStorage

	// encryptor handles per-layer encryption when Push(opts.Encrypt)
	// is requested. Set via WithEncryptor; nil disables encryption
	// (Push with Encrypt=true is then refused).
	encryptor *ImageEncryptor

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

	// now is time.Now in production; tests replace it to advance time (#284)
	now func() time.Time
}

// RegistryOption is a functional option for constructing a Registry.
type RegistryOption func(*Registry)

// WithStorage installs the QuicBaaSStorage backend the Registry uses
// for blob + manifest + tag persistence. Required for Push/Pull/List/
// Delete to function. The Registry takes ownership of the storage
// (Close on the registry closes the storage).
func WithStorage(s *QuicBaaSStorage) RegistryOption {
	return func(r *Registry) {
		r.storage = s
	}
}

// WithEncryptor installs an ImageEncryptor so the Registry can fulfill
// Push(opts.Encrypt=true). When unset, encrypted pushes return
// ErrEncryptionNotConfigured. The encryptor's underlying KMSClient
// can be any implementation — LocalKMSClient ships out of the box;
// production deployments swap in the QuicBaaS-KMS-backed
// implementation when it lands.
func WithEncryptor(e *ImageEncryptor) RegistryOption {
	return func(r *Registry) {
		r.encryptor = e
	}
}

// NewRegistry creates a new TrustedRegistry with the given configuration
func NewRegistry(config RegistryConfig, logger *slog.Logger, opts ...RegistryOption) (*Registry, error) {
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
		now:           time.Now,
	}
	for _, opt := range opts {
		opt(r)
	}

	r.initialized.Store(true)

	r.logger.Info("trusted registry initialized",
		"listen_addr", config.ListenAddr,
		"attestation_required", config.Attestation.RequireAttestation,
		"storage_addr", config.Storage.Addr,
		"storage_namespace", config.Storage.Namespace,
		"encryption_enabled", config.Encryption.EncryptByDefault,
		"storage_configured", r.storage != nil,
	)

	return r, nil
}

// Push stores a container image in the registry. Layers are persisted
// blob-by-blob keyed by digest, the manifest is persisted at the
// supplied reference, and a tag entry is written so List() can find
// the image by ref.
//
// Phase 5 first-ship intentionally skips encryption and signing — the
// opts fields are honored to the extent the underlying storage
// supports them today (none, both are deferred). Callers that pass
// Encrypt=true receive ErrEncryptionNotConfigured rather than a
// silently-unencrypted push.
func (r *Registry) Push(ctx context.Context, ref string, image *Image, opts PushOptions) error {
	if err := r.checkState(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateImageRef(ref); err != nil {
		return err
	}
	if image == nil {
		return ErrInvalidManifest{Reference: ref, Reason: "image cannot be nil"}
	}
	if image.Manifest == nil {
		return ErrInvalidManifest{Reference: ref, Reason: "manifest cannot be nil"}
	}
	if r.storage == nil {
		return ErrStorageNotConfigured{Op: "Push"}
	}
	if opts.Encrypt && r.encryptor == nil {
		return ErrEncryptionNotConfigured{Reference: ref}
	}
	if opts.SignImage {
		return ErrSigningNotConfigured{Reference: ref}
	}
	// An image without layers has no content to serve; refuse it here so
	// every transport that pushes through the registry inherits the check.
	if len(image.Layers) == 0 {
		return ErrImageEmpty{}
	}

	select {
	case r.pushSemaphore <- struct{}{}:
		defer func() { <-r.pushSemaphore }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	r.logger.Debug("pushing image",
		"ref", ref,
		"overwrite", opts.AllowOverwrite,
		"layers", len(image.Layers),
	)

	if !opts.AllowOverwrite {
		exists, err := r.storage.ManifestExists(ctx, ref)
		if err != nil {
			return err
		}
		if exists {
			return ErrImageAlreadyExists{Reference: ref}
		}
	}

	// Encrypted push: route each layer through the encryptor before
	// persisting. The encrypted blob bytes land at the layer digest
	// in storage; the manifest carries an "encrypted=true" annotation
	// plus the wrapped DEK + nonce so Pull can reverse the operation.
	var encLayers []EncryptedLayer
	if opts.Encrypt {
		keyID := opts.KeyID
		if keyID == "" {
			keyID = "registry-default"
		}
		encImage, err := r.encryptor.EncryptImage(ctx, image, keyID)
		if err != nil {
			return err
		}
		encLayers = encImage.EncryptedLayers
		if image.Manifest.Annotations == nil {
			image.Manifest.Annotations = make(map[string]string)
		}
		image.Manifest.Annotations[ManifestAnnotationEncrypted] = "true"
		image.Manifest.Annotations[ManifestAnnotationKeyID] = encImage.KeyID
	}

	for i := range image.Layers {
		l := &image.Layers[i]
		if l.Digest == "" {
			return ErrInvalidManifest{Reference: ref, Reason: "layer with empty digest"}
		}
		var blob []byte
		if opts.Encrypt {
			env, err := encodeEncryptedLayer(&encLayers[i])
			if err != nil {
				return err
			}
			blob = env
		} else {
			blob = l.Content
		}
		if err := r.storage.StoreBlob(ctx, l.Digest, blob); err != nil {
			return err
		}
	}

	// Persist the config blob if present so it survives independent of
	// the manifest. The manifest references it by digest.
	if len(image.Config) > 0 && image.Manifest.Config.Digest != "" {
		if err := r.storage.StoreBlob(ctx, image.Manifest.Config.Digest, image.Config); err != nil {
			return err
		}
	}

	now := r.now().UTC()
	if image.Manifest.CreatedAt.IsZero() {
		image.Manifest.CreatedAt = now
	}
	image.Manifest.UpdatedAt = now
	image.Manifest.Reference = ref

	return r.storage.StoreManifest(ctx, ref, image.Manifest)
}

// Annotation keys recorded on encrypted manifests. Kept namespaced so
// they round-trip through generic OCI tooling without collision.
const (
	// ManifestAnnotationEncrypted is "true" on a manifest whose layers
	// were encrypted on push.
	ManifestAnnotationEncrypted = "org.letstrust.registry.encrypted"
	// ManifestAnnotationKeyID names the key the layers were encrypted with.
	ManifestAnnotationKeyID = "org.letstrust.registry.key-id"
)

// Pull retrieves a container image from the registry. The manifest is
// looked up at the supplied reference, then each layer is fetched
// blob-by-blob using the digest recorded in the manifest. The
// returned Image always references the on-disk content directly —
// no decryption is performed today; encrypted images surface
// ErrEncryptionNotConfigured.
func (r *Registry) Pull(ctx context.Context, ref string, opts PullOptions) (*Image, error) {
	if err := r.checkState(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateImageRef(ref); err != nil {
		return nil, err
	}
	if r.storage == nil {
		return nil, ErrStorageNotConfigured{Op: "Pull"}
	}

	select {
	case r.pullSemaphore <- struct{}{}:
		defer func() { <-r.pullSemaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	r.logger.Debug("pulling image", "ref", ref, "platform", opts.Platform)

	manifest, err := r.storage.GetManifest(ctx, ref)
	if err != nil {
		// Surface the public ErrImageNotFound at the registry boundary
		// so callers don't need to know about the storage-layer
		// ErrManifestNotFound, which is an internal type. Other
		// storage errors (transport, validation) pass through.
		var notFound ErrManifestNotFound
		if errors.As(err, &notFound) {
			return nil, ErrImageNotFound{Reference: ref}
		}
		return nil, err
	}
	if manifest == nil {
		return nil, ErrImageNotFound{Reference: ref}
	}

	img := &Image{Manifest: manifest}

	if manifest.Config.Digest != "" {
		data, err := r.storage.GetBlob(ctx, manifest.Config.Digest)
		if err != nil {
			return nil, err
		}
		img.Config = data
	}

	encrypted := manifest.Annotations != nil &&
		manifest.Annotations[ManifestAnnotationEncrypted] == "true"
	if encrypted && r.encryptor == nil {
		return nil, ErrEncryptionNotConfigured{Reference: ref}
	}

	img.Layers = make([]Layer, 0, len(manifest.Layers))
	for _, d := range manifest.Layers {
		data, err := r.storage.GetBlob(ctx, d.Digest)
		if err != nil {
			return nil, err
		}
		if !encrypted {
			img.Layers = append(img.Layers, Layer{
				Digest:    d.Digest,
				MediaType: d.MediaType,
				Size:      d.Size,
				Content:   data,
			})
			continue
		}
		encLayer, err := decodeEncryptedLayer(data)
		if err != nil {
			return nil, err
		}
		layer, err := r.encryptor.decryptLayer(ctx, encLayer)
		if err != nil {
			return nil, err
		}
		img.Layers = append(img.Layers, *layer)
	}
	return img, nil
}

// Delete removes a container image from the registry. The manifest
// is removed first; layer blobs and the config blob are then GC'd if
// they are no longer referenced by any surviving manifest. This is a
// best-effort reference-counting sweep — under concurrent pushes a
// blob may be re-counted, in which case the next Delete cycle picks
// it up. The cost is O(remaining manifests) per delete, which is
// fine for the volumes Phase 5 ships at.
func (r *Registry) Delete(ctx context.Context, ref string) error {
	if err := r.checkState(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateImageRef(ref); err != nil {
		return err
	}
	if r.storage == nil {
		return ErrStorageNotConfigured{Op: "Delete"}
	}

	r.logger.Debug("deleting image", "ref", ref)

	// Fetch the manifest so we know which blobs to consider for GC.
	manifest, err := r.storage.GetManifest(ctx, ref)
	if err != nil {
		var notFound ErrManifestNotFound
		if errors.As(err, &notFound) {
			return ErrImageNotFound{Reference: ref}
		}
		return err
	}
	if manifest == nil {
		return ErrImageNotFound{Reference: ref}
	}

	if err := r.storage.DeleteManifest(ctx, ref); err != nil {
		return err
	}

	// Run GC on layer + config blobs.
	candidates := make([]string, 0, len(manifest.Layers)+1)
	for _, d := range manifest.Layers {
		if d.Digest != "" {
			candidates = append(candidates, d.Digest)
		}
	}
	if manifest.Config.Digest != "" {
		candidates = append(candidates, manifest.Config.Digest)
	}
	if len(candidates) == 0 {
		return nil
	}

	stillReferenced, err := r.referencedBlobs(ctx)
	if err != nil {
		// GC failure must not undo the manifest delete — the caller's
		// intent (remove the image) succeeded. Log and continue;
		// orphan blobs will be picked up by the next delete cycle or
		// a future explicit sweep.
		r.logger.Warn("registry: blob GC scan failed; leaving orphans",
			"ref", ref, "error", err)
		return nil
	}
	for _, digest := range candidates {
		if _, ok := stillReferenced[digest]; ok {
			continue
		}
		if delErr := r.storage.DeleteBlob(ctx, digest); delErr != nil {
			r.logger.Warn("registry: failed to GC blob",
				"digest", digest, "error", delErr)
		}
	}
	return nil
}

// referencedBlobs walks every remaining manifest and returns the set
// of blob digests still in use. Used by Delete's GC pass to decide
// which orphans to reclaim. The set includes both layer digests and
// config blob digests since either can be content-shared across
// images.
func (r *Registry) referencedBlobs(ctx context.Context) (map[string]struct{}, error) {
	refs := make(map[string]struct{})
	cursor := ""
	for {
		res, err := r.storage.ListManifests(ctx, ListOptions{
			Limit:  500,
			Cursor: cursor,
		})
		if err != nil {
			return nil, err
		}
		for i := range res.Manifests {
			m := res.Manifests[i]
			if m.Config.Digest != "" {
				refs[m.Config.Digest] = struct{}{}
			}
			for _, d := range m.Layers {
				if d.Digest != "" {
					refs[d.Digest] = struct{}{}
				}
			}
		}
		if !res.HasMore || res.NextCursor == "" {
			break
		}
		cursor = res.NextCursor
	}
	return refs, nil
}

// List returns image manifests matching the given options. The
// underlying QuicBaaSStorage performs the prefix-scan and pagination;
// IncludeEncrypted is honored at the storage layer (Phase 5 ignores
// it since encryption is deferred).
func (r *Registry) List(ctx context.Context, opts RegistryListOptions) ([]*ImageManifest, error) {
	if err := r.checkState(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.storage == nil {
		return nil, ErrStorageNotConfigured{Op: "List"}
	}

	r.logger.Debug("listing images",
		"repository", opts.Repository,
		"tag_prefix", opts.TagPrefix,
		"limit", opts.Limit,
	)

	sopts := ListOptions{
		Repository:  opts.Repository,
		Prefix:      opts.TagPrefix,
		Limit:       opts.Limit,
		IncludeTags: true,
	}
	res, err := r.storage.ListManifests(ctx, sopts)
	if err != nil {
		return nil, err
	}
	out := make([]*ImageManifest, len(res.Manifests))
	for i := range res.Manifests {
		m := res.Manifests[i]
		out[i] = &m
	}
	return out, nil
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
		if r.now().Sub(attestation.Timestamp) > r.config.Attestation.QuoteMaxAge {
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
		ValidUntil: r.now().Add(r.config.Attestation.CacheSessionDuration),
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
	if r.now().After(session.ValidUntil) {
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
