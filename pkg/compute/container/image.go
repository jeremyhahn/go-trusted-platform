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

package container

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
)

// ImageVerifier defines the interface for image signature verification.
// This can be implemented by external packages like pkg/attestation/image.
type ImageVerifier interface {
	// Verify verifies the signature of a container image.
	Verify(ctx context.Context, imageRef string, opts ImageVerifyOptions) (*ImageVerificationResult, error)
}

// ImageVerifyOptions contains options for image verification.
type ImageVerifyOptions struct {
	// TrustedRootCA is the path to the trusted root CA for verification.
	TrustedRootCA string

	// AllowedSigners are the allowed signer identities.
	AllowedSigners []string

	// RequireSignature requires a valid signature.
	RequireSignature bool

	// SignatureType specifies the expected signature type (cosign, notation).
	SignatureType string
}

// ImageVerificationResult contains the result of image verification.
type ImageVerificationResult struct {
	// Verified indicates if the image signature is valid.
	Verified bool

	// Signer is the identity of the signer.
	Signer string

	// Issuer is the certificate issuer.
	Issuer string

	// SignatureType is the type of signature (cosign, notation).
	SignatureType string

	// Certificate is the signing certificate in PEM format.
	Certificate []byte

	// Timestamp is when the signature was created.
	SignatureTimestamp time.Time

	// Annotations are signature annotations.
	Annotations map[string]string
}

// ImageManagerConfig holds configuration for the ImageManager.
type ImageManagerConfig struct {
	// Logger is the logger to use.
	Logger *slog.Logger

	// CacheSize is the maximum number of verification results to cache.
	CacheSize int

	// CacheTTL is how long to cache verification results.
	CacheTTL time.Duration

	// RequireSignature requires all images to have valid signatures.
	RequireSignature bool

	// TrustedRootCA is the path to the trusted root CA.
	TrustedRootCA string

	// AllowedSigners are identities allowed to sign images.
	AllowedSigners []string

	// AllowedRegistries are registries allowed to pull from.
	AllowedRegistries []string
}

// Validate validates the ImageManagerConfig.
func (c *ImageManagerConfig) Validate() error {
	if c.Logger == nil {
		return ErrInvalidSpec
	}
	if c.CacheSize < 0 {
		return ErrInvalidSpec
	}
	if c.CacheTTL < 0 {
		return ErrInvalidSpec
	}
	return nil
}

// ImageManagerOption configures an ImageManager.
type ImageManagerOption func(*ImageManager)

// WithImageManagerLogger sets the logger for the image manager.
func WithImageManagerLogger(logger *slog.Logger) ImageManagerOption {
	return func(m *ImageManager) {
		m.logger = logger
	}
}

// WithImageVerifier sets the image verifier.
func WithImageVerifier(verifier ImageVerifier) ImageManagerOption {
	return func(m *ImageManager) {
		m.verifier = verifier
	}
}

// WithPodmanForImages sets the Podman backend for image operations.
func WithPodmanForImages(podman PodmanBackend) ImageManagerOption {
	return func(m *ImageManager) {
		m.podman = podman
	}
}

// verificationCacheEntry holds a cached verification result.
type verificationCacheEntry struct {
	result    *ImageVerification
	expiresAt time.Time
}

// ImageManager manages container images including pulling, verification,
// and digest computation for attestation.
type ImageManager struct {
	config   ImageManagerConfig
	logger   *slog.Logger
	podman   PodmanBackend
	verifier ImageVerifier

	// verificationCache caches verification results.
	verificationCache sync.Map

	// digestCache caches image digests.
	digestCache sync.Map

	// closed indicates if the manager has been closed.
	closed atomic.Bool

	// now is time.Now in production; tests replace it to cross the cache
	// TTL without sleeping (#284).
	now func() time.Time
}

// NewImageManager creates a new ImageManager with the given configuration.
func NewImageManager(config ImageManagerConfig, opts ...ImageManagerOption) (*ImageManager, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	m := &ImageManager{
		config: config,
		logger: config.Logger,
		now:    time.Now,
	}

	for _, opt := range opts {
		opt(m)
	}

	// Set defaults
	if m.logger == nil {
		m.logger = slog.Default()
	}
	if config.CacheSize == 0 {
		m.config.CacheSize = 100
	}
	if config.CacheTTL == 0 {
		m.config.CacheTTL = 5 * time.Minute
	}

	return m, nil
}

// PullImage pulls a container image from a registry.
// It validates the registry against the allowed list and optionally
// verifies the image signature after pulling.
func (m *ImageManager) PullImage(ctx context.Context, ref string, opts PullOptions) error {
	if m.closed.Load() {
		return ErrOrchestratorClosed
	}

	if ref == "" {
		return ErrInvalidImage
	}

	// Validate registry if allowed list is configured
	if len(m.config.AllowedRegistries) > 0 {
		registry := parseRegistry(ref)
		if !isRegistryAllowed(registry, m.config.AllowedRegistries) {
			return NewImageError(ref, registry, ErrRegistryUnreachable)
		}
	}

	m.logger.Info("pulling image", "ref", ref)

	// Pull via Podman
	if m.podman != nil {
		if err := m.podman.PullImage(ctx, ref); err != nil {
			return NewImageError(ref, "", ErrImagePullFailed)
		}
	}

	// Verify signature if required
	if opts.VerifySignature || m.config.RequireSignature {
		verification, err := m.VerifyImage(ctx, ref)
		if err != nil {
			return err
		}
		if !verification.Verified {
			return NewImageError(ref, "", ErrImageSignatureRequired)
		}
	}

	m.logger.Info("pulled image", "ref", ref)
	return nil
}

// VerifyImage verifies the signature of a container image and reports the
// immutable OCI content digest of the image the verdict applies to.
// Results are cached to avoid repeated verification of the same image.
//
// The digest is resolved with GetImageDigest, so it is the image's own content
// digest and nothing else. There is deliberately no fallback: a hash of the
// image REFERENCE is a different, non-portable value that no registry, no
// other host and no verifier can reproduce, and presenting it in the Digest
// field of a verification result would make an authoritative-looking record of
// an artifact that was never identified. An image whose digest cannot be
// resolved is an error and produces no result at all.
func (m *ImageManager) VerifyImage(ctx context.Context, ref string) (*ImageVerification, error) {
	if m.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	if ref == "" {
		return nil, ErrInvalidImage
	}

	// Check cache
	if cached, ok := m.getVerificationFromCache(ref); ok {
		return cached, nil
	}

	m.logger.Debug("verifying image", "ref", ref)

	// Establish WHAT is being verified before verifying it. A verification
	// result names the artifact it covers; one that cannot name it is not
	// evidence, so an unresolvable digest fails the whole call rather than
	// yielding a result with a placeholder in the Digest field.
	digest, err := m.GetImageDigest(ctx, ref)
	if err != nil {
		return nil, err
	}

	var verification *ImageVerification

	if m.verifier != nil {
		// Use external verifier
		verifyOpts := ImageVerifyOptions{
			TrustedRootCA:    m.config.TrustedRootCA,
			AllowedSigners:   m.config.AllowedSigners,
			RequireSignature: m.config.RequireSignature,
		}

		result, err := m.verifier.Verify(ctx, ref, verifyOpts)
		if err != nil {
			return nil, NewImageError(ref, "", err)
		}

		verification = &ImageVerification{
			ImageRef:      ref,
			Digest:        digest,
			Verified:      result.Verified,
			Signer:        result.Signer,
			SignatureType: result.SignatureType,
			Timestamp:     m.now(),
			Certificate:   result.Certificate,
			Annotations:   result.Annotations,
		}
	} else {
		// No verifier configured. The image is identified but unendorsed:
		// Verified stays false and the caller decides whether that is
		// acceptable (see ImageManagerConfig.RequireSignature).
		verification = &ImageVerification{
			ImageRef:  ref,
			Digest:    digest,
			Verified:  false,
			Timestamp: m.now(),
		}
	}

	// Cache the result
	m.cacheVerification(ref, verification)

	return verification, nil
}

// GetImageDigest returns the immutable OCI content digest of a container
// image, in canonical "sha256:<64 hex>" form.
//
// The digest is read from the image itself. There is deliberately no
// fallback: hashing the image REFERENCE produces a different, non-portable
// value that no registry, no other host and no verifier can reproduce, so
// substituting it for an unavailable content digest would make every
// downstream measurement a fabrication. An image whose digest cannot be read
// — including a locally built image that was never pushed and therefore has
// no repository digest — is an error.
func (m *ImageManager) GetImageDigest(ctx context.Context, ref string) (string, error) {
	if m.closed.Load() {
		return "", ErrOrchestratorClosed
	}

	if ref == "" {
		return "", ErrInvalidImage
	}

	// A reference that already carries a content digest needs no lookup.
	if _, digest, pinned := orchestration.SplitImageReference(ref); pinned {
		if err := orchestration.ValidateImageDigest(digest); err != nil {
			return "", NewImageError(ref, "", err)
		}
		return digest, nil
	}

	if cached, ok := m.digestCache.Load(ref); ok {
		return cached.(string), nil
	}

	m.logger.Debug("resolving image digest", "ref", ref)

	if m.podman == nil {
		return "", NewImageError(ref, "", ErrPodmanNotAvailable)
	}

	image, err := m.podman.InspectImage(ctx, ref)
	if err != nil {
		return "", NewImageError(ref, "", err)
	}
	if image == nil || image.Digest == "" {
		return "", NewImageError(ref, "", &orchestration.ImageDigestUnresolvedError{
			Image: ref,
			Cause: ErrInvalidImage,
		})
	}
	if err := orchestration.ValidateImageDigest(image.Digest); err != nil {
		return "", NewImageError(ref, "", &orchestration.ImageDigestUnresolvedError{
			Image: ref,
			Cause: err,
		})
	}

	m.digestCache.Store(ref, image.Digest)

	return image.Digest, nil
}

// ListImages returns all available images.
func (m *ImageManager) ListImages(ctx context.Context) ([]ImageInfoResult, error) {
	if m.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	if m.podman == nil {
		return nil, ErrPodmanNotAvailable
	}

	podmanImages, err := m.podman.ListImages(ctx)
	if err != nil {
		return nil, NewImageError("", "", err)
	}

	results := make([]ImageInfoResult, 0, len(podmanImages))
	for _, img := range podmanImages {
		result := ImageInfoResult{
			ID:           img.ID,
			Names:        img.Names,
			Digest:       img.Digest,
			Size:         img.Size,
			Created:      img.Created,
			Labels:       img.Labels,
			Architecture: img.Architecture,
			OS:           img.OS,
		}
		results = append(results, result)
	}

	return results, nil
}

// InspectImage returns detailed information about an image.
func (m *ImageManager) InspectImage(ctx context.Context, ref string) (*ImageInfoResult, error) {
	if m.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	if ref == "" {
		return nil, ErrInvalidImage
	}

	if m.podman == nil {
		return nil, ErrPodmanNotAvailable
	}

	img, err := m.podman.InspectImage(ctx, ref)
	if err != nil {
		return nil, NewImageError(ref, "", ErrImageNotFound)
	}

	result := &ImageInfoResult{
		ID:           img.ID,
		Names:        img.Names,
		Digest:       img.Digest,
		Size:         img.Size,
		Created:      img.Created,
		Labels:       img.Labels,
		Architecture: img.Architecture,
		OS:           img.OS,
	}

	return result, nil
}

// RemoveImage removes an image from local storage.
func (m *ImageManager) RemoveImage(ctx context.Context, ref string, force bool) error {
	if m.closed.Load() {
		return ErrOrchestratorClosed
	}

	if ref == "" {
		return ErrInvalidImage
	}

	m.logger.Info("removing image", "ref", ref, "force", force)

	// Clear caches
	m.verificationCache.Delete(ref)
	m.digestCache.Delete(ref)

	// Note: Podman backend doesn't expose RemoveImage in our interface
	// This would need to be added if image removal is required

	return nil
}

// ClearCache clears all cached verification results and digests.
func (m *ImageManager) ClearCache() {
	m.verificationCache.Range(func(key, value interface{}) bool {
		m.verificationCache.Delete(key)
		return true
	})
	m.digestCache.Range(func(key, value interface{}) bool {
		m.digestCache.Delete(key)
		return true
	})
}

// Close closes the image manager and releases resources.
func (m *ImageManager) Close() error {
	if m.closed.Load() {
		return nil
	}
	m.closed.Store(true)
	m.ClearCache()
	return nil
}

// getVerificationFromCache retrieves a verification result from the cache.
func (m *ImageManager) getVerificationFromCache(ref string) (*ImageVerification, bool) {
	value, ok := m.verificationCache.Load(ref)
	if !ok {
		return nil, false
	}

	entry := value.(*verificationCacheEntry)
	if m.now().After(entry.expiresAt) {
		m.verificationCache.Delete(ref)
		return nil, false
	}

	return entry.result, true
}

// cacheVerification stores a verification result in the cache.
func (m *ImageManager) cacheVerification(ref string, result *ImageVerification) {
	entry := &verificationCacheEntry{
		result:    result,
		expiresAt: m.now().Add(m.config.CacheTTL),
	}
	m.verificationCache.Store(ref, entry)

	// Evict old entries if cache is full
	m.evictOldEntries()
}

// evictOldEntries removes expired cache entries.
func (m *ImageManager) evictOldEntries() {
	now := m.now()
	count := 0

	m.verificationCache.Range(func(key, value interface{}) bool {
		entry := value.(*verificationCacheEntry)
		if now.After(entry.expiresAt) {
			m.verificationCache.Delete(key)
		} else {
			count++
		}
		return count < m.config.CacheSize
	})
}

// ImageInfoResult contains information about a container image.
type ImageInfoResult struct {
	// ID is the image ID.
	ID string `json:"id"`

	// Names are the image names/tags.
	Names []string `json:"names"`

	// Digest is the image digest.
	Digest string `json:"digest"`

	// Size is the image size in bytes.
	Size int64 `json:"size"`

	// Created is when the image was created.
	Created time.Time `json:"created"`

	// Labels are image labels.
	Labels map[string]string `json:"labels"`

	// Architecture is the image architecture.
	Architecture string `json:"architecture"`

	// OS is the image operating system.
	OS string `json:"os"`
}

// parseRegistry extracts the registry from an image reference.
func parseRegistry(ref string) string {
	// Handle digest references
	ref = strings.Split(ref, "@")[0]

	// Handle tag references
	parts := strings.Split(ref, ":")
	if len(parts) > 1 && !strings.Contains(parts[len(parts)-1], "/") {
		ref = strings.Join(parts[:len(parts)-1], ":")
	}

	// Split by /
	pathParts := strings.Split(ref, "/")
	if len(pathParts) == 1 {
		// No registry specified, default to docker.io
		return "docker.io"
	}

	// Check if first part looks like a registry (has . or :)
	first := pathParts[0]
	if strings.Contains(first, ".") || strings.Contains(first, ":") {
		return first
	}

	// Docker Hub with user prefix
	return "docker.io"
}

// isRegistryAllowed checks if a registry is in the allowed list.
func isRegistryAllowed(registry string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}

	registry = strings.ToLower(registry)
	for _, a := range allowed {
		if strings.ToLower(a) == registry {
			return true
		}
		// Support wildcard matching
		if strings.HasPrefix(a, "*.") {
			suffix := strings.TrimPrefix(a, "*")
			if strings.HasSuffix(registry, suffix) {
				return true
			}
		}
	}
	return false
}

// ParseImageReference parses an image reference into its components.
func ParseImageReference(ref string) *ImageReference {
	result := &ImageReference{
		Raw: ref,
	}

	// Extract digest
	if idx := strings.Index(ref, "@"); idx != -1 {
		result.Digest = ref[idx+1:]
		ref = ref[:idx]
	}

	// Extract tag
	if idx := strings.LastIndex(ref, ":"); idx != -1 {
		// Make sure this isn't a port number
		afterColon := ref[idx+1:]
		if !strings.Contains(afterColon, "/") {
			result.Tag = afterColon
			ref = ref[:idx]
		}
	}

	// Default tag
	if result.Tag == "" && result.Digest == "" {
		result.Tag = "latest"
	}

	// Parse registry and repository
	parts := strings.Split(ref, "/")
	switch {
	case len(parts) == 1:
		result.Registry = "docker.io"
		result.Repository = "library/" + parts[0]
		result.Name = parts[0]
	case len(parts) == 2:
		if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") {
			result.Registry = parts[0]
			result.Repository = parts[1]
			result.Name = parts[1]
		} else {
			result.Registry = "docker.io"
			result.Repository = strings.Join(parts, "/")
			result.Name = parts[1]
		}
	default:
		result.Registry = parts[0]
		result.Repository = strings.Join(parts[1:], "/")
		result.Name = parts[len(parts)-1]
	}

	return result
}

// ImageReference represents a parsed image reference.
type ImageReference struct {
	// Raw is the original reference string.
	Raw string `json:"raw"`

	// Registry is the registry host.
	Registry string `json:"registry"`

	// Repository is the full repository path.
	Repository string `json:"repository"`

	// Name is the image name without registry or tag.
	Name string `json:"name"`

	// Tag is the image tag.
	Tag string `json:"tag"`

	// Digest is the image digest.
	Digest string `json:"digest"`
}

// String returns the canonical image reference string.
func (r *ImageReference) String() string {
	var sb strings.Builder

	if r.Registry != "" && r.Registry != "docker.io" {
		sb.WriteString(r.Registry)
		sb.WriteString("/")
	}

	sb.WriteString(r.Repository)

	if r.Digest != "" {
		sb.WriteString("@")
		sb.WriteString(r.Digest)
	} else if r.Tag != "" {
		sb.WriteString(":")
		sb.WriteString(r.Tag)
	}

	return sb.String()
}

// FullReference returns the fully qualified image reference.
func (r *ImageReference) FullReference() string {
	var sb strings.Builder

	sb.WriteString(r.Registry)
	sb.WriteString("/")
	sb.WriteString(r.Repository)

	if r.Digest != "" {
		sb.WriteString("@")
		sb.WriteString(r.Digest)
	} else if r.Tag != "" {
		sb.WriteString(":")
		sb.WriteString(r.Tag)
	}

	return sb.String()
}
