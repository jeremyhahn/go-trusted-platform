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

package image

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// RegistryClient defines the interface for interacting with container registries.
type RegistryClient interface {
	// PushSignature uploads a signature to the registry.
	PushSignature(ctx context.Context, ref *ImageReference, sig *ImageSignature) error

	// PullSignature retrieves a signature from the registry.
	PullSignature(ctx context.Context, ref *ImageReference) (*ImageSignature, error)

	// GetImageManifest retrieves an image manifest from the registry.
	GetImageManifest(ctx context.Context, ref *ImageReference) ([]byte, error)

	// GetImageDigest retrieves the digest of an image.
	GetImageDigest(ctx context.Context, ref *ImageReference) (string, error)

	// Close closes the registry client and releases resources.
	Close() error
}

// registryClient implements the RegistryClient interface.
type registryClient struct {
	httpClient *http.Client
	options    *RegistryOptions
	closed     atomic.Bool
}

// NewRegistryClient creates a new registry client.
func NewRegistryClient(opts *RegistryOptions) (*registryClient, error) {
	if opts == nil {
		opts = &RegistryOptions{}
	}

	// Default timeout
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}

	// Default retries
	if opts.MaxRetries == 0 {
		opts.MaxRetries = 3
	}

	// Default retry delay
	if opts.RetryDelay == 0 {
		opts.RetryDelay = time.Second
	}

	// Default user agent
	if opts.UserAgent == "" {
		opts.UserAgent = "go-trusted-platform/1.0"
	}

	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	if opts.CACertPool != nil {
		transport.TLSClientConfig.RootCAs = opts.CACertPool
	}

	httpClient := &http.Client{
		Timeout:   opts.Timeout,
		Transport: transport,
	}

	return &registryClient{
		httpClient: httpClient,
		options:    opts,
	}, nil
}

// PushSignature uploads a signature to the registry.
func (c *registryClient) PushSignature(ctx context.Context, ref *ImageReference, sig *ImageSignature) error {
	if c.closed.Load() {
		return ErrRegistryUnavailable{Reason: "client closed"}
	}

	if ref == nil {
		return ErrNilParameter{Parameter: "ref"}
	}

	if sig == nil {
		return ErrNilParameter{Parameter: "sig"}
	}

	// Serialize signature
	sigData, err := json.Marshal(sig)
	if err != nil {
		return ErrSigningFailed{ImageDigest: ref.Digest, Reason: "failed to serialize signature", Err: err}
	}

	// Create signature reference
	sigRef := &ImageReference{
		Registry:   ref.Registry,
		Repository: ref.Repository,
		Tag:        ref.SignatureTag(),
	}

	// Upload as OCI artifact
	url := c.buildURL(sigRef, "/v2/"+sigRef.Repository+"/manifests/"+sigRef.Tag)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(sigData))
	if err != nil {
		return ErrRegistryUnavailable{Registry: ref.Registry, Reason: "failed to create request", Err: err}
	}

	req.Header.Set("Content-Type", "application/vnd.dev.cosign.simplesigning.v1+json")
	c.setAuthHeader(req, ref.Registry)
	c.setUserAgent(req)

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return ErrRegistryUnavailable{Registry: ref.Registry, Reason: "request failed", Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return ErrRegistryAccessDenied{Registry: ref.Registry, Reason: "authentication failed"}
	}

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return ErrRegistryUnavailable{Registry: ref.Registry, Reason: "upload failed: " + string(body)}
	}

	return nil
}

// PullSignature retrieves a signature from the registry.
func (c *registryClient) PullSignature(ctx context.Context, ref *ImageReference) (*ImageSignature, error) {
	if c.closed.Load() {
		return nil, ErrRegistryUnavailable{Reason: "client closed"}
	}

	if ref == nil {
		return nil, ErrNilParameter{Parameter: "ref"}
	}

	// Create signature reference
	sigRef := &ImageReference{
		Registry:   ref.Registry,
		Repository: ref.Repository,
		Tag:        ref.SignatureTag(),
	}

	// Fetch signature artifact
	url := c.buildURL(sigRef, "/v2/"+sigRef.Repository+"/manifests/"+sigRef.Tag)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, ErrRegistryUnavailable{Registry: ref.Registry, Reason: "failed to create request", Err: err}
	}

	req.Header.Set("Accept", "application/vnd.dev.cosign.simplesigning.v1+json, application/vnd.oci.image.manifest.v1+json")
	c.setAuthHeader(req, ref.Registry)
	c.setUserAgent(req)

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return nil, ErrRegistryUnavailable{Registry: ref.Registry, Reason: "request failed", Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrSignatureNotFound{ImageDigest: ref.Digest}
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrRegistryAccessDenied{Registry: ref.Registry, Reason: "authentication failed"}
	}

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, ErrRegistryUnavailable{Registry: ref.Registry, Reason: "fetch failed: " + string(body)}
	}

	// Parse signature
	var sig ImageSignature
	if err := json.NewDecoder(resp.Body).Decode(&sig); err != nil {
		return nil, ErrInvalidSignature{Reason: "failed to parse signature", Err: err}
	}

	return &sig, nil
}

// GetImageManifest retrieves an image manifest from the registry.
func (c *registryClient) GetImageManifest(ctx context.Context, ref *ImageReference) ([]byte, error) {
	if c.closed.Load() {
		return nil, ErrRegistryUnavailable{Reason: "client closed"}
	}

	if ref == nil {
		return nil, ErrNilParameter{Parameter: "ref"}
	}

	// Determine reference (digest or tag)
	reference := ref.Digest
	if reference == "" {
		reference = ref.Tag
	}
	if reference == "" {
		reference = DefaultTag
	}

	url := c.buildURL(ref, "/v2/"+ref.Repository+"/manifests/"+reference)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, ErrRegistryUnavailable{Registry: ref.Registry, Reason: "failed to create request", Err: err}
	}

	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.index.v1+json",
	}, ", "))
	c.setAuthHeader(req, ref.Registry)
	c.setUserAgent(req)

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return nil, ErrRegistryUnavailable{Registry: ref.Registry, Reason: "request failed", Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrImageNotFound{Reference: ref.String()}
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrRegistryAccessDenied{Registry: ref.Registry, Reason: "authentication failed"}
	}

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, ErrRegistryUnavailable{Registry: ref.Registry, Reason: "fetch failed: " + string(body)}
	}

	return io.ReadAll(resp.Body)
}

// GetImageDigest retrieves the digest of an image.
func (c *registryClient) GetImageDigest(ctx context.Context, ref *ImageReference) (_ string, err error) {
	if c.closed.Load() {
		return "", ErrRegistryUnavailable{Reason: "client closed"}
	}

	if ref == nil {
		return "", ErrNilParameter{Parameter: "ref"}
	}

	// If digest is already set, return it
	if ref.Digest != "" {
		return ref.Digest, nil
	}

	// Determine reference
	reference := ref.Tag
	if reference == "" {
		reference = DefaultTag
	}

	url := c.buildURL(ref, "/v2/"+ref.Repository+"/manifests/"+reference)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", ErrRegistryUnavailable{Registry: ref.Registry, Reason: "failed to create request", Err: err}
	}

	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
	}, ", "))
	c.setAuthHeader(req, ref.Registry)
	c.setUserAgent(req)

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return "", ErrRegistryUnavailable{Registry: ref.Registry, Reason: "request failed", Err: err}
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
		return "", ErrImageNotFound{Reference: ref.String()}
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", ErrRegistryAccessDenied{Registry: ref.Registry, Reason: "authentication failed"}
	}

	if resp.StatusCode >= 400 {
		return "", ErrRegistryUnavailable{Registry: ref.Registry, Reason: "unexpected status: " + resp.Status}
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		digest = resp.Header.Get("OCI-Content-Digest")
	}

	if digest == "" {
		return "", ErrInvalidManifest{Reason: "no digest in response"}
	}

	return digest, nil
}

// Close closes the registry client.
func (c *registryClient) Close() error {
	c.closed.Store(true)
	c.httpClient.CloseIdleConnections()
	return nil
}

// buildURL builds the full URL for a registry request.
// HTTPS is always used — insecure HTTP connections are not permitted.
func (c *registryClient) buildURL(ref *ImageReference, path string) string {
	scheme := "https"

	registry := ref.Registry
	if registry == "" {
		registry = DefaultRegistry
	}

	// Handle docker.io special case
	if registry == "docker.io" {
		registry = "registry-1.docker.io"
	}

	return scheme + "://" + registry + path
}

// setAuthHeader sets the authorization header for a request.
func (c *registryClient) setAuthHeader(req *http.Request, registry string) {
	if c.options.Auth == nil {
		return
	}

	if c.options.Auth.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.options.Auth.Token)
		return
	}

	if c.options.Auth.Username != "" && c.options.Auth.Password != "" {
		auth := base64.StdEncoding.EncodeToString(
			[]byte(c.options.Auth.Username + ":" + c.options.Auth.Password),
		)
		req.Header.Set("Authorization", "Basic "+auth)
	}
}

// setUserAgent sets the user agent header.
func (c *registryClient) setUserAgent(req *http.Request) {
	req.Header.Set("User-Agent", c.options.UserAgent)
}

// doWithRetry performs a request with retry logic.
func (c *registryClient) doWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	var resp *http.Response
	attempt := 0
	retryCfg := &quicbaas.RetryConfig{
		MaxAttempts: c.options.MaxRetries + 1,
		Backoff:     &quicbaas.ConstantBackoff{Delay: c.options.RetryDelay},
		// Preserve pre-SDK behavior: transport errors and 5xx responses
		// are retryable; a failure to clone the request body aborts.
		RetryableFunc: func(err error) bool {
			var cloneErr ErrRequestClone
			return !errors.As(err, &cloneErr)
		},
	}
	err := quicbaas.RetryDo(ctx, retryCfg, func(ctx context.Context) error {
		if attempt > 0 {
			// Clone request for retry
			cloned, cloneErr := cloneRequest(ctx, req)
			if cloneErr != nil {
				return ErrRequestClone{Err: cloneErr}
			}
			req = cloned
		}
		attempt++

		r, doErr := c.httpClient.Do(req)
		if doErr != nil {
			return doErr
		}

		// Retry on 5xx errors
		if r.StatusCode >= 500 {
			retryErr := ErrRegistryUnavailable{Reason: "server error: " + r.Status}
			if cerr := r.Body.Close(); cerr != nil {
				retryErr = ErrRegistryUnavailable{Reason: "server error: " + r.Status + "; body close: " + cerr.Error()}
			}
			return retryErr
		}

		resp = r
		return nil
	})
	if err != nil {
		// Preserve pre-SDK behavior: cancellation surfaces as the raw
		// context error, and a clone failure surfaces as its cause.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		var cloneErr ErrRequestClone
		if errors.As(err, &cloneErr) {
			return nil, cloneErr.Err
		}
		return nil, err
	}
	return resp, nil
}

// cloneRequest creates a copy of the request with a new context.
func cloneRequest(ctx context.Context, req *http.Request) (*http.Request, error) {
	clone := req.Clone(ctx)
	if req.Body != nil {
		// Read and restore body
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body))
		clone.Body = io.NopCloser(bytes.NewReader(body))
	}
	return clone, nil
}

// SignatureCache provides caching for signature lookups.
type SignatureCache struct {
	cache sync.Map
	ttl   time.Duration
	now   func() time.Time // time.Now in production; tests replace it to advance time (#284)
}

// NewSignatureCache creates a new signature cache.
func NewSignatureCache(ttl time.Duration) *SignatureCache {
	return &SignatureCache{
		ttl: ttl,
		now: time.Now,
	}
}

// Get retrieves a cached signature.
func (c *SignatureCache) Get(key string) (*ImageSignature, bool) {
	value, ok := c.cache.Load(key)
	if !ok {
		return nil, false
	}

	entry, ok := value.(*CacheEntry)
	if !ok {
		return nil, false
	}

	if c.now().After(entry.ExpiresAt) {
		c.cache.Delete(key)
		return nil, false
	}

	sig, ok := entry.Value.(*ImageSignature)
	return sig, ok
}

// Set stores a signature in the cache.
func (c *SignatureCache) Set(key string, sig *ImageSignature) {
	now := c.now()
	entry := &CacheEntry{
		Key:       key,
		Value:     sig,
		ExpiresAt: now.Add(c.ttl),
		CreatedAt: now,
	}
	c.cache.Store(key, entry)
}

// Delete removes a signature from the cache.
func (c *SignatureCache) Delete(key string) {
	c.cache.Delete(key)
}

// Clear removes all entries from the cache.
func (c *SignatureCache) Clear() {
	c.cache.Range(func(key, value interface{}) bool {
		c.cache.Delete(key)
		return true
	})
}

// CachingRegistryClient wraps a RegistryClient with signature caching.
type CachingRegistryClient struct {
	client RegistryClient
	cache  *SignatureCache
}

// NewCachingRegistryClient creates a new caching registry client.
func NewCachingRegistryClient(client RegistryClient, cacheTTL time.Duration) *CachingRegistryClient {
	return &CachingRegistryClient{
		client: client,
		cache:  NewSignatureCache(cacheTTL),
	}
}

// PushSignature uploads a signature and invalidates the cache.
func (c *CachingRegistryClient) PushSignature(ctx context.Context, ref *ImageReference, sig *ImageSignature) error {
	err := c.client.PushSignature(ctx, ref, sig)
	if err == nil {
		// Cache the new signature
		c.cache.Set(ref.String(), sig)
	}
	return err
}

// PullSignature retrieves a signature, using cache if available.
func (c *CachingRegistryClient) PullSignature(ctx context.Context, ref *ImageReference) (*ImageSignature, error) {
	// Check cache first
	if sig, ok := c.cache.Get(ref.String()); ok {
		return sig, nil
	}

	// Fetch from registry
	sig, err := c.client.PullSignature(ctx, ref)
	if err != nil {
		return nil, err
	}

	// Cache the result
	c.cache.Set(ref.String(), sig)
	return sig, nil
}

// GetImageManifest retrieves an image manifest (not cached).
func (c *CachingRegistryClient) GetImageManifest(ctx context.Context, ref *ImageReference) ([]byte, error) {
	return c.client.GetImageManifest(ctx, ref)
}

// GetImageDigest retrieves an image digest (not cached).
func (c *CachingRegistryClient) GetImageDigest(ctx context.Context, ref *ImageReference) (string, error) {
	return c.client.GetImageDigest(ctx, ref)
}

// Close closes the underlying client.
func (c *CachingRegistryClient) Close() error {
	c.cache.Clear()
	return c.client.Close()
}

// InvalidateCache removes a cached signature.
func (c *CachingRegistryClient) InvalidateCache(ref *ImageReference) {
	c.cache.Delete(ref.String())
}
