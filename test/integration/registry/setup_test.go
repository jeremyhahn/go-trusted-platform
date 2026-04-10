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

//go:build integration

// Package registry provides integration tests for the trusted registry.
// These tests verify registry lifecycle, attestation-based access control,
// and image encryption workflows.
//
// Run tests via:
//
//	make integration-test-registry
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// Test Timeouts
// =============================================================================

const (
	// DefaultTestTimeout is the default timeout for integration tests.
	DefaultTestTimeout = 2 * time.Minute

	// LongTestTimeout is for tests that may take longer (large images).
	LongTestTimeout = 5 * time.Minute

	// ShortTestTimeout is for quick operations.
	ShortTestTimeout = 30 * time.Second
)

// =============================================================================
// Mock Registry Backend
// =============================================================================

// MockRegistryBackend provides a mock implementation of a registry backend
// for testing purposes.
type MockRegistryBackend struct {
	mu                sync.RWMutex
	images            map[string]*StoredImage
	sessions          map[string]*MockSession
	pushCalls         int32
	pullCalls         int32
	deleteCalls       int32
	shouldFail        bool
	failError         error
	attestationNeeded bool
	encryptionNeeded  bool
}

// StoredImage represents an image stored in the mock registry.
type StoredImage struct {
	Reference       string
	Digest          string
	Manifest        *ImageManifest
	Config          []byte
	Layers          []LayerData
	Encrypted       bool
	EncryptionKeyID string
	Signed          bool
	SigningKeyID    string
	Annotations     map[string]string
	PushedAt        time.Time
	PushedBy        string
}

// MockSession represents a client session in the mock registry.
type MockSession struct {
	ClientID    string
	SessionID   string
	AIK         []byte
	PCRs        map[int][]byte
	ValidUntil  time.Time
	Permissions []string
	CreatedAt   time.Time
	Verified    bool
}

// NewMockRegistryBackend creates a new mock registry backend.
func NewMockRegistryBackend() *MockRegistryBackend {
	return &MockRegistryBackend{
		images:   make(map[string]*StoredImage),
		sessions: make(map[string]*MockSession),
	}
}

// Push stores an image in the mock registry.
func (m *MockRegistryBackend) Push(ctx context.Context, ref string, opts PushOptions) (*PushResult, error) {
	atomic.AddInt32(&m.pushCalls, 1)

	if m.shouldFail {
		return nil, m.failError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if image exists and overwrite is not allowed
	if _, exists := m.images[ref]; exists && !opts.AllowOverwrite {
		return nil, fmt.Errorf("image already exists: %s", ref)
	}

	// Compute digest from layers
	digest := m.computeDigest(opts.Layers, opts.Config)

	// Compute total size
	var totalSize int64
	for _, layer := range opts.Layers {
		totalSize += int64(len(layer.Content))
	}
	totalSize += int64(len(opts.Config))

	// Create stored image
	storedImage := &StoredImage{
		Reference:       ref,
		Digest:          digest,
		Config:          opts.Config,
		Layers:          opts.Layers,
		Encrypted:       opts.Encrypt,
		EncryptionKeyID: opts.KeyID,
		Signed:          opts.SignImage,
		SigningKeyID:    opts.SigningKeyID,
		Annotations:     opts.Annotations,
		PushedAt:        time.Now(),
	}

	// Build manifest
	storedImage.Manifest = m.buildManifest(ref, digest, totalSize, opts.Layers, opts.Config, opts.Annotations)
	storedImage.Manifest.Encrypted = opts.Encrypt
	storedImage.Manifest.Signed = opts.SignImage

	m.images[ref] = storedImage

	return &PushResult{
		Reference: ref,
		Digest:    digest,
		Size:      totalSize,
		Encrypted: opts.Encrypt,
		Signed:    opts.SignImage,
		PushedAt:  storedImage.PushedAt,
	}, nil
}

// Pull retrieves an image from the mock registry.
func (m *MockRegistryBackend) Pull(ctx context.Context, ref string, opts PullOptions) (*PullResult, error) {
	atomic.AddInt32(&m.pullCalls, 1)

	if m.shouldFail {
		return nil, m.failError
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	storedImage, exists := m.images[ref]
	if !exists {
		return nil, ErrImageNotFound{Reference: ref}
	}

	return &PullResult{
		Reference:      ref,
		Manifest:       storedImage.Manifest,
		Config:         storedImage.Config,
		Layers:         storedImage.Layers,
		Encrypted:      storedImage.Encrypted,
		Signed:         storedImage.Signed,
		SignatureValid: storedImage.Signed, // Mock always returns valid for signed images
		PulledAt:       time.Now(),
	}, nil
}

// Delete removes an image from the mock registry.
func (m *MockRegistryBackend) Delete(ctx context.Context, ref string, opts DeleteOptions) (*DeleteResult, error) {
	atomic.AddInt32(&m.deleteCalls, 1)

	if m.shouldFail {
		return nil, m.failError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	storedImage, exists := m.images[ref]
	if !exists {
		return nil, ErrImageNotFound{Reference: ref}
	}

	layersDeleted := 0
	if opts.DeleteLayers {
		layersDeleted = len(storedImage.Layers)
	}

	delete(m.images, ref)

	return &DeleteResult{
		Reference:     ref,
		Digest:        storedImage.Digest,
		DeletedAt:     time.Now(),
		LayersDeleted: layersDeleted,
	}, nil
}

// Inspect returns details about an image.
func (m *MockRegistryBackend) Inspect(ctx context.Context, ref string) (*InspectResult, error) {
	if m.shouldFail {
		return nil, m.failError
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	storedImage, exists := m.images[ref]
	if !exists {
		return nil, ErrImageNotFound{Reference: ref}
	}

	var totalSize int64
	for _, layer := range storedImage.Layers {
		totalSize += int64(len(layer.Content))
	}

	return &InspectResult{
		Reference:       ref,
		Manifest:        storedImage.Manifest,
		Config:          parseImageConfig(storedImage.Config),
		TotalSize:       totalSize,
		LayerCount:      len(storedImage.Layers),
		Encrypted:       storedImage.Encrypted,
		EncryptionKeyID: storedImage.EncryptionKeyID,
		Signed:          storedImage.Signed,
		SigningKeyID:    storedImage.SigningKeyID,
		SignatureValid:  storedImage.Signed,
	}, nil
}

// List returns all images in the mock registry.
func (m *MockRegistryBackend) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	if m.shouldFail {
		return nil, m.failError
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	images := make([]ImageManifest, 0, len(m.images))
	for _, img := range m.images {
		// Apply filters
		if opts.Repository != "" && img.Reference != opts.Repository {
			continue
		}
		if !opts.IncludeEncrypted && img.Encrypted {
			continue
		}

		images = append(images, *img.Manifest)

		// Apply limit
		if opts.Limit > 0 && len(images) >= opts.Limit {
			break
		}
	}

	return &ListResult{
		Images:     images,
		TotalCount: len(images),
		HasMore:    opts.Limit > 0 && len(m.images) > opts.Limit,
	}, nil
}

// VerifyClient verifies client attestation.
func (m *MockRegistryBackend) VerifyClient(ctx context.Context, opts VerifyClientOptions) (*VerifyClientResult, error) {
	if m.shouldFail {
		return nil, m.failError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Simple mock verification - accept all clients with valid looking data
	if len(opts.AIK) == 0 || len(opts.Quote) == 0 {
		return &VerifyClientResult{
			Verified: false,
			ClientID: opts.ClientID,
			Reason:   "missing attestation data",
		}, nil
	}

	sessionID := generateMockSessionID()
	validUntil := time.Now().Add(1 * time.Hour)

	session := &MockSession{
		ClientID:    opts.ClientID,
		SessionID:   sessionID,
		AIK:         opts.AIK,
		PCRs:        opts.PCRs,
		ValidUntil:  validUntil,
		Permissions: []string{"pull", "push", "delete"},
		CreatedAt:   time.Now(),
		Verified:    true,
	}

	m.sessions[opts.ClientID] = session

	return &VerifyClientResult{
		Verified:    true,
		ClientID:    opts.ClientID,
		SessionID:   sessionID,
		ValidUntil:  validUntil,
		Permissions: session.Permissions,
	}, nil
}

// GetSession returns a client session.
func (m *MockRegistryBackend) GetSession(ctx context.Context, clientID string) (*SessionResult, error) {
	if m.shouldFail {
		return nil, m.failError
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[clientID]
	if !exists {
		return nil, ErrSessionNotFound{ClientID: clientID}
	}

	return &SessionResult{
		ClientID:    session.ClientID,
		SessionID:   session.SessionID,
		AIK:         hex.EncodeToString(session.AIK[:16]), // First 16 bytes as fingerprint
		PCRs:        session.PCRs,
		ValidUntil:  session.ValidUntil,
		Permissions: session.Permissions,
		CreatedAt:   session.CreatedAt,
	}, nil
}

// InvalidateSession removes a client session.
func (m *MockRegistryBackend) InvalidateSession(ctx context.Context, clientID string) error {
	if m.shouldFail {
		return m.failError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[clientID]; !exists {
		return ErrSessionNotFound{ClientID: clientID}
	}

	delete(m.sessions, clientID)
	return nil
}

// EncryptImage encrypts an image.
func (m *MockRegistryBackend) EncryptImage(ctx context.Context, ref string, keyID string) (*EncryptImageResult, error) {
	if m.shouldFail {
		return nil, m.failError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	storedImage, exists := m.images[ref]
	if !exists {
		return nil, ErrImageNotFound{Reference: ref}
	}

	storedImage.Encrypted = true
	storedImage.EncryptionKeyID = keyID
	storedImage.Manifest.Encrypted = true

	return &EncryptImageResult{
		Reference:       ref,
		KeyID:           keyID,
		EncryptedAt:     time.Now(),
		LayersEncrypted: len(storedImage.Layers),
	}, nil
}

// DecryptImage decrypts an image.
func (m *MockRegistryBackend) DecryptImage(ctx context.Context, ref string) (*DecryptImageResult, error) {
	if m.shouldFail {
		return nil, m.failError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	storedImage, exists := m.images[ref]
	if !exists {
		return nil, ErrImageNotFound{Reference: ref}
	}

	keyID := storedImage.EncryptionKeyID
	storedImage.Encrypted = false
	storedImage.EncryptionKeyID = ""
	storedImage.Manifest.Encrypted = false

	return &DecryptImageResult{
		Reference:   ref,
		KeyID:       keyID,
		DecryptedAt: time.Now(),
		Manifest:    storedImage.Manifest,
		Layers:      storedImage.Layers,
	}, nil
}

// SetFailure configures the mock to fail with the given error.
func (m *MockRegistryBackend) SetFailure(err error) {
	m.shouldFail = true
	m.failError = err
}

// ClearFailure clears any configured failure.
func (m *MockRegistryBackend) ClearFailure() {
	m.shouldFail = false
	m.failError = nil
}

// GetPushCalls returns the number of Push calls.
func (m *MockRegistryBackend) GetPushCalls() int32 {
	return atomic.LoadInt32(&m.pushCalls)
}

// GetPullCalls returns the number of Pull calls.
func (m *MockRegistryBackend) GetPullCalls() int32 {
	return atomic.LoadInt32(&m.pullCalls)
}

// GetDeleteCalls returns the number of Delete calls.
func (m *MockRegistryBackend) GetDeleteCalls() int32 {
	return atomic.LoadInt32(&m.deleteCalls)
}

// Reset resets the mock state.
func (m *MockRegistryBackend) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.images = make(map[string]*StoredImage)
	m.sessions = make(map[string]*MockSession)
	atomic.StoreInt32(&m.pushCalls, 0)
	atomic.StoreInt32(&m.pullCalls, 0)
	atomic.StoreInt32(&m.deleteCalls, 0)
	m.shouldFail = false
	m.failError = nil
}

// GetImage returns a stored image for test verification.
func (m *MockRegistryBackend) GetImage(ref string) (*StoredImage, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	img, exists := m.images[ref]
	return img, exists
}

// computeDigest computes a digest for the given layers and config.
func (m *MockRegistryBackend) computeDigest(layers []LayerData, config []byte) string {
	h := sha256.New()
	for _, layer := range layers {
		h.Write(layer.Content)
	}
	h.Write(config)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// buildManifest creates a manifest for the stored image.
func (m *MockRegistryBackend) buildManifest(ref, digest string, size int64, layers []LayerData, config []byte, annotations map[string]string) *ImageManifest {
	layerDescriptors := make([]Descriptor, len(layers))
	for i, layer := range layers {
		h := sha256.Sum256(layer.Content)
		layerDescriptors[i] = Descriptor{
			MediaType:   layer.MediaType,
			Digest:      "sha256:" + hex.EncodeToString(h[:]),
			Size:        int64(len(layer.Content)),
			Annotations: layer.Annotations,
		}
	}

	configHash := sha256.Sum256(config)

	return &ImageManifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeImageManifest,
		Config: Descriptor{
			MediaType: MediaTypeImageConfig,
			Digest:    "sha256:" + hex.EncodeToString(configHash[:]),
			Size:      int64(len(config)),
		},
		Layers:      layerDescriptors,
		Annotations: annotations,
		Reference:   ref,
		Digest:      digest,
		Size:        size,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

// =============================================================================
// Mock Status Provider
// =============================================================================

// MockStatusProvider provides mock registry status information.
type MockStatusProvider struct {
	healthy            bool
	status             string
	version            string
	startTime          time.Time
	imageCount         int
	totalSize          int64
	activeConnections  int
	attestationEnabled bool
	encryptionEnabled  bool
	storageBackend     string
	storageStatus      string
}

// NewMockStatusProvider creates a new mock status provider.
func NewMockStatusProvider() *MockStatusProvider {
	return &MockStatusProvider{
		healthy:            true,
		status:             "running",
		version:            "1.0.0-test",
		startTime:          time.Now(),
		storageBackend:     "memory",
		storageStatus:      "healthy",
		attestationEnabled: true,
		encryptionEnabled:  true,
	}
}

// GetStatus returns the mock registry status.
func (m *MockStatusProvider) GetStatus() *StatusResult {
	return &StatusResult{
		Healthy:            m.healthy,
		Status:             m.status,
		Version:            m.version,
		Uptime:             time.Since(m.startTime),
		ImageCount:         m.imageCount,
		TotalSize:          m.totalSize,
		ActiveConnections:  m.activeConnections,
		AttestationEnabled: m.attestationEnabled,
		EncryptionEnabled:  m.encryptionEnabled,
		StorageBackend:     m.storageBackend,
		StorageStatus:      m.storageStatus,
	}
}

// SetHealthy sets the healthy status.
func (m *MockStatusProvider) SetHealthy(healthy bool) {
	m.healthy = healthy
	if healthy {
		m.status = "running"
	} else {
		m.status = "degraded"
	}
}

// =============================================================================
// Test Fixtures
// =============================================================================

// TestFixtures holds all mock components for testing.
type TestFixtures struct {
	Backend        *MockRegistryBackend
	StatusProvider *MockStatusProvider
}

// NewTestFixtures creates a new set of test fixtures.
func NewTestFixtures() *TestFixtures {
	return &TestFixtures{
		Backend:        NewMockRegistryBackend(),
		StatusProvider: NewMockStatusProvider(),
	}
}

// Reset resets all fixtures.
func (f *TestFixtures) Reset() {
	f.Backend.Reset()
}

// =============================================================================
// Test Helper Functions
// =============================================================================

// CreateTestImageWithLayers creates a test image with the specified number of layers.
func CreateTestImageWithLayers(t *testing.T, numLayers, layerSize int) ([]LayerData, []byte) {
	t.Helper()
	return GenerateTestImage(numLayers, layerSize)
}

// CreateTestImageWithAnnotations creates a test image with annotations.
func CreateTestImageWithAnnotations(t *testing.T, annotations map[string]string) ([]LayerData, []byte, map[string]string) {
	t.Helper()
	layers, config := GenerateTestImage(1, 1024)
	return layers, config, annotations
}

// AssertImageInRegistry asserts that an image exists in the registry.
func AssertImageInRegistry(t *testing.T, backend *MockRegistryBackend, ref string) {
	t.Helper()
	_, exists := backend.GetImage(ref)
	if !exists {
		t.Errorf("expected image %s to exist in registry", ref)
	}
}

// AssertImageNotInRegistry asserts that an image does not exist in the registry.
func AssertImageNotInRegistry(t *testing.T, backend *MockRegistryBackend, ref string) {
	t.Helper()
	_, exists := backend.GetImage(ref)
	if exists {
		t.Errorf("expected image %s to not exist in registry", ref)
	}
}

// AssertImageEncrypted asserts that an image is encrypted.
func AssertImageEncrypted(t *testing.T, backend *MockRegistryBackend, ref string, expectedKeyID string) {
	t.Helper()
	img, exists := backend.GetImage(ref)
	if !exists {
		t.Fatalf("image %s not found", ref)
	}
	if !img.Encrypted {
		t.Errorf("expected image %s to be encrypted", ref)
	}
	if img.EncryptionKeyID != expectedKeyID {
		t.Errorf("expected encryption key ID %s, got %s", expectedKeyID, img.EncryptionKeyID)
	}
}

// AssertImageSigned asserts that an image is signed.
func AssertImageSigned(t *testing.T, backend *MockRegistryBackend, ref string, expectedKeyID string) {
	t.Helper()
	img, exists := backend.GetImage(ref)
	if !exists {
		t.Fatalf("image %s not found", ref)
	}
	if !img.Signed {
		t.Errorf("expected image %s to be signed", ref)
	}
	if img.SigningKeyID != expectedKeyID {
		t.Errorf("expected signing key ID %s, got %s", expectedKeyID, img.SigningKeyID)
	}
}

// =============================================================================
// ID Generation
// =============================================================================

var mockSessionIDCounter int64

// generateMockSessionID generates a unique mock session ID.
func generateMockSessionID() string {
	id := atomic.AddInt64(&mockSessionIDCounter, 1)
	return fmt.Sprintf("session-%d-%d", time.Now().Unix(), id)
}

// =============================================================================
// Config Parsing
// =============================================================================

// parseImageConfig parses image config bytes into an ImageConfig struct.
// This is a simplified parser for mock testing.
func parseImageConfig(config []byte) *ImageConfig {
	// Return a default config for testing
	return &ImageConfig{
		Architecture: "amd64",
		OS:           "linux",
		Created:      time.Now(),
		Cmd:          []string{"/bin/sh"},
		Env:          []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		WorkingDir:   "/",
	}
}
