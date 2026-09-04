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
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Mock KMS client for testing
type mockKMSClient struct {
	mu      sync.RWMutex
	keys    map[string]*KeyInfo
	keyData map[string][]byte // Simulated key material
	genErr  error
	getErr  error
	encErr  error
	decErr  error
}

func newMockKMSClient() *mockKMSClient {
	return &mockKMSClient{
		keys:    make(map[string]*KeyInfo),
		keyData: make(map[string][]byte),
	}
}

func (m *mockKMSClient) GenerateKey(ctx context.Context, name, algorithm string, usage []string) (string, error) {
	if m.genErr != nil {
		return "", m.genErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	keyID := "key-" + name
	m.keys[keyID] = &KeyInfo{
		KeyID:     keyID,
		Name:      name,
		Algorithm: algorithm,
		Version:   1,
		Usage:     usage,
		CreatedAt: time.Now().UTC(),
	}
	// Generate simulated key material
	m.keyData[keyID] = make([]byte, 32)
	for i := range m.keyData[keyID] {
		m.keyData[keyID][i] = byte(i)
	}
	return keyID, nil
}

func (m *mockKMSClient) GetKey(ctx context.Context, keyID string) (*KeyInfo, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	if info, ok := m.keys[keyID]; ok {
		return info, nil
	}
	return nil, ErrKeyNotFound{KeyID: keyID}
}

func (m *mockKMSClient) Encrypt(ctx context.Context, keyID string, plaintext, aad []byte) ([]byte, int, error) {
	if m.encErr != nil {
		return nil, 0, m.encErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Simple XOR "encryption" for testing
	keyMaterial, ok := m.keyData[keyID]
	if !ok {
		return nil, 0, ErrKeyNotFound{KeyID: keyID}
	}

	ciphertext := make([]byte, len(plaintext))
	for i, b := range plaintext {
		ciphertext[i] = b ^ keyMaterial[i%len(keyMaterial)]
	}
	return ciphertext, 1, nil
}

func (m *mockKMSClient) Decrypt(ctx context.Context, keyID string, ciphertext, aad []byte) ([]byte, error) {
	if m.decErr != nil {
		return nil, m.decErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Simple XOR "decryption" for testing (same as encrypt for XOR)
	keyMaterial, ok := m.keyData[keyID]
	if !ok {
		return nil, ErrKeyNotFound{KeyID: keyID}
	}

	plaintext := make([]byte, len(ciphertext))
	for i, b := range ciphertext {
		plaintext[i] = b ^ keyMaterial[i%len(keyMaterial)]
	}
	return plaintext, nil
}

// Helper to create test image
func createTestImage(t *testing.T) *Image {
	t.Helper()
	return &Image{
		Manifest: &ImageManifest{
			SchemaVersion: 2,
			MediaType:     "application/vnd.oci.image.manifest.v1+json",
			Config: Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    "sha256:config123",
				Size:      1024,
			},
			Layers: []Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
					Digest:    "sha256:layer1",
					Size:      4096,
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
					Digest:    "sha256:layer2",
					Size:      8192,
				},
			},
		},
		Config: []byte(`{"architecture":"amd64"}`),
		Layers: []Layer{
			{
				Digest:    "sha256:layer1",
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
				Size:      4096,
				Content:   []byte("layer 1 content - this is compressed tar data"),
			},
			{
				Digest:    "sha256:layer2",
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
				Size:      8192,
				Content:   []byte("layer 2 content - more compressed tar data here"),
			},
		},
	}
}

// Tests for NewImageEncryptor

func TestNewImageEncryptor_Success(t *testing.T) {
	kms := newMockKMSClient()

	encryptor, err := NewImageEncryptor(kms)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if encryptor == nil {
		t.Fatal("expected encryptor to be non-nil")
	}
	if encryptor.keyNamespace != "container-images" {
		t.Errorf("expected default namespace 'container-images', got %s", encryptor.keyNamespace)
	}
}

func TestNewImageEncryptor_WithOptions(t *testing.T) {
	kms := newMockKMSClient()

	encryptor, err := NewImageEncryptor(kms, WithKeyNamespace("custom-namespace"))
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if encryptor.keyNamespace != "custom-namespace" {
		t.Errorf("expected namespace 'custom-namespace', got %s", encryptor.keyNamespace)
	}
}

func TestNewImageEncryptor_NilKMS(t *testing.T) {
	_, err := NewImageEncryptor(nil)
	if err == nil {
		t.Fatal("expected error for nil KMS")
	}
	var nilErr ErrNilClient
	if !errors.As(err, &nilErr) {
		t.Errorf("expected ErrNilClient, got %T", err)
	}
}

// Tests for EncryptImage

func TestEncryptImage_Success(t *testing.T) {
	kms := newMockKMSClient()
	// Pre-create the key
	_, _ = kms.GenerateKey(context.Background(), "container-images/test-key", DefaultKeyAlgorithm, []string{"encrypt", "decrypt"})

	encryptor, _ := NewImageEncryptor(kms)
	image := createTestImage(t)

	ctx := context.Background()
	encrypted, err := encryptor.EncryptImage(ctx, image, "test-key")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if encrypted == nil {
		t.Fatal("expected encrypted image to be non-nil")
	}
	if len(encrypted.EncryptedLayers) != len(image.Layers) {
		t.Errorf("expected %d encrypted layers, got %d", len(image.Layers), len(encrypted.EncryptedLayers))
	}
	if encrypted.KeyID == "" {
		t.Error("expected non-empty key ID")
	}
	if encrypted.EncryptedAt.IsZero() {
		t.Error("expected non-zero encryption timestamp")
	}
}

func TestEncryptImage_NilContext(t *testing.T) {
	kms := newMockKMSClient()
	encryptor, _ := NewImageEncryptor(kms)
	image := createTestImage(t)

	_, err := encryptor.EncryptImage(nil, image, "test-key") //nolint:staticcheck // testing nil context handling
	if err == nil {
		t.Fatal("expected error for nil context")
	}
	var nilCtxErr ErrNilContext
	if !errors.As(err, &nilCtxErr) {
		t.Errorf("expected ErrNilContext, got %T", err)
	}
}

func TestEncryptImage_NilImage(t *testing.T) {
	kms := newMockKMSClient()
	encryptor, _ := NewImageEncryptor(kms)

	ctx := context.Background()
	_, err := encryptor.EncryptImage(ctx, nil, "test-key")
	if err == nil {
		t.Fatal("expected error for nil image")
	}
	var emptyErr ErrImageEmpty
	if !errors.As(err, &emptyErr) {
		t.Errorf("expected ErrImageEmpty, got %T", err)
	}
}

func TestEncryptImage_EmptyLayers(t *testing.T) {
	kms := newMockKMSClient()
	encryptor, _ := NewImageEncryptor(kms)

	image := &Image{
		Manifest: &ImageManifest{},
		Layers:   []Layer{}, // No layers
	}

	ctx := context.Background()
	_, err := encryptor.EncryptImage(ctx, image, "test-key")
	if err == nil {
		t.Fatal("expected error for empty layers")
	}
	var emptyErr ErrImageEmpty
	if !errors.As(err, &emptyErr) {
		t.Errorf("expected ErrImageEmpty, got %T", err)
	}
}

func TestEncryptImage_EmptyKeyID(t *testing.T) {
	kms := newMockKMSClient()
	encryptor, _ := NewImageEncryptor(kms)
	image := createTestImage(t)

	ctx := context.Background()
	_, err := encryptor.EncryptImage(ctx, image, "")
	if err == nil {
		t.Fatal("expected error for empty key ID")
	}
	var configErr ErrInvalidConfig
	if !errors.As(err, &configErr) {
		t.Errorf("expected ErrInvalidConfig, got %T", err)
	}
}

func TestEncryptImage_KeyCreationFailed(t *testing.T) {
	kms := newMockKMSClient()
	kms.genErr = errors.New("key generation failed")
	kms.getErr = ErrKeyNotFound{KeyID: "test-key"} // Force key creation attempt

	encryptor, _ := NewImageEncryptor(kms)
	image := createTestImage(t)

	ctx := context.Background()
	_, err := encryptor.EncryptImage(ctx, image, "test-key")
	if err == nil {
		t.Fatal("expected error for key creation failure")
	}
	var keyErr ErrKeyCreationFailed
	if !errors.As(err, &keyErr) {
		t.Errorf("expected ErrKeyCreationFailed, got %T", err)
	}
}

func TestEncryptImage_WrapFailed(t *testing.T) {
	kms := newMockKMSClient()
	_, _ = kms.GenerateKey(context.Background(), "container-images/test-key", DefaultKeyAlgorithm, []string{"encrypt"})
	kms.encErr = errors.New("wrap failed")

	encryptor, _ := NewImageEncryptor(kms)
	image := createTestImage(t)

	ctx := context.Background()
	_, err := encryptor.EncryptImage(ctx, image, "test-key")
	if err == nil {
		t.Fatal("expected error for wrap failure")
	}
	var encErr ErrEncryptionFailed
	if !errors.As(err, &encErr) {
		t.Errorf("expected ErrEncryptionFailed, got %T", err)
	}
}

// Tests for DecryptImage

func TestDecryptImage_Success(t *testing.T) {
	kms := newMockKMSClient()
	_, _ = kms.GenerateKey(context.Background(), "container-images/test-key", DefaultKeyAlgorithm, []string{"encrypt", "decrypt"})

	encryptor, _ := NewImageEncryptor(kms)
	originalImage := createTestImage(t)

	ctx := context.Background()

	// Encrypt
	encrypted, err := encryptor.EncryptImage(ctx, originalImage, "test-key")
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Decrypt
	decrypted, err := encryptor.DecryptImage(ctx, encrypted)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if decrypted == nil {
		t.Fatal("expected decrypted image to be non-nil")
	}

	// Verify layers match
	if len(decrypted.Layers) != len(originalImage.Layers) {
		t.Errorf("expected %d layers, got %d", len(originalImage.Layers), len(decrypted.Layers))
	}

	for i, layer := range decrypted.Layers {
		if layer.Digest != originalImage.Layers[i].Digest {
			t.Errorf("layer %d digest mismatch", i)
		}
		if !bytes.Equal(layer.Content, originalImage.Layers[i].Content) {
			t.Errorf("layer %d content mismatch", i)
		}
	}
}

func TestDecryptImage_NilContext(t *testing.T) {
	kms := newMockKMSClient()
	encryptor, _ := NewImageEncryptor(kms)

	encrypted := &EncryptedImage{
		EncryptedLayers: []EncryptedLayer{{Digest: "test"}},
	}

	_, err := encryptor.DecryptImage(nil, encrypted) //nolint:staticcheck // testing nil context handling
	if err == nil {
		t.Fatal("expected error for nil context")
	}
	var nilCtxErr ErrNilContext
	if !errors.As(err, &nilCtxErr) {
		t.Errorf("expected ErrNilContext, got %T", err)
	}
}

func TestDecryptImage_NilEncryptedImage(t *testing.T) {
	kms := newMockKMSClient()
	encryptor, _ := NewImageEncryptor(kms)

	ctx := context.Background()
	_, err := encryptor.DecryptImage(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil encrypted image")
	}
	var emptyErr ErrImageEmpty
	if !errors.As(err, &emptyErr) {
		t.Errorf("expected ErrImageEmpty, got %T", err)
	}
}

func TestDecryptImage_EmptyLayers(t *testing.T) {
	kms := newMockKMSClient()
	encryptor, _ := NewImageEncryptor(kms)

	encrypted := &EncryptedImage{
		EncryptedLayers: []EncryptedLayer{},
	}

	ctx := context.Background()
	_, err := encryptor.DecryptImage(ctx, encrypted)
	if err == nil {
		t.Fatal("expected error for empty layers")
	}
	var emptyErr ErrImageEmpty
	if !errors.As(err, &emptyErr) {
		t.Errorf("expected ErrImageEmpty, got %T", err)
	}
}

func TestDecryptImage_UnwrapFailed(t *testing.T) {
	kms := newMockKMSClient()
	_, _ = kms.GenerateKey(context.Background(), "container-images/test-key", DefaultKeyAlgorithm, []string{"encrypt", "decrypt"})

	encryptor, _ := NewImageEncryptor(kms)
	originalImage := createTestImage(t)

	ctx := context.Background()

	// Encrypt
	encrypted, err := encryptor.EncryptImage(ctx, originalImage, "test-key")
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Set decryption error
	kms.decErr = errors.New("unwrap failed")

	// Decrypt should fail
	_, err = encryptor.DecryptImage(ctx, encrypted)
	if err == nil {
		t.Fatal("expected error for unwrap failure")
	}
	var decErr ErrDecryptionFailed
	if !errors.As(err, &decErr) {
		t.Errorf("expected ErrDecryptionFailed, got %T", err)
	}
}

// Tests for empty layer handling

func TestEncryptDecrypt_EmptyLayer(t *testing.T) {
	kms := newMockKMSClient()
	_, _ = kms.GenerateKey(context.Background(), "container-images/test-key", DefaultKeyAlgorithm, []string{"encrypt", "decrypt"})

	encryptor, _ := NewImageEncryptor(kms)

	image := &Image{
		Manifest: &ImageManifest{SchemaVersion: 2},
		Layers: []Layer{
			{
				Digest:    "sha256:empty",
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
				Size:      0,
				Content:   nil, // Empty content
			},
		},
	}

	ctx := context.Background()

	// Encrypt
	encrypted, err := encryptor.EncryptImage(ctx, image, "test-key")
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Encrypted layer should have nil content but metadata
	if encrypted.EncryptedLayers[0].Encrypted != nil {
		t.Error("expected nil encrypted content for empty layer")
	}

	// Decrypt
	decrypted, err := encryptor.DecryptImage(ctx, encrypted)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	// Decrypted layer should have nil content
	if decrypted.Layers[0].Content != nil {
		t.Error("expected nil content for empty layer")
	}
}

// Tests for EncryptedImageMetadata

func TestEncryptedImageMetadata_Success(t *testing.T) {
	kms := newMockKMSClient()
	_, _ = kms.GenerateKey(context.Background(), "container-images/test-key", DefaultKeyAlgorithm, []string{"encrypt", "decrypt"})

	encryptor, _ := NewImageEncryptor(kms)
	image := createTestImage(t)

	ctx := context.Background()
	encrypted, _ := encryptor.EncryptImage(ctx, image, "test-key")

	metadata, err := encryptor.EncryptedImageMetadata(encrypted)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(metadata) == 0 {
		t.Error("expected non-empty metadata")
	}

	// Metadata should not contain encrypted content
	if bytes.Contains(metadata, encrypted.EncryptedLayers[0].Encrypted) {
		t.Error("metadata should not contain encrypted layer content")
	}
}

// Tests for encryption helper functions

func TestGenerateDEK(t *testing.T) {
	dek1, err := generateDEK()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(dek1) != DEKSize {
		t.Errorf("expected DEK size %d, got %d", DEKSize, len(dek1))
	}

	dek2, _ := generateDEK()
	if bytes.Equal(dek1, dek2) {
		t.Error("expected unique DEKs")
	}
}

func TestEncryptDecryptContent(t *testing.T) {
	plaintext := []byte("test content to encrypt and decrypt")

	dek, err := generateDEK()
	if err != nil {
		t.Fatalf("failed to generate DEK: %v", err)
	}

	// Encrypt
	ciphertext, err := encryptContent(plaintext, dek)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}
	// The nonce is inside the blob now, so its presence is asserted through
	// the framing rather than through a returned value.
	if len(ciphertext) != NonceSize+len(plaintext)+TagSize {
		t.Errorf("expected nonce+plaintext+tag = %d bytes, got %d",
			NonceSize+len(plaintext)+TagSize, len(ciphertext))
	}

	// Decrypt
	decrypted, err := decryptContent(ciphertext, dek)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted content should match original plaintext")
	}
}

func TestEncryptContent_InvalidKey(t *testing.T) {
	plaintext := []byte("test content")
	invalidKey := []byte("too-short") // AES requires 16, 24, or 32 byte key

	_, err := encryptContent(plaintext, invalidKey)
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
}

func TestDecryptContent_InvalidKey(t *testing.T) {
	// First encrypt with valid key
	plaintext := []byte("test content")
	validKey, _ := generateDEK()
	ciphertext, _ := encryptContent(plaintext, validKey)

	// Try to decrypt with invalid key
	invalidKey, _ := generateDEK() // Different key
	_, err := decryptContent(ciphertext, invalidKey)
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
}

func TestDecryptContent_TamperedCiphertext(t *testing.T) {
	plaintext := []byte("test content")
	dek, _ := generateDEK()
	ciphertext, _ := encryptContent(plaintext, dek)

	// Byte 0 is inside the nonce prefix now, so this also covers a tampered
	// nonce — which used to be a separate field nothing authenticated.
	ciphertext[0] ^= 0xFF

	_, err := decryptContent(ciphertext, dek)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

// Tests for stripEncryptedSuffix

func TestStripEncryptedSuffix(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "application/vnd.oci.image.layer.v1.tar+gzip+encrypted",
			expected: "application/vnd.oci.image.layer.v1.tar+gzip",
		},
		{
			input:    "application/vnd.oci.image.layer.v1.tar+encrypted",
			expected: "application/vnd.oci.image.layer.v1.tar",
		},
		{
			input:    "application/vnd.oci.image.layer.v1.tar+gzip",
			expected: "application/vnd.oci.image.layer.v1.tar+gzip",
		},
		{
			input:    "+encrypted",
			expected: "+encrypted", // Too short to strip
		},
		{
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := stripEncryptedSuffix(tt.input)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// Benchmark tests

func BenchmarkEncryptContent(b *testing.B) {
	plaintext := make([]byte, 1024*1024) // 1MB
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	dek, _ := generateDEK()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encryptContent(plaintext, dek)
	}
}

func BenchmarkDecryptContent(b *testing.B) {
	plaintext := make([]byte, 1024*1024) // 1MB
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	dek, _ := generateDEK()
	ciphertext, _ := encryptContent(plaintext, dek)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = decryptContent(ciphertext, dek)
	}
}
