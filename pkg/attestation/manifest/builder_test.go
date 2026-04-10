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

package manifest

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// mockTPMDevice is a mock TPM device for testing.
type mockTPMDevice struct {
	generateQuoteFunc  func(ctx context.Context, nonce []byte, pcrIndices []int, algorithm HashAlgorithm) ([]byte, []byte, error)
	readPCRFunc        func(ctx context.Context, pcr int, algorithm HashAlgorithm) ([]byte, error)
	getAKPublicKeyFunc func(ctx context.Context) ([]byte, error)
	signFunc           func(ctx context.Context, data []byte, algorithm HashAlgorithm) ([]byte, error)
	closeFunc          func() error
}

func (m *mockTPMDevice) GenerateQuote(ctx context.Context, nonce []byte, pcrIndices []int, algorithm HashAlgorithm) ([]byte, []byte, error) {
	if m.generateQuoteFunc != nil {
		return m.generateQuoteFunc(ctx, nonce, pcrIndices, algorithm)
	}
	return []byte("quote-data"), []byte("signature"), nil
}

func (m *mockTPMDevice) ReadPCR(ctx context.Context, pcr int, algorithm HashAlgorithm) ([]byte, error) {
	if m.readPCRFunc != nil {
		return m.readPCRFunc(ctx, pcr, algorithm)
	}
	return make([]byte, 32), nil
}

func (m *mockTPMDevice) GetAKPublicKey(ctx context.Context) ([]byte, error) {
	if m.getAKPublicKeyFunc != nil {
		return m.getAKPublicKeyFunc(ctx)
	}
	return []byte("ak-public-key"), nil
}

func (m *mockTPMDevice) Sign(ctx context.Context, data []byte, algorithm HashAlgorithm) ([]byte, error) {
	if m.signFunc != nil {
		return m.signFunc(ctx, data, algorithm)
	}
	return []byte("signature"), nil
}

func (m *mockTPMDevice) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func createValidHostAttestation() *HostAttestation {
	return &HostAttestation{
		QuoteData:          []byte("host-quote-data"),
		Signature:          []byte("host-signature"),
		SignatureAlgorithm: "RSASSA-PKCS1-v1_5-SHA256",
		PCRs: []PCRValue{
			{Index: 0, Value: make([]byte, 32), Algorithm: HashAlgorithmSHA256},
			{Index: 1, Value: make([]byte, 32), Algorithm: HashAlgorithmSHA256},
		},
		PCRDigest:     make([]byte, 32),
		Nonce:         []byte("host-nonce12345678901234"),
		Timestamp:     time.Now(),
		AKPublicKey:   []byte("ak-public-key"),
		HashAlgorithm: HashAlgorithmSHA256,
	}
}

func createValidVMAttestation(vmID string) *VMAttestation {
	return &VMAttestation{
		VMID:               vmID,
		HostID:             "host-1",
		QuoteData:          []byte("vm-quote-data-" + vmID),
		Signature:          []byte("vm-signature-" + vmID),
		SignatureAlgorithm: "RSASSA-PKCS1-v1_5-SHA256",
		PCRs: []PCRValue{
			{Index: 0, Value: make([]byte, 32), Algorithm: HashAlgorithmSHA256},
		},
		PCRDigest:     make([]byte, 32),
		Nonce:         []byte("vm-nonce12345678901234" + vmID),
		Timestamp:     time.Now(),
		AIKPublicKey:  []byte("aik-public-key"),
		HashAlgorithm: HashAlgorithmSHA256,
	}
}

func createValidContainerAttestation(containerID string) *ContainerAttestation {
	return &ContainerAttestation{
		ContainerID: containerID,
		ImageID:     "sha256:abc123",
		ImageDigest: "sha256:abc123",
		Digest:      make([]byte, 32),
		PCRValue:    make([]byte, 32),
		Timestamp:   time.Now(),
	}
}

func TestNewManifestBuilder(t *testing.T) {
	t.Run("DefaultLogger", func(t *testing.T) {
		builder := NewManifestBuilder()
		if builder == nil {
			t.Fatal("expected non-nil builder")
		}
	})

	t.Run("WithOptions", func(t *testing.T) {
		tpm := &mockTPMDevice{}
		builder := NewManifestBuilder(
			WithTPMDevice(tpm),
		)
		if builder == nil {
			t.Fatal("expected non-nil builder")
		}
	})
}

func TestManifestBuilderInitialize(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
			Version:       "1.0",
		}

		err := builder.Initialize(context.Background(), config)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
	})

	t.Run("NilConfig", func(t *testing.T) {
		builder := NewManifestBuilder()
		err := builder.Initialize(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for nil config")
		}
	})

	t.Run("InvalidConfig", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}

		err := builder.Initialize(context.Background(), config)
		if err == nil {
			t.Fatal("expected error for invalid config")
		}
	})

	t.Run("AlreadyInitialized", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}

		err := builder.Initialize(context.Background(), config)
		if err != nil {
			t.Fatalf("first initialization should succeed: %v", err)
		}

		err = builder.Initialize(context.Background(), config)
		if err == nil {
			t.Fatal("expected error for double initialization")
		}
	})

	t.Run("ContextCanceled", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := builder.Initialize(ctx, config)
		if err == nil {
			t.Fatal("expected error for canceled context")
		}
	})
}

func TestManifestBuilderSetHostAttestation(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}
		if err := builder.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		attestation := createValidHostAttestation()
		err := builder.SetHostAttestation(context.Background(), attestation)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
	})

	t.Run("NotInitialized", func(t *testing.T) {
		builder := NewManifestBuilder()
		attestation := createValidHostAttestation()
		err := builder.SetHostAttestation(context.Background(), attestation)
		if err == nil {
			t.Fatal("expected error for uninitialized builder")
		}
	})

	t.Run("NilAttestation", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}
		if err := builder.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		err := builder.SetHostAttestation(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for nil attestation")
		}
	})

	t.Run("InvalidAttestation", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}
		if err := builder.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		attestation := &HostAttestation{} // Invalid - missing fields
		err := builder.SetHostAttestation(context.Background(), attestation)
		if err == nil {
			t.Fatal("expected error for invalid attestation")
		}
	})

	t.Run("ContextCanceled", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}
		if err := builder.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		attestation := createValidHostAttestation()
		err := builder.SetHostAttestation(ctx, attestation)
		if err == nil {
			t.Fatal("expected error for canceled context")
		}
	})
}

func TestManifestBuilderAddVMAttestation(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}
		if err := builder.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		attestation := createValidVMAttestation("vm-1")
		err := builder.AddVMAttestation(context.Background(), attestation)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}

		if builder.GetVMCount() != 1 {
			t.Errorf("expected 1 VM, got %d", builder.GetVMCount())
		}
	})

	t.Run("MultipleVMs", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}
		if err := builder.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		for i := 0; i < 5; i++ {
			attestation := createValidVMAttestation("vm-" + string(rune('1'+i)))
			err := builder.AddVMAttestation(context.Background(), attestation)
			if err != nil {
				t.Fatalf("expected success, got error: %v", err)
			}
		}

		if builder.GetVMCount() != 5 {
			t.Errorf("expected 5 VMs, got %d", builder.GetVMCount())
		}
	})

	t.Run("NotInitialized", func(t *testing.T) {
		builder := NewManifestBuilder()
		attestation := createValidVMAttestation("vm-1")
		err := builder.AddVMAttestation(context.Background(), attestation)
		if err == nil {
			t.Fatal("expected error for uninitialized builder")
		}
	})

	t.Run("NilAttestation", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}
		if err := builder.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		err := builder.AddVMAttestation(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for nil attestation")
		}
	})
}

func TestManifestBuilderAddContainerAttestation(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}
		if err := builder.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		attestation := createValidContainerAttestation("container-1")
		err := builder.AddContainerAttestation(context.Background(), attestation)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}

		if builder.GetContainerCount() != 1 {
			t.Errorf("expected 1 container, got %d", builder.GetContainerCount())
		}
	})

	t.Run("MultipleContainers", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}
		if err := builder.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		for i := 0; i < 10; i++ {
			attestation := createValidContainerAttestation("container-" + string(rune('0'+i)))
			err := builder.AddContainerAttestation(context.Background(), attestation)
			if err != nil {
				t.Fatalf("expected success, got error: %v", err)
			}
		}

		if builder.GetContainerCount() != 10 {
			t.Errorf("expected 10 containers, got %d", builder.GetContainerCount())
		}
	})

	t.Run("NotInitialized", func(t *testing.T) {
		builder := NewManifestBuilder()
		attestation := createValidContainerAttestation("container-1")
		err := builder.AddContainerAttestation(context.Background(), attestation)
		if err == nil {
			t.Fatal("expected error for uninitialized builder")
		}
	})

	t.Run("NilAttestation", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}
		if err := builder.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		err := builder.AddContainerAttestation(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for nil attestation")
		}
	})
}

func TestManifestBuilderBuild(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
			Version:       "1.0",
		}
		if err := builder.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		if err := builder.SetHostAttestation(context.Background(), createValidHostAttestation()); err != nil {
			t.Fatalf("SetHostAttestation failed: %v", err)
		}
		if err := builder.AddVMAttestation(context.Background(), createValidVMAttestation("vm-1")); err != nil {
			t.Fatalf("AddVMAttestation failed: %v", err)
		}
		if err := builder.AddContainerAttestation(context.Background(), createValidContainerAttestation("container-1")); err != nil {
			t.Fatalf("AddContainerAttestation failed: %v", err)
		}

		manifest, err := builder.Build(context.Background())
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}

		if manifest.ID == "" {
			t.Error("expected manifest ID")
		}
		if manifest.HostID != "host-1" {
			t.Errorf("expected host-1, got %s", manifest.HostID)
		}
		if len(manifest.Nonce) != 32 {
			t.Errorf("expected 32-byte nonce, got %d", len(manifest.Nonce))
		}
		if len(manifest.MerkleRoot) == 0 {
			t.Error("expected non-empty Merkle root")
		}
		if len(manifest.VMs) != 1 {
			t.Errorf("expected 1 VM, got %d", len(manifest.VMs))
		}
		if len(manifest.Containers) != 1 {
			t.Errorf("expected 1 container, got %d", len(manifest.Containers))
		}
	})

	t.Run("NoHostAttestation", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}
		if err := builder.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		_, err := builder.Build(context.Background())
		if err == nil {
			t.Fatal("expected error for missing host attestation")
		}
	})

	t.Run("NotInitialized", func(t *testing.T) {
		builder := NewManifestBuilder()
		_, err := builder.Build(context.Background())
		if err == nil {
			t.Fatal("expected error for uninitialized builder")
		}
	})

	t.Run("ContextCanceled", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}
		if err := builder.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}
		if err := builder.SetHostAttestation(context.Background(), createValidHostAttestation()); err != nil {
			t.Fatalf("SetHostAttestation failed: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := builder.Build(ctx)
		if err == nil {
			t.Fatal("expected error for canceled context")
		}
	})
}

func TestManifestBuilderBuildWithNonce(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
			Version:       "1.0",
		}
		if err := builder.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}
		if err := builder.SetHostAttestation(context.Background(), createValidHostAttestation()); err != nil {
			t.Fatalf("SetHostAttestation failed: %v", err)
		}

		nonce := []byte("custom-nonce-1234567890123456")
		manifest, err := builder.BuildWithNonce(context.Background(), nonce)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}

		if !bytes.Equal(manifest.Nonce, nonce) {
			t.Error("expected nonce to match provided value")
		}
	})

	t.Run("ShortNonce", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}
		if err := builder.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}
		if err := builder.SetHostAttestation(context.Background(), createValidHostAttestation()); err != nil {
			t.Fatalf("SetHostAttestation failed: %v", err)
		}

		nonce := []byte("short")
		_, err := builder.BuildWithNonce(context.Background(), nonce)
		if err == nil {
			t.Fatal("expected error for short nonce")
		}
	})
}

func TestManifestBuilderReset(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}
		if err := builder.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		if err := builder.SetHostAttestation(context.Background(), createValidHostAttestation()); err != nil {
			t.Fatalf("SetHostAttestation failed: %v", err)
		}
		if err := builder.AddVMAttestation(context.Background(), createValidVMAttestation("vm-1")); err != nil {
			t.Fatalf("AddVMAttestation failed: %v", err)
		}
		if err := builder.AddContainerAttestation(context.Background(), createValidContainerAttestation("container-1")); err != nil {
			t.Fatalf("AddContainerAttestation failed: %v", err)
		}

		if builder.GetVMCount() != 1 {
			t.Error("expected 1 VM before reset")
		}
		if builder.GetContainerCount() != 1 {
			t.Error("expected 1 container before reset")
		}

		builder.Reset()

		if builder.GetVMCount() != 0 {
			t.Error("expected 0 VMs after reset")
		}
		if builder.GetContainerCount() != 0 {
			t.Error("expected 0 containers after reset")
		}
	})
}

func TestManifestBuilderClose(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tpm := &mockTPMDevice{}
		builder := NewManifestBuilder(WithTPMDevice(tpm))
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}
		if err := builder.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		err := builder.Close()
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
	})

	t.Run("DoubleClose", func(t *testing.T) {
		builder := NewManifestBuilder()
		config := &BuilderConfig{
			HostID:        "host-1",
			HashAlgorithm: HashAlgorithmSHA256,
			NonceSize:     32,
		}
		if err := builder.Initialize(context.Background(), config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		err := builder.Close()
		if err != nil {
			t.Fatalf("first close should succeed: %v", err)
		}

		err = builder.Close()
		if err != nil {
			t.Fatalf("second close should also succeed: %v", err)
		}
	})
}

func TestComputeMerkleRoot(t *testing.T) {
	t.Run("SingleLeaf", func(t *testing.T) {
		leaves := [][]byte{
			{0x01, 0x02, 0x03},
		}
		root := ComputeMerkleRoot(leaves, HashAlgorithmSHA256)
		if root == nil {
			t.Fatal("expected non-nil root")
		}
		if !bytes.Equal(root, leaves[0]) {
			t.Error("single leaf should be the root")
		}
	})

	t.Run("TwoLeaves", func(t *testing.T) {
		leaves := [][]byte{
			{0x01, 0x02, 0x03},
			{0x04, 0x05, 0x06},
		}
		root := ComputeMerkleRoot(leaves, HashAlgorithmSHA256)
		if root == nil {
			t.Fatal("expected non-nil root")
		}
		if len(root) != 32 {
			t.Errorf("expected 32-byte hash, got %d", len(root))
		}
	})

	t.Run("ThreeLeaves", func(t *testing.T) {
		leaves := [][]byte{
			{0x01, 0x02, 0x03},
			{0x04, 0x05, 0x06},
			{0x07, 0x08, 0x09},
		}
		root := ComputeMerkleRoot(leaves, HashAlgorithmSHA256)
		if root == nil {
			t.Fatal("expected non-nil root")
		}
		if len(root) != 32 {
			t.Errorf("expected 32-byte hash, got %d", len(root))
		}
	})

	t.Run("EmptyLeaves", func(t *testing.T) {
		leaves := [][]byte{}
		root := ComputeMerkleRoot(leaves, HashAlgorithmSHA256)
		if root != nil {
			t.Error("expected nil root for empty leaves")
		}
	})

	t.Run("SHA384", func(t *testing.T) {
		leaves := [][]byte{
			{0x01, 0x02, 0x03},
			{0x04, 0x05, 0x06},
		}
		root := ComputeMerkleRoot(leaves, HashAlgorithmSHA384)
		if root == nil {
			t.Fatal("expected non-nil root")
		}
		if len(root) != 48 {
			t.Errorf("expected 48-byte hash for SHA384, got %d", len(root))
		}
	})

	t.Run("SHA512", func(t *testing.T) {
		leaves := [][]byte{
			{0x01, 0x02, 0x03},
			{0x04, 0x05, 0x06},
		}
		root := ComputeMerkleRoot(leaves, HashAlgorithmSHA512)
		if root == nil {
			t.Fatal("expected non-nil root")
		}
		if len(root) != 64 {
			t.Errorf("expected 64-byte hash for SHA512, got %d", len(root))
		}
	})
}

func TestHashAttestation(t *testing.T) {
	t.Run("SHA256", func(t *testing.T) {
		data1 := []byte("data1")
		data2 := []byte("data2")
		hash := HashAttestation(data1, data2, HashAlgorithmSHA256)
		if len(hash) != 32 {
			t.Errorf("expected 32-byte hash, got %d", len(hash))
		}
	})

	t.Run("SHA384", func(t *testing.T) {
		data1 := []byte("data1")
		data2 := []byte("data2")
		hash := HashAttestation(data1, data2, HashAlgorithmSHA384)
		if len(hash) != 48 {
			t.Errorf("expected 48-byte hash, got %d", len(hash))
		}
	})

	t.Run("SHA512", func(t *testing.T) {
		data1 := []byte("data1")
		data2 := []byte("data2")
		hash := HashAttestation(data1, data2, HashAlgorithmSHA512)
		if len(hash) != 64 {
			t.Errorf("expected 64-byte hash, got %d", len(hash))
		}
	})

	t.Run("Deterministic", func(t *testing.T) {
		data1 := []byte("data1")
		data2 := []byte("data2")
		hash1 := HashAttestation(data1, data2, HashAlgorithmSHA256)
		hash2 := HashAttestation(data1, data2, HashAlgorithmSHA256)
		if !bytes.Equal(hash1, hash2) {
			t.Error("expected deterministic hashing")
		}
	})
}
