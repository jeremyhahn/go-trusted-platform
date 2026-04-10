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

package vm

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"testing"
	"time"
)

// mockVTPMDevice is a mock implementation of VTPMDevice for testing.
type mockVTPMDevice struct {
	pcrs             map[int]map[HashAlgorithm][]byte
	aikPubKey        []byte
	ekCert           []byte
	closed           bool
	generateQuoteErr error
	readPCRErr       error
	getAIKPubKeyErr  error
	getEKCertErr     error
}

func newMockVTPMDevice() *mockVTPMDevice {
	// Generate RSA key pair for AIK
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	aikPubKeyBytes, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)

	// Generate EK certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vm:vm-test-123@host:host-test-456"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
	}
	ekCertBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)

	mock := &mockVTPMDevice{
		pcrs:      make(map[int]map[HashAlgorithm][]byte),
		aikPubKey: aikPubKeyBytes,
		ekCert:    ekCertBytes,
	}

	// Initialize PCRs with zeros
	for pcr := 0; pcr <= 23; pcr++ {
		mock.pcrs[pcr] = make(map[HashAlgorithm][]byte)
		for _, alg := range []HashAlgorithm{HashAlgorithmSHA1, HashAlgorithmSHA256, HashAlgorithmSHA384, HashAlgorithmSHA512} {
			mock.pcrs[pcr][alg] = make([]byte, alg.DigestSize())
		}
	}

	return mock
}

func (m *mockVTPMDevice) GenerateQuote(ctx context.Context, nonce []byte, pcrIndices []int, algorithm HashAlgorithm) ([]byte, []byte, error) {
	if m.generateQuoteErr != nil {
		return nil, nil, m.generateQuoteErr
	}

	// Generate mock quote data
	quoteData := make([]byte, 64)
	rand.Read(quoteData)

	// Generate mock signature
	signature := make([]byte, 256)
	rand.Read(signature)

	return quoteData, signature, nil
}

func (m *mockVTPMDevice) ReadPCR(ctx context.Context, pcr int, algorithm HashAlgorithm) ([]byte, error) {
	if m.readPCRErr != nil {
		return nil, m.readPCRErr
	}

	if pcr < 0 || pcr > 23 {
		return nil, ErrInvalidConfig{Field: "PCR", Reason: "PCR index out of range"}
	}

	value := m.pcrs[pcr][algorithm]
	result := make([]byte, len(value))
	copy(result, value)
	return result, nil
}

func (m *mockVTPMDevice) GetAIKPublicKey(ctx context.Context) ([]byte, error) {
	if m.getAIKPubKeyErr != nil {
		return nil, m.getAIKPubKeyErr
	}
	return m.aikPubKey, nil
}

func (m *mockVTPMDevice) GetEKCertificate(ctx context.Context) ([]byte, error) {
	if m.getEKCertErr != nil {
		return nil, m.getEKCertErr
	}
	return m.ekCert, nil
}

func (m *mockVTPMDevice) Close() error {
	m.closed = true
	return nil
}

func (m *mockVTPMDevice) SetPCRValue(pcr int, algorithm HashAlgorithm, value []byte) {
	if m.pcrs[pcr] == nil {
		m.pcrs[pcr] = make(map[HashAlgorithm][]byte)
	}
	m.pcrs[pcr][algorithm] = value
}

func TestNewVMAttestor(t *testing.T) {
	t.Run("with defaults", func(t *testing.T) {
		attestor := NewVMAttestor()
		if attestor == nil {
			t.Error("Expected non-nil attestor")
		}
	})

	t.Run("with vTPM device", func(t *testing.T) {
		mock := newMockVTPMDevice()
		attestor := NewVMAttestor(WithVTPMDevice(mock))
		if attestor == nil {
			t.Error("Expected non-nil attestor")
		}
	})

	t.Run("with logger", func(t *testing.T) {
		logger := slog.Default()
		attestor := NewVMAttestor(WithAttestorLogger(logger))
		if attestor == nil {
			t.Error("Expected non-nil attestor")
		}
	})
}

func TestVMAttestor_Initialize(t *testing.T) {
	ctx := context.Background()

	t.Run("successful initialization", func(t *testing.T) {
		mock := newMockVTPMDevice()
		attestor := NewVMAttestor(WithVTPMDevice(mock))

		config := &AttestorConfig{
			VTPMDevicePath:       "/dev/tpm0",
			DefaultHashAlgorithm: HashAlgorithmSHA256,
			DefaultPCRIndices:    []int{0, 1, 7, 14},
			IncludeWorkloadPCR:   true,
		}

		err := attestor.Initialize(ctx, config)
		if err != nil {
			t.Errorf("Initialize() unexpected error: %v", err)
		}
	})

	t.Run("nil config", func(t *testing.T) {
		mock := newMockVTPMDevice()
		attestor := NewVMAttestor(WithVTPMDevice(mock))

		err := attestor.Initialize(ctx, nil)
		if err == nil {
			t.Error("Expected error for nil config")
		}
		var configErr ErrInvalidConfig
		if !errors.As(err, &configErr) {
			t.Errorf("Expected ErrInvalidConfig, got %T", err)
		}
	})

	t.Run("invalid config - empty device path", func(t *testing.T) {
		mock := newMockVTPMDevice()
		attestor := NewVMAttestor(WithVTPMDevice(mock))

		config := &AttestorConfig{
			VTPMDevicePath:       "",
			DefaultHashAlgorithm: HashAlgorithmSHA256,
		}

		err := attestor.Initialize(ctx, config)
		if err == nil {
			t.Error("Expected error for empty device path")
		}
	})

	t.Run("no vTPM device", func(t *testing.T) {
		attestor := NewVMAttestor()

		config := &AttestorConfig{
			VTPMDevicePath:       "/dev/tpm0",
			DefaultHashAlgorithm: HashAlgorithmSHA256,
		}

		err := attestor.Initialize(ctx, config)
		if err == nil {
			t.Error("Expected error for no vTPM device")
		}
		var vtpmErr ErrVTPMNotAvailable
		if !errors.As(err, &vtpmErr) {
			t.Errorf("Expected ErrVTPMNotAvailable, got %T", err)
		}
	})

	t.Run("AIK not found", func(t *testing.T) {
		mock := newMockVTPMDevice()
		mock.getAIKPubKeyErr = errors.New("AIK not loaded")
		attestor := NewVMAttestor(WithVTPMDevice(mock))

		config := &AttestorConfig{
			VTPMDevicePath:       "/dev/tpm0",
			DefaultHashAlgorithm: HashAlgorithmSHA256,
		}

		err := attestor.Initialize(ctx, config)
		if err == nil {
			t.Error("Expected error for AIK not found")
		}
		var aikErr ErrAIKNotFound
		if !errors.As(err, &aikErr) {
			t.Errorf("Expected ErrAIKNotFound, got %T", err)
		}
	})

	t.Run("already initialized", func(t *testing.T) {
		mock := newMockVTPMDevice()
		attestor := NewVMAttestor(WithVTPMDevice(mock))

		config := &AttestorConfig{
			VTPMDevicePath:       "/dev/tpm0",
			DefaultHashAlgorithm: HashAlgorithmSHA256,
		}

		// First initialization
		err := attestor.Initialize(ctx, config)
		if err != nil {
			t.Errorf("First Initialize() unexpected error: %v", err)
		}

		// Second initialization should fail
		err = attestor.Initialize(ctx, config)
		if err == nil {
			t.Error("Expected error for already initialized")
		}
	})

	t.Run("context canceled", func(t *testing.T) {
		mock := newMockVTPMDevice()
		attestor := NewVMAttestor(WithVTPMDevice(mock))

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		config := &AttestorConfig{
			VTPMDevicePath:       "/dev/tpm0",
			DefaultHashAlgorithm: HashAlgorithmSHA256,
		}

		err := attestor.Initialize(ctx, config)
		if err == nil {
			t.Error("Expected error for canceled context")
		}
		var ctxErr ErrContextCanceled
		if !errors.As(err, &ctxErr) {
			t.Errorf("Expected ErrContextCanceled, got %T", err)
		}
	})
}

func TestVMAttestor_GenerateQuote(t *testing.T) {
	ctx := context.Background()

	setupAttestor := func() (*mockVTPMDevice, VMAttestor) {
		mock := newMockVTPMDevice()
		attestor := NewVMAttestor(WithVTPMDevice(mock))

		config := &AttestorConfig{
			VTPMDevicePath:       "/dev/tpm0",
			DefaultHashAlgorithm: HashAlgorithmSHA256,
			DefaultPCRIndices:    []int{0, 1, 7},
			IncludeWorkloadPCR:   true,
		}

		if err := attestor.Initialize(ctx, config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}
		return mock, attestor
	}

	t.Run("successful quote generation", func(t *testing.T) {
		_, attestor := setupAttestor()

		request := &QuoteRequest{
			Nonce:         []byte{0x01, 0x02, 0x03, 0x04},
			PCRIndices:    []int{0, 1, 7},
			HashAlgorithm: HashAlgorithmSHA256,
		}

		quote, err := attestor.GenerateQuote(ctx, request)
		if err != nil {
			t.Errorf("GenerateQuote() unexpected error: %v", err)
		}
		if quote == nil {
			t.Error("Expected non-nil quote")
			return
		}

		if len(quote.QuoteData) == 0 {
			t.Error("Expected non-empty quote data")
		}
		if len(quote.Signature) == 0 {
			t.Error("Expected non-empty signature")
		}
		// Should have 4 PCRs (0, 1, 7, and 14 from workload)
		if len(quote.PCRs) != 4 {
			t.Errorf("Expected 4 PCRs, got %d", len(quote.PCRs))
		}
		if quote.HashAlgorithm != HashAlgorithmSHA256 {
			t.Errorf("Expected SHA256, got %s", quote.HashAlgorithm)
		}
	})

	t.Run("not initialized", func(t *testing.T) {
		attestor := NewVMAttestor()

		request := &QuoteRequest{
			Nonce:         []byte{0x01, 0x02},
			PCRIndices:    []int{0},
			HashAlgorithm: HashAlgorithmSHA256,
		}

		_, err := attestor.GenerateQuote(ctx, request)
		if err == nil {
			t.Error("Expected error for not initialized")
		}
		var initErr ErrAttestorNotInitialized
		if !errors.As(err, &initErr) {
			t.Errorf("Expected ErrAttestorNotInitialized, got %T", err)
		}
	})

	t.Run("nil request", func(t *testing.T) {
		_, attestor := setupAttestor()

		_, err := attestor.GenerateQuote(ctx, nil)
		if err == nil {
			t.Error("Expected error for nil request")
		}
	})

	t.Run("invalid request", func(t *testing.T) {
		_, attestor := setupAttestor()

		request := &QuoteRequest{
			Nonce:         []byte{},
			PCRIndices:    []int{0},
			HashAlgorithm: HashAlgorithmSHA256,
		}

		_, err := attestor.GenerateQuote(ctx, request)
		if err == nil {
			t.Error("Expected error for empty nonce")
		}
	})

	t.Run("quote generation error", func(t *testing.T) {
		mock, attestor := setupAttestor()
		mock.generateQuoteErr = errors.New("TPM error")

		request := &QuoteRequest{
			Nonce:         []byte{0x01, 0x02},
			PCRIndices:    []int{0},
			HashAlgorithm: HashAlgorithmSHA256,
		}

		_, err := attestor.GenerateQuote(ctx, request)
		if err == nil {
			t.Error("Expected error for quote generation failure")
		}
		var quoteErr ErrQuoteGenerationFailed
		if !errors.As(err, &quoteErr) {
			t.Errorf("Expected ErrQuoteGenerationFailed, got %T", err)
		}
	})

	t.Run("PCR read error", func(t *testing.T) {
		mock, attestor := setupAttestor()
		mock.readPCRErr = errors.New("PCR read error")

		request := &QuoteRequest{
			Nonce:         []byte{0x01, 0x02},
			PCRIndices:    []int{0},
			HashAlgorithm: HashAlgorithmSHA256,
		}

		_, err := attestor.GenerateQuote(ctx, request)
		if err == nil {
			t.Error("Expected error for PCR read failure")
		}
		var pcrErr ErrPCRReadFailed
		if !errors.As(err, &pcrErr) {
			t.Errorf("Expected ErrPCRReadFailed, got %T", err)
		}
	})

	t.Run("context canceled", func(t *testing.T) {
		_, attestor := setupAttestor()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		request := &QuoteRequest{
			Nonce:         []byte{0x01, 0x02},
			PCRIndices:    []int{0},
			HashAlgorithm: HashAlgorithmSHA256,
		}

		_, err := attestor.GenerateQuote(ctx, request)
		if err == nil {
			t.Error("Expected error for canceled context")
		}
	})
}

func TestVMAttestor_GetIdentity(t *testing.T) {
	ctx := context.Background()

	setupAttestor := func() (*mockVTPMDevice, VMAttestor) {
		mock := newMockVTPMDevice()
		attestor := NewVMAttestor(WithVTPMDevice(mock))

		config := &AttestorConfig{
			VTPMDevicePath:       "/dev/tpm0",
			DefaultHashAlgorithm: HashAlgorithmSHA256,
		}

		if err := attestor.Initialize(ctx, config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}
		return mock, attestor
	}

	t.Run("successful identity retrieval", func(t *testing.T) {
		_, attestor := setupAttestor()

		identity, err := attestor.GetIdentity(ctx)
		if err != nil {
			t.Errorf("GetIdentity() unexpected error: %v", err)
		}
		if identity == nil {
			t.Error("Expected non-nil identity")
			return
		}

		if identity.VMID != "vm-test-123" {
			t.Errorf("Expected vmID 'vm-test-123', got %s", identity.VMID)
		}
		if identity.HostID != "host-test-456" {
			t.Errorf("Expected hostID 'host-test-456', got %s", identity.HostID)
		}
		if identity.EKCertificate == nil {
			t.Error("Expected non-nil EK certificate")
		}
	})

	t.Run("not initialized", func(t *testing.T) {
		attestor := NewVMAttestor()

		_, err := attestor.GetIdentity(ctx)
		if err == nil {
			t.Error("Expected error for not initialized")
		}
	})

	t.Run("EK certificate error", func(t *testing.T) {
		mock, attestor := setupAttestor()
		mock.getEKCertErr = errors.New("certificate not found")

		_, err := attestor.GetIdentity(ctx)
		if err == nil {
			t.Error("Expected error for EK certificate failure")
		}
	})

	t.Run("invalid EK certificate format", func(t *testing.T) {
		mock, attestor := setupAttestor()
		mock.ekCert = []byte{0x00, 0x01, 0x02} // Invalid certificate

		_, err := attestor.GetIdentity(ctx)
		if err == nil {
			t.Error("Expected error for invalid certificate")
		}
	})
}

func TestVMAttestor_GetAttestation(t *testing.T) {
	ctx := context.Background()

	setupAttestor := func() (*mockVTPMDevice, VMAttestor) {
		mock := newMockVTPMDevice()
		attestor := NewVMAttestor(WithVTPMDevice(mock))

		config := &AttestorConfig{
			VTPMDevicePath:       "/dev/tpm0",
			DefaultHashAlgorithm: HashAlgorithmSHA256,
			IncludeWorkloadPCR:   true,
		}

		if err := attestor.Initialize(ctx, config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}
		return mock, attestor
	}

	t.Run("successful attestation", func(t *testing.T) {
		mock, attestor := setupAttestor()

		// Set a non-zero workload PCR value
		workloadPCR := make([]byte, 32)
		rand.Read(workloadPCR)
		mock.SetPCRValue(14, HashAlgorithmSHA256, workloadPCR)

		request := &QuoteRequest{
			Nonce:         []byte{0x01, 0x02, 0x03, 0x04},
			PCRIndices:    []int{0, 1, 7},
			HashAlgorithm: HashAlgorithmSHA256,
		}

		attestation, err := attestor.GetAttestation(ctx, request)
		if err != nil {
			t.Errorf("GetAttestation() unexpected error: %v", err)
		}
		if attestation == nil {
			t.Error("Expected non-nil attestation")
			return
		}

		if attestation.Identity == nil {
			t.Error("Expected non-nil identity")
		}
		if attestation.Quote == nil {
			t.Error("Expected non-nil quote")
		}
		if attestation.AttestationID == "" {
			t.Error("Expected non-empty attestation ID")
		}
		if attestation.Timestamp.IsZero() {
			t.Error("Expected non-zero timestamp")
		}
	})

	t.Run("not initialized", func(t *testing.T) {
		attestor := NewVMAttestor()

		request := &QuoteRequest{
			Nonce:         []byte{0x01, 0x02},
			PCRIndices:    []int{0},
			HashAlgorithm: HashAlgorithmSHA256,
		}

		_, err := attestor.GetAttestation(ctx, request)
		if err == nil {
			t.Error("Expected error for not initialized")
		}
	})
}

func TestVMAttestor_ReadPCR(t *testing.T) {
	ctx := context.Background()

	setupAttestor := func() (*mockVTPMDevice, VMAttestor) {
		mock := newMockVTPMDevice()
		attestor := NewVMAttestor(WithVTPMDevice(mock))

		config := &AttestorConfig{
			VTPMDevicePath:       "/dev/tpm0",
			DefaultHashAlgorithm: HashAlgorithmSHA256,
		}

		if err := attestor.Initialize(ctx, config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}
		return mock, attestor
	}

	t.Run("successful PCR read", func(t *testing.T) {
		mock, attestor := setupAttestor()

		// Set a specific PCR value
		expectedValue := make([]byte, 32)
		hash := sha256.Sum256([]byte("test data"))
		copy(expectedValue, hash[:])
		mock.SetPCRValue(14, HashAlgorithmSHA256, expectedValue)

		pcr, err := attestor.ReadPCR(ctx, 14, HashAlgorithmSHA256)
		if err != nil {
			t.Errorf("ReadPCR() unexpected error: %v", err)
		}
		if pcr == nil {
			t.Error("Expected non-nil PCR value")
			return
		}

		if pcr.Index != 14 {
			t.Errorf("Expected index 14, got %d", pcr.Index)
		}
		if pcr.Algorithm != HashAlgorithmSHA256 {
			t.Errorf("Expected SHA256, got %s", pcr.Algorithm)
		}
	})

	t.Run("invalid PCR index - negative", func(t *testing.T) {
		_, attestor := setupAttestor()

		_, err := attestor.ReadPCR(ctx, -1, HashAlgorithmSHA256)
		if err == nil {
			t.Error("Expected error for negative PCR index")
		}
	})

	t.Run("invalid PCR index - too high", func(t *testing.T) {
		_, attestor := setupAttestor()

		_, err := attestor.ReadPCR(ctx, 24, HashAlgorithmSHA256)
		if err == nil {
			t.Error("Expected error for PCR index too high")
		}
	})

	t.Run("invalid hash algorithm", func(t *testing.T) {
		_, attestor := setupAttestor()

		_, err := attestor.ReadPCR(ctx, 0, HashAlgorithm("invalid"))
		if err == nil {
			t.Error("Expected error for invalid hash algorithm")
		}
	})

	t.Run("not initialized", func(t *testing.T) {
		attestor := NewVMAttestor()

		_, err := attestor.ReadPCR(ctx, 0, HashAlgorithmSHA256)
		if err == nil {
			t.Error("Expected error for not initialized")
		}
	})
}

func TestVMAttestor_Close(t *testing.T) {
	ctx := context.Background()

	t.Run("successful close", func(t *testing.T) {
		mock := newMockVTPMDevice()
		attestor := NewVMAttestor(WithVTPMDevice(mock))

		config := &AttestorConfig{
			VTPMDevicePath:       "/dev/tpm0",
			DefaultHashAlgorithm: HashAlgorithmSHA256,
		}

		if err := attestor.Initialize(ctx, config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		err := attestor.Close()
		if err != nil {
			t.Errorf("Close() unexpected error: %v", err)
		}

		if !mock.closed {
			t.Error("Expected vTPM device to be closed")
		}
	})

	t.Run("double close", func(t *testing.T) {
		mock := newMockVTPMDevice()
		attestor := NewVMAttestor(WithVTPMDevice(mock))

		config := &AttestorConfig{
			VTPMDevicePath:       "/dev/tpm0",
			DefaultHashAlgorithm: HashAlgorithmSHA256,
		}

		if err := attestor.Initialize(ctx, config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		err := attestor.Close()
		if err != nil {
			t.Errorf("First Close() unexpected error: %v", err)
		}

		err = attestor.Close()
		if err != nil {
			t.Errorf("Second Close() unexpected error: %v", err)
		}
	})

	t.Run("operations after close", func(t *testing.T) {
		mock := newMockVTPMDevice()
		attestor := NewVMAttestor(WithVTPMDevice(mock))

		config := &AttestorConfig{
			VTPMDevicePath:       "/dev/tpm0",
			DefaultHashAlgorithm: HashAlgorithmSHA256,
		}

		if err := attestor.Initialize(ctx, config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}
		if err := attestor.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		// Operations should fail after close
		request := &QuoteRequest{
			Nonce:         []byte{0x01, 0x02},
			PCRIndices:    []int{0},
			HashAlgorithm: HashAlgorithmSHA256,
		}

		_, err := attestor.GenerateQuote(ctx, request)
		if err == nil {
			t.Error("Expected error for operation after close")
		}
	})
}
