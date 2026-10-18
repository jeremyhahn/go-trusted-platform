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

package network

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockVMVerifier implements vm.VMVerifier for testing.
type mockVMVerifier struct {
	initializeError   error
	verifyQuoteResult *vm.VerificationResult
	verifyQuoteError  error
	verifyQuoteCalled bool
	verifyAttestError error
	verifyEKError     error
	closeError        error
}

func newMockVMVerifier() *mockVMVerifier {
	return &mockVMVerifier{
		verifyQuoteResult: &vm.VerificationResult{
			Status:         vm.VerificationStatusVerified,
			SignatureValid: true,
			NonceValid:     true,
			PCRsValid:      true,
		},
	}
}

func (m *mockVMVerifier) Initialize(ctx context.Context, config *vm.VerifierConfig) error {
	return m.initializeError
}

func (m *mockVMVerifier) VerifyQuote(ctx context.Context, request *vm.VerifyRequest) (*vm.VerificationResult, error) {
	m.verifyQuoteCalled = true
	if m.verifyQuoteError != nil {
		return nil, m.verifyQuoteError
	}
	return m.verifyQuoteResult, nil
}

func (m *mockVMVerifier) VerifyAttestation(ctx context.Context, attestation *vm.VMAttestation, expectedPCRs map[int][]byte, expectedNonce []byte) (*vm.VerificationResult, error) {
	return m.verifyQuoteResult, m.verifyAttestError
}

func (m *mockVMVerifier) VerifyEKCertificate(ctx context.Context, identity *vm.VMIdentity) error {
	return m.verifyEKError
}

func (m *mockVMVerifier) Close() error {
	return m.closeError
}

// Ensure mockVMVerifier implements vm.VMVerifier
var _ vm.VMVerifier = (*mockVMVerifier)(nil)

// mockQuoteProvider implements QuoteProvider for testing.
type mockQuoteProvider struct {
	quote    *vm.VMQuote
	identity *vm.VMIdentity
	err      error
}

func (m *mockQuoteProvider) GetQuote(ctx context.Context, deviceID string, nonce []byte) (*vm.VMQuote, *vm.VMIdentity, error) {
	if m.err != nil {
		return nil, nil, m.err
	}
	return m.quote, m.identity, nil
}

// Ensure mockQuoteProvider implements QuoteProvider
var _ QuoteProvider = (*mockQuoteProvider)(nil)

// createTestQuote creates a test VMQuote for testing.
func createTestQuote() *vm.VMQuote {
	return &vm.VMQuote{
		QuoteData:     []byte("test-quote-data"),
		Signature:     []byte("test-signature"),
		Nonce:         []byte("test-nonce"),
		PCRs:          []vm.PCRValue{{Index: 0, Value: []byte("pcr0")}},
		Timestamp:     time.Now(),
		HashAlgorithm: vm.HashAlgorithmSHA256,
	}
}

// createTestIdentity creates a test VMIdentity for testing.
func createTestIdentity() *vm.VMIdentity {
	return &vm.VMIdentity{
		VMID:   "test-vm-id",
		HostID: "test-host-id",
	}
}

// =============================================================================
// VMAttestationAdapter Tests
// =============================================================================

func TestNewVMAttestationAdapter(t *testing.T) {
	t.Run("nil verifier returns error", func(t *testing.T) {
		adapter, err := NewVMAttestationAdapter(nil)
		assert.Nil(t, adapter)
		assert.Error(t, err)
		assert.IsType(t, ErrInvalidConfig{}, err)

		configErr := err.(ErrInvalidConfig)
		assert.Equal(t, "verifier", configErr.Field)
		assert.Contains(t, configErr.Reason, "cannot be nil")
	})

	t.Run("successful creation with verifier", func(t *testing.T) {
		verifier := newMockVMVerifier()
		adapter, err := NewVMAttestationAdapter(verifier)

		require.NoError(t, err)
		assert.NotNil(t, adapter)
		assert.NotNil(t, adapter.verifier)
		assert.NotNil(t, adapter.logger)
		assert.Nil(t, adapter.quoteProvider)
	})

	t.Run("with logger option", func(t *testing.T) {
		verifier := newMockVMVerifier()
		logger := slog.Default()

		adapter, err := NewVMAttestationAdapter(verifier, WithVMAdapterLogger(logger))

		require.NoError(t, err)
		assert.NotNil(t, adapter)
		assert.Equal(t, logger, adapter.logger)
	})

	t.Run("with quote provider option", func(t *testing.T) {
		verifier := newMockVMVerifier()
		provider := &mockQuoteProvider{}

		adapter, err := NewVMAttestationAdapter(verifier, WithQuoteProvider(provider))

		require.NoError(t, err)
		assert.NotNil(t, adapter)
		assert.NotNil(t, adapter.quoteProvider)
	})

	t.Run("with multiple options", func(t *testing.T) {
		verifier := newMockVMVerifier()
		logger := slog.Default()
		provider := &mockQuoteProvider{}

		adapter, err := NewVMAttestationAdapter(
			verifier,
			WithVMAdapterLogger(logger),
			WithQuoteProvider(provider),
		)

		require.NoError(t, err)
		assert.NotNil(t, adapter)
		assert.Equal(t, logger, adapter.logger)
		assert.NotNil(t, adapter.quoteProvider)
	})

	t.Run("nil logger defaults to slog.Default", func(t *testing.T) {
		verifier := newMockVMVerifier()
		adapter, err := NewVMAttestationAdapter(verifier, WithVMAdapterLogger(nil))

		require.NoError(t, err)
		assert.NotNil(t, adapter)
		assert.NotNil(t, adapter.logger)
	})
}

func TestVMAttestationAdapter_Verify(t *testing.T) {
	ctx := context.Background()

	t.Run("successful verification", func(t *testing.T) {
		verifier := newMockVMVerifier()
		verifier.verifyQuoteResult = &vm.VerificationResult{
			Status:         vm.VerificationStatusVerified,
			SignatureValid: true,
			NonceValid:     true,
			PCRsValid:      true,
		}

		provider := &mockQuoteProvider{
			quote:    createTestQuote(),
			identity: createTestIdentity(),
		}

		adapter, err := NewVMAttestationAdapter(verifier, WithQuoteProvider(provider))
		require.NoError(t, err)

		verified, err := adapter.Verify(ctx, "device-1", []byte("nonce"), nil)

		require.NoError(t, err)
		assert.True(t, verified)
		assert.True(t, verifier.verifyQuoteCalled)
	})

	t.Run("verification fails with failed status", func(t *testing.T) {
		verifier := newMockVMVerifier()
		verifier.verifyQuoteResult = &vm.VerificationResult{
			Status:         vm.VerificationStatusFailed,
			SignatureValid: false,
			NonceValid:     true,
			PCRsValid:      true,
		}

		provider := &mockQuoteProvider{
			quote:    createTestQuote(),
			identity: createTestIdentity(),
		}

		adapter, err := NewVMAttestationAdapter(verifier, WithQuoteProvider(provider))
		require.NoError(t, err)

		verified, err := adapter.Verify(ctx, "device-1", []byte("nonce"), nil)

		require.NoError(t, err)
		assert.False(t, verified)
	})

	t.Run("empty deviceID returns error", func(t *testing.T) {
		verifier := newMockVMVerifier()
		adapter, err := NewVMAttestationAdapter(verifier)
		require.NoError(t, err)

		verified, err := adapter.Verify(ctx, "", []byte("nonce"), nil)

		assert.False(t, verified)
		assert.Error(t, err)
		assert.IsType(t, ErrInvalidConfig{}, err)

		configErr := err.(ErrInvalidConfig)
		assert.Equal(t, "deviceID", configErr.Field)
	})

	t.Run("no quote provider returns error", func(t *testing.T) {
		verifier := newMockVMVerifier()
		adapter, err := NewVMAttestationAdapter(verifier)
		require.NoError(t, err)

		verified, err := adapter.Verify(ctx, "device-1", []byte("nonce"), nil)

		assert.False(t, verified)
		assert.Error(t, err)
		assert.IsType(t, ErrAttestFailed{}, err)

		attestErr := err.(ErrAttestFailed)
		assert.Equal(t, "device-1", attestErr.DeviceID)
		assert.Contains(t, attestErr.Reason, "no quote provider")
	})

	t.Run("get quote error returns attestation failure", func(t *testing.T) {
		verifier := newMockVMVerifier()
		provider := &mockQuoteProvider{
			err: errors.New("quote retrieval failed"),
		}

		adapter, err := NewVMAttestationAdapter(verifier, WithQuoteProvider(provider))
		require.NoError(t, err)

		verified, err := adapter.Verify(ctx, "device-1", []byte("nonce"), nil)

		assert.False(t, verified)
		assert.Error(t, err)
		assert.IsType(t, ErrAttestFailed{}, err)

		attestErr := err.(ErrAttestFailed)
		assert.Equal(t, "device-1", attestErr.DeviceID)
		assert.Contains(t, attestErr.Reason, "failed to get quote")
		assert.NotNil(t, attestErr.Cause)
	})

	t.Run("nil quote from provider returns error", func(t *testing.T) {
		verifier := newMockVMVerifier()
		provider := &mockQuoteProvider{
			quote:    nil,
			identity: createTestIdentity(),
		}

		adapter, err := NewVMAttestationAdapter(verifier, WithQuoteProvider(provider))
		require.NoError(t, err)

		verified, err := adapter.Verify(ctx, "device-1", []byte("nonce"), nil)

		assert.False(t, verified)
		assert.Error(t, err)
		assert.IsType(t, ErrAttestFailed{}, err)

		attestErr := err.(ErrAttestFailed)
		assert.Contains(t, attestErr.Reason, "nil quote")
	})

	t.Run("verification error returns attestation failure", func(t *testing.T) {
		verifier := newMockVMVerifier()
		verifier.verifyQuoteError = errors.New("verification internal error")

		provider := &mockQuoteProvider{
			quote:    createTestQuote(),
			identity: createTestIdentity(),
		}

		adapter, err := NewVMAttestationAdapter(verifier, WithQuoteProvider(provider))
		require.NoError(t, err)

		verified, err := adapter.Verify(ctx, "device-1", []byte("nonce"), nil)

		assert.False(t, verified)
		assert.Error(t, err)
		assert.IsType(t, ErrAttestFailed{}, err)

		attestErr := err.(ErrAttestFailed)
		assert.Contains(t, attestErr.Reason, "verification failed")
	})

	t.Run("context cancellation returns error", func(t *testing.T) {
		verifier := newMockVMVerifier()
		provider := &mockQuoteProvider{
			quote:    createTestQuote(),
			identity: createTestIdentity(),
		}

		adapter, err := NewVMAttestationAdapter(verifier, WithQuoteProvider(provider))
		require.NoError(t, err)

		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		verified, err := adapter.Verify(cancelCtx, "device-1", []byte("nonce"), nil)

		assert.False(t, verified)
		assert.Error(t, err)
		assert.IsType(t, ErrContextCanceled{}, err)

		cancelErr := err.(ErrContextCanceled)
		assert.Equal(t, "Verify", cancelErr.Operation)
	})

	t.Run("with expected PCRs", func(t *testing.T) {
		verifier := newMockVMVerifier()
		provider := &mockQuoteProvider{
			quote:    createTestQuote(),
			identity: createTestIdentity(),
		}

		adapter, err := NewVMAttestationAdapter(verifier, WithQuoteProvider(provider))
		require.NoError(t, err)

		expectedPCRs := map[int][]byte{
			0: []byte("pcr0"),
			1: []byte("pcr1"),
		}

		verified, err := adapter.Verify(ctx, "device-1", []byte("nonce"), expectedPCRs)

		require.NoError(t, err)
		assert.True(t, verified)
	})

	t.Run("nil identity from provider is allowed", func(t *testing.T) {
		verifier := newMockVMVerifier()
		provider := &mockQuoteProvider{
			quote:    createTestQuote(),
			identity: nil,
		}

		adapter, err := NewVMAttestationAdapter(verifier, WithQuoteProvider(provider))
		require.NoError(t, err)

		verified, err := adapter.Verify(ctx, "device-1", []byte("nonce"), nil)

		require.NoError(t, err)
		assert.True(t, verified)
	})
}

// =============================================================================
// DirectQuoteVerifier Tests
// =============================================================================

func TestNewDirectQuoteVerifier(t *testing.T) {
	t.Run("nil verifier returns error", func(t *testing.T) {
		verifier, err := NewDirectQuoteVerifier(nil)

		assert.Nil(t, verifier)
		assert.Error(t, err)
		assert.IsType(t, ErrInvalidConfig{}, err)

		configErr := err.(ErrInvalidConfig)
		assert.Equal(t, "verifier", configErr.Field)
		assert.Contains(t, configErr.Reason, "cannot be nil")
	})

	t.Run("successful creation", func(t *testing.T) {
		mockVerifier := newMockVMVerifier()
		verifier, err := NewDirectQuoteVerifier(mockVerifier)

		require.NoError(t, err)
		assert.NotNil(t, verifier)
		assert.NotNil(t, verifier.verifier)
		assert.NotNil(t, verifier.logger)
	})

	t.Run("with logger option", func(t *testing.T) {
		mockVerifier := newMockVMVerifier()
		logger := slog.Default()

		verifier, err := NewDirectQuoteVerifier(mockVerifier, WithDirectVerifierLogger(logger))

		require.NoError(t, err)
		assert.NotNil(t, verifier)
		assert.Equal(t, logger, verifier.logger)
	})

	t.Run("nil logger defaults to slog.Default", func(t *testing.T) {
		mockVerifier := newMockVMVerifier()
		verifier, err := NewDirectQuoteVerifier(mockVerifier, WithDirectVerifierLogger(nil))

		require.NoError(t, err)
		assert.NotNil(t, verifier)
		assert.NotNil(t, verifier.logger)
	})
}

func TestDirectQuoteVerifier_VerifyQuote(t *testing.T) {
	ctx := context.Background()

	t.Run("successful verification", func(t *testing.T) {
		mockVerifier := newMockVMVerifier()
		mockVerifier.verifyQuoteResult = &vm.VerificationResult{
			Status:         vm.VerificationStatusVerified,
			SignatureValid: true,
			NonceValid:     true,
			PCRsValid:      true,
		}

		verifier, err := NewDirectQuoteVerifier(mockVerifier)
		require.NoError(t, err)

		quote := createTestQuote()
		identity := createTestIdentity()

		verified, err := verifier.VerifyQuote(ctx, quote, identity, []byte("nonce"), nil)

		require.NoError(t, err)
		assert.True(t, verified)
		assert.True(t, mockVerifier.verifyQuoteCalled)
	})

	t.Run("verification fails with failed status", func(t *testing.T) {
		mockVerifier := newMockVMVerifier()
		mockVerifier.verifyQuoteResult = &vm.VerificationResult{
			Status:         vm.VerificationStatusFailed,
			SignatureValid: false,
			NonceValid:     true,
			PCRsValid:      true,
		}

		verifier, err := NewDirectQuoteVerifier(mockVerifier)
		require.NoError(t, err)

		quote := createTestQuote()
		identity := createTestIdentity()

		verified, err := verifier.VerifyQuote(ctx, quote, identity, []byte("nonce"), nil)

		require.NoError(t, err)
		assert.False(t, verified)
	})

	t.Run("nil quote returns error", func(t *testing.T) {
		mockVerifier := newMockVMVerifier()
		verifier, err := NewDirectQuoteVerifier(mockVerifier)
		require.NoError(t, err)

		verified, err := verifier.VerifyQuote(ctx, nil, createTestIdentity(), []byte("nonce"), nil)

		assert.False(t, verified)
		assert.Error(t, err)
		assert.IsType(t, ErrInvalidConfig{}, err)

		configErr := err.(ErrInvalidConfig)
		assert.Equal(t, "quote", configErr.Field)
		assert.Contains(t, configErr.Reason, "cannot be nil")
	})

	t.Run("verification error returns attestation failure", func(t *testing.T) {
		mockVerifier := newMockVMVerifier()
		mockVerifier.verifyQuoteError = errors.New("verification internal error")

		verifier, err := NewDirectQuoteVerifier(mockVerifier)
		require.NoError(t, err)

		quote := createTestQuote()
		identity := createTestIdentity()

		verified, err := verifier.VerifyQuote(ctx, quote, identity, []byte("nonce"), nil)

		assert.False(t, verified)
		assert.Error(t, err)
		assert.IsType(t, ErrAttestFailed{}, err)

		attestErr := err.(ErrAttestFailed)
		assert.Contains(t, attestErr.Reason, "verification failed")
	})

	t.Run("context cancellation returns error", func(t *testing.T) {
		mockVerifier := newMockVMVerifier()
		verifier, err := NewDirectQuoteVerifier(mockVerifier)
		require.NoError(t, err)

		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		quote := createTestQuote()
		identity := createTestIdentity()

		verified, err := verifier.VerifyQuote(cancelCtx, quote, identity, []byte("nonce"), nil)

		assert.False(t, verified)
		assert.Error(t, err)
		assert.IsType(t, ErrContextCanceled{}, err)

		cancelErr := err.(ErrContextCanceled)
		assert.Equal(t, "VerifyQuote", cancelErr.Operation)
	})

	t.Run("with expected PCRs", func(t *testing.T) {
		mockVerifier := newMockVMVerifier()
		verifier, err := NewDirectQuoteVerifier(mockVerifier)
		require.NoError(t, err)

		quote := createTestQuote()
		identity := createTestIdentity()
		expectedPCRs := map[int][]byte{
			0: []byte("pcr0"),
			1: []byte("pcr1"),
		}

		verified, err := verifier.VerifyQuote(ctx, quote, identity, []byte("nonce"), expectedPCRs)

		require.NoError(t, err)
		assert.True(t, verified)
	})

	t.Run("nil identity is allowed", func(t *testing.T) {
		mockVerifier := newMockVMVerifier()
		verifier, err := NewDirectQuoteVerifier(mockVerifier)
		require.NoError(t, err)

		quote := createTestQuote()

		verified, err := verifier.VerifyQuote(ctx, quote, nil, []byte("nonce"), nil)

		require.NoError(t, err)
		assert.True(t, verified)
	})

	t.Run("empty expected nonce is allowed", func(t *testing.T) {
		mockVerifier := newMockVMVerifier()
		verifier, err := NewDirectQuoteVerifier(mockVerifier)
		require.NoError(t, err)

		quote := createTestQuote()
		identity := createTestIdentity()

		verified, err := verifier.VerifyQuote(ctx, quote, identity, nil, nil)

		require.NoError(t, err)
		assert.True(t, verified)
	})
}

// =============================================================================
// InMemoryQuoteStore Tests
// =============================================================================

func TestNewInMemoryQuoteStore(t *testing.T) {
	t.Run("creates store with initialized maps", func(t *testing.T) {
		store := NewInMemoryQuoteStore()

		assert.NotNil(t, store)
		assert.NotNil(t, store.quotes)
		assert.NotNil(t, store.identities)
		assert.NotNil(t, store.logger)
		assert.Empty(t, store.quotes)
		assert.Empty(t, store.identities)
	})
}

func TestInMemoryQuoteStore_StoreQuote(t *testing.T) {
	t.Run("store quote with identity", func(t *testing.T) {
		store := NewInMemoryQuoteStore()
		quote := createTestQuote()
		identity := createTestIdentity()
		nonce := []byte("test-nonce")

		store.StoreQuote("device-1", quote, identity, nonce)

		assert.Len(t, store.quotes, 1)
		assert.Len(t, store.identities, 1)

		storedQuote := store.quotes["device-1"]
		assert.NotNil(t, storedQuote)
		assert.Equal(t, quote, storedQuote.quote)
		assert.Equal(t, nonce, storedQuote.nonce)

		storedIdentity := store.identities["device-1"]
		assert.Equal(t, identity, storedIdentity)
	})

	t.Run("store quote without identity", func(t *testing.T) {
		store := NewInMemoryQuoteStore()
		quote := createTestQuote()
		nonce := []byte("test-nonce")

		store.StoreQuote("device-1", quote, nil, nonce)

		assert.Len(t, store.quotes, 1)
		assert.Len(t, store.identities, 0)

		storedQuote := store.quotes["device-1"]
		assert.NotNil(t, storedQuote)
		assert.Equal(t, quote, storedQuote.quote)
	})

	t.Run("overwrite existing quote", func(t *testing.T) {
		store := NewInMemoryQuoteStore()
		quote1 := createTestQuote()
		quote1.Nonce = []byte("nonce-1")

		quote2 := createTestQuote()
		quote2.Nonce = []byte("nonce-2")

		store.StoreQuote("device-1", quote1, nil, []byte("nonce-1"))
		store.StoreQuote("device-1", quote2, nil, []byte("nonce-2"))

		assert.Len(t, store.quotes, 1)

		storedQuote := store.quotes["device-1"]
		assert.Equal(t, []byte("nonce-2"), storedQuote.nonce)
	})

	t.Run("store multiple devices", func(t *testing.T) {
		store := NewInMemoryQuoteStore()
		quote := createTestQuote()

		store.StoreQuote("device-1", quote, createTestIdentity(), []byte("nonce-1"))
		store.StoreQuote("device-2", quote, createTestIdentity(), []byte("nonce-2"))
		store.StoreQuote("device-3", quote, nil, []byte("nonce-3"))

		assert.Len(t, store.quotes, 3)
		assert.Len(t, store.identities, 2)
	})
}

func TestInMemoryQuoteStore_GetQuote(t *testing.T) {
	ctx := context.Background()

	t.Run("get existing quote", func(t *testing.T) {
		store := NewInMemoryQuoteStore()
		quote := createTestQuote()
		identity := createTestIdentity()
		nonce := []byte("test-nonce")

		store.StoreQuote("device-1", quote, identity, nonce)

		retrievedQuote, retrievedIdentity, err := store.GetQuote(ctx, "device-1", nonce)

		require.NoError(t, err)
		assert.Equal(t, quote, retrievedQuote)
		assert.Equal(t, identity, retrievedIdentity)
	})

	t.Run("get quote not found", func(t *testing.T) {
		store := NewInMemoryQuoteStore()

		quote, identity, err := store.GetQuote(ctx, "non-existent", []byte("nonce"))

		assert.Nil(t, quote)
		assert.Nil(t, identity)
		assert.Error(t, err)
		assert.IsType(t, ErrAttestFailed{}, err)

		attestErr := err.(ErrAttestFailed)
		assert.Equal(t, "non-existent", attestErr.DeviceID)
		assert.Contains(t, attestErr.Reason, "no quote found")
	})

	t.Run("nonce mismatch returns error", func(t *testing.T) {
		store := NewInMemoryQuoteStore()
		quote := createTestQuote()
		identity := createTestIdentity()

		store.StoreQuote("device-1", quote, identity, []byte("stored-nonce"))

		retrievedQuote, retrievedIdentity, err := store.GetQuote(ctx, "device-1", []byte("different-nonce"))

		assert.Nil(t, retrievedQuote)
		assert.Nil(t, retrievedIdentity)
		assert.Error(t, err)
		assert.IsType(t, ErrAttestFailed{}, err)

		attestErr := err.(ErrAttestFailed)
		assert.Equal(t, "device-1", attestErr.DeviceID)
		assert.Contains(t, attestErr.Reason, "nonce mismatch")
	})

	t.Run("empty nonce skips verification", func(t *testing.T) {
		store := NewInMemoryQuoteStore()
		quote := createTestQuote()
		identity := createTestIdentity()

		store.StoreQuote("device-1", quote, identity, []byte("stored-nonce"))

		retrievedQuote, retrievedIdentity, err := store.GetQuote(ctx, "device-1", nil)

		require.NoError(t, err)
		assert.Equal(t, quote, retrievedQuote)
		assert.Equal(t, identity, retrievedIdentity)
	})

	t.Run("empty stored nonce skips verification", func(t *testing.T) {
		store := NewInMemoryQuoteStore()
		quote := createTestQuote()
		identity := createTestIdentity()

		store.StoreQuote("device-1", quote, identity, nil)

		retrievedQuote, retrievedIdentity, err := store.GetQuote(ctx, "device-1", []byte("request-nonce"))

		require.NoError(t, err)
		assert.Equal(t, quote, retrievedQuote)
		assert.Equal(t, identity, retrievedIdentity)
	})

	t.Run("context cancellation returns error", func(t *testing.T) {
		store := NewInMemoryQuoteStore()
		quote := createTestQuote()

		store.StoreQuote("device-1", quote, nil, []byte("nonce"))

		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		retrievedQuote, retrievedIdentity, err := store.GetQuote(cancelCtx, "device-1", []byte("nonce"))

		assert.Nil(t, retrievedQuote)
		assert.Nil(t, retrievedIdentity)
		assert.Error(t, err)
		assert.IsType(t, ErrContextCanceled{}, err)

		cancelErr := err.(ErrContextCanceled)
		assert.Equal(t, "GetQuote", cancelErr.Operation)
	})

	t.Run("get quote without identity returns nil identity", func(t *testing.T) {
		store := NewInMemoryQuoteStore()
		quote := createTestQuote()

		store.StoreQuote("device-1", quote, nil, []byte("nonce"))

		retrievedQuote, retrievedIdentity, err := store.GetQuote(ctx, "device-1", []byte("nonce"))

		require.NoError(t, err)
		assert.Equal(t, quote, retrievedQuote)
		assert.Nil(t, retrievedIdentity)
	})
}

func TestInMemoryQuoteStore_DeleteQuote(t *testing.T) {
	t.Run("delete existing quote", func(t *testing.T) {
		store := NewInMemoryQuoteStore()
		quote := createTestQuote()
		identity := createTestIdentity()

		store.StoreQuote("device-1", quote, identity, []byte("nonce"))
		assert.Len(t, store.quotes, 1)
		assert.Len(t, store.identities, 1)

		store.DeleteQuote("device-1")

		assert.Len(t, store.quotes, 0)
		assert.Len(t, store.identities, 0)
	})

	t.Run("delete non-existent quote", func(t *testing.T) {
		store := NewInMemoryQuoteStore()

		// Should not panic or error
		store.DeleteQuote("non-existent")

		assert.Len(t, store.quotes, 0)
		assert.Len(t, store.identities, 0)
	})

	t.Run("delete one of multiple quotes", func(t *testing.T) {
		store := NewInMemoryQuoteStore()
		quote := createTestQuote()

		store.StoreQuote("device-1", quote, createTestIdentity(), []byte("nonce-1"))
		store.StoreQuote("device-2", quote, createTestIdentity(), []byte("nonce-2"))
		assert.Len(t, store.quotes, 2)

		store.DeleteQuote("device-1")

		assert.Len(t, store.quotes, 1)
		assert.Contains(t, store.quotes, "device-2")
		assert.NotContains(t, store.quotes, "device-1")
	})

	t.Run("delete quote without identity", func(t *testing.T) {
		store := NewInMemoryQuoteStore()
		quote := createTestQuote()

		store.StoreQuote("device-1", quote, nil, []byte("nonce"))
		assert.Len(t, store.quotes, 1)
		assert.Len(t, store.identities, 0)

		store.DeleteQuote("device-1")

		assert.Len(t, store.quotes, 0)
		assert.Len(t, store.identities, 0)
	})
}

func TestInMemoryQuoteStore_Clear(t *testing.T) {
	t.Run("clear all quotes", func(t *testing.T) {
		store := NewInMemoryQuoteStore()
		quote := createTestQuote()

		store.StoreQuote("device-1", quote, createTestIdentity(), []byte("nonce-1"))
		store.StoreQuote("device-2", quote, createTestIdentity(), []byte("nonce-2"))
		store.StoreQuote("device-3", quote, createTestIdentity(), []byte("nonce-3"))

		assert.Len(t, store.quotes, 3)
		assert.Len(t, store.identities, 3)

		store.Clear()

		assert.Len(t, store.quotes, 0)
		assert.Len(t, store.identities, 0)
	})

	t.Run("clear empty store", func(t *testing.T) {
		store := NewInMemoryQuoteStore()

		// Should not panic
		store.Clear()

		assert.Len(t, store.quotes, 0)
		assert.Len(t, store.identities, 0)
	})

	t.Run("store works after clear", func(t *testing.T) {
		store := NewInMemoryQuoteStore()
		quote := createTestQuote()

		store.StoreQuote("device-1", quote, createTestIdentity(), []byte("nonce-1"))
		store.Clear()

		store.StoreQuote("device-2", quote, createTestIdentity(), []byte("nonce-2"))

		assert.Len(t, store.quotes, 1)
		assert.Contains(t, store.quotes, "device-2")
	})
}

// =============================================================================
// bytesEqual Tests
// =============================================================================

func TestBytesEqual(t *testing.T) {
	t.Run("equal slices", func(t *testing.T) {
		a := []byte{1, 2, 3, 4, 5}
		b := []byte{1, 2, 3, 4, 5}

		assert.True(t, bytesEqual(a, b))
	})

	t.Run("not equal slices", func(t *testing.T) {
		a := []byte{1, 2, 3, 4, 5}
		b := []byte{1, 2, 3, 4, 6}

		assert.False(t, bytesEqual(a, b))
	})

	t.Run("different lengths", func(t *testing.T) {
		a := []byte{1, 2, 3, 4, 5}
		b := []byte{1, 2, 3}

		assert.False(t, bytesEqual(a, b))
	})

	t.Run("empty slices", func(t *testing.T) {
		a := []byte{}
		b := []byte{}

		assert.True(t, bytesEqual(a, b))
	})

	t.Run("nil slices", func(t *testing.T) {
		var a []byte
		var b []byte

		assert.True(t, bytesEqual(a, b))
	})

	t.Run("one nil one empty", func(t *testing.T) {
		var a []byte
		b := []byte{}

		// Both have length 0, so they are equal
		assert.True(t, bytesEqual(a, b))
	})

	t.Run("one nil one non-empty", func(t *testing.T) {
		var a []byte
		b := []byte{1, 2, 3}

		assert.False(t, bytesEqual(a, b))
	})

	t.Run("single byte equal", func(t *testing.T) {
		a := []byte{42}
		b := []byte{42}

		assert.True(t, bytesEqual(a, b))
	})

	t.Run("single byte not equal", func(t *testing.T) {
		a := []byte{42}
		b := []byte{43}

		assert.False(t, bytesEqual(a, b))
	})

	t.Run("first byte different", func(t *testing.T) {
		a := []byte{1, 2, 3, 4, 5}
		b := []byte{0, 2, 3, 4, 5}

		assert.False(t, bytesEqual(a, b))
	})

	t.Run("last byte different", func(t *testing.T) {
		a := []byte{1, 2, 3, 4, 5}
		b := []byte{1, 2, 3, 4, 0}

		assert.False(t, bytesEqual(a, b))
	})

	t.Run("middle byte different", func(t *testing.T) {
		a := []byte{1, 2, 3, 4, 5}
		b := []byte{1, 2, 0, 4, 5}

		assert.False(t, bytesEqual(a, b))
	})
}

// =============================================================================
// Integration Tests - VMAttestationAdapter with InMemoryQuoteStore
// =============================================================================

func TestVMAttestationAdapter_WithInMemoryQuoteStore(t *testing.T) {
	ctx := context.Background()

	t.Run("full verification flow", func(t *testing.T) {
		// Setup verifier
		verifier := newMockVMVerifier()
		verifier.verifyQuoteResult = &vm.VerificationResult{
			Status:         vm.VerificationStatusVerified,
			SignatureValid: true,
			NonceValid:     true,
			PCRsValid:      true,
		}

		// Setup quote store
		store := NewInMemoryQuoteStore()
		quote := createTestQuote()
		identity := createTestIdentity()
		nonce := []byte("test-nonce")

		store.StoreQuote("device-1", quote, identity, nonce)

		// Setup adapter
		adapter, err := NewVMAttestationAdapter(verifier, WithQuoteProvider(store))
		require.NoError(t, err)

		// Verify
		verified, err := adapter.Verify(ctx, "device-1", nonce, nil)

		require.NoError(t, err)
		assert.True(t, verified)
		assert.True(t, verifier.verifyQuoteCalled)
	})

	t.Run("verification with nonce mismatch", func(t *testing.T) {
		verifier := newMockVMVerifier()
		store := NewInMemoryQuoteStore()
		quote := createTestQuote()

		store.StoreQuote("device-1", quote, nil, []byte("stored-nonce"))

		adapter, err := NewVMAttestationAdapter(verifier, WithQuoteProvider(store))
		require.NoError(t, err)

		verified, err := adapter.Verify(ctx, "device-1", []byte("different-nonce"), nil)

		assert.False(t, verified)
		assert.Error(t, err)
		assert.IsType(t, ErrAttestFailed{}, err)
	})

	t.Run("verification after quote deletion", func(t *testing.T) {
		verifier := newMockVMVerifier()
		store := NewInMemoryQuoteStore()
		quote := createTestQuote()

		store.StoreQuote("device-1", quote, nil, []byte("nonce"))
		store.DeleteQuote("device-1")

		adapter, err := NewVMAttestationAdapter(verifier, WithQuoteProvider(store))
		require.NoError(t, err)

		verified, err := adapter.Verify(ctx, "device-1", []byte("nonce"), nil)

		assert.False(t, verified)
		assert.Error(t, err)
		assert.IsType(t, ErrAttestFailed{}, err)
	})

	t.Run("verification after store clear", func(t *testing.T) {
		verifier := newMockVMVerifier()
		store := NewInMemoryQuoteStore()
		quote := createTestQuote()

		store.StoreQuote("device-1", quote, nil, []byte("nonce"))
		store.Clear()

		adapter, err := NewVMAttestationAdapter(verifier, WithQuoteProvider(store))
		require.NoError(t, err)

		verified, err := adapter.Verify(ctx, "device-1", []byte("nonce"), nil)

		assert.False(t, verified)
		assert.Error(t, err)
	})
}

// =============================================================================
// Option Function Tests
// =============================================================================

func TestWithVMAdapterLogger(t *testing.T) {
	t.Run("sets logger", func(t *testing.T) {
		logger := slog.Default()
		adapter := &VMAttestationAdapter{}

		opt := WithVMAdapterLogger(logger)
		opt(adapter)

		assert.Equal(t, logger, adapter.logger)
	})
}

func TestWithQuoteProvider(t *testing.T) {
	t.Run("sets quote provider", func(t *testing.T) {
		provider := &mockQuoteProvider{}
		adapter := &VMAttestationAdapter{}

		opt := WithQuoteProvider(provider)
		opt(adapter)

		assert.Equal(t, provider, adapter.quoteProvider)
	})
}

func TestWithDirectVerifierLogger(t *testing.T) {
	t.Run("sets logger", func(t *testing.T) {
		logger := slog.Default()
		verifier := &DirectQuoteVerifier{}

		opt := WithDirectVerifierLogger(logger)
		opt(verifier)

		assert.Equal(t, logger, verifier.logger)
	})
}

// =============================================================================
// Interface Compliance Tests
// =============================================================================

func TestInterfaceCompliance(t *testing.T) {
	t.Run("VMAttestationAdapter implements AttestationVerifier", func(t *testing.T) {
		var _ AttestationVerifier = (*VMAttestationAdapter)(nil)
	})

	t.Run("InMemoryQuoteStore implements QuoteProvider", func(t *testing.T) {
		var _ QuoteProvider = (*InMemoryQuoteStore)(nil)
	})
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestEdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("adapter verify with empty nonce", func(t *testing.T) {
		verifier := newMockVMVerifier()
		provider := &mockQuoteProvider{
			quote:    createTestQuote(),
			identity: createTestIdentity(),
		}

		adapter, err := NewVMAttestationAdapter(verifier, WithQuoteProvider(provider))
		require.NoError(t, err)

		verified, err := adapter.Verify(ctx, "device-1", nil, nil)

		require.NoError(t, err)
		assert.True(t, verified)
	})

	t.Run("store quote with nil quote", func(t *testing.T) {
		store := NewInMemoryQuoteStore()

		// Should not panic
		store.StoreQuote("device-1", nil, nil, []byte("nonce"))

		assert.Len(t, store.quotes, 1)
	})

	t.Run("get stored nil quote", func(t *testing.T) {
		store := NewInMemoryQuoteStore()
		store.StoreQuote("device-1", nil, nil, nil)

		quote, identity, err := store.GetQuote(ctx, "device-1", nil)

		require.NoError(t, err)
		assert.Nil(t, quote)
		assert.Nil(t, identity)
	})

	t.Run("direct verifier with unknown status", func(t *testing.T) {
		mockVerifier := newMockVMVerifier()
		mockVerifier.verifyQuoteResult = &vm.VerificationResult{
			Status: vm.VerificationStatusUnknown,
		}

		verifier, err := NewDirectQuoteVerifier(mockVerifier)
		require.NoError(t, err)

		quote := createTestQuote()

		verified, err := verifier.VerifyQuote(ctx, quote, nil, nil, nil)

		require.NoError(t, err)
		assert.False(t, verified)
	})

	t.Run("direct verifier with pending status", func(t *testing.T) {
		mockVerifier := newMockVMVerifier()
		mockVerifier.verifyQuoteResult = &vm.VerificationResult{
			Status: vm.VerificationStatusPending,
		}

		verifier, err := NewDirectQuoteVerifier(mockVerifier)
		require.NoError(t, err)

		quote := createTestQuote()

		verified, err := verifier.VerifyQuote(ctx, quote, nil, nil, nil)

		require.NoError(t, err)
		assert.False(t, verified)
	})
}
