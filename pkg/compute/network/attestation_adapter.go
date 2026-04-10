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
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
)

// QuoteProvider provides TPM quotes for device verification.
// This interface allows the adapter to retrieve quotes from various sources
// such as a quote cache, an attestation service, or direct device communication.
type QuoteProvider interface {
	// GetQuote retrieves the TPM quote for a device.
	// The nonce should be verified to match the provided value.
	GetQuote(ctx context.Context, deviceID string, nonce []byte) (*vm.VMQuote, *vm.VMIdentity, error)
}

// VMAttestationAdapter adapts the attestation/vm.VMVerifier to the
// compute/network.AttestationVerifier interface.
type VMAttestationAdapter struct {
	verifier      vm.VMVerifier
	quoteProvider QuoteProvider
	logger        *slog.Logger
}

// VMAttestationAdapterOption configures the adapter.
type VMAttestationAdapterOption func(*VMAttestationAdapter)

// WithVMAdapterLogger sets the logger for the adapter.
func WithVMAdapterLogger(logger *slog.Logger) VMAttestationAdapterOption {
	return func(a *VMAttestationAdapter) {
		a.logger = logger
	}
}

// WithQuoteProvider sets the quote provider for the adapter.
func WithQuoteProvider(provider QuoteProvider) VMAttestationAdapterOption {
	return func(a *VMAttestationAdapter) {
		a.quoteProvider = provider
	}
}

// NewVMAttestationAdapter creates a new adapter wrapping the VM verifier.
func NewVMAttestationAdapter(
	verifier vm.VMVerifier,
	opts ...VMAttestationAdapterOption,
) (*VMAttestationAdapter, error) {
	if verifier == nil {
		return nil, ErrInvalidConfig{Field: "verifier", Reason: "VM verifier cannot be nil"}
	}

	a := &VMAttestationAdapter{
		verifier: verifier,
	}

	for _, opt := range opts {
		opt(a)
	}

	if a.logger == nil {
		a.logger = slog.Default()
	}

	return a, nil
}

// Verify verifies the attestation for a device.
// It retrieves the quote from the QuoteProvider and verifies it using the VMVerifier.
func (a *VMAttestationAdapter) Verify(
	ctx context.Context,
	deviceID string,
	nonce []byte,
	expectedPCRs map[int][]byte,
) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ErrContextCanceled{Operation: "Verify"}
	default:
	}

	if deviceID == "" {
		return false, ErrInvalidConfig{Field: "deviceID", Reason: "device ID cannot be empty"}
	}

	if a.quoteProvider == nil {
		return false, ErrAttestFailed{
			DeviceID: deviceID,
			Reason:   "no quote provider configured",
		}
	}

	// Get the quote from the provider
	quote, identity, err := a.quoteProvider.GetQuote(ctx, deviceID, nonce)
	if err != nil {
		a.logger.Error("failed to get quote from provider",
			"device_id", deviceID,
			"error", err,
		)
		return false, ErrAttestFailed{
			DeviceID: deviceID,
			Reason:   "failed to get quote",
			Cause:    err,
		}
	}

	if quote == nil {
		return false, ErrAttestFailed{
			DeviceID: deviceID,
			Reason:   "quote provider returned nil quote",
		}
	}

	// Build verification request
	request := &vm.VerifyRequest{
		Quote:         quote,
		Identity:      identity,
		ExpectedNonce: nonce,
		ExpectedPCRs:  expectedPCRs,
	}

	// Verify the quote
	result, err := a.verifier.VerifyQuote(ctx, request)
	if err != nil {
		a.logger.Error("quote verification failed",
			"device_id", deviceID,
			"error", err,
		)
		return false, ErrAttestFailed{
			DeviceID: deviceID,
			Reason:   "verification failed",
			Cause:    err,
		}
	}

	verified := result.Status == vm.VerificationStatusVerified

	a.logger.Debug("attestation verification complete",
		"device_id", deviceID,
		"verified", verified,
		"status", result.Status,
		"signature_valid", result.SignatureValid,
		"nonce_valid", result.NonceValid,
		"pcrs_valid", result.PCRsValid,
	)

	return verified, nil
}

// Ensure VMAttestationAdapter implements AttestationVerifier
var _ AttestationVerifier = (*VMAttestationAdapter)(nil)

// DirectQuoteVerifier provides direct quote verification when the quote is
// already available (e.g., passed in the authentication request).
// This is useful when the quote is embedded in the authentication flow.
type DirectQuoteVerifier struct {
	verifier vm.VMVerifier
	logger   *slog.Logger
}

// DirectQuoteVerifierOption configures the verifier.
type DirectQuoteVerifierOption func(*DirectQuoteVerifier)

// WithDirectVerifierLogger sets the logger for the verifier.
func WithDirectVerifierLogger(logger *slog.Logger) DirectQuoteVerifierOption {
	return func(v *DirectQuoteVerifier) {
		v.logger = logger
	}
}

// NewDirectQuoteVerifier creates a new direct quote verifier.
func NewDirectQuoteVerifier(
	verifier vm.VMVerifier,
	opts ...DirectQuoteVerifierOption,
) (*DirectQuoteVerifier, error) {
	if verifier == nil {
		return nil, ErrInvalidConfig{Field: "verifier", Reason: "VM verifier cannot be nil"}
	}

	v := &DirectQuoteVerifier{
		verifier: verifier,
	}

	for _, opt := range opts {
		opt(v)
	}

	if v.logger == nil {
		v.logger = slog.Default()
	}

	return v, nil
}

// VerifyQuote verifies a quote directly without needing a QuoteProvider.
// This is useful when the caller already has the quote data.
func (v *DirectQuoteVerifier) VerifyQuote(
	ctx context.Context,
	quote *vm.VMQuote,
	identity *vm.VMIdentity,
	expectedNonce []byte,
	expectedPCRs map[int][]byte,
) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ErrContextCanceled{Operation: "VerifyQuote"}
	default:
	}

	if quote == nil {
		return false, ErrInvalidConfig{Field: "quote", Reason: "quote cannot be nil"}
	}

	request := &vm.VerifyRequest{
		Quote:         quote,
		Identity:      identity,
		ExpectedNonce: expectedNonce,
		ExpectedPCRs:  expectedPCRs,
	}

	result, err := v.verifier.VerifyQuote(ctx, request)
	if err != nil {
		return false, ErrAttestFailed{
			Reason: "verification failed",
			Cause:  err,
		}
	}

	verified := result.Status == vm.VerificationStatusVerified

	v.logger.Debug("direct quote verification complete",
		"verified", verified,
		"status", result.Status,
	)

	return verified, nil
}

// InMemoryQuoteStore provides a simple in-memory quote store for testing
// and development purposes.
type InMemoryQuoteStore struct {
	quotes     map[string]*storedQuote // deviceID -> stored quote
	identities map[string]*vm.VMIdentity
	logger     *slog.Logger
}

type storedQuote struct {
	quote *vm.VMQuote
	nonce []byte
}

// NewInMemoryQuoteStore creates a new in-memory quote store.
func NewInMemoryQuoteStore() *InMemoryQuoteStore {
	return &InMemoryQuoteStore{
		quotes:     make(map[string]*storedQuote),
		identities: make(map[string]*vm.VMIdentity),
		logger:     slog.Default(),
	}
}

// StoreQuote stores a quote for a device.
func (s *InMemoryQuoteStore) StoreQuote(deviceID string, quote *vm.VMQuote, identity *vm.VMIdentity, nonce []byte) {
	s.quotes[deviceID] = &storedQuote{
		quote: quote,
		nonce: nonce,
	}
	if identity != nil {
		s.identities[deviceID] = identity
	}
}

// GetQuote retrieves the quote for a device.
func (s *InMemoryQuoteStore) GetQuote(ctx context.Context, deviceID string, nonce []byte) (*vm.VMQuote, *vm.VMIdentity, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ErrContextCanceled{Operation: "GetQuote"}
	default:
	}

	stored, ok := s.quotes[deviceID]
	if !ok {
		return nil, nil, ErrAttestFailed{
			DeviceID: deviceID,
			Reason:   "no quote found for device",
		}
	}

	// Verify nonce matches if provided
	if len(nonce) > 0 && len(stored.nonce) > 0 {
		if !bytesEqual(nonce, stored.nonce) {
			return nil, nil, ErrAttestFailed{
				DeviceID: deviceID,
				Reason:   "nonce mismatch",
			}
		}
	}

	identity := s.identities[deviceID]
	return stored.quote, identity, nil
}

// DeleteQuote removes a quote for a device.
func (s *InMemoryQuoteStore) DeleteQuote(deviceID string) {
	delete(s.quotes, deviceID)
	delete(s.identities, deviceID)
}

// Clear removes all stored quotes.
func (s *InMemoryQuoteStore) Clear() {
	s.quotes = make(map[string]*storedQuote)
	s.identities = make(map[string]*vm.VMIdentity)
}

// Ensure InMemoryQuoteStore implements QuoteProvider
var _ QuoteProvider = (*InMemoryQuoteStore)(nil)

// bytesEqual compares two byte slices for equality.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
