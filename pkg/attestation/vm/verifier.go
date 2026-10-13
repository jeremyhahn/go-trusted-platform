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
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"sync/atomic"
	"time"
)

// VMVerifier provides TPM quote verification capabilities.
type VMVerifier interface {
	// Initialize sets up the verifier with the given configuration.
	Initialize(ctx context.Context, config *VerifierConfig) error

	// VerifyQuote verifies a TPM quote and returns the verification result.
	VerifyQuote(ctx context.Context, request *VerifyRequest) (*VerificationResult, error)

	// VerifyAttestation verifies a complete VM attestation.
	VerifyAttestation(ctx context.Context, attestation *VMAttestation, expectedPCRs map[int][]byte, expectedNonce []byte) (*VerificationResult, error)

	// VerifyEKCertificate verifies the EK certificate chain.
	VerifyEKCertificate(ctx context.Context, identity *VMIdentity) error

	// Close releases resources held by the verifier.
	Close() error
}

// vmVerifier is the concrete implementation of VMVerifier.
type vmVerifier struct {
	initialized atomic.Bool
	closed      atomic.Bool
	config      *VerifierConfig
	certPool    *x509.CertPool
	logger      *slog.Logger
}

// VMVerifierOption configures a VM verifier.
type VMVerifierOption func(*vmVerifier)

// WithVerifierLogger sets the logger for the verifier.
func WithVerifierLogger(logger *slog.Logger) VMVerifierOption {
	return func(v *vmVerifier) {
		v.logger = logger
	}
}

// NewVMVerifier creates a new VM verifier with the given options.
func NewVMVerifier(opts ...VMVerifierOption) VMVerifier {
	v := &vmVerifier{}

	for _, opt := range opts {
		opt(v)
	}

	if v.logger == nil {
		v.logger = slog.Default()
	}

	return v
}

// Initialize sets up the verifier with the given configuration.
func (v *vmVerifier) Initialize(ctx context.Context, config *VerifierConfig) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "Initialize"}
	default:
	}

	if v.initialized.Load() {
		return ErrInvalidConfig{Reason: "verifier already initialized"}
	}

	if config == nil {
		return ErrInvalidConfig{Reason: "configuration cannot be nil"}
	}

	if err := config.Validate(); err != nil {
		return err
	}

	// Build certificate pool for chain validation
	certPool := x509.NewCertPool()
	certPool.AddCert(config.PlatformCACert)
	for _, cert := range config.TrustedRoots {
		certPool.AddCert(cert)
	}

	v.config = config
	v.certPool = certPool
	v.initialized.Store(true)

	v.logger.Info("VM verifier initialized",
		"max_quote_age", config.MaxQuoteAge,
		"require_host_binding", config.RequireHostBinding,
		"allowed_hosts", len(config.AllowedHostIDs),
	)

	return nil
}

// VerifyQuote verifies a TPM quote and returns the verification result.
func (v *vmVerifier) VerifyQuote(ctx context.Context, request *VerifyRequest) (*VerificationResult, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "VerifyQuote"}
	default:
	}

	if !v.initialized.Load() {
		return nil, ErrVerifierNotInitialized{}
	}

	if v.closed.Load() {
		return nil, ErrVerifierNotInitialized{}
	}

	if request == nil {
		return nil, ErrInvalidConfig{Reason: "verify request cannot be nil"}
	}

	if err := request.Validate(); err != nil {
		return nil, err
	}

	result := &VerificationResult{
		Status:     VerificationStatusPending,
		VerifiedAt: time.Now().UTC(),
	}

	// Verify quote signature
	sigValid, sigErr := v.verifySignature(ctx, request.Quote)
	result.SignatureValid = sigValid
	if !sigValid {
		result.AddError("signature verification failed: " + sigErr.Error())
	}

	// Verify certificate chain
	chainValid, chainErr := v.verifyCertificateChain(ctx, request.Identity)
	result.CertificateChainValid = chainValid
	if !chainValid && chainErr != nil {
		result.AddError("certificate chain verification failed: " + chainErr.Error())
	}

	// Verify nonce
	nonceValid := bytes.Equal(request.Quote.Nonce, request.ExpectedNonce)
	result.NonceValid = nonceValid
	if !nonceValid {
		result.AddError("nonce mismatch")
	}

	// Verify PCR values
	pcrsValid, pcrMismatches := v.verifyPCRs(request.Quote.PCRs, request.ExpectedPCRs)
	result.PCRsValid = pcrsValid
	result.PCRMismatches = pcrMismatches
	if !pcrsValid {
		for _, mismatch := range pcrMismatches {
			result.AddError("PCR " + string(rune('0'+mismatch.Index)) + " mismatch")
		}
	}

	// Verify host binding if required
	if v.config.RequireHostBinding && request.ExpectedHostID != "" {
		hostValid := request.Identity.HostID == request.ExpectedHostID
		result.HostBindingValid = hostValid
		if !hostValid {
			result.AddError("host binding mismatch: expected " + request.ExpectedHostID + ", got " + request.Identity.HostID)
		}
	} else {
		result.HostBindingValid = true
	}

	// Verify timestamp if max age is configured
	if request.MaxQuoteAge > 0 {
		age := time.Since(request.Quote.Timestamp).Seconds()
		timestampValid := int64(age) <= request.MaxQuoteAge
		result.TimestampValid = timestampValid
		if !timestampValid {
			result.AddError("quote expired")
		}
	} else {
		result.TimestampValid = true
	}

	// Determine overall status
	if result.SignatureValid && result.CertificateChainValid && result.NonceValid &&
		result.PCRsValid && result.HostBindingValid && result.TimestampValid {
		result.Status = VerificationStatusVerified
	} else {
		result.Status = VerificationStatusFailed
	}

	v.logger.Info("quote verified",
		"status", result.Status,
		"signature_valid", result.SignatureValid,
		"chain_valid", result.CertificateChainValid,
		"nonce_valid", result.NonceValid,
		"pcrs_valid", result.PCRsValid,
		"host_binding_valid", result.HostBindingValid,
		"timestamp_valid", result.TimestampValid,
	)

	return result, nil
}

// VerifyAttestation verifies a complete VM attestation.
func (v *vmVerifier) VerifyAttestation(ctx context.Context, attestation *VMAttestation, expectedPCRs map[int][]byte, expectedNonce []byte) (*VerificationResult, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "VerifyAttestation"}
	default:
	}

	if !v.initialized.Load() {
		return nil, ErrVerifierNotInitialized{}
	}

	if attestation == nil {
		return nil, ErrInvalidConfig{Reason: "attestation cannot be nil"}
	}

	if err := attestation.Validate(); err != nil {
		return nil, err
	}

	// Build verify request from attestation
	request := &VerifyRequest{
		Quote:          attestation.Quote,
		Identity:       attestation.Identity,
		ExpectedNonce:  expectedNonce,
		ExpectedPCRs:   expectedPCRs,
		PlatformCACert: v.config.PlatformCACert,
		MaxQuoteAge:    v.config.MaxQuoteAge,
	}

	// Verify the quote
	result, err := v.VerifyQuote(ctx, request)
	if err != nil {
		return nil, err
	}

	// Update attestation with verification result
	attestation.VerificationResult = result

	v.logger.Info("attestation verified",
		"vm_id", attestation.Identity.VMID,
		"host_id", attestation.Identity.HostID,
		"status", result.Status,
	)

	return result, nil
}

// VerifyEKCertificate verifies the EK certificate chain.
func (v *vmVerifier) VerifyEKCertificate(ctx context.Context, identity *VMIdentity) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "VerifyEKCertificate"}
	default:
	}

	if !v.initialized.Load() {
		return ErrVerifierNotInitialized{}
	}

	if identity == nil {
		return ErrInvalidVMIdentity{Reason: "identity cannot be nil"}
	}

	if identity.EKCertificate == nil {
		return ErrEKCertificateInvalid{Reason: "EK certificate is nil"}
	}

	valid, err := v.verifyCertificateChain(ctx, identity)
	if !valid {
		if err != nil {
			return err
		}
		return ErrCertificateChainInvalid{Reason: "certificate chain validation failed"}
	}

	return nil
}

// Close releases resources held by the verifier.
func (v *vmVerifier) Close() error {
	if v.closed.Swap(true) {
		return nil
	}

	v.logger.Info("VM verifier closed")
	return nil
}

// verifySignature verifies the TPM quote signature under the scheme the quote
// declares in SignatureAlgorithm, never one inferred from the AIK key type.
func (v *vmVerifier) verifySignature(ctx context.Context, quote *VMQuote) (bool, error) {
	err := VerifyQuoteSignatureWithAlgorithm(quote.AIKPublicKey, quote.QuoteData, quote.Signature, quote.SignatureAlgorithm)
	if err != nil {
		return false, err
	}
	return true, nil
}

// verifyCertificateChain verifies the EK certificate chain.
func (v *vmVerifier) verifyCertificateChain(ctx context.Context, identity *VMIdentity) (bool, error) {
	if identity.EKCertificate == nil {
		return false, ErrEKCertificateInvalid{Reason: "EK certificate is nil"}
	}

	// Build intermediate certificate pool if available
	intermediatePool := x509.NewCertPool()
	for _, cert := range identity.EKCertificateChain {
		intermediatePool.AddCert(cert)
	}

	// Verify the certificate chain
	opts := x509.VerifyOptions{
		Roots:         v.certPool,
		Intermediates: intermediatePool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err := identity.EKCertificate.Verify(opts)
	if err != nil {
		return false, ErrCertificateChainInvalid{
			Reason: "certificate chain verification failed",
			Cause:  err,
		}
	}

	// Verify the certificate CN contains valid VM identity
	cn := identity.EKCertificate.Subject.CommonName
	parsedIdentity, err := ParseCN(cn)
	if err != nil {
		return false, err
	}

	// Verify parsed identity matches provided identity
	if parsedIdentity.VMID != identity.VMID || parsedIdentity.HostID != identity.HostID {
		return false, ErrInvalidVMIdentity{
			VMID:   identity.VMID,
			HostID: identity.HostID,
			Reason: "certificate CN does not match provided identity",
		}
	}

	// Verify host is in allowed list if configured
	if len(v.config.AllowedHostIDs) > 0 {
		allowed := false
		for _, hostID := range v.config.AllowedHostIDs {
			if hostID == identity.HostID {
				allowed = true
				break
			}
		}
		if !allowed {
			return false, ErrHostBindingInvalid{
				ExpectedHostID: "one of allowed hosts",
				ActualHostID:   identity.HostID,
			}
		}
	}

	return true, nil
}

// verifyPCRs verifies PCR values match expected values.
func (v *vmVerifier) verifyPCRs(actualPCRs []PCRValue, expectedPCRs map[int][]byte) (bool, []PCRMismatchDetail) {
	if len(expectedPCRs) == 0 {
		// No expected PCRs specified, skip verification
		return true, nil
	}

	var mismatches []PCRMismatchDetail

	for _, pcr := range actualPCRs {
		expected, ok := expectedPCRs[pcr.Index]
		if !ok {
			// This PCR is not in the expected list, skip it
			continue
		}

		if !bytes.Equal(pcr.Value, expected) {
			mismatches = append(mismatches, PCRMismatchDetail{
				Index:    pcr.Index,
				Expected: expected,
				Actual:   pcr.Value,
			})
		}
	}

	return len(mismatches) == 0, mismatches
}

// parsePublicKey parses a public key from DER or PEM encoded data.
func parsePublicKey(data []byte) (crypto.PublicKey, error) {
	// Try DER format first
	pubKey, err := x509.ParsePKIXPublicKey(data)
	if err == nil {
		return pubKey, nil
	}

	// Try PEM format
	block, _ := pem.Decode(data)
	if block != nil {
		pubKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err == nil {
			return pubKey, nil
		}
	}

	// Try parsing as RSA public key directly
	rsaPubKey, err := x509.ParsePKCS1PublicKey(data)
	if err == nil {
		return rsaPubKey, nil
	}

	return nil, ErrSignatureInvalid{Reason: "failed to parse public key"}
}

// parseEKCertificate parses an EK certificate from DER or PEM encoded data.
func parseEKCertificate(data []byte) (*x509.Certificate, error) {
	// Try DER format first
	cert, err := x509.ParseCertificate(data)
	if err == nil {
		return cert, nil
	}

	// Try PEM format
	block, _ := pem.Decode(data)
	if block != nil && block.Type == "CERTIFICATE" {
		cert, err = x509.ParseCertificate(block.Bytes)
		if err == nil {
			return cert, nil
		}
	}

	return nil, ErrEKCertificateInvalid{
		Reason: "failed to parse EK certificate",
		Cause:  err,
	}
}
