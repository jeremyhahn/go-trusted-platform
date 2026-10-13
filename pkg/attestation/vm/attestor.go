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
	"crypto/sha256"
	"log/slog"
	"sync/atomic"
	"time"
)

// VMAttestor provides TPM quote generation capabilities for VMs using vTPM.
type VMAttestor interface {
	// Initialize sets up the attestor with the given configuration.
	Initialize(ctx context.Context, config *AttestorConfig) error

	// GenerateQuote generates a TPM quote using the vTPM's AIK/AK.
	// The quote includes the specified PCR values signed by the AIK/AK.
	GenerateQuote(ctx context.Context, request *QuoteRequest) (*VMQuote, error)

	// GetIdentity returns the VM identity from the vTPM EK certificate.
	GetIdentity(ctx context.Context) (*VMIdentity, error)

	// GetAttestation generates a full attestation including quote and identity.
	GetAttestation(ctx context.Context, request *QuoteRequest) (*VMAttestation, error)

	// ReadPCR reads a single PCR value from the vTPM.
	ReadPCR(ctx context.Context, index int, algorithm HashAlgorithm) (*PCRValue, error)

	// Close releases resources held by the attestor.
	Close() error
}

// VTPMDevice provides vTPM operations for quote generation and PCR reading.
// This interface abstracts the vTPM device to allow for testing with
// simulated vTPM implementations.
type VTPMDevice interface {
	// GenerateQuote generates a TPM quote signed by the AIK/AK.
	GenerateQuote(ctx context.Context, nonce []byte, pcrIndices []int, algorithm HashAlgorithm) (
		quoteData []byte, signature []byte, err error)

	// ReadPCR reads the current value of the specified PCR.
	ReadPCR(ctx context.Context, pcr int, algorithm HashAlgorithm) ([]byte, error)

	// GetAIKPublicKey returns the public key of the AIK/AK.
	GetAIKPublicKey(ctx context.Context) ([]byte, error)

	// GetAIKSignatureAlgorithm returns the x509.SignatureAlgorithm name of
	// the scheme the AIK/AK signs quotes under (for example "SHA256-RSAPSS").
	GetAIKSignatureAlgorithm(ctx context.Context) (string, error)

	// GetEKCertificate returns the vTPM EK certificate.
	GetEKCertificate(ctx context.Context) ([]byte, error)

	// Close releases vTPM resources.
	Close() error
}

// vmAttestor is the concrete implementation of VMAttestor.
type vmAttestor struct {
	initialized atomic.Bool
	closed      atomic.Bool
	config      *AttestorConfig
	vtpm        VTPMDevice
	logger      *slog.Logger
}

// VMAttestorOption configures a VM attestor.
type VMAttestorOption func(*vmAttestor)

// WithVTPMDevice sets the vTPM device for the attestor.
func WithVTPMDevice(vtpm VTPMDevice) VMAttestorOption {
	return func(a *vmAttestor) {
		a.vtpm = vtpm
	}
}

// WithAttestorLogger sets the logger for the attestor.
func WithAttestorLogger(logger *slog.Logger) VMAttestorOption {
	return func(a *vmAttestor) {
		a.logger = logger
	}
}

// NewVMAttestor creates a new VM attestor with the given options.
func NewVMAttestor(opts ...VMAttestorOption) VMAttestor {
	a := &vmAttestor{}

	for _, opt := range opts {
		opt(a)
	}

	if a.logger == nil {
		a.logger = slog.Default()
	}

	return a
}

// Initialize sets up the attestor with the given configuration.
func (a *vmAttestor) Initialize(ctx context.Context, config *AttestorConfig) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "Initialize"}
	default:
	}

	if a.initialized.Load() {
		return ErrInvalidConfig{Reason: "attestor already initialized"}
	}

	if config == nil {
		return ErrInvalidConfig{Reason: "configuration cannot be nil"}
	}

	if err := config.Validate(); err != nil {
		return err
	}

	if a.vtpm == nil {
		return ErrVTPMNotAvailable{Reason: "vTPM device not configured"}
	}

	// Verify vTPM is accessible by reading AIK public key
	_, err := a.vtpm.GetAIKPublicKey(ctx)
	if err != nil {
		return ErrAIKNotFound{Reason: err.Error()}
	}

	a.config = config
	a.initialized.Store(true)

	a.logger.Info("VM attestor initialized",
		"vtpm_device", config.VTPMDevicePath,
		"hash_algorithm", config.DefaultHashAlgorithm,
		"include_workload_pcr", config.IncludeWorkloadPCR,
	)

	return nil
}

// GenerateQuote generates a TPM quote using the vTPM's AIK/AK.
func (a *vmAttestor) GenerateQuote(ctx context.Context, request *QuoteRequest) (*VMQuote, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "GenerateQuote"}
	default:
	}

	if !a.initialized.Load() {
		return nil, ErrAttestorNotInitialized{}
	}

	if a.closed.Load() {
		return nil, ErrAttestorNotInitialized{}
	}

	if request == nil {
		return nil, ErrInvalidConfig{Reason: "quote request cannot be nil"}
	}

	if err := request.Validate(); err != nil {
		return nil, err
	}

	// Determine PCR indices to include
	pcrIndices := request.PCRIndices
	if a.config.IncludeWorkloadPCR {
		// Add WorkloadPCR (workload chain) if not already included
		workloadPCRIndex := a.config.GetWorkloadPCRIndex()
		hasWorkloadPCR := false
		for _, idx := range pcrIndices {
			if idx == workloadPCRIndex {
				hasWorkloadPCR = true
				break
			}
		}
		if !hasWorkloadPCR {
			pcrIndices = append(pcrIndices, workloadPCRIndex)
		}
	}

	// Generate the TPM quote
	quoteData, signature, err := a.vtpm.GenerateQuote(ctx, request.Nonce, pcrIndices, request.HashAlgorithm)
	if err != nil {
		return nil, ErrQuoteGenerationFailed{Reason: "failed to generate TPM quote", Cause: err}
	}

	// Read PCR values
	pcrs := make([]PCRValue, 0, len(pcrIndices))
	for _, idx := range pcrIndices {
		value, err := a.vtpm.ReadPCR(ctx, idx, request.HashAlgorithm)
		if err != nil {
			return nil, ErrPCRReadFailed{PCR: idx, Cause: err}
		}
		pcrs = append(pcrs, PCRValue{
			Index:     idx,
			Value:     value,
			Algorithm: request.HashAlgorithm,
		})
	}

	// Compute PCR digest
	pcrDigest := a.computePCRDigest(pcrs, request.HashAlgorithm)

	// Get AIK public key
	aikPubKey, err := a.vtpm.GetAIKPublicKey(ctx)
	if err != nil {
		return nil, ErrQuoteGenerationFailed{Reason: "failed to get AIK public key", Cause: err}
	}

	sigAlg, err := a.vtpm.GetAIKSignatureAlgorithm(ctx)
	if err != nil {
		return nil, ErrQuoteGenerationFailed{Reason: "failed to get AIK signature algorithm", Cause: err}
	}

	quote := &VMQuote{
		QuoteData:          quoteData,
		Signature:          signature,
		SignatureAlgorithm: sigAlg,
		PCRs:               pcrs,
		PCRDigest:          pcrDigest,
		Nonce:              request.Nonce,
		Timestamp:          time.Now().UTC(),
		AIKPublicKey:       aikPubKey,
		HashAlgorithm:      request.HashAlgorithm,
	}

	a.logger.Info("quote generated",
		"pcr_count", len(pcrs),
		"hash_algorithm", request.HashAlgorithm,
		"nonce_size", len(request.Nonce),
	)

	return quote, nil
}

// GetIdentity returns the VM identity from the vTPM EK certificate.
func (a *vmAttestor) GetIdentity(ctx context.Context) (*VMIdentity, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "GetIdentity"}
	default:
	}

	if !a.initialized.Load() {
		return nil, ErrAttestorNotInitialized{}
	}

	if a.closed.Load() {
		return nil, ErrAttestorNotInitialized{}
	}

	// Get EK certificate from vTPM
	ekCertBytes, err := a.vtpm.GetEKCertificate(ctx)
	if err != nil {
		return nil, ErrEKCertificateInvalid{Reason: "failed to get EK certificate", Cause: err}
	}

	// Parse EK certificate
	ekCert, err := parseEKCertificate(ekCertBytes)
	if err != nil {
		return nil, err
	}

	// Parse VM identity from certificate CN
	cn := ekCert.Subject.CommonName
	identity, err := ParseCN(cn)
	if err != nil {
		return nil, err
	}

	identity.EKCertificate = ekCert

	return identity, nil
}

// GetAttestation generates a full attestation including quote and identity.
func (a *vmAttestor) GetAttestation(ctx context.Context, request *QuoteRequest) (*VMAttestation, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "GetAttestation"}
	default:
	}

	if !a.initialized.Load() {
		return nil, ErrAttestorNotInitialized{}
	}

	// Get VM identity
	identity, err := a.GetIdentity(ctx)
	if err != nil {
		return nil, err
	}

	// Generate quote
	quote, err := a.GenerateQuote(ctx, request)
	if err != nil {
		return nil, err
	}

	// Extract workload PCR if present
	var workloadPCR []byte
	workloadPCRIndex := a.config.GetWorkloadPCRIndex()
	for _, pcr := range quote.PCRs {
		if pcr.Index == workloadPCRIndex {
			workloadPCR = pcr.Value
			break
		}
	}

	attestation := &VMAttestation{
		Identity:      identity,
		Quote:         quote,
		Timestamp:     time.Now().UTC(),
		AttestationID: generateAttestationID(identity.VMID, quote.Timestamp),
		WorkloadPCR:   workloadPCR,
		Metadata:      make(map[string]string),
	}

	a.logger.Info("attestation generated",
		"vm_id", identity.VMID,
		"host_id", identity.HostID,
		"attestation_id", attestation.AttestationID,
	)

	return attestation, nil
}

// ReadPCR reads a single PCR value from the vTPM.
func (a *vmAttestor) ReadPCR(ctx context.Context, index int, algorithm HashAlgorithm) (*PCRValue, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "ReadPCR"}
	default:
	}

	if !a.initialized.Load() {
		return nil, ErrAttestorNotInitialized{}
	}

	if a.closed.Load() {
		return nil, ErrAttestorNotInitialized{}
	}

	if index < 0 || index > 23 {
		return nil, ErrInvalidConfig{
			Field:  "index",
			Reason: "PCR index must be between 0 and 23",
		}
	}

	if !algorithm.IsValid() {
		return nil, ErrInvalidHashAlgorithm{Algorithm: algorithm.String()}
	}

	value, err := a.vtpm.ReadPCR(ctx, index, algorithm)
	if err != nil {
		return nil, ErrPCRReadFailed{PCR: index, Cause: err}
	}

	return &PCRValue{
		Index:     index,
		Value:     value,
		Algorithm: algorithm,
	}, nil
}

// Close releases resources held by the attestor.
func (a *vmAttestor) Close() error {
	if a.closed.Swap(true) {
		return nil
	}

	if a.vtpm != nil {
		if err := a.vtpm.Close(); err != nil {
			a.logger.Warn("failed to close vTPM device", "error", err)
		}
	}

	a.logger.Info("VM attestor closed")
	return nil
}

// computePCRDigest computes the digest of all PCR values.
func (a *vmAttestor) computePCRDigest(pcrs []PCRValue, algorithm HashAlgorithm) []byte {
	hasher := sha256.New()
	for _, pcr := range pcrs {
		hasher.Write(pcr.Value)
	}
	return hasher.Sum(nil)
}

// generateAttestationID generates a unique attestation ID.
func generateAttestationID(vmID string, timestamp time.Time) string {
	data := vmID + timestamp.Format(time.RFC3339Nano)
	hash := sha256.Sum256([]byte(data))
	return string(hash[:16])
}
