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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync/atomic"
	"time"
)

// TPMProvider defines the interface for TPM operations required by the attestor.
// This allows for dependency injection and testing with mock TPMs.
type TPMProvider interface {
	// ExtendPCR extends the specified PCR with the given hash.
	// The hash must be SHA-256 (32 bytes).
	ExtendPCR(ctx context.Context, pcrIndex int, hash []byte) error

	// ReadPCR reads the current value of the specified PCR.
	// Returns the PCR value as a SHA-256 hash.
	ReadPCR(ctx context.Context, pcrIndex int) ([]byte, error)

	// GenerateQuote generates a TPM quote over the specified PCR indices.
	// Returns the quote data structure containing the quote and signature.
	GenerateQuote(ctx context.Context, pcrIndices []int, nonce []byte) (*Quote, error)

	// VerifyQuote verifies a TPM quote signature using the AIK.
	// Returns nil if verification succeeds.
	VerifyQuote(ctx context.Context, quote *Quote) error
}

// Quote represents a TPM quote with associated attestation data.
type Quote struct {
	// QuoteData contains the TPM2B_ATTEST structure.
	QuoteData []byte `json:"quote_data"`

	// Signature is the TPM signature over the quote data.
	Signature []byte `json:"signature"`

	// PCRs contains the quoted PCR values indexed by PCR number.
	PCRs map[int][]byte `json:"pcrs"`

	// Nonce is the nonce used in quote generation.
	Nonce []byte `json:"nonce"`

	// Timestamp is when the quote was generated.
	Timestamp time.Time `json:"timestamp"`
}

// AttestationVerificationResult contains the result of container attestation verification.
type AttestationVerificationResult struct {
	// ContainerID is the container that was verified.
	ContainerID string `json:"container_id"`

	// ContainerName is the container name.
	ContainerName string `json:"container_name"`

	// Verified indicates if attestation passed all checks.
	Verified bool `json:"verified"`

	// ImageDigest is the verified image digest.
	ImageDigest []byte `json:"image_digest"`

	// ConfigDigest is the verified config digest.
	ConfigDigest []byte `json:"config_digest"`

	// PCRValue is the WorkloadPCR value from the quote.
	PCRValue []byte `json:"pcr_value"`

	// ExpectedPCRValue is the computed expected PCR value.
	ExpectedPCRValue []byte `json:"expected_pcr_value"`

	// Timestamp is when verification was performed.
	Timestamp time.Time `json:"timestamp"`

	// Error contains the error message if verification failed.
	Error string `json:"error,omitempty"`
}

// ContainerAttestor provides TPM-based attestation for containers.
// It manages the measurement log and integrates with the TPM for
// PCR operations and quote generation/verification.
type ContainerAttestor struct {
	tpm      TPMProvider
	log      *ThreadSafeMeasurementLog
	pcrIndex int
	closed   atomic.Bool
}

// ContainerAttestorOption configures a ContainerAttestor.
type ContainerAttestorOption func(*ContainerAttestor)

// WithPCRIndex sets the PCR index to use for container measurements.
// Default is the WorkloadPCR index (14).
func WithPCRIndex(index int) ContainerAttestorOption {
	return func(a *ContainerAttestor) {
		a.pcrIndex = index
	}
}

// WithThreadSafeMeasurementLog sets a pre-existing measurement log.
// This is useful for restoring state from persistence.
func WithThreadSafeMeasurementLog(log *ThreadSafeMeasurementLog) ContainerAttestorOption {
	return func(a *ContainerAttestor) {
		a.log = log
	}
}

// NewContainerAttestor creates a new ContainerAttestor with the given
// TPM provider and options.
func NewContainerAttestor(tpm TPMProvider, opts ...ContainerAttestorOption) (*ContainerAttestor, error) {
	if tpm == nil {
		return nil, ErrPodmanNotAvailable
	}

	a := &ContainerAttestor{
		tpm:      tpm,
		log:      NewThreadSafeMeasurementLog(),
		pcrIndex: DefaultPCRIndex,
	}

	for _, opt := range opts {
		opt(a)
	}

	// Validate PCR index (0-23 for TPM 2.0)
	if a.pcrIndex < 0 || a.pcrIndex > 23 {
		return nil, ErrInvalidSpec
	}

	return a, nil
}

// ComputeImageDigest computes the SHA-256 digest of a container image.
// The imageRef is the full image reference (e.g., "docker.io/library/alpine:latest").
//
// Note: In a real implementation, this would hash the actual image layers.
// This implementation provides a deterministic hash of the image reference
// for testing and development purposes.
func (a *ContainerAttestor) ComputeImageDigest(imageRef string) ([]byte, error) {
	if a.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	if imageRef == "" {
		return nil, ErrInvalidImage
	}

	// Compute SHA-256 of the image reference
	// In production, this would hash the actual image layers
	h := sha256.New()
	h.Write([]byte(imageRef))
	return h.Sum(nil), nil
}

// ComputeConfigDigest computes the SHA-256 digest of a container's configuration.
// The spec contains the container configuration to hash.
func (a *ContainerAttestor) ComputeConfigDigest(spec *ContainerSpec) ([]byte, error) {
	if a.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	if spec == nil {
		return nil, ErrInvalidSpec
	}

	// Serialize the spec to JSON for deterministic hashing
	data, err := json.Marshal(spec)
	if err != nil {
		return nil, NewContainerError("", spec.Name, "compute_config_digest", err)
	}

	h := sha256.New()
	h.Write(data)
	return h.Sum(nil), nil
}

// ComputeContainerEntryHash computes the combined hash for a container measurement.
// This is the hash that will be extended to the PCR.
func (a *ContainerAttestor) ComputeContainerEntryHash(
	containerID string,
	imageDigest, configDigest []byte,
) ([]byte, error) {
	if a.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	if containerID == "" {
		return nil, ErrInvalidContainerID
	}

	return ComputeEntryHash(containerID, imageDigest, configDigest, EventContainerCreate), nil
}

// ExtendPCR extends the configured PCR with the given hash and records
// the measurement in the log.
func (a *ContainerAttestor) ExtendPCR(ctx context.Context, pcrIndex int, hash []byte) error {
	if a.closed.Load() {
		return ErrOrchestratorClosed
	}

	if pcrIndex < 0 || pcrIndex > 23 {
		return ErrInvalidSpec
	}

	if len(hash) != SHA256Size {
		return ErrMeasurementLogInvalid
	}

	return a.tpm.ExtendPCR(ctx, pcrIndex, hash)
}

// GenerateQuote generates a TPM quote over the specified PCR indices.
// If no indices are provided, the configured WorkloadPCR index is used.
func (a *ContainerAttestor) GenerateQuote(ctx context.Context, pcrIndices []int) (*Quote, error) {
	if a.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	if len(pcrIndices) == 0 {
		pcrIndices = []int{a.pcrIndex}
	}

	// Generate a nonce for freshness
	nonce := make([]byte, 32)
	h := sha256.New()
	h.Write([]byte(time.Now().String()))
	copy(nonce, h.Sum(nil))

	return a.tpm.GenerateQuote(ctx, pcrIndices, nonce)
}

// VerifyAttestation verifies container attestation by:
// 1. Verifying the TPM quote signature
// 2. Replaying the measurement log to compute expected PCR value
// 3. Comparing the expected PCR with the quoted PCR value
// 4. Extracting the specific container's measurements from the log
//
// Returns an AttestationVerificationResult with verification status and details.
func (a *ContainerAttestor) VerifyAttestation(
	ctx context.Context,
	quote *Quote,
	log *ThreadSafeMeasurementLog,
) (*AttestationVerificationResult, error) {
	if a.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	if quote == nil {
		return nil, ErrQuoteVerificationFailed
	}

	if log == nil {
		return nil, ErrMeasurementLogInvalid
	}

	result := &AttestationVerificationResult{
		Timestamp: time.Now(),
		Verified:  false,
	}

	// Step 1: Verify quote signature
	if err := a.tpm.VerifyQuote(ctx, quote); err != nil {
		result.Error = "quote verification failed: " + err.Error()
		return result, ErrQuoteVerificationFailed
	}

	// Step 2: Replay log to compute expected PCR value
	expectedPCR := log.ComputeExpectedPCR()
	result.ExpectedPCRValue = expectedPCR

	// Step 3: Compare with quoted PCR value
	quotedPCR, ok := quote.PCRs[a.pcrIndex]
	if !ok {
		result.Error = "PCR index not in quote"
		return result, ErrPCRMismatch
	}
	result.PCRValue = quotedPCR

	if !bytes.Equal(expectedPCR, quotedPCR) {
		result.Error = "PCR value mismatch"
		return result, NewAttestationError("", expectedPCR, quotedPCR, ErrPCRMismatch)
	}

	result.Verified = true
	return result, nil
}

// VerifyContainerAttestation verifies attestation for a specific container.
// This is a convenience method that extracts the container's measurements
// from the log and includes them in the result.
func (a *ContainerAttestor) VerifyContainerAttestation(
	ctx context.Context,
	containerID string,
	quote *Quote,
	log *ThreadSafeMeasurementLog,
) (*AttestationVerificationResult, error) {
	if containerID == "" {
		return nil, ErrInvalidContainerID
	}

	// Perform base verification
	result, err := a.VerifyAttestation(ctx, quote, log)
	if err != nil {
		return result, err
	}

	// Find the container's entry in the log
	entry, err := log.FindEntry(containerID)
	if err != nil {
		result.Error = "container not found in measurement log"
		result.Verified = false
		return result, err
	}

	// Add container-specific information to result
	result.ContainerID = containerID
	result.ContainerName = entry.ContainerName
	result.ImageDigest = entry.ImageDigest
	result.ConfigDigest = entry.ConfigDigest

	return result, nil
}

// RecordContainerCreate records a container creation event and extends the WorkloadPCR.
func (a *ContainerAttestor) RecordContainerCreate(
	ctx context.Context,
	containerID string,
	containerName string,
	imageDigest, configDigest []byte,
) error {
	return a.recordEvent(ctx, containerID, containerName, EventContainerCreate, imageDigest, configDigest, "container created")
}

// RecordContainerStart records a container start event and extends the WorkloadPCR.
func (a *ContainerAttestor) RecordContainerStart(
	ctx context.Context,
	containerID string,
	containerName string,
) error {
	// For start events, we use empty digests as the image/config haven't changed
	return a.recordEvent(ctx, containerID, containerName, EventContainerStart, nil, nil, "container started")
}

// RecordContainerStop records a container stop event and extends the WorkloadPCR.
func (a *ContainerAttestor) RecordContainerStop(
	ctx context.Context,
	containerID string,
	containerName string,
) error {
	return a.recordEvent(ctx, containerID, containerName, EventContainerStop, nil, nil, "container stopped")
}

// RecordContainerRemove records a container removal event and extends the WorkloadPCR.
func (a *ContainerAttestor) RecordContainerRemove(
	ctx context.Context,
	containerID string,
	containerName string,
) error {
	return a.recordEvent(ctx, containerID, containerName, EventContainerRemove, nil, nil, "container removed")
}

// recordEvent records a container lifecycle event and extends the PCR.
func (a *ContainerAttestor) recordEvent(
	ctx context.Context,
	containerID string,
	containerName string,
	eventType MeasurementEventType,
	imageDigest, configDigest []byte,
	description string,
) error {
	if a.closed.Load() {
		return ErrOrchestratorClosed
	}

	if containerID == "" {
		return ErrInvalidContainerID
	}

	// Create measurement entry
	entry := NewMeasurementEntry(containerID, containerName, eventType, imageDigest, configDigest, description)

	// Extend PCR with the cumulative hash
	if err := a.tpm.ExtendPCR(ctx, a.pcrIndex, entry.CumulativeHash); err != nil {
		return NewContainerError(containerID, containerName, "extend_pcr", err)
	}

	// Append to measurement log
	if err := a.log.AppendEntry(entry); err != nil {
		return err
	}

	return nil
}

// GetMeasurementLog returns the current measurement log.
func (a *ContainerAttestor) GetMeasurementLog() *ThreadSafeMeasurementLog {
	return a.log
}

// GetPCRIndex returns the PCR index used for container measurements.
func (a *ContainerAttestor) GetPCRIndex() int {
	return a.pcrIndex
}

// Close closes the attestor and releases resources.
func (a *ContainerAttestor) Close() error {
	a.closed.Store(true)
	return nil
}
