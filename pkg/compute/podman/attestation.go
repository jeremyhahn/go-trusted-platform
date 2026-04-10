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

package podman

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// PCRIndex for container workloads (typically PCR 14)
const ContainerPCRIndex = 14

// ContainerQuote holds attestation data for a container
type ContainerQuote struct {
	// ContainerID is the container identifier
	ContainerID string `json:"container_id" yaml:"container_id"`

	// ContainerName is the container name
	ContainerName string `json:"container_name" yaml:"container_name"`

	// ImageRef is the image reference
	ImageRef string `json:"image_ref" yaml:"image_ref"`

	// ImageDigest is the digest of the container image
	ImageDigest string `json:"image_digest" yaml:"image_digest"`

	// PCRIndex is the PCR index used for measurement
	PCRIndex int `json:"pcr_index" yaml:"pcr_index"`

	// PCRValue is the PCR value after extension
	PCRValue []byte `json:"pcr_value" yaml:"pcr_value"`

	// MeasurementLog contains the measurement data
	MeasurementLog []byte `json:"measurement_log" yaml:"measurement_log"`

	// Timestamp is when the attestation was created
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`

	// Signature is an optional signature over the quote
	Signature []byte `json:"signature,omitempty" yaml:"signature,omitempty"`

	// Nonce is a nonce used in the attestation
	Nonce []byte `json:"nonce,omitempty" yaml:"nonce,omitempty"`
}

// ContainerMeasurement represents a measurement event for a container
type ContainerMeasurement struct {
	// ContainerID is the container identifier
	ContainerID string `json:"container_id" yaml:"container_id"`

	// EventType describes the type of event
	EventType string `json:"event_type" yaml:"event_type"`

	// EventData is the data being measured
	EventData []byte `json:"event_data" yaml:"event_data"`

	// Digest is the SHA-256 hash of the event data
	Digest []byte `json:"digest" yaml:"digest"`

	// Timestamp is when the measurement occurred
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
}

// ContainerAttestor defines the interface for container attestation
type ContainerAttestor interface {
	// OnContainerStart is called when a container starts - extends PCR
	OnContainerStart(ctx context.Context, container *Container) error

	// OnContainerStop is called when a container stops
	OnContainerStop(ctx context.Context, container *Container) error

	// GetContainerQuote returns an attestation quote for a container
	GetContainerQuote(ctx context.Context, containerID string, nonce []byte) (*ContainerQuote, error)

	// GetMeasurementLog returns the measurement log for a container
	GetMeasurementLog(ctx context.Context, containerID string) ([]*ContainerMeasurement, error)

	// VerifyQuote verifies a container quote
	VerifyQuote(ctx context.Context, quote *ContainerQuote, expectedPCR []byte) error
}

// TPMExtender defines the interface for extending TPM PCRs
// This allows the attestor to work with different TPM implementations
type TPMExtender interface {
	// ExtendPCR extends a PCR with the given data
	ExtendPCR(pcrIndex int, data []byte) error

	// ReadPCR reads the current value of a PCR
	ReadPCR(pcrIndex int) ([]byte, error)

	// CreateQuote creates an attestation quote
	CreateQuote(pcrIndices []int, nonce []byte) ([]byte, error)
}

// containerAttestor implements the ContainerAttestor interface
type containerAttestor struct {
	tpm          TPMExtender
	pcrIndex     int
	measurements sync.Map // map[string][]*ContainerMeasurement
	logger       interface {
		Infof(format string, args ...any)
		Errorf(format string, args ...any)
		Debugf(format string, args ...any)
	}
}

// AttestorConfig holds configuration for the container attestor
type AttestorConfig struct {
	// PCRIndex is the PCR index to use for measurements
	PCRIndex int `json:"pcr_index" yaml:"pcr_index"`

	// EnableSigning enables signing of quotes
	EnableSigning bool `json:"enable_signing" yaml:"enable_signing"`
}

// DefaultAttestorConfig returns the default attestor configuration
func DefaultAttestorConfig() *AttestorConfig {
	return &AttestorConfig{
		PCRIndex:      ContainerPCRIndex,
		EnableSigning: false,
	}
}

// NewContainerAttestor creates a new container attestor
func NewContainerAttestor(tpm TPMExtender, config *AttestorConfig, logger interface {
	Infof(format string, args ...any)
	Errorf(format string, args ...any)
	Debugf(format string, args ...any)
}) (ContainerAttestor, error) {
	if config == nil {
		config = DefaultAttestorConfig()
	}

	attestor := &containerAttestor{
		tpm:      tpm,
		pcrIndex: config.PCRIndex,
		logger:   logger,
	}

	return attestor, nil
}

// OnContainerStart is called when a container starts
func (a *containerAttestor) OnContainerStart(ctx context.Context, container *Container) error {
	if container == nil {
		return NewContainerError("", "attestation", ErrContainerNotFound)
	}

	// Build measurement data from container metadata
	measurementData := buildContainerMeasurement(container)

	// Calculate digest
	digest := sha256.Sum256(measurementData)

	// Extend TPM PCR if available
	if a.tpm != nil {
		if err := a.tpm.ExtendPCR(a.pcrIndex, digest[:]); err != nil {
			if a.logger != nil {
				a.logger.Errorf("Failed to extend PCR %d for container %s: %v", a.pcrIndex, container.ID, err)
			}
			return NewContainerError(container.ID, "pcr extend", ErrAttestationFailed)
		}
		if a.logger != nil {
			a.logger.Infof("Extended PCR %d for container %s (image: %s)", a.pcrIndex, container.ID, container.Image)
		}
	}

	// Record measurement
	measurement := &ContainerMeasurement{
		ContainerID: container.ID,
		EventType:   "container_start",
		EventData:   measurementData,
		Digest:      digest[:],
		Timestamp:   time.Now(),
	}

	a.recordMeasurement(container.ID, measurement)

	return nil
}

// OnContainerStop is called when a container stops
func (a *containerAttestor) OnContainerStop(ctx context.Context, container *Container) error {
	if container == nil {
		return NewContainerError("", "attestation", ErrContainerNotFound)
	}

	// Build measurement data for stop event
	measurementData := buildStopMeasurement(container)

	// Calculate digest
	digest := sha256.Sum256(measurementData)

	// Extend TPM PCR if available
	if a.tpm != nil {
		if err := a.tpm.ExtendPCR(a.pcrIndex, digest[:]); err != nil {
			if a.logger != nil {
				a.logger.Errorf("Failed to extend PCR %d for container stop %s: %v", a.pcrIndex, container.ID, err)
			}
			return NewContainerError(container.ID, "pcr extend", ErrAttestationFailed)
		}
		if a.logger != nil {
			a.logger.Infof("Extended PCR %d for container stop %s", a.pcrIndex, container.ID)
		}
	}

	// Record measurement
	measurement := &ContainerMeasurement{
		ContainerID: container.ID,
		EventType:   "container_stop",
		EventData:   measurementData,
		Digest:      digest[:],
		Timestamp:   time.Now(),
	}

	a.recordMeasurement(container.ID, measurement)

	return nil
}

// GetContainerQuote returns an attestation quote for a container
func (a *containerAttestor) GetContainerQuote(ctx context.Context, containerID string, nonce []byte) (*ContainerQuote, error) {
	if containerID == "" {
		return nil, NewContainerError("", "quote", ErrContainerNotFound)
	}

	quote := &ContainerQuote{
		ContainerID: containerID,
		PCRIndex:    a.pcrIndex,
		Timestamp:   time.Now(),
		Nonce:       nonce,
	}

	// Get PCR value if TPM is available
	if a.tpm != nil {
		pcrValue, err := a.tpm.ReadPCR(a.pcrIndex)
		if err != nil {
			return nil, NewContainerError(containerID, "read pcr", ErrAttestationFailed)
		}
		quote.PCRValue = pcrValue

		// Create TPM quote if nonce provided
		if len(nonce) > 0 {
			signature, err := a.tpm.CreateQuote([]int{a.pcrIndex}, nonce)
			if err != nil {
				return nil, NewContainerError(containerID, "create quote", ErrAttestationFailed)
			}
			quote.Signature = signature
		}
	}

	// Get measurements for this container
	measurements := a.getMeasurements(containerID)
	if len(measurements) > 0 {
		// Build measurement log
		var measurementLog []byte
		for _, m := range measurements {
			measurementLog = append(measurementLog, m.Digest...)
		}
		quote.MeasurementLog = measurementLog

		// Get image info from first start measurement
		for _, m := range measurements {
			if m.EventType == "container_start" {
				// Extract image info from measurement data
				// This would typically be parsed from the structured measurement
				break
			}
		}
	}

	return quote, nil
}

// GetMeasurementLog returns the measurement log for a container
func (a *containerAttestor) GetMeasurementLog(ctx context.Context, containerID string) ([]*ContainerMeasurement, error) {
	if containerID == "" {
		return nil, NewContainerError("", "measurement log", ErrContainerNotFound)
	}

	measurements := a.getMeasurements(containerID)

	return measurements, nil
}

// VerifyQuote verifies a container quote against expected PCR value
func (a *containerAttestor) VerifyQuote(ctx context.Context, quote *ContainerQuote, expectedPCR []byte) error {
	if quote == nil {
		return NewContainerError("", "verify quote", ErrAttestationFailed)
	}

	// Verify PCR value matches expected
	if len(expectedPCR) > 0 && len(quote.PCRValue) > 0 {
		if !compareBytes(quote.PCRValue, expectedPCR) {
			return NewContainerError(quote.ContainerID, "verify quote", ErrAttestationFailed)
		}
	}

	// Replay measurement log to verify PCR
	if len(quote.MeasurementLog) > 0 {
		// Start with zero PCR
		pcr := make([]byte, 32)

		// Each measurement is 32 bytes (SHA-256)
		for i := 0; i+32 <= len(quote.MeasurementLog); i += 32 {
			measurement := quote.MeasurementLog[i : i+32]

			// PCR = SHA256(PCR || measurement)
			combined := append(pcr, measurement...)
			hash := sha256.Sum256(combined)
			pcr = hash[:]
		}

		// Compare computed PCR with quote
		if !compareBytes(pcr, quote.PCRValue) {
			return NewContainerError(quote.ContainerID, "verify measurement log", ErrAttestationFailed)
		}
	}

	return nil
}

// recordMeasurement records a measurement for a container
func (a *containerAttestor) recordMeasurement(containerID string, measurement *ContainerMeasurement) {
	existing, _ := a.measurements.LoadOrStore(containerID, []*ContainerMeasurement{})
	measurements := existing.([]*ContainerMeasurement)
	measurements = append(measurements, measurement)
	a.measurements.Store(containerID, measurements)
}

// getMeasurements returns all measurements for a container
func (a *containerAttestor) getMeasurements(containerID string) []*ContainerMeasurement {
	if v, ok := a.measurements.Load(containerID); ok {
		return v.([]*ContainerMeasurement)
	}
	return nil
}

// buildContainerMeasurement builds measurement data from container metadata
func buildContainerMeasurement(container *Container) []byte {
	// Build a deterministic measurement from container metadata
	var data []byte

	// Container ID
	data = append(data, []byte(container.ID)...)

	// Image reference
	data = append(data, []byte(container.Image)...)

	// Image digest if available
	if container.ImageDigest != "" {
		data = append(data, []byte(container.ImageDigest)...)
	}

	// Container name
	data = append(data, []byte(container.Name)...)

	// Command
	for _, cmd := range container.Command {
		data = append(data, []byte(cmd)...)
	}

	// Timestamp
	data = append(data, []byte(container.CreatedAt.Format(time.RFC3339))...)

	return data
}

// buildStopMeasurement builds measurement data for container stop event
func buildStopMeasurement(container *Container) []byte {
	var data []byte

	// Event type
	data = append(data, []byte("container_stop")...)

	// Container ID
	data = append(data, []byte(container.ID)...)

	// Exit code
	data = append(data, byte(container.ExitCode))

	// Stop timestamp
	if container.FinishedAt != nil {
		data = append(data, []byte(container.FinishedAt.Format(time.RFC3339))...)
	} else {
		data = append(data, []byte(time.Now().Format(time.RFC3339))...)
	}

	return data
}

// compareBytes compares two byte slices for equality
func compareBytes(a, b []byte) bool {
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

// ComputeExpectedPCR computes the expected PCR value from a list of measurements
func ComputeExpectedPCR(measurements []*ContainerMeasurement) []byte {
	// Start with zero PCR
	pcr := make([]byte, 32)

	for _, m := range measurements {
		// PCR = SHA256(PCR || digest)
		combined := append(pcr, m.Digest...)
		hash := sha256.Sum256(combined)
		pcr = hash[:]
	}

	return pcr
}

// FormatPCRValue formats a PCR value as a hex string
func FormatPCRValue(pcr []byte) string {
	return hex.EncodeToString(pcr)
}

// ParsePCRValue parses a hex-encoded PCR value
func ParsePCRValue(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
