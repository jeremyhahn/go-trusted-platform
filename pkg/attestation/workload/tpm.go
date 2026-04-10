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

package workload

import (
	"context"
)

// TPMDevice provides TPM operations for PCR extension and reading.
// This interface abstracts the TPM device to allow for testing with
// simulated TPM implementations.
type TPMDevice interface {
	// ExtendPCR extends the specified PCR with the given digest.
	// The algorithm specifies which PCR bank to use.
	ExtendPCR(ctx context.Context, pcr int, algorithm HashAlgorithm, digest []byte) error

	// ReadPCR reads the current value of the specified PCR.
	// The algorithm specifies which PCR bank to read from.
	ReadPCR(ctx context.Context, pcr int, algorithm HashAlgorithm) ([]byte, error)

	// Close releases TPM resources.
	Close() error
}

// TPMDeviceFactory creates TPM device instances.
type TPMDeviceFactory interface {
	// Open opens a connection to the TPM device.
	Open(ctx context.Context) (TPMDevice, error)
}

// SoftwareTPM provides a software-only implementation of TPMDevice for testing.
// This implementation maintains PCR state in memory without requiring hardware TPM.
type SoftwareTPM struct {
	pcrs   map[int]map[HashAlgorithm][]byte
	closed bool
}

// NewSoftwareTPM creates a new software TPM instance with zeroed PCRs.
func NewSoftwareTPM() *SoftwareTPM {
	tpm := &SoftwareTPM{
		pcrs: make(map[int]map[HashAlgorithm][]byte),
	}
	// Initialize PCR 14 with zeros for all supported algorithms
	for pcr := 0; pcr <= 23; pcr++ {
		tpm.pcrs[pcr] = make(map[HashAlgorithm][]byte)
		for _, alg := range []HashAlgorithm{HashAlgorithmSHA1, HashAlgorithmSHA256, HashAlgorithmSHA384, HashAlgorithmSHA512} {
			tpm.pcrs[pcr][alg] = make([]byte, alg.DigestSize())
		}
	}
	return tpm
}

// ExtendPCR extends the specified PCR with the given digest using software computation.
func (s *SoftwareTPM) ExtendPCR(ctx context.Context, pcr int, algorithm HashAlgorithm, digest []byte) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "ExtendPCR"}
	default:
	}

	if s.closed {
		return ErrTPMNotAvailable{}
	}

	if pcr < 0 || pcr > 23 {
		return ErrInvalidConfig{Field: "PCR", Reason: "PCR index must be between 0 and 23"}
	}

	if !algorithm.IsValid() {
		return ErrInvalidHashAlgorithm{Algorithm: algorithm.String()}
	}

	expectedSize := algorithm.DigestSize()
	if len(digest) != expectedSize {
		return ErrInvalidConfig{
			Field:  "digest",
			Reason: "digest size does not match algorithm",
		}
	}

	// PCR extension: new_pcr = HASH(current_pcr || digest)
	currentValue := s.pcrs[pcr][algorithm]
	hasher := getHasher(algorithm)
	if hasher == nil {
		return ErrInvalidHashAlgorithm{Algorithm: algorithm.String()}
	}

	hasher.Write(currentValue)
	hasher.Write(digest)
	s.pcrs[pcr][algorithm] = hasher.Sum(nil)

	return nil
}

// ReadPCR reads the current value of the specified PCR.
func (s *SoftwareTPM) ReadPCR(ctx context.Context, pcr int, algorithm HashAlgorithm) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "ReadPCR"}
	default:
	}

	if s.closed {
		return nil, ErrTPMNotAvailable{}
	}

	if pcr < 0 || pcr > 23 {
		return nil, ErrInvalidConfig{Field: "PCR", Reason: "PCR index must be between 0 and 23"}
	}

	if !algorithm.IsValid() {
		return nil, ErrInvalidHashAlgorithm{Algorithm: algorithm.String()}
	}

	value := s.pcrs[pcr][algorithm]
	result := make([]byte, len(value))
	copy(result, value)
	return result, nil
}

// Close marks the software TPM as closed.
func (s *SoftwareTPM) Close() error {
	s.closed = true
	return nil
}

// SetPCRValue sets a PCR to a specific value (for testing purposes).
func (s *SoftwareTPM) SetPCRValue(pcr int, algorithm HashAlgorithm, value []byte) error {
	if s.closed {
		return ErrTPMNotAvailable{}
	}

	if pcr < 0 || pcr > 23 {
		return ErrInvalidConfig{Field: "PCR", Reason: "PCR index must be between 0 and 23"}
	}

	if !algorithm.IsValid() {
		return ErrInvalidHashAlgorithm{Algorithm: algorithm.String()}
	}

	expectedSize := algorithm.DigestSize()
	if len(value) != expectedSize {
		return ErrInvalidConfig{
			Field:  "value",
			Reason: "value size does not match algorithm digest size",
		}
	}

	copy(s.pcrs[pcr][algorithm], value)
	return nil
}

// softwareTPMFactory creates software TPM instances.
type softwareTPMFactory struct {
	tpm *SoftwareTPM
}

// NewSoftwareTPMFactory creates a factory that returns software TPM instances.
func NewSoftwareTPMFactory(tpm *SoftwareTPM) TPMDeviceFactory {
	return &softwareTPMFactory{tpm: tpm}
}

// Open returns the software TPM instance.
func (f *softwareTPMFactory) Open(ctx context.Context) (TPMDevice, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "Open"}
	default:
	}

	if f.tpm == nil {
		f.tpm = NewSoftwareTPM()
	}
	return f.tpm, nil
}
