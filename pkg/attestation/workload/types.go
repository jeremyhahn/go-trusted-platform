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
	"time"
)

// WorkloadType represents the type of workload being measured.
type WorkloadType string

// Supported workload types.
const (
	// WorkloadTypeVM represents a virtual machine workload.
	WorkloadTypeVM WorkloadType = "vm"

	// WorkloadTypeContainer represents a container workload.
	WorkloadTypeContainer WorkloadType = "container"
)

// String returns the string representation of WorkloadType.
func (w WorkloadType) String() string {
	return string(w)
}

// IsValid returns true if the workload type is valid.
func (w WorkloadType) IsValid() bool {
	switch w {
	case WorkloadTypeVM, WorkloadTypeContainer:
		return true
	default:
		return false
	}
}

// ChainEntry represents a single entry in the workload measurement chain.
type ChainEntry struct {
	// Timestamp is when the measurement was recorded.
	Timestamp time.Time

	// WorkloadType indicates whether this is a VM or container.
	WorkloadType WorkloadType

	// WorkloadID is the unique identifier for the workload (container ID, VM UUID).
	WorkloadID string

	// ImageDigest is the digest of the workload image.
	ImageDigest string

	// Digest is the measurement hash computed from workload attributes.
	Digest []byte

	// PCRValue is the PCR value after this extension.
	PCRValue []byte
}

// WorkloadMeasurement contains the attributes used to compute a workload measurement.
type WorkloadMeasurement struct {
	// WorkloadType indicates whether this is a VM or container.
	WorkloadType WorkloadType

	// WorkloadID is the unique identifier for the workload.
	WorkloadID string

	// ImageDigest is the digest of the workload image.
	ImageDigest string
}

// Validate validates the workload measurement fields.
func (m *WorkloadMeasurement) Validate() error {
	if !m.WorkloadType.IsValid() {
		return ErrInvalidWorkloadType{Type: string(m.WorkloadType)}
	}
	if m.WorkloadID == "" {
		return ErrInvalidWorkloadID{Reason: "workload ID cannot be empty"}
	}
	return nil
}

// HashAlgorithm represents a cryptographic hash algorithm.
type HashAlgorithm string

// Supported hash algorithms for PCR banks.
const (
	HashAlgorithmSHA1   HashAlgorithm = "sha1"
	HashAlgorithmSHA256 HashAlgorithm = "sha256"
	HashAlgorithmSHA384 HashAlgorithm = "sha384"
	HashAlgorithmSHA512 HashAlgorithm = "sha512"
)

// String returns the string representation of HashAlgorithm.
func (h HashAlgorithm) String() string {
	return string(h)
}

// IsValid returns true if the hash algorithm is supported.
func (h HashAlgorithm) IsValid() bool {
	switch h {
	case HashAlgorithmSHA1, HashAlgorithmSHA256, HashAlgorithmSHA384, HashAlgorithmSHA512:
		return true
	default:
		return false
	}
}

// DigestSize returns the digest size in bytes for the hash algorithm.
func (h HashAlgorithm) DigestSize() int {
	switch h {
	case HashAlgorithmSHA1:
		return 20
	case HashAlgorithmSHA256:
		return 32
	case HashAlgorithmSHA384:
		return 48
	case HashAlgorithmSHA512:
		return 64
	default:
		return 0
	}
}

// ChainStatistics provides statistics about the measurement chain.
type ChainStatistics struct {
	// TotalEntries is the total number of entries in the chain.
	TotalEntries int

	// VMCount is the number of VM workloads measured.
	VMCount int

	// ContainerCount is the number of container workloads measured.
	ContainerCount int

	// FirstEntryTime is the timestamp of the first entry.
	FirstEntryTime time.Time

	// LastEntryTime is the timestamp of the last entry.
	LastEntryTime time.Time

	// CurrentPCRValue is the current PCR value.
	CurrentPCRValue []byte
}
