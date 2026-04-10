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
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// getHasher returns a hash.Hash for the given algorithm.
func getHasher(algorithm HashAlgorithm) hash.Hash {
	switch algorithm {
	case HashAlgorithmSHA1:
		return sha1.New()
	case HashAlgorithmSHA256:
		return sha256.New()
	case HashAlgorithmSHA384:
		return sha512.New384()
	case HashAlgorithmSHA512:
		return sha512.New()
	default:
		return nil
	}
}

// computeDigest computes the digest for a workload measurement.
// Formula: digest = HASH(workload_type || "|" || workload_id || "|" || image_digest)
func computeDigest(algorithm HashAlgorithm, measurement *WorkloadMeasurement) ([]byte, error) {
	hasher := getHasher(algorithm)
	if hasher == nil {
		return nil, ErrInvalidHashAlgorithm{Algorithm: algorithm.String()}
	}

	// Build the measurement string: type|id|digest
	hasher.Write([]byte(measurement.WorkloadType))
	hasher.Write([]byte("|"))
	hasher.Write([]byte(measurement.WorkloadID))
	hasher.Write([]byte("|"))
	hasher.Write([]byte(measurement.ImageDigest))

	return hasher.Sum(nil), nil
}

// computeExpectedPCR computes what the PCR value should be after extension.
// Formula: new_pcr = HASH(current_pcr || digest)
func computeExpectedPCR(algorithm HashAlgorithm, currentPCR, digest []byte) ([]byte, error) {
	hasher := getHasher(algorithm)
	if hasher == nil {
		return nil, ErrInvalidHashAlgorithm{Algorithm: algorithm.String()}
	}

	hasher.Write(currentPCR)
	hasher.Write(digest)
	return hasher.Sum(nil), nil
}
