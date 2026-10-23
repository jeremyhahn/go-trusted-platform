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

package kms

import (
	"fmt"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// DefaultDataKeyBits is the size of a data key minted with neither an
// algorithm nor a key size: an AES-256 key.
const DefaultDataKeyBits = 256

// dataKeyBits is the key size, in bits, of each algorithm a data key may
// be minted for.
var dataKeyBits = map[platformv1.KMSKeyAlgorithm]int32{
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128:           128,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_192:           192,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256:           256,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305: 256,
}

// aesAlgorithmByBits are the key sizes an unspecified algorithm accepts,
// each naming the AES variant of that size.
var aesAlgorithmByBits = map[int32]platformv1.KMSKeyAlgorithm{
	128: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128,
	192: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_192,
	256: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
}

// ErrUnsupportedDataKeyAlgorithm is returned when a data key is requested
// for an algorithm that is not a symmetric data-key cipher.
type ErrUnsupportedDataKeyAlgorithm struct {
	Algorithm platformv1.KMSKeyAlgorithm
}

func (e *ErrUnsupportedDataKeyAlgorithm) Error() string {
	return fmt.Sprintf("unsupported data key algorithm %s: want AES_128, AES_192, AES_256 or CHACHA20_POLY1305", e.Algorithm)
}

// ErrInvalidDataKeySize is returned when key_size is not a size the
// requested algorithm mints.
type ErrInvalidDataKeySize struct {
	Algorithm platformv1.KMSKeyAlgorithm
	Bits      int32
}

func (e *ErrInvalidDataKeySize) Error() string {
	return fmt.Sprintf("invalid data key size %d bits for %s: key_size is in bits; 0 means the algorithm's size", e.Bits, e.Algorithm)
}

// ResolveDataKey resolves a data-key request to the algorithm and key
// size, in bits, of the key it mints. keySizeBits is the request's
// key_size, which is in bits on every transport. A named algorithm fixes
// the size, and a non-zero key_size must match it. An unspecified
// algorithm is the AES variant of key_size (128, 192 or 256), AES-256
// when key_size is 0.
func ResolveDataKey(algorithm platformv1.KMSKeyAlgorithm, keySizeBits int32) (platformv1.KMSKeyAlgorithm, int32, error) {
	if algorithm == platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED {
		if keySizeBits == 0 {
			keySizeBits = DefaultDataKeyBits
		}
		resolved, ok := aesAlgorithmByBits[keySizeBits]
		if !ok {
			return algorithm, 0, &ErrInvalidDataKeySize{Algorithm: algorithm, Bits: keySizeBits}
		}
		return resolved, keySizeBits, nil
	}

	bits, ok := dataKeyBits[algorithm]
	if !ok {
		return algorithm, 0, &ErrUnsupportedDataKeyAlgorithm{Algorithm: algorithm}
	}
	if keySizeBits != 0 && keySizeBits != bits {
		return algorithm, 0, &ErrInvalidDataKeySize{Algorithm: algorithm, Bits: keySizeBits}
	}
	return algorithm, bits, nil
}
