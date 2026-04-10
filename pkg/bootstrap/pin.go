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

package bootstrap

import (
	"crypto/rand"
	"math/big"
)

const digits = "0123456789"

// GenerateNumericPIN generates a cryptographically random numeric PIN of
// the specified length using crypto/rand. Each digit is independently and
// uniformly selected from 0-9.
func GenerateNumericPIN(length int) ([]byte, error) {
	if length <= 0 {
		return nil, ErrInvalidPINLength{Length: length}
	}
	result := make([]byte, length)
	for i := range result {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return nil, ErrPINGeneration{Cause: err}
		}
		result[i] = digits[idx.Int64()]
	}
	return result, nil
}
