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

package dns

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateTLSAUsage_AcceptsEveryDefinedUsage: RFC 6698 §2.1.1 defines
// usages 0-3, and each is stored.
func TestValidateTLSAUsage_AcceptsEveryDefinedUsage(t *testing.T) {
	for usage := uint32(0); usage <= TLSAUsageMax; usage++ {
		assert.NoError(t, ValidateTLSAUsage(usage), "usage %d", usage)
	}
}

// TestValidateTLSAUsage_RefusesUndefinedUsage: a usage above 3 is refused
// with the typed error carrying the offending value.
func TestValidateTLSAUsage_RefusesUndefinedUsage(t *testing.T) {
	for _, usage := range []uint32{4, 5, 255, 261} {
		err := ValidateTLSAUsage(usage)
		var invalid ErrInvalidTLSAUsage
		require.True(t, errors.As(err, &invalid), "usage %d: err = %v", usage, err)
		assert.Equal(t, usage, invalid.Usage)
		assert.Contains(t, err.Error(), "RFC 6698")
	}
}
