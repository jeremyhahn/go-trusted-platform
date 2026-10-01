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

package ovs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIFlowCookie_CarriesTheOwnerAndRoundTrips(t *testing.T) {
	seen := map[uint64]bool{}
	for i := 0; i < 64; i++ {
		cookie, err := NewAPIFlowCookie()
		require.NoError(t, err)
		assert.Equal(t, APIFlowCookieOwner, cookie&(0xFFFF<<48), "the owner prefix is in the high 16 bits")
		assert.False(t, seen[cookie], "cookies must not repeat")
		seen[cookie] = true

		back, err := ParseFlowID(FlowID(cookie))
		require.NoError(t, err)
		assert.Equal(t, cookie, back)
	}
}

func TestParseFlowID_AcceptsHexAndDecimal(t *testing.T) {
	v, err := ParseFlowID("flow-0xA9F1000000000001")
	require.NoError(t, err)
	assert.Equal(t, uint64(0xA9F1000000000001), v)

	v, err = ParseFlowID("flow-123")
	require.NoError(t, err)
	assert.Equal(t, uint64(123), v)
}

func TestParseFlowID_RefusesWhatNamesNoSingleFlow(t *testing.T) {
	for _, id := range []string{
		"",
		"123",
		"550e8400-e29b-41d4-a716-446655440000",
		"flow-",
		"flow-0xzz",
		"flow-to-delete",
		"flow-0",
		"flow-0x0",
	} {
		t.Run(id, func(t *testing.T) {
			_, err := ParseFlowID(id)
			var typed *ErrInvalidFlowID
			require.ErrorAs(t, err, &typed)
			assert.Equal(t, id, typed.ID)
			assert.Contains(t, typed.Error(), "invalid flow id")
		})
	}
}
