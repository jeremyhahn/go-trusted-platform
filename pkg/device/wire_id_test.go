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

package device

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// maxID is above 2^53, where a JSON number loses precision in JavaScript.
const maxID = ID(18446744073709551615)

func TestID_MarshalsAsAString(t *testing.T) {
	out, err := json.Marshal(maxID)

	require.NoError(t, err)
	assert.Equal(t, `"18446744073709551615"`, string(out))
	assert.Equal(t, "18446744073709551615", maxID.String())
	assert.Equal(t, uint64(18446744073709551615), maxID.Uint64())
}

func TestID_UnmarshalsAStringOrANumber(t *testing.T) {
	for body, want := range map[string]ID{
		`"18446744073709551615"`: maxID,
		`18446744073709551615`:   maxID,
		`"7"`:                    7,
		`null`:                   0,
		`""`:                     0,
	} {
		t.Run(body, func(t *testing.T) {
			var id ID
			require.NoError(t, json.Unmarshal([]byte(body), &id))
			assert.Equal(t, want, id)
		})
	}
}

func TestID_RejectsWhatIsNotAnUnsignedInteger(t *testing.T) {
	for _, body := range []string{`-1`, `"-1"`, `1.5`, `1e9`, `"abc"`, `true`, `"18446744073709551616"`, `"\x"`} {
		t.Run(body, func(t *testing.T) {
			var id ID
			err := id.UnmarshalJSON([]byte(body))

			assert.Equal(t, ErrInvalidID{Value: body}, err)
			assert.Contains(t, err.Error(), body)
			assert.Zero(t, id)
		})
	}
}
