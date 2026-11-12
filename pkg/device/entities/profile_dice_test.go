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

package entities

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDeviceProfile_DICEFieldsValidate(t *testing.T) {
	goodHash := strings.Repeat("ab", 32)
	tests := []struct {
		name       string
		deviceID   string
		fwHash     string
		wantIDErr  bool
		wantFWErr  bool
		wantReason string
	}{
		{name: "both empty", deviceID: "", fwHash: ""},
		{name: "good", deviceID: "0123456789abcdef0123456789ABCDEF01234567", fwHash: goodHash},
		{name: "good id only", deviceID: "00ff"},
		{name: "good hash only", fwHash: strings.ToUpper(goodHash)},
		{name: "id odd length", deviceID: "abc", wantIDErr: true, wantReason: DICEReasonBadLength},
		{name: "id too long", deviceID: strings.Repeat("aa", MaxDICEDeviceIDBytes+1), wantIDErr: true, wantReason: DICEReasonBadLength},
		{name: "id non-hex", deviceID: "zz11", wantIDErr: true, wantReason: DICEReasonNotHex},
		{name: "hash short", fwHash: strings.Repeat("ab", 31), wantFWErr: true, wantReason: DICEReasonBadLength},
		{name: "hash long", fwHash: strings.Repeat("ab", 33), wantFWErr: true, wantReason: DICEReasonBadLength},
		{name: "hash non-hex", fwHash: strings.Repeat("g0", 32), wantFWErr: true, wantReason: DICEReasonNotHex},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &DeviceProfile{DICEDeviceID: tt.deviceID, GoldenFWHash: tt.fwHash}
			err := p.ValidateDICEFields()
			switch {
			case tt.wantIDErr:
				var idErr ErrInvalidDICEDeviceID
				require.True(t, errors.As(err, &idErr), "got %v", err)
				assert.Equal(t, tt.deviceID, idErr.Value)
				assert.Equal(t, tt.wantReason, idErr.Reason)
			case tt.wantFWErr:
				var fwErr ErrInvalidGoldenFWHash
				require.True(t, errors.As(err, &fwErr), "got %v", err)
				assert.Equal(t, tt.fwHash, fwErr.Value)
				assert.Equal(t, tt.wantReason, fwErr.Reason)
			default:
				require.NoError(t, err)
			}
		})
	}
}

func TestDeviceProfile_DICEFieldsYAMLRoundTrip(t *testing.T) {
	in := &DeviceProfile{DICEDeviceID: "00ff", GoldenFWHash: strings.Repeat("01", 32)}
	data, err := yaml.Marshal(in)
	require.NoError(t, err)
	assert.Contains(t, string(data), "dice-device-id: ")
	assert.Contains(t, string(data), "golden-fw-hash: ")

	var out DeviceProfile
	require.NoError(t, yaml.Unmarshal(data, &out))
	assert.Equal(t, in.DICEDeviceID, out.DICEDeviceID)
	assert.Equal(t, in.GoldenFWHash, out.GoldenFWHash)
}
