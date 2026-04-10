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

package uefi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGUID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    GUID
		wantErr bool
	}{
		{
			name:  "standard format",
			input: "8BE4DF61-93CA-11D2-AA0D-00E098032B8C",
			want: GUID{
				Data1: 0x8BE4DF61,
				Data2: 0x93CA,
				Data3: 0x11D2,
				Data4: [8]byte{0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C},
			},
		},
		{
			name:  "with braces",
			input: "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}",
			want: GUID{
				Data1: 0x8BE4DF61,
				Data2: 0x93CA,
				Data3: 0x11D2,
				Data4: [8]byte{0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C},
			},
		},
		{
			name:  "lowercase",
			input: "8be4df61-93ca-11d2-aa0d-00e098032b8c",
			want: GUID{
				Data1: 0x8BE4DF61,
				Data2: 0x93CA,
				Data3: 0x11D2,
				Data4: [8]byte{0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C},
			},
		},
		{
			name:  "image security database",
			input: "D719B2CB-3D3A-4596-A3BC-DAD00E67656F",
			want: GUID{
				Data1: 0xD719B2CB,
				Data2: 0x3D3A,
				Data3: 0x4596,
				Data4: [8]byte{0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F},
			},
		},
		{
			name:    "invalid - wrong number of parts",
			input:   "8BE4DF61-93CA-11D2-AA0D",
			wantErr: true,
		},
		{
			name:    "invalid - bad hex",
			input:   "ZZZZZZ61-93CA-11D2-AA0D-00E098032B8C",
			wantErr: true,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseGUID(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGUID_String(t *testing.T) {
	g := GUID{
		Data1: 0x8BE4DF61,
		Data2: 0x93CA,
		Data3: 0x11D2,
		Data4: [8]byte{0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C},
	}

	expected := "8BE4DF61-93CA-11D2-AA0D-00E098032B8C"
	assert.Equal(t, expected, g.String())
}

func TestGUID_Bytes(t *testing.T) {
	g := GUID{
		Data1: 0x8BE4DF61,
		Data2: 0x93CA,
		Data3: 0x11D2,
		Data4: [8]byte{0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C},
	}

	b := g.Bytes()
	assert.Len(t, b, 16)

	// Data1, Data2, Data3 are little-endian, Data4 is big-endian
	// 0x8BE4DF61 -> 61 DF E4 8B
	assert.Equal(t, byte(0x61), b[0])
	assert.Equal(t, byte(0xDF), b[1])
	assert.Equal(t, byte(0xE4), b[2])
	assert.Equal(t, byte(0x8B), b[3])

	// 0x93CA -> CA 93
	assert.Equal(t, byte(0xCA), b[4])
	assert.Equal(t, byte(0x93), b[5])

	// 0x11D2 -> D2 11
	assert.Equal(t, byte(0xD2), b[6])
	assert.Equal(t, byte(0x11), b[7])

	// Data4 is big-endian
	assert.Equal(t, byte(0xAA), b[8])
	assert.Equal(t, byte(0x0D), b[9])
}

func TestGUIDFromBytes(t *testing.T) {
	// Create a GUID
	original := GUID{
		Data1: 0x8BE4DF61,
		Data2: 0x93CA,
		Data3: 0x11D2,
		Data4: [8]byte{0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C},
	}

	// Convert to bytes and back
	b := original.Bytes()
	parsed, err := GUIDFromBytes(b)
	require.NoError(t, err)
	assert.Equal(t, original, parsed)
}

func TestGUIDFromBytes_TooShort(t *testing.T) {
	_, err := GUIDFromBytes([]byte{0x01, 0x02, 0x03})
	assert.Error(t, err)
}

func TestGUID_Equal(t *testing.T) {
	g1 := MustParseGUID("8BE4DF61-93CA-11D2-AA0D-00E098032B8C")
	g2 := MustParseGUID("8BE4DF61-93CA-11D2-AA0D-00E098032B8C")
	g3 := MustParseGUID("D719B2CB-3D3A-4596-A3BC-DAD00E67656F")

	assert.True(t, g1.Equal(g2))
	assert.False(t, g1.Equal(g3))
}

func TestGUID_IsZero(t *testing.T) {
	zero := GUID{}
	nonZero := MustParseGUID("8BE4DF61-93CA-11D2-AA0D-00E098032B8C")

	assert.True(t, zero.IsZero())
	assert.False(t, nonZero.IsZero())
}

func TestNewGUID(t *testing.T) {
	g1 := NewGUID()
	g2 := NewGUID()

	// Should generate different GUIDs
	assert.False(t, g1.Equal(g2))

	// Should not be zero
	assert.False(t, g1.IsZero())
	assert.False(t, g2.IsZero())

	// Should have valid string representation
	s := g1.String()
	assert.Len(t, s, 36) // XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
}

func TestWellKnownGUIDs(t *testing.T) {
	// Test that well-known GUIDs parse correctly
	tests := []struct {
		name string
		guid GUID
		str  string
	}{
		{"EFIGlobalVariable", EFIGlobalVariable, "8BE4DF61-93CA-11D2-AA0D-00E098032B8C"},
		{"EFIImageSecurityDatabase", EFIImageSecurityDatabase, "D719B2CB-3D3A-4596-A3BC-DAD00E67656F"},
		{"EFISHA256", EFISHA256, "C1C41626-504C-4092-ACA9-41F936934328"},
		{"FFS2GUID", FFS2GUID, "8C8CE578-8A3D-4F1C-9935-896185C32DD3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.str, tt.guid.String())
		})
	}
}

func TestMustParseGUID_Panic(t *testing.T) {
	assert.Panics(t, func() {
		MustParseGUID("invalid-guid")
	})
}
