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

package vxlan

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVNIMapper(t *testing.T) {
	t.Run("creates mapper with provided config", func(t *testing.T) {
		config := VNIMappingConfig{
			BaseVNI: 2000000,
			MaxVLAN: 2000,
		}

		mapper := NewVNIMapper(config)

		require.NotNil(t, mapper)
		assert.Equal(t, VNI(2000000), mapper.config.BaseVNI)
		assert.Equal(t, uint16(2000), mapper.config.MaxVLAN)
	})

	t.Run("uses defaults for zero values", func(t *testing.T) {
		config := VNIMappingConfig{
			BaseVNI: 0,
			MaxVLAN: 0,
		}

		mapper := NewVNIMapper(config)

		require.NotNil(t, mapper)
		assert.Equal(t, DefaultBaseVNI, mapper.config.BaseVNI)
		assert.Equal(t, uint16(4094), mapper.config.MaxVLAN)
	})

	t.Run("initializes empty maps", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())

		assert.NotNil(t, mapper.vlanToVNI)
		assert.NotNil(t, mapper.vniToVLAN)
		assert.Equal(t, 0, len(mapper.vlanToVNI))
		assert.Equal(t, 0, len(mapper.vniToVLAN))
	})
}

func TestVNIMapper_VLANToVNI(t *testing.T) {
	t.Run("calculates VNI from VLAN with default mapping", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())

		vni, err := mapper.VLANToVNI(100)

		require.NoError(t, err)
		assert.Equal(t, VNI(1000100), vni)
	})

	t.Run("returns explicit mapping when registered", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())
		err := mapper.RegisterMapping(100, 5000000)
		require.NoError(t, err)

		vni, err := mapper.VLANToVNI(100)

		require.NoError(t, err)
		assert.Equal(t, VNI(5000000), vni)
	})

	t.Run("rejects VLAN exceeding maximum", func(t *testing.T) {
		mapper := NewVNIMapper(VNIMappingConfig{
			BaseVNI: DefaultBaseVNI,
			MaxVLAN: 1000,
		})

		_, err := mapper.VLANToVNI(1001)

		assert.ErrorIs(t, err, ErrVLANOutOfRange)
	})

	t.Run("handles VLAN 0", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())

		vni, err := mapper.VLANToVNI(0)

		require.NoError(t, err)
		assert.Equal(t, DefaultBaseVNI, vni)
	})

	t.Run("handles maximum VLAN", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())

		vni, err := mapper.VLANToVNI(4094)

		require.NoError(t, err)
		assert.Equal(t, VNI(1004094), vni)
	})
}

func TestVNIMapper_VNIToVLAN(t *testing.T) {
	t.Run("calculates VLAN from VNI with default mapping", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())

		vlan, err := mapper.VNIToVLAN(1000100)

		require.NoError(t, err)
		assert.Equal(t, uint16(100), vlan)
	})

	t.Run("returns explicit mapping when registered", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())
		err := mapper.RegisterMapping(100, 5000000)
		require.NoError(t, err)

		vlan, err := mapper.VNIToVLAN(5000000)

		require.NoError(t, err)
		assert.Equal(t, uint16(100), vlan)
	})

	t.Run("rejects invalid VNI - zero", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())

		_, err := mapper.VNIToVLAN(0)

		assert.ErrorIs(t, err, ErrVNIOutOfRange)
	})

	t.Run("rejects invalid VNI - exceeds maximum", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())

		_, err := mapper.VNIToVLAN(MaxVNI + 1)

		assert.ErrorIs(t, err, ErrVNIOutOfRange)
	})

	t.Run("rejects VNI below base when no explicit mapping", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())

		_, err := mapper.VNIToVLAN(100) // Below BaseVNI of 1000000

		assert.ErrorIs(t, err, ErrMappingNotFound)
	})

	t.Run("rejects VNI resulting in VLAN exceeding maximum", func(t *testing.T) {
		mapper := NewVNIMapper(VNIMappingConfig{
			BaseVNI: DefaultBaseVNI,
			MaxVLAN: 1000,
		})

		_, err := mapper.VNIToVLAN(1002000) // Would result in VLAN 2000 > MaxVLAN 1000

		assert.ErrorIs(t, err, ErrVLANOutOfRange)
	})

	t.Run("handles base VNI returning VLAN 0", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())

		vlan, err := mapper.VNIToVLAN(DefaultBaseVNI)

		require.NoError(t, err)
		assert.Equal(t, uint16(0), vlan)
	})
}

func TestVNIMapper_RegisterMapping(t *testing.T) {
	t.Run("registers valid mapping", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())

		err := mapper.RegisterMapping(100, 5000000)

		require.NoError(t, err)
		assert.True(t, mapper.HasMapping(100))
		assert.True(t, mapper.HasVNI(5000000))
	})

	t.Run("rejects VLAN exceeding maximum", func(t *testing.T) {
		mapper := NewVNIMapper(VNIMappingConfig{
			BaseVNI: DefaultBaseVNI,
			MaxVLAN: 1000,
		})

		err := mapper.RegisterMapping(1001, 5000000)

		assert.ErrorIs(t, err, ErrVLANOutOfRange)
	})

	t.Run("rejects invalid VNI - zero", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())

		err := mapper.RegisterMapping(100, 0)

		assert.ErrorIs(t, err, ErrVNIOutOfRange)
	})

	t.Run("rejects invalid VNI - exceeds maximum", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())

		err := mapper.RegisterMapping(100, MaxVNI+1)

		assert.ErrorIs(t, err, ErrVNIOutOfRange)
	})

	t.Run("rejects VNI already in use by different VLAN", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())
		err := mapper.RegisterMapping(100, 5000000)
		require.NoError(t, err)

		err = mapper.RegisterMapping(200, 5000000)

		assert.ErrorIs(t, err, ErrVNIInUse)
	})

	t.Run("allows updating same VLAN with same VNI", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())
		err := mapper.RegisterMapping(100, 5000000)
		require.NoError(t, err)

		err = mapper.RegisterMapping(100, 5000000)

		require.NoError(t, err)
	})
}

func TestVNIMapper_UnregisterMapping(t *testing.T) {
	t.Run("removes existing mapping", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())
		err := mapper.RegisterMapping(100, 5000000)
		require.NoError(t, err)

		err = mapper.UnregisterMapping(100)

		require.NoError(t, err)
		assert.False(t, mapper.HasMapping(100))
		assert.False(t, mapper.HasVNI(5000000))
	})

	t.Run("returns error for non-existent mapping", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())

		err := mapper.UnregisterMapping(100)

		assert.ErrorIs(t, err, ErrMappingNotFound)
	})

	t.Run("rejects VLAN exceeding maximum", func(t *testing.T) {
		mapper := NewVNIMapper(VNIMappingConfig{
			BaseVNI: DefaultBaseVNI,
			MaxVLAN: 1000,
		})

		err := mapper.UnregisterMapping(1001)

		assert.ErrorIs(t, err, ErrVLANOutOfRange)
	})
}

func TestVNIMapper_ListMappings(t *testing.T) {
	t.Run("returns empty map when no mappings", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())

		mappings := mapper.ListMappings()

		assert.NotNil(t, mappings)
		assert.Equal(t, 0, len(mappings))
	})

	t.Run("returns all registered mappings", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())
		err := mapper.RegisterMapping(100, 5000100)
		require.NoError(t, err)
		err = mapper.RegisterMapping(200, 5000200)
		require.NoError(t, err)

		mappings := mapper.ListMappings()

		assert.Equal(t, 2, len(mappings))
		assert.Equal(t, VNI(5000100), mappings[100])
		assert.Equal(t, VNI(5000200), mappings[200])
	})

	t.Run("returns a copy of mappings", func(t *testing.T) {
		mapper := NewVNIMapper(DefaultVNIMappingConfig())
		err := mapper.RegisterMapping(100, 5000100)
		require.NoError(t, err)

		mappings := mapper.ListMappings()
		mappings[200] = 5000200 // Modify returned map

		// Original should be unchanged
		assert.False(t, mapper.HasMapping(200))
	})
}

func TestVNIMapper_HasMapping(t *testing.T) {
	mapper := NewVNIMapper(DefaultVNIMappingConfig())

	t.Run("returns false for non-existent mapping", func(t *testing.T) {
		assert.False(t, mapper.HasMapping(100))
	})

	t.Run("returns true for existing mapping", func(t *testing.T) {
		err := mapper.RegisterMapping(100, 5000000)
		require.NoError(t, err)

		assert.True(t, mapper.HasMapping(100))
	})
}

func TestVNIMapper_HasVNI(t *testing.T) {
	mapper := NewVNIMapper(DefaultVNIMappingConfig())

	t.Run("returns false for non-existent VNI", func(t *testing.T) {
		assert.False(t, mapper.HasVNI(5000000))
	})

	t.Run("returns true for existing VNI", func(t *testing.T) {
		err := mapper.RegisterMapping(100, 5000000)
		require.NoError(t, err)

		assert.True(t, mapper.HasVNI(5000000))
	})
}

func TestVNIMapper_Config(t *testing.T) {
	config := VNIMappingConfig{
		BaseVNI: 2000000,
		MaxVLAN: 2000,
	}
	mapper := NewVNIMapper(config)

	result := mapper.Config()

	assert.Equal(t, config.BaseVNI, result.BaseVNI)
	assert.Equal(t, config.MaxVLAN, result.MaxVLAN)
}

func TestVNIMapper_Count(t *testing.T) {
	mapper := NewVNIMapper(DefaultVNIMappingConfig())

	t.Run("returns 0 initially", func(t *testing.T) {
		assert.Equal(t, 0, mapper.Count())
	})

	t.Run("returns correct count after registrations", func(t *testing.T) {
		err := mapper.RegisterMapping(100, 5000100)
		require.NoError(t, err)
		err = mapper.RegisterMapping(200, 5000200)
		require.NoError(t, err)

		assert.Equal(t, 2, mapper.Count())
	})

	t.Run("returns correct count after unregistration", func(t *testing.T) {
		err := mapper.UnregisterMapping(100)
		require.NoError(t, err)

		assert.Equal(t, 1, mapper.Count())
	})
}

func TestVNIMapper_Clear(t *testing.T) {
	mapper := NewVNIMapper(DefaultVNIMappingConfig())
	err := mapper.RegisterMapping(100, 5000100)
	require.NoError(t, err)
	err = mapper.RegisterMapping(200, 5000200)
	require.NoError(t, err)

	mapper.Clear()

	assert.Equal(t, 0, mapper.Count())
	assert.False(t, mapper.HasMapping(100))
	assert.False(t, mapper.HasMapping(200))
}

func TestVNIMapper_ValidateVNIRange(t *testing.T) {
	mapper := NewVNIMapper(VNIMappingConfig{
		BaseVNI: 1000000,
		MaxVLAN: 1000,
	})

	tests := []struct {
		name     string
		vni      VNI
		expected bool
	}{
		{
			name:     "base VNI is valid",
			vni:      1000000,
			expected: true,
		},
		{
			name:     "max VNI is valid",
			vni:      1001000, // BaseVNI + MaxVLAN
			expected: true,
		},
		{
			name:     "mid-range VNI is valid",
			vni:      1000500,
			expected: true,
		},
		{
			name:     "VNI below base is invalid",
			vni:      999999,
			expected: false,
		},
		{
			name:     "VNI above max is invalid",
			vni:      1001001,
			expected: false,
		},
		{
			name:     "zero VNI is invalid",
			vni:      0,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := mapper.ValidateVNIRange(tc.vni)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestVNIMapper_Concurrency(t *testing.T) {
	mapper := NewVNIMapper(DefaultVNIMappingConfig())
	var wg sync.WaitGroup
	numGoroutines := 100

	// Test concurrent registrations
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(vlan uint16) {
			defer wg.Done()
			vni := VNI(5000000 + uint32(vlan))
			_ = mapper.RegisterMapping(vlan, vni)
		}(uint16(i))
	}
	wg.Wait()

	// Verify all mappings are present
	for i := 0; i < numGoroutines; i++ {
		assert.True(t, mapper.HasMapping(uint16(i)))
	}

	// Test concurrent reads
	wg.Add(numGoroutines * 2)
	for i := 0; i < numGoroutines; i++ {
		go func(vlan uint16) {
			defer wg.Done()
			_, _ = mapper.VLANToVNI(vlan)
		}(uint16(i))
		go func(vni VNI) {
			defer wg.Done()
			_, _ = mapper.VNIToVLAN(vni)
		}(VNI(5000000 + uint32(i)))
	}
	wg.Wait()

	// Test concurrent unregistrations
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(vlan uint16) {
			defer wg.Done()
			_ = mapper.UnregisterMapping(vlan)
		}(uint16(i))
	}
	wg.Wait()

	assert.Equal(t, 0, mapper.Count())
}
