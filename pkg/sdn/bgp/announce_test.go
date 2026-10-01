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

package bgp

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnnounceConfig_Validate_Valid(t *testing.T) {
	tests := []struct {
		name   string
		config AnnounceConfig
	}{
		{
			name:   "empty config",
			config: AnnounceConfig{},
		},
		{
			name: "IPv4 only",
			config: AnnounceConfig{
				IPv4Prefixes: []string{"203.0.113.0/24"},
			},
		},
		{
			name: "IPv6 only",
			config: AnnounceConfig{
				IPv6Prefixes: []string{"2001:DB8::/36"},
			},
		},
		{
			name: "both IPv4 and IPv6",
			config: AnnounceConfig{
				IPv4Prefixes: []string{"203.0.113.0/24"},
				IPv6Prefixes: []string{"2001:DB8::/36"},
			},
		},
		{
			name: "multiple prefixes",
			config: AnnounceConfig{
				IPv4Prefixes: []string{"203.0.113.0/24", "10.0.0.0/8"},
				IPv6Prefixes: []string{"2001:DB8::/36", "fd00::/48"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			require.NoError(t, err)
		})
	}
}

func TestAnnounceConfig_Validate_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		config AnnounceConfig
	}{
		{
			name: "invalid IPv4 prefix",
			config: AnnounceConfig{
				IPv4Prefixes: []string{"not-a-prefix"},
			},
		},
		{
			name: "IPv6 in IPv4 list",
			config: AnnounceConfig{
				IPv4Prefixes: []string{"2001:DB8::/36"},
			},
		},
		{
			name: "invalid IPv6 prefix",
			config: AnnounceConfig{
				IPv6Prefixes: []string{"garbage"},
			},
		},
		{
			name: "IPv4 in IPv6 list",
			config: AnnounceConfig{
				IPv6Prefixes: []string{"203.0.113.0/24"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			require.Error(t, err)
		})
	}
}

func TestAnnounceConfig_AllPrefixes(t *testing.T) {
	t.Run("returns all prefixes", func(t *testing.T) {
		cfg := AnnounceConfig{
			IPv4Prefixes: []string{"203.0.113.0/24"},
			IPv6Prefixes: []string{"2001:DB8::/36"},
		}
		prefixes, err := cfg.AllPrefixes()
		require.NoError(t, err)
		assert.Len(t, prefixes, 2)
		assert.Equal(t, "203.0.113.0/24", prefixes[0].String())
		assert.Equal(t, "2001:db8::/36", prefixes[1].String())
	})

	t.Run("empty config returns empty slice", func(t *testing.T) {
		cfg := AnnounceConfig{}
		prefixes, err := cfg.AllPrefixes()
		require.NoError(t, err)
		assert.Empty(t, prefixes)
	})

	t.Run("invalid prefix returns error", func(t *testing.T) {
		cfg := AnnounceConfig{
			IPv4Prefixes: []string{"bad"},
		}
		_, err := cfg.AllPrefixes()
		require.Error(t, err)
		var prefixErr *ErrPrefixInvalid
		require.True(t, errors.As(err, &prefixErr))
	})
}

func TestAnnounceConfig_HasPrefixes(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		cfg := AnnounceConfig{}
		assert.False(t, cfg.HasPrefixes())
	})

	t.Run("has IPv4", func(t *testing.T) {
		cfg := AnnounceConfig{IPv4Prefixes: []string{"10.0.0.0/8"}}
		assert.True(t, cfg.HasPrefixes())
	})

	t.Run("has IPv6", func(t *testing.T) {
		cfg := AnnounceConfig{IPv6Prefixes: []string{"fd00::/48"}}
		assert.True(t, cfg.HasPrefixes())
	})
}

func TestBGPConfig_Validate_WithAnnounce(t *testing.T) {
	t.Run("valid config with announce", func(t *testing.T) {
		cfg := validBGPConfigForAnnounce()
		cfg.Announce = &AnnounceConfig{
			IPv4Prefixes: []string{"203.0.113.0/24"},
		}
		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("invalid announce prefix rejected", func(t *testing.T) {
		cfg := validBGPConfigForAnnounce()
		cfg.Announce = &AnnounceConfig{
			IPv4Prefixes: []string{"not-valid"},
		}
		err := cfg.Validate()
		require.Error(t, err)
	})

	t.Run("nil announce is valid", func(t *testing.T) {
		cfg := validBGPConfigForAnnounce()
		cfg.Announce = nil
		err := cfg.Validate()
		require.NoError(t, err)
	})
}

func TestBGPConfig_Validate_WithNeighbors(t *testing.T) {
	t.Run("valid neighbor in config", func(t *testing.T) {
		cfg := validBGPConfigForAnnounce()
		cfg.Neighbors = []NeighborConfig{validNeighborConfigForAnnounce()}
		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("invalid neighbor rejected", func(t *testing.T) {
		cfg := validBGPConfigForAnnounce()
		cfg.Neighbors = []NeighborConfig{{}} // empty, invalid
		err := cfg.Validate()
		require.Error(t, err)
	})
}

func validBGPConfigForAnnounce() BGPConfig {
	return BGPConfig{
		RouterID: netip.MustParseAddr("10.255.0.1"),
		ASN:      64512,
		Capabilities: BGPCapabilities{
			IPv4Unicast: true,
		},
	}
}

func validNeighborConfigForAnnounce() NeighborConfig {
	return NeighborConfig{
		Address:     netip.MustParseAddr("10.255.0.2"),
		ASN:         64512,
		IPv4Unicast: true,
	}
}
