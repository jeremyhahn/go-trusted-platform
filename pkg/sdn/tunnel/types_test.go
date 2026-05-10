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

package tunnel

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validGREConfig() TunnelConfig {
	return TunnelConfig{
		Name:     "gre1",
		Type:     TunnelTypeGRE,
		Local:    "99.12.246.36",
		Remote:   "45.63.110.165",
		TunnelIP: "10.255.0.1/30",
		MTU:      1400,
		TTL:      64,
	}
}

func TestTunnelConfig_Validate_Valid(t *testing.T) {
	tests := []struct {
		name   string
		config TunnelConfig
	}{
		{
			name:   "valid GRE tunnel",
			config: validGREConfig(),
		},
		{
			name: "valid GRE6 tunnel",
			config: TunnelConfig{
				Name:       "gre6-01",
				Type:       TunnelTypeGRE6,
				Local:      "2001:db8::1",
				Remote:     "2001:db8::2",
				TunnelIP:   "10.255.0.1/30",
				TunnelIPv6: "fd00::1/126",
			},
		},
		{
			name: "valid IPIP tunnel",
			config: TunnelConfig{
				Name:     "ipip1",
				Type:     TunnelTypeIPIP,
				Local:    "192.168.1.1",
				Remote:   "192.168.2.1",
				TunnelIP: "10.0.0.1/30",
			},
		},
		{
			name: "GRE with key",
			config: TunnelConfig{
				Name:     "gre-keyed",
				Type:     TunnelTypeGRE,
				Local:    "10.0.0.1",
				Remote:   "10.0.0.2",
				TunnelIP: "10.255.0.1/30",
				Key:      42,
			},
		},
		{
			name: "defaults for MTU and TTL",
			config: TunnelConfig{
				Name:     "gre-defaults",
				Type:     TunnelTypeGRE,
				Local:    "10.0.0.1",
				Remote:   "10.0.0.2",
				TunnelIP: "10.255.0.1/30",
			},
		},
		{
			name: "TTL zero means default",
			config: TunnelConfig{
				Name:     "gre-ttl0",
				Type:     TunnelTypeGRE,
				Local:    "10.0.0.1",
				Remote:   "10.0.0.2",
				TunnelIP: "10.255.0.1/30",
				TTL:      0,
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

func TestTunnelConfig_Validate_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		config TunnelConfig
		reason string
	}{
		{
			name:   "empty name",
			config: TunnelConfig{Type: TunnelTypeGRE, Local: "1.2.3.4", Remote: "5.6.7.8", TunnelIP: "10.0.0.1/30"},
			reason: "name is required",
		},
		{
			name:   "name too long",
			config: TunnelConfig{Name: "0123456789abcdef", Type: TunnelTypeGRE, Local: "1.2.3.4", Remote: "5.6.7.8", TunnelIP: "10.0.0.1/30"},
			reason: "name exceeds 15 characters",
		},
		{
			name:   "empty type",
			config: TunnelConfig{Name: "gre1", Local: "1.2.3.4", Remote: "5.6.7.8", TunnelIP: "10.0.0.1/30"},
			reason: "type is required",
		},
		{
			name:   "invalid type",
			config: TunnelConfig{Name: "gre1", Type: "vxlan", Local: "1.2.3.4", Remote: "5.6.7.8", TunnelIP: "10.0.0.1/30"},
			reason: "type must be gre, gre6, or ipip",
		},
		{
			name:   "empty local",
			config: TunnelConfig{Name: "gre1", Type: TunnelTypeGRE, Remote: "5.6.7.8", TunnelIP: "10.0.0.1/30"},
			reason: "local endpoint is required",
		},
		{
			name:   "invalid local IP",
			config: TunnelConfig{Name: "gre1", Type: TunnelTypeGRE, Local: "not-an-ip", Remote: "5.6.7.8", TunnelIP: "10.0.0.1/30"},
			reason: "local is not a valid IP address",
		},
		{
			name:   "empty remote",
			config: TunnelConfig{Name: "gre1", Type: TunnelTypeGRE, Local: "1.2.3.4", TunnelIP: "10.0.0.1/30"},
			reason: "remote endpoint is required",
		},
		{
			name:   "invalid remote IP",
			config: TunnelConfig{Name: "gre1", Type: TunnelTypeGRE, Local: "1.2.3.4", Remote: "bad", TunnelIP: "10.0.0.1/30"},
			reason: "remote is not a valid IP address",
		},
		{
			name:   "empty tunnel IP",
			config: TunnelConfig{Name: "gre1", Type: TunnelTypeGRE, Local: "1.2.3.4", Remote: "5.6.7.8"},
			reason: "tunnel-ip is required",
		},
		{
			name:   "invalid tunnel IP CIDR",
			config: TunnelConfig{Name: "gre1", Type: TunnelTypeGRE, Local: "1.2.3.4", Remote: "5.6.7.8", TunnelIP: "10.0.0.1"},
			reason: "tunnel-ip is not valid CIDR",
		},
		{
			name:   "invalid tunnel IPv6 CIDR",
			config: TunnelConfig{Name: "gre1", Type: TunnelTypeGRE, Local: "1.2.3.4", Remote: "5.6.7.8", TunnelIP: "10.0.0.1/30", TunnelIPv6: "bad"},
			reason: "tunnel-ipv6 is not valid CIDR",
		},
		{
			name:   "MTU too low",
			config: TunnelConfig{Name: "gre1", Type: TunnelTypeGRE, Local: "1.2.3.4", Remote: "5.6.7.8", TunnelIP: "10.0.0.1/30", MTU: 10},
			reason: "MTU out of range",
		},
		{
			name:   "MTU too high",
			config: TunnelConfig{Name: "gre1", Type: TunnelTypeGRE, Local: "1.2.3.4", Remote: "5.6.7.8", TunnelIP: "10.0.0.1/30", MTU: 100000},
			reason: "MTU out of range",
		},
		{
			name:   "TTL too high",
			config: TunnelConfig{Name: "gre1", Type: TunnelTypeGRE, Local: "1.2.3.4", Remote: "5.6.7.8", TunnelIP: "10.0.0.1/30", TTL: 256},
			reason: "TTL out of range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			require.Error(t, err)
			var invalidConfig *ErrInvalidTunnelConfig
			require.True(t, errors.As(err, &invalidConfig))
			assert.Contains(t, invalidConfig.Reason, tt.reason)
		})
	}
}

func TestTunnelConfig_EffectiveMTU(t *testing.T) {
	t.Run("custom MTU", func(t *testing.T) {
		c := TunnelConfig{MTU: 1280}
		assert.Equal(t, 1280, c.effectiveMTU())
	})

	t.Run("default MTU", func(t *testing.T) {
		c := TunnelConfig{}
		assert.Equal(t, DefaultMTU, c.effectiveMTU())
	})
}

func TestTunnelConfig_EffectiveTTL(t *testing.T) {
	t.Run("custom TTL", func(t *testing.T) {
		c := TunnelConfig{TTL: 128}
		assert.Equal(t, 128, c.effectiveTTL())
	})

	t.Run("default TTL", func(t *testing.T) {
		c := TunnelConfig{}
		assert.Equal(t, DefaultTTL, c.effectiveTTL())
	})
}
