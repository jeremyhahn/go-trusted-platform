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

func TestPrimaryServer_WithServers(t *testing.T) {
	cfg := &ResolverConfig{
		Servers: []ResolverServer{
			{Address: "10.0.0.1", Port: 8053},
			{Address: "10.0.0.2", Port: 53},
		},
	}
	result := cfg.PrimaryServer()
	assert.Equal(t, "10.0.0.1:8053", result)
}

func TestPrimaryServer_Empty(t *testing.T) {
	cfg := &ResolverConfig{}
	result := cfg.PrimaryServer()
	assert.Equal(t, "", result)
}

func TestPrimaryServerDnsmasq_Format(t *testing.T) {
	cfg := &ResolverConfig{
		Servers: []ResolverServer{
			{Address: "192.168.1.1", Port: 8053},
		},
	}
	result := cfg.PrimaryServerDnsmasq()
	assert.Equal(t, "192.168.1.1#8053", result)
}

func TestPrimaryServerDnsmasq_Empty(t *testing.T) {
	cfg := &ResolverConfig{}
	result := cfg.PrimaryServerDnsmasq()
	assert.Equal(t, "", result)
}

func TestNameservers_WithLocalForwarder(t *testing.T) {
	cfg := &ResolverConfig{
		Servers: []ResolverServer{
			{Address: "10.0.0.1", Port: 8053},
		},
		LocalForwarder: &LocalForwarderConfig{
			Enabled:   true,
			Listen:    "127.0.0.1:53",
			CacheSize: 1000,
		},
	}
	result := cfg.Nameservers()
	assert.Equal(t, []string{"127.0.0.1"}, result)
}

func TestNameservers_WithoutLocalForwarder(t *testing.T) {
	cfg := &ResolverConfig{
		Servers: []ResolverServer{
			{Address: "10.0.0.1", Port: 53},
			{Address: "10.0.0.2", Port: 53},
		},
	}
	result := cfg.Nameservers()
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, result)
}

func TestNameservers_WithDisabledLocalForwarder(t *testing.T) {
	cfg := &ResolverConfig{
		Servers: []ResolverServer{
			{Address: "10.0.0.1", Port: 8053},
		},
		LocalForwarder: &LocalForwarderConfig{
			Enabled: false,
		},
	}
	result := cfg.Nameservers()
	assert.Equal(t, []string{"10.0.0.1"}, result)
}

func TestNameservers_Empty(t *testing.T) {
	cfg := &ResolverConfig{}
	result := cfg.Nameservers()
	assert.Nil(t, result)
}

func TestNetResolver_CreatesResolver(t *testing.T) {
	cfg := &ResolverConfig{
		Servers: []ResolverServer{
			{Address: "127.0.0.1", Port: 8053},
		},
	}
	resolver := cfg.NetResolver()
	require.NotNil(t, resolver)
	assert.True(t, resolver.PreferGo)
}

func TestNetResolver_Empty(t *testing.T) {
	cfg := &ResolverConfig{}
	resolver := cfg.NetResolver()
	assert.Nil(t, resolver)
}

func TestNeedsLocalForwarder_NonStandardPort(t *testing.T) {
	cfg := &ResolverConfig{
		Servers: []ResolverServer{
			{Address: "127.0.0.1", Port: 8053},
		},
	}
	assert.True(t, cfg.NeedsLocalForwarder())
}

func TestNeedsLocalForwarder_StandardPort(t *testing.T) {
	cfg := &ResolverConfig{
		Servers: []ResolverServer{
			{Address: "8.8.8.8", Port: 53},
		},
	}
	assert.False(t, cfg.NeedsLocalForwarder())
}

func TestNeedsLocalForwarder_MixedPorts(t *testing.T) {
	cfg := &ResolverConfig{
		Servers: []ResolverServer{
			{Address: "8.8.8.8", Port: 53},
			{Address: "127.0.0.1", Port: 8053},
		},
	}
	assert.True(t, cfg.NeedsLocalForwarder())
}

func TestNeedsLocalForwarder_NoServers(t *testing.T) {
	cfg := &ResolverConfig{}
	assert.False(t, cfg.NeedsLocalForwarder())
}

func TestValidate_Valid(t *testing.T) {
	cfg := &ResolverConfig{
		Servers: []ResolverServer{
			{Address: "127.0.0.1", Port: 8053},
			{Address: "8.8.8.8", Port: 53},
		},
	}
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestValidate_NoServers(t *testing.T) {
	cfg := &ResolverConfig{}
	err := cfg.Validate()
	require.Error(t, err)
	var target ErrNoResolverServers
	assert.True(t, errors.As(err, &target))
}

func TestValidate_InvalidPortZero(t *testing.T) {
	cfg := &ResolverConfig{
		Servers: []ResolverServer{
			{Address: "127.0.0.1", Port: 0},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	var target ErrInvalidResolverPort
	assert.True(t, errors.As(err, &target))
	assert.Equal(t, "127.0.0.1", target.Address)
	assert.Equal(t, 0, target.Port)
}

func TestValidate_InvalidPortTooHigh(t *testing.T) {
	cfg := &ResolverConfig{
		Servers: []ResolverServer{
			{Address: "10.0.0.1", Port: 70000},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	var target ErrInvalidResolverPort
	assert.True(t, errors.As(err, &target))
	assert.Equal(t, 70000, target.Port)
}

func TestValidate_InvalidPortNegative(t *testing.T) {
	cfg := &ResolverConfig{
		Servers: []ResolverServer{
			{Address: "10.0.0.1", Port: -1},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	var target ErrInvalidResolverPort
	assert.True(t, errors.As(err, &target))
}

func TestValidate_EmptyAddress(t *testing.T) {
	cfg := &ResolverConfig{
		Servers: []ResolverServer{
			{Address: "", Port: 53},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	var target ErrInvalidResolverAddress
	assert.True(t, errors.As(err, &target))
	assert.Equal(t, 0, target.Index)
}

func TestValidate_EmptyAddressSecondServer(t *testing.T) {
	cfg := &ResolverConfig{
		Servers: []ResolverServer{
			{Address: "127.0.0.1", Port: 53},
			{Address: "", Port: 53},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	var target ErrInvalidResolverAddress
	assert.True(t, errors.As(err, &target))
	assert.Equal(t, 1, target.Index)
}

func TestDefaultResolverConfig(t *testing.T) {
	cfg := DefaultResolverConfig()
	require.NotNil(t, cfg)
	require.Len(t, cfg.Servers, 1)
	assert.Equal(t, "127.0.0.1", cfg.Servers[0].Address)
	assert.Equal(t, 8053, cfg.Servers[0].Port)
	require.Len(t, cfg.Fallback, 2)
	assert.Equal(t, "1.1.1.1:53", cfg.Fallback[0])
	assert.Equal(t, "8.8.8.8:53", cfg.Fallback[1])
	require.NotNil(t, cfg.LocalForwarder)
	assert.Equal(t, "127.0.0.1:53", cfg.LocalForwarder.Listen)
	assert.Equal(t, 1000, cfg.LocalForwarder.CacheSize)
	assert.False(t, cfg.LocalForwarder.Enabled)
}

func TestDefaultConfig_HasResolver(t *testing.T) {
	require.NotNil(t, DefaultConfig.Resolver)
	assert.Len(t, DefaultConfig.Resolver.Servers, 1)
	assert.Equal(t, "127.0.0.1", DefaultConfig.Resolver.Servers[0].Address)
	assert.Equal(t, 8053, DefaultConfig.Resolver.Servers[0].Port)
	assert.NoError(t, DefaultConfig.Resolver.Validate())
}

func TestResolverErrorMessages(t *testing.T) {
	t.Run("ErrNoResolverServers", func(t *testing.T) {
		err := ErrNoResolverServers{}
		assert.Equal(t, "resolver: no servers configured", err.Error())
	})

	t.Run("ErrInvalidResolverPort", func(t *testing.T) {
		err := ErrInvalidResolverPort{Address: "10.0.0.1", Port: 99999}
		assert.Contains(t, err.Error(), "99999")
		assert.Contains(t, err.Error(), "10.0.0.1")
	})

	t.Run("ErrInvalidResolverAddress", func(t *testing.T) {
		err := ErrInvalidResolverAddress{Index: 2}
		assert.Contains(t, err.Error(), "2")
	})
}

func TestValidate_BoundaryPorts(t *testing.T) {
	t.Run("Port1_Valid", func(t *testing.T) {
		cfg := &ResolverConfig{
			Servers: []ResolverServer{{Address: "127.0.0.1", Port: 1}},
		}
		assert.NoError(t, cfg.Validate())
	})

	t.Run("Port65535_Valid", func(t *testing.T) {
		cfg := &ResolverConfig{
			Servers: []ResolverServer{{Address: "127.0.0.1", Port: 65535}},
		}
		assert.NoError(t, cfg.Validate())
	})

	t.Run("Port65536_Invalid", func(t *testing.T) {
		cfg := &ResolverConfig{
			Servers: []ResolverServer{{Address: "127.0.0.1", Port: 65536}},
		}
		err := cfg.Validate()
		require.Error(t, err)
		var target ErrInvalidResolverPort
		assert.True(t, errors.As(err, &target))
	})
}
