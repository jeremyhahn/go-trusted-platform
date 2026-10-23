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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A resolver section with no usable server is refused, and Run refuses it
// before anything is started.
func TestConfigValidate_Resolver(t *testing.T) {
	assert.NoError(t, (&Config{}).Validate(), "no resolver section")
	assert.NoError(t, (&Config{Resolver: DefaultResolverConfig()}).Validate())

	cfg := &Config{Resolver: &ResolverConfig{}}
	assert.ErrorIs(t, cfg.Validate(), ErrNoResolverServers{})
	assert.ErrorIs(t, Run("", "", nil, cfg), ErrNoResolverServers{})

	cfg = &Config{Resolver: &ResolverConfig{Servers: []ResolverServer{{Address: "127.0.0.1", Port: 0}}}}
	var portErr ErrInvalidResolverPort
	assert.ErrorAs(t, cfg.Validate(), &portErr)
}

// default-ttl must be a TTL RFC 2181 §8 allows; 0 leaves it unset.
func TestConfigValidate_DefaultTTL(t *testing.T) {
	for _, ttl := range []int{0, 300, maxTTL} {
		assert.NoError(t, (&Config{DefaultTTL: ttl}).Validate(), ttl)
	}
	for _, ttl := range []int{-1, maxTTL + 1} {
		cfg := &Config{DefaultTTL: ttl}
		assert.ErrorIs(t, cfg.Validate(), ErrInvalidTTL, ttl)
		assert.ErrorIs(t, Run("", "", nil, cfg), ErrInvalidTTL, ttl)
	}
}

// TestConfigValidate_KeyLifetime: a ksk or zsk lifetime that is not a positive
// duration stops dns.Run; an absent one, or DNSSEC disabled, does not.
func TestConfigValidate_KeyLifetime(t *testing.T) {
	dnssecWith := func(ksk, zsk string) *Config {
		return &Config{DNSSEC: &DNSSECConfig{
			Enabled: true,
			KSK:     &DNSSECKeyConfig{Lifetime: ksk},
			ZSK:     &DNSSECKeyConfig{Lifetime: zsk},
		}}
	}

	assert.NoError(t, dnssecWith("365d", "30d").Validate())
	assert.NoError(t, dnssecWith("", "").Validate())
	assert.NoError(t, (&Config{DNSSEC: &DNSSECConfig{Enabled: true}}).Validate())
	assert.NoError(t, (&Config{DNSSEC: &DNSSECConfig{KSK: &DNSSECKeyConfig{Lifetime: "x"}}}).Validate())

	for _, cfg := range []*Config{
		dnssecWith("365", "30d"),
		dnssecWith("365d", "0d"),
		dnssecWith("-1d", "30d"),
		dnssecWith("365d", "a year"),
	} {
		assert.ErrorIs(t, cfg.Validate(), ErrInvalidKeyLifetime)
		assert.ErrorIs(t, Run("", "", nil, cfg), ErrInvalidKeyLifetime)
	}
}

// TestDNSSECKeyConfig_LifetimeDuration: the configured lifetime is returned as
// a duration, 0 when none is set.
func TestDNSSECKeyConfig_LifetimeDuration(t *testing.T) {
	lifetime, err := (&DNSSECKeyConfig{Lifetime: "30d"}).LifetimeDuration()
	require.NoError(t, err)
	assert.Equal(t, 30*24*time.Hour, lifetime)

	var unset *DNSSECKeyConfig
	lifetime, err = unset.LifetimeDuration()
	require.NoError(t, err)
	assert.Zero(t, lifetime)

	_, err = (&DNSSECKeyConfig{Lifetime: "30x"}).LifetimeDuration()
	assert.ErrorIs(t, err, ErrInvalidKeyLifetime)
}

// RecordTTL is default-ttl, or 3600 when it is unset.
func TestConfigRecordTTL(t *testing.T) {
	assert.Equal(t, uint32(120), (&Config{DefaultTTL: 120}).RecordTTL())
	assert.Equal(t, fallbackRecordTTL, (&Config{}).RecordTTL())
	var nilConfig *Config
	assert.Equal(t, fallbackRecordTTL, nilConfig.RecordTTL())
}
