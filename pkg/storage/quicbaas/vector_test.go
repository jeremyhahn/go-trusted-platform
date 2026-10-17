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

package quicbaas

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestToQuicBaaSConfig_VectorEnabled proves an enabled vector section
// reaches the embedded server: without it the server never registers the
// Vector service and every Vector RPC answers UNIMPLEMENTED.
func TestToQuicBaaSConfig_VectorEnabled(t *testing.T) {
	c := &Config{DataDir: t.TempDir(), Vector: &VectorServiceConfig{Enabled: true}}
	c.SetDefaults()
	assert.True(t, c.ToQuicBaaSConfig().Vector.Enabled)
}

// TestToQuicBaaSConfig_VectorDisabled proves an absent or disabled vector
// section leaves the embedded server's vector service off.
func TestToQuicBaaSConfig_VectorDisabled(t *testing.T) {
	for name, section := range map[string]*VectorServiceConfig{
		"absent":   nil,
		"disabled": {Enabled: false},
	} {
		t.Run(name, func(t *testing.T) {
			c := &Config{DataDir: t.TempDir(), Vector: section}
			c.SetDefaults()
			assert.False(t, c.ToQuicBaaSConfig().Vector.Enabled)
		})
	}
}

func TestVectorServiceConfig_Active(t *testing.T) {
	var absent *VectorServiceConfig
	assert.False(t, absent.Active(), "a nil section is disabled")
	assert.False(t, (&VectorServiceConfig{}).Active())
	assert.True(t, (&VectorServiceConfig{Enabled: true}).Active())
}

// TestTestConfig_VectorMatchesBuild proves the embedded test config serves
// the vector service exactly when the build carries it, so the integration
// build (WITH_VECTOR=1 tags) runs the Vector suites against a real store.
func TestTestConfig_VectorMatchesBuild(t *testing.T) {
	cfg := TestConfig(t)
	assert.Equal(t, vectorCompiled, cfg.Vector.Active())
	assert.NoError(t, cfg.validateVector())
}
