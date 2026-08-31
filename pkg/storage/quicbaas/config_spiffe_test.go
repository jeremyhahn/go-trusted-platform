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
	"github.com/stretchr/testify/require"
)

// TestToQuicBaaSConfig_SPIFFETrustDomain proves the platform's
// spiffe-trust-domain key reaches the embedded server's IAM config — the
// value qrdb first-boot requires to issue the admin certificate and create
// the system tenant.
func TestToQuicBaaSConfig_SPIFFETrustDomain(t *testing.T) {
	c := &Config{
		DataDir:           t.TempDir(),
		SPIFFETrustDomain: "trusted-platform.internal",
	}
	c.SetDefaults()
	cfg := c.ToQuicBaaSConfig()
	assert.Equal(t, "trusted-platform.internal", cfg.IAM.SPIFFETrustDomain)
}

// TestValidate_SPIFFETrustDomain_Required proves the embedded
// configuration fails closed without a trust domain: qrdb first-boot
// cannot seed IAM, so a server without one would be a partially
// initialized security service.
func TestValidate_SPIFFETrustDomain_Required(t *testing.T) {
	c := &Config{DataDir: t.TempDir()}
	err := c.Validate()
	var invalid ErrInvalidConfig
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "SPIFFETrustDomain", invalid.Field)
}

// TestValidate_SPIFFETrustDomain_Format accepts valid trust domain names
// and rejects malformed ones (scheme, path, port, uppercase, spaces).
func TestValidate_SPIFFETrustDomain_Format(t *testing.T) {
	valid := []string{"trusted-platform.internal", "example.internal", "a", "prod-1.corp_x.io"}
	for _, d := range valid {
		c := &Config{DataDir: t.TempDir(), SPIFFETrustDomain: d}
		assert.NoError(t, c.Validate(), d)
	}
	invalid := []string{"spiffe://x.io", "x.io/path", "X.IO", "has space", ".leadingdot", "trailingdot.", "host:443"}
	for _, d := range invalid {
		c := &Config{DataDir: t.TempDir(), SPIFFETrustDomain: d}
		err := c.Validate()
		var bad ErrInvalidConfig
		require.ErrorAs(t, err, &bad, d)
		assert.Equal(t, "SPIFFETrustDomain", bad.Field, d)
	}
}
