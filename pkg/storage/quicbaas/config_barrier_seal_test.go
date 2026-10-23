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

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/stretchr/testify/assert"
)

// TestToQuicBaaSConfig_BarrierShamir proves a shamir barrier selects the
// embedded server's Shamir seal strategy with the configured M-of-N — the
// only barrier that enforces the quorum a shamir /init asks for.
func TestToQuicBaaSConfig_BarrierShamir(t *testing.T) {
	c := &Config{
		DataDir:                t.TempDir(),
		SPIFFETrustDomain:      "example.internal",
		BarrierSealStrategy:    "shamir",
		BarrierShamirThreshold: 3,
		BarrierShamirShares:    5,
	}
	c.SetDefaults()
	cfg := c.ToQuicBaaSConfig()
	assert.Equal(t, "shamir", cfg.Seal.Strategy)
	assert.Equal(t, 3, cfg.Seal.Threshold)
	assert.Equal(t, 5, cfg.Seal.TotalShares)
}

// TestToQuicBaaSConfig_BarrierShamirDefaultQuorum proves an unset M-of-N
// keeps the embedded server's own Shamir defaults rather than zeroing them.
func TestToQuicBaaSConfig_BarrierShamirDefaultQuorum(t *testing.T) {
	c := &Config{DataDir: t.TempDir(), SPIFFETrustDomain: "example.internal", BarrierSealStrategy: "shamir"}
	c.SetDefaults()
	cfg := c.ToQuicBaaSConfig()
	defaults := quicbaas.EmbeddedServerConfig().Seal
	assert.Equal(t, "shamir", cfg.Seal.Strategy)
	assert.Equal(t, defaults.Threshold, cfg.Seal.Threshold)
	assert.Equal(t, defaults.TotalShares, cfg.Seal.TotalShares)
}

// TestToQuicBaaSConfig_BarrierNonShamirKeepsDefault proves every other
// barrier strategy leaves the embedded seal section untouched.
func TestToQuicBaaSConfig_BarrierNonShamirKeepsDefault(t *testing.T) {
	for _, strategy := range []string{"", "software", "tpm2"} {
		t.Run("strategy "+strategy, func(t *testing.T) {
			c := &Config{
				DataDir:                t.TempDir(),
				SPIFFETrustDomain:      "example.internal",
				BarrierSealStrategy:    strategy,
				BarrierShamirThreshold: 2,
				BarrierShamirShares:    3,
			}
			c.SetDefaults()
			cfg := c.ToQuicBaaSConfig()
			assert.Equal(t, quicbaas.EmbeddedServerConfig().Seal, cfg.Seal)
		})
	}
}

// The embedded server's TPM probe and tpm2 seal strategy open the platform's
// TPM: a set TPMDevice reaches seal.tpm2.device.
func TestToQuicBaaSConfig_TPMDevice(t *testing.T) {
	c := &Config{
		DataDir:           t.TempDir(),
		SPIFFETrustDomain: "example.internal",
		TPMDevice:         "/tmp/swtpm/swtpm.sock",
	}
	c.SetDefaults()
	cfg := c.ToQuicBaaSConfig()
	assert.Equal(t, "/tmp/swtpm/swtpm.sock", cfg.Seal.TPM2.Device)
}

// No TPMDevice keeps the upstream default; an empty device is never written.
func TestToQuicBaaSConfig_TPMDeviceUnsetKeepsDefault(t *testing.T) {
	c := &Config{DataDir: t.TempDir(), SPIFFETrustDomain: "example.internal"}
	c.SetDefaults()
	cfg := c.ToQuicBaaSConfig()
	assert.Equal(t, quicbaas.EmbeddedServerConfig().Seal.TPM2.Device, cfg.Seal.TPM2.Device)
}
