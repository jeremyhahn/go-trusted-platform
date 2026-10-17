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

package app

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/barrier"
	quicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/stretchr/testify/assert"
)

// TestMirrorBarrierSealStrategy_Shamir proves a shamir barrier section
// reaches the embedded QuicBaaS config with its M-of-N, so the SDK seals the
// data-plane barrier with the Shamir strategy the gate requires.
func TestMirrorBarrierSealStrategy_Shamir(t *testing.T) {
	app := &App{
		QuicBaaSConfig: &quicbaas.Config{},
		BarrierConfig: &barrier.Config{
			SealStrategy: barrier.SealStrategyShamir, ShamirThreshold: 3, ShamirShares: 5,
		},
	}
	app.mirrorBarrierSealStrategy()
	assert.Equal(t, barrier.SealStrategyShamir, app.QuicBaaSConfig.BarrierSealStrategy)
	assert.Equal(t, 3, app.QuicBaaSConfig.BarrierShamirThreshold)
	assert.Equal(t, 5, app.QuicBaaSConfig.BarrierShamirShares)
}

// TestMirrorBarrierSealStrategy_NonShamirLeavesDefault proves single-key
// strategies and an absent barrier section leave the embedded barrier on its
// default strategy, even when Shamir counts are present.
func TestMirrorBarrierSealStrategy_NonShamirLeavesDefault(t *testing.T) {
	cases := map[string]*barrier.Config{
		"no barrier section": nil,
		"software":           {SealStrategy: barrier.SealStrategySoftware, ShamirThreshold: 2, ShamirShares: 3},
		"tpm2":               {SealStrategy: barrier.SealStrategyTPM2},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			app := &App{QuicBaaSConfig: &quicbaas.Config{}, BarrierConfig: cfg}
			app.mirrorBarrierSealStrategy()
			assert.Empty(t, app.QuicBaaSConfig.BarrierSealStrategy)
			assert.Zero(t, app.QuicBaaSConfig.BarrierShamirThreshold)
			assert.Zero(t, app.QuicBaaSConfig.BarrierShamirShares)
		})
	}
}

// A concrete tpm.device reaches the embedded quicbaas config, so its TPM
// probe opens the platform's TPM rather than /dev/tpmrm0.
func TestMirrorTPMDevice_ConcreteDevice(t *testing.T) {
	app := &App{QuicBaaSConfig: &quicbaas.Config{}}
	app.TPMConfig.Device = "/tmp/swtpm/swtpm.sock"
	app.mirrorTPMDevice()
	assert.Equal(t, "/tmp/swtpm/swtpm.sock", app.QuicBaaSConfig.TPMDevice)
}

// The simulator, an empty device and the unresolved "auto" sentinel name no
// device the embedded server could open, so nothing is mirrored.
func TestMirrorTPMDevice_NothingToMirror(t *testing.T) {
	cases := map[string]func(a *App){
		"simulator": func(a *App) {
			a.TPMConfig.UseSimulator = true
			a.TPMConfig.Device = "/dev/tpmrm0"
		},
		"empty device": func(a *App) {},
		"auto":         func(a *App) { a.TPMConfig.Device = vtpm.TPMDeviceAuto },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			app := &App{QuicBaaSConfig: &quicbaas.Config{}}
			setup(app)
			app.mirrorTPMDevice()
			assert.Empty(t, app.QuicBaaSConfig.TPMDevice)
		})
	}
}
