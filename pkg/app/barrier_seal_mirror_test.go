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
