// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
	"github.com/stretchr/testify/assert"
)

// =============================================================================
// scopeIsEmbeddedOnly — pure function, fully testable
// =============================================================================

// TestW1_ScopeIsEmbeddedOnly_NilScope verifies that a nil scope returns false.
func TestW1_ScopeIsEmbeddedOnly_NilScope(t *testing.T) {
	t.Parallel()
	assert.False(t, scopeIsEmbeddedOnly(nil))
}

// TestW1_ScopeIsEmbeddedOnly_EmptyStrategies verifies that a scope with no
// strategy entries returns false.
func TestW1_ScopeIsEmbeddedOnly_EmptyStrategies(t *testing.T) {
	t.Parallel()
	scope := &trust.ScopeConfig{Strategies: []trust.Strategy{}}
	assert.False(t, scopeIsEmbeddedOnly(scope))
}

// TestW1_ScopeIsEmbeddedOnly_SingleEmbedded verifies that a scope with exactly
// one StrategyEmbedded entry returns true.
func TestW1_ScopeIsEmbeddedOnly_SingleEmbedded(t *testing.T) {
	t.Parallel()
	scope := &trust.ScopeConfig{
		Strategies: []trust.Strategy{trust.StrategyEmbedded},
	}
	assert.True(t, scopeIsEmbeddedOnly(scope))
}

// TestW1_ScopeIsEmbeddedOnly_MultipleEmbedded verifies that a scope whose
// entire strategy list consists of StrategyEmbedded entries returns true.
func TestW1_ScopeIsEmbeddedOnly_MultipleEmbedded(t *testing.T) {
	t.Parallel()
	scope := &trust.ScopeConfig{
		Strategies: []trust.Strategy{
			trust.StrategyEmbedded,
			trust.StrategyEmbedded,
		},
	}
	assert.True(t, scopeIsEmbeddedOnly(scope))
}

// TestW1_ScopeIsEmbeddedOnly_NonEmbeddedStrategy verifies that a scope with a
// single non-embedded strategy returns false.
func TestW1_ScopeIsEmbeddedOnly_NonEmbeddedStrategy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		strategy trust.Strategy
	}{
		{name: "DANE", strategy: trust.StrategyDANE},
		{name: "SPKI", strategy: trust.StrategySPKI},
		{name: "TOFU", strategy: trust.StrategyTOFU},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			scope := &trust.ScopeConfig{
				Strategies: []trust.Strategy{tt.strategy},
			}
			assert.False(t, scopeIsEmbeddedOnly(scope),
				"single %s strategy should not be embedded-only", tt.name)
		})
	}
}

// TestW1_ScopeIsEmbeddedOnly_MixedStrategies verifies that a scope containing
// StrategyEmbedded alongside other strategies returns false, because the
// function requires ALL strategies to be embedded.
func TestW1_ScopeIsEmbeddedOnly_MixedStrategies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		strategies []trust.Strategy
	}{
		{
			name:       "EmbeddedAndDANE",
			strategies: []trust.Strategy{trust.StrategyEmbedded, trust.StrategyDANE},
		},
		{
			name:       "DANEAndEmbedded",
			strategies: []trust.Strategy{trust.StrategyDANE, trust.StrategyEmbedded},
		},
		{
			name:       "SPKIAndEmbedded",
			strategies: []trust.Strategy{trust.StrategySPKI, trust.StrategyEmbedded},
		},
		{
			name: "AllStrategiesMixed",
			strategies: []trust.Strategy{
				trust.StrategyDANE,
				trust.StrategySPKI,
				trust.StrategyTOFU,
				trust.StrategyEmbedded,
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			scope := &trust.ScopeConfig{Strategies: tt.strategies}
			assert.False(t, scopeIsEmbeddedOnly(scope),
				"mixed strategies including non-embedded must return false")
		})
	}
}

// TestW1_ScopeIsEmbeddedOnly_NilStrategiesField verifies that a non-nil
// ScopeConfig with a nil Strategies slice returns false (zero-length guard).
func TestW1_ScopeIsEmbeddedOnly_NilStrategiesField(t *testing.T) {
	t.Parallel()
	scope := &trust.ScopeConfig{Strategies: nil}
	assert.False(t, scopeIsEmbeddedOnly(scope))
}
