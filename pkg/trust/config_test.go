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

package trust

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Bootstrap == nil {
		t.Fatal("expected default scope to be configured")
	}
	want := []Strategy{StrategyDANE, StrategyNoise, StrategySPKI}
	if len(cfg.Bootstrap.Strategies) != len(want) {
		t.Fatalf("expected %d strategies, got %d", len(want), len(cfg.Bootstrap.Strategies))
	}
	for i, strategy := range want {
		if cfg.Bootstrap.Strategies[i] != strategy {
			t.Errorf("strategy %d: expected %s, got %s", i, strategy, cfg.Bootstrap.Strategies[i])
		}
	}
	if cfg.Bootstrap.PerMethodTimeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %s", cfg.Bootstrap.PerMethodTimeout)
	}
	if cfg.BMC != nil {
		t.Error("expected the bmc scope to be unconfigured")
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected default config to validate, got %v", err)
	}
}

func TestConfigScope(t *testing.T) {
	bootstrapScope := &ScopeConfig{Strategies: []Strategy{StrategyEmbedded}}
	bmcScope := &ScopeConfig{Strategies: []Strategy{StrategySPKI}}
	cfg := &Config{Bootstrap: bootstrapScope, BMC: bmcScope}

	if cfg.Scope(ClassBootstrap) != bootstrapScope {
		t.Error("expected bootstrap scope")
	}
	if cfg.Scope(ClassBMC) != bmcScope {
		t.Error("expected bmc scope")
	}
}

func TestConfigScope_Unknown(t *testing.T) {
	cfg := &Config{Bootstrap: &ScopeConfig{Strategies: []Strategy{StrategyEmbedded}}}
	if cfg.Scope(Class("bogus")) != nil {
		t.Error("expected nil scope for unknown class")
	}
	if cfg.Scope(ClassBMC) != nil {
		t.Error("expected nil scope for unconfigured class")
	}
}

func TestConfigValidate_Valid(t *testing.T) {
	cfg := &Config{
		Bootstrap: &ScopeConfig{
			Strategies: []Strategy{StrategyDANE, StrategyNoise, StrategySPKI, StrategyEmbedded},
			ServerURL:  "https://cp.example.com:8443",
			Hostname:   "cp.example.com",
			Noise: &NoiseConfig{
				ServerAddr:      "cp.example.com:9999",
				ServerStaticKey: "aabbcc",
			},
			SPKI:             &SPKIConfig{Pin: "deadbeef"},
			PerMethodTimeout: 5 * time.Second,
		},
		BMC: &ScopeConfig{
			Strategies: []Strategy{StrategyDANE, StrategySPKI},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestConfigValidate_EmptyStrategies(t *testing.T) {
	cfg := &Config{Bootstrap: &ScopeConfig{}}
	err := cfg.Validate()
	var invalid *ErrInvalidConfig
	if !errors.As(err, &invalid) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
	if invalid.Field != "strategies" {
		t.Errorf("expected strategies field, got %s", invalid.Field)
	}
	if invalid.Class != ClassBootstrap {
		t.Errorf("expected default class, got %s", invalid.Class)
	}
}

func TestConfigValidate_StrategyNotAllowed(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *Config
		class    Class
		strategy Strategy
	}{
		{
			name:     "noise not allowed for bmc",
			cfg:      &Config{BMC: &ScopeConfig{Strategies: []Strategy{StrategyNoise}}},
			class:    ClassBMC,
			strategy: StrategyNoise,
		},
		{
			name:     "ca-file not allowed for bootstrap",
			cfg:      &Config{Bootstrap: &ScopeConfig{Strategies: []Strategy{StrategyCAFile}}},
			class:    ClassBootstrap,
			strategy: StrategyCAFile,
		},
		{
			// The platform CA is the Anchor, not a strategy any class may list.
			name:     "platform-ca is no longer a strategy",
			cfg:      &Config{BMC: &ScopeConfig{Strategies: []Strategy{Strategy("platform-ca")}}},
			class:    ClassBMC,
			strategy: Strategy("platform-ca"),
		},
		{
			name:     "unknown strategy rejected",
			cfg:      &Config{Bootstrap: &ScopeConfig{Strategies: []Strategy{Strategy("bogus")}}},
			class:    ClassBootstrap,
			strategy: Strategy("bogus"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			var notAllowed *ErrStrategyNotAllowed
			if !errors.As(err, &notAllowed) {
				t.Fatalf("expected ErrStrategyNotAllowed, got %v", err)
			}
			if notAllowed.Class != tt.class || notAllowed.Strategy != tt.strategy {
				t.Errorf("expected class %s strategy %s, got class %s strategy %s",
					tt.class, tt.strategy, notAllowed.Class, notAllowed.Strategy)
			}
		})
	}
}

func TestConfigValidate_NoiseNilConfigAllowed(t *testing.T) {
	// A chain may list noise without supplying its inputs; the
	// resolver records a runtime attempt failure instead (legacy
	// auto-mode semantics).
	cfg := &Config{Bootstrap: &ScopeConfig{Strategies: []Strategy{StrategyNoise}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestConfigValidate_NoiseRequirements(t *testing.T) {
	tests := []struct {
		name  string
		noise *NoiseConfig
		field string
	}{
		{
			name:  "missing static key",
			noise: &NoiseConfig{ServerAddr: "cp:9999"},
			field: "noise.server-static-key",
		},
		{
			name:  "missing server addr",
			noise: &NoiseConfig{ServerStaticKey: "aabbcc"},
			field: "noise.server-addr",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Bootstrap: &ScopeConfig{
				Strategies: []Strategy{StrategyNoise},
				Noise:      tt.noise,
			}}
			err := cfg.Validate()
			var invalid *ErrInvalidConfig
			if !errors.As(err, &invalid) {
				t.Fatalf("expected ErrInvalidConfig, got %v", err)
			}
			if invalid.Field != tt.field {
				t.Errorf("expected field %s, got %s", tt.field, invalid.Field)
			}
		})
	}
}

func TestConfigValidate_SPKIPinFileResolution(t *testing.T) {
	pinFile := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(pinFile, []byte("  deadbeefcafe\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Bootstrap: &ScopeConfig{
		Strategies: []Strategy{StrategySPKI},
		SPKI:       &SPKIConfig{PinFile: pinFile},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
	if cfg.Bootstrap.SPKI.Pin != "deadbeefcafe" {
		t.Errorf("expected pin resolved from file, got %q", cfg.Bootstrap.SPKI.Pin)
	}
}

func TestConfigValidate_SPKIPinFileUnreadable(t *testing.T) {
	cfg := &Config{Bootstrap: &ScopeConfig{
		Strategies: []Strategy{StrategySPKI},
		SPKI:       &SPKIConfig{PinFile: filepath.Join(t.TempDir(), "missing")},
	}}
	err := cfg.Validate()
	var invalid *ErrInvalidConfig
	if !errors.As(err, &invalid) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
	if invalid.Field != "spki.pin-file" {
		t.Errorf("expected spki.pin-file field, got %s", invalid.Field)
	}
}

func TestConfigValidate_SPKIWithoutPinAllowed(t *testing.T) {
	// A scope without a static pin is valid: a PinStore may supply
	// per-endpoint pins at resolution time.
	cfg := &Config{BMC: &ScopeConfig{Strategies: []Strategy{StrategySPKI}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestConfigValidate_CAFileWithoutPathAllowed(t *testing.T) {
	// An empty ca-file path validates; the resolver records a runtime
	// attempt failure instead (legacy auto-mode semantics).
	cfg := &Config{BMC: &ScopeConfig{Strategies: []Strategy{StrategyCAFile}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestConfigValidate_NegativeTimeout(t *testing.T) {
	cfg := &Config{Bootstrap: &ScopeConfig{
		Strategies:       []Strategy{StrategyEmbedded},
		PerMethodTimeout: -1 * time.Second,
	}}
	err := cfg.Validate()
	var invalid *ErrInvalidConfig
	if !errors.As(err, &invalid) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
	if invalid.Field != "per-method-timeout" {
		t.Errorf("expected per-method-timeout field, got %s", invalid.Field)
	}
}

func TestScopeConfigHasStrategy(t *testing.T) {
	scope := &ScopeConfig{Strategies: []Strategy{StrategyDANE, StrategySPKI}}
	if !scope.HasStrategy(StrategyDANE) {
		t.Error("expected dane to be present")
	}
	if scope.HasStrategy(StrategyNoise) {
		t.Error("expected noise to be absent")
	}
}
