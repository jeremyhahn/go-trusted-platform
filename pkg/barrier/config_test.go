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

package barrier

import (
	"errors"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if cfg.SealStrategy != SealStrategySoftware {
		t.Errorf("expected SealStrategy %q, got %q", SealStrategySoftware, cfg.SealStrategy)
	}
	if cfg.AutoUnseal {
		t.Error("expected AutoUnseal to be false by default")
	}
	if cfg.ShamirThreshold != 0 {
		t.Errorf("expected ShamirThreshold 0, got %d", cfg.ShamirThreshold)
	}
	if cfg.ShamirShares != 0 {
		t.Errorf("expected ShamirShares 0, got %d", cfg.ShamirShares)
	}
}

func TestDefaultConfig_Validate(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig should validate: %v", err)
	}
}

func TestConfig_Validate_ValidStrategies(t *testing.T) {
	strategies := []string{
		SealStrategySoftware,
		SealStrategyTPM2,
		SealStrategyPKCS11,
		"",
	}
	for _, s := range strategies {
		cfg := &Config{SealStrategy: s}
		if err := cfg.Validate(); err != nil {
			t.Errorf("strategy %q should be valid, got error: %v", s, err)
		}
	}
}

func TestConfig_Validate_InvalidStrategy(t *testing.T) {
	cfg := &Config{SealStrategy: "invalid"}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for invalid strategy")
	}
	var configErr *ConfigError
	if !errors.As(err, &configErr) {
		t.Fatalf("expected ConfigError, got %T: %v", err, err)
	}
	if configErr.Field != "SealStrategy" {
		t.Errorf("expected field SealStrategy, got %q", configErr.Field)
	}
}

func TestConfig_Validate_NegativeThreshold(t *testing.T) {
	cfg := &Config{ShamirThreshold: -1}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative threshold")
	}
	var configErr *ConfigError
	if !errors.As(err, &configErr) {
		t.Fatalf("expected ConfigError, got %T: %v", err, err)
	}
	if configErr.Field != "ShamirThreshold" {
		t.Errorf("expected field ShamirThreshold, got %q", configErr.Field)
	}
}

func TestConfig_Validate_NegativeShares(t *testing.T) {
	cfg := &Config{ShamirShares: -1}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative shares")
	}
	var configErr *ConfigError
	if !errors.As(err, &configErr) {
		t.Fatalf("expected ConfigError, got %T: %v", err, err)
	}
	if configErr.Field != "ShamirShares" {
		t.Errorf("expected field ShamirShares, got %q", configErr.Field)
	}
}

func TestConfig_Validate_ThresholdWithoutShares(t *testing.T) {
	cfg := &Config{ShamirThreshold: 3, ShamirShares: 0}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for threshold without shares")
	}
	var configErr *ConfigError
	if !errors.As(err, &configErr) {
		t.Fatalf("expected ConfigError, got %T: %v", err, err)
	}
	if configErr.Field != "ShamirShares" {
		t.Errorf("expected field ShamirShares, got %q", configErr.Field)
	}
}

func TestConfig_Validate_SharesWithoutThreshold(t *testing.T) {
	cfg := &Config{ShamirThreshold: 0, ShamirShares: 5}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for shares without threshold")
	}
	var configErr *ConfigError
	if !errors.As(err, &configErr) {
		t.Fatalf("expected ConfigError, got %T: %v", err, err)
	}
	if configErr.Field != "ShamirThreshold" {
		t.Errorf("expected field ShamirThreshold, got %q", configErr.Field)
	}
}

func TestConfig_Validate_ThresholdExceedsShares(t *testing.T) {
	cfg := &Config{ShamirThreshold: 5, ShamirShares: 3}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for threshold exceeding shares")
	}
	var configErr *ConfigError
	if !errors.As(err, &configErr) {
		t.Fatalf("expected ConfigError, got %T: %v", err, err)
	}
	if configErr.Field != "ShamirThreshold" {
		t.Errorf("expected field ShamirThreshold, got %q", configErr.Field)
	}
}

func TestConfig_Validate_ValidShamir(t *testing.T) {
	cfg := &Config{
		SealStrategy:    SealStrategySoftware,
		ShamirThreshold: 3,
		ShamirShares:    5,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid Shamir config should validate: %v", err)
	}
}

func TestConfig_IsShamir(t *testing.T) {
	tests := []struct {
		name      string
		threshold int
		shares    int
		want      bool
	}{
		{"zero values", 0, 0, false},
		{"threshold only", 3, 0, false},
		{"shares only", 0, 5, false},
		{"both set", 3, 5, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				ShamirThreshold: tt.threshold,
				ShamirShares:    tt.shares,
			}
			if got := cfg.IsShamir(); got != tt.want {
				t.Errorf("IsShamir() = %v, want %v", got, tt.want)
			}
		})
	}
}
