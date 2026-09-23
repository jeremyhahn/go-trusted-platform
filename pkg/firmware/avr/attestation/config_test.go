// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation

import (
	"log/slog"
	"testing"
	"time"
)

func TestConfigValidate_AcceptsAUsableConfiguration(t *testing.T) {
	cfg := &Config{TenantID: "acme", RequestTimeout: time.Second}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// A zero timeout is the documented default, not a refusal.
	zero := &Config{TenantID: "acme"}
	if err := zero.Validate(); err != nil {
		t.Fatalf("Validate with a zero timeout: %v", err)
	}
}

func TestConfigValidate_RefusesUnusableConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		want   error
	}{
		{name: "nil", config: nil, want: ErrNilConfig{}},
		{name: "no tenant", config: &Config{}, want: ErrInvalidTenant{}},
		{name: "tenant with a slash", config: &Config{TenantID: "a/b"}, want: ErrInvalidTenant{}},
		{name: "tenant with a space", config: &Config{TenantID: "a b"}, want: ErrInvalidTenant{}},
		{
			name:   "negative timeout",
			config: &Config{TenantID: "acme", RequestTimeout: -time.Nanosecond},
			want:   ErrInvalidConfig{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if err == nil {
				t.Fatal("Validate accepted an unusable configuration")
			}
			if !sameErrorType(err, tc.want) {
				t.Fatalf("err = %T (%v), want %T", err, err, tc.want)
			}
		})
	}
}

func TestConfigDefaults_FillInTheZeroValues(t *testing.T) {
	cfg := &Config{TenantID: "acme"}

	if got := cfg.requestTimeout(); got != DefaultRequestTimeout {
		t.Errorf("requestTimeout = %v, want %v", got, DefaultRequestTimeout)
	}
	if cfg.clock() == nil {
		t.Error("clock is nil")
	}
	if cfg.logger() == nil {
		t.Error("logger is nil; a caller who wants no logs must not get a nil dereference")
	}
	// The clock must produce a moving wall time, not a zero one.
	if cfg.clock()().IsZero() {
		t.Error("the default clock reports the zero time")
	}
}

func TestConfigDefaults_DoNotOverrideWhatWasSet(t *testing.T) {
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	logger := slog.New(slog.DiscardHandler)
	cfg := &Config{
		TenantID:       "acme",
		RequestTimeout: 7 * time.Second,
		Clock:          func() time.Time { return stamp },
		Logger:         logger,
	}

	if got := cfg.requestTimeout(); got != 7*time.Second {
		t.Errorf("requestTimeout = %v, want 7s", got)
	}
	if got := cfg.clock()(); !got.Equal(stamp) {
		t.Errorf("clock = %v, want %v", got, stamp)
	}
	if cfg.logger() != logger {
		t.Error("logger was replaced")
	}
}
