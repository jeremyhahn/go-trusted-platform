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

package controlplane

import (
	"errors"
	"testing"
	"time"
)

func TestConfigValidateValid(t *testing.T) {
	cfg := &Config{
		Enabled:   true,
		BaseURL:   "https://cp.example.com:8443",
		GatewayID: "gw-1",
		Interval:  15 * time.Second,
		CertFile:  "/etc/gatewayd/idevid.pem",
		KeyFile:   "/etc/gatewayd/idevid-key.pem",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestConfigValidateDisabledOrNil(t *testing.T) {
	var nilCfg *Config
	if err := nilCfg.Validate(); err != nil {
		t.Fatalf("nil config must validate: %v", err)
	}
	disabled := &Config{Enabled: false}
	if err := disabled.Validate(); err != nil {
		t.Fatalf("disabled config must validate: %v", err)
	}
}

func TestConfigValidateMissingBaseURL(t *testing.T) {
	cfg := &Config{Enabled: true}
	var missing ErrMissingField
	if err := cfg.Validate(); !errors.As(err, &missing) || missing.Field != "base-url" {
		t.Fatalf("err = %v, want ErrMissingField{base-url}", err)
	}
}

// The mTLS client certificate is the telemetry identity claim, and
// net/http performs no handshake for a non-https base URL — so a scheme
// other than https silently ships telemetry in cleartext with the
// configured certificate never presented.
func TestConfigValidateRequiresHTTPSBaseURL(t *testing.T) {
	base := func(rawURL string) *Config {
		return &Config{
			Enabled:  true,
			BaseURL:  rawURL,
			CertFile: "c.pem",
			KeyFile:  "k.pem",
		}
	}

	rejected := []struct {
		name   string
		rawURL string
	}{
		{"cleartext http", "http://cp.example.com:8080"},
		{"non-transport scheme", "file:///etc/passwd"},
		{"schemeless host:port", "cp.example.com:8443"},
		{"relative path", "/api/v1"},
		{"bare host", "cp.example.com"},
		{"https without a host", "https://"},
		{"embedded credentials", "https://user:pass@cp.example.com:8443"},
		{"malformed url", "https://cp example.com:8443"},
		{"control character", "https://cp.example.com:8443/\x7f"},
		// Suffix components are refused, not ignored: the reporter
		// appends the route paths to this value, so anything past the
		// host silently re-targets the request. A query is the worst
		// case — it parses with an EMPTY path, so the appended route
		// lands inside the query and every push goes to "/".
		{"path prefix", "https://cp.example.com:8443/platform"},
		{"query string", "https://cp.example.com:8443?tenant=x"},
		{"fragment", "https://cp.example.com:8443#frag"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			var invalid *ErrConfigInvalid
			err := base(tc.rawURL).Validate()
			if !errors.As(err, &invalid) || invalid.Field != "base-url" {
				t.Fatalf("Validate(%q) = %v, want ErrConfigInvalid{base-url}", tc.rawURL, err)
			}
		})
	}

	accepted := []string{
		"https://cp.example.com:8443",
		"https://cp.example.com",
		// A bare trailing slash is the same base written differently,
		// so it is normalized rather than refused.
		"https://cp.example.com:8443/",
		"https://10.0.0.1:8443",
	}
	for _, rawURL := range accepted {
		t.Run("accepts "+rawURL, func(t *testing.T) {
			if err := base(rawURL).Validate(); err != nil {
				t.Fatalf("Validate(%q) = %v, want nil", rawURL, err)
			}
		})
	}
}

func TestConfigValidateRequiresClientIdentity(t *testing.T) {
	var missing ErrMissingField

	certOnly := &Config{Enabled: true, BaseURL: "https://cp:8443", CertFile: "c.pem"}
	if err := certOnly.Validate(); !errors.As(err, &missing) || missing.Field != "key-file" {
		t.Fatalf("cert-only err = %v, want ErrMissingField{key-file}", err)
	}
	keyOnly := &Config{Enabled: true, BaseURL: "https://cp:8443", KeyFile: "k.pem"}
	if err := keyOnly.Validate(); !errors.As(err, &missing) || missing.Field != "cert-file" {
		t.Fatalf("key-only err = %v, want ErrMissingField{cert-file}", err)
	}
	neither := &Config{Enabled: true, BaseURL: "https://cp:8443"}
	if err := neither.Validate(); !errors.As(err, &missing) || missing.Field != "cert-file" {
		t.Fatalf("no-identity err = %v, want ErrMissingField{cert-file}", err)
	}
}

func TestConfigValidateInterval(t *testing.T) {
	base := func() *Config {
		return &Config{
			Enabled:  true,
			BaseURL:  "https://cp:8443",
			CertFile: "c.pem",
			KeyFile:  "k.pem",
		}
	}
	var invalid *ErrConfigInvalid

	negative := base()
	negative.Interval = -time.Second
	if err := negative.Validate(); !errors.As(err, &invalid) || invalid.Field != "interval" {
		t.Fatalf("negative err = %v, want ErrConfigInvalid{interval}", err)
	}

	// A unitless YAML `interval: 30` decodes to 30 nanoseconds — reject
	// anything below the 1s floor instead of hot-looping telemetry.
	nanoseconds := base()
	nanoseconds.Interval = 30 * time.Nanosecond
	if err := nanoseconds.Validate(); !errors.As(err, &invalid) || invalid.Field != "interval" {
		t.Fatalf("sub-second err = %v, want ErrConfigInvalid{interval}", err)
	}

	zero := base() // zero selects the reporter default
	if err := zero.Validate(); err != nil {
		t.Fatalf("zero interval must validate: %v", err)
	}
}

func TestConfigValidateReconcileInterval(t *testing.T) {
	base := func() *Config {
		return &Config{
			Enabled: true, BaseURL: "https://cp.example.com:8443",
			CertFile: "/etc/gatewayd/idevid.pem", KeyFile: "/etc/gatewayd/idevid-key.pem",
		}
	}
	cfg := base()
	if cfg.EffectiveReconcileInterval() != DefaultReconcileInterval {
		t.Fatalf("unset reconcile-interval should default, got %v", cfg.EffectiveReconcileInterval())
	}
	cfg.ReconcileInterval = 2 * time.Minute
	if err := cfg.Validate(); err != nil || cfg.EffectiveReconcileInterval() != 2*time.Minute {
		t.Fatalf("explicit interval: err=%v effective=%v", err, cfg.EffectiveReconcileInterval())
	}
	for _, bad := range []time.Duration{-time.Second, 30} {
		cfg := base()
		cfg.ReconcileInterval = bad
		var invalid *ErrConfigInvalid
		if err := cfg.Validate(); !errors.As(err, &invalid) || invalid.Field != "reconcile-interval" {
			t.Fatalf("reconcile-interval=%v: err = %v, want ErrConfigInvalid on reconcile-interval", bad, err)
		}
	}
	var nilCfg *Config
	if nilCfg.EffectiveReconcileInterval() != DefaultReconcileInterval {
		t.Fatal("nil config should default")
	}
}
