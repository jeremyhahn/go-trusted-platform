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

package ntp

import (
	"errors"
	"testing"
	"time"
)

// controlPlaneConfig returns the approved control-plane defaults: consume
// upstream, serve the trusted CIDRs with NTS, orphan fallback on.
func controlPlaneConfig() *Config {
	return &Config{
		Enabled: true,
		Mode:    ModeBoth,
		Consume: &ConsumeConfig{
			Upstream: []UpstreamSource{
				{Address: "198.18.0.1", Prefer: true, IBurst: true},
				{Address: "pool.ntp.org", Pool: true, IBurst: true},
			},
			StartupGate: &StartupGate{
				BlockUntilSynced: true,
				Timeout:          120 * time.Second,
				OnTimeout:        ActionWarnAndContinue,
			},
			OrphanFallback: true,
		},
		Serve: &ServeConfig{
			ListenNetworks: []string{"198.18.0.0/24", "172.16.201.0/24"},
			LocalStratum:   10,
			NTS: &NTSConfig{
				Enabled: true,
				CertURI: "kms://platform/ntp/nts-cert",
				KeyURI:  "kms://platform/ntp/nts-key",
			},
		},
		RTC: &RTCConfig{WriteBack: true},
	}
}

// consumerConfig returns the approved gateway/compute defaults.
func consumerConfig() *Config {
	return &Config{
		Enabled: true,
		Mode:    ModeConsume,
		Consume: &ConsumeConfig{
			Upstream: []UpstreamSource{
				{Address: "198.18.0.10", Prefer: true, IBurst: true, NTS: true},
			},
			StartupGate: &StartupGate{
				BlockUntilSynced: true,
				Timeout:          120 * time.Second,
				OnTimeout:        ActionWarnAndContinue,
			},
		},
		RTC: &RTCConfig{WriteBack: true},
	}
}

func TestConfigValidateAcceptsApprovedRoleDefaults(t *testing.T) {
	cases := map[string]*Config{
		"control-plane": controlPlaneConfig(),
		"consumer":      consumerConfig(),
		"serve-only": {
			Enabled: true,
			Mode:    ModeServe,
			Serve: &ServeConfig{
				ListenNetworks: []string{"10.0.0.0/8"},
			},
		},
		"disabled section is inert": {Enabled: false, Mode: "nonsense"},
	}

	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestConfigValidateRejectsInvalidInput(t *testing.T) {
	cases := map[string]struct {
		config *Config
		want   error
	}{
		"nil config": {
			config: nil,
			want:   ErrNilConfig{},
		},
		"unknown mode": {
			config: &Config{Enabled: true, Mode: "sometimes"},
			want:   ErrInvalidMode{Mode: "sometimes"},
		},
		"consume without section": {
			config: &Config{Enabled: true, Mode: ModeConsume},
			want:   ErrMissingConsumeSection{Mode: string(ModeConsume)},
		},
		"serve without section": {
			config: &Config{Enabled: true, Mode: ModeServe},
			want:   ErrMissingServeSection{Mode: string(ModeServe)},
		},
		"no upstream and no orphan fallback": {
			config: &Config{Enabled: true, Mode: ModeConsume, Consume: &ConsumeConfig{}},
			want:   ErrNoUpstream{},
		},
		"empty upstream address": {
			config: &Config{Enabled: true, Mode: ModeConsume, Consume: &ConsumeConfig{
				Upstream: []UpstreamSource{{Address: "  "}},
			}},
			want: ErrEmptyUpstreamAddress{Index: 0},
		},
		"upstream address injects a directive": {
			config: &Config{Enabled: true, Mode: ModeConsume, Consume: &ConsumeConfig{
				Upstream: []UpstreamSource{{Address: "1.2.3.4\nallow 0.0.0.0/0"}},
			}},
			want: ErrInvalidUpstreamAddress{Address: "1.2.3.4\nallow 0.0.0.0/0"},
		},
		"unknown on-timeout action": {
			config: &Config{Enabled: true, Mode: ModeConsume, Consume: &ConsumeConfig{
				Upstream:    []UpstreamSource{{Address: "1.2.3.4"}},
				StartupGate: &StartupGate{BlockUntilSynced: true, OnTimeout: "explode"},
			}},
			want: ErrInvalidTimeoutAction{Action: "explode"},
		},
		"negative gate timeout": {
			config: &Config{Enabled: true, Mode: ModeConsume, Consume: &ConsumeConfig{
				Upstream:    []UpstreamSource{{Address: "1.2.3.4"}},
				StartupGate: &StartupGate{BlockUntilSynced: true, Timeout: -time.Second},
			}},
			want: ErrInvalidGateTimeout{Seconds: -1},
		},
		"serve with no allow-list": {
			config: &Config{Enabled: true, Mode: ModeServe, Serve: &ServeConfig{}},
			want:   ErrNoListenNetworks{},
		},
		"serve to the whole IPv4 internet": {
			config: &Config{Enabled: true, Mode: ModeServe, Serve: &ServeConfig{
				ListenNetworks: []string{"0.0.0.0/0"},
			}},
			want: ErrUnrestrictedListenNetwork{Network: "0.0.0.0/0"},
		},
		"serve to the whole IPv6 internet": {
			config: &Config{Enabled: true, Mode: ModeServe, Serve: &ServeConfig{
				ListenNetworks: []string{"::/0"},
			}},
			want: ErrUnrestrictedListenNetwork{Network: "::/0"},
		},
		"unparseable CIDR": {
			config: &Config{Enabled: true, Mode: ModeServe, Serve: &ServeConfig{
				ListenNetworks: []string{"198.18.0.1"},
			}},
			want: ErrInvalidListenNetwork{Network: "198.18.0.1"},
		},
		"local stratum out of range": {
			config: &Config{Enabled: true, Mode: ModeServe, Serve: &ServeConfig{
				ListenNetworks: []string{"10.0.0.0/8"},
				LocalStratum:   99,
			}},
			want: ErrInvalidLocalStratum{Stratum: 99},
		},
		"NTS without a certificate": {
			config: &Config{Enabled: true, Mode: ModeServe, Serve: &ServeConfig{
				ListenNetworks: []string{"10.0.0.0/8"},
				NTS:            &NTSConfig{Enabled: true, KeyURI: "kms://k"},
			}},
			want: ErrMissingNTSMaterial{Field: "serve.nts.cert-uri"},
		},
		"NTS without a key": {
			config: &Config{Enabled: true, Mode: ModeServe, Serve: &ServeConfig{
				ListenNetworks: []string{"10.0.0.0/8"},
				NTS:            &NTSConfig{Enabled: true, CertURI: "kms://c"},
			}},
			want: ErrMissingNTSMaterial{Field: "serve.nts.key-uri"},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.config.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want %v", tc.want)
			}
			// ErrInvalidListenNetwork carries a wrapped parse cause, so
			// compare on type rather than value for that case.
			var cidrErr ErrInvalidListenNetwork
			if errors.As(tc.want, &cidrErr) {
				var got ErrInvalidListenNetwork
				if !errors.As(err, &got) {
					t.Fatalf("Validate() = %v, want ErrInvalidListenNetwork", err)
				}
				if got.Network != cidrErr.Network {
					t.Fatalf("network = %q, want %q", got.Network, cidrErr.Network)
				}
				return
			}
			if err.Error() != tc.want.Error() {
				t.Fatalf("Validate() = %q, want %q", err.Error(), tc.want.Error())
			}
		})
	}
}

func TestConfigAccessorsUseApprovedDefaults(t *testing.T) {
	cfg := controlPlaneConfig()

	if !cfg.Active() {
		t.Fatal("Active() = false, want true")
	}
	if !cfg.GateEnabled() {
		t.Fatal("GateEnabled() = false, want true")
	}
	if got := cfg.GateTimeout(); got != 120*time.Second {
		t.Fatalf("GateTimeout() = %v, want 120s", got)
	}
	if got := cfg.TimeoutAction(); got != ActionWarnAndContinue {
		t.Fatalf("TimeoutAction() = %v, want %v", got, ActionWarnAndContinue)
	}
	if !cfg.RTCWriteBack() {
		t.Fatal("RTCWriteBack() = false, want true")
	}
	if got := cfg.LocalStratum(); got != 10 {
		t.Fatalf("LocalStratum() = %d, want 10", got)
	}
	if !cfg.NTSServing() {
		t.Fatal("NTSServing() = false, want true")
	}
	if !cfg.Mode.Serves() || !cfg.Mode.Consumes() {
		t.Fatal("ModeBoth should both serve and consume")
	}
}

func TestConfigAccessorsFallBackWhenUnset(t *testing.T) {
	var absent *Config

	if absent.Active() {
		t.Fatal("nil Active() = true, want false")
	}
	if absent.GateEnabled() {
		t.Fatal("nil GateEnabled() = true, want false")
	}
	if got := absent.GateTimeout(); got != DefaultGateTimeout {
		t.Fatalf("nil GateTimeout() = %v, want %v", got, DefaultGateTimeout)
	}
	if got := absent.TimeoutAction(); got != ActionWarnAndContinue {
		t.Fatalf("nil TimeoutAction() = %v, want warn-and-continue", got)
	}
	if absent.RTCWriteBack() {
		t.Fatal("nil RTCWriteBack() = true, want false")
	}
	if got := absent.LocalStratum(); got != DefaultLocalStratum {
		t.Fatalf("nil LocalStratum() = %d, want %d", got, DefaultLocalStratum)
	}
	if absent.NTSServing() {
		t.Fatal("nil NTSServing() = true, want false")
	}

	// A consume-only node must never be treated as an NTS server even when
	// a serve block was left behind in the file.
	consumer := consumerConfig()
	consumer.Serve = &ServeConfig{NTS: &NTSConfig{Enabled: true}}
	if consumer.NTSServing() {
		t.Fatal("consume-only NTSServing() = true, want false")
	}
	if ModeConsume.Serves() {
		t.Fatal("ModeConsume.Serves() = true, want false")
	}
	if ModeServe.Consumes() {
		t.Fatal("ModeServe.Consumes() = true, want false")
	}
}
