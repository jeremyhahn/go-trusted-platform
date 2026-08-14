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

package bmc

import (
	"errors"
	"strings"
	"testing"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Port != 623 {
		t.Errorf("DefaultConfig().Port = %d, want 623", cfg.Port)
	}
	if cfg.Protocol != ProtocolIPMI {
		t.Errorf("DefaultConfig().Protocol = %q, want %q", cfg.Protocol, ProtocolIPMI)
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errType error
	}{
		{
			name: "valid config",
			config: &Config{
				Address:  "192.168.1.100",
				Port:     623,
				Username: "admin",
				Password: "pass",
				Protocol: ProtocolIPMI,
			},
			wantErr: false,
		},
		{
			name: "missing address",
			config: &Config{
				Port:     623,
				Protocol: ProtocolIPMI,
			},
			wantErr: true,
			errType: ErrInvalidConfig{},
		},
		{
			name: "port too low",
			config: &Config{
				Address:  "192.168.1.100",
				Port:     0,
				Protocol: ProtocolIPMI,
			},
			wantErr: true,
			errType: ErrInvalidConfig{},
		},
		{
			name: "port too high",
			config: &Config{
				Address:  "192.168.1.100",
				Port:     70000,
				Protocol: ProtocolIPMI,
			},
			wantErr: true,
			errType: ErrInvalidConfig{},
		},
		{
			name: "invalid protocol",
			config: &Config{
				Address:  "192.168.1.100",
				Port:     623,
				Protocol: Protocol("telnet"),
			},
			wantErr: true,
			errType: ErrInvalidConfig{},
		},
		{
			name: "valid redfish config",
			config: &Config{
				Address:  "10.0.0.1",
				Port:     443,
				Username: "root",
				Password: "secret",
				Protocol: ProtocolRedfish,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errType != nil {
					var target ErrInvalidConfig
					if !errors.As(err, &target) {
						t.Errorf("expected ErrInvalidConfig, got %T", err)
					}
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// --- P2: Certificate / Key / Backend validation ---

// baseValidCfg returns a Config that passes existing Validate for
// Address/Port/Protocol so tests can focus on the cert-block branches.
func baseValidCfg() *Config {
	return &Config{
		Address:  "192.168.1.100",
		Port:     623,
		Username: "admin",
		Password: "pass",
		Protocol: ProtocolIPMI,
	}
}

// certBlockWithChallenge returns a minimal Identity + KeyConfig pair
// using the given challenge type.
func certBlockWithChallenge(challenge string) (*common.Identity, *common.KeyConfig) {
	id := &common.Identity{
		ACME: &common.ACMEIdentityConfig{
			Challenge:  challenge,
			AuthzType:  "dns",
			AuthzValue: "bmc01.internal",
		},
		Subject: trustedca.CASubject{CommonName: "bmc01.internal"},
	}
	key := &common.KeyConfig{
		CN:           "bmc01.internal",
		KeyAlgorithm: "ECDSA",
	}
	return id, key
}

func TestConfig_Validate_NoCertConfig_IsValid(t *testing.T) {
	cfg := baseValidCfg()
	if err := cfg.Validate(); err != nil {
		t.Errorf("baseline config rejected: %v", err)
	}
}

func TestConfig_Validate_CertRequiresKey(t *testing.T) {
	cfg := baseValidCfg()
	id, _ := certBlockWithChallenge("dns-01")
	cfg.Certificate = id
	// Key deliberately nil.
	err := cfg.Validate()
	var want ErrInvalidConfig
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(want.Reason, "certificate and key") {
		t.Errorf("unexpected reason: %q", want.Reason)
	}
}

func TestConfig_Validate_KeyRequiresCert(t *testing.T) {
	cfg := baseValidCfg()
	_, key := certBlockWithChallenge("dns-01")
	cfg.Key = key
	err := cfg.Validate()
	var want ErrInvalidConfig
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
}

func TestConfig_Validate_BackendWithoutCertRejected(t *testing.T) {
	cfg := baseValidCfg()
	cfg.Backend = CertBackendRedfish
	// Certificate + Key nil.
	err := cfg.Validate()
	var want ErrInvalidConfig
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
	if want.Field != "backend" {
		t.Errorf("field = %q, want backend", want.Field)
	}
}

func TestConfig_Validate_InvalidBackendName(t *testing.T) {
	cfg := baseValidCfg()
	id, key := certBlockWithChallenge("dns-01")
	cfg.Certificate = id
	cfg.Key = key
	cfg.Backend = CertBackend("vendor-foo")
	err := cfg.Validate()
	var want ErrInvalidConfig
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(want.Reason, "unrecognized cert backend") {
		t.Errorf("unexpected reason: %q", want.Reason)
	}
}

func TestConfig_Validate_MissingACMEChallenge(t *testing.T) {
	cfg := baseValidCfg()
	cfg.Key = &common.KeyConfig{CN: "x"}
	cfg.Certificate = &common.Identity{
		// ACME nil → missing Challenge branch.
	}
	err := cfg.Validate()
	var want ErrInvalidConfig
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(want.Field, "acme.challenge") {
		t.Errorf("field = %q, want contains acme.challenge", want.Field)
	}
}

func TestConfig_Validate_MissingACMEChallengeInner(t *testing.T) {
	cfg := baseValidCfg()
	cfg.Key = &common.KeyConfig{CN: "x"}
	cfg.Certificate = &common.Identity{
		ACME: &common.ACMEIdentityConfig{
			// Challenge empty.
		},
	}
	err := cfg.Validate()
	var want ErrInvalidConfig
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
}

func TestConfig_Validate_RejectsHTTP01(t *testing.T) {
	cfg := baseValidCfg()
	id, key := certBlockWithChallenge("http-01")
	cfg.Certificate = id
	cfg.Key = key
	err := cfg.Validate()
	var want ErrInvalidConfig
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(want.Field, "challenge") {
		t.Errorf("field = %q, want contains challenge", want.Field)
	}
	if !strings.Contains(want.Reason, "dns-01") {
		t.Errorf("reason does not mention dns-01: %q", want.Reason)
	}
}

func TestConfig_Validate_RejectsEmptyChallenge(t *testing.T) {
	cfg := baseValidCfg()
	id, key := certBlockWithChallenge("")
	cfg.Certificate = id
	cfg.Key = key
	err := cfg.Validate()
	var want ErrInvalidConfig
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want ErrInvalidConfig for empty challenge", err)
	}
}

func TestConfig_Validate_AcceptsDNS01(t *testing.T) {
	cfg := baseValidCfg()
	id, key := certBlockWithChallenge("dns-01")
	cfg.Certificate = id
	cfg.Key = key
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid dns-01 config rejected: %v", err)
	}
}

func TestConfig_Validate_AcceptsDNS01WithBackend(t *testing.T) {
	cfg := baseValidCfg()
	id, key := certBlockWithChallenge("dns-01")
	cfg.Certificate = id
	cfg.Key = key
	for _, b := range []CertBackend{CertBackendAuto, CertBackendRedfish, CertBackendSMCCGI, ""} {
		cfg.Backend = b
		if err := cfg.Validate(); err != nil {
			t.Errorf("backend=%q rejected: %v", b, err)
		}
	}
}

func TestConfig_Endpoint(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		want   string
	}{
		{
			name:   "standard IPMI endpoint",
			config: &Config{Address: "192.168.1.100", Port: 623},
			want:   "192.168.1.100:623",
		},
		{
			name:   "redfish endpoint",
			config: &Config{Address: "bmc.example.com", Port: 443},
			want:   "bmc.example.com:443",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.Endpoint(); got != tt.want {
				t.Errorf("Endpoint() = %q, want %q", got, tt.want)
			}
		})
	}
}
