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
	"testing"
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
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
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
