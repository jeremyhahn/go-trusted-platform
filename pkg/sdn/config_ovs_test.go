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

package sdn_test

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
)

// validOVSConfig returns a minimal valid OVSConfig for mutation in tests.
func validOVSConfig() *sdn.OVSConfig {
	return &sdn.OVSConfig{
		Socket: "/var/run/openvswitch/db.sock",
		Bridge: "br0",
	}
}

func TestOVSConfigValidate_Offload(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *sdn.OVSConfig)
		wantErr error
	}{
		{
			name:   "base config valid",
			mutate: func(c *sdn.OVSConfig) {},
		},
		{
			name: "hw-offload without tc-policy valid",
			mutate: func(c *sdn.OVSConfig) {
				c.HWOffload = true
			},
		},
		{
			name: "hw-offload with tc-policy none valid",
			mutate: func(c *sdn.OVSConfig) {
				c.HWOffload = true
				c.TCPolicy = "none"
			},
		},
		{
			name: "hw-offload with tc-policy skip_sw valid",
			mutate: func(c *sdn.OVSConfig) {
				c.HWOffload = true
				c.TCPolicy = "skip_sw"
			},
		},
		{
			name: "hw-offload with tc-policy skip_hw valid",
			mutate: func(c *sdn.OVSConfig) {
				c.HWOffload = true
				c.TCPolicy = "skip_hw"
			},
		},
		{
			name: "dpdk with netdev datapath valid",
			mutate: func(c *sdn.OVSConfig) {
				c.Datapath = "netdev"
				c.DPDK = &sdn.DPDKConfig{Init: true, SocketMem: "1024"}
			},
		},
		{
			name: "invalid tc-policy value",
			mutate: func(c *sdn.OVSConfig) {
				c.HWOffload = true
				c.TCPolicy = "skip_everything"
			},
			wantErr: sdn.ErrInvalidTCPolicy{Policy: "skip_everything"},
		},
		{
			name: "tc-policy without hw-offload",
			mutate: func(c *sdn.OVSConfig) {
				c.TCPolicy = "skip_sw"
			},
			wantErr: sdn.ErrTCPolicyWithoutHWOffload{},
		},
		{
			name: "dpdk with system datapath",
			mutate: func(c *sdn.OVSConfig) {
				c.Datapath = "system"
				c.DPDK = &sdn.DPDKConfig{Init: true}
			},
			wantErr: sdn.ErrDPDKRequiresNetdev{Datapath: "system"},
		},
		{
			name: "dpdk with empty datapath",
			mutate: func(c *sdn.OVSConfig) {
				c.DPDK = &sdn.DPDKConfig{Init: true}
			},
			wantErr: sdn.ErrDPDKRequiresNetdev{Datapath: ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validOVSConfig()
			tt.mutate(cfg)

			err := cfg.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestOVSConfigValidate_OffloadErrorsPrecededByBaseChecks(t *testing.T) {
	// Missing socket must still win over offload errors so operators fix
	// base connectivity first.
	cfg := &sdn.OVSConfig{
		Bridge:   "br0",
		TCPolicy: "bogus",
	}
	var target sdn.ErrInvalidOVSSocket
	if err := cfg.Validate(); !errors.As(err, &target) {
		t.Fatalf("Validate() = %v, want ErrInvalidOVSSocket", cfg.Validate())
	}
}

func TestOVSOffloadErrorStrings(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"ErrInvalidTCPolicy", sdn.ErrInvalidTCPolicy{Policy: "x"}, `sdn: invalid ovs tc-policy "x" (must be "none", "skip_sw", or "skip_hw")`},
		{"ErrTCPolicyWithoutHWOffload", sdn.ErrTCPolicyWithoutHWOffload{}, "sdn: ovs tc-policy requires hw-offload to be enabled"},
		{"ErrDPDKRequiresNetdev", sdn.ErrDPDKRequiresNetdev{Datapath: "system"}, `sdn: ovs dpdk configuration requires datapath "netdev" (got "system")`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Fatalf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}
