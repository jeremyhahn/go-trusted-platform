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

package bootstrap

import (
	"errors"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestVirtualMediaSMBURL covers the canonical URL builder used by both the
// real ISO stager and the orchestrator's bootNodeVirtualMedia. The format
// is what the BMC will be asked to mount; getting it wrong manifests as
// "share not found" only after the BMC has the request, which is hard to
// debug — so we lock the format here.
func TestVirtualMediaSMBURL(t *testing.T) {
	tests := []struct {
		name         string
		deployerHost string
		localPath    string
		want         string
	}{
		{
			name:         "absolute local path",
			deployerHost: "10.4.2.91",
			localPath:    "/srv/build/trusted-platform.iso",
			want:         "smb://10.4.2.91/boot/trusted-platform.iso",
		},
		{
			name:         "relative local path",
			deployerHost: "jumpbox.lan",
			localPath:    "build/release.iso",
			want:         "smb://jumpbox.lan/boot/release.iso",
		},
		{
			name:         "filename only",
			deployerHost: "10.0.0.1",
			localPath:    "platform.iso",
			want:         "smb://10.0.0.1/boot/platform.iso",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := virtualMediaSMBURL(tt.deployerHost, tt.localPath)
			if got != tt.want {
				t.Errorf("virtualMediaSMBURL(%q, %q) = %q, want %q",
					tt.deployerHost, tt.localPath, got, tt.want)
			}
		})
	}
}

// TestValidate_BootMethod covers the boot_method field rules in
// BootstrapConfig.Validate. Empty defaults to pxe (already covered by other
// validate tests). Explicit invalid values, virtual-media without BMC, and
// virtual-media without iso_path are exercised here.
func TestValidate_BootMethod(t *testing.T) {
	baseConfig := func() *BootstrapConfig {
		return &BootstrapConfig{
			Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy.example.com"},
			Environment: testEnvironment(),
			Platform:    PlatformGlobalConfig{Domain: "example.com"},
			Nodes: []NodeConfig{
				{
					Hostname:    "cp-0",
					Role:        RoleControlPlane,
					BMCAddress:  "10.200.0.10",
					BMCUser:     "admin",
					BMCPassword: "secret",
				},
			},
		}
	}

	tests := []struct {
		name        string
		mutate      func(*BootstrapConfig)
		wantErrType interface{}
		wantOK      bool
	}{
		{
			name:   "default empty boot_method is valid",
			mutate: func(c *BootstrapConfig) {},
			wantOK: true,
		},
		{
			name: "explicit pxe is valid",
			mutate: func(c *BootstrapConfig) {
				c.Nodes[0].BootMethod = "pxe"
			},
			wantOK: true,
		},
		{
			name: "virtual-media with bmc and iso_path is valid",
			mutate: func(c *BootstrapConfig) {
				c.Nodes[0].BootMethod = "virtual-media"
				c.ISOPath = "/tmp/test.iso"
			},
			wantOK: true,
		},
		{
			name: "unknown value is rejected",
			mutate: func(c *BootstrapConfig) {
				c.Nodes[0].BootMethod = "magic"
			},
			wantErrType: ErrInvalidBootMethod{},
		},
		{
			name: "virtual-media without iso_path is rejected",
			mutate: func(c *BootstrapConfig) {
				c.Nodes[0].BootMethod = "virtual-media"
				// no ISOPath
			},
			wantErrType: ErrMissingRequiredField{},
		},
		{
			name: "virtual-media without bmc_address is rejected",
			mutate: func(c *BootstrapConfig) {
				c.Nodes[0].BMCAddress = ""
				c.Nodes[0].MACs = []string{"AA:BB:CC:DD:EE:01"} // satisfy identity check
				c.Nodes[0].BootMethod = "virtual-media"
				c.ISOPath = "/tmp/test.iso"
			},
			wantErrType: ErrVirtualMediaRequiresBMC{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseConfig()
			tt.mutate(cfg)
			err := cfg.Validate()
			if tt.wantOK {
				if err != nil {
					t.Fatalf("Validate returned unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate returned nil, want error of type %T", tt.wantErrType)
			}
			switch tt.wantErrType.(type) {
			case ErrInvalidBootMethod:
				var e ErrInvalidBootMethod
				if !errors.As(err, &e) {
					t.Errorf("expected ErrInvalidBootMethod, got %T: %v", err, err)
				}
			case ErrMissingRequiredField:
				var e ErrMissingRequiredField
				if !errors.As(err, &e) {
					t.Errorf("expected ErrMissingRequiredField, got %T: %v", err, err)
				}
			case ErrVirtualMediaRequiresBMC:
				var e ErrVirtualMediaRequiresBMC
				if !errors.As(err, &e) {
					t.Errorf("expected ErrVirtualMediaRequiresBMC, got %T: %v", err, err)
				}
			}
		})
	}
}

// TestNodeConfig_EffectiveBootMethod verifies the empty-defaults-to-pxe
// helper that the orchestrator dispatch relies on. Trivial but locks the
// default so a future refactor doesn't accidentally flip it to virtual-media.
func TestNodeConfig_EffectiveBootMethod(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", BootMethodPXE},
		{"pxe", BootMethodPXE},
		{"virtual-media", BootMethodVirtualMedia},
	}
	for _, tt := range tests {
		n := &NodeConfig{BootMethod: tt.in}
		if got := n.EffectiveBootMethod(); got != tt.want {
			t.Errorf("EffectiveBootMethod(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestNodeConfigYAML_BootMethodMigrationCarriesThrough is a regression
// guard: the legacy `mac:` migration shadow type must propagate the
// boot_method field, or virtual-media nodes silently fall back to pxe.
func TestNodeConfigYAML_BootMethodCarriesThrough(t *testing.T) {
	yamlBytes := []byte(`
hostname: cp-01
role: control-plane
bmc_address: 10.0.0.5
boot_method: virtual-media
mac: "AA:BB:CC:DD:EE:01"
`)
	var n NodeConfig
	if err := yaml.Unmarshal(yamlBytes, &n); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if n.BootMethod != "virtual-media" {
		t.Errorf("BootMethod = %q, want virtual-media", n.BootMethod)
	}
	if len(n.MACs) != 1 || n.MACs[0] != "AA:BB:CC:DD:EE:01" {
		t.Errorf("legacy mac migration failed: MACs=%v", n.MACs)
	}
}
