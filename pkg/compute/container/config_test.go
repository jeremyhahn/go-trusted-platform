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

package container

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
)

func TestContainerServiceMode_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode     ContainerServiceMode
		expected string
	}{
		{ServiceModeEmbedded, "embedded"},
		{ServiceModeStandalone, "standalone"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			t.Parallel()
			if got := tt.mode.String(); got != tt.expected {
				t.Errorf("ContainerServiceMode.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestContainerServiceMode_IsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		mode  ContainerServiceMode
		valid bool
	}{
		{"embedded", ServiceModeEmbedded, true},
		{"standalone", ServiceModeStandalone, true},
		{"empty", ContainerServiceMode(""), false},
		{"invalid", ContainerServiceMode("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.mode.IsValid(); got != tt.valid {
				t.Errorf("ContainerServiceMode.IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestNetworkMode_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode     NetworkMode
		expected string
	}{
		{NetworkModeBridge, "bridge"},
		{NetworkModeHost, "host"},
		{NetworkModeNone, "none"},
		{NetworkModeSDN, "sdn"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			t.Parallel()
			if got := tt.mode.String(); got != tt.expected {
				t.Errorf("NetworkMode.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestNetworkMode_IsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		mode  NetworkMode
		valid bool
	}{
		{"bridge", NetworkModeBridge, true},
		{"host", NetworkModeHost, true},
		{"none", NetworkModeNone, true},
		{"sdn", NetworkModeSDN, true},
		{"empty", NetworkMode(""), false},
		{"invalid", NetworkMode("custom"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.mode.IsValid(); got != tt.valid {
				t.Errorf("NetworkMode.IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestOrchestratorContainerSpec_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		spec    *OrchestratorContainerSpec
		wantErr error
	}{
		{
			name:    "nil spec",
			spec:    nil,
			wantErr: ErrInvalidSpec,
		},
		{
			name: "empty name",
			spec: &OrchestratorContainerSpec{
				Name:  "",
				Image: "nginx:latest",
			},
			wantErr: ErrInvalidName,
		},
		{
			name: "invalid name - starts with number",
			spec: &OrchestratorContainerSpec{
				Name:  "1container",
				Image: "nginx:latest",
			},
			wantErr: ErrInvalidName,
		},
		{
			name: "invalid name - special chars",
			spec: &OrchestratorContainerSpec{
				Name:  "my@container",
				Image: "nginx:latest",
			},
			wantErr: ErrInvalidName,
		},
		{
			name: "empty image",
			spec: &OrchestratorContainerSpec{
				Name:  "mycontainer",
				Image: "",
			},
			wantErr: ErrInvalidImage,
		},
		{
			name: "valid minimal spec",
			spec: &OrchestratorContainerSpec{
				Name:  "mycontainer",
				Image: "nginx:latest",
			},
			wantErr: nil,
		},
		{
			name: "valid name with hyphen",
			spec: &OrchestratorContainerSpec{
				Name:  "my-container",
				Image: "nginx:latest",
			},
			wantErr: nil,
		},
		{
			name: "valid name with underscore",
			spec: &OrchestratorContainerSpec{
				Name:  "my_container",
				Image: "nginx:latest",
			},
			wantErr: nil,
		},
		{
			name: "valid name with numbers",
			spec: &OrchestratorContainerSpec{
				Name:  "container123",
				Image: "nginx:latest",
			},
			wantErr: nil,
		},
		{
			name: "valid full spec",
			spec: &OrchestratorContainerSpec{
				Name:    "webapp",
				Image:   "registry.example.com/app:v1.0",
				Command: []string{"/app"},
				Args:    []string{"--port", "8080"},
				Env:     map[string]string{"ENV": "production"},
				Mounts: []MountConfig{
					{Source: "/host/data", Target: "/data", ReadOnly: true},
				},
				Resources: ResourceConfig{
					MemoryLimit: "512M",
					CPULimit:    "1",
				},
				Network: ContainerNetworkConfig{
					Mode: NetworkModeBridge,
				},
				Service: ServiceConfig{
					Mode: ServiceModeEmbedded,
				},
				Labels: map[string]string{"app": "web"},
			},
			wantErr: nil,
		},
		{
			name: "invalid network mode",
			spec: &OrchestratorContainerSpec{
				Name:  "mycontainer",
				Image: "nginx:latest",
				Network: ContainerNetworkConfig{
					Mode: NetworkMode("invalid"),
				},
			},
			wantErr: ErrInvalidNetworkMode,
		},
		{
			name: "invalid service mode",
			spec: &OrchestratorContainerSpec{
				Name:  "mycontainer",
				Image: "nginx:latest",
				Service: ServiceConfig{
					Mode: ContainerServiceMode("invalid"),
				},
			},
			wantErr: ErrInvalidServiceMode,
		},
		{
			name: "invalid resource config",
			spec: &OrchestratorContainerSpec{
				Name:  "mycontainer",
				Image: "nginx:latest",
				Resources: ResourceConfig{
					MemoryLimit: "invalid",
				},
			},
			wantErr: ErrInvalidResourceConfig,
		},
		{
			name: "invalid mount config",
			spec: &OrchestratorContainerSpec{
				Name:  "mycontainer",
				Image: "nginx:latest",
				Mounts: []MountConfig{
					{Source: "", Target: ""}, // Missing target
				},
			},
			wantErr: ErrInvalidMountConfig,
		},
		{
			name: "SDN mode without SDN config",
			spec: &OrchestratorContainerSpec{
				Name:  "mycontainer",
				Image: "nginx:latest",
				Network: ContainerNetworkConfig{
					Mode: NetworkModeSDN,
					SDN:  nil,
				},
			},
			wantErr: ErrInvalidNetworkMode,
		},
		{
			name: "valid SDN config",
			spec: &OrchestratorContainerSpec{
				Name:  "mycontainer",
				Image: "nginx:latest",
				Network: ContainerNetworkConfig{
					Mode: NetworkModeSDN,
					SDN: &SDNConfig{
						Bridge: "br-platform",
						VLANID: 100,
					},
				},
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.spec.Validate()
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("OrchestratorContainerSpec.Validate() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("OrchestratorContainerSpec.Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("OrchestratorContainerSpec.Validate() unexpected error = %v", err)
			}
		})
	}
}

func TestContainerConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *ContainerConfig
		wantErr error
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: ErrInvalidSpec,
		},
		{
			name: "empty name",
			config: &ContainerConfig{
				Name:  "",
				Image: "nginx:latest",
			},
			wantErr: ErrInvalidName,
		},
		{
			name: "empty image",
			config: &ContainerConfig{
				Name:  "mycontainer",
				Image: "",
			},
			wantErr: ErrInvalidImage,
		},
		{
			name: "valid config",
			config: &ContainerConfig{
				Name:  "mycontainer",
				Image: "nginx:latest",
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.config.Validate()
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("ContainerConfig.Validate() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("ContainerConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("ContainerConfig.Validate() unexpected error = %v", err)
			}
		})
	}
}

func TestServiceConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  ServiceConfig
		wantErr error
	}{
		{
			name:    "empty mode defaults to embedded",
			config:  ServiceConfig{},
			wantErr: nil,
		},
		{
			name: "valid embedded",
			config: ServiceConfig{
				Mode: ServiceModeEmbedded,
			},
			wantErr: nil,
		},
		{
			name: "valid standalone",
			config: ServiceConfig{
				Mode: ServiceModeStandalone,
			},
			wantErr: nil,
		},
		{
			name: "valid standalone with config",
			config: ServiceConfig{
				Mode: ServiceModeStandalone,
				Standalone: &StandaloneConfig{
					Restart:   "always",
					After:     []string{"network.target"},
					MemoryMax: "4G",
				},
			},
			wantErr: nil,
		},
		{
			name: "invalid mode",
			config: ServiceConfig{
				Mode: ContainerServiceMode("invalid"),
			},
			wantErr: ErrInvalidServiceMode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.config.Validate()
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("ServiceConfig.Validate() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("ServiceConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("ServiceConfig.Validate() unexpected error = %v", err)
			}
		})
	}
}

func TestStandaloneConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *StandaloneConfig
		wantErr error
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: nil,
		},
		{
			name:    "empty config",
			config:  &StandaloneConfig{},
			wantErr: nil,
		},
		{
			name: "valid systemd override",
			config: &StandaloneConfig{
				InitSystemOverride: "systemd",
			},
			wantErr: nil,
		},
		{
			name: "valid rc override",
			config: &StandaloneConfig{
				InitSystemOverride: "rc",
			},
			wantErr: nil,
		},
		{
			name: "valid runit override",
			config: &StandaloneConfig{
				InitSystemOverride: "runit",
			},
			wantErr: nil,
		},
		{
			name: "invalid init system",
			config: &StandaloneConfig{
				InitSystemOverride: "invalid",
			},
			wantErr: ErrUnsupportedInitSystem,
		},
		{
			name: "valid restart always",
			config: &StandaloneConfig{
				Restart: "always",
			},
			wantErr: nil,
		},
		{
			name: "valid restart on-failure",
			config: &StandaloneConfig{
				Restart: "on-failure",
			},
			wantErr: nil,
		},
		{
			name: "valid restart no",
			config: &StandaloneConfig{
				Restart: "no",
			},
			wantErr: nil,
		},
		{
			name: "invalid restart policy",
			config: &StandaloneConfig{
				Restart: "invalid",
			},
			wantErr: ErrInvalidSpec,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.config.Validate()
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("StandaloneConfig.Validate() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("StandaloneConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("StandaloneConfig.Validate() unexpected error = %v", err)
			}
		})
	}
}

func TestContainerNetworkConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  ContainerNetworkConfig
		wantErr error
	}{
		{
			name:    "empty defaults to bridge",
			config:  ContainerNetworkConfig{},
			wantErr: nil,
		},
		{
			name: "valid bridge",
			config: ContainerNetworkConfig{
				Mode: NetworkModeBridge,
			},
			wantErr: nil,
		},
		{
			name: "valid host",
			config: ContainerNetworkConfig{
				Mode: NetworkModeHost,
			},
			wantErr: nil,
		},
		{
			name: "valid none",
			config: ContainerNetworkConfig{
				Mode: NetworkModeNone,
			},
			wantErr: nil,
		},
		{
			name: "SDN without config",
			config: ContainerNetworkConfig{
				Mode: NetworkModeSDN,
			},
			wantErr: ErrInvalidNetworkMode,
		},
		{
			name: "valid SDN",
			config: ContainerNetworkConfig{
				Mode: NetworkModeSDN,
				SDN: &SDNConfig{
					Bridge: "br0",
					VLANID: 100,
				},
			},
			wantErr: nil,
		},
		{
			name: "invalid mode",
			config: ContainerNetworkConfig{
				Mode: NetworkMode("invalid"),
			},
			wantErr: ErrInvalidNetworkMode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.config.Validate()
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("ContainerNetworkConfig.Validate() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("ContainerNetworkConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("ContainerNetworkConfig.Validate() unexpected error = %v", err)
			}
		})
	}
}

func TestSDNConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *SDNConfig
		wantErr error
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: nil,
		},
		{
			name: "empty bridge",
			config: &SDNConfig{
				Bridge: "",
			},
			wantErr: ErrNetworkSetupFailed,
		},
		{
			name: "valid untagged VLAN",
			config: &SDNConfig{
				Bridge: "br0",
				VLANID: 0,
			},
			wantErr: nil,
		},
		{
			name: "valid tagged VLAN",
			config: &SDNConfig{
				Bridge: "br0",
				VLANID: 100,
			},
			wantErr: nil,
		},
		{
			name: "max valid VLAN",
			config: &SDNConfig{
				Bridge: "br0",
				VLANID: 4094,
			},
			wantErr: nil,
		},
		{
			name: "invalid VLAN",
			config: &SDNConfig{
				Bridge: "br0",
				VLANID: 4095,
			},
			wantErr: ErrVLANConfigFailed,
		},
		{
			name: "VLAN too high",
			config: &SDNConfig{
				Bridge: "br0",
				VLANID: 5000,
			},
			wantErr: ErrVLANConfigFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.config.Validate()
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("SDNConfig.Validate() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("SDNConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("SDNConfig.Validate() unexpected error = %v", err)
			}
		})
	}
}

func TestResourceConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  ResourceConfig
		wantErr error
	}{
		{
			name:    "empty config",
			config:  ResourceConfig{},
			wantErr: nil,
		},
		{
			name: "valid memory in MB",
			config: ResourceConfig{
				MemoryLimit: "512M",
			},
			wantErr: nil,
		},
		{
			name: "valid memory in GB",
			config: ResourceConfig{
				MemoryLimit: "4G",
			},
			wantErr: nil,
		},
		{
			name: "valid memory in bytes",
			config: ResourceConfig{
				MemoryLimit: "1073741824",
			},
			wantErr: nil,
		},
		{
			name: "invalid memory format",
			config: ResourceConfig{
				MemoryLimit: "invalid",
			},
			wantErr: ErrInvalidResourceConfig,
		},
		{
			name: "valid memory reservation",
			config: ResourceConfig{
				MemoryReservation: "256M",
			},
			wantErr: nil,
		},
		{
			name: "invalid memory reservation",
			config: ResourceConfig{
				MemoryReservation: "abc",
			},
			wantErr: ErrInvalidResourceConfig,
		},
		{
			name: "valid memory swap",
			config: ResourceConfig{
				MemorySwap: "1G",
			},
			wantErr: nil,
		},
		{
			name: "invalid memory swap",
			config: ResourceConfig{
				MemorySwap: "xyz",
			},
			wantErr: ErrInvalidResourceConfig,
		},
		{
			name: "negative cpu shares",
			config: ResourceConfig{
				CPUShares: -1,
			},
			wantErr: ErrInvalidResourceConfig,
		},
		{
			name: "valid cpu shares",
			config: ResourceConfig{
				CPUShares: 1024,
			},
			wantErr: nil,
		},
		{
			name: "negative pids limit",
			config: ResourceConfig{
				PidsLimit: -1,
			},
			wantErr: ErrInvalidResourceConfig,
		},
		{
			name: "valid pids limit",
			config: ResourceConfig{
				PidsLimit: 100,
			},
			wantErr: nil,
		},
		{
			name: "valid fractional cpu limit",
			config: ResourceConfig{
				CPULimit: "0.5",
			},
			wantErr: nil,
		},
		{
			// A limit the runtime cannot apply is refused at validation, so the
			// launch fails before a container is created rather than after.
			name: "unparseable cpu limit",
			config: ResourceConfig{
				CPULimit: "two",
			},
			wantErr: ErrInvalidResourceConfig,
		},
		{
			name: "negative cpu limit",
			config: ResourceConfig{
				CPULimit: "-1",
			},
			wantErr: ErrInvalidResourceConfig,
		},
		{
			name: "full valid config",
			config: ResourceConfig{
				CPULimit:          "2",
				CPUShares:         512,
				MemoryLimit:       "1G",
				MemorySwap:        "2G",
				MemoryReservation: "512M",
				PidsLimit:         1000,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.config.Validate()
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("ResourceConfig.Validate() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("ResourceConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("ResourceConfig.Validate() unexpected error = %v", err)
			}
		})
	}
}

func TestMountConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  MountConfig
		wantErr error
	}{
		{
			name: "empty target",
			config: MountConfig{
				Source: "/host/path",
				Target: "",
			},
			wantErr: ErrInvalidMountConfig,
		},
		{
			name: "bind mount without source",
			config: MountConfig{
				Source: "",
				Target: "/container/path",
				Type:   MountTypeBind,
			},
			wantErr: ErrInvalidMountConfig,
		},
		{
			name: "volume mount without source",
			config: MountConfig{
				Source: "",
				Target: "/container/path",
				Type:   MountTypeVolume,
			},
			wantErr: ErrInvalidMountConfig,
		},
		{
			name: "tmpfs mount without source",
			config: MountConfig{
				Source: "",
				Target: "/container/path",
				Type:   MountTypeTmpfs,
			},
			wantErr: nil, // tmpfs doesn't need source
		},
		{
			name: "valid bind mount",
			config: MountConfig{
				Source:   "/host/path",
				Target:   "/container/path",
				Type:     MountTypeBind,
				ReadOnly: true,
			},
			wantErr: nil,
		},
		{
			name: "valid volume mount",
			config: MountConfig{
				Source: "myvolume",
				Target: "/data",
				Type:   MountTypeVolume,
			},
			wantErr: nil,
		},
		{
			name: "invalid mount type",
			config: MountConfig{
				Source: "/host",
				Target: "/container",
				Type:   MountType("invalid"),
			},
			wantErr: ErrInvalidMountConfig,
		},
		{
			name: "default type with source",
			config: MountConfig{
				Source: "/host",
				Target: "/container",
			},
			wantErr: nil,
		},
		{
			name: "default type without source",
			config: MountConfig{
				Source: "",
				Target: "/container",
			},
			wantErr: ErrInvalidMountConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.config.Validate()
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("MountConfig.Validate() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("MountConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("MountConfig.Validate() unexpected error = %v", err)
			}
		})
	}
}

func TestValidateImageReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ref     string
		wantErr bool
	}{
		{"empty", "", true},
		{"simple image", "nginx", false},
		{"image with tag", "nginx:latest", false},
		{"image with version tag", "nginx:1.21", false},
		{"registry and image", "docker.io/nginx", false},
		{"full path", "registry.example.com/myapp/image:v1.0", false},
		{"with digest", "nginx@sha256:abc123", false},
		{"registry with port", "localhost:5000/image:tag", false},
		{"trailing slash", "nginx/", true},
		{"empty tag", "nginx:", false}, // Empty tag defaults to latest
		{"invalid digest format", "nginx@", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateImageReference(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateImageReference(%q) error = %v, wantErr %v", tt.ref, err, tt.wantErr)
			}
		})
	}
}

func TestIsValidMemoryFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mem   string
		valid bool
	}{
		{"", false},
		{"512M", true},
		{"512m", true},
		{"1G", true},
		{"1g", true},
		{"100K", true},
		{"1024B", true},
		{"1024", true}, // bytes
		{"512MB", true},
		{"1GB", true},
		{"invalid", false},
		{"M512", false},
		{"1.5G", false}, // no decimals
		{"-512M", false},
	}

	for _, tt := range tests {
		t.Run(tt.mem, func(t *testing.T) {
			t.Parallel()
			if got := isValidMemoryFormat(tt.mem); got != tt.valid {
				t.Errorf("isValidMemoryFormat(%q) = %v, want %v", tt.mem, got, tt.valid)
			}
		})
	}
}

func TestContainerConfig_ToOrchestratorContainerSpec(t *testing.T) {
	t.Parallel()

	t.Run("nil config", func(t *testing.T) {
		t.Parallel()
		var config *ContainerConfig
		if got := config.ToOrchestratorContainerSpec(); got != nil {
			t.Error("ToOrchestratorContainerSpec() should return nil for nil config")
		}
	})

	t.Run("converts all fields", func(t *testing.T) {
		t.Parallel()
		config := &ContainerConfig{
			Name:    "test",
			Image:   "nginx:latest",
			Command: []string{"/bin/sh"},
			Args:    []string{"-c", "echo hello"},
			Env:     map[string]string{"KEY": "value"},
			Mounts: []MountConfig{
				{Source: "/host", Target: "/container"},
			},
			Resources: ResourceConfig{
				MemoryLimit: "512M",
			},
			Network: ContainerNetworkConfig{
				Mode: NetworkModeBridge,
			},
			Service: ServiceConfig{
				Mode: ServiceModeEmbedded,
			},
			Labels:     map[string]string{"app": "test"},
			Privileged: false,
			Capabilities: CapabilityConfig{
				Add:  []string{"NET_ADMIN"},
				Drop: []string{"ALL"},
			},
			Ports: []PortMapping{
				{ContainerPort: 80, HostPort: 8080},
			},
		}

		spec := config.ToOrchestratorContainerSpec()

		if spec.Name != config.Name {
			t.Errorf("Name = %q, want %q", spec.Name, config.Name)
		}
		if spec.Image != config.Image {
			t.Errorf("Image = %q, want %q", spec.Image, config.Image)
		}
		if len(spec.Command) != len(config.Command) {
			t.Errorf("Command length = %d, want %d", len(spec.Command), len(config.Command))
		}
		if len(spec.Args) != len(config.Args) {
			t.Errorf("Args length = %d, want %d", len(spec.Args), len(config.Args))
		}
		if spec.Env["KEY"] != "value" {
			t.Errorf("Env[KEY] = %q, want %q", spec.Env["KEY"], "value")
		}
		if len(spec.Mounts) != 1 {
			t.Errorf("Mounts length = %d, want 1", len(spec.Mounts))
		}
		if spec.Resources.MemoryLimit != "512M" {
			t.Errorf("Resources.MemoryLimit = %q, want %q", spec.Resources.MemoryLimit, "512M")
		}
		if spec.Network.Mode != NetworkModeBridge {
			t.Errorf("Network.Mode = %q, want %q", spec.Network.Mode, NetworkModeBridge)
		}
		if spec.Service.Mode != ServiceModeEmbedded {
			t.Errorf("Service.Mode = %q, want %q", spec.Service.Mode, ServiceModeEmbedded)
		}
		if len(spec.Ports) != 1 {
			t.Errorf("Ports length = %d, want 1", len(spec.Ports))
		}
	})
}

func TestOrchestratorContainerSpec_ToAttestationSpec(t *testing.T) {
	t.Parallel()

	t.Run("nil spec", func(t *testing.T) {
		t.Parallel()
		var spec *OrchestratorContainerSpec
		if got := spec.ToAttestationSpec(); got != nil {
			t.Error("ToAttestationSpec() should return nil for nil spec")
		}
	})

	newSpec := func() *OrchestratorContainerSpec {
		return &OrchestratorContainerSpec{
			Name:       "test",
			Image:      "nginx:latest",
			Command:    []string{"/bin/sh"},
			Args:       []string{"-c", "true"},
			User:       "nginx",
			WorkingDir: "/app",
			Privileged: false,
			Env:        map[string]string{"KEY": "value"},
			Labels:     map[string]string{"app": "web"},
			Mounts: []MountConfig{
				{Source: "/host", Target: "/container", Type: MountTypeBind, ReadOnly: true},
			},
			Capabilities: CapabilityConfig{
				Add:  []string{"NET_ADMIN"},
				Drop: []string{"ALL"},
			},
			Ports: []PortMapping{
				{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
			},
		}
	}

	t.Run("converts to the SDK container spec", func(t *testing.T) {
		t.Parallel()
		spec := newSpec()
		attestSpec := spec.ToAttestationSpec()

		if attestSpec.Name != spec.Name {
			t.Errorf("Name = %q, want %q", attestSpec.Name, spec.Name)
		}
		if attestSpec.Image != spec.Image {
			t.Errorf("Image = %q, want %q", attestSpec.Image, spec.Image)
		}
		if attestSpec.User != spec.User {
			t.Errorf("User = %q, want %q", attestSpec.User, spec.User)
		}
		if attestSpec.WorkDir != spec.WorkingDir {
			t.Errorf("WorkDir = %q, want %q", attestSpec.WorkDir, spec.WorkingDir)
		}
		if len(attestSpec.Mounts) != 1 {
			t.Fatalf("Mounts length = %d, want 1", len(attestSpec.Mounts))
		}
		if !attestSpec.Mounts[0].ReadOnly {
			t.Error("mount read-only flag was not carried across")
		}
		if len(attestSpec.Ports) != 1 || attestSpec.Ports[0] != "8080:80/tcp" {
			t.Errorf("Ports = %v, want [8080:80/tcp]", attestSpec.Ports)
		}
		if attestSpec.Labels["app"] != "web" {
			t.Error("caller labels must be preserved")
		}
	})

	// The privilege dimension maps to the real SDK fields. It used to be
	// smuggled through reserved "trustedplatform.io/*" labels because the SDK
	// spec had no field for it; those fields now exist and are measured, so the
	// label carrier is gone and must not come back.
	t.Run("privilege fields map to real SDK fields, not labels", func(t *testing.T) {
		t.Parallel()

		spec := newSpec()
		spec.Privileged = true
		spec.Mounts[0].Type = MountTypeTmpfs
		spec.Mounts[0].Source = ""
		attestSpec := spec.ToAttestationSpec()

		if !attestSpec.Privileged {
			t.Error("Privileged was not mapped to ContainerSpec.Privileged")
		}
		if len(attestSpec.CapAdd) != 1 || attestSpec.CapAdd[0] != "NET_ADMIN" {
			t.Errorf("CapAdd = %v, want [NET_ADMIN]", attestSpec.CapAdd)
		}
		if len(attestSpec.CapDrop) != 1 || attestSpec.CapDrop[0] != "ALL" {
			t.Errorf("CapDrop = %v, want [ALL]", attestSpec.CapDrop)
		}
		if attestSpec.Mounts[0].Type != orchestration.MountTypeTmpfs {
			t.Errorf("mount Type = %q, want %q",
				attestSpec.Mounts[0].Type, orchestration.MountTypeTmpfs)
		}
		for key := range attestSpec.Labels {
			if strings.HasPrefix(key, "trustedplatform.io/") {
				t.Errorf("reserved measurement label %q leaked into the spec; "+
					"the privilege dimension is carried by real fields now", key)
			}
		}
	})

	// The property the deleted label carrier existed to guarantee: each of the
	// four security-relevant fields still changes the configuration digest, so
	// no measurement coverage was lost by moving to the upstream fields.
	t.Run("security-relevant fields stay inside the digest", func(t *testing.T) {
		t.Parallel()

		base := newSpec().ToAttestationSpec()
		baseDigest, err := orchestration.ContainerConfigDigest(base)
		if err != nil {
			t.Fatalf("ContainerConfigDigest: %v", err)
		}

		testCases := []struct {
			name   string
			mutate func(*OrchestratorContainerSpec)
		}{
			{"privileged", func(s *OrchestratorContainerSpec) { s.Privileged = true }},
			{"cap add", func(s *OrchestratorContainerSpec) {
				s.Capabilities.Add = []string{"NET_ADMIN", "SYS_ADMIN"}
			}},
			{"cap drop", func(s *OrchestratorContainerSpec) { s.Capabilities.Drop = nil }},
			{"mount type", func(s *OrchestratorContainerSpec) { s.Mounts[0].Type = MountTypeVolume }},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				spec := newSpec()
				tc.mutate(spec)
				digest, err := orchestration.ContainerConfigDigest(spec.ToAttestationSpec())
				if err != nil {
					t.Fatalf("ContainerConfigDigest: %v", err)
				}
				if digest == baseDigest {
					t.Errorf("changing %s must change the configuration digest", tc.name)
				}
			})
		}
	})

	// Same proof stated as the reviewer's question: two containers that differ
	// in exactly one of these dimensions and nothing else must not measure the
	// same. Each pair is built from scratch so nothing else can differ.
	t.Run("a single differing dimension produces a different digest", func(t *testing.T) {
		t.Parallel()

		digestOf := func(t *testing.T, s *OrchestratorContainerSpec) string {
			t.Helper()
			d, err := orchestration.ContainerConfigDigest(s.ToAttestationSpec())
			if err != nil {
				t.Fatalf("ContainerConfigDigest: %v", err)
			}
			return d
		}

		pairs := []struct {
			name string
			a    func() *OrchestratorContainerSpec
			b    func() *OrchestratorContainerSpec
		}{
			{
				name: "only privileged",
				a:    func() *OrchestratorContainerSpec { return newSpec() },
				b: func() *OrchestratorContainerSpec {
					s := newSpec()
					s.Privileged = true
					return s
				},
			},
			{
				name: "only one added capability",
				a:    func() *OrchestratorContainerSpec { return newSpec() },
				b: func() *OrchestratorContainerSpec {
					s := newSpec()
					s.Capabilities.Add = append(s.Capabilities.Add, "SYS_ADMIN")
					return s
				},
			},
			{
				name: "only one dropped capability",
				a:    func() *OrchestratorContainerSpec { return newSpec() },
				b: func() *OrchestratorContainerSpec {
					s := newSpec()
					s.Capabilities.Drop = []string{"ALL", "NET_RAW"}
					return s
				},
			},
			{
				name: "only the mount type",
				a:    func() *OrchestratorContainerSpec { return newSpec() },
				b: func() *OrchestratorContainerSpec {
					s := newSpec()
					s.Mounts[0].Type = MountTypeVolume
					return s
				},
			},
		}

		for _, pair := range pairs {
			t.Run(pair.name, func(t *testing.T) {
				if digestOf(t, pair.a()) == digestOf(t, pair.b()) {
					t.Errorf("containers differing by %s measured identically", pair.name)
				}
			})
		}
	})

	// Capability order is not semantically meaningful, so it must not change
	// the digest. ContainerConfigDigest sorts both lists before hashing.
	t.Run("capability order does not change the digest", func(t *testing.T) {
		t.Parallel()

		a := newSpec()
		a.Capabilities.Add = []string{"NET_ADMIN", "SYS_TIME"}
		a.Capabilities.Drop = []string{"MKNOD", "AUDIT_WRITE"}
		b := newSpec()
		b.Capabilities.Add = []string{"SYS_TIME", "NET_ADMIN"}
		b.Capabilities.Drop = []string{"AUDIT_WRITE", "MKNOD"}

		digestA, err := orchestration.ContainerConfigDigest(a.ToAttestationSpec())
		if err != nil {
			t.Fatalf("ContainerConfigDigest(a): %v", err)
		}
		digestB, err := orchestration.ContainerConfigDigest(b.ToAttestationSpec())
		if err != nil {
			t.Fatalf("ContainerConfigDigest(b): %v", err)
		}
		if digestA != digestB {
			t.Error("capability ordering must not affect the configuration digest")
		}
	})

	// Sorting must not corrupt the caller's slices: the measurement spec is
	// derived from a spec that is also used to launch the container.
	t.Run("computing the digest does not reorder the caller capabilities", func(t *testing.T) {
		t.Parallel()

		spec := newSpec()
		spec.Capabilities.Add = []string{"SYS_TIME", "NET_ADMIN"}
		if _, err := orchestration.ContainerConfigDigest(spec.ToAttestationSpec()); err != nil {
			t.Fatalf("ContainerConfigDigest: %v", err)
		}
		if spec.Capabilities.Add[0] != "SYS_TIME" || spec.Capabilities.Add[1] != "NET_ADMIN" {
			t.Errorf("caller capability order was mutated: %v", spec.Capabilities.Add)
		}
	})

	// The SDK deliberately excludes Name as a per-instance identifier.
	t.Run("container name is excluded from the digest", func(t *testing.T) {
		t.Parallel()

		a := newSpec()
		b := newSpec()
		b.Name = "different-name"

		digestA, err := orchestration.ContainerConfigDigest(a.ToAttestationSpec())
		if err != nil {
			t.Fatalf("ContainerConfigDigest(a): %v", err)
		}
		digestB, err := orchestration.ContainerConfigDigest(b.ToAttestationSpec())
		if err != nil {
			t.Fatalf("ContainerConfigDigest(b): %v", err)
		}
		if digestA != digestB {
			t.Error("the container name must not affect the configuration digest")
		}
	})
}

// TestOrchestratorContainerSpec_MeasurementGaps classifies EVERY field of
// OrchestratorContainerSpec as measured, deliberately excluded, or a stated
// gap — and proves the classification.
//
// It is exhaustive by reflection, so a field added to the specification fails
// this test until its measurement status is decided in writing. The launch-side
// counterpart, TestLaunchConfig_MeasurementCoverage, does the same for the
// effective launch configuration the backend receives.
//
// The gaps fall into two kinds, and the distinction matters:
//
//   - Upstream gaps: the field changes what the container can reach, but the
//     go-quicbaas SDK container spec has no field for it. Each names the
//     upstream field that would close it. It is closed by adding that field to
//     orchestration.ContainerSpec and its ContainerConfigDigest — never by
//     smuggling the value through a label.
//   - Deliberate exclusions: the field is availability or management, not
//     integrity, or nothing in the launch path reads it at all. Measuring it
//     would make goldens brittle for no security gain.
func TestOrchestratorContainerSpec_MeasurementGaps(t *testing.T) {
	t.Parallel()

	base := func() *OrchestratorContainerSpec {
		return &OrchestratorContainerSpec{
			Name:  "gap",
			Image: "nginx:latest",
			Mounts: []MountConfig{
				{Source: "/host", Target: "/container", Type: MountTypeBind},
			},
		}
	}

	digestOf := func(t *testing.T, s *OrchestratorContainerSpec) string {
		t.Helper()
		d, err := orchestration.ContainerConfigDigest(s.ToAttestationSpec())
		if err != nil {
			t.Fatalf("ContainerConfigDigest: %v", err)
		}
		return d
	}
	baseDigest := digestOf(t, base())

	// measured: mutating the field must change the configuration digest.
	measured := map[string]func(*OrchestratorContainerSpec){
		"Image":      func(s *OrchestratorContainerSpec) { s.Image = "nginx:1.27" },
		"Command":    func(s *OrchestratorContainerSpec) { s.Command = []string{"/bin/sh"} },
		"Args":       func(s *OrchestratorContainerSpec) { s.Args = []string{"-c", "curl evil"} },
		"Env":        func(s *OrchestratorContainerSpec) { s.Env = map[string]string{"K": "v"} },
		"Mounts":     func(s *OrchestratorContainerSpec) { s.Mounts[0].Source = "/etc" },
		"Labels":     func(s *OrchestratorContainerSpec) { s.Labels = map[string]string{"a": "b"} },
		"User":       func(s *OrchestratorContainerSpec) { s.User = "0:0" },
		"WorkingDir": func(s *OrchestratorContainerSpec) { s.WorkingDir = "/root" },
		"Privileged": func(s *OrchestratorContainerSpec) { s.Privileged = true },
		"Capabilities": func(s *OrchestratorContainerSpec) {
			s.Capabilities = CapabilityConfig{Add: []string{"SYS_ADMIN"}}
		},
		"Ports": func(s *OrchestratorContainerSpec) {
			s.Ports = []PortMapping{{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}}
		},
		"Network": func(s *OrchestratorContainerSpec) { s.Network.Mode = NetworkModeHost },
		// The host TPM is measured as the /dev/tpm0 entry the launch
		// configuration carries. This was the two-derivations hole.
		"TPMAccess": func(s *OrchestratorContainerSpec) { s.TPMAccess = true },
	}

	// carried but excluded from the digest by design.
	carried := map[string]string{
		"Name": "a per-instance identifier the SDK excludes from the digest",
	}

	gaps := map[string]struct {
		reason string
		mutate func(*OrchestratorContainerSpec)
	}{
		"Resources": {
			// Availability, not integrity: limits can starve a workload but
			// cannot change what it runs or what it can reach. They ARE carried
			// on the effective launch configuration and applied by every launch
			// path, so no supervisor runs a differently constrained container;
			// they are simply not part of the workload's measured identity.
			reason: "CPU, memory and PID limits are availability, not integrity, and " +
				"never reach the measured launch configuration",
			mutate: func(s *OrchestratorContainerSpec) {
				s.Resources = ResourceConfig{CPULimit: "2", MemoryLimit: "2G", PidsLimit: 4096}
			},
		},
		"RestartPolicy": {
			// Lifecycle only, and inert: no code reads it.
			reason: "restart behaviour is lifecycle, not integrity; nothing in the " +
				"launch path reads the field",
			mutate: func(s *OrchestratorContainerSpec) { s.RestartPolicy = RestartAlways },
		},
		"HealthCheck": {
			// Would be integrity-relevant if it were wired — the runtime would
			// execute the command inside the container — but nothing reads it,
			// so it cannot reach a container today. Measuring an inert field
			// would make goldens brittle without protecting anything. If it is
			// ever wired into the launch path it must be measured, and
			// TestLaunchConfig_MeasurementCoverage will demand that.
			reason: "inert: no code path applies the health check, so it cannot " +
				"reach a container. Must be measured if it is ever wired",
			mutate: func(s *OrchestratorContainerSpec) {
				s.HealthCheck = &HealthCheckConfig{Command: []string{"/bin/true"}}
			},
		},
		"Annotations": {
			// Metadata with no consumer. Labels ARE measured, and anything that
			// needs to be measured belongs there.
			reason: "inert metadata with no consumer; Labels are measured and are " +
				"where measured metadata belongs",
			mutate: func(s *OrchestratorContainerSpec) {
				s.Annotations = map[string]string{"note": "unmeasured"}
			},
		},
		"Service": {
			// Chooses who supervises the container, not what runs inside it.
			// Note the standalone generators build their own podman command
			// line, which is a separate derivation and a separate finding.
			reason: "selects the supervisor (platformd or an init service), not the " +
				"container's contents or privileges",
			mutate: func(s *OrchestratorContainerSpec) {
				s.Service = ServiceConfig{Mode: ServiceModeStandalone}
			},
		},
	}

	specType := reflect.TypeOf(OrchestratorContainerSpec{})
	for i := 0; i < specType.NumField(); i++ {
		name := specType.Field(i).Name
		_, isMeasured := measured[name]
		_, isCarried := carried[name]
		_, isGap := gaps[name]
		if !isMeasured && !isCarried && !isGap {
			t.Errorf("OrchestratorContainerSpec.%s is not classified: decide whether "+
				"it belongs in the configuration digest, wire it through "+
				"newLaunchConfig if so, and update "+
				"docs/attestation/workload-attestation.md", name)
		}
	}

	for name, mutate := range measured {
		t.Run("measured/"+name, func(t *testing.T) {
			spec := base()
			mutate(spec)
			if digestOf(t, spec) == baseDigest {
				t.Errorf("changing %s must change the configuration digest", name)
			}
		})
	}

	for name, gap := range gaps {
		t.Run("gap/"+name, func(t *testing.T) {
			spec := base()
			gap.mutate(spec)
			if digestOf(t, spec) != baseDigest {
				t.Errorf("%s now affects the configuration digest — the gap is closed; "+
					"reclassify it here and in docs/attestation/workload-attestation.md "+
					"(reason was: %s)", name, gap.reason)
			}
		})
	}

	// Sub-field gaps inside fields that are otherwise measured. Each names the
	// upstream field that would close it.
	subGaps := []struct {
		field    string
		upstream string
		mutate   func(*OrchestratorContainerSpec)
	}{
		{
			field:    "MountConfig.Propagation",
			upstream: "orchestration.ContainerMount.Propagation",
			mutate: func(s *OrchestratorContainerSpec) {
				s.Mounts[0].Propagation = PropagationRShared
			},
		},
		{
			field:    "Network.Hostname",
			upstream: "orchestration.ContainerSpec.Hostname",
			mutate:   func(s *OrchestratorContainerSpec) { s.Network.Hostname = "elsewhere" },
		},
		{
			field:    "Network.DNSServers",
			upstream: "orchestration.ContainerSpec.DNS",
			mutate:   func(s *OrchestratorContainerSpec) { s.Network.DNSServers = []string{"10.0.0.1"} },
		},
		{
			field:    "Network.DNSSearch",
			upstream: "orchestration.ContainerSpec.DNSSearch",
			mutate:   func(s *OrchestratorContainerSpec) { s.Network.DNSSearch = []string{"evil.test"} },
		},
		{
			// Not even applied: no launch path reads ExtraHosts, so it reaches
			// no container. It must be measured the day it is wired.
			field:    "Network.ExtraHosts (inert: nothing applies it)",
			upstream: "orchestration.ContainerSpec.ExtraHosts",
			mutate:   func(s *OrchestratorContainerSpec) { s.Network.ExtraHosts = []string{"evil:10.0.0.2"} },
		},
		{
			// The SDN block is applied by the network manager after create,
			// outside the container configuration the backend receives.
			field:    "Network.SDN",
			upstream: "an SDN attachment digest folded into the measurement",
			mutate: func(s *OrchestratorContainerSpec) {
				s.Network.Mode = NetworkModeSDN
				s.Network.SDN = &SDNConfig{Bridge: "br0", VLANID: 42, IPAddress: "10.0.0.9"}
			},
		},
	}

	for _, gap := range subGaps {
		t.Run("gap/"+gap.field, func(t *testing.T) {
			spec := base()
			gap.mutate(spec)
			// The SDN case also changes the measured network mode, so compare
			// against a spec that differs only by the sub-field.
			reference := base()
			if gap.field == "Network.SDN" {
				reference.Network.Mode = NetworkModeSDN
				reference.Network.SDN = &SDNConfig{Bridge: "other", VLANID: 7}
			}
			if digestOf(t, spec) != digestOf(t, reference) {
				t.Errorf("%s now affects the configuration digest — the gap is closed; "+
					"remove it here, from AttestationSpec's doc comment and from "+
					"docs/attestation/workload-attestation.md (it would be closed by %s)",
					gap.field, gap.upstream)
			}
		})
	}
}

func TestServiceConfig_GetMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   ServiceConfig
		expected ContainerServiceMode
	}{
		{
			name:     "empty defaults to embedded",
			config:   ServiceConfig{},
			expected: ServiceModeEmbedded,
		},
		{
			name: "explicit embedded",
			config: ServiceConfig{
				Mode: ServiceModeEmbedded,
			},
			expected: ServiceModeEmbedded,
		},
		{
			name: "standalone",
			config: ServiceConfig{
				Mode: ServiceModeStandalone,
			},
			expected: ServiceModeStandalone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.config.GetMode(); got != tt.expected {
				t.Errorf("GetMode() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestContainerNetworkConfig_GetNetworkMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   ContainerNetworkConfig
		expected NetworkMode
	}{
		{
			name:     "empty defaults to bridge",
			config:   ContainerNetworkConfig{},
			expected: NetworkModeBridge,
		},
		{
			name: "explicit bridge",
			config: ContainerNetworkConfig{
				Mode: NetworkModeBridge,
			},
			expected: NetworkModeBridge,
		},
		{
			name: "host",
			config: ContainerNetworkConfig{
				Mode: NetworkModeHost,
			},
			expected: NetworkModeHost,
		},
		{
			name: "sdn",
			config: ContainerNetworkConfig{
				Mode: NetworkModeSDN,
			},
			expected: NetworkModeSDN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.config.GetNetworkMode(); got != tt.expected {
				t.Errorf("GetNetworkMode() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestContainerNameValidation(t *testing.T) {
	t.Parallel()

	validNames := []string{
		"a",
		"abc",
		"Container",
		"my-container",
		"my_container",
		"container123",
		"A123-_test",
	}

	invalidNames := []string{
		"",
		"1container",              // starts with number
		"-container",              // starts with hyphen
		"_container",              // starts with underscore
		"my@container",            // special char
		"my container",            // space
		"my.container",            // dot
		string(make([]byte, 200)), // too long
	}

	for _, name := range validNames {
		t.Run("valid_"+name, func(t *testing.T) {
			t.Parallel()
			if !containerNameRegex.MatchString(name) {
				t.Errorf("containerNameRegex should match valid name: %q", name)
			}
		})
	}

	for _, name := range invalidNames {
		displayName := name
		if len(displayName) > 20 {
			displayName = displayName[:20] + "..."
		}
		t.Run("invalid_"+displayName, func(t *testing.T) {
			t.Parallel()
			if containerNameRegex.MatchString(name) {
				t.Errorf("containerNameRegex should not match invalid name: %q", name)
			}
		})
	}
}
