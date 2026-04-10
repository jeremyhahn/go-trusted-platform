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
	"testing"
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
			} else {
				if err != nil {
					t.Errorf("OrchestratorContainerSpec.Validate() unexpected error = %v", err)
				}
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
			} else {
				if err != nil {
					t.Errorf("ContainerConfig.Validate() unexpected error = %v", err)
				}
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
			} else {
				if err != nil {
					t.Errorf("ServiceConfig.Validate() unexpected error = %v", err)
				}
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
			} else {
				if err != nil {
					t.Errorf("StandaloneConfig.Validate() unexpected error = %v", err)
				}
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
			} else {
				if err != nil {
					t.Errorf("ContainerNetworkConfig.Validate() unexpected error = %v", err)
				}
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
			} else {
				if err != nil {
					t.Errorf("SDNConfig.Validate() unexpected error = %v", err)
				}
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
			} else {
				if err != nil {
					t.Errorf("ResourceConfig.Validate() unexpected error = %v", err)
				}
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
			} else {
				if err != nil {
					t.Errorf("MountConfig.Validate() unexpected error = %v", err)
				}
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

	t.Run("converts all fields", func(t *testing.T) {
		t.Parallel()
		spec := &OrchestratorContainerSpec{
			Name:       "test",
			Image:      "nginx:latest",
			Command:    []string{"/bin/sh"},
			User:       "nginx",
			WorkingDir: "/app",
			Privileged: false,
			Env:        map[string]string{"KEY": "value"},
			Mounts: []MountConfig{
				{Source: "/host", Target: "/container", Type: MountTypeBind, ReadOnly: true},
			},
			Capabilities: CapabilityConfig{
				Add:  []string{"NET_ADMIN"},
				Drop: []string{"ALL"},
			},
		}

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
		if attestSpec.WorkingDir != spec.WorkingDir {
			t.Errorf("WorkingDir = %q, want %q", attestSpec.WorkingDir, spec.WorkingDir)
		}
		if attestSpec.Privileged != spec.Privileged {
			t.Errorf("Privileged = %v, want %v", attestSpec.Privileged, spec.Privileged)
		}
		if len(attestSpec.Mounts) != 1 {
			t.Errorf("Mounts length = %d, want 1", len(attestSpec.Mounts))
		}
		if len(attestSpec.Capabilities.Add) != 1 {
			t.Errorf("Capabilities.Add length = %d, want 1", len(attestSpec.Capabilities.Add))
		}
	})
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
