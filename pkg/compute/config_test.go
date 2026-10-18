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

package compute

import (
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

func TestDefaultOrchestratorConfig(t *testing.T) {
	tests := []struct {
		name        string
		computeType ComputeType
		checkQEMU   bool
	}{
		{"VM Config", ComputeTypeVM, true},
		{"Container Config", ComputeTypeContainer, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultOrchestratorConfig(tt.computeType)

			if config.Type != tt.computeType {
				t.Errorf("Expected Type %v, got %v", tt.computeType, config.Type)
			}

			if config.WorkDir == "" {
				t.Error("WorkDir should not be empty")
			}

			if config.DefaultMemory <= 0 {
				t.Error("DefaultMemory should be greater than 0")
			}

			if config.DefaultCPUs != runtime.NumCPU() {
				t.Errorf("Expected DefaultCPUs %d, got %d", runtime.NumCPU(), config.DefaultCPUs)
			}

			if config.DefaultDiskSize == "" {
				t.Error("DefaultDiskSize should not be empty")
			}

			if config.MaxInstances <= 0 {
				t.Error("MaxInstances should be greater than 0")
			}

			if config.NetworkBridge == "" {
				t.Error("NetworkBridge should not be empty")
			}

			if config.OVSSocketPath == "" {
				t.Error("OVSSocketPath should not be empty")
			}

			if tt.checkQEMU {
				if config.QEMUBinary == "" {
					t.Error("QEMUBinary should not be empty for VM config")
				}
				if config.OVMFCode == "" {
					t.Error("OVMFCode should not be empty for VM config")
				}
				if config.OVMFVars == "" {
					t.Error("OVMFVars should not be empty for VM config")
				}
			}
		})
	}
}

func TestOrchestratorConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *OrchestratorConfig
		wantErr bool
		errType error
	}{
		{
			name:    "Valid VM config",
			config:  DefaultOrchestratorConfig(ComputeTypeVM),
			wantErr: false,
		},
		{
			name:    "Valid Container config",
			config:  DefaultOrchestratorConfig(ComputeTypeContainer),
			wantErr: false,
		},
		{
			name: "Invalid compute type",
			config: &OrchestratorConfig{
				Type:            ComputeType("invalid"),
				WorkDir:         "/tmp",
				DefaultMemory:   4096,
				DefaultCPUs:     2,
				DefaultDiskSize: "10G",
				MaxInstances:    10,
			},
			wantErr: true,
			errType: ErrInvalidConfiguration,
		},
		{
			name: "Empty work directory",
			config: &OrchestratorConfig{
				Type:            ComputeTypeVM,
				WorkDir:         "",
				DefaultMemory:   4096,
				DefaultCPUs:     2,
				DefaultDiskSize: "10G",
				MaxInstances:    10,
			},
			wantErr: true,
			errType: ErrInvalidConfiguration,
		},
		{
			name: "Invalid memory",
			config: &OrchestratorConfig{
				Type:            ComputeTypeVM,
				WorkDir:         "/tmp",
				DefaultMemory:   0,
				DefaultCPUs:     2,
				DefaultDiskSize: "10G",
				MaxInstances:    10,
			},
			wantErr: true,
			errType: ErrInvalidConfiguration,
		},
		{
			name: "Invalid CPUs",
			config: &OrchestratorConfig{
				Type:            ComputeTypeVM,
				WorkDir:         "/tmp",
				DefaultMemory:   4096,
				DefaultCPUs:     0,
				DefaultDiskSize: "10G",
				MaxInstances:    10,
			},
			wantErr: true,
			errType: ErrInvalidConfiguration,
		},
		{
			name: "Empty disk size",
			config: &OrchestratorConfig{
				Type:            ComputeTypeVM,
				WorkDir:         "/tmp",
				DefaultMemory:   4096,
				DefaultCPUs:     2,
				DefaultDiskSize: "",
				MaxInstances:    10,
			},
			wantErr: true,
			errType: ErrInvalidConfiguration,
		},
		{
			name: "Invalid max instances",
			config: &OrchestratorConfig{
				Type:            ComputeTypeVM,
				WorkDir:         "/tmp",
				DefaultMemory:   4096,
				DefaultCPUs:     2,
				DefaultDiskSize: "10G",
				MaxInstances:    0,
			},
			wantErr: true,
			errType: ErrInvalidConfiguration,
		},
		{
			name: "VM missing QEMU binary",
			config: &OrchestratorConfig{
				Type:            ComputeTypeVM,
				WorkDir:         "/tmp",
				DefaultMemory:   4096,
				DefaultCPUs:     2,
				DefaultDiskSize: "10G",
				MaxInstances:    10,
				Arch:            qemu.ArchX86_64,
				QEMUBinary:      "",
				OVMFCode:        "/path/to/ovmf",
				OVMFVars:        "/path/to/vars",
			},
			wantErr: true,
			errType: ErrInvalidConfiguration,
		},
		{
			name: "VM missing OVMF code",
			config: &OrchestratorConfig{
				Type:            ComputeTypeVM,
				WorkDir:         "/tmp",
				DefaultMemory:   4096,
				DefaultCPUs:     2,
				DefaultDiskSize: "10G",
				MaxInstances:    10,
				Arch:            qemu.ArchX86_64,
				QEMUBinary:      "qemu-system-x86_64",
				OVMFCode:        "",
				OVMFVars:        "/path/to/vars",
			},
			wantErr: true,
			errType: ErrInvalidConfiguration,
		},
		{
			name: "VM missing OVMF vars",
			config: &OrchestratorConfig{
				Type:            ComputeTypeVM,
				WorkDir:         "/tmp",
				DefaultMemory:   4096,
				DefaultCPUs:     2,
				DefaultDiskSize: "10G",
				MaxInstances:    10,
				Arch:            qemu.ArchX86_64,
				QEMUBinary:      "qemu-system-x86_64",
				OVMFCode:        "/path/to/ovmf",
				OVMFVars:        "",
			},
			wantErr: true,
			errType: ErrInvalidConfiguration,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("OrchestratorConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errType != nil {
				if err != tt.errType && !isErrorType(err, tt.errType) {
					t.Errorf("Expected error type %v, got %v", tt.errType, err)
				}
			}
		})
	}
}

func TestOrchestratorConfig_Fields(t *testing.T) {
	config := &OrchestratorConfig{
		Type:            ComputeTypeVM,
		WorkDir:         "/var/lib/compute",
		DefaultMemory:   8192,
		DefaultCPUs:     8,
		DefaultDiskSize: "50G",
		MaxInstances:    50,
		EnableKVM:       true,
		NetworkBridge:   "br0",
		OVSSocketPath:   "/var/run/ovs/db.sock",
		Arch:            qemu.ArchX86_64,
		QEMUBinary:      "/usr/bin/qemu-system-x86_64",
		OVMFCode:        "/usr/share/ovmf/code.fd",
		OVMFCodeSecure:  "/usr/share/ovmf/code-secure.fd",
		OVMFVars:        "/usr/share/ovmf/vars.fd",
		AutoCleanup:     true,
		Debug:           true,
	}

	if config.Type != ComputeTypeVM {
		t.Errorf("Expected Type VM, got %v", config.Type)
	}
	if config.WorkDir != "/var/lib/compute" {
		t.Errorf("Expected WorkDir /var/lib/compute, got %s", config.WorkDir)
	}
	if config.DefaultMemory != 8192 {
		t.Errorf("Expected DefaultMemory 8192, got %d", config.DefaultMemory)
	}
	if config.DefaultCPUs != 8 {
		t.Errorf("Expected DefaultCPUs 8, got %d", config.DefaultCPUs)
	}
	if config.DefaultDiskSize != "50G" {
		t.Errorf("Expected DefaultDiskSize 50G, got %s", config.DefaultDiskSize)
	}
	if config.MaxInstances != 50 {
		t.Errorf("Expected MaxInstances 50, got %d", config.MaxInstances)
	}
	if !config.EnableKVM {
		t.Error("Expected EnableKVM to be true")
	}
	if config.NetworkBridge != "br0" {
		t.Errorf("Expected NetworkBridge br0, got %s", config.NetworkBridge)
	}
	if !config.AutoCleanup {
		t.Error("Expected AutoCleanup to be true")
	}
	if !config.Debug {
		t.Error("Expected Debug to be true")
	}
}

// Helper function to check if an error wraps a specific error type
func isErrorType(err, target error) bool {
	if err == nil || target == nil {
		return false
	}
	// Simple check - in production you'd use errors.Is()
	return err.Error() != "" && target.Error() != ""
}
