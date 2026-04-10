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
	"fmt"
	"runtime"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// OrchestratorConfig holds configuration for the compute orchestrator
type OrchestratorConfig struct {
	// Type is the orchestrator type (vm, container)
	Type ComputeType `json:"type" yaml:"type"`

	// WorkDir is the base working directory for all instances
	WorkDir string `json:"work_dir" yaml:"work_dir"`

	// DefaultMemory is the default memory allocation in MB
	DefaultMemory int `json:"default_memory" yaml:"default_memory"`

	// DefaultCPUs is the default number of CPU cores
	DefaultCPUs int `json:"default_cpus" yaml:"default_cpus"`

	// DefaultDiskSize is the default disk size
	DefaultDiskSize string `json:"default_disk_size" yaml:"default_disk_size"`

	// MaxInstances is the maximum number of instances allowed
	MaxInstances int `json:"max_instances" yaml:"max_instances"`

	// EnableKVM enables KVM acceleration by default (VMs only)
	EnableKVM bool `json:"enable_kvm" yaml:"enable_kvm"`

	// NetworkBridge is the default network bridge name
	NetworkBridge string `json:"network_bridge" yaml:"network_bridge"`

	// OVSSocketPath is the path to the OVSDB socket
	OVSSocketPath string `json:"ovs_socket_path" yaml:"ovs_socket_path"`

	// QEMUBinary is the path to the QEMU binary (VMs only)
	QEMUBinary string `json:"qemu_binary,omitempty" yaml:"qemu_binary,omitempty"`

	// OVMFCode is the path to OVMF firmware code
	OVMFCode string `json:"ovmf_code,omitempty" yaml:"ovmf_code,omitempty"`

	// OVMFCodeSecure is the path to OVMF firmware with Secure Boot
	OVMFCodeSecure string `json:"ovmf_code_secure,omitempty" yaml:"ovmf_code_secure,omitempty"`

	// OVMFVars is the path to OVMF NVRAM template
	OVMFVars string `json:"ovmf_vars,omitempty" yaml:"ovmf_vars,omitempty"`

	// AutoCleanup enables automatic cleanup of stopped instances
	AutoCleanup bool `json:"auto_cleanup" yaml:"auto_cleanup"`

	// Debug enables debug logging
	Debug bool `json:"debug" yaml:"debug"`

	// PolicyEngine enables 802.1X port authentication on network attachment
	// When nil, network ports are attached without authentication (default behavior)
	// When set, ports are placed in provisioning state until activated
	PolicyEngine policy.PolicyEngine `json:"-" yaml:"-"`

	// PortAuthEnabled enables port authentication on network attachment
	// This flag controls whether the PolicyEngine is used during AttachNetwork
	PortAuthEnabled bool `json:"port_auth_enabled" yaml:"port_auth_enabled"`
}

// DefaultOrchestratorConfig returns a configuration with sensible defaults
func DefaultOrchestratorConfig(computeType ComputeType) *OrchestratorConfig {
	config := &OrchestratorConfig{
		Type:            computeType,
		WorkDir:         "/var/lib/trusted-platform/compute",
		DefaultMemory:   4096,
		DefaultCPUs:     runtime.NumCPU(),
		DefaultDiskSize: "20G",
		MaxInstances:    100,
		EnableKVM:       true,
		NetworkBridge:   "trusted0",
		OVSSocketPath:   "/var/run/openvswitch/db.sock",
		AutoCleanup:     false,
		Debug:           false,
		PortAuthEnabled: false,
	}

	// VM-specific defaults
	if computeType == ComputeTypeVM {
		config.QEMUBinary = "qemu-system-x86_64"
		config.OVMFCode = "/usr/share/OVMF/OVMF_CODE_4M.fd"
		config.OVMFCodeSecure = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
		config.OVMFVars = "/usr/share/OVMF/OVMF_VARS_4M.fd"
	}

	return config
}

// Validate validates the orchestrator configuration
func (c *OrchestratorConfig) Validate() error {
	if !c.Type.IsValid() {
		return fmt.Errorf("%w: invalid compute type: %s", ErrInvalidConfiguration, c.Type)
	}

	if c.WorkDir == "" {
		return fmt.Errorf("%w: work directory is required", ErrInvalidConfiguration)
	}

	if c.DefaultMemory <= 0 {
		return fmt.Errorf("%w: default memory must be greater than 0", ErrInvalidConfiguration)
	}

	if c.DefaultCPUs <= 0 {
		return fmt.Errorf("%w: default CPUs must be greater than 0", ErrInvalidConfiguration)
	}

	if c.DefaultDiskSize == "" {
		return fmt.Errorf("%w: default disk size is required", ErrInvalidConfiguration)
	}

	if c.MaxInstances <= 0 {
		return fmt.Errorf("%w: max instances must be greater than 0", ErrInvalidConfiguration)
	}

	// Validate port authentication configuration
	if c.PortAuthEnabled && c.PolicyEngine == nil {
		return fmt.Errorf("%w: policy engine is required when port authentication is enabled", ErrInvalidConfiguration)
	}

	// VM-specific validation
	if c.Type == ComputeTypeVM {
		if c.QEMUBinary == "" {
			return fmt.Errorf("%w: QEMU binary path is required for VM orchestrator", ErrInvalidConfiguration)
		}
		if c.OVMFCode == "" {
			return fmt.Errorf("%w: OVMF code path is required for VM orchestrator", ErrInvalidConfiguration)
		}
		if c.OVMFVars == "" {
			return fmt.Errorf("%w: OVMF vars path is required for VM orchestrator", ErrInvalidConfiguration)
		}
	}

	return nil
}
