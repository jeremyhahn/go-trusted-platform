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

package podman

import (
	"time"
)

const (
	// DefaultTimeout is the default timeout for Podman operations
	DefaultTimeout = 30 * time.Second

	// DefaultStopTimeout is the default timeout for stopping containers
	DefaultStopTimeout = 10

	// DefaultNetworkMode is the default network mode for containers
	DefaultNetworkMode = "bridge"

	// TPMDevicePath is the path to the TPM device
	TPMDevicePath = "/dev/tpm0"

	// DefaultStorageRoot is the default root for container storage
	DefaultStorageRoot = "/var/lib/containers/storage"

	// DefaultRunRoot is the default runtime state directory
	DefaultRunRoot = "/run/containers/storage"

	// DefaultTmpDir is the default temporary directory for libpod
	DefaultTmpDir = "/run/libpod"

	// DefaultGraphDriver is the default storage driver
	DefaultGraphDriver = "overlay"

	// DefaultOCIRuntime is the default OCI runtime
	DefaultOCIRuntime = "crun"
)

// PodmanConfig holds configuration for the embedded Podman runtime.
// This is the top-level configuration for trusted computing container management.
type PodmanConfig struct {
	// Storage configuration
	StorageRoot string `json:"storage_root" yaml:"storage_root"`
	RunRoot     string `json:"run_root" yaml:"run_root"`
	TmpDir      string `json:"tmp_dir" yaml:"tmp_dir"`

	// Storage driver (overlay, vfs, btrfs, zfs, devmapper)
	GraphDriver string `json:"graph_driver" yaml:"graph_driver"`

	// OCI Runtime (crun, runc)
	OCIRuntime string `json:"oci_runtime" yaml:"oci_runtime"`

	// Cgroup manager (systemd, cgroupfs)
	CgroupManager string `json:"cgroup_manager" yaml:"cgroup_manager"`

	// Events logger (file, journald, none)
	EventsLogger string `json:"events_logger" yaml:"events_logger"`

	// Namespace for container isolation
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`

	// NetworkConfigDir is the directory for CNI network configs
	NetworkConfigDir string `json:"network_config_dir" yaml:"network_config_dir"`

	// Timeout is the default timeout for Podman operations
	Timeout time.Duration `json:"timeout" yaml:"timeout"`

	// StopTimeout is the default timeout in seconds for stopping containers
	StopTimeout int `json:"stop_timeout" yaml:"stop_timeout"`

	// Debug enables debug logging
	Debug bool `json:"debug" yaml:"debug"`

	// DefaultNetworkMode is the default network mode for containers
	DefaultNetworkMode string `json:"default_network_mode" yaml:"default_network_mode"`

	// DefaultImage is the default container image to use when not specified
	DefaultImage string `json:"default_image" yaml:"default_image"`

	// EnableTPMAccess allows containers to access the host TPM by default
	EnableTPMAccess bool `json:"enable_tpm_access" yaml:"enable_tpm_access"`

	// MaxContainers is the maximum number of containers allowed
	MaxContainers int `json:"max_containers" yaml:"max_containers"`

	// RegistryAuth holds registry authentication credentials
	RegistryAuth map[string]*RegistryCredentials `json:"registry_auth,omitempty" yaml:"registry_auth,omitempty"`

	// InsecureRegistries is a list of registries to allow insecure connections
	InsecureRegistries []string `json:"insecure_registries,omitempty" yaml:"insecure_registries,omitempty"`
}

// RegistryCredentials holds authentication credentials for a container registry
type RegistryCredentials struct {
	// Username is the registry username
	Username string `json:"username" yaml:"username"`

	// Password is the registry password
	Password string `json:"password" yaml:"password" secret:"true"`

	// IdentityToken is an identity token for registry auth
	IdentityToken string `json:"identity_token,omitempty" yaml:"identity_token,omitempty" secret:"true"`
}

// DefaultPodmanConfig returns a PodmanConfig with sensible defaults for embedded runtime
func DefaultPodmanConfig() *PodmanConfig {
	return &PodmanConfig{
		StorageRoot:        DefaultStorageRoot,
		RunRoot:            DefaultRunRoot,
		TmpDir:             DefaultTmpDir,
		GraphDriver:        DefaultGraphDriver,
		OCIRuntime:         DefaultOCIRuntime,
		CgroupManager:      "systemd",
		EventsLogger:       "file",
		NetworkConfigDir:   "/etc/cni/net.d",
		Timeout:            DefaultTimeout,
		StopTimeout:        DefaultStopTimeout,
		Debug:              false,
		DefaultNetworkMode: DefaultNetworkMode,
		EnableTPMAccess:    false,
		MaxContainers:      100,
	}
}

// Validate validates the Podman configuration
func (c *PodmanConfig) Validate() error {
	if c.StorageRoot == "" {
		return NewConfigValidationError("storage_root", "storage root is required")
	}

	if c.RunRoot == "" {
		return NewConfigValidationError("run_root", "run root is required")
	}

	if c.Timeout <= 0 {
		return NewConfigValidationError("timeout", "timeout must be positive")
	}

	if c.StopTimeout < 0 {
		return NewConfigValidationError("stop_timeout", "stop timeout cannot be negative")
	}

	if c.MaxContainers <= 0 {
		return NewConfigValidationError("max_containers", "max containers must be positive")
	}

	// Validate storage driver
	validDrivers := map[string]bool{
		"overlay":   true,
		"vfs":       true,
		"btrfs":     true,
		"zfs":       true,
		"devmapper": true,
	}

	if c.GraphDriver != "" && !validDrivers[c.GraphDriver] {
		return NewConfigValidationError("graph_driver", "invalid storage driver: "+c.GraphDriver)
	}

	// Validate OCI runtime
	validRuntimes := map[string]bool{
		"crun":  true,
		"runc":  true,
		"youki": true,
		"runsc": true, // gVisor
		"kata":  true, // Kata Containers
	}

	if c.OCIRuntime != "" && !validRuntimes[c.OCIRuntime] {
		return NewConfigValidationError("oci_runtime", "invalid OCI runtime: "+c.OCIRuntime)
	}

	// Validate cgroup manager
	validCgroupManagers := map[string]bool{
		"systemd":  true,
		"cgroupfs": true,
	}

	if c.CgroupManager != "" && !validCgroupManagers[c.CgroupManager] {
		return NewConfigValidationError("cgroup_manager", "invalid cgroup manager: "+c.CgroupManager)
	}

	return nil
}

// ToRuntimeConfig converts PodmanConfig to RuntimeConfig
func (c *PodmanConfig) ToRuntimeConfig() *RuntimeConfig {
	return &RuntimeConfig{
		Root:            c.StorageRoot,
		RunRoot:         c.RunRoot,
		TmpDir:          c.TmpDir,
		GraphDriverName: c.GraphDriver,
		StaticDir:       c.StorageRoot + "/libpod",
		VolumePath:      c.StorageRoot + "/volumes",
		OCIRuntime:      c.OCIRuntime,
		ImageStorePath:  c.StorageRoot + "/images",
		EnableTPMAccess: c.EnableTPMAccess,
	}
}

// ToManagerConfig converts PodmanConfig to ManagerConfig
func (c *PodmanConfig) ToManagerConfig() *ManagerConfig {
	return &ManagerConfig{
		Runtime:            c.ToRuntimeConfig(),
		MaxContainers:      c.MaxContainers,
		DefaultStopTimeout: c.StopTimeout,
		EnableTPMAccess:    c.EnableTPMAccess,
		Debug:              c.Debug,
	}
}

// WithStorageRoot sets the storage root
func (c *PodmanConfig) WithStorageRoot(root string) *PodmanConfig {
	c.StorageRoot = root
	return c
}

// WithRunRoot sets the run root
func (c *PodmanConfig) WithRunRoot(root string) *PodmanConfig {
	c.RunRoot = root
	return c
}

// WithGraphDriver sets the storage driver
func (c *PodmanConfig) WithGraphDriver(driver string) *PodmanConfig {
	c.GraphDriver = driver
	return c
}

// WithOCIRuntime sets the OCI runtime
func (c *PodmanConfig) WithOCIRuntime(runtime string) *PodmanConfig {
	c.OCIRuntime = runtime
	return c
}

// WithTimeout sets the timeout
func (c *PodmanConfig) WithTimeout(timeout time.Duration) *PodmanConfig {
	c.Timeout = timeout
	return c
}

// WithDebug enables or disables debug mode
func (c *PodmanConfig) WithDebug(debug bool) *PodmanConfig {
	c.Debug = debug
	return c
}

// WithTPMAccess enables or disables TPM access by default
func (c *PodmanConfig) WithTPMAccess(enable bool) *PodmanConfig {
	c.EnableTPMAccess = enable
	return c
}

// WithMaxContainers sets the maximum number of containers
func (c *PodmanConfig) WithMaxContainers(max int) *PodmanConfig {
	c.MaxContainers = max
	return c
}

// Clone creates a deep copy of the configuration
func (c *PodmanConfig) Clone() *PodmanConfig {
	clone := &PodmanConfig{
		StorageRoot:        c.StorageRoot,
		RunRoot:            c.RunRoot,
		TmpDir:             c.TmpDir,
		GraphDriver:        c.GraphDriver,
		OCIRuntime:         c.OCIRuntime,
		CgroupManager:      c.CgroupManager,
		EventsLogger:       c.EventsLogger,
		Namespace:          c.Namespace,
		NetworkConfigDir:   c.NetworkConfigDir,
		Timeout:            c.Timeout,
		StopTimeout:        c.StopTimeout,
		Debug:              c.Debug,
		DefaultNetworkMode: c.DefaultNetworkMode,
		DefaultImage:       c.DefaultImage,
		EnableTPMAccess:    c.EnableTPMAccess,
		MaxContainers:      c.MaxContainers,
	}

	if c.RegistryAuth != nil {
		clone.RegistryAuth = make(map[string]*RegistryCredentials, len(c.RegistryAuth))
		for k, v := range c.RegistryAuth {
			clone.RegistryAuth[k] = &RegistryCredentials{
				Username:      v.Username,
				Password:      v.Password,
				IdentityToken: v.IdentityToken,
			}
		}
	}

	if c.InsecureRegistries != nil {
		clone.InsecureRegistries = make([]string, len(c.InsecureRegistries))
		copy(clone.InsecureRegistries, c.InsecureRegistries)
	}

	return clone
}
