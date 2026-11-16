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
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultPodmanConfig(t *testing.T) {
	config := DefaultPodmanConfig()

	require.NotNil(t, config)
	assert.Equal(t, DefaultStorageRoot, config.StorageRoot)
	assert.Equal(t, DefaultRunRoot, config.RunRoot)
	assert.Equal(t, DefaultTmpDir, config.TmpDir)
	assert.Equal(t, DefaultGraphDriver, config.GraphDriver)
	assert.Equal(t, DefaultOCIRuntime, config.OCIRuntime)
	assert.Equal(t, "systemd", config.CgroupManager)
	assert.Equal(t, "file", config.EventsLogger)
	assert.Equal(t, DefaultTimeout, config.Timeout)
	assert.Equal(t, DefaultStopTimeout, config.StopTimeout)
	assert.False(t, config.Debug)
	assert.Equal(t, DefaultNetworkMode, config.DefaultNetworkMode)
	assert.False(t, config.EnableTPMAccess)
	assert.Equal(t, 100, config.MaxContainers)
}

func TestPodmanConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    *PodmanConfig
		expectErr bool
		errField  string
	}{
		{
			name:      "valid default config",
			config:    DefaultPodmanConfig(),
			expectErr: false,
		},
		{
			name: "missing storage root",
			config: &PodmanConfig{
				StorageRoot:   "",
				RunRoot:       DefaultRunRoot,
				Timeout:       DefaultTimeout,
				StopTimeout:   DefaultStopTimeout,
				MaxContainers: 100,
			},
			expectErr: true,
			errField:  "storage_root",
		},
		{
			name: "missing run root",
			config: &PodmanConfig{
				StorageRoot:   DefaultStorageRoot,
				RunRoot:       "",
				Timeout:       DefaultTimeout,
				StopTimeout:   DefaultStopTimeout,
				MaxContainers: 100,
			},
			expectErr: true,
			errField:  "run_root",
		},
		{
			name: "zero timeout",
			config: &PodmanConfig{
				StorageRoot:   DefaultStorageRoot,
				RunRoot:       DefaultRunRoot,
				Timeout:       0,
				StopTimeout:   DefaultStopTimeout,
				MaxContainers: 100,
			},
			expectErr: true,
			errField:  "timeout",
		},
		{
			name: "negative timeout",
			config: &PodmanConfig{
				StorageRoot:   DefaultStorageRoot,
				RunRoot:       DefaultRunRoot,
				Timeout:       -1 * time.Second,
				StopTimeout:   DefaultStopTimeout,
				MaxContainers: 100,
			},
			expectErr: true,
			errField:  "timeout",
		},
		{
			name: "negative stop timeout",
			config: &PodmanConfig{
				StorageRoot:   DefaultStorageRoot,
				RunRoot:       DefaultRunRoot,
				Timeout:       DefaultTimeout,
				StopTimeout:   -1,
				MaxContainers: 100,
			},
			expectErr: true,
			errField:  "stop_timeout",
		},
		{
			name: "zero max containers",
			config: &PodmanConfig{
				StorageRoot:   DefaultStorageRoot,
				RunRoot:       DefaultRunRoot,
				Timeout:       DefaultTimeout,
				StopTimeout:   DefaultStopTimeout,
				MaxContainers: 0,
			},
			expectErr: true,
			errField:  "max_containers",
		},
		{
			name: "negative max containers",
			config: &PodmanConfig{
				StorageRoot:   DefaultStorageRoot,
				RunRoot:       DefaultRunRoot,
				Timeout:       DefaultTimeout,
				StopTimeout:   DefaultStopTimeout,
				MaxContainers: -1,
			},
			expectErr: true,
			errField:  "max_containers",
		},
		{
			name: "invalid graph driver",
			config: &PodmanConfig{
				StorageRoot:   DefaultStorageRoot,
				RunRoot:       DefaultRunRoot,
				Timeout:       DefaultTimeout,
				StopTimeout:   DefaultStopTimeout,
				MaxContainers: 100,
				GraphDriver:   "invalid_driver",
			},
			expectErr: true,
			errField:  "graph_driver",
		},
		{
			name: "valid graph driver - overlay",
			config: &PodmanConfig{
				StorageRoot:   DefaultStorageRoot,
				RunRoot:       DefaultRunRoot,
				Timeout:       DefaultTimeout,
				StopTimeout:   DefaultStopTimeout,
				MaxContainers: 100,
				GraphDriver:   "overlay",
			},
			expectErr: false,
		},
		{
			name: "valid graph driver - vfs",
			config: &PodmanConfig{
				StorageRoot:   DefaultStorageRoot,
				RunRoot:       DefaultRunRoot,
				Timeout:       DefaultTimeout,
				StopTimeout:   DefaultStopTimeout,
				MaxContainers: 100,
				GraphDriver:   "vfs",
			},
			expectErr: false,
		},
		{
			name: "invalid OCI runtime",
			config: &PodmanConfig{
				StorageRoot:   DefaultStorageRoot,
				RunRoot:       DefaultRunRoot,
				Timeout:       DefaultTimeout,
				StopTimeout:   DefaultStopTimeout,
				MaxContainers: 100,
				OCIRuntime:    "invalid_runtime",
			},
			expectErr: true,
			errField:  "oci_runtime",
		},
		{
			name: "valid OCI runtime - crun",
			config: &PodmanConfig{
				StorageRoot:   DefaultStorageRoot,
				RunRoot:       DefaultRunRoot,
				Timeout:       DefaultTimeout,
				StopTimeout:   DefaultStopTimeout,
				MaxContainers: 100,
				OCIRuntime:    "crun",
			},
			expectErr: false,
		},
		{
			name: "valid OCI runtime - runc",
			config: &PodmanConfig{
				StorageRoot:   DefaultStorageRoot,
				RunRoot:       DefaultRunRoot,
				Timeout:       DefaultTimeout,
				StopTimeout:   DefaultStopTimeout,
				MaxContainers: 100,
				OCIRuntime:    "runc",
			},
			expectErr: false,
		},
		{
			name: "invalid cgroup manager",
			config: &PodmanConfig{
				StorageRoot:   DefaultStorageRoot,
				RunRoot:       DefaultRunRoot,
				Timeout:       DefaultTimeout,
				StopTimeout:   DefaultStopTimeout,
				MaxContainers: 100,
				CgroupManager: "invalid_cgroup",
			},
			expectErr: true,
			errField:  "cgroup_manager",
		},
		{
			name: "valid cgroup manager - systemd",
			config: &PodmanConfig{
				StorageRoot:   DefaultStorageRoot,
				RunRoot:       DefaultRunRoot,
				Timeout:       DefaultTimeout,
				StopTimeout:   DefaultStopTimeout,
				MaxContainers: 100,
				CgroupManager: "systemd",
			},
			expectErr: false,
		},
		{
			name: "valid cgroup manager - cgroupfs",
			config: &PodmanConfig{
				StorageRoot:   DefaultStorageRoot,
				RunRoot:       DefaultRunRoot,
				Timeout:       DefaultTimeout,
				StopTimeout:   DefaultStopTimeout,
				MaxContainers: 100,
				CgroupManager: "cgroupfs",
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectErr {
				require.Error(t, err)
				if tt.errField != "" {
					assert.Contains(t, err.Error(), tt.errField)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPodmanConfig_WithStorageRoot(t *testing.T) {
	config := DefaultPodmanConfig()
	customPath := "/custom/storage"

	result := config.WithStorageRoot(customPath)

	assert.Same(t, config, result) // Should return same instance for chaining
	assert.Equal(t, customPath, config.StorageRoot)
}

func TestPodmanConfig_WithRunRoot(t *testing.T) {
	config := DefaultPodmanConfig()
	customPath := "/custom/run"

	result := config.WithRunRoot(customPath)

	assert.Same(t, config, result)
	assert.Equal(t, customPath, config.RunRoot)
}

func TestPodmanConfig_WithGraphDriver(t *testing.T) {
	config := DefaultPodmanConfig()

	result := config.WithGraphDriver("vfs")

	assert.Same(t, config, result)
	assert.Equal(t, "vfs", config.GraphDriver)
}

func TestPodmanConfig_WithOCIRuntime(t *testing.T) {
	config := DefaultPodmanConfig()

	result := config.WithOCIRuntime("runc")

	assert.Same(t, config, result)
	assert.Equal(t, "runc", config.OCIRuntime)
}

func TestPodmanConfig_WithTimeout(t *testing.T) {
	config := DefaultPodmanConfig()
	customTimeout := 60 * time.Second

	result := config.WithTimeout(customTimeout)

	assert.Same(t, config, result)
	assert.Equal(t, customTimeout, config.Timeout)
}

func TestPodmanConfig_WithDebug(t *testing.T) {
	config := DefaultPodmanConfig()

	result := config.WithDebug(true)

	assert.Same(t, config, result)
	assert.True(t, config.Debug)

	config.WithDebug(false)
	assert.False(t, config.Debug)
}

func TestPodmanConfig_WithTPMAccess(t *testing.T) {
	config := DefaultPodmanConfig()

	result := config.WithTPMAccess(true)

	assert.Same(t, config, result)
	assert.True(t, config.EnableTPMAccess)

	config.WithTPMAccess(false)
	assert.False(t, config.EnableTPMAccess)
}

func TestPodmanConfig_WithMaxContainers(t *testing.T) {
	config := DefaultPodmanConfig()
	max := 500

	result := config.WithMaxContainers(max)

	assert.Same(t, config, result)
	assert.Equal(t, max, config.MaxContainers)
}

func TestPodmanConfig_Clone(t *testing.T) {
	original := DefaultPodmanConfig()
	original.Debug = true
	original.EnableTPMAccess = true
	original.RegistryAuth = map[string]*RegistryCredentials{
		"docker.io": {
			Username: "user",
			Password: "pass",
		},
	}
	original.InsecureRegistries = []string{"localhost:5000"}

	clone := original.Clone()

	// Verify clone is independent
	require.NotNil(t, clone)
	assert.NotSame(t, original, clone)

	// Verify values are copied
	assert.Equal(t, original.StorageRoot, clone.StorageRoot)
	assert.Equal(t, original.RunRoot, clone.RunRoot)
	assert.Equal(t, original.TmpDir, clone.TmpDir)
	assert.Equal(t, original.GraphDriver, clone.GraphDriver)
	assert.Equal(t, original.OCIRuntime, clone.OCIRuntime)
	assert.Equal(t, original.Timeout, clone.Timeout)
	assert.Equal(t, original.Debug, clone.Debug)
	assert.Equal(t, original.EnableTPMAccess, clone.EnableTPMAccess)
	assert.Equal(t, original.MaxContainers, clone.MaxContainers)

	// Verify registry auth is deep copied
	assert.Len(t, clone.RegistryAuth, 1)
	assert.NotSame(t, original.RegistryAuth["docker.io"], clone.RegistryAuth["docker.io"])
	assert.Equal(t, original.RegistryAuth["docker.io"].Username, clone.RegistryAuth["docker.io"].Username)

	// Verify insecure registries is deep copied
	assert.Len(t, clone.InsecureRegistries, 1)
	assert.Equal(t, original.InsecureRegistries[0], clone.InsecureRegistries[0])

	// Modify clone and verify original is unchanged
	clone.Debug = false
	clone.StorageRoot = "/modified/path"
	assert.True(t, original.Debug)
	assert.NotEqual(t, "/modified/path", original.StorageRoot)
}

func TestPodmanConfig_Clone_NilMaps(t *testing.T) {
	original := DefaultPodmanConfig()
	// Ensure maps are nil
	original.RegistryAuth = nil
	original.InsecureRegistries = nil

	clone := original.Clone()

	assert.Nil(t, clone.RegistryAuth)
	assert.Nil(t, clone.InsecureRegistries)
}

func TestPodmanConfig_MethodChaining(t *testing.T) {
	config := DefaultPodmanConfig().
		WithStorageRoot("/custom/storage").
		WithRunRoot("/custom/run").
		WithGraphDriver("vfs").
		WithOCIRuntime("runc").
		WithTimeout(60 * time.Second).
		WithDebug(true).
		WithTPMAccess(true).
		WithMaxContainers(200)

	assert.Equal(t, "/custom/storage", config.StorageRoot)
	assert.Equal(t, "/custom/run", config.RunRoot)
	assert.Equal(t, "vfs", config.GraphDriver)
	assert.Equal(t, "runc", config.OCIRuntime)
	assert.Equal(t, 60*time.Second, config.Timeout)
	assert.True(t, config.Debug)
	assert.True(t, config.EnableTPMAccess)
	assert.Equal(t, 200, config.MaxContainers)

	// Validate the chained config
	err := config.Validate()
	assert.NoError(t, err)
}

func TestPodmanConfig_Constants(t *testing.T) {
	// Verify constants are properly defined
	assert.Equal(t, 30*time.Second, DefaultTimeout)
	assert.Equal(t, 10, DefaultStopTimeout)
	assert.Equal(t, "bridge", DefaultNetworkMode)
	assert.Equal(t, "/dev/tpm0", TPMDevicePath)
	assert.Equal(t, "/var/lib/containers/storage", DefaultStorageRoot)
	assert.Equal(t, "/run/containers/storage", DefaultRunRoot)
	assert.Equal(t, "/run/libpod", DefaultTmpDir)
	assert.Equal(t, "overlay", DefaultGraphDriver)
	assert.Equal(t, "crun", DefaultOCIRuntime)
}

func TestPodmanConfig_ZeroStopTimeout(t *testing.T) {
	config := &PodmanConfig{
		StorageRoot:   DefaultStorageRoot,
		RunRoot:       DefaultRunRoot,
		Timeout:       DefaultTimeout,
		StopTimeout:   0, // Zero is valid (immediate stop)
		MaxContainers: 100,
	}

	err := config.Validate()
	assert.NoError(t, err)
}

func TestPodmanConfig_ToRuntimeConfig(t *testing.T) {
	config := DefaultPodmanConfig()
	config.EnableTPMAccess = true

	runtimeConfig := config.ToRuntimeConfig()

	assert.Equal(t, config.StorageRoot, runtimeConfig.Root)
	assert.Equal(t, config.RunRoot, runtimeConfig.RunRoot)
	assert.Equal(t, config.TmpDir, runtimeConfig.TmpDir)
	assert.Equal(t, config.GraphDriver, runtimeConfig.GraphDriverName)
	assert.Equal(t, config.StorageRoot+"/libpod", runtimeConfig.StaticDir)
	assert.Equal(t, config.StorageRoot+"/volumes", runtimeConfig.VolumePath)
	assert.Equal(t, config.OCIRuntime, runtimeConfig.OCIRuntime)
	assert.Equal(t, config.StorageRoot+"/images", runtimeConfig.ImageStorePath)

	// The host TPM default is a default for the container SPECIFICATION, where
	// it is measured. It must not travel to the runtime, which would apply it to
	// every container behind the measurement.
	assert.NotContains(t, runtimeConfigFields(), "EnableTPMAccess",
		"RuntimeConfig must carry no TPM default: the grant belongs to the "+
			"container configuration that is measured")
}

// runtimeConfigFields lists the field names of RuntimeConfig.
func runtimeConfigFields() []string {
	t := reflect.TypeOf(RuntimeConfig{})
	names := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		names = append(names, t.Field(i).Name)
	}
	return names
}

// managerConfigFields lists the field names of ManagerConfig.
func managerConfigFields() []string {
	t := reflect.TypeOf(ManagerConfig{})
	names := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		names = append(names, t.Field(i).Name)
	}
	return names
}

func TestPodmanConfig_ToManagerConfig(t *testing.T) {
	config := DefaultPodmanConfig()
	config.MaxContainers = 50
	config.StopTimeout = 30
	config.EnableTPMAccess = true
	config.Debug = true

	managerConfig := config.ToManagerConfig()

	assert.NotNil(t, managerConfig.Runtime)
	assert.Equal(t, config.MaxContainers, managerConfig.MaxContainers)
	assert.Equal(t, config.StopTimeout, managerConfig.DefaultStopTimeout)
	assert.Equal(t, config.Debug, managerConfig.Debug)
	assert.NotContains(t, managerConfigFields(), "EnableTPMAccess",
		"ManagerConfig must carry no TPM default: NewPodmanManager used to copy "+
			"it onto the runtime, granting the device outside any container "+
			"configuration")
}

func TestPodmanConfig_WithInsecureRegistries(t *testing.T) {
	config := DefaultPodmanConfig()
	config.InsecureRegistries = []string{"localhost:5000", "registry.internal:5000"}

	err := config.Validate()
	assert.NoError(t, err)
	assert.Len(t, config.InsecureRegistries, 2)
}

func TestPodmanConfig_WithRegistryAuth(t *testing.T) {
	config := DefaultPodmanConfig()
	config.RegistryAuth = map[string]*RegistryCredentials{
		"ghcr.io": {
			Username: "github_user",
			Password: "github_token",
		},
		"gcr.io": {
			Username: "_json_key",
			Password: "service_account_json",
		},
	}

	err := config.Validate()
	assert.NoError(t, err)
	assert.Len(t, config.RegistryAuth, 2)
}
