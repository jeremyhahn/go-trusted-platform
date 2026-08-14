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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultRuntimeConfig(t *testing.T) {
	config := DefaultRuntimeConfig()

	require.NotNil(t, config)
	assert.NotEmpty(t, config.Root)
	assert.NotEmpty(t, config.RunRoot)
	assert.NotEmpty(t, config.TmpDir)
	assert.NotEmpty(t, config.GraphDriverName)
	assert.NotEmpty(t, config.StaticDir)
	assert.NotEmpty(t, config.VolumePath)
	assert.NotEmpty(t, config.OCIRuntime)
	assert.NotEmpty(t, config.ImageStorePath)
}

func TestRuntimeConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    *RuntimeConfig
		expectErr bool
		errField  string
	}{
		{
			name:      "valid config",
			config:    DefaultRuntimeConfig(),
			expectErr: false,
		},
		{
			name: "missing root",
			config: &RuntimeConfig{
				Root:            "",
				RunRoot:         DefaultRunRoot,
				TmpDir:          DefaultTmpDir,
				StaticDir:       "/var/lib/containers/storage/libpod",
				VolumePath:      "/var/lib/containers/storage/volumes",
				OCIRuntime:      DefaultOCIRuntime,
				ImageStorePath:  "/var/lib/containers/storage/images",
				GraphDriverName: DefaultGraphDriver,
			},
			expectErr: true,
			errField:  "root",
		},
		{
			name: "missing run_root",
			config: &RuntimeConfig{
				Root:            DefaultStorageRoot,
				RunRoot:         "",
				TmpDir:          DefaultTmpDir,
				StaticDir:       "/var/lib/containers/storage/libpod",
				VolumePath:      "/var/lib/containers/storage/volumes",
				OCIRuntime:      DefaultOCIRuntime,
				ImageStorePath:  "/var/lib/containers/storage/images",
				GraphDriverName: DefaultGraphDriver,
			},
			expectErr: true,
			errField:  "run_root",
		},
		{
			name: "invalid graph driver",
			config: &RuntimeConfig{
				Root:            DefaultStorageRoot,
				RunRoot:         DefaultRunRoot,
				TmpDir:          DefaultTmpDir,
				StaticDir:       "/var/lib/containers/storage/libpod",
				VolumePath:      "/var/lib/containers/storage/volumes",
				OCIRuntime:      DefaultOCIRuntime,
				ImageStorePath:  "/var/lib/containers/storage/images",
				GraphDriverName: "invalid_driver",
			},
			expectErr: true,
			errField:  "graph_driver",
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

func TestRuntimeError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *RuntimeError
		expected string
	}{
		{
			name: "with wrapped error",
			err: &RuntimeError{
				Operation: "start",
				Err:       ErrContainerNotFound,
			},
			expected: "runtime start: container not found",
		},
		{
			name: "without wrapped error",
			err: &RuntimeError{
				Operation: "initialize",
			},
			expected: "runtime initialize",
		},
		{
			name: "with custom error",
			err: &RuntimeError{
				Operation: "stop",
				Err:       errors.New("custom error"),
			},
			expected: "runtime stop: custom error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestRuntimeError_Unwrap(t *testing.T) {
	wrapped := ErrContainerNotFound
	err := &RuntimeError{
		Operation: "start",
		Err:       wrapped,
	}

	assert.Equal(t, wrapped, err.Unwrap())
	assert.ErrorIs(t, err, wrapped)
}

func TestParseUserSpec(t *testing.T) {
	tests := []struct {
		name        string
		spec        string
		expectedUID uint32
		expectedGID uint32
	}{
		{
			name:        "empty spec",
			spec:        "",
			expectedUID: 0,
			expectedGID: 0,
		},
		{
			name:        "uid only",
			spec:        "1000",
			expectedUID: 1000,
			expectedGID: 0,
		},
		{
			name:        "uid:gid",
			spec:        "1000:1000",
			expectedUID: 1000,
			expectedGID: 1000,
		},
		{
			name:        "different uid and gid",
			spec:        "1000:2000",
			expectedUID: 1000,
			expectedGID: 2000,
		},
		{
			name:        "root user",
			spec:        "0:0",
			expectedUID: 0,
			expectedGID: 0,
		},
		{
			name:        "invalid uid (uses 0)",
			spec:        "notanumber",
			expectedUID: 0,
			expectedGID: 0,
		},
		{
			name:        "invalid gid (uses 0)",
			spec:        "1000:notanumber",
			expectedUID: 1000,
			expectedGID: 0,
		},
		{
			name:        "name spec (returns 0)",
			spec:        "nobody:nogroup",
			expectedUID: 0,
			expectedGID: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uid, gid := parseUserSpec(tt.spec)
			assert.Equal(t, tt.expectedUID, uid)
			assert.Equal(t, tt.expectedGID, gid)
		})
	}
}

func TestSanitizeImageName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple image name",
			input:    "alpine",
			expected: "alpine",
		},
		{
			name:     "image with tag",
			input:    "alpine:latest",
			expected: "alpine_latest",
		},
		{
			name:     "image with registry",
			input:    "docker.io/library/alpine:3.18",
			expected: "docker.io_library_alpine_3.18",
		},
		{
			name:     "image with digest",
			input:    "alpine@sha256:abc123",
			expected: "alpine_sha256_abc123",
		},
		{
			name:     "complex image reference",
			input:    "gcr.io/my-project/my-image:v1.0.0",
			expected: "gcr.io_my-project_my-image_v1.0.0",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeImageName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRemoveString(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		remove   string
		expected []string
	}{
		{
			name:     "remove existing element",
			slice:    []string{"a", "b", "c"},
			remove:   "b",
			expected: []string{"a", "c"},
		},
		{
			name:     "remove first element",
			slice:    []string{"a", "b", "c"},
			remove:   "a",
			expected: []string{"b", "c"},
		},
		{
			name:     "remove last element",
			slice:    []string{"a", "b", "c"},
			remove:   "c",
			expected: []string{"a", "b"},
		},
		{
			name:     "element not in slice",
			slice:    []string{"a", "b", "c"},
			remove:   "d",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "empty slice",
			slice:    []string{},
			remove:   "a",
			expected: []string{},
		},
		{
			name:     "single element slice",
			slice:    []string{"a"},
			remove:   "a",
			expected: []string{},
		},
		{
			name:     "duplicate elements - removes all",
			slice:    []string{"a", "b", "a", "c"},
			remove:   "a",
			expected: []string{"b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := removeString(tt.slice, tt.remove)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestContainerState_Fields(t *testing.T) {
	state := &containerState{
		ID:       "abc123",
		Name:     "test-container",
		Image:    "alpine:latest",
		State:    ContainerStateRunning,
		PID:      12345,
		ExitCode: 0,
	}

	assert.Equal(t, "abc123", state.ID)
	assert.Equal(t, "test-container", state.Name)
	assert.Equal(t, "alpine:latest", state.Image)
	assert.Equal(t, ContainerStateRunning, state.State)
	assert.Equal(t, 12345, state.PID)
	assert.Equal(t, 0, state.ExitCode)
}

func TestOCIConfigStructs(t *testing.T) {
	// Test OCI config structure serialization/fields
	cfg := &ociConfig{
		OCIVersion: "1.0.0",
		Root: &ociRoot{
			Path:     "/rootfs",
			Readonly: true,
		},
		Process: &ociProcess{
			Terminal: false,
			User: ociUser{
				UID: 1000,
				GID: 1000,
			},
			Args: []string{"sleep", "infinity"},
			Env:  []string{"PATH=/usr/bin"},
			Cwd:  "/app",
		},
		Hostname: "testhost",
		Mounts: []ociMount{
			{
				Destination: "/proc",
				Type:        "proc",
				Source:      "proc",
			},
		},
	}

	assert.Equal(t, "1.0.0", cfg.OCIVersion)
	require.NotNil(t, cfg.Root)
	assert.Equal(t, "/rootfs", cfg.Root.Path)
	assert.True(t, cfg.Root.Readonly)
	require.NotNil(t, cfg.Process)
	assert.False(t, cfg.Process.Terminal)
	assert.Equal(t, uint32(1000), cfg.Process.User.UID)
	assert.Equal(t, []string{"sleep", "infinity"}, cfg.Process.Args)
	assert.Equal(t, "testhost", cfg.Hostname)
	assert.Len(t, cfg.Mounts, 1)
}

func TestOCIResources(t *testing.T) {
	memLimit := int64(1073741824) // 1GB
	cpuShares := uint64(1024)
	cpuQuota := int64(100000)
	cpuPeriod := uint64(100000)

	resources := &ociResources{
		Memory: &ociMemory{
			Limit: &memLimit,
		},
		CPU: &ociCPU{
			Shares: &cpuShares,
			Quota:  &cpuQuota,
			Period: &cpuPeriod,
		},
		Pids: &ociPids{
			Limit: 100,
		},
	}

	require.NotNil(t, resources.Memory)
	require.NotNil(t, resources.Memory.Limit)
	assert.Equal(t, int64(1073741824), *resources.Memory.Limit)

	require.NotNil(t, resources.CPU)
	require.NotNil(t, resources.CPU.Shares)
	assert.Equal(t, uint64(1024), *resources.CPU.Shares)
	require.NotNil(t, resources.CPU.Quota)
	assert.Equal(t, int64(100000), *resources.CPU.Quota)
	require.NotNil(t, resources.CPU.Period)
	assert.Equal(t, uint64(100000), *resources.CPU.Period)

	require.NotNil(t, resources.Pids)
	assert.Equal(t, int64(100), resources.Pids.Limit)
}

func TestOCICapabilities(t *testing.T) {
	caps := &ociCapabilities{
		Bounding:    []string{"CAP_NET_BIND_SERVICE"},
		Effective:   []string{"CAP_NET_BIND_SERVICE"},
		Inheritable: []string{},
		Permitted:   []string{"CAP_NET_BIND_SERVICE"},
		Ambient:     []string{},
	}

	assert.Contains(t, caps.Bounding, "CAP_NET_BIND_SERVICE")
	assert.Contains(t, caps.Effective, "CAP_NET_BIND_SERVICE")
	assert.Empty(t, caps.Inheritable)
	assert.Contains(t, caps.Permitted, "CAP_NET_BIND_SERVICE")
	assert.Empty(t, caps.Ambient)
}

func TestOCINamespace(t *testing.T) {
	namespaces := []ociNamespace{
		{Type: "pid"},
		{Type: "network"},
		{Type: "ipc"},
		{Type: "uts"},
		{Type: "mount"},
	}

	assert.Len(t, namespaces, 5)
	types := make([]string, len(namespaces))
	for i, ns := range namespaces {
		types[i] = ns.Type
	}
	assert.Contains(t, types, "pid")
	assert.Contains(t, types, "network")
	assert.Contains(t, types, "ipc")
	assert.Contains(t, types, "uts")
	assert.Contains(t, types, "mount")
}

func TestOCILinuxDevice(t *testing.T) {
	device := &ociLinuxDevice{
		Path:  "/dev/tpm0",
		Type:  "c",
		Major: 10,
		Minor: 224,
	}

	assert.Equal(t, "/dev/tpm0", device.Path)
	assert.Equal(t, "c", device.Type)
	assert.Equal(t, int64(10), device.Major)
	assert.Equal(t, int64(224), device.Minor)
}

func TestRuntimeConfig_Fields(t *testing.T) {
	config := &RuntimeConfig{
		Root:            "/var/lib/containers/storage",
		RunRoot:         "/run/containers/storage",
		TmpDir:          "/run/libpod",
		GraphDriverName: "overlay",
		StaticDir:       "/var/lib/containers/storage/libpod",
		VolumePath:      "/var/lib/containers/storage/volumes",
		OCIRuntime:      "crun",
		ImageStorePath:  "/var/lib/containers/storage/images",
	}

	assert.Equal(t, "/var/lib/containers/storage", config.Root)
	assert.Equal(t, "/run/containers/storage", config.RunRoot)
	assert.Equal(t, "/run/libpod", config.TmpDir)
	assert.Equal(t, "overlay", config.GraphDriverName)
	assert.Equal(t, "/var/lib/containers/storage/libpod", config.StaticDir)
	assert.Equal(t, "/var/lib/containers/storage/volumes", config.VolumePath)
	assert.Equal(t, "crun", config.OCIRuntime)
	assert.Equal(t, "/var/lib/containers/storage/images", config.ImageStorePath)
}

func TestOCIMount_Fields(t *testing.T) {
	mount := ociMount{
		Destination: "/data",
		Type:        "bind",
		Source:      "/host/data",
		Options:     []string{"rbind", "rw"},
	}

	assert.Equal(t, "/data", mount.Destination)
	assert.Equal(t, "bind", mount.Type)
	assert.Equal(t, "/host/data", mount.Source)
	assert.Contains(t, mount.Options, "rbind")
	assert.Contains(t, mount.Options, "rw")
}

func TestOCILinux_Fields(t *testing.T) {
	linux := &ociLinux{
		Namespaces: []ociNamespace{
			{Type: "pid"},
			{Type: "mount"},
		},
		CgroupsPath:   "/containers/test",
		MaskedPaths:   []string{"/proc/kcore"},
		ReadonlyPaths: []string{"/proc/bus"},
	}

	assert.Len(t, linux.Namespaces, 2)
	assert.Equal(t, "/containers/test", linux.CgroupsPath)
	assert.Contains(t, linux.MaskedPaths, "/proc/kcore")
	assert.Contains(t, linux.ReadonlyPaths, "/proc/bus")
}

func TestOCIRlimit_Fields(t *testing.T) {
	rlimit := ociRlimit{
		Type: "RLIMIT_NOFILE",
		Hard: 1048576,
		Soft: 1048576,
	}

	assert.Equal(t, "RLIMIT_NOFILE", rlimit.Type)
	assert.Equal(t, uint64(1048576), rlimit.Hard)
	assert.Equal(t, uint64(1048576), rlimit.Soft)
}
