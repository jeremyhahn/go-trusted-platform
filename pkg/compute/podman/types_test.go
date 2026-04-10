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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerState_String(t *testing.T) {
	tests := []struct {
		state    ContainerState
		expected string
	}{
		{ContainerStateCreated, "created"},
		{ContainerStateRunning, "running"},
		{ContainerStatePaused, "paused"},
		{ContainerStateStopped, "stopped"},
		{ContainerStateExited, "exited"},
		{ContainerStateUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.String())
		})
	}
}

func TestContainerState_IsValid(t *testing.T) {
	validStates := []ContainerState{
		ContainerStateCreated,
		ContainerStateRunning,
		ContainerStatePaused,
		ContainerStateStopped,
		ContainerStateExited,
		ContainerStateUnknown,
	}

	for _, state := range validStates {
		t.Run(state.String(), func(t *testing.T) {
			assert.True(t, state.IsValid())
		})
	}

	// Test invalid state
	invalidState := ContainerState("invalid")
	assert.False(t, invalidState.IsValid())
}

func TestContainerState_IsRunning(t *testing.T) {
	assert.True(t, ContainerStateRunning.IsRunning())
	assert.False(t, ContainerStateCreated.IsRunning())
	assert.False(t, ContainerStateStopped.IsRunning())
	assert.False(t, ContainerStateExited.IsRunning())
	assert.False(t, ContainerStatePaused.IsRunning())
}

func TestContainerConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    *ContainerConfig
		expectErr bool
		errField  string
	}{
		{
			name: "valid config",
			config: &ContainerConfig{
				Name:  "test-container",
				Image: "alpine:latest",
			},
			expectErr: false,
		},
		{
			name: "missing name",
			config: &ContainerConfig{
				Image: "alpine:latest",
			},
			expectErr: true,
			errField:  "name",
		},
		{
			name: "missing image",
			config: &ContainerConfig{
				Name: "test-container",
			},
			expectErr: true,
			errField:  "image",
		},
		{
			name: "valid config with mounts",
			config: &ContainerConfig{
				Name:  "test-container",
				Image: "alpine:latest",
				Mounts: []Mount{
					{Source: "/host/path", Target: "/container/path", Type: "bind"},
				},
			},
			expectErr: false,
		},
		{
			name: "valid config with ports",
			config: &ContainerConfig{
				Name:  "test-container",
				Image: "alpine:latest",
				Ports: []PortMapping{
					{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
				},
			},
			expectErr: false,
		},
		{
			name: "valid config with resources",
			config: &ContainerConfig{
				Name:  "test-container",
				Image: "alpine:latest",
				Resources: &ResourceLimits{
					MemoryLimit: 1024 * 1024 * 512, // 512MB
					CPUQuota:    100000,
				},
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

func TestMount_Validate(t *testing.T) {
	tests := []struct {
		name      string
		mount     *Mount
		expectErr bool
	}{
		{
			name:      "valid bind mount",
			mount:     &Mount{Source: "/host", Target: "/container", Type: "bind"},
			expectErr: false,
		},
		{
			name:      "valid volume mount",
			mount:     &Mount{Source: "myvolume", Target: "/data", Type: "volume"},
			expectErr: false,
		},
		{
			name:      "valid tmpfs mount",
			mount:     &Mount{Target: "/tmp", Type: "tmpfs"},
			expectErr: false,
		},
		{
			name:      "missing target",
			mount:     &Mount{Source: "/host", Type: "bind"},
			expectErr: true,
		},
		{
			name:      "invalid type",
			mount:     &Mount{Source: "/host", Target: "/container", Type: "invalid"},
			expectErr: true,
		},
		{
			name:      "bind mount without source",
			mount:     &Mount{Target: "/container", Type: "bind"},
			expectErr: true,
		},
		{
			name:      "default type is bind",
			mount:     &Mount{Source: "/host", Target: "/container"},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.mount.Validate()
			if tt.expectErr {
				require.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPortMapping_Validate(t *testing.T) {
	tests := []struct {
		name      string
		port      *PortMapping
		expectErr bool
	}{
		{
			name:      "valid tcp port",
			port:      &PortMapping{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
			expectErr: false,
		},
		{
			name:      "valid udp port",
			port:      &PortMapping{HostPort: 53, ContainerPort: 53, Protocol: "udp"},
			expectErr: false,
		},
		{
			name:      "default protocol is tcp",
			port:      &PortMapping{HostPort: 8080, ContainerPort: 80},
			expectErr: false,
		},
		{
			name:      "missing container port",
			port:      &PortMapping{HostPort: 8080, Protocol: "tcp"},
			expectErr: true,
		},
		{
			name:      "invalid protocol",
			port:      &PortMapping{HostPort: 8080, ContainerPort: 80, Protocol: "invalid"},
			expectErr: true,
		},
		{
			name:      "with host IP",
			port:      &PortMapping{HostIP: "127.0.0.1", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.port.Validate()
			if tt.expectErr {
				require.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestResourceLimits_Validate(t *testing.T) {
	tests := []struct {
		name      string
		limits    *ResourceLimits
		expectErr bool
	}{
		{
			name:      "valid limits",
			limits:    &ResourceLimits{MemoryLimit: 1024 * 1024 * 512, CPUQuota: 100000, CPUPeriod: 100000},
			expectErr: false,
		},
		{
			name:      "zero values",
			limits:    &ResourceLimits{},
			expectErr: false,
		},
		{
			name:      "negative memory",
			limits:    &ResourceLimits{MemoryLimit: -1},
			expectErr: true,
		},
		{
			name:      "negative cpu quota",
			limits:    &ResourceLimits{CPUQuota: -1},
			expectErr: true,
		},
		{
			name:      "negative cpu period",
			limits:    &ResourceLimits{CPUPeriod: -1},
			expectErr: true,
		},
		{
			name:      "negative cpus",
			limits:    &ResourceLimits{CPUs: -1},
			expectErr: true,
		},
		{
			name:      "negative pids limit",
			limits:    &ResourceLimits{PidsLimit: -1},
			expectErr: true,
		},
		{
			name:      "valid with all fields",
			limits:    &ResourceLimits{MemoryLimit: 1024 * 1024 * 1024, MemoryReservation: 512 * 1024 * 1024, CPUQuota: 150000, CPUPeriod: 100000, CPUShares: 1024, CPUs: 2.0, PidsLimit: 1000},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.limits.Validate()
			if tt.expectErr {
				require.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestContainer_Fields(t *testing.T) {
	now := time.Now()
	startedAt := now.Add(-1 * time.Hour)
	finishedAt := now

	container := &Container{
		ID:          "abc123",
		Name:        "test-container",
		Image:       "alpine:latest",
		ImageDigest: "sha256:abc123",
		State:       ContainerStateRunning,
		CreatedAt:   now.Add(-2 * time.Hour),
		StartedAt:   &startedAt,
		FinishedAt:  &finishedAt,
		ExitCode:    0,
		Labels:      map[string]string{"app": "test"},
		Mounts: []Mount{
			{Source: "/host", Target: "/container", Type: "bind"},
		},
		Ports: []PortMapping{
			{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
		},
		Environment: map[string]string{"ENV_VAR": "value"},
		PID:         12345,
		Command:     []string{"sleep", "infinity"},
		NetworkMode: "bridge",
	}

	assert.Equal(t, "abc123", container.ID)
	assert.Equal(t, "test-container", container.Name)
	assert.Equal(t, "alpine:latest", container.Image)
	assert.Equal(t, ContainerStateRunning, container.State)
	assert.Equal(t, 12345, container.PID)
	assert.Len(t, container.Labels, 1)
	assert.Len(t, container.Mounts, 1)
	assert.Len(t, container.Ports, 1)
	assert.Len(t, container.Environment, 1)
	assert.Len(t, container.Command, 2)
}

func TestContainerConfig_Fields(t *testing.T) {
	timeout := 30
	config := &ContainerConfig{
		Name:        "test-container",
		Image:       "nginx:latest",
		Command:     []string{"nginx", "-g", "daemon off;"},
		Entrypoint:  []string{"/docker-entrypoint.sh"},
		Environment: map[string]string{"NGINX_PORT": "80"},
		Labels:      map[string]string{"tier": "frontend"},
		Mounts: []Mount{
			{Source: "/etc/nginx", Target: "/etc/nginx", Type: "bind", ReadOnly: true},
		},
		Ports: []PortMapping{
			{HostPort: 80, ContainerPort: 80, Protocol: "tcp"},
		},
		Resources: &ResourceLimits{
			MemoryLimit: 256 * 1024 * 1024,
			CPUs:        1.0,
		},
		TPMAccess:   false,
		NetworkMode: "bridge",
		User:        "nginx",
		WorkDir:     "/usr/share/nginx/html",
		Hostname:    "webserver",
		Privileged:  false,
		ReadOnly:    true,
		AutoRemove:  false,
		StopTimeout: &timeout,
		CapAdd:      []string{"NET_ADMIN"},
		CapDrop:     []string{"MKNOD"},
		SecurityOpt: []string{"no-new-privileges"},
		DNS:         []string{"8.8.8.8"},
		DNSSearch:   []string{"example.com"},
	}

	err := config.Validate()
	require.NoError(t, err)

	assert.Equal(t, "test-container", config.Name)
	assert.Equal(t, "nginx:latest", config.Image)
	assert.Len(t, config.Command, 3)
	assert.Len(t, config.Entrypoint, 1)
	assert.Equal(t, "80", config.Environment["NGINX_PORT"])
	assert.Equal(t, "frontend", config.Labels["tier"])
	assert.True(t, config.Mounts[0].ReadOnly)
	assert.NotNil(t, config.Resources)
	assert.False(t, config.Privileged)
	assert.True(t, config.ReadOnly)
	assert.Equal(t, 30, *config.StopTimeout)
}

func TestImage_Fields(t *testing.T) {
	created := time.Now().Add(-24 * time.Hour)
	image := &Image{
		ID:           "sha256:abc123",
		Names:        []string{"alpine:latest", "alpine:3.18"},
		Digest:       "sha256:def456",
		Size:         5 * 1024 * 1024,
		Created:      created,
		Labels:       map[string]string{"maintainer": "test@example.com"},
		Architecture: "amd64",
		OS:           "linux",
	}

	assert.Equal(t, "sha256:abc123", image.ID)
	assert.Len(t, image.Names, 2)
	assert.Equal(t, "sha256:def456", image.Digest)
	assert.Equal(t, int64(5*1024*1024), image.Size)
	assert.Equal(t, "amd64", image.Architecture)
	assert.Equal(t, "linux", image.OS)
}

func TestContainerStats_Fields(t *testing.T) {
	stats := &ContainerStats{
		ContainerID:    "abc123",
		Name:           "test-container",
		CPUPercent:     25.5,
		MemoryUsage:    128 * 1024 * 1024,
		MemoryLimit:    256 * 1024 * 1024,
		MemoryPercent:  50.0,
		NetworkRxBytes: 1024 * 1024,
		NetworkTxBytes: 512 * 1024,
		BlockRead:      2048,
		BlockWrite:     1024,
		PIDs:           5,
		Timestamp:      time.Now(),
	}

	assert.Equal(t, "abc123", stats.ContainerID)
	assert.Equal(t, 25.5, stats.CPUPercent)
	assert.Equal(t, 50.0, stats.MemoryPercent)
	assert.Equal(t, int64(5), stats.PIDs)
}

func TestExecConfig_Fields(t *testing.T) {
	config := &ExecConfig{
		Command:      []string{"ls", "-la"},
		User:         "root",
		WorkDir:      "/app",
		Environment:  map[string]string{"DEBUG": "true"},
		Privileged:   true,
		AttachStdout: true,
		AttachStderr: true,
	}

	assert.Len(t, config.Command, 2)
	assert.Equal(t, "root", config.User)
	assert.Equal(t, "/app", config.WorkDir)
	assert.True(t, config.Privileged)
	assert.True(t, config.AttachStdout)
	assert.True(t, config.AttachStderr)
}

func TestExecResult_Fields(t *testing.T) {
	result := &ExecResult{
		ExitCode: 0,
		Stdout:   []byte("output"),
		Stderr:   []byte("error"),
	}

	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, "output", string(result.Stdout))
	assert.Equal(t, "error", string(result.Stderr))
}

func TestContainerLogs_Fields(t *testing.T) {
	now := time.Now()
	logs := &ContainerLogs{
		ContainerID: "abc123",
		Stdout:      []byte("stdout logs"),
		Stderr:      []byte("stderr logs"),
		Since:       now.Add(-1 * time.Hour),
		Until:       now,
	}

	assert.Equal(t, "abc123", logs.ContainerID)
	assert.Equal(t, "stdout logs", string(logs.Stdout))
	assert.Equal(t, "stderr logs", string(logs.Stderr))
}

func TestMount_Options(t *testing.T) {
	mount := &Mount{
		Source:   "/host/data",
		Target:   "/container/data",
		Type:     "bind",
		ReadOnly: true,
		Options:  []string{"nosuid", "nodev"},
	}

	err := mount.Validate()
	require.NoError(t, err)
	assert.Len(t, mount.Options, 2)
}

func TestContainerConfig_InvalidMounts(t *testing.T) {
	config := &ContainerConfig{
		Name:  "test",
		Image: "alpine",
		Mounts: []Mount{
			{Source: "/host", Type: "bind"}, // Missing target
		},
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mounts")
}

func TestContainerConfig_InvalidPorts(t *testing.T) {
	config := &ContainerConfig{
		Name:  "test",
		Image: "alpine",
		Ports: []PortMapping{
			{HostPort: 8080, Protocol: "tcp"}, // Missing container port
		},
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ports")
}

func TestContainerConfig_InvalidResources(t *testing.T) {
	config := &ContainerConfig{
		Name:  "test",
		Image: "alpine",
		Resources: &ResourceLimits{
			MemoryLimit: -1, // Invalid negative value
		},
	}

	err := config.Validate()
	require.Error(t, err)
}
