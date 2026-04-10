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

package modes

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPXEController_Valid(t *testing.T) {
	config := &PXEControllerConfig{
		Interface:         "eth0",
		HTTPPort:          8080,
		TFTPPort:          69,
		ServerAddr:        "172.16.7.1",
		PlatformdAddr:     "https://platformd:8443",
		BootstrapStrategy: "dane",
	}

	controller, err := NewPXEController(config, slog.Default())
	require.NoError(t, err)
	require.NotNil(t, controller)

	assert.Equal(t, config, controller.config)
	assert.NotNil(t, controller.scriptGenerator)
	assert.NotNil(t, controller.deviceLookup)
	assert.NotNil(t, controller.logger)
	assert.False(t, controller.IsRunning())
}

func TestNewPXEController_NilConfig(t *testing.T) {
	controller, err := NewPXEController(nil, slog.Default())
	assert.Nil(t, controller)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPXEControllerConfigNil))
}

func TestNewPXEController_NilLogger(t *testing.T) {
	config := &PXEControllerConfig{
		Interface:  "eth0",
		HTTPPort:   8080,
		TFTPPort:   69,
		ServerAddr: "172.16.7.1",
	}

	controller, err := NewPXEController(config, nil)
	require.NoError(t, err)
	require.NotNil(t, controller)
	assert.NotNil(t, controller.logger)
}

func TestPXEController_IsRunning(t *testing.T) {
	config := &PXEControllerConfig{
		Interface:  "eth0",
		HTTPPort:   8080,
		TFTPPort:   69,
		ServerAddr: "172.16.7.1",
	}

	controller, err := NewPXEController(config, slog.Default())
	require.NoError(t, err)

	assert.False(t, controller.IsRunning())
}

func TestPXEController_StopNotRunning(t *testing.T) {
	config := &PXEControllerConfig{
		Interface:  "eth0",
		HTTPPort:   8080,
		TFTPPort:   69,
		ServerAddr: "172.16.7.1",
	}

	controller, err := NewPXEController(config, slog.Default())
	require.NoError(t, err)

	err = controller.Stop()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotRunning))
}

func TestPXEController_DefaultDeviceLookup(t *testing.T) {
	config := &PXEControllerConfig{
		Interface:         "eth0",
		HTTPPort:          8080,
		TFTPPort:          69,
		ServerAddr:        "172.16.7.1",
		PlatformdAddr:     "https://platformd:8443",
		BootstrapStrategy: "dane",
	}

	controller, err := NewPXEController(config, slog.Default())
	require.NoError(t, err)

	info, err := controller.defaultDeviceLookup("52:54:00:aa:bb:cc")
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, "52:54:00:aa:bb:cc", info.MAC)
	assert.Equal(t, "worker", info.Role)
	assert.Equal(t, "https://platformd:8443", info.ConfigServerURL)
	assert.Equal(t, "dane", info.BootstrapStrategy)
	assert.Contains(t, info.KernelURL, "172.16.7.1:8080")
	assert.Contains(t, info.InitrdURL, "172.16.7.1:8080")
}

func TestParentDir(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "absolute path",
			path:     "/var/lib/ipxe/vmlinuz",
			expected: "/var/lib/ipxe",
		},
		{
			name:     "root level",
			path:     "/vmlinuz",
			expected: "",
		},
		{
			name:     "no slash",
			path:     "vmlinuz",
			expected: ".",
		},
		{
			name:     "nested path",
			path:     "/a/b/c/d",
			expected: "/a/b/c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parentDir(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}
