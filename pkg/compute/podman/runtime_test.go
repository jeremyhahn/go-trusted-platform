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
