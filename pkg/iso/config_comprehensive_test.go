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

package iso

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

func TestPlatformISOConfigValidate(t *testing.T) {
	tmpDir := t.TempDir()

	// Create dummy files for validation
	platformdBinary := filepath.Join(tmpDir, "platformd")
	os.WriteFile(platformdBinary, []byte("#!/bin/sh\necho platformd"), 0755)

	platformConfig := filepath.Join(tmpDir, "platform.yaml")
	os.WriteFile(platformConfig, []byte("version: 1.4.0\n"), 0644)

	tests := []struct {
		name    string
		config  *PlatformISOConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid configuration",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
					Mirror:  "http://dl-cdn.alpinelinux.org/alpine",
				},
				Platform: PlatformConfig{
					Version:         "1.4.0",
					PlatformdBinary: platformdBinary,
					ConfigFile:      platformConfig,
				},
				Directories: DirectoryConfig{
					Work:    tmpDir,
					ISO:     filepath.Join(tmpDir, "iso"),
					Overlay: filepath.Join(tmpDir, "overlay"),
				},
				RootFS: RootFSConfig{
					Type: "lvm",
				},
			},
			wantErr: false,
		},
		{
			name: "missing Alpine version",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Mirror: "http://example.com",
				},
			},
			wantErr: true,
			errMsg:  "alpine version",
		},
		{
			name: "invalid root filesystem type",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
					Mirror:  "http://example.com",
				},
				Directories: DirectoryConfig{
					Work: "/tmp/work",
				},
				Platform: PlatformConfig{
					Version: "1.4.0",
				},
				RootFS: RootFSConfig{
					Type: "btrfs",
				},
			},
			wantErr: true,
			errMsg:  "root_fs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPlatformISOConfigSetDefaults(t *testing.T) {
	config := &PlatformISOConfig{}
	config.SetDefaults()

	assert.NotEmpty(t, config.Directories.Work)
	assert.NotEmpty(t, config.Directories.ISO)
	assert.NotEmpty(t, config.Directories.Overlay)
}

func TestPlatformISOConfigYAMLSerialization(t *testing.T) {
	config := &PlatformISOConfig{
		Alpine: AlpineConfig{
			Version: "3.22.2",
			Mirror:  "http://example.com",
		},
		Directories: DirectoryConfig{
			Work: "/tmp/work",
		},
		Platform: PlatformConfig{
			Version: "1.4.0",
		},
	}

	data, err := yaml.Marshal(config)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	yamlStr := string(data)
	assert.Contains(t, yamlStr, "alpine:")
	assert.Contains(t, yamlStr, "version: 3.22.2")
	assert.Contains(t, yamlStr, "platform:")
}
