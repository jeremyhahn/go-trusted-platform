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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPlatformISOConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *PlatformISOConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
					Mirror:  "http://mirror.cs.odu.edu/alpine",
				},
				Directories: DirectoryConfig{
					Work: "work",
				},
				Platform: PlatformConfig{
					Version: "1.4.0",
				},
				RootFS: RootFSConfig{
					Type: "lvm",
				},
				Security: SecurityConfig{
					Lockdown:     false,
					LockdownMode: "confidentiality",
				},
			},
			wantErr: false,
		},
		{
			name: "missing alpine version",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Mirror: "http://mirror.cs.odu.edu/alpine",
				},
				Directories: DirectoryConfig{
					Work: "work",
				},
				Platform: PlatformConfig{
					Version: "1.4.0",
				},
			},
			wantErr: true,
			errMsg:  "alpine version is required",
		},
		{
			name: "missing alpine mirror",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
				},
				Directories: DirectoryConfig{
					Work: "work",
				},
				Platform: PlatformConfig{
					Version: "1.4.0",
				},
			},
			wantErr: true,
			errMsg:  "alpine mirror is required",
		},
		{
			name: "missing work directory",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
					Mirror:  "http://mirror.cs.odu.edu/alpine",
				},
				Platform: PlatformConfig{
					Version: "1.4.0",
				},
			},
			wantErr: true,
			errMsg:  "work directory is required",
		},
		{
			name: "missing platform version",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
					Mirror:  "http://mirror.cs.odu.edu/alpine",
				},
				Directories: DirectoryConfig{
					Work: "work",
				},
			},
			wantErr: true,
			errMsg:  "platform version is required",
		},
		{
			name: "invalid lockdown mode",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
					Mirror:  "http://mirror.cs.odu.edu/alpine",
				},
				Directories: DirectoryConfig{
					Work: "work",
				},
				Platform: PlatformConfig{
					Version: "1.4.0",
				},
				Security: SecurityConfig{
					Lockdown:     true,
					LockdownMode: "invalid",
				},
			},
			wantErr: true,
			errMsg:  "lockdown_mode must be either 'integrity' or 'confidentiality'",
		},
		{
			name: "invalid root filesystem type",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
					Mirror:  "http://mirror.cs.odu.edu/alpine",
				},
				Directories: DirectoryConfig{
					Work: "work",
				},
				Platform: PlatformConfig{
					Version: "1.4.0",
				},
				RootFS: RootFSConfig{
					Type: "invalid",
				},
			},
			wantErr: true,
			errMsg:  "root_fs type must be either 'lvm' or 'ext4'",
		},
		{
			name: "TPM auto-unseal without seal PCR",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
					Mirror:  "http://mirror.cs.odu.edu/alpine",
				},
				Directories: DirectoryConfig{
					Work: "work",
				},
				Platform: PlatformConfig{
					Version: "1.4.0",
				},
				RootFS: RootFSConfig{
					Type: "lvm",
				},
				Security: SecurityConfig{
					TPM: TPMConfig{
						AutoUnseal: true,
						SealPCR:    "",
					},
				},
			},
			wantErr: true,
			errMsg:  "tpm seal_pcr is required when auto_unseal is enabled",
		},
		{
			name: "valid integrity lockdown",
			config: &PlatformISOConfig{
				Alpine: AlpineConfig{
					Version: "3.22.2",
					Mirror:  "http://mirror.cs.odu.edu/alpine",
				},
				Directories: DirectoryConfig{
					Work: "work",
				},
				Platform: PlatformConfig{
					Version: "1.4.0",
				},
				Security: SecurityConfig{
					Lockdown:     true,
					LockdownMode: "integrity",
				},
				RootFS: RootFSConfig{
					Type: "ext4",
				},
			},
			wantErr: false,
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

func TestPlatformISOConfig_SetDefaults(t *testing.T) {
	config := &PlatformISOConfig{
		Platform: PlatformConfig{
			Version: "1.4.0",
		},
		Alpine: AlpineConfig{
			Version: "3.22.2",
		},
	}

	config.SetDefaults()

	// Test directory defaults
	assert.NotEmpty(t, config.Directories.Work)
	assert.Equal(t, "work", config.Directories.Work)
	assert.Contains(t, config.Directories.ISO, "work")
	assert.Contains(t, config.Directories.Overlay, "work")
	assert.Contains(t, config.Directories.Keys, "work")
	assert.Contains(t, config.Directories.NVRAM, "work")

	// Test Alpine defaults
	assert.NotEmpty(t, config.Alpine.Mirror)
	assert.Equal(t, "http://mirror.cs.odu.edu/alpine", config.Alpine.Mirror)

	// Test platform defaults
	assert.NotEmpty(t, config.Platform.ObjcopyBinary)
	assert.Equal(t, "objcopy", config.Platform.ObjcopyBinary)
	assert.NotEmpty(t, config.Platform.AfterInstallAction)
	assert.Equal(t, "poweroff", config.Platform.AfterInstallAction)

	// Test TPM defaults
	assert.NotEmpty(t, config.Security.TPM.Device)
	assert.Equal(t, "/dev/tpm0", config.Security.TPM.Device)
	assert.NotEmpty(t, config.Security.TPM.SealPCR)
	assert.Equal(t, "7,11", config.Security.TPM.SealPCR)
	assert.Contains(t, config.Security.TPM.SWTPMStateDir, "work")
	assert.Contains(t, config.Security.TPM.SWTPMCtrlSocket, "swtpm-ctrl")
	assert.Contains(t, config.Security.TPM.SWTPMSocket, "swtpm-sock")

	// Test lockdown mode default
	assert.NotEmpty(t, config.Security.LockdownMode)
	assert.Equal(t, "confidentiality", config.Security.LockdownMode)

	// Test OVMF defaults
	// Note: OVMF paths are OS-specific and may not exist on test systems
	assert.NotEmpty(t, config.Security.OVMFCode)
	assert.NotEmpty(t, config.Security.OVMFVars)

	// Test FIPS defaults
	assert.NotEmpty(t, config.Security.FIPSConfig.ContainerRuntime)
	assert.Equal(t, "docker", config.Security.FIPSConfig.ContainerRuntime)
	assert.Equal(t, "openssl-fips-provider-builder", config.Security.FIPSConfig.OpenSSLContainer)
	assert.Equal(t, "fips-kernel-builder", config.Security.FIPSConfig.KernelContainer)

	// Test root filesystem default
	assert.NotEmpty(t, config.RootFS.Type)
	assert.Equal(t, "lvm", config.RootFS.Type)

	// Test build defaults
	assert.NotEmpty(t, config.Build.QEMUDisk)
	assert.Equal(t, "alpine-platform-installed.qcow2", config.Build.QEMUDisk)
	assert.Equal(t, "10G", config.Build.QEMUDiskSize)

	// Test output ISO name
	assert.NotEmpty(t, config.Output.ISO)
	assert.Contains(t, config.Output.ISO, "trusted-platform-alpine")
	assert.Contains(t, config.Output.ISO, config.Platform.Version)

	// Test output ISO name with FIPS
	config.Security.FIPS = true
	config.Output.ISO = "" // Reset
	config.SetDefaults()
	assert.Contains(t, config.Output.ISO, "-fips-")

	// Test output directory
	assert.Equal(t, ".", config.Output.Directory)
}

func TestPlatformISOConfig_String(t *testing.T) {
	config := &PlatformISOConfig{
		Alpine: AlpineConfig{
			Version: "3.22.2",
		},
		Platform: PlatformConfig{
			Version: "1.4.0",
		},
		Security: SecurityConfig{
			SecureBoot: true,
			FIPS:       true,
			TPM: TPMConfig{
				AutoUnseal: true,
			},
		},
		LUKS: LUKSConfig{
			Enabled: true,
		},
	}

	str := config.String()

	assert.Contains(t, str, "PlatformISOConfig")
	assert.Contains(t, str, "3.22.2") // Alpine version
	assert.Contains(t, str, "1.4.0")  // Platform version
	assert.Contains(t, str, "true")   // For boolean values
}

func TestPlatformISOConfig_SetDefaults_CustomValues(t *testing.T) {
	// Test that SetDefaults doesn't overwrite custom values
	config := &PlatformISOConfig{
		Platform: PlatformConfig{
			Version:            "1.4.0",
			ObjcopyBinary:      "/custom/objcopy",
			AfterInstallAction: "reboot",
		},
		Alpine: AlpineConfig{
			Version: "3.22.2",
			Mirror:  "http://custom.mirror.com",
		},
		Directories: DirectoryConfig{
			Work:    "/custom/work",
			ISO:     "/custom/iso",
			Overlay: "/custom/overlay",
			Keys:    "/custom/keys",
			NVRAM:   "/custom/nvram",
		},
		Security: SecurityConfig{
			TPM: TPMConfig{
				Device:          "/dev/custom",
				SealPCR:         "0,1,2",
				SWTPMStateDir:   "/custom/tpm",
				SWTPMCtrlSocket: "/custom/ctrl",
				SWTPMSocket:     "/custom/sock",
			},
			LockdownMode: "integrity",
			OVMFCode:     "/custom/ovmf/code",
			OVMFVars:     "/custom/ovmf/vars",
			FIPSConfig: FIPSConfig{
				ContainerRuntime: "podman",
				OpenSSLContainer: "custom-openssl",
				KernelContainer:  "custom-kernel",
			},
		},
		RootFS: RootFSConfig{
			Type: "ext4",
		},
		Build: BuildOptions{
			QEMUDisk:     "custom.qcow2",
			QEMUDiskSize: "20G",
		},
		Output: OutputConfig{
			ISO:       "custom.iso",
			Directory: "/custom/output",
		},
	}

	config.SetDefaults()

	// Verify custom values were not overwritten
	assert.Equal(t, "/custom/objcopy", config.Platform.ObjcopyBinary)
	assert.Equal(t, "reboot", config.Platform.AfterInstallAction)
	assert.Equal(t, "http://custom.mirror.com", config.Alpine.Mirror)
	assert.Equal(t, "/custom/work", config.Directories.Work)
	assert.Equal(t, "/custom/iso", config.Directories.ISO)
	assert.Equal(t, "/dev/custom", config.Security.TPM.Device)
	assert.Equal(t, "0,1,2", config.Security.TPM.SealPCR)
	assert.Equal(t, "integrity", config.Security.LockdownMode)
	assert.Equal(t, "/custom/ovmf/code", config.Security.OVMFCode)
	assert.Equal(t, "podman", config.Security.FIPSConfig.ContainerRuntime)
	assert.Equal(t, "ext4", config.RootFS.Type)
	assert.Equal(t, "custom.qcow2", config.Build.QEMUDisk)
	assert.Equal(t, "custom.iso", config.Output.ISO)
	assert.Equal(t, "/custom/output", config.Output.Directory)
}

func TestISOConfig_HelperMethods(t *testing.T) {
	tmpDir := t.TempDir()
	config := &ISOConfig{
		Version:   "3.22.2",
		ISO:       "alpine-standard-3.22.2-x86_64.iso",
		URL:       "http://example.com/alpine.iso",
		MirrorURL: "http://example.com",
		WorkDir:   tmpDir,
	}

	err := config.Validate()
	assert.NoError(t, err)

	t.Run("ChecksumURL", func(t *testing.T) {
		url := config.ChecksumURL()
		assert.Equal(t, "http://example.com/alpine.iso.sha256", url)
	})

	t.Run("ISOPath", func(t *testing.T) {
		path := config.ISOPath()
		assert.Contains(t, path, tmpDir)
		assert.Contains(t, path, "alpine-standard-3.22.2-x86_64.iso")
	})

	t.Run("ChecksumPath", func(t *testing.T) {
		path := config.ChecksumPath()
		assert.Contains(t, path, tmpDir)
		assert.Contains(t, path, ".sha256")
	})

	t.Run("VerifiedMarkerPath", func(t *testing.T) {
		path := config.VerifiedMarkerPath()
		assert.Contains(t, path, tmpDir)
		assert.Contains(t, path, ".verified")
	})

	t.Run("TempPath", func(t *testing.T) {
		path := config.TempPath()
		assert.Contains(t, path, tmpDir)
		assert.Contains(t, path, ".tmp")
	})
}

func TestDefaultISOConfig(t *testing.T) {
	config := DefaultISOConfig()

	assert.NotNil(t, config)
	assert.NotEmpty(t, config.Version)
	assert.NotEmpty(t, config.MirrorURL)
	assert.NotEmpty(t, config.WorkDir)
	assert.True(t, config.VerifyChecksum)
	assert.True(t, config.ResumeDownload)
	assert.NotEmpty(t, config.VolumeID)
}

func TestISOConfig_Validate_Autopopulate(t *testing.T) {
	config := &ISOConfig{
		Version:   "3.22.2",
		WorkDir:   "work",
		MirrorURL: "http://example.com",
	}

	err := config.Validate()
	assert.NoError(t, err)

	// Verify auto-populated fields
	assert.NotEmpty(t, config.ISO)
	assert.Contains(t, config.ISO, "alpine-standard")
	assert.Contains(t, config.ISO, "3.22.2")
	assert.Contains(t, config.ISO, "x86_64")

	assert.NotEmpty(t, config.URL)
	assert.Contains(t, config.URL, "http://example.com")
	assert.Contains(t, config.URL, "v3.22")
	assert.Contains(t, config.URL, "releases")

	assert.NotEmpty(t, config.ISODir)
	assert.Contains(t, config.ISODir, "work")
	assert.Contains(t, config.ISODir, "iso")
}

func TestPlatformISOConfig_EdgeCases(t *testing.T) {
	t.Run("empty lockdown mode with lockdown disabled", func(t *testing.T) {
		config := &PlatformISOConfig{
			Alpine: AlpineConfig{
				Version: "3.22.2",
				Mirror:  "http://mirror.cs.odu.edu/alpine",
			},
			Directories: DirectoryConfig{
				Work: "work",
			},
			Platform: PlatformConfig{
				Version: "1.4.0",
			},
			Security: SecurityConfig{
				Lockdown:     false,
				LockdownMode: "", // Empty is OK when lockdown is disabled
			},
			RootFS: RootFSConfig{
				Type: "lvm",
			},
		}

		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("TPM auto-unseal with valid seal PCR", func(t *testing.T) {
		config := &PlatformISOConfig{
			Alpine: AlpineConfig{
				Version: "3.22.2",
				Mirror:  "http://mirror.cs.odu.edu/alpine",
			},
			Directories: DirectoryConfig{
				Work: "work",
			},
			Platform: PlatformConfig{
				Version: "1.4.0",
			},
			Security: SecurityConfig{
				TPM: TPMConfig{
					AutoUnseal: true,
					SealPCR:    "0,7,9",
				},
			},
			RootFS: RootFSConfig{
				Type: "lvm",
			},
		}

		err := config.Validate()
		assert.NoError(t, err)
	})
}

func TestPlatformISOConfig_AllBooleanCombinations(t *testing.T) {
	baseConfig := &PlatformISOConfig{
		Alpine: AlpineConfig{
			Version: "3.22.2",
			Mirror:  "http://mirror.cs.odu.edu/alpine",
		},
		Directories: DirectoryConfig{
			Work: "work",
		},
		Platform: PlatformConfig{
			Version: "1.4.0",
		},
		RootFS: RootFSConfig{
			Type: "lvm",
		},
	}

	tests := []struct {
		name       string
		modifyFunc func(*PlatformISOConfig)
	}{
		{
			name: "all security features enabled",
			modifyFunc: func(c *PlatformISOConfig) {
				c.Security.SecureBoot = true
				c.Security.Lockdown = true
				c.Security.LockdownMode = "confidentiality"
				c.Security.FIPS = true
				c.Security.EnableFIDO2 = true
				c.Security.TPM.AutoUnseal = true
				c.Security.TPM.SealPCR = "0,7,9"
				c.LUKS.Enabled = true
			},
		},
		{
			name: "all security features disabled",
			modifyFunc: func(c *PlatformISOConfig) {
				c.Security.SecureBoot = false
				c.Security.Lockdown = false
				c.Security.FIPS = false
				c.Security.EnableFIDO2 = false
				c.Security.TPM.AutoUnseal = false
				c.LUKS.Enabled = false
			},
		},
		{
			name: "mixed security settings",
			modifyFunc: func(c *PlatformISOConfig) {
				c.Security.SecureBoot = true
				c.Security.Lockdown = false
				c.Security.FIPS = true
				c.Security.EnableFIDO2 = false
				c.LUKS.Enabled = true
				c.LUKS.TPMOnly = true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := *baseConfig // Copy
			tt.modifyFunc(&config)

			// Should validate successfully
			err := config.Validate()
			assert.NoError(t, err)

			// SetDefaults should work
			config.SetDefaults()

			// String() should not panic
			str := config.String()
			assert.NotEmpty(t, str)
		})
	}
}
