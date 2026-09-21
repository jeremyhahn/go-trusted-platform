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

package installer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOSInstaller(t *testing.T) {
	tests := []struct {
		name    string
		config  *OSConfig
		wantErr bool
		errMsg  string
		osType  OperatingSystem
	}{
		{
			name: "alpine installer",
			config: &OSConfig{
				OS:      OSAlpine,
				Version: "3.19",
			},
			wantErr: false,
			osType:  OSAlpine,
		},
		{
			name: "debian installer",
			config: &OSConfig{
				OS:      OSDebian,
				Version: "bookworm",
			},
			wantErr: false,
			osType:  OSDebian,
		},
		{
			name: "fedora installer",
			config: &OSConfig{
				OS:      OSFedora,
				Version: "39",
			},
			wantErr: false,
			osType:  OSFedora,
		},
		{
			name: "ubuntu installer",
			config: &OSConfig{
				OS:      OSUbuntu,
				Version: "22.04",
			},
			wantErr: false,
			osType:  OSUbuntu,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errMsg:  "OS config is required",
		},
		{
			name: "unsupported OS",
			config: &OSConfig{
				OS: "unsupported",
			},
			wantErr: true,
			errMsg:  "unsupported OS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := createTestLogger()
			installer, err := NewOSInstaller(logger, tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, installer)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, installer)
				assert.Equal(t, tt.osType, installer.Name())
			}
		})
	}
}

func TestAlpineInstaller_Name(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:      OSAlpine,
		Version: "3.19",
	}

	installer, err := NewOSInstaller(logger, config)
	require.NoError(t, err)

	assert.Equal(t, OSAlpine, installer.Name())
}

func TestAlpineInstaller_ConfigureSystem(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:       OSAlpine,
		Version:  "3.19",
		Hostname: "test-host",
	}

	installer, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	// Create a temporary directory to simulate root filesystem
	tmpDir, err := os.MkdirTemp("", "alpine-test-*")
	require.NoError(t, err)
	t.Cleanup(func() {
		if removeErr := os.RemoveAll(tmpDir); removeErr != nil {
			t.Logf("Failed to clean up temp dir: %v", removeErr)
		}
	})

	// Create necessary subdirectories
	etcDir := filepath.Join(tmpDir, "etc")
	err = os.MkdirAll(etcDir, 0755)
	require.NoError(t, err)

	// Test with encryption
	diskInfo := &DiskInfo{
		Device:        "/dev/sda",
		EFIPartition:  "/dev/sda1",
		RootPartition: "/dev/sda2",
		MappedDevice:  "/dev/mapper/cryptroot",
	}

	ctx := context.Background()
	err = installer.ConfigureSystem(ctx, tmpDir, diskInfo)
	require.NoError(t, err)

	// Verify fstab was created
	fstabPath := filepath.Join(tmpDir, "etc", "fstab")
	assert.FileExists(t, fstabPath)

	fstabContent, err := os.ReadFile(fstabPath)
	require.NoError(t, err)
	// The ESP is mounted by its label so the entry is valid whatever device
	// name the partition gets on the booted node (sda1, nvme0n1p1, mmcblk0p1).
	assert.Contains(t, string(fstabContent), "LABEL=EFI /boot/efi vfat")
	assert.NotContains(t, string(fstabContent), "/dev/sda1")
	assert.Contains(t, string(fstabContent), "/dev/mapper/cryptroot")
	assert.Contains(t, string(fstabContent), "/ ext4")

	// Verify crypttab was created
	crypttabPath := filepath.Join(tmpDir, "etc", "crypttab")
	assert.FileExists(t, crypttabPath)

	crypttabContent, err := os.ReadFile(crypttabPath)
	require.NoError(t, err)
	assert.Contains(t, string(crypttabContent), "cryptroot")
	assert.Contains(t, string(crypttabContent), "/dev/sda2")
	assert.Contains(t, string(crypttabContent), "luks")

	// Verify resolv.conf was created
	resolvPath := filepath.Join(tmpDir, "etc", "resolv.conf")
	assert.FileExists(t, resolvPath)

	resolvContent, err := os.ReadFile(resolvPath)
	require.NoError(t, err)
	assert.Contains(t, string(resolvContent), "nameserver")

	// Verify hostname was created
	hostnamePath := filepath.Join(tmpDir, "etc", "hostname")
	assert.FileExists(t, hostnamePath)

	hostnameContent, err := os.ReadFile(hostnamePath)
	require.NoError(t, err)
	assert.Contains(t, string(hostnameContent), "test-host")
}

func TestAlpineInstaller_ConfigureSystem_NoEncryption(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:      OSAlpine,
		Version: "3.19",
	}

	installer, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	tmpDir, err := os.MkdirTemp("", "alpine-test-*")
	require.NoError(t, err)
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	etcDir := filepath.Join(tmpDir, "etc")
	err = os.MkdirAll(etcDir, 0755)
	require.NoError(t, err)

	// Test without encryption
	diskInfo := &DiskInfo{
		Device:        "/dev/sda",
		EFIPartition:  "/dev/sda1",
		RootPartition: "/dev/sda2",
	}

	ctx := context.Background()
	err = installer.ConfigureSystem(ctx, tmpDir, diskInfo)
	require.NoError(t, err)

	// Verify fstab was created without mapped device
	fstabPath := filepath.Join(tmpDir, "etc", "fstab")
	assert.FileExists(t, fstabPath)

	fstabContent, err := os.ReadFile(fstabPath)
	require.NoError(t, err)
	assert.Contains(t, string(fstabContent), "/dev/sda2")
	assert.NotContains(t, string(fstabContent), "/dev/mapper")

	// Verify crypttab was NOT created
	crypttabPath := filepath.Join(tmpDir, "etc", "crypttab")
	assert.NoFileExists(t, crypttabPath)
}

func TestAlpineInstaller_ConfigureSystem_DefaultHostname(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:      OSAlpine,
		Version: "3.19",
		// No hostname specified
	}

	installer, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	tmpDir, err := os.MkdirTemp("", "alpine-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	etcDir := filepath.Join(tmpDir, "etc")
	err = os.MkdirAll(etcDir, 0755)
	require.NoError(t, err)

	diskInfo := &DiskInfo{
		Device:        "/dev/sda",
		EFIPartition:  "/dev/sda1",
		RootPartition: "/dev/sda2",
	}

	ctx := context.Background()
	err = installer.ConfigureSystem(ctx, tmpDir, diskInfo)
	require.NoError(t, err)

	hostnamePath := filepath.Join(tmpDir, "etc", "hostname")
	assert.FileExists(t, hostnamePath)

	hostnameContent, err := os.ReadFile(hostnamePath)
	require.NoError(t, err)
	assert.Contains(t, string(hostnameContent), "trusted-platform")
}

// Note: The following tests would require network access and actual command execution
// They are documented here but should be run as integration tests

// TestAlpineInstaller_InstallBase - Integration test only
// - Downloads Alpine minirootfs from CDN
// - Extracts tarball to root path
// - Creates APK repository configuration
// - Installs base packages using chroot
// - Verifies package installation

// TestAlpineInstaller_InstallKernel - Integration test only
// - Verifies linux-lts package is installed
// - Creates mkinitfs configuration with cryptsetup
// - Generates initramfs with proper features
// - Verifies kernel and initramfs exist

// TestAlpineInstaller_SetRootPassword - Integration test only
// - Sets root password using chpasswd in chroot
// - Verifies password is set correctly
// - Tests with empty password (should skip)

func TestDebianInstaller_NotImplemented(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:      OSDebian,
		Version: "bookworm",
	}

	installer, err := NewOSInstaller(logger, config)
	require.NoError(t, err)

	ctx := context.Background()
	tmpDir := "/tmp/test"

	tests := []struct {
		name   string
		action func() error
	}{
		{
			name: "InstallBase",
			action: func() error {
				return installer.InstallBase(ctx, tmpDir)
			},
		},
		{
			name: "ConfigureSystem",
			action: func() error {
				return installer.ConfigureSystem(ctx, tmpDir, &DiskInfo{})
			},
		},
		{
			name: "InstallKernel",
			action: func() error {
				return installer.InstallKernel(ctx, tmpDir)
			},
		},
		{
			name: "SetRootPassword",
			action: func() error {
				return installer.SetRootPassword(ctx, tmpDir, "password")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.action()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "not yet implemented")
		})
	}

	assert.Equal(t, OSDebian, installer.Name())
}

func TestFedoraInstaller_NotImplemented(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:      OSFedora,
		Version: "39",
	}

	installer, err := NewOSInstaller(logger, config)
	require.NoError(t, err)

	ctx := context.Background()
	tmpDir := "/tmp/test"

	tests := []struct {
		name   string
		action func() error
	}{
		{
			name: "InstallBase",
			action: func() error {
				return installer.InstallBase(ctx, tmpDir)
			},
		},
		{
			name: "ConfigureSystem",
			action: func() error {
				return installer.ConfigureSystem(ctx, tmpDir, &DiskInfo{})
			},
		},
		{
			name: "InstallKernel",
			action: func() error {
				return installer.InstallKernel(ctx, tmpDir)
			},
		},
		{
			name: "SetRootPassword",
			action: func() error {
				return installer.SetRootPassword(ctx, tmpDir, "password")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.action()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "not yet implemented")
		})
	}

	assert.Equal(t, OSFedora, installer.Name())
}

func TestUbuntuInstaller_NotImplemented(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:      OSUbuntu,
		Version: "22.04",
	}

	installer, err := NewOSInstaller(logger, config)
	require.NoError(t, err)

	ctx := context.Background()
	tmpDir := "/tmp/test"

	tests := []struct {
		name   string
		action func() error
	}{
		{
			name: "InstallBase",
			action: func() error {
				return installer.InstallBase(ctx, tmpDir)
			},
		},
		{
			name: "ConfigureSystem",
			action: func() error {
				return installer.ConfigureSystem(ctx, tmpDir, &DiskInfo{})
			},
		},
		{
			name: "InstallKernel",
			action: func() error {
				return installer.InstallKernel(ctx, tmpDir)
			},
		},
		{
			name: "SetRootPassword",
			action: func() error {
				return installer.SetRootPassword(ctx, tmpDir, "password")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.action()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "not yet implemented")
		})
	}

	assert.Equal(t, OSUbuntu, installer.Name())
}

func TestOSConfig_Defaults(t *testing.T) {
	tests := []struct {
		name   string
		config *OSConfig
		verify func(t *testing.T, cfg *OSConfig)
	}{
		{
			name: "full alpine config",
			config: &OSConfig{
				OS:           OSAlpine,
				Version:      "3.19",
				Mirror:       "https://dl-cdn.alpinelinux.org/alpine",
				Packages:     []string{"vim", "git"},
				RootPassword: "secure123",
			},
			verify: func(t *testing.T, cfg *OSConfig) {
				assert.Equal(t, OSAlpine, cfg.OS)
				assert.Equal(t, "3.19", cfg.Version)
				assert.NotEmpty(t, cfg.Mirror)
				assert.Len(t, cfg.Packages, 2)
				assert.NotEmpty(t, cfg.RootPassword)
			},
		},
		{
			name: "minimal config",
			config: &OSConfig{
				OS: OSAlpine,
			},
			verify: func(t *testing.T, cfg *OSConfig) {
				assert.Equal(t, OSAlpine, cfg.OS)
				assert.Empty(t, cfg.Version)
				assert.Empty(t, cfg.Mirror)
				assert.Nil(t, cfg.Packages)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.verify(t, tt.config)
		})
	}
}

func TestAlpineInstaller_FstabGeneration(t *testing.T) {
	tests := []struct {
		name     string
		diskInfo *DiskInfo
		verify   func(t *testing.T, fstabContent string)
	}{
		{
			name: "with encryption",
			diskInfo: &DiskInfo{
				EFIPartition:  "/dev/sda1",
				RootPartition: "/dev/sda2",
				MappedDevice:  "/dev/mapper/cryptroot",
			},
			verify: func(t *testing.T, content string) {
				assert.Contains(t, content, "LABEL=EFI /boot/efi vfat")
				assert.NotContains(t, content, "/dev/sda1")
				assert.Contains(t, content, "/dev/mapper/cryptroot")
				assert.Contains(t, content, "/ ext4")
			},
		},
		{
			name: "without encryption",
			diskInfo: &DiskInfo{
				EFIPartition:  "/dev/vda1",
				RootPartition: "/dev/vda2",
			},
			verify: func(t *testing.T, content string) {
				assert.Contains(t, content, "LABEL=EFI /boot/efi vfat")
				assert.NotContains(t, content, "/dev/vda1")
				assert.Contains(t, content, "/dev/vda2")
				assert.NotContains(t, content, "/dev/mapper")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := createTestLogger()
			config := &OSConfig{
				OS:      OSAlpine,
				Version: "3.19",
			}

			installer, err := newAlpineInstaller(logger, config)
			require.NoError(t, err)

			tmpDir, err := os.MkdirTemp("", "alpine-fstab-test-*")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			etcDir := filepath.Join(tmpDir, "etc")
			err = os.MkdirAll(etcDir, 0755)
			require.NoError(t, err)

			ctx := context.Background()
			err = installer.ConfigureSystem(ctx, tmpDir, tt.diskInfo)
			require.NoError(t, err)

			fstabPath := filepath.Join(tmpDir, "etc", "fstab")
			content, err := os.ReadFile(fstabPath)
			require.NoError(t, err)

			tt.verify(t, string(content))
		})
	}
}

func TestAlpineInstaller_CrypttabGeneration(t *testing.T) {
	tests := []struct {
		name          string
		diskInfo      *DiskInfo
		shouldExist   bool
		verifyContent func(t *testing.T, content string)
	}{
		{
			name: "with encryption",
			diskInfo: &DiskInfo{
				RootPartition: "/dev/sda2",
				MappedDevice:  "/dev/mapper/cryptroot",
			},
			shouldExist: true,
			verifyContent: func(t *testing.T, content string) {
				assert.Contains(t, content, "cryptroot")
				assert.Contains(t, content, "/dev/sda2")
				assert.Contains(t, content, "none")
				assert.Contains(t, content, "luks")
			},
		},
		{
			name: "without encryption",
			diskInfo: &DiskInfo{
				RootPartition: "/dev/sda2",
			},
			shouldExist: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := createTestLogger()
			config := &OSConfig{
				OS:      OSAlpine,
				Version: "3.19",
			}

			installer, err := newAlpineInstaller(logger, config)
			require.NoError(t, err)

			tmpDir, err := os.MkdirTemp("", "alpine-crypttab-test-*")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			etcDir := filepath.Join(tmpDir, "etc")
			err = os.MkdirAll(etcDir, 0755)
			require.NoError(t, err)

			ctx := context.Background()
			err = installer.ConfigureSystem(ctx, tmpDir, tt.diskInfo)
			require.NoError(t, err)

			crypttabPath := filepath.Join(tmpDir, "etc", "crypttab")
			if tt.shouldExist {
				assert.FileExists(t, crypttabPath)
				content, err := os.ReadFile(crypttabPath)
				require.NoError(t, err)
				tt.verifyContent(t, string(content))
			} else {
				assert.NoFileExists(t, crypttabPath)
			}
		})
	}
}
