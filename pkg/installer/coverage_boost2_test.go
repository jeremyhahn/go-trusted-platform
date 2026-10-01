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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// alpine.go - generateIMAPolicy all branches
// =============================================================================

func TestGenerateIMAPolicy_TCB(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:      OSAlpine,
		Version: "3.22",
		IMA: &IMAConfig{
			Enabled:       true,
			Policy:        "tcb",
			HashAlgorithm: "sha256",
		},
	}

	inst, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	ai := inst.(*alpineInstaller)
	policy := ai.generateIMAPolicy()

	assert.Contains(t, policy, "TCB Policy")
	assert.Contains(t, policy, "BPRM_CHECK")
	assert.Contains(t, policy, "MMAP_CHECK")
	assert.Contains(t, policy, "MODULE_CHECK")
	assert.Contains(t, policy, "FIRMWARE_CHECK")
	assert.Contains(t, policy, "KEXEC_KERNEL_CHECK")
	assert.Contains(t, policy, "KEXEC_INITRAMFS_CHECK")
	assert.Contains(t, policy, "dont_measure")
}

func TestGenerateIMAPolicy_AppraiseTCB(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:      OSAlpine,
		Version: "3.22",
		IMA: &IMAConfig{
			Enabled: true,
			Policy:  "appraise_tcb",
		},
	}

	inst, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	ai := inst.(*alpineInstaller)
	policy := ai.generateIMAPolicy()

	assert.Contains(t, policy, "TCB with Appraisal Policy")
	assert.Contains(t, policy, "appraise func=BPRM_CHECK")
	assert.Contains(t, policy, "imasig")
}

func TestGenerateIMAPolicy_SecureBoot(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:      OSAlpine,
		Version: "3.22",
		IMA: &IMAConfig{
			Enabled: true,
			Policy:  "secure_boot",
		},
	}

	inst, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	ai := inst.(*alpineInstaller)
	policy := ai.generateIMAPolicy()

	assert.Contains(t, policy, "Secure Boot Policy")
	assert.Contains(t, policy, "KEXEC_KERNEL_CHECK")
	assert.NotContains(t, policy, "BPRM_CHECK")
}

func TestGenerateIMAPolicy_CriticalData(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:      OSAlpine,
		Version: "3.22",
		IMA: &IMAConfig{
			Enabled: true,
			Policy:  "critical_data",
		},
	}

	inst, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	ai := inst.(*alpineInstaller)
	policy := ai.generateIMAPolicy()

	assert.Contains(t, policy, "Critical Data Policy")
	assert.Contains(t, policy, "CRITICAL_DATA")
}

func TestGenerateIMAPolicy_Default(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:      OSAlpine,
		Version: "3.22",
		IMA: &IMAConfig{
			Enabled: true,
			Policy:  "unknown_policy",
		},
	}

	inst, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	ai := inst.(*alpineInstaller)
	policy := ai.generateIMAPolicy()

	assert.Contains(t, policy, "Default TCB Policy")
	assert.Contains(t, policy, "BPRM_CHECK")
}

func TestGenerateIMAPolicy_WithMonitorPaths(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:      OSAlpine,
		Version: "3.22",
		IMA: &IMAConfig{
			Enabled:      true,
			Policy:       "tcb",
			MonitorPaths: []string{"/custom/path1", "/custom/path2"},
		},
	}

	inst, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	ai := inst.(*alpineInstaller)
	policy := ai.generateIMAPolicy()

	assert.Contains(t, policy, "Custom monitored paths")
	assert.Contains(t, policy, "/custom/path1")
	assert.Contains(t, policy, "/custom/path2")
}

func TestGenerateIMAPolicy_NoMonitorPaths(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:      OSAlpine,
		Version: "3.22",
		IMA: &IMAConfig{
			Enabled: true,
			Policy:  "tcb",
		},
	}

	inst, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	ai := inst.(*alpineInstaller)
	policy := ai.generateIMAPolicy()

	assert.NotContains(t, policy, "Custom monitored paths")
}

// =============================================================================
// installer.go - installOS mock-based testing
// =============================================================================

func TestInstaller_InstallOS_Success(t *testing.T) {
	mockOS := new(MockOSInstaller)
	ctx := context.Background()
	config := createTestConfig()

	mockOS.On("InstallBase", ctx, "/mnt").Return(nil)
	mockOS.On("ConfigureSystem", ctx, "/mnt", mock.AnythingOfType("*installer.DiskInfo")).Return(nil)
	mockOS.On("InstallKernel", ctx, "/mnt").Return(nil)
	mockOS.On("SetRootPassword", ctx, "/mnt", "root123").Return(nil)
	mockOS.On("InstallPackages", ctx, "/mnt").Return(nil)
	mockOS.On("ExecutePostInstall", ctx, "/mnt").Return(nil)

	inst := &installer{
		config:      config,
		logger:      createTestLogger(),
		osInstaller: mockOS,
	}

	diskInfo := &DiskInfo{
		Device:        "/dev/sda",
		EFIPartition:  "/dev/sda1",
		RootPartition: "/dev/sda2",
	}

	err := inst.installOS(ctx, diskInfo)
	assert.NoError(t, err)
	mockOS.AssertExpectations(t)
}

func TestInstaller_InstallOS_BaseInstallFails(t *testing.T) {
	mockOS := new(MockOSInstaller)
	ctx := context.Background()
	config := createTestConfig()

	mockOS.On("InstallBase", ctx, "/mnt").Return(errors.New("download failed"))

	inst := &installer{
		config:      config,
		logger:      createTestLogger(),
		osInstaller: mockOS,
	}

	diskInfo := &DiskInfo{Device: "/dev/sda"}
	err := inst.installOS(ctx, diskInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to install base system")
}

func TestInstaller_InstallOS_ConfigureSystemFails(t *testing.T) {
	mockOS := new(MockOSInstaller)
	ctx := context.Background()
	config := createTestConfig()

	mockOS.On("InstallBase", ctx, "/mnt").Return(nil)
	mockOS.On("ConfigureSystem", ctx, "/mnt", mock.AnythingOfType("*installer.DiskInfo")).
		Return(errors.New("config error"))

	inst := &installer{
		config:      config,
		logger:      createTestLogger(),
		osInstaller: mockOS,
	}

	diskInfo := &DiskInfo{Device: "/dev/sda"}
	err := inst.installOS(ctx, diskInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to configure system")
}

func TestInstaller_InstallOS_KernelInstallFails(t *testing.T) {
	mockOS := new(MockOSInstaller)
	ctx := context.Background()
	config := createTestConfig()

	mockOS.On("InstallBase", ctx, "/mnt").Return(nil)
	mockOS.On("ConfigureSystem", ctx, "/mnt", mock.AnythingOfType("*installer.DiskInfo")).Return(nil)
	mockOS.On("InstallKernel", ctx, "/mnt").Return(errors.New("kernel not found"))

	inst := &installer{
		config:      config,
		logger:      createTestLogger(),
		osInstaller: mockOS,
	}

	diskInfo := &DiskInfo{Device: "/dev/sda"}
	err := inst.installOS(ctx, diskInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to install kernel")
}

func TestInstaller_InstallOS_SetRootPasswordFails(t *testing.T) {
	mockOS := new(MockOSInstaller)
	ctx := context.Background()
	config := createTestConfig()

	mockOS.On("InstallBase", ctx, "/mnt").Return(nil)
	mockOS.On("ConfigureSystem", ctx, "/mnt", mock.AnythingOfType("*installer.DiskInfo")).Return(nil)
	mockOS.On("InstallKernel", ctx, "/mnt").Return(nil)
	mockOS.On("SetRootPassword", ctx, "/mnt", "root123").Return(errors.New("chpasswd failed"))

	inst := &installer{
		config:      config,
		logger:      createTestLogger(),
		osInstaller: mockOS,
	}

	diskInfo := &DiskInfo{Device: "/dev/sda"}
	err := inst.installOS(ctx, diskInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to set root password")
}

func TestInstaller_InstallOS_NoRootPassword(t *testing.T) {
	// When config.OS.RootPassword is empty the installer falls back to the
	// default "password" credential rather than skipping SetRootPassword.
	// This guarantees every install yields a working root login even when
	// the device template forgets to set one. See pkg/installer/installer.go
	// installOS() rootPassword default.
	mockOS := new(MockOSInstaller)
	ctx := context.Background()
	config := createTestConfig()
	config.OS.RootPassword = "" // triggers the "password" default

	mockOS.On("InstallBase", ctx, "/mnt").Return(nil)
	mockOS.On("ConfigureSystem", ctx, "/mnt", mock.AnythingOfType("*installer.DiskInfo")).Return(nil)
	mockOS.On("InstallKernel", ctx, "/mnt").Return(nil)
	mockOS.On("SetRootPassword", ctx, "/mnt", "password").Return(nil)
	mockOS.On("InstallPackages", ctx, "/mnt").Return(nil)
	mockOS.On("ExecutePostInstall", ctx, "/mnt").Return(nil)

	inst := &installer{
		config:      config,
		logger:      createTestLogger(),
		osInstaller: mockOS,
	}

	diskInfo := &DiskInfo{Device: "/dev/sda"}
	err := inst.installOS(ctx, diskInfo)
	assert.NoError(t, err)
	mockOS.AssertCalled(t, "SetRootPassword", ctx, "/mnt", "password")
}

func TestInstaller_InstallOS_PackageInstallFails_NoFatalError(t *testing.T) {
	mockOS := new(MockOSInstaller)
	ctx := context.Background()
	config := createTestConfig()

	mockOS.On("InstallBase", ctx, "/mnt").Return(nil)
	mockOS.On("ConfigureSystem", ctx, "/mnt", mock.AnythingOfType("*installer.DiskInfo")).Return(nil)
	mockOS.On("InstallKernel", ctx, "/mnt").Return(nil)
	mockOS.On("SetRootPassword", ctx, "/mnt", "root123").Return(nil)
	mockOS.On("InstallPackages", ctx, "/mnt").Return(errors.New("package not found"))
	mockOS.On("ExecutePostInstall", ctx, "/mnt").Return(nil)

	inst := &installer{
		config:      config,
		logger:      createTestLogger(),
		osInstaller: mockOS,
	}

	diskInfo := &DiskInfo{Device: "/dev/sda"}
	err := inst.installOS(ctx, diskInfo)
	// Package install failure is NOT fatal
	assert.NoError(t, err)
}

// TestInstaller_InstallOS_PostInstallFatal verifies that post-install script
// failures abort the install. Per pkg/installer/installer.go installOS(),
// post-install scripts configure SSH/operator access and a silent failure
// would leave the operator with an unreachable OS — the installer fails
// loudly instead. Scripts that genuinely want to tolerate non-critical
// errors must trap and exit 0 themselves.
func TestInstaller_InstallOS_PostInstallFatal(t *testing.T) {
	mockOS := new(MockOSInstaller)
	ctx := context.Background()
	config := createTestConfig()

	mockOS.On("InstallBase", ctx, "/mnt").Return(nil)
	mockOS.On("ConfigureSystem", ctx, "/mnt", mock.AnythingOfType("*installer.DiskInfo")).Return(nil)
	mockOS.On("InstallKernel", ctx, "/mnt").Return(nil)
	mockOS.On("SetRootPassword", ctx, "/mnt", "root123").Return(nil)
	mockOS.On("InstallPackages", ctx, "/mnt").Return(nil)
	mockOS.On("ExecutePostInstall", ctx, "/mnt").Return(errors.New("script error"))

	inst := &installer{
		config:      config,
		logger:      createTestLogger(),
		osInstaller: mockOS,
	}

	diskInfo := &DiskInfo{Device: "/dev/sda"}
	err := inst.installOS(ctx, diskInfo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "post-install scripts failed")
	assert.Contains(t, err.Error(), "script error")
}

func TestInstaller_InstallOS_WithNetwork(t *testing.T) {
	mockOS := new(MockOSInstaller)
	ctx := context.Background()
	config := createTestConfig()
	config.Network = &NetworkConfig{
		DNS: &DNSConfig{
			Nameservers: []string{"8.8.8.8"},
		},
	}

	mockOS.On("InstallBase", ctx, "/mnt").Return(nil)
	mockOS.On("ConfigureSystem", ctx, "/mnt", mock.AnythingOfType("*installer.DiskInfo")).Return(nil)
	mockOS.On("InstallKernel", ctx, "/mnt").Return(nil)
	mockOS.On("SetRootPassword", ctx, "/mnt", "root123").Return(nil)
	mockOS.On("InstallPackages", ctx, "/mnt").Return(nil)
	mockOS.On("ConfigureNetwork", ctx, "/mnt", config.Network, config.Plan).Return(nil)
	mockOS.On("ExecutePostInstall", ctx, "/mnt").Return(nil)

	inst := &installer{
		config:      config,
		logger:      createTestLogger(),
		osInstaller: mockOS,
	}

	diskInfo := &DiskInfo{Device: "/dev/sda"}
	err := inst.installOS(ctx, diskInfo)
	assert.NoError(t, err)
	mockOS.AssertCalled(t, "ConfigureNetwork", ctx, "/mnt", config.Network, config.Plan)
}

func TestInstaller_InstallOS_NetworkConfigFails_NoFatalError(t *testing.T) {
	mockOS := new(MockOSInstaller)
	ctx := context.Background()
	config := createTestConfig()
	config.Network = &NetworkConfig{
		Interfaces: []InterfaceConfig{
			{Name: "eth0", Type: InterfaceTypeDHCP},
		},
	}

	mockOS.On("InstallBase", ctx, "/mnt").Return(nil)
	mockOS.On("ConfigureSystem", ctx, "/mnt", mock.AnythingOfType("*installer.DiskInfo")).Return(nil)
	mockOS.On("InstallKernel", ctx, "/mnt").Return(nil)
	mockOS.On("SetRootPassword", ctx, "/mnt", "root123").Return(nil)
	mockOS.On("InstallPackages", ctx, "/mnt").Return(nil)
	mockOS.On("ConfigureNetwork", ctx, "/mnt", config.Network, config.Plan).Return(errors.New("network error"))
	mockOS.On("ExecutePostInstall", ctx, "/mnt").Return(nil)

	inst := &installer{
		config:      config,
		logger:      createTestLogger(),
		osInstaller: mockOS,
	}

	diskInfo := &DiskInfo{Device: "/dev/sda"}
	err := inst.installOS(ctx, diskInfo)
	// Network config failure is NOT fatal
	assert.NoError(t, err)
}

// TestInstaller_InstallOS_PlatformNetworkFails_Fatal verifies a host on a
// platform network (network.role set) fails the install when its network
// cannot be configured: it must not boot with forwarding or its host
// firewall in an unknown state.
func TestInstaller_InstallOS_PlatformNetworkFails_Fatal(t *testing.T) {
	mockOS := new(MockOSInstaller)
	ctx := context.Background()
	config := createTestConfig()
	config.Network = &NetworkConfig{Role: HostRoleCompute}

	mockOS.On("InstallBase", ctx, "/mnt").Return(nil)
	mockOS.On("ConfigureSystem", ctx, "/mnt", mock.AnythingOfType("*installer.DiskInfo")).Return(nil)
	mockOS.On("InstallKernel", ctx, "/mnt").Return(nil)
	mockOS.On("SetRootPassword", ctx, "/mnt", "root123").Return(nil)
	mockOS.On("InstallPackages", ctx, "/mnt").Return(nil)
	mockOS.On("ConfigureNetwork", ctx, "/mnt", config.Network, config.Plan).Return(errors.New("sysctl write failed"))

	inst := &installer{
		config:      config,
		logger:      createTestLogger(),
		osInstaller: mockOS,
	}

	err := inst.installOS(ctx, &DiskInfo{Device: "/dev/sda"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "platform host network")
	mockOS.AssertNotCalled(t, "ExecutePostInstall", ctx, "/mnt")
}

// =============================================================================
// installer.go - setupDisk unsupported filesystem type
// =============================================================================

func TestInstaller_SetupDisk_UnsupportedFilesystem(t *testing.T) {
	mockDisk := new(MockDiskManager)
	ctx := context.Background()

	config := &Config{
		Disk: &DiskConfig{
			Device:         "/dev/sda",
			PartitionTable: PartitionTableGPT,
			RootFilesystem: "btrfs", // unsupported
		},
		OS: &OSConfig{OS: OSAlpine},
	}

	mockDisk.On("CreatePartitionTable", ctx, PartitionTableGPT).Return(nil)
	mockDisk.On("CreateEFIPartition", ctx, 0).Return(nil)
	mockDisk.On("CreateRootPartition", ctx).Return(nil)

	inst := &installer{
		config:      config,
		logger:      createTestLogger(),
		diskManager: mockDisk,
	}

	_, err := inst.setupDisk(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported filesystem type")
}

// =============================================================================
// profiles.go - GetProfile coverage for all profile internals
// =============================================================================

func TestGetProfile_AllProfiles_InternalConfig(t *testing.T) {
	profiles := ListProfiles()
	for _, name := range profiles {
		t.Run(name, func(t *testing.T) {
			config, err := GetProfile(name)
			require.NoError(t, err)
			require.NotNil(t, config)

			// Verify disk defaults were applied
			assert.NotEmpty(t, string(config.Disk.PartitionTable))
			assert.Greater(t, config.Disk.EFIPartitionSize, 0)
			assert.NotEmpty(t, string(config.Disk.RootFilesystem))

			// Verify OS defaults were applied
			assert.NotEmpty(t, config.OS.Architecture)
			assert.NotEmpty(t, config.OS.Hostname)
			assert.NotEmpty(t, string(config.OS.FilesystemType))

			// If lockdown is enabled, mode should be set
			if config.OS.Lockdown {
				assert.NotEmpty(t, config.OS.LockdownMode)
			}

			// If TPM is enabled, PCRs should be set
			if config.EnableTPMSealing {
				assert.NotEmpty(t, config.PCRs)
			}
		})
	}
}

func TestGetProfile_DevProfileDebug(t *testing.T) {
	config, err := GetProfile("dev")
	require.NoError(t, err)
	assert.True(t, config.Debug, "dev profile should have Debug enabled")
}

func TestGetProfile_ProductionNotDebug(t *testing.T) {
	config, err := GetProfile("production")
	require.NoError(t, err)
	assert.False(t, config.Debug, "production profile should not have Debug enabled")
}

// =============================================================================
// installer.go - generateOSRelease all OS types
// =============================================================================

func TestGenerateOSRelease_AllTypes(t *testing.T) {
	tests := []struct {
		name     string
		osType   OperatingSystem
		version  string
		contains []string
	}{
		{
			name:    "alpine",
			osType:  OSAlpine,
			version: "3.22",
			contains: []string{
				`NAME="alpine"`,
				`VERSION="3.22"`,
				`ID=alpine`,
				`VERSION_ID="3.22"`,
				"PRETTY_NAME",
			},
		},
		{
			name:    "debian",
			osType:  OSDebian,
			version: "bookworm",
			contains: []string{
				`NAME="debian"`,
				`VERSION="bookworm"`,
			},
		},
		{
			name:    "fedora",
			osType:  OSFedora,
			version: "40",
			contains: []string{
				`NAME="fedora"`,
				`VERSION="40"`,
			},
		},
		{
			name:    "ubuntu",
			osType:  OSUbuntu,
			version: "24.04",
			contains: []string{
				`NAME="ubuntu"`,
				`VERSION="24.04"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &OSConfig{
				OS:      tt.osType,
				Version: tt.version,
			}
			result := generateOSRelease(config)
			for _, expected := range tt.contains {
				assert.Contains(t, result, expected)
			}
			// Should end with newline
			assert.True(t, strings.HasSuffix(result, "\n"))
		})
	}
}

// =============================================================================
// installer.go - NewInstaller with missing OS config
// =============================================================================

func TestNewInstaller_MissingOSConfig(t *testing.T) {
	logger := createTestLogger()
	config := &Config{
		Disk: &DiskConfig{
			Device:         "/dev/sda",
			PartitionTable: PartitionTableGPT,
		},
	}

	_, err := NewInstaller(logger, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OS configuration is required")
}

// =============================================================================
// types.go - FilesystemType constants
// =============================================================================

func TestFilesystemType_Constants(t *testing.T) {
	assert.Equal(t, "lvm", string(FilesystemLVM))
	assert.Equal(t, "ext4", string(FilesystemExt4))
}

// =============================================================================
// config_loader.go - LoadInstallConfig with LVM defaults
// =============================================================================

func TestLoadInstallConfig_LVMDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	yamlContent := `version: "1.0"
disk:
  device: /dev/sda
  filesystem: lvm
os:
  name: alpine
  version: "3.22.2"
security:
  tpm:
    enabled: false
  secure_boot:
    enabled: false
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(yamlContent), 0600))

	cfg, err := LoadInstallConfig(configPath)
	require.NoError(t, err)
	assert.Equal(t, "vg0", cfg.Disk.LVMVolumeGroup)
	assert.Equal(t, "root", cfg.Disk.LVMLogicalVolume)
}

func TestLoadInstallConfig_WithLVMConfig(t *testing.T) {
	tmpDir := t.TempDir()
	yamlContent := `version: "1.0"
disk:
  device: /dev/sda
  filesystem: lvm
  lvm:
    volume_group: myvg
    logical_volume: mylv
os:
  name: alpine
  version: "3.22.2"
security:
  tpm:
    enabled: false
  secure_boot:
    enabled: false
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(yamlContent), 0600))

	cfg, err := LoadInstallConfig(configPath)
	require.NoError(t, err)
	assert.Equal(t, "myvg", cfg.Disk.LVMVolumeGroup)
	assert.Equal(t, "mylv", cfg.Disk.LVMLogicalVolume)
}

func TestLoadInstallConfig_EncryptionDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	yamlContent := `version: "1.0"
disk:
  device: /dev/sda
  encryption:
    enabled: true
    password: test123
os:
  name: alpine
  version: "3.22.2"
security:
  tpm:
    enabled: false
  secure_boot:
    enabled: false
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(yamlContent), 0600))

	cfg, err := LoadInstallConfig(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg.Disk.Encryption)
	assert.Equal(t, "aes-xts-plain64", cfg.Disk.Encryption.Cipher)
	assert.Equal(t, 512, cfg.Disk.Encryption.KeySize)
	assert.Equal(t, "sha256", cfg.Disk.Encryption.Hash)
	assert.Equal(t, "cryptroot", cfg.Disk.Encryption.MappedName)
	assert.Equal(t, "luks2", cfg.Disk.Encryption.Version)
	assert.Equal(t, "test123", cfg.Disk.Encryption.Password)
	assert.Equal(t, "test123", cfg.Disk.Encryption.Passphrase)
}

func TestLoadInstallConfig_OSDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	yamlContent := `version: "1.0"
disk:
  device: /dev/sda
os:
  name: alpine
  version: "3.22.2"
  lockdown: true
security:
  tpm:
    enabled: false
  secure_boot:
    enabled: false
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(yamlContent), 0600))

	cfg, err := LoadInstallConfig(configPath)
	require.NoError(t, err)
	assert.Equal(t, "x86_64", cfg.OS.Architecture)
	assert.Equal(t, "trusted-platform", cfg.OS.Hostname)
	assert.Equal(t, FilesystemLVM, cfg.OS.FilesystemType)
	assert.Equal(t, "confidentiality", cfg.OS.LockdownMode)
}

// =============================================================================
// alpine.go - ConfigureSystem with IMA enabled
// =============================================================================

func TestAlpineInstaller_ConfigureSystem_WithIMAEnabled(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:      OSAlpine,
		Version: "3.22",
		IMA: &IMAConfig{
			Enabled:       true,
			Policy:        "tcb",
			HashAlgorithm: "sha256",
			AuditEnabled:  true,
			AppraiseMode:  "enforce",
			EVM:           true,
		},
	}

	inst, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "etc"), 0755))

	diskInfo := &DiskInfo{
		Device:        "/dev/sda",
		EFIPartition:  "/dev/sda1",
		RootPartition: "/dev/sda2",
	}

	ctx := context.Background()
	err = inst.ConfigureSystem(ctx, tmpDir, diskInfo)
	require.NoError(t, err)

	// Verify IMA was configured
	assert.FileExists(t, filepath.Join(tmpDir, "etc", "ima", "ima-policy"))
	assert.FileExists(t, filepath.Join(tmpDir, "etc", "ima", "ima.conf"))
}

// =============================================================================
// config_generator.go - GenerateInstallConfig with EnableFIDO2
// =============================================================================

func TestGenerateInstallConfig_WithFIDO2(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device: "/dev/sda",
		},
		OS: &OSConfig{
			OS:          OSAlpine,
			Version:     "3.22",
			EnableFIDO2: true,
		},
	}

	data, err := GenerateInstallConfig(config)
	require.NoError(t, err)
	assert.Contains(t, string(data), "fido2")
}

// =============================================================================
// profiles.go - ListProfilesWithDescriptions content check
// =============================================================================

func TestListProfilesWithDescriptions_Content(t *testing.T) {
	profiles := ListProfilesWithDescriptions()
	assert.Len(t, profiles, 4)

	names := make(map[string]bool)
	for _, p := range profiles {
		names[p.Name] = true
		assert.NotEmpty(t, p.Description, "profile %s should have a description", p.Name)
	}

	assert.True(t, names["dev"])
	assert.True(t, names["production"])
	assert.True(t, names["fips"])
	assert.True(t, names["production-hs"])
}

// =============================================================================
// profiles.go - ConfigToYAML and ConfigFromYAML additional coverage
// =============================================================================

func TestConfigToYAML_WithEncryption(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device: "/dev/sda",
			Encryption: &EncryptionConfig{
				Cipher:   "aes-xts-plain64",
				KeySize:  512,
				Password: "secret",
			},
		},
		OS: &OSConfig{
			OS:      OSAlpine,
			Version: "3.22",
		},
	}

	yaml, err := ConfigToYAML(config)
	require.NoError(t, err)
	assert.Contains(t, yaml, "aes-xts-plain64")
}

func TestConfigFromYAML_Empty(t *testing.T) {
	config, err := ConfigFromYAML([]byte("{}"))
	require.NoError(t, err)
	assert.NotNil(t, config)
}
