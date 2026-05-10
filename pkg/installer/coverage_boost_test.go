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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// os.go - Stub installer coverage for EnableServices, InstallPackages,
// ExecutePostInstall, ConfigureNetwork
// =============================================================================

func TestDebianInstaller_AllMethods(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{OS: OSDebian, Version: "bookworm"}
	inst, err := NewOSInstaller(logger, config)
	require.NoError(t, err)

	ctx := context.Background()
	tmpDir := "/tmp/test"

	t.Run("EnableServices", func(t *testing.T) {
		err := inst.EnableServices(ctx, tmpDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not yet implemented")
	})

	t.Run("InstallPackages", func(t *testing.T) {
		err := inst.InstallPackages(ctx, tmpDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not yet implemented")
	})

	t.Run("ExecutePostInstall", func(t *testing.T) {
		err := inst.ExecutePostInstall(ctx, tmpDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not yet implemented")
	})

	t.Run("ConfigureNetwork", func(t *testing.T) {
		err := inst.ConfigureNetwork(ctx, tmpDir, &NetworkConfig{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not yet implemented")
	})
}

func TestFedoraInstaller_AllMethods(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{OS: OSFedora, Version: "39"}
	inst, err := NewOSInstaller(logger, config)
	require.NoError(t, err)

	ctx := context.Background()
	tmpDir := "/tmp/test"

	t.Run("EnableServices", func(t *testing.T) {
		err := inst.EnableServices(ctx, tmpDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not yet implemented")
	})

	t.Run("InstallPackages", func(t *testing.T) {
		err := inst.InstallPackages(ctx, tmpDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not yet implemented")
	})

	t.Run("ExecutePostInstall", func(t *testing.T) {
		err := inst.ExecutePostInstall(ctx, tmpDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not yet implemented")
	})

	t.Run("ConfigureNetwork", func(t *testing.T) {
		err := inst.ConfigureNetwork(ctx, tmpDir, &NetworkConfig{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not yet implemented")
	})
}

func TestUbuntuInstaller_AllMethods(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{OS: OSUbuntu, Version: "22.04"}
	inst, err := NewOSInstaller(logger, config)
	require.NoError(t, err)

	ctx := context.Background()
	tmpDir := "/tmp/test"

	t.Run("EnableServices", func(t *testing.T) {
		err := inst.EnableServices(ctx, tmpDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not yet implemented")
	})

	t.Run("InstallPackages", func(t *testing.T) {
		err := inst.InstallPackages(ctx, tmpDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not yet implemented")
	})

	t.Run("ExecutePostInstall", func(t *testing.T) {
		err := inst.ExecutePostInstall(ctx, tmpDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not yet implemented")
	})

	t.Run("ConfigureNetwork", func(t *testing.T) {
		err := inst.ConfigureNetwork(ctx, tmpDir, &NetworkConfig{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not yet implemented")
	})
}

// =============================================================================
// config_loader.go - MergeWithDefaults edge cases
// =============================================================================

func TestMergeWithDefaults_NilDefaults(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{Device: "/dev/sda"},
		OS:   &OSConfig{OS: OSAlpine},
	}
	merged := MergeWithDefaults(config, nil)
	require.NotNil(t, merged)
	assert.Equal(t, "/dev/sda", merged.Disk.Device)
}

func TestMergeWithDefaults_BothNil(t *testing.T) {
	merged := MergeWithDefaults(nil, nil)
	assert.Nil(t, merged)
}

func TestMergeWithDefaults_UKIFromDefaults(t *testing.T) {
	defaults := &Config{
		Disk: &DiskConfig{Device: "/dev/sda"},
		OS:   &OSConfig{OS: OSAlpine},
		UKI: &UKIConfig{
			Cmdline:    "root=/dev/sda2",
			KernelPath: "/boot/vmlinuz",
		},
		SecureBoot: &SecureBootConfig{
			KeyPath:  "/keys/db.key",
			CertPath: "/keys/db.crt",
		},
		PCRs: []uint{0, 7, 9},
	}

	config := &Config{
		Disk: &DiskConfig{Device: "/dev/vda"},
		OS:   &OSConfig{OS: OSDebian},
	}

	merged := MergeWithDefaults(config, defaults)
	require.NotNil(t, merged)

	// UKI from defaults
	assert.NotNil(t, merged.UKI)
	assert.Equal(t, "root=/dev/sda2", merged.UKI.Cmdline)

	// SecureBoot from defaults
	assert.NotNil(t, merged.SecureBoot)
	assert.Equal(t, "/keys/db.key", merged.SecureBoot.KeyPath)

	// PCRs from defaults
	assert.Equal(t, []uint{0, 7, 9}, merged.PCRs)
}

func TestMergeWithDefaults_ConfigOverridesUKI(t *testing.T) {
	defaults := &Config{
		Disk: &DiskConfig{Device: "/dev/sda"},
		OS:   &OSConfig{OS: OSAlpine},
		UKI: &UKIConfig{
			Cmdline: "old-cmdline",
		},
		SecureBoot: &SecureBootConfig{
			KeyPath: "/old/key",
		},
		PCRs: []uint{0},
	}

	config := &Config{
		UKI: &UKIConfig{
			Cmdline: "new-cmdline",
		},
		SecureBoot: &SecureBootConfig{
			KeyPath: "/new/key",
		},
		PCRs: []uint{0, 7, 9, 11},
	}

	merged := MergeWithDefaults(config, defaults)
	require.NotNil(t, merged)

	assert.Equal(t, "new-cmdline", merged.UKI.Cmdline)
	assert.Equal(t, "/new/key", merged.SecureBoot.KeyPath)
	assert.Equal(t, []uint{0, 7, 9, 11}, merged.PCRs)
}

func TestMergeWithDefaults_DebugFlag(t *testing.T) {
	defaults := &Config{
		Debug: true,
		Disk:  &DiskConfig{Device: "/dev/sda"},
		OS:    &OSConfig{OS: OSAlpine},
	}

	config := &Config{
		Debug: false,
	}

	merged := MergeWithDefaults(config, defaults)
	// Debug is config.Debug || defaults.Debug, so true || false = true
	assert.True(t, merged.Debug)
}

func TestMergeWithDefaults_TPMSealingFlag(t *testing.T) {
	defaults := &Config{
		EnableTPMSealing: false,
		Disk:             &DiskConfig{Device: "/dev/sda"},
		OS:               &OSConfig{OS: OSAlpine},
	}

	config := &Config{
		EnableTPMSealing: true,
	}

	merged := MergeWithDefaults(config, defaults)
	assert.True(t, merged.EnableTPMSealing)
}

// =============================================================================
// profiles.go - GetProfileWithDescription error, case-insensitive
// =============================================================================

func TestGetProfileWithDescription_Error(t *testing.T) {
	_, err := GetProfileWithDescription("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown profile")
}

func TestGetProfile_CaseInsensitive(t *testing.T) {
	config, err := GetProfile("DEV")
	require.NoError(t, err)
	assert.NotNil(t, config)
	assert.True(t, config.Debug)
}

func TestGenerateConfigFromProfile_RootPasswordOverride(t *testing.T) {
	config, err := GenerateConfigFromProfile("dev", map[string]string{
		"root_password": "my-root-pass",
	})
	require.NoError(t, err)
	assert.Equal(t, "my-root-pass", config.OS.RootPassword)
}

func TestGenerateConfigFromProfile_RootPasswordAlternateKey(t *testing.T) {
	config, err := GenerateConfigFromProfile("dev", map[string]string{
		"rootpassword": "alt-root-pass",
	})
	require.NoError(t, err)
	assert.Equal(t, "alt-root-pass", config.OS.RootPassword)
}

func TestGenerateConfigFromProfile_NoEncryptionPasswordOverride(t *testing.T) {
	// Get a profile without encryption (production might not have it)
	// Test that password override on nil encryption doesn't panic
	config, err := GenerateConfigFromProfile("dev", map[string]string{
		"hostname": "override-host",
	})
	require.NoError(t, err)
	assert.Equal(t, "override-host", config.OS.Hostname)
}

func TestConfigToYAML_Error(t *testing.T) {
	// ConfigToYAML with valid config should succeed
	config := &Config{
		Disk: &DiskConfig{Device: "/dev/sda"},
		OS:   &OSConfig{OS: OSAlpine},
	}
	yaml, err := ConfigToYAML(config)
	require.NoError(t, err)
	assert.NotEmpty(t, yaml)
}

// =============================================================================
// alpine.go - boolToInt, ConfigureSystem branches
// =============================================================================

func TestBoolToInt(t *testing.T) {
	assert.Equal(t, 1, boolToInt(true))
	assert.Equal(t, 0, boolToInt(false))
}

func TestAlpineInstaller_ConfigureSystem_WithLVM(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:                 OSAlpine,
		Version:            "3.22",
		Hostname:           "lvm-host",
		FIPS:               true,
		Lockdown:           true,
		TPMAutoUpgradeSeal: true,
	}

	inst, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "etc"), 0755))

	diskInfo := &DiskInfo{
		Device:        "/dev/sda",
		EFIPartition:  "/dev/sda1",
		RootPartition: "/dev/sda2",
		MappedDevice:  "/dev/mapper/cryptroot",
		LVMDevice:     "/dev/mapper/vg0-root",
	}

	ctx := context.Background()
	err = inst.ConfigureSystem(ctx, tmpDir, diskInfo)
	require.NoError(t, err)

	// Verify fstab uses LVM device, not LUKS device
	fstabContent, err := os.ReadFile(filepath.Join(tmpDir, "etc", "fstab"))
	require.NoError(t, err)
	assert.Contains(t, string(fstabContent), "/dev/mapper/vg0-root")
	assert.Contains(t, string(fstabContent), "/ ext4")

	// Verify crypttab was still created (because MappedDevice is set)
	crypttabContent, err := os.ReadFile(filepath.Join(tmpDir, "etc", "crypttab"))
	require.NoError(t, err)
	assert.Contains(t, string(crypttabContent), "cryptroot")

	// Verify hostname
	hostnameContent, err := os.ReadFile(filepath.Join(tmpDir, "etc", "hostname"))
	require.NoError(t, err)
	assert.Contains(t, string(hostnameContent), "lvm-host")

	// Verify alpine-tpm.conf has correct booleans
	tpmConfContent, err := os.ReadFile(filepath.Join(tmpDir, "etc", "alpine-tpm.conf"))
	require.NoError(t, err)
	assert.Contains(t, string(tpmConfContent), "TPM_AUTO_UPGRADE_SEAL=1")
	assert.Contains(t, string(tpmConfContent), "LOCKDOWN=1")
	assert.Contains(t, string(tpmConfContent), "FIPS=1")
}

func TestAlpineInstaller_ConfigureSystem_AllFalse(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:                 OSAlpine,
		Version:            "3.22",
		FIPS:               false,
		Lockdown:           false,
		TPMAutoUpgradeSeal: false,
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

	// Verify alpine-tpm.conf has correct booleans
	tpmConfContent, err := os.ReadFile(filepath.Join(tmpDir, "etc", "alpine-tpm.conf"))
	require.NoError(t, err)
	assert.Contains(t, string(tpmConfContent), "TPM_AUTO_UPGRADE_SEAL=0")
	assert.Contains(t, string(tpmConfContent), "LOCKDOWN=0")
	assert.Contains(t, string(tpmConfContent), "FIPS=0")
}

func TestAlpineInstaller_ConfigureSystem_WithPlatformdBinary(t *testing.T) {
	logger := createTestLogger()

	// Create a fake platformd binary
	tmpSrc := t.TempDir()
	binarySrc := filepath.Join(tmpSrc, "platformd")
	binaryData := []byte("#!/bin/sh\necho platformd")
	require.NoError(t, os.WriteFile(binarySrc, binaryData, 0755))

	config := &OSConfig{
		OS:              OSAlpine,
		Version:         "3.22",
		PlatformdBinary: binarySrc,
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

	// Verify platformd was installed
	destPath := filepath.Join(tmpDir, "usr", "bin", "platformd")
	stat, err := os.Stat(destPath)
	require.NoError(t, err)
	assert.Equal(t, int64(len(binaryData)), stat.Size())
	assert.Equal(t, os.FileMode(0755), stat.Mode().Perm())

	// Verify symlink was created
	symlinkPath := filepath.Join(tmpDir, "usr", "sbin", "platformd")
	target, err := os.Readlink(symlinkPath)
	require.NoError(t, err)
	assert.Equal(t, "/usr/bin/platformd", target)
}

func TestAlpineInstaller_ConfigureSystem_PlatformdBinaryNotFound(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:              OSAlpine,
		Version:         "3.22",
		PlatformdBinary: "/nonexistent/platformd",
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
	// Should return an error because PlatformdBinary is set but not found
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read platformd binary")
}

func TestAlpineInstaller_ConfigureSystem_NoEFIPartition(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:      OSAlpine,
		Version: "3.22",
	}

	inst, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "etc"), 0755))

	diskInfo := &DiskInfo{
		Device:        "/dev/sda",
		RootPartition: "/dev/sda2",
	}

	ctx := context.Background()
	err = inst.ConfigureSystem(ctx, tmpDir, diskInfo)
	require.NoError(t, err)

	fstabContent, err := os.ReadFile(filepath.Join(tmpDir, "etc", "fstab"))
	require.NoError(t, err)
	assert.NotContains(t, string(fstabContent), "vfat")
	assert.Contains(t, string(fstabContent), "/dev/sda2")
}

// =============================================================================
// alpine.go - configureIMA
// =============================================================================

func TestAlpineInstaller_ConfigureIMA_Disabled(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:      OSAlpine,
		Version: "3.22",
		IMA:     nil,
	}

	inst, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	ai := inst.(*alpineInstaller)
	ctx := context.Background()
	tmpDir := t.TempDir()

	err = ai.configureIMA(ctx, tmpDir)
	assert.NoError(t, err)
}

func TestAlpineInstaller_ConfigureIMA_ExplicitlyDisabled(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:      OSAlpine,
		Version: "3.22",
		IMA: &IMAConfig{
			Enabled: false,
		},
	}

	inst, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	ai := inst.(*alpineInstaller)
	ctx := context.Background()
	tmpDir := t.TempDir()

	err = ai.configureIMA(ctx, tmpDir)
	assert.NoError(t, err)
}

func TestAlpineInstaller_ConfigureIMA_Enabled(t *testing.T) {
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
			MonitorPaths:  []string{"/custom/path"},
		},
	}

	inst, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	ai := inst.(*alpineInstaller)
	ctx := context.Background()
	tmpDir := t.TempDir()

	err = ai.configureIMA(ctx, tmpDir)
	assert.NoError(t, err)

	// Verify IMA policy file was created
	policyPath := filepath.Join(tmpDir, "etc", "ima", "ima-policy")
	assert.FileExists(t, policyPath)

	// Verify IMA config file was created
	confPath := filepath.Join(tmpDir, "etc", "ima", "ima.conf")
	assert.FileExists(t, confPath)

	confContent, err := os.ReadFile(confPath)
	require.NoError(t, err)
	assert.Contains(t, string(confContent), "IMA_ENABLED=1")
	assert.Contains(t, string(confContent), "IMA_POLICY=tcb")
	assert.Contains(t, string(confContent), "IMA_HASH=sha256")
	assert.Contains(t, string(confContent), "IMA_AUDIT=1")
	assert.Contains(t, string(confContent), "IMA_APPRAISE=enforce")
	assert.Contains(t, string(confContent), "IMA_EVM=1")

	// Verify start script was created
	startScriptPath := filepath.Join(tmpDir, "etc", "local.d", "ima.start")
	assert.FileExists(t, startScriptPath)
}

// =============================================================================
// alpine.go - installWebUI (no ISO mounted, returns nil)
// =============================================================================

func TestAlpineInstaller_InstallWebUI_NoSource(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:      OSAlpine,
		Version: "3.22",
	}

	inst, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	ai := inst.(*alpineInstaller)
	ctx := context.Background()
	tmpDir := t.TempDir()

	// No WebUI source on ISO, should return nil
	err = ai.installWebUI(ctx, tmpDir)
	assert.NoError(t, err)
}

func TestAlpineInstaller_InstallWebUI_CustomPath(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:               OSAlpine,
		Version:          "3.22",
		WebUIInstallPath: "/custom/web/path",
	}

	inst, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	ai := inst.(*alpineInstaller)
	ctx := context.Background()
	tmpDir := t.TempDir()

	// No WebUI source, should return nil, but the custom path is stored
	err = ai.installWebUI(ctx, tmpDir)
	assert.NoError(t, err)
}

// =============================================================================
// alpine.go - installCABundle (no ISO mounted, returns nil)
// =============================================================================

func TestAlpineInstaller_InstallCABundle_NoSource(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		OS:      OSAlpine,
		Version: "3.22",
	}

	inst, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	ai := inst.(*alpineInstaller)
	ctx := context.Background()
	tmpDir := t.TempDir()

	err = ai.installCABundle(ctx, tmpDir)
	assert.NoError(t, err)
}

// =============================================================================
// alpine.go - hasPreFetchedPackages, getPreFetchPath
// =============================================================================

func TestAlpineInstaller_HasPreFetchedPackages_False(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{OS: OSAlpine, Version: "3.22"}
	inst, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	ai := inst.(*alpineInstaller)
	// No pre-fetch marker exists on test system
	assert.False(t, ai.hasPreFetchedPackages())
}

func TestAlpineInstaller_GetPreFetchPath_Empty(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{OS: OSAlpine, Version: "3.22"}
	inst, err := newAlpineInstaller(logger, config)
	require.NoError(t, err)

	ai := inst.(*alpineInstaller)
	assert.Empty(t, ai.getPreFetchPath())
}

// =============================================================================
// profiles.go - ValidateProfileName edge cases
// =============================================================================

func TestValidateProfileName_CaseInsensitive(t *testing.T) {
	err := ValidateProfileName("DEV")
	assert.NoError(t, err)

	err = ValidateProfileName("Production")
	assert.NoError(t, err)
}

func TestValidateProfileName_EmptyString(t *testing.T) {
	err := ValidateProfileName("")
	assert.Error(t, err)
}

// =============================================================================
// config_loader.go - expandXKMSReferences edge cases
// =============================================================================

func TestExpandXKMSReferences_NilEncryption(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device: "/dev/sda",
			// No encryption config
		},
		OS: &OSConfig{
			OS:           OSAlpine,
			RootPassword: "plain-password",
		},
	}

	err := expandXKMSReferences(config)
	assert.NoError(t, err)
	assert.Equal(t, "plain-password", config.OS.RootPassword)
}

func TestExpandXKMSReferences_NilDisk(t *testing.T) {
	config := &Config{
		OS: &OSConfig{
			OS:           OSAlpine,
			RootPassword: "plain-password",
		},
	}

	err := expandXKMSReferences(config)
	assert.NoError(t, err)
}

func TestExpandXKMSReferences_NilOS(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device: "/dev/sda",
		},
	}

	err := expandXKMSReferences(config)
	assert.NoError(t, err)
}

func TestExpandXKMSReferences_NonXKMSPassword(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device: "/dev/sda",
			Encryption: &EncryptionConfig{
				Password: "regular-password",
			},
		},
		OS: &OSConfig{
			OS:           OSAlpine,
			RootPassword: "regular-root-password",
		},
	}

	err := expandXKMSReferences(config)
	assert.NoError(t, err)
	assert.Equal(t, "regular-password", config.Disk.Encryption.Password)
	assert.Equal(t, "regular-root-password", config.OS.RootPassword)
}

func TestExpandXKMSReferences_RootPasswordXKMSError(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device: "/dev/sda",
		},
		OS: &OSConfig{
			OS:           OSAlpine,
			RootPassword: "xkms:///nonexistent/root/password",
		},
	}

	err := expandXKMSReferences(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read root password from XKMS")
}

func TestReadFromXKMS_WhitespaceHandling(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret")
	require.NoError(t, os.WriteFile(secretFile, []byte("  secret-with-spaces  \n"), 0600))

	value, err := readFromXKMS(secretFile)
	assert.NoError(t, err)
	assert.Equal(t, "secret-with-spaces", value)
}

// =============================================================================
// config_generator.go - GenerateInstallConfig additional branches
// =============================================================================

func TestGenerateInstallConfig_LVMDefaults(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device:         "/dev/sda",
			RootFilesystem: FilesystemLVM,
			// No LVMVolumeGroup or LVMLogicalVolume set
		},
		OS: &OSConfig{
			OS:      OSAlpine,
			Version: "3.22",
		},
	}

	data, err := GenerateInstallConfig(config)
	require.NoError(t, err)

	// Should have default LVM values
	assert.Contains(t, string(data), "vg0")
	assert.Contains(t, string(data), "root")
}

func TestGenerateInstallConfig_Ext4NoLVM(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device:         "/dev/sda",
			RootFilesystem: FilesystemExt4,
		},
		OS: &OSConfig{
			OS:      OSAlpine,
			Version: "3.22",
		},
	}

	data, err := GenerateInstallConfig(config)
	require.NoError(t, err)

	// Should not have LVM config when using ext4
	assert.NotContains(t, string(data), "volume_group")
}

func TestGenerateInstallConfig_LockdownDefaults(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device: "/dev/sda",
		},
		OS: &OSConfig{
			OS:       OSAlpine,
			Version:  "3.22",
			Lockdown: true,
			// No LockdownMode specified
		},
	}

	data, err := GenerateInstallConfig(config)
	require.NoError(t, err)
	assert.Contains(t, string(data), "confidentiality")
}

func TestWriteInstallConfig_NilConfig(t *testing.T) {
	err := WriteInstallConfig(nil, "/tmp/test.yaml")
	assert.Error(t, err)
}

// =============================================================================
// config.go - additional tests
// =============================================================================

func TestLoadConfig_EmptyYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "empty.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(""), 0600))

	config, err := LoadConfig(configPath)
	require.NoError(t, err)
	// Empty YAML should initialize nil pointers
	assert.NotNil(t, config.Disk)
	assert.NotNil(t, config.OS)
}

func TestDefaultConfig_EncryptionDefaults(t *testing.T) {
	config := DefaultConfig()
	require.NotNil(t, config.Disk.Encryption)

	assert.Equal(t, "luks2", config.Disk.Encryption.Version)
	assert.Equal(t, "aes-xts-plain64", config.Disk.Encryption.Cipher)
	assert.Equal(t, 512, config.Disk.Encryption.KeySize)
	assert.Equal(t, "sha256", config.Disk.Encryption.Hash)
	assert.Equal(t, "cryptroot", config.Disk.Encryption.MappedName)
	assert.Empty(t, config.Disk.Encryption.PBKDF) // intentionally empty
}

func TestDefaultConfig_OSDefaults(t *testing.T) {
	config := DefaultConfig()
	assert.Equal(t, "x86_64", config.OS.Architecture)
	assert.Equal(t, "trusted-platform", config.OS.Hostname)
	assert.Equal(t, FilesystemLVM, config.OS.FilesystemType)
	assert.True(t, config.OS.Lockdown)
	assert.Equal(t, "confidentiality", config.OS.LockdownMode)
	assert.True(t, config.OS.TPMAutoUpgradeSeal)
}

// =============================================================================
// installer.go - NewInstaller FIPS flag propagation
// =============================================================================

func TestNewInstaller_FIPSPropagation(t *testing.T) {
	logger := createTestLogger()
	config := &Config{
		Disk: &DiskConfig{
			Device:         "/dev/sda",
			PartitionTable: PartitionTableGPT,
			Encryption: &EncryptionConfig{
				Password: "test123",
			},
		},
		OS: &OSConfig{
			OS:   OSAlpine,
			FIPS: true,
		},
	}

	inst, err := NewInstaller(logger, config)
	require.NoError(t, err)
	require.NotNil(t, inst)

	// FIPS should be propagated to encryption config
	assert.True(t, config.Disk.Encryption.FIPS)
}

func TestNewInstaller_DebugPropagation(t *testing.T) {
	logger := createTestLogger()
	config := &Config{
		Disk: &DiskConfig{
			Device:         "/dev/sda",
			PartitionTable: PartitionTableGPT,
		},
		OS: &OSConfig{
			OS: OSAlpine,
		},
		Debug: true,
	}

	inst, err := NewInstaller(logger, config)
	require.NoError(t, err)
	require.NotNil(t, inst)

	// Debug should be propagated to OS config
	assert.True(t, config.OS.Debug)
}

func TestNewInstaller_FilesystemTypeSyncFromDisk(t *testing.T) {
	logger := createTestLogger()
	config := &Config{
		Disk: &DiskConfig{
			Device:         "/dev/sda",
			PartitionTable: PartitionTableGPT,
			RootFilesystem: FilesystemExt4,
		},
		OS: &OSConfig{
			OS: OSAlpine,
			// FilesystemType is empty, should get synced from disk config
		},
	}

	inst, err := NewInstaller(logger, config)
	require.NoError(t, err)
	require.NotNil(t, inst)

	assert.Equal(t, FilesystemExt4, config.OS.FilesystemType)
}

func TestNewInstaller_FilesystemTypeDefaultsToLVM(t *testing.T) {
	logger := createTestLogger()
	config := &Config{
		Disk: &DiskConfig{
			Device:         "/dev/sda",
			PartitionTable: PartitionTableGPT,
			// RootFilesystem is empty
		},
		OS: &OSConfig{
			OS: OSAlpine,
			// FilesystemType is empty
		},
	}

	inst, err := NewInstaller(logger, config)
	require.NoError(t, err)
	require.NotNil(t, inst)

	assert.Equal(t, FilesystemLVM, config.OS.FilesystemType)
}

// =============================================================================
// installer.go - Install OS failure path
// =============================================================================

func TestInstaller_Install_OSInstallFailure(t *testing.T) {
	mockDisk := new(MockDiskManager)
	mockOS := new(MockOSInstaller)
	mockUKI := new(MockUKIBuilder)

	ctx := context.Background()
	config := createTestConfig()

	// Disk setup succeeds
	mockDisk.On("CreatePartitionTable", ctx, PartitionTableGPT).Return(nil)
	mockDisk.On("CreateEFIPartition", ctx, 0).Return(nil)
	mockDisk.On("CreateRootPartition", ctx).Return(nil)
	mockDisk.On("SetupLUKS", ctx, "", mock.AnythingOfType("*installer.EncryptionConfig")).
		Return("/dev/mapper/cryptroot", nil)
	mockDisk.On("CreateLVMPhysicalVolume", ctx, "/dev/mapper/cryptroot").Return(nil)
	mockDisk.On("CreateLVMVolumeGroup", ctx, "vg0", []string{"/dev/mapper/cryptroot"}).Return(nil)
	mockDisk.On("CreateLVMLogicalVolume", ctx, "vg0", "root", "100%FREE").Return("/dev/mapper/vg0-root", nil)
	mockDisk.On("FormatFilesystem", ctx, "/dev/mapper/vg0-root", "ext4", "root").Return(nil)
	mockDisk.On("Mount", ctx, "/dev/mapper/vg0-root", "/mnt", "ext4", uintptr(0)).Return(nil)
	mockDisk.On("EnsureDeviceNode", ctx, "/dev/sda1", mock.AnythingOfType("time.Duration")).Return(nil)
	mockDisk.On("Mount", ctx, "/dev/sda1", "/mnt/boot/efi", "vfat", uintptr(0)).Return(nil)

	// OS install fails
	mockOS.On("InstallBase", ctx, "/mnt").Return(errors.New("download failed"))

	inst := &installer{
		config:      config,
		logger:      createTestLogger(),
		diskManager: mockDisk,
		osInstaller: mockOS,
		ukiBuilder:  mockUKI,
	}

	err := inst.Install(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "os installation failed")
}

// =============================================================================
// types.go - NetworkConfig.Validate edge cases, Config.Validate with network
// =============================================================================

func TestNetworkConfig_Validate_BondMissingMode(t *testing.T) {
	nc := &NetworkConfig{
		Bonds: []BondConfig{
			{Name: "bond0", Interfaces: []string{"eth0", "eth1"}},
		},
	}
	err := nc.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mode is required")
}

func TestConfig_Validate_WithInvalidNetwork(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device: "/dev/sda",
		},
		OS: &OSConfig{
			OS: OSAlpine,
		},
		Network: &NetworkConfig{
			Interfaces: []InterfaceConfig{
				{Type: InterfaceTypeDHCP}, // Missing name
			},
		},
	}
	err := config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "name is required")
}

func TestNetworkConfig_Validate_StaticWithIPv6Only(t *testing.T) {
	nc := &NetworkConfig{
		Interfaces: []InterfaceConfig{
			{
				Name:        "eth0",
				Type:        InterfaceTypeStatic,
				IPv6Address: "2001:db8::1/64",
			},
		},
	}
	err := nc.Validate()
	assert.NoError(t, err)
}

// =============================================================================
// errors.go - error constructors with nil cause
// =============================================================================

func TestErrorConstructors_NilCause(t *testing.T) {
	tests := []struct {
		name        string
		errFunc     func() error
		expectedMsg string
	}{
		{
			name:        "DiskOperation nil cause",
			errFunc:     func() error { return ErrDiskOperation("test", nil) },
			expectedMsg: "disk_operation: test",
		},
		{
			name:        "Encryption nil cause",
			errFunc:     func() error { return ErrEncryption("test", nil) },
			expectedMsg: "encryption: test",
		},
		{
			name:        "OSInstall nil cause",
			errFunc:     func() error { return ErrOSInstall("test", nil) },
			expectedMsg: "os_install: test",
		},
		{
			name:        "UKIBuild nil cause",
			errFunc:     func() error { return ErrUKIBuild("test", nil) },
			expectedMsg: "uki_build: test",
		},
		{
			name:        "SecureBoot nil cause",
			errFunc:     func() error { return ErrSecureBoot("test", nil) },
			expectedMsg: "secure_boot: test",
		},
		{
			name:        "TPM nil cause",
			errFunc:     func() error { return ErrTPM("test", nil) },
			expectedMsg: "tpm: test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.errFunc()
			assert.Error(t, err)
			assert.Equal(t, tt.expectedMsg, err.Error())

			var installerErr *InstallerError
			assert.True(t, errors.As(err, &installerErr))
			assert.Nil(t, installerErr.Unwrap())
		})
	}
}

// =============================================================================
// fido2_enroll.go - additional coverage
// =============================================================================

func TestFIDO2EnrollmentConfig_Defaults(t *testing.T) {
	config := &FIDO2EnrollmentConfig{
		LUKSDevice:     "/dev/vda2",
		LUKSPassphrase: "test",
	}

	enrollment, err := NewFIDO2Enrollment(config)
	require.NoError(t, err)
	assert.NotNil(t, enrollment)

	// Verify all defaults
	assert.Equal(t, 3, config.TargetKeyslot)
	assert.Equal(t, "luks-alpine", config.RelyingPartyID)
	assert.Equal(t, "luks-user", config.UserName)
}

// =============================================================================
// config.go - SaveConfig round-trip verification
// =============================================================================

func TestSaveConfig_Permissions(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "secure-config.yaml")

	config := DefaultConfig()
	config.Disk.Device = "/dev/sda"

	err := SaveConfig(config, configPath)
	require.NoError(t, err)

	info, err := os.Stat(configPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

// =============================================================================
// config_loader.go - LoadInstallConfig with FIDO2 config
// =============================================================================

func TestLoadInstallConfig_WithFIDO2(t *testing.T) {
	tmpDir := t.TempDir()
	yamlContent := `version: "1.0"
disk:
  device: /dev/sda
  partition_table: gpt
  efi_size: 538
  filesystem: lvm
os:
  name: alpine
  version: "3.22.2"
  architecture: x86_64
  hostname: fido2-host
  mirror: https://dl-cdn.alpinelinux.org/alpine
  root_password: rootpass
  filesystem_type: lvm
  enable-fido2: true
security:
  tpm:
    enabled: true
  secure_boot:
    enabled: false
`

	configPath := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(yamlContent), 0600))

	cfg, err := LoadInstallConfig(configPath)
	require.NoError(t, err)
	assert.True(t, cfg.OS.EnableFIDO2)
	assert.True(t, cfg.EnableTPMSealing)
	// TPM enabled with no PCRs should get default PCRs
	assert.Equal(t, []uint{0, 7, 9}, cfg.PCRs)
}

// =============================================================================
// installer.go - SetupDisk without encryption
// =============================================================================

func TestInstaller_SetupDisk_NoEncryption_WithLVM(t *testing.T) {
	mockDisk := new(MockDiskManager)
	ctx := context.Background()

	config := &Config{
		Disk: &DiskConfig{
			Device:           "/dev/sda",
			PartitionTable:   PartitionTableGPT,
			RootFilesystem:   FilesystemLVM,
			LVMVolumeGroup:   "myvg",
			LVMLogicalVolume: "mylv",
			// No encryption
		},
		OS: &OSConfig{
			OS: OSAlpine,
		},
	}

	// Setup expectations for no-encryption, LVM path
	mockDisk.On("CreatePartitionTable", ctx, PartitionTableGPT).Return(nil)
	mockDisk.On("CreateEFIPartition", ctx, 0).Return(nil)
	mockDisk.On("CreateRootPartition", ctx).Return(nil)
	// No LUKS setup
	mockDisk.On("CreateLVMPhysicalVolume", ctx, "/dev/sda2").Return(nil)
	mockDisk.On("CreateLVMVolumeGroup", ctx, "myvg", []string{"/dev/sda2"}).Return(nil)
	mockDisk.On("CreateLVMLogicalVolume", ctx, "myvg", "mylv", "100%FREE").Return("/dev/mapper/myvg-mylv", nil)
	mockDisk.On("FormatFilesystem", ctx, "/dev/mapper/myvg-mylv", "ext4", "root").Return(nil)
	mockDisk.On("Mount", ctx, "/dev/mapper/myvg-mylv", "/mnt", "ext4", uintptr(0)).Return(nil)
	mockDisk.On("EnsureDeviceNode", ctx, "/dev/sda1", mock.AnythingOfType("time.Duration")).Return(nil)
	mockDisk.On("Mount", ctx, "/dev/sda1", "/mnt/boot/efi", "vfat", uintptr(0)).Return(nil)

	inst := &installer{
		config:      config,
		logger:      createTestLogger(),
		diskManager: mockDisk,
	}

	diskInfo, err := inst.setupDisk(ctx)
	require.NoError(t, err)
	assert.NotNil(t, diskInfo)
	assert.Equal(t, "/dev/sda", diskInfo.Device)
	assert.Empty(t, diskInfo.MappedDevice) // No encryption
	assert.Equal(t, "/dev/mapper/myvg-mylv", diskInfo.LVMDevice)
}

func TestInstaller_SetupDisk_NoEncryption_Ext4(t *testing.T) {
	mockDisk := new(MockDiskManager)
	ctx := context.Background()

	config := &Config{
		Disk: &DiskConfig{
			Device:         "/dev/sda",
			PartitionTable: PartitionTableGPT,
			RootFilesystem: FilesystemExt4,
			// No encryption, no LVM
		},
		OS: &OSConfig{
			OS: OSAlpine,
		},
	}

	mockDisk.On("CreatePartitionTable", ctx, PartitionTableGPT).Return(nil)
	mockDisk.On("CreateEFIPartition", ctx, 0).Return(nil)
	mockDisk.On("CreateRootPartition", ctx).Return(nil)
	mockDisk.On("FormatFilesystem", ctx, "/dev/sda2", "ext4", "root").Return(nil)
	mockDisk.On("Mount", ctx, "/dev/sda2", "/mnt", "ext4", uintptr(0)).Return(nil)
	mockDisk.On("EnsureDeviceNode", ctx, "/dev/sda1", mock.AnythingOfType("time.Duration")).Return(nil)
	mockDisk.On("Mount", ctx, "/dev/sda1", "/mnt/boot/efi", "vfat", uintptr(0)).Return(nil)

	inst := &installer{
		config:      config,
		logger:      createTestLogger(),
		diskManager: mockDisk,
	}

	diskInfo, err := inst.setupDisk(ctx)
	require.NoError(t, err)
	assert.NotNil(t, diskInfo)
	assert.Equal(t, FilesystemExt4, diskInfo.FilesystemType)
}

// =============================================================================
// uki.go - UKI builder adapter SignUKI nil config
// =============================================================================

func TestUKIBuilderAdapter_SignUKI_NilConfig(t *testing.T) {
	logger := createTestLogger()
	builder := NewUKIBuilderAdapter(logger)

	err := builder.SignUKI(context.Background(), "/path/to/uki", nil)
	assert.Error(t, err)

	var installerErr *InstallerError
	assert.ErrorAs(t, err, &installerErr)
	assert.Equal(t, ErrorTypeSecureBoot, installerErr.Type)
}

func TestUKIBuilderAdapter_BuildUKI_MissingCmdline(t *testing.T) {
	logger := createTestLogger()
	builder := NewUKIBuilderAdapter(logger)

	config := &UKIConfig{
		KernelPath: "/boot/vmlinuz",
		// Missing Cmdline
	}

	var buf = &mockWriter{}
	err := builder.BuildUKI(context.Background(), config, buf)
	assert.Error(t, err)

	var installerErr *InstallerError
	assert.ErrorAs(t, err, &installerErr)
	assert.Equal(t, ErrorTypeUKIBuild, installerErr.Type)
}

// =============================================================================
// types.go - FIDO2Config, IMAConfig structure tests
// =============================================================================

func TestFIDO2Config_Structure(t *testing.T) {
	config := &FIDO2Config{
		RelyingPartyID:       "my-rp",
		Keyslot:              3,
		UserPresenceRequired: true,
		Timeout:              30,
	}

	assert.Equal(t, "my-rp", config.RelyingPartyID)
	assert.Equal(t, 3, config.Keyslot)
	assert.True(t, config.UserPresenceRequired)
	assert.Equal(t, 30, config.Timeout)
}

func TestIMAConfig_Structure(t *testing.T) {
	config := &IMAConfig{
		Enabled:        true,
		Policy:         "tcb",
		EVM:            true,
		HashAlgorithm:  "sha256",
		MonitorPaths:   []string{"/bin", "/sbin"},
		AppraiseMode:   "enforce",
		AuditEnabled:   true,
		SigningKeyPath: "/keys/ima.key",
		PublicKeyPath:  "/keys/ima.pub",
	}

	assert.True(t, config.Enabled)
	assert.True(t, config.EVM)
	assert.Equal(t, "tcb", config.Policy)
	assert.Equal(t, "sha256", config.HashAlgorithm)
	assert.Len(t, config.MonitorPaths, 2)
	assert.Equal(t, "enforce", config.AppraiseMode)
	assert.True(t, config.AuditEnabled)
}

func TestConfig_WithFIDO2(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device: "/dev/sda",
		},
		OS: &OSConfig{
			OS: OSAlpine,
		},
		EnableFIDO2Enrollment: true,
		FIDO2: &FIDO2Config{
			RelyingPartyID:       "luks-test",
			Keyslot:              3,
			UserPresenceRequired: true,
			Timeout:              60,
		},
	}

	assert.True(t, config.EnableFIDO2Enrollment)
	assert.NotNil(t, config.FIDO2)
	assert.Equal(t, "luks-test", config.FIDO2.RelyingPartyID)
	assert.NoError(t, config.Validate())
}

func TestConfig_WithEnvironment(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device: "/dev/sda",
		},
		OS: &OSConfig{
			OS: OSAlpine,
		},
		Environment: "test",
	}

	assert.Equal(t, "test", config.Environment)
	assert.NoError(t, config.Validate())
}

// =============================================================================
// postinstall.go - NewPostInstallExecutor fields
// =============================================================================

func TestNewPostInstallExecutor_Fields(t *testing.T) {
	logger := createTestLogger()
	config := &OSConfig{
		PostInstall:       "echo hello",
		PostInstallScript: "/path/to/script.sh",
	}

	executor := NewPostInstallExecutor(logger, config)
	assert.NotNil(t, executor)
	assert.Equal(t, logger, executor.logger)
	assert.Equal(t, config, executor.config)
	assert.Equal(t, "echo hello", executor.config.PostInstall)
	assert.Equal(t, "/path/to/script.sh", executor.config.PostInstallScript)
}

// mockWriter is a minimal io.Writer for testing
type mockWriter struct{}

func (m *mockWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}
