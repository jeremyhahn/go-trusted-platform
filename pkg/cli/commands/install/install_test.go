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

package install

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	pkgconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

// ============================================================================
// Test Helper Functions
// ============================================================================

func getTestFlagsWithFormat(format cli.OutputFormat) func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: format,
		}
	}
}

// ============================================================================
// Root Command Tests
// ============================================================================

func TestNewCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := NewCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "install", cmd.Use)
	assert.Equal(t, "System installation operations", cmd.Short)
	assert.Contains(t, cmd.Long, "Manage system installation and deployment operations")

	// Verify subcommands are registered
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 3) // system, uki, uki-rebuild

	// Verify key subcommands exist
	expectedCommands := map[string]bool{
		"system":      false,
		"uki":         false,
		"uki-rebuild": false,
	}
	for _, sub := range subcommands {
		if _, ok := expectedCommands[sub.Use]; ok {
			expectedCommands[sub.Use] = true
		}
	}
	for cmdName, found := range expectedCommands {
		assert.True(t, found, "%s subcommand should exist", cmdName)
	}
}

func TestNewCommand_NilFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return nil
	}

	cmd := NewCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "install", cmd.Use)
}

// ============================================================================
// System Command Tests
// ============================================================================

func TestNewSystemCommand(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)

	cmd := newSystemCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "system", cmd.Use)
	assert.Equal(t, "Install complete operating system", cmd.Short)
	assert.Contains(t, cmd.Long, "System installation performs complete OS installation")
}

func TestNewSystemCommand_AllFlagsExist(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newSystemCommand(getFlags)

	// Verify all flags exist
	expectedFlags := []string{
		"config",
		"os",
		"os-version",
		"disk",
		"efi-size",
		"partition-table",
		"filesystem",
		"lvm-vg",
		"lvm-lv",
		"password",
		"root-password",
		"hostname",
		"mirror",
		"automated",
		"fips",
		"lockdown",
		"lockdown-mode",
		"tpm-auto-upgrade-seal",
		"platformd-binary",
		"verbose",
		"debug",
	}

	for _, flagName := range expectedFlags {
		flag := cmd.Flag(flagName)
		require.NotNil(t, flag, "flag %s should exist", flagName)
	}
}

func TestNewSystemCommand_FlagDefaults(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newSystemCommand(getFlags)

	tests := []struct {
		flagName    string
		expectedVal string
	}{
		{"config", ""},
		{"os", "alpine"},
		{"os-version", ""},
		{"disk", ""},
		{"efi-size", "538"},
		{"partition-table", "gpt"},
		{"filesystem", "lvm"},
		{"lvm-vg", "vg0"},
		{"lvm-lv", "root"},
		{"password", ""},
		{"root-password", ""},
		{"hostname", "trusted-platform"},
		{"mirror", ""},
		{"automated", "false"},
		{"fips", "false"},
		{"lockdown", "true"},
		{"lockdown-mode", "confidentiality"},
		{"tpm-auto-upgrade-seal", "true"},
		{"platformd-binary", ""},
		{"verbose", "false"},
		{"debug", "false"},
	}

	for _, tt := range tests {
		t.Run(tt.flagName, func(t *testing.T) {
			flag := cmd.Flag(tt.flagName)
			require.NotNil(t, flag)
			assert.Equal(t, tt.expectedVal, flag.DefValue, "flag %s has incorrect default value", tt.flagName)
		})
	}
}

func TestNewSystemCommand_FlagParsing(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		flagName string
		expected string
	}{
		{
			name:     "custom os",
			args:     []string{"--os", "debian"},
			flagName: "os",
			expected: "debian",
		},
		{
			name:     "custom disk",
			args:     []string{"--disk", "/dev/nvme0n1"},
			flagName: "disk",
			expected: "/dev/nvme0n1",
		},
		{
			name:     "custom efi size",
			args:     []string{"--efi-size", "1024"},
			flagName: "efi-size",
			expected: "1024",
		},
		{
			name:     "partition table mbr",
			args:     []string{"--partition-table", "mbr"},
			flagName: "partition-table",
			expected: "mbr",
		},
		{
			name:     "filesystem ext4",
			args:     []string{"--filesystem", "ext4"},
			flagName: "filesystem",
			expected: "ext4",
		},
		{
			name:     "custom hostname",
			args:     []string{"--hostname", "myserver"},
			flagName: "hostname",
			expected: "myserver",
		},
		{
			name:     "automated mode",
			args:     []string{"--automated"},
			flagName: "automated",
			expected: "true",
		},
		{
			name:     "fips enabled",
			args:     []string{"--fips"},
			flagName: "fips",
			expected: "true",
		},
		{
			name:     "lockdown disabled",
			args:     []string{"--lockdown=false"},
			flagName: "lockdown",
			expected: "false",
		},
		{
			name:     "verbose mode",
			args:     []string{"--verbose"},
			flagName: "verbose",
			expected: "true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newSystemCommand(getTestFlagsWithFormat(cli.OutputFormatJSON))
			err := cmd.ParseFlags(tt.args)
			require.NoError(t, err)

			flag := cmd.Flag(tt.flagName)
			require.NotNil(t, flag)
			assert.Equal(t, tt.expected, flag.Value.String())
		})
	}
}

// ============================================================================
// UKI Command Tests
// ============================================================================

func TestNewUKICommand(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)

	cmd := newUKICommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "uki", cmd.Use)
	assert.Equal(t, "Build a Unified Kernel Image (UKI)", cmd.Short)
	assert.Contains(t, cmd.Long, "Build a Unified Kernel Image by combining kernel, initramfs")
}

func TestNewUKICommand_AllFlagsExist(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newUKICommand(getFlags)

	// Verify all flags exist
	expectedFlags := []string{
		"kernel",
		"initramfs",
		"cmdline",
		"output",
		"osrelease",
		"stub",
		"use-objcopy",
		"verbose",
		"debug",
	}

	for _, flagName := range expectedFlags {
		flag := cmd.Flag(flagName)
		require.NotNil(t, flag, "flag %s should exist", flagName)
	}
}

func TestNewUKICommand_FlagDefaults(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newUKICommand(getFlags)

	tests := []struct {
		flagName    string
		expectedVal string
	}{
		{"kernel", ""},
		{"initramfs", ""},
		{"cmdline", ""},
		{"output", ""},
		{"osrelease", ""},
		{"stub", ""},
		{"use-objcopy", "false"},
		{"verbose", "false"},
		{"debug", "false"},
	}

	for _, tt := range tests {
		t.Run(tt.flagName, func(t *testing.T) {
			flag := cmd.Flag(tt.flagName)
			require.NotNil(t, flag)
			assert.Equal(t, tt.expectedVal, flag.DefValue, "flag %s has incorrect default value", tt.flagName)
		})
	}
}

func TestNewUKICommand_FlagParsing(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		flagName string
		expected string
	}{
		{
			name:     "kernel path",
			args:     []string{"--kernel", "/boot/vmlinuz"},
			flagName: "kernel",
			expected: "/boot/vmlinuz",
		},
		{
			name:     "initramfs path",
			args:     []string{"--initramfs", "/boot/initramfs"},
			flagName: "initramfs",
			expected: "/boot/initramfs",
		},
		{
			name:     "cmdline",
			args:     []string{"--cmdline", "root=/dev/mapper/cryptroot ro"},
			flagName: "cmdline",
			expected: "root=/dev/mapper/cryptroot ro",
		},
		{
			name:     "output path",
			args:     []string{"--output", "/boot/efi/EFI/BOOT/BOOTX64.EFI"},
			flagName: "output",
			expected: "/boot/efi/EFI/BOOT/BOOTX64.EFI",
		},
		{
			name:     "osrelease path",
			args:     []string{"--osrelease", "/etc/os-release"},
			flagName: "osrelease",
			expected: "/etc/os-release",
		},
		{
			name:     "stub path",
			args:     []string{"--stub", "/usr/lib/systemd/boot/efi/linuxx64.efi.stub"},
			flagName: "stub",
			expected: "/usr/lib/systemd/boot/efi/linuxx64.efi.stub",
		},
		{
			name:     "use objcopy",
			args:     []string{"--use-objcopy"},
			flagName: "use-objcopy",
			expected: "true",
		},
		{
			name:     "verbose",
			args:     []string{"--verbose"},
			flagName: "verbose",
			expected: "true",
		},
		{
			name:     "debug",
			args:     []string{"--debug"},
			flagName: "debug",
			expected: "true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newUKICommand(getTestFlagsWithFormat(cli.OutputFormatJSON))
			err := cmd.ParseFlags(tt.args)
			require.NoError(t, err)

			flag := cmd.Flag(tt.flagName)
			require.NotNil(t, flag)
			assert.Equal(t, tt.expected, flag.Value.String())
		})
	}
}

func TestRunUKIBuild_KernelOpenFailed(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	cmdFlags := &ukiFlags{
		kernelPath:    "/nonexistent/vmlinuz",
		initramfsPath: "/nonexistent/initramfs",
		cmdlineStr:    "root=/dev/mapper/cryptroot ro",
		outputPath:    "/tmp/test.efi",
	}

	err := runUKIBuild(flags, cmdFlags)

	require.Error(t, err)
	var kernelErr ErrKernelOpenFailed
	require.ErrorAs(t, err, &kernelErr)
	assert.Equal(t, "/nonexistent/vmlinuz", kernelErr.Path)
}

func TestRunUKIBuild_InitramfsOpenFailed(t *testing.T) {
	// Create a temp kernel file
	tmpDir := t.TempDir()
	kernelPath := filepath.Join(tmpDir, "vmlinuz")
	err := os.WriteFile(kernelPath, []byte("fake kernel"), 0644)
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	cmdFlags := &ukiFlags{
		kernelPath:    kernelPath,
		initramfsPath: "/nonexistent/initramfs",
		cmdlineStr:    "root=/dev/mapper/cryptroot ro",
		outputPath:    "/tmp/test.efi",
	}

	err = runUKIBuild(flags, cmdFlags)

	require.Error(t, err)
	var initramfsErr ErrInitramfsOpenFailed
	require.ErrorAs(t, err, &initramfsErr)
	assert.Equal(t, "/nonexistent/initramfs", initramfsErr.Path)
}

func TestRunUKIBuild_StubOpenFailed(t *testing.T) {
	// Create temp kernel and initramfs files
	tmpDir := t.TempDir()
	kernelPath := filepath.Join(tmpDir, "vmlinuz")
	initramfsPath := filepath.Join(tmpDir, "initramfs")
	err := os.WriteFile(kernelPath, []byte("fake kernel"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(initramfsPath, []byte("fake initramfs"), 0644)
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	cmdFlags := &ukiFlags{
		kernelPath:    kernelPath,
		initramfsPath: initramfsPath,
		cmdlineStr:    "root=/dev/mapper/cryptroot ro",
		outputPath:    filepath.Join(tmpDir, "test.efi"),
		stubPath:      "/nonexistent/stub.efi",
	}

	err = runUKIBuild(flags, cmdFlags)

	require.Error(t, err)
	var stubErr ErrStubOpenFailed
	require.ErrorAs(t, err, &stubErr)
	assert.Equal(t, "/nonexistent/stub.efi", stubErr.Path)
}

func TestRunUKIBuild_WithOSRelease(t *testing.T) {
	// Create temp files
	tmpDir := t.TempDir()
	kernelPath := filepath.Join(tmpDir, "vmlinuz")
	initramfsPath := filepath.Join(tmpDir, "initramfs")
	osReleasePath := filepath.Join(tmpDir, "os-release")
	outputPath := filepath.Join(tmpDir, "test.efi")

	err := os.WriteFile(kernelPath, []byte("fake kernel"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(initramfsPath, []byte("fake initramfs"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(osReleasePath, []byte("NAME=TestOS\nVERSION=1.0\n"), 0644)
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	cmdFlags := &ukiFlags{
		kernelPath:    kernelPath,
		initramfsPath: initramfsPath,
		cmdlineStr:    "root=/dev/mapper/cryptroot ro",
		outputPath:    outputPath,
		osReleasePath: osReleasePath,
		verbose:       true,
	}

	// This will fail at UKI build stage (no real UKI builder for test)
	// but it exercises the os-release reading code path
	err = runUKIBuild(flags, cmdFlags)

	// The function will proceed past os-release reading and fail at BuildFile
	require.Error(t, err)
	var buildErr ErrUKIBuildFailed
	require.ErrorAs(t, err, &buildErr)
}

func TestRunUKIBuild_WithOSReleaseReadFailure(t *testing.T) {
	// Create temp files
	tmpDir := t.TempDir()
	kernelPath := filepath.Join(tmpDir, "vmlinuz")
	initramfsPath := filepath.Join(tmpDir, "initramfs")
	outputPath := filepath.Join(tmpDir, "test.efi")

	err := os.WriteFile(kernelPath, []byte("fake kernel"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(initramfsPath, []byte("fake initramfs"), 0644)
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	cmdFlags := &ukiFlags{
		kernelPath:    kernelPath,
		initramfsPath: initramfsPath,
		cmdlineStr:    "root=/dev/mapper/cryptroot ro",
		outputPath:    outputPath,
		osReleasePath: "/nonexistent/os-release", // This file doesn't exist
		verbose:       true,
	}

	// This will log a warning for os-release but continue
	err = runUKIBuild(flags, cmdFlags)

	// The function will continue past os-release and fail at BuildFile
	require.Error(t, err)
	var buildErr ErrUKIBuildFailed
	require.ErrorAs(t, err, &buildErr)
}

func TestRunUKIBuild_WithObjcopyBuilder(t *testing.T) {
	// Create temp files
	tmpDir := t.TempDir()
	kernelPath := filepath.Join(tmpDir, "vmlinuz")
	initramfsPath := filepath.Join(tmpDir, "initramfs")
	outputPath := filepath.Join(tmpDir, "test.efi")

	err := os.WriteFile(kernelPath, []byte("fake kernel"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(initramfsPath, []byte("fake initramfs"), 0644)
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	cmdFlags := &ukiFlags{
		kernelPath:    kernelPath,
		initramfsPath: initramfsPath,
		cmdlineStr:    "root=/dev/mapper/cryptroot ro",
		outputPath:    outputPath,
		useObjcopy:    true,
		debug:         true,
	}

	// This will use objcopy builder path
	err = runUKIBuild(flags, cmdFlags)

	// The function will fail at BuildFile
	require.Error(t, err)
	var buildErr ErrUKIBuildFailed
	require.ErrorAs(t, err, &buildErr)
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestGetInstallLogger(t *testing.T) {
	tests := []struct {
		name    string
		verbose bool
		debug   bool
	}{
		{
			name:    "default logger",
			verbose: false,
			debug:   false,
		},
		{
			name:    "verbose logger",
			verbose: true,
			debug:   false,
		},
		{
			name:    "debug logger",
			verbose: false,
			debug:   true,
		},
		{
			name:    "debug overrides verbose",
			verbose: true,
			debug:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := getInstallLogger(tt.verbose, tt.debug)
			require.NotNil(t, logger)
		})
	}
}

func TestGetPBKDFForFIPS(t *testing.T) {
	tests := []struct {
		name     string
		fips     bool
		expected string
	}{
		{
			name:     "FIPS enabled",
			fips:     true,
			expected: "pbkdf2",
		},
		{
			name:     "FIPS disabled",
			fips:     false,
			expected: "argon2id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getPBKDFForFIPS(tt.fips)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCreateConfigFromFlags(t *testing.T) {
	tests := []struct {
		name     string
		flags    *systemFlags
		expected func(*testing.T, *installer.Config)
	}{
		{
			name: "alpine with gpt and lvm",
			flags: &systemFlags{
				os:             "alpine",
				disk:           "/dev/sda",
				partitionTable: "gpt",
				filesystem:     "lvm",
				efiSize:        538,
				lvmVG:          "vg0",
				lvmLV:          "root",
				password:       "secret123",
				hostname:       "testhost",
				fips:           false,
				lockdown:       true,
				lockdownMode:   "confidentiality",
			},
			expected: func(t *testing.T, config *installer.Config) {
				assert.Equal(t, installer.OSAlpine, config.OS.OS)
				assert.Equal(t, "/dev/sda", config.Disk.Device)
				assert.Equal(t, installer.PartitionTableGPT, config.Disk.PartitionTable)
				assert.Equal(t, installer.FilesystemLVM, config.Disk.RootFilesystem)
				assert.Equal(t, 538, config.Disk.EFIPartitionSize)
				assert.Equal(t, "vg0", config.Disk.LVMVolumeGroup)
				assert.Equal(t, "root", config.Disk.LVMLogicalVolume)
				assert.Equal(t, "secret123", config.Disk.Encryption.Password)
				assert.Equal(t, "testhost", config.OS.Hostname)
				assert.False(t, config.OS.FIPS)
				assert.True(t, config.OS.Lockdown)
				assert.Equal(t, "confidentiality", config.OS.LockdownMode)
				assert.Equal(t, "argon2id", config.Disk.Encryption.PBKDF)
			},
		},
		{
			name: "debian with mbr and ext4",
			flags: &systemFlags{
				os:             "debian",
				disk:           "/dev/vda",
				partitionTable: "mbr",
				filesystem:     "ext4",
				efiSize:        256,
				password:       "pass",
				hostname:       "debianhost",
				fips:           true,
				lockdown:       false,
			},
			expected: func(t *testing.T, config *installer.Config) {
				assert.Equal(t, installer.OSDebian, config.OS.OS)
				assert.Equal(t, "/dev/vda", config.Disk.Device)
				assert.Equal(t, installer.PartitionTableMBR, config.Disk.PartitionTable)
				assert.Equal(t, installer.FilesystemExt4, config.Disk.RootFilesystem)
				assert.Equal(t, 256, config.Disk.EFIPartitionSize)
				assert.Equal(t, "debianhost", config.OS.Hostname)
				assert.True(t, config.OS.FIPS)
				assert.False(t, config.OS.Lockdown)
				assert.Equal(t, "pbkdf2", config.Disk.Encryption.PBKDF)
			},
		},
		{
			name: "fedora",
			flags: &systemFlags{
				os:             "fedora",
				disk:           "/dev/nvme0n1",
				partitionTable: "gpt",
				filesystem:     "lvm",
				hostname:       "fedorahost",
			},
			expected: func(t *testing.T, config *installer.Config) {
				assert.Equal(t, installer.OSFedora, config.OS.OS)
				assert.Equal(t, "/dev/nvme0n1", config.Disk.Device)
				assert.Equal(t, "fedorahost", config.OS.Hostname)
			},
		},
		{
			name: "ubuntu",
			flags: &systemFlags{
				os:             "ubuntu",
				disk:           "/dev/sdb",
				partitionTable: "gpt",
				filesystem:     "lvm",
				hostname:       "ubuntuhost",
			},
			expected: func(t *testing.T, config *installer.Config) {
				assert.Equal(t, installer.OSUbuntu, config.OS.OS)
				assert.Equal(t, "/dev/sdb", config.Disk.Device)
				assert.Equal(t, "ubuntuhost", config.OS.Hostname)
			},
		},
		{
			name: "unknown os defaults to alpine",
			flags: &systemFlags{
				os:             "unknown",
				disk:           "/dev/sda",
				partitionTable: "unknown",
				filesystem:     "unknown",
			},
			expected: func(t *testing.T, config *installer.Config) {
				assert.Equal(t, installer.OSAlpine, config.OS.OS)
				assert.Equal(t, installer.PartitionTableGPT, config.Disk.PartitionTable)
				assert.Equal(t, installer.FilesystemLVM, config.Disk.RootFilesystem)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createConfigFromFlags(tt.flags)
			require.NotNil(t, config)
			require.NotNil(t, config.Disk)
			require.NotNil(t, config.OS)
			require.NotNil(t, config.Disk.Encryption)
			tt.expected(t, config)
		})
	}
}

// ============================================================================
// Error Type Tests
// ============================================================================

func TestErrDaemonConnectionRequired(t *testing.T) {
	err := ErrDaemonConnectionRequired{Command: "install system"}
	assert.Equal(t, "install system: daemon connection required (dual-mode not yet implemented)", err.Error())
}

func TestErrConfigLoadFailed(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		err      error
		expected string
	}{
		{
			name:     "with path",
			path:     "/etc/platformd/install.yaml",
			err:      errors.New("file not found"),
			expected: "failed to load configuration from /etc/platformd/install.yaml: file not found",
		},
		{
			name:     "without path",
			path:     "",
			err:      errors.New("invalid yaml"),
			expected: "failed to load configuration: invalid yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrConfigLoadFailed{Path: tt.path, Err: tt.err}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestErrConfigValidationFailed(t *testing.T) {
	err := ErrConfigValidationFailed{Err: errors.New("disk device is required")}
	assert.Equal(t, "invalid configuration: disk device is required", err.Error())
}

func TestErrPasswordRequired(t *testing.T) {
	err := ErrPasswordRequired{}
	assert.Equal(t, "password is required in automated mode", err.Error())
}

func TestErrInstallerCreationFailed(t *testing.T) {
	err := ErrInstallerCreationFailed{Err: errors.New("unknown OS")}
	assert.Equal(t, "failed to create installer: unknown OS", err.Error())
}

func TestErrInstallationFailed(t *testing.T) {
	err := ErrInstallationFailed{Err: errors.New("disk full")}
	assert.Equal(t, "installation failed: disk full", err.Error())
}

func TestErrKernelOpenFailed(t *testing.T) {
	err := ErrKernelOpenFailed{Path: "/boot/vmlinuz", Err: errors.New("permission denied")}
	assert.Equal(t, "failed to open kernel /boot/vmlinuz: permission denied", err.Error())
}

func TestErrInitramfsOpenFailed(t *testing.T) {
	err := ErrInitramfsOpenFailed{Path: "/boot/initramfs", Err: errors.New("no such file")}
	assert.Equal(t, "failed to open initramfs /boot/initramfs: no such file", err.Error())
}

func TestErrOSReleaseReadFailed(t *testing.T) {
	err := ErrOSReleaseReadFailed{Path: "/etc/os-release", Err: errors.New("permission denied")}
	assert.Equal(t, "failed to read os-release /etc/os-release: permission denied", err.Error())
}

func TestErrStubOpenFailed(t *testing.T) {
	err := ErrStubOpenFailed{Path: "/usr/lib/stub.efi", Err: errors.New("file not found")}
	assert.Equal(t, "failed to open EFI stub /usr/lib/stub.efi: file not found", err.Error())
}

func TestErrUKIBuildFailed(t *testing.T) {
	err := ErrUKIBuildFailed{Err: errors.New("objcopy failed")}
	assert.Equal(t, "failed to build UKI: objcopy failed", err.Error())
}

// ============================================================================
// Command Args Validation Tests
// ============================================================================

func TestUKICommand_RequiredFlagsMissing(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "missing all required flags",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "missing kernel",
			args:    []string{"--initramfs", "/boot/initramfs", "--cmdline", "test", "--output", "/tmp/test.efi"},
			wantErr: true,
		},
		{
			name:    "missing initramfs",
			args:    []string{"--kernel", "/boot/vmlinuz", "--cmdline", "test", "--output", "/tmp/test.efi"},
			wantErr: true,
		},
		{
			name:    "missing cmdline",
			args:    []string{"--kernel", "/boot/vmlinuz", "--initramfs", "/boot/initramfs", "--output", "/tmp/test.efi"},
			wantErr: true,
		},
		{
			name:    "missing output",
			args:    []string{"--kernel", "/boot/vmlinuz", "--initramfs", "/boot/initramfs", "--cmdline", "test"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newUKICommand(getFlags)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if tt.wantErr {
				require.Error(t, err)
			}
		})
	}
}

func TestSystemCommand_NoArgsAccepted(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newSystemCommand(getFlags)

	// System command should work with no args (uses defaults and config file)
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	// Will fail due to validation, but args are accepted
	require.Error(t, err)
}

// ============================================================================
// Flags Struct Tests
// ============================================================================

func TestSystemFlagsStruct(t *testing.T) {
	flags := &systemFlags{
		config:             "/etc/platformd/install.yaml",
		os:                 "alpine",
		osVersion:          "3.22",
		disk:               "/dev/sda",
		efiSize:            538,
		partitionTable:     "gpt",
		filesystem:         "lvm",
		lvmVG:              "vg0",
		lvmLV:              "root",
		password:           "secret",
		rootPassword:       "rootsecret",
		hostname:           "testhost",
		mirror:             "https://example.com/alpine",
		automated:          true,
		fips:               true,
		lockdown:           true,
		lockdownMode:       "confidentiality",
		tpmAutoUpgradeSeal: true,
		platformdBinary:    "/usr/bin/platformd",
		verbose:            true,
		debug:              true,
	}

	assert.Equal(t, "/etc/platformd/install.yaml", flags.config)
	assert.Equal(t, "alpine", flags.os)
	assert.Equal(t, "3.22", flags.osVersion)
	assert.Equal(t, "/dev/sda", flags.disk)
	assert.Equal(t, 538, flags.efiSize)
	assert.Equal(t, "gpt", flags.partitionTable)
	assert.Equal(t, "lvm", flags.filesystem)
	assert.Equal(t, "vg0", flags.lvmVG)
	assert.Equal(t, "root", flags.lvmLV)
	assert.Equal(t, "secret", flags.password)
	assert.Equal(t, "rootsecret", flags.rootPassword)
	assert.Equal(t, "testhost", flags.hostname)
	assert.Equal(t, "https://example.com/alpine", flags.mirror)
	assert.True(t, flags.automated)
	assert.True(t, flags.fips)
	assert.True(t, flags.lockdown)
	assert.Equal(t, "confidentiality", flags.lockdownMode)
	assert.True(t, flags.tpmAutoUpgradeSeal)
	assert.Equal(t, "/usr/bin/platformd", flags.platformdBinary)
	assert.True(t, flags.verbose)
	assert.True(t, flags.debug)
}

func TestUKIFlagsStruct(t *testing.T) {
	flags := &ukiFlags{
		kernelPath:    "/boot/vmlinuz",
		initramfsPath: "/boot/initramfs",
		cmdlineStr:    "root=/dev/mapper/cryptroot ro",
		outputPath:    "/boot/efi/EFI/BOOT/BOOTX64.EFI",
		osReleasePath: "/etc/os-release",
		stubPath:      "/usr/lib/stub.efi",
		useObjcopy:    true,
		verbose:       true,
		debug:         true,
	}

	assert.Equal(t, "/boot/vmlinuz", flags.kernelPath)
	assert.Equal(t, "/boot/initramfs", flags.initramfsPath)
	assert.Equal(t, "root=/dev/mapper/cryptroot ro", flags.cmdlineStr)
	assert.Equal(t, "/boot/efi/EFI/BOOT/BOOTX64.EFI", flags.outputPath)
	assert.Equal(t, "/etc/os-release", flags.osReleasePath)
	assert.Equal(t, "/usr/lib/stub.efi", flags.stubPath)
	assert.True(t, flags.useObjcopy)
	assert.True(t, flags.verbose)
	assert.True(t, flags.debug)
}

// ============================================================================
// Config Loading Tests
// ============================================================================

func TestLoadConfig_ConfigFileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	nonexistentPath := filepath.Join(tmpDir, "nonexistent.yaml")

	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newSystemCommand(getFlags)

	cmdFlags := &systemFlags{
		config:         nonexistentPath,
		os:             "alpine",
		disk:           "/dev/sda",
		partitionTable: "gpt",
		filesystem:     "lvm",
		lvmVG:          "vg0",
		lvmLV:          "root",
		hostname:       "testhost",
		lockdown:       true,
		lockdownMode:   "confidentiality",
	}

	logger := getInstallLogger(false, false)
	config, err := loadConfig(logger, cmd, cmdFlags)

	// When config file doesn't exist but was explicitly specified, should succeed
	// and create config from flags (since stat will fail)
	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Equal(t, "/dev/sda", config.Disk.Device)
}

func TestLoadConfig_CreatesFromFlagsWhenNoConfigFile(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newSystemCommand(getFlags)

	cmdFlags := &systemFlags{
		config:         "", // No config file specified
		os:             "debian",
		disk:           "/dev/vda",
		partitionTable: "gpt",
		filesystem:     "lvm",
		efiSize:        512,
		lvmVG:          "myvg",
		lvmLV:          "mylv",
		password:       "testpass",
		hostname:       "myhost",
		lockdown:       true,
		lockdownMode:   "integrity",
	}

	logger := getInstallLogger(false, false)
	config, err := loadConfig(logger, cmd, cmdFlags)

	// Default config file (/etc/platformd/install.yaml) likely doesn't exist
	// so it should create from flags
	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Equal(t, "/dev/vda", config.Disk.Device)
	assert.Equal(t, installer.OSDebian, config.OS.OS)
	assert.Equal(t, "myhost", config.OS.Hostname)
}

func TestLoadConfig_LoadsFromExistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "install.yaml")

	// Write a valid config file with the App structure
	configContent := `
disk:
  device: /dev/sda
  partition-table: gpt
  efi-partition-size: 538
  encryption:
    password: filepassword
os:
  os: alpine
  hostname: filehost
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newSystemCommand(getFlags)

	cmdFlags := &systemFlags{
		config: configPath,
	}

	logger := getInstallLogger(false, false)
	config, err := loadConfig(logger, cmd, cmdFlags)

	require.NoError(t, err)
	require.NotNil(t, config)
}

// ============================================================================
// Edge Case Tests
// ============================================================================

func TestCreateConfigFromFlags_EmptyFlags(t *testing.T) {
	flags := &systemFlags{}

	config := createConfigFromFlags(flags)

	require.NotNil(t, config)
	require.NotNil(t, config.Disk)
	require.NotNil(t, config.OS)
	require.NotNil(t, config.Disk.Encryption)

	// Should have defaults for unknown values
	assert.Equal(t, installer.OSAlpine, config.OS.OS)
	assert.Equal(t, installer.PartitionTableGPT, config.Disk.PartitionTable)
	assert.Equal(t, installer.FilesystemLVM, config.Disk.RootFilesystem)
}

func TestNewCommand_VerifyLongDescription(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := NewCommand(getFlags)

	// Verify the long description contains expected content
	assert.Contains(t, cmd.Long, "install subsystem provides tools for")
	assert.Contains(t, cmd.Long, "Complete operating system installation with encryption")
	assert.Contains(t, cmd.Long, "Unified Kernel Image (UKI) building")
}

func TestNewSystemCommand_VerifyExample(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newSystemCommand(getFlags)

	// Verify examples are present
	assert.Contains(t, cmd.Example, "platformctl install system")
	assert.Contains(t, cmd.Example, "--config")
	assert.Contains(t, cmd.Example, "--os alpine")
}

func TestNewUKICommand_VerifyLongDescription(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newUKICommand(getFlags)

	// Verify Long description contains examples (UKI command puts examples in Long field)
	assert.Contains(t, cmd.Long, "platformctl install uki")
	assert.Contains(t, cmd.Long, "--kernel")
	assert.Contains(t, cmd.Long, "--initramfs")
	assert.Contains(t, cmd.Long, "--cmdline")
	assert.Contains(t, cmd.Long, "--output")
}

func TestSystemFlagsVerboseShorthand(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newSystemCommand(getFlags)

	// Test that -v works as shorthand for --verbose
	err := cmd.ParseFlags([]string{"-v"})
	require.NoError(t, err)

	flag := cmd.Flag("verbose")
	require.NotNil(t, flag)
	assert.Equal(t, "true", flag.Value.String())
}

func TestUKIFlagsVerboseShorthand(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newUKICommand(getFlags)

	// Test that -v works as shorthand for --verbose
	err := cmd.ParseFlags([]string{"-v"})
	require.NoError(t, err)

	flag := cmd.Flag("verbose")
	require.NotNil(t, flag)
	assert.Equal(t, "true", flag.Value.String())
}

// ============================================================================
// Config File Loading Tests
// ============================================================================

func TestLoadUnifiedConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")

	// Write invalid YAML
	err := os.WriteFile(configPath, []byte("{{{{invalid yaml"), 0644)
	require.NoError(t, err)

	logger := getInstallLogger(false, false)
	_, err = loadUnifiedConfig(logger, configPath)

	require.Error(t, err)
}

func TestLoadUnifiedConfig_FileNotReadable(t *testing.T) {
	logger := getInstallLogger(false, false)
	_, err := loadUnifiedConfig(logger, "/nonexistent/path/config.yaml")

	require.Error(t, err)
}

// TestLoadUnifiedConfig_StaleNetworkKeyRefused refuses a key the network
// schema no longer has rather than ignoring it.
func TestLoadUnifiedConfig_StaleNetworkKeyRefused(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "stale.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("network:\n  bridges:\n    - name: br-fabric\n      members: [bond0]\n"), 0o644))

	_, err := loadUnifiedConfig(getInstallLogger(false, false), configPath)
	var target *pkgconfig.ErrUnknownConfigKeys
	require.True(t, errors.As(err, &target), "got %v", err)
	assert.Equal(t, "network.bridges[0].members", target.Keys[0].Path)
	assert.Equal(t, 4, target.Keys[0].Line)
}

func TestLoadUnifiedConfig_ValidEmptyConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "empty.yaml")

	// Write valid but empty YAML
	err := os.WriteFile(configPath, []byte("---\n"), 0644)
	require.NoError(t, err)

	logger := getInstallLogger(false, false)
	config, err := loadUnifiedConfig(logger, configPath)

	// Should succeed but return config with nil fields
	require.NoError(t, err)
	require.NotNil(t, config)
}

// ============================================================================
// Command Integration Tests
// ============================================================================

func TestInstallCommandHierarchy(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	rootCmd := NewCommand(getFlags)

	// Find system subcommand
	var systemCmd, ukiCmd *struct{}
	for _, sub := range rootCmd.Commands() {
		switch sub.Use {
		case "system":
			systemCmd = &struct{}{}
		case "uki":
			ukiCmd = &struct{}{}
		}
	}

	assert.NotNil(t, systemCmd, "system subcommand should exist")
	assert.NotNil(t, ukiCmd, "uki subcommand should exist")
}

func TestSystemCommand_MultipleFlagsAtOnce(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newSystemCommand(getFlags)

	args := []string{
		"--os", "debian",
		"--disk", "/dev/nvme0n1",
		"--efi-size", "1024",
		"--partition-table", "gpt",
		"--filesystem", "ext4",
		"--hostname", "myserver",
		"--automated",
		"--fips",
		"--verbose",
	}

	err := cmd.ParseFlags(args)
	require.NoError(t, err)

	assert.Equal(t, "debian", cmd.Flag("os").Value.String())
	assert.Equal(t, "/dev/nvme0n1", cmd.Flag("disk").Value.String())
	assert.Equal(t, "1024", cmd.Flag("efi-size").Value.String())
	assert.Equal(t, "gpt", cmd.Flag("partition-table").Value.String())
	assert.Equal(t, "ext4", cmd.Flag("filesystem").Value.String())
	assert.Equal(t, "myserver", cmd.Flag("hostname").Value.String())
	assert.Equal(t, "true", cmd.Flag("automated").Value.String())
	assert.Equal(t, "true", cmd.Flag("fips").Value.String())
	assert.Equal(t, "true", cmd.Flag("verbose").Value.String())
}

func TestUKICommand_MultipleFlagsAtOnce(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newUKICommand(getFlags)

	args := []string{
		"--kernel", "/boot/vmlinuz",
		"--initramfs", "/boot/initramfs",
		"--cmdline", "root=/dev/mapper/cryptroot ro quiet",
		"--output", "/boot/efi/EFI/BOOT/BOOTX64.EFI",
		"--osrelease", "/etc/os-release",
		"--use-objcopy",
		"--debug",
	}

	err := cmd.ParseFlags(args)
	require.NoError(t, err)

	assert.Equal(t, "/boot/vmlinuz", cmd.Flag("kernel").Value.String())
	assert.Equal(t, "/boot/initramfs", cmd.Flag("initramfs").Value.String())
	assert.Equal(t, "root=/dev/mapper/cryptroot ro quiet", cmd.Flag("cmdline").Value.String())
	assert.Equal(t, "/boot/efi/EFI/BOOT/BOOTX64.EFI", cmd.Flag("output").Value.String())
	assert.Equal(t, "/etc/os-release", cmd.Flag("osrelease").Value.String())
	assert.Equal(t, "true", cmd.Flag("use-objcopy").Value.String())
	assert.Equal(t, "true", cmd.Flag("debug").Value.String())
}

// ============================================================================
// Additional Config Override Tests
// ============================================================================

func TestApplyFlagOverrides_DiskConfig(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newSystemCommand(getFlags)

	// Parse flags to mark them as changed
	args := []string{
		"--disk", "/dev/nvme0n1",
		"--partition-table", "mbr",
		"--efi-size", "1024",
		"--filesystem", "ext4",
		"--lvm-vg", "custom_vg",
		"--lvm-lv", "custom_lv",
	}
	err := cmd.ParseFlags(args)
	require.NoError(t, err)

	// Create base config
	config := &installer.Config{
		Disk: &installer.DiskConfig{
			Device:           "/dev/sda",
			PartitionTable:   installer.PartitionTableGPT,
			EFIPartitionSize: 538,
			RootFilesystem:   installer.FilesystemLVM,
			LVMVolumeGroup:   "vg0",
			LVMLogicalVolume: "root",
		},
		OS: &installer.OSConfig{
			OS:       installer.OSAlpine,
			Hostname: "testhost",
		},
	}

	cmdFlags := &systemFlags{
		disk:           "/dev/nvme0n1",
		partitionTable: "mbr",
		efiSize:        1024,
		filesystem:     "ext4",
		lvmVG:          "custom_vg",
		lvmLV:          "custom_lv",
	}

	logger := getInstallLogger(false, false)
	applyFlagOverrides(logger, config, cmd, cmdFlags)

	assert.Equal(t, "/dev/nvme0n1", config.Disk.Device)
	assert.Equal(t, installer.PartitionTableMBR, config.Disk.PartitionTable)
	assert.Equal(t, 1024, config.Disk.EFIPartitionSize)
	assert.Equal(t, installer.FilesystemExt4, config.Disk.RootFilesystem)
	assert.Equal(t, "custom_vg", config.Disk.LVMVolumeGroup)
	assert.Equal(t, "custom_lv", config.Disk.LVMLogicalVolume)
}

func TestApplyFlagOverrides_OSConfig(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newSystemCommand(getFlags)

	// Parse flags to mark them as changed
	args := []string{
		"--os", "debian",
		"--os-version", "bookworm",
		"--hostname", "myserver",
		"--mirror", "https://example.com/debian",
		"--fips",
		"--lockdown=false",
		"--lockdown-mode", "integrity",
	}
	err := cmd.ParseFlags(args)
	require.NoError(t, err)

	// Create base config
	config := &installer.Config{
		Disk: &installer.DiskConfig{
			Device: "/dev/sda",
		},
		OS: &installer.OSConfig{
			OS:           installer.OSAlpine,
			Version:      "3.22",
			Hostname:     "testhost",
			FIPS:         false,
			Lockdown:     true,
			LockdownMode: "confidentiality",
		},
	}

	cmdFlags := &systemFlags{
		os:           "debian",
		osVersion:    "bookworm",
		hostname:     "myserver",
		mirror:       "https://example.com/debian",
		fips:         true,
		lockdown:     false,
		lockdownMode: "integrity",
	}

	logger := getInstallLogger(false, false)
	applyFlagOverrides(logger, config, cmd, cmdFlags)

	assert.Equal(t, installer.OSDebian, config.OS.OS)
	assert.Equal(t, "bookworm", config.OS.Version)
	assert.Equal(t, "myserver", config.OS.Hostname)
	assert.Equal(t, "https://example.com/debian", config.OS.Mirror)
	assert.True(t, config.OS.FIPS)
	assert.False(t, config.OS.Lockdown)
	assert.Equal(t, "integrity", config.OS.LockdownMode)
}

func TestApplyFlagOverrides_PasswordConfig(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newSystemCommand(getFlags)

	// Parse flags to mark them as changed
	args := []string{
		"--password", "secret123",
		"--root-password", "rootsecret",
	}
	err := cmd.ParseFlags(args)
	require.NoError(t, err)

	// Create base config with nil encryption
	config := &installer.Config{
		Disk: &installer.DiskConfig{
			Device:     "/dev/sda",
			Encryption: nil,
		},
		OS: &installer.OSConfig{
			OS:           installer.OSAlpine,
			RootPassword: "",
		},
	}

	cmdFlags := &systemFlags{
		password:     "secret123",
		rootPassword: "rootsecret",
	}

	logger := getInstallLogger(false, false)
	applyFlagOverrides(logger, config, cmd, cmdFlags)

	require.NotNil(t, config.Disk.Encryption)
	assert.Equal(t, "secret123", config.Disk.Encryption.Password)
	assert.Equal(t, "secret123", config.Disk.Encryption.Passphrase)
	assert.Equal(t, "rootsecret", config.OS.RootPassword)
}

func TestApplyFlagOverrides_TPMConfig(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newSystemCommand(getFlags)

	// Parse flags to mark them as changed
	args := []string{
		"--tpm-auto-upgrade-seal=false",
		"--platformd-binary", "/custom/path/platformd",
	}
	err := cmd.ParseFlags(args)
	require.NoError(t, err)

	// Create base config
	config := &installer.Config{
		Disk: &installer.DiskConfig{
			Device: "/dev/sda",
		},
		OS: &installer.OSConfig{
			OS:                 installer.OSAlpine,
			TPMAutoUpgradeSeal: true,
			PlatformdBinary:    "",
		},
	}

	cmdFlags := &systemFlags{
		tpmAutoUpgradeSeal: false,
		platformdBinary:    "/custom/path/platformd",
	}

	logger := getInstallLogger(false, false)
	applyFlagOverrides(logger, config, cmd, cmdFlags)

	assert.False(t, config.OS.TPMAutoUpgradeSeal)
	assert.Equal(t, "/custom/path/platformd", config.OS.PlatformdBinary)
}

func TestApplyFlagOverrides_OSTypes(t *testing.T) {
	tests := []struct {
		name     string
		osFlag   string
		expected installer.OperatingSystem
	}{
		{"alpine", "alpine", installer.OSAlpine},
		{"debian", "debian", installer.OSDebian},
		{"fedora", "fedora", installer.OSFedora},
		{"ubuntu", "ubuntu", installer.OSUbuntu},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
			cmd := newSystemCommand(getFlags)

			args := []string{"--os", tt.osFlag}
			err := cmd.ParseFlags(args)
			require.NoError(t, err)

			config := &installer.Config{
				Disk: &installer.DiskConfig{Device: "/dev/sda"},
				OS:   &installer.OSConfig{OS: installer.OSAlpine},
			}

			cmdFlags := &systemFlags{os: tt.osFlag}

			logger := getInstallLogger(false, false)
			applyFlagOverrides(logger, config, cmd, cmdFlags)

			assert.Equal(t, tt.expected, config.OS.OS)
		})
	}
}

func TestApplyFlagOverrides_FilesystemTypes(t *testing.T) {
	tests := []struct {
		name     string
		fsFlag   string
		expected installer.FilesystemType
	}{
		{"lvm", "lvm", installer.FilesystemLVM},
		{"ext4", "ext4", installer.FilesystemExt4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
			cmd := newSystemCommand(getFlags)

			args := []string{"--filesystem", tt.fsFlag}
			err := cmd.ParseFlags(args)
			require.NoError(t, err)

			config := &installer.Config{
				Disk: &installer.DiskConfig{Device: "/dev/sda", RootFilesystem: installer.FilesystemLVM},
				OS:   &installer.OSConfig{OS: installer.OSAlpine, FilesystemType: installer.FilesystemLVM},
			}

			cmdFlags := &systemFlags{filesystem: tt.fsFlag}

			logger := getInstallLogger(false, false)
			applyFlagOverrides(logger, config, cmd, cmdFlags)

			assert.Equal(t, tt.expected, config.Disk.RootFilesystem)
			assert.Equal(t, tt.expected, config.OS.FilesystemType)
		})
	}
}

func TestApplyFlagOverrides_PartitionTableTypes(t *testing.T) {
	tests := []struct {
		name     string
		ptFlag   string
		expected installer.PartitionTable
	}{
		{"gpt", "gpt", installer.PartitionTableGPT},
		{"mbr", "mbr", installer.PartitionTableMBR},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
			cmd := newSystemCommand(getFlags)

			args := []string{"--partition-table", tt.ptFlag}
			err := cmd.ParseFlags(args)
			require.NoError(t, err)

			config := &installer.Config{
				Disk: &installer.DiskConfig{Device: "/dev/sda", PartitionTable: installer.PartitionTableGPT},
				OS:   &installer.OSConfig{OS: installer.OSAlpine},
			}

			cmdFlags := &systemFlags{partitionTable: tt.ptFlag}

			logger := getInstallLogger(false, false)
			applyFlagOverrides(logger, config, cmd, cmdFlags)

			assert.Equal(t, tt.expected, config.Disk.PartitionTable)
		})
	}
}

// ============================================================================
// RunSystemInstall Error Handling Tests
// ============================================================================

func TestRunSystemInstall_ConfigValidationFailed(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newSystemCommand(getFlags)

	// Set args to have no disk specified
	err := cmd.ParseFlags([]string{})
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}
	cmdFlags := &systemFlags{
		// No disk specified - validation should fail
		os:       "alpine",
		hostname: "testhost",
	}

	err = runSystemInstall(cmd, flags, cmdFlags)

	require.Error(t, err)
	var validationErr ErrConfigValidationFailed
	require.ErrorAs(t, err, &validationErr)
}

func TestRunSystemInstall_PasswordRequiredInAutomatedMode(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newSystemCommand(getFlags)

	err := cmd.ParseFlags([]string{"--disk", "/dev/sda", "--automated"})
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}
	cmdFlags := &systemFlags{
		disk:      "/dev/sda",
		automated: true,
		os:        "alpine",
		hostname:  "testhost",
		// No password specified in automated mode
	}

	err = runSystemInstall(cmd, flags, cmdFlags)

	require.Error(t, err)
	var pwdErr ErrPasswordRequired
	require.ErrorAs(t, err, &pwdErr)
}

func TestRunSystemInstall_InstallerCreationFailed(t *testing.T) {
	getFlags := getTestFlagsWithFormat(cli.OutputFormatJSON)
	cmd := newSystemCommand(getFlags)

	err := cmd.ParseFlags([]string{"--disk", "/nonexistent/device", "--password", "test"})
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}
	cmdFlags := &systemFlags{
		disk:     "/nonexistent/device",
		password: "test",
		os:       "invalid_os_that_doesnt_exist",
		hostname: "testhost",
	}

	err = runSystemInstall(cmd, flags, cmdFlags)

	require.Error(t, err)
	// Could be either validation error or installer creation error
	// depending on how the installer handles the invalid OS
}

func TestRunSystemInstall_ConfigLoadFailed(t *testing.T) {
	// A config file that exists but does not decode is a hard failure; only
	// an absent file falls back to the command-line flags.
	cmd := newSystemCommand(getTestFlagsWithFormat(cli.OutputFormatJSON))
	cfgPath := filepath.Join(t.TempDir(), "install.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("os: [unclosed\n"), 0o644))

	err := runSystemInstall(cmd, &cli.CommonFlags{}, &systemFlags{config: cfgPath})

	var loadErr ErrConfigLoadFailed
	require.ErrorAs(t, err, &loadErr)
	require.Equal(t, cfgPath, loadErr.Path)
}

// ============================================================================
// Additional UKI Tests for Code Coverage
// ============================================================================

func TestRunUKIBuild_WithDebugLogging(t *testing.T) {
	// Create temp files
	tmpDir := t.TempDir()
	kernelPath := filepath.Join(tmpDir, "vmlinuz")
	initramfsPath := filepath.Join(tmpDir, "initramfs")
	outputPath := filepath.Join(tmpDir, "test.efi")

	err := os.WriteFile(kernelPath, []byte("fake kernel"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(initramfsPath, []byte("fake initramfs"), 0644)
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	cmdFlags := &ukiFlags{
		kernelPath:    kernelPath,
		initramfsPath: initramfsPath,
		cmdlineStr:    "root=/dev/mapper/cryptroot ro",
		outputPath:    outputPath,
		debug:         true, // Enable debug mode
	}

	// This exercises the debug logging path
	err = runUKIBuild(flags, cmdFlags)

	require.Error(t, err)
	var buildErr ErrUKIBuildFailed
	require.ErrorAs(t, err, &buildErr)
}

func TestRunUKIBuild_WithVerboseNotDebug(t *testing.T) {
	// Create temp files
	tmpDir := t.TempDir()
	kernelPath := filepath.Join(tmpDir, "vmlinuz")
	initramfsPath := filepath.Join(tmpDir, "initramfs")
	outputPath := filepath.Join(tmpDir, "test.efi")

	err := os.WriteFile(kernelPath, []byte("fake kernel"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(initramfsPath, []byte("fake initramfs"), 0644)
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	cmdFlags := &ukiFlags{
		kernelPath:    kernelPath,
		initramfsPath: initramfsPath,
		cmdlineStr:    "root=/dev/mapper/cryptroot ro",
		outputPath:    outputPath,
		verbose:       true,
		debug:         false, // Verbose but not debug
	}

	err = runUKIBuild(flags, cmdFlags)

	require.Error(t, err)
	var buildErr ErrUKIBuildFailed
	require.ErrorAs(t, err, &buildErr)
}

func TestRunUKIBuild_WithValidStub(t *testing.T) {
	// Create temp files including a stub
	tmpDir := t.TempDir()
	kernelPath := filepath.Join(tmpDir, "vmlinuz")
	initramfsPath := filepath.Join(tmpDir, "initramfs")
	stubPath := filepath.Join(tmpDir, "stub.efi")
	outputPath := filepath.Join(tmpDir, "test.efi")

	err := os.WriteFile(kernelPath, []byte("fake kernel"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(initramfsPath, []byte("fake initramfs"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(stubPath, []byte("fake stub"), 0644)
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	cmdFlags := &ukiFlags{
		kernelPath:    kernelPath,
		initramfsPath: initramfsPath,
		cmdlineStr:    "root=/dev/mapper/cryptroot ro",
		outputPath:    outputPath,
		stubPath:      stubPath,
		verbose:       true,
	}

	// This should get past stub opening and fail at build
	err = runUKIBuild(flags, cmdFlags)

	require.Error(t, err)
	var buildErr ErrUKIBuildFailed
	require.ErrorAs(t, err, &buildErr)
}
