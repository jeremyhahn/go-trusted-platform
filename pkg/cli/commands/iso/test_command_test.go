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
	"bytes"
	"os"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

func TestNewTestCommand_Creation(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newTestCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "test", cmd.Use)
	assert.Equal(t, "Test ISO images in QEMU", cmd.Short)
	assert.Contains(t, cmd.Long, "Test platform ISO images using QEMU")
}

func TestNewTestCommand_HasSubcommands(t *testing.T) {
	cmd := newTestCommand(getTestFlags)

	subcommands := cmd.Commands()
	assert.GreaterOrEqual(t, len(subcommands), 5) // install, firstboot, boot, all, client-server, pxe

	// Verify expected subcommand names exist
	subcommandNames := make(map[string]bool)
	for _, sub := range subcommands {
		subcommandNames[sub.Use] = true
	}

	assert.True(t, subcommandNames["install"], "install subcommand should exist")
	assert.True(t, subcommandNames["firstboot"], "firstboot subcommand should exist")
	assert.True(t, subcommandNames["boot"], "boot subcommand should exist")
	assert.True(t, subcommandNames["all"], "all subcommand should exist")
}

func TestTestFlags_StructFields(t *testing.T) {
	flags := &testFlags{
		iso:         "platform.iso",
		disk:        "disk.qcow2",
		diskSize:    "20G",
		memory:      4096,
		cpus:        4,
		workDir:     "work",
		secureBoot:  true,
		debug:       false,
		fido2Enable: false,
		fido2Mode:   "canokey",
		canoKeyFile: "/tmp/canokey.state",
		canoKeyPcap: "/tmp/canokey.pcap",
		u2fPassthru: "/dev/hidraw0",
		qemuBinary:  "/usr/bin/qemu-system-x86_64",
		networkMode: "user",
	}

	assert.Equal(t, "platform.iso", flags.iso)
	assert.Equal(t, "disk.qcow2", flags.disk)
	assert.Equal(t, "20G", flags.diskSize)
	assert.Equal(t, 4096, flags.memory)
	assert.Equal(t, 4, flags.cpus)
	assert.Equal(t, "work", flags.workDir)
	assert.True(t, flags.secureBoot)
	assert.False(t, flags.debug)
	assert.False(t, flags.fido2Enable)
	assert.Equal(t, "canokey", flags.fido2Mode)
	assert.Equal(t, "/tmp/canokey.state", flags.canoKeyFile)
	assert.Equal(t, "/tmp/canokey.pcap", flags.canoKeyPcap)
	assert.Equal(t, "/dev/hidraw0", flags.u2fPassthru)
	assert.Equal(t, "/usr/bin/qemu-system-x86_64", flags.qemuBinary)
	assert.Equal(t, "user", flags.networkMode)
}

func TestTestInstallSubcommand_FlagsExist(t *testing.T) {
	cmd := newTestCommand(getTestFlags)
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))

	// Find install subcommand
	for _, sub := range cmd.Commands() {
		if sub.Use == "install" {
			sub.SetOut(new(bytes.Buffer))
			sub.SetErr(new(bytes.Buffer))

			// Verify common flags exist
			expectedFlags := []string{
				"disk", "disk-size", "memory", "cpus", "work-dir",
				"secure-boot", "debug",
				"fido2", "fido2-mode", "canokey-file", "canokey-pcap",
				"u2f-device", "qemu-binary", "network",
				"iso", // iso flag specific to install
			}

			for _, flagName := range expectedFlags {
				flag := sub.Flags().Lookup(flagName)
				assert.NotNil(t, flag, "install subcommand should have flag '%s'", flagName)
			}
			return
		}
	}

	t.Fatal("install subcommand not found")
}

func TestTestBootSubcommand_FlagsExist(t *testing.T) {
	cmd := newTestCommand(getTestFlags)

	// Find boot subcommand
	for _, sub := range cmd.Commands() {
		if sub.Use == "boot" {
			sub.SetOut(new(bytes.Buffer))
			sub.SetErr(new(bytes.Buffer))

			// Verify common flags exist
			expectedFlags := []string{
				"disk", "disk-size", "memory", "cpus", "work-dir",
				"secure-boot", "debug",
			}

			for _, flagName := range expectedFlags {
				flag := sub.Flags().Lookup(flagName)
				assert.NotNil(t, flag, "boot subcommand should have flag '%s'", flagName)
			}

			// boot subcommand should NOT have iso flag
			isoFlag := sub.Flags().Lookup("iso")
			assert.Nil(t, isoFlag, "boot subcommand should not have iso flag")
			return
		}
	}

	t.Fatal("boot subcommand not found")
}

func TestTestSubcommands_DefaultValues(t *testing.T) {
	cmd := newTestCommand(getTestFlags)

	for _, sub := range cmd.Commands() {
		if sub.Use == "install" || sub.Use == "boot" || sub.Use == "firstboot" || sub.Use == "all" {
			sub.SetOut(new(bytes.Buffer))
			sub.SetErr(new(bytes.Buffer))

			// Check default values
			diskFlag := sub.Flags().Lookup("disk")
			if diskFlag != nil {
				assert.Equal(t, "alpine-platform-installed.qcow2", diskFlag.DefValue)
			}

			diskSizeFlag := sub.Flags().Lookup("disk-size")
			if diskSizeFlag != nil {
				assert.Equal(t, "10G", diskSizeFlag.DefValue)
			}

			memoryFlag := sub.Flags().Lookup("memory")
			if memoryFlag != nil {
				assert.Equal(t, "8192", memoryFlag.DefValue)
			}

			cpusFlag := sub.Flags().Lookup("cpus")
			if cpusFlag != nil {
				cpuDefault, _ := strconv.Atoi(cpusFlag.DefValue)
				assert.Equal(t, runtime.NumCPU(), cpuDefault)
			}

			workDirFlag := sub.Flags().Lookup("work-dir")
			if workDirFlag != nil {
				assert.Equal(t, "work", workDirFlag.DefValue)
			}

			secureBootFlag := sub.Flags().Lookup("secure-boot")
			if secureBootFlag != nil {
				assert.Equal(t, "true", secureBootFlag.DefValue)
			}

			debugFlag := sub.Flags().Lookup("debug")
			if debugFlag != nil {
				assert.Equal(t, "false", debugFlag.DefValue)
			}

			fido2Flag := sub.Flags().Lookup("fido2")
			if fido2Flag != nil {
				assert.Equal(t, "false", fido2Flag.DefValue)
			}

			fido2ModeFlag := sub.Flags().Lookup("fido2-mode")
			if fido2ModeFlag != nil {
				assert.Equal(t, "canokey", fido2ModeFlag.DefValue)
			}
		}
	}
}

func TestCreateTestQEMUConfig_Basic(t *testing.T) {
	flags := &testFlags{
		disk:       "test.qcow2",
		diskSize:   "10G",
		memory:     4096,
		cpus:       2,
		workDir:    "test-work",
		secureBoot: true,
		debug:      false,
	}

	config := createTestQEMUConfig(flags)

	assert.Equal(t, "test.qcow2", config.DiskPath)
	assert.Equal(t, "10G", config.DiskSize)
	assert.Equal(t, 4096, config.Memory)
	assert.Equal(t, 2, config.CPUs)
	assert.Equal(t, "test-work", config.WorkDir)
	assert.True(t, config.SecureBoot)
	assert.False(t, config.Debug)
	assert.True(t, config.SerialConsole)
	assert.True(t, config.NoGraphic)
}

func TestCreateTestQEMUConfig_WithFIDO2(t *testing.T) {
	flags := &testFlags{
		disk:        "test.qcow2",
		diskSize:    "10G",
		memory:      4096,
		cpus:        2,
		workDir:     "test-work",
		secureBoot:  true,
		debug:       false,
		fido2Enable: true,
		fido2Mode:   "canokey",
		canoKeyFile: "/tmp/canokey.state",
		canoKeyPcap: "/tmp/canokey.pcap",
	}

	config := createTestQEMUConfig(flags)

	assert.NotNil(t, config.FIDO2)
	assert.True(t, config.FIDO2.Enable)
	assert.Equal(t, "canokey", config.FIDO2.Mode)
	assert.Equal(t, "/tmp/canokey.state", config.FIDO2.CanoKeyFile)
	assert.Equal(t, "/tmp/canokey.pcap", config.FIDO2.CanoKeyPcap)
}

func TestCreateTestQEMUConfig_WithNetworkMode(t *testing.T) {
	flags := &testFlags{
		disk:        "test.qcow2",
		diskSize:    "10G",
		memory:      4096,
		cpus:        2,
		workDir:     "test-work",
		secureBoot:  true,
		debug:       false,
		networkMode: "bridge",
	}

	config := createTestQEMUConfig(flags)

	assert.Equal(t, "bridge", config.NetworkMode)
}

func TestCreateTestQEMUConfig_WithCustomQEMUBinary(t *testing.T) {
	flags := &testFlags{
		disk:       "test.qcow2",
		diskSize:   "10G",
		memory:     4096,
		cpus:       2,
		workDir:    "test-work",
		secureBoot: true,
		debug:      false,
		qemuBinary: "/custom/path/to/qemu",
	}

	config := createTestQEMUConfig(flags)

	assert.Equal(t, "/custom/path/to/qemu", config.QEMUBinary)
}

func TestCreateTestQEMUConfig_WithU2FPassthrough(t *testing.T) {
	flags := &testFlags{
		disk:        "test.qcow2",
		diskSize:    "10G",
		memory:      4096,
		cpus:        2,
		workDir:     "test-work",
		secureBoot:  true,
		debug:       false,
		fido2Enable: true,
		fido2Mode:   "u2f-passthru",
		u2fPassthru: "/dev/hidraw0",
	}

	config := createTestQEMUConfig(flags)

	assert.NotNil(t, config.FIDO2)
	assert.Equal(t, "u2f-passthru", config.FIDO2.Mode)
	assert.Equal(t, "/dev/hidraw0", config.FIDO2.PassthruDevice)
}

func TestCreateTestLogger_Debug(t *testing.T) {
	logger := createTestLogger(true)
	assert.NotNil(t, logger)
}

func TestCreateTestLogger_Normal(t *testing.T) {
	logger := createTestLogger(false)
	assert.NotNil(t, logger)
}

func TestCreateTestContext(t *testing.T) {
	ctx, cancel := createTestContext()
	defer cancel()

	assert.NotNil(t, ctx)
	assert.NotNil(t, cancel)

	// Context should not be done yet
	select {
	case <-ctx.Done():
		t.Error("context should not be done yet")
	default:
		// Expected
	}

	// Cancel should work
	cancel()
	<-ctx.Done() // Should not block
}

func TestResolveDefaultISO_NotFound(t *testing.T) {
	// The function should return a name even if file doesn't exist
	result := resolveDefaultISO()
	assert.NotEmpty(t, result)
	assert.Contains(t, result, ".iso")
}

func TestCopyTestFile_FileNotFound(t *testing.T) {
	err := copyTestFile("/nonexistent/source", "/tmp/dest")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read source file")
}

func TestCopyTestFile_DestinationError(t *testing.T) {
	// Create a temp source file
	tmpSrc, err := os.CreateTemp("", "copy-test-src-*")
	require.NoError(t, err)
	defer os.Remove(tmpSrc.Name())

	_, err = tmpSrc.WriteString("test content")
	require.NoError(t, err)
	tmpSrc.Close()

	// Try to copy to an invalid destination
	err = copyTestFile(tmpSrc.Name(), "/nonexistent/directory/file")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write destination file")
}

func TestCopyTestFile_Success(t *testing.T) {
	// Create a temp source file
	tmpSrc, err := os.CreateTemp("", "copy-test-src-*")
	require.NoError(t, err)
	defer os.Remove(tmpSrc.Name())

	content := "test content for copy"
	_, err = tmpSrc.WriteString(content)
	require.NoError(t, err)
	tmpSrc.Close()

	// Create temp destination
	tmpDst, err := os.CreateTemp("", "copy-test-dst-*")
	require.NoError(t, err)
	defer os.Remove(tmpDst.Name())
	tmpDst.Close()

	// Copy file
	err = copyTestFile(tmpSrc.Name(), tmpDst.Name())
	assert.NoError(t, err)

	// Verify content
	dstContent, err := os.ReadFile(tmpDst.Name())
	require.NoError(t, err)
	assert.Equal(t, content, string(dstContent))
}

func TestQEMUDefaultConfig(t *testing.T) {
	// Verify that qemu.DefaultConfig returns a valid config
	config := qemu.DefaultConfig()
	assert.NotNil(t, config)
}
