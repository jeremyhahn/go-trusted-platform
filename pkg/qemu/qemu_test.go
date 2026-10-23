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

package qemu

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVM(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		logger      *logging.Logger
		wantErr     bool
		expectedErr error
	}{
		{
			name:        "nil config",
			config:      nil,
			logger:      logging.DefaultLogger(),
			wantErr:     true,
			expectedErr: nil,
		},
		{
			name: "invalid config - missing disk path",
			config: &Config{
				Memory:   4096,
				CPUs:     2,
				DiskSize: "10G",
				WorkDir:  "work",
			},
			logger:      logging.DefaultLogger(),
			wantErr:     true,
			expectedErr: nil,
		},
		{
			name: "invalid config - zero memory",
			config: &Config{
				DiskPath: "test.qcow2",
				Memory:   0,
				CPUs:     2,
				DiskSize: "10G",
				WorkDir:  "work",
			},
			logger:      logging.DefaultLogger(),
			wantErr:     true,
			expectedErr: nil,
		},
		{
			name: "invalid config - zero CPUs",
			config: &Config{
				DiskPath: "test.qcow2",
				Memory:   4096,
				CPUs:     0,
				DiskSize: "10G",
				WorkDir:  "work",
			},
			logger:      logging.DefaultLogger(),
			wantErr:     true,
			expectedErr: nil,
		},
		{
			name: "invalid config - OVMF not found",
			config: &Config{
				DiskPath: "test.qcow2",
				Memory:   4096,
				CPUs:     2,
				DiskSize: "10G",
				WorkDir:  "work",
				OVMFCode: "/nonexistent/OVMF_CODE.fd",
				OVMFVars: "/nonexistent/OVMF_VARS.fd",
			},
			logger:      logging.DefaultLogger(),
			wantErr:     true,
			expectedErr: ErrOVMFNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vm, err := NewVM(tt.config, tt.logger)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.expectedErr != nil {
					assert.ErrorIs(t, err, tt.expectedErr)
				}
				assert.Nil(t, vm)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, vm)
			}
		})
	}
}

func TestNewVMWithNilLogger(t *testing.T) {
	tmpDir := t.TempDir()

	// Create mock OVMF files
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	config := &Config{
		DiskPath: filepath.Join(tmpDir, "test.qcow2"),
		Memory:   4096,
		CPUs:     2,
		DiskSize: "10G",
		WorkDir:  tmpDir,
		OVMFCode: ovmfCode,
		OVMFVars: ovmfVars,
	}

	// Should create default logger if nil is provided
	vm, err := NewVM(config, nil)
	assert.NoError(t, err)
	assert.NotNil(t, vm)
	assert.NotNil(t, vm.logger)
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.NotNil(t, config)
	assert.Equal(t, 4096, config.Memory)
	assert.Greater(t, config.CPUs, 0)
	assert.Equal(t, "work", config.WorkDir)
	assert.Equal(t, "10G", config.DiskSize)
	assert.True(t, config.EnableKVM)
	assert.True(t, config.SerialConsole)
	assert.True(t, config.NoGraphic)
	assert.False(t, config.SecureBoot)
	assert.False(t, config.PXEEnabled)
	assert.Equal(t, "d", config.BootOrder)
	// NetworkMode is auto-detected: "bridge" if br-int bridge exists, otherwise "user"
	assert.Contains(t, []string{"user", "bridge"}, config.NetworkMode)
}

func TestConfigValidate(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	// Create mock OVMF files
	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				DiskPath: "test.qcow2",
				Memory:   4096,
				CPUs:     2,
				DiskSize: "10G",
				WorkDir:  "work",
				OVMFCode: ovmfCode,
				OVMFVars: ovmfVars,
			},
			wantErr: false,
		},
		{
			name: "missing disk path",
			config: &Config{
				Memory:   4096,
				CPUs:     2,
				DiskSize: "10G",
				WorkDir:  "work",
			},
			wantErr: true,
		},
		{
			name: "invalid memory",
			config: &Config{
				DiskPath: "test.qcow2",
				Memory:   -1,
				CPUs:     2,
				DiskSize: "10G",
				WorkDir:  "work",
			},
			wantErr: true,
		},
		{
			name: "invalid CPUs",
			config: &Config{
				DiskPath: "test.qcow2",
				Memory:   4096,
				CPUs:     -1,
				DiskSize: "10G",
				WorkDir:  "work",
			},
			wantErr: true,
		},
		{
			name: "missing disk size",
			config: &Config{
				DiskPath: "test.qcow2",
				Memory:   4096,
				CPUs:     2,
				WorkDir:  "work",
			},
			wantErr: true,
		},
		{
			name: "missing work dir",
			config: &Config{
				DiskPath: "test.qcow2",
				Memory:   4096,
				CPUs:     2,
				DiskSize: "10G",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigGetNVRAMPath(t *testing.T) {
	config := &Config{
		WorkDir: "/test/work",
	}

	expected := "/test/work/nvram/OVMF_VARS.fd"
	assert.Equal(t, expected, config.GetNVRAMPath())
}

func TestConfigGetOVMFCodePath(t *testing.T) {
	tests := []struct {
		name       string
		secureBoot bool
		expected   string
	}{
		{
			name:       "regular OVMF",
			secureBoot: false,
			expected:   "/usr/share/OVMF/OVMF_CODE.fd",
		},
		{
			name:       "secure boot OVMF",
			secureBoot: true,
			expected:   "/usr/share/OVMF/OVMF_CODE.secboot.fd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				SecureBoot:     tt.secureBoot,
				OVMFCode:       "/usr/share/OVMF/OVMF_CODE.fd",
				OVMFCodeSecure: "/usr/share/OVMF/OVMF_CODE.secboot.fd",
			}

			assert.Equal(t, tt.expected, config.GetOVMFCodePath())
		})
	}
}

func TestConfigGetTPMSocketPath(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected string
	}{
		{
			name: "custom TPM socket",
			config: &Config{
				TPMSocket: "/custom/tpm.sock",
				WorkDir:   "/test/work",
			},
			expected: "/custom/tpm.sock",
		},
		{
			name: "default TPM socket",
			config: &Config{
				WorkDir: "/test/work",
			},
			expected: "/test/work/tpm/swtpm.sock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.config.GetTPMSocketPath())
		})
	}
}

func TestVMIsRunning(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	config := &Config{
		DiskPath: filepath.Join(tmpDir, "test.qcow2"),
		Memory:   4096,
		CPUs:     2,
		DiskSize: "10G",
		WorkDir:  tmpDir,
		OVMFCode: ovmfCode,
		OVMFVars: ovmfVars,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	// Initially not running
	assert.False(t, vm.IsRunning())

	// Simulate running state
	vm.running.Store(true)
	assert.True(t, vm.IsRunning())

	// Stop
	vm.running.Store(false)
	assert.False(t, vm.IsRunning())
}

func TestVMGetPID(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	config := &Config{
		DiskPath: filepath.Join(tmpDir, "test.qcow2"),
		Memory:   4096,
		CPUs:     2,
		DiskSize: "10G",
		WorkDir:  tmpDir,
		OVMFCode: ovmfCode,
		OVMFVars: ovmfVars,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	// Initially no PID
	assert.Equal(t, 0, vm.GetPID())
}

func TestVMGetConfig(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	config := &Config{
		DiskPath: filepath.Join(tmpDir, "test.qcow2"),
		Memory:   4096,
		CPUs:     2,
		DiskSize: "10G",
		WorkDir:  tmpDir,
		OVMFCode: ovmfCode,
		OVMFVars: ovmfVars,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	assert.Equal(t, config, vm.GetConfig())
}

func TestBootModeIsValid(t *testing.T) {
	tests := []struct {
		mode  BootMode
		valid bool
	}{
		{BootModeInstall, true},
		{BootModeBoot, true},
		{BootModePXE, true},
		{BootMode("invalid"), false},
		{BootMode(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.mode.IsValid())
		})
	}
}

func TestBootModeString(t *testing.T) {
	tests := []struct {
		mode     BootMode
		expected string
	}{
		{BootModeInstall, "install"},
		{BootModeBoot, "boot"},
		{BootModePXE, "pxe"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.mode.String())
		})
	}
}

func TestVMStartErrors(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	tests := []struct {
		name        string
		config      *Config
		mode        string
		setupFunc   func(*Config, string) error
		expectedErr error
	}{
		{
			name: "invalid mode",
			config: &Config{
				DiskPath: filepath.Join(tmpDir, "test.qcow2"),
				Memory:   4096,
				CPUs:     2,
				DiskSize: "10G",
				WorkDir:  tmpDir,
				OVMFCode: ovmfCode,
				OVMFVars: ovmfVars,
			},
			mode:        "invalid",
			expectedErr: ErrInvalidMode,
		},
		{
			name: "install mode - ISO not found",
			config: &Config{
				ISO:      filepath.Join(tmpDir, "nonexistent.iso"),
				DiskPath: filepath.Join(tmpDir, "test.qcow2"),
				Memory:   4096,
				CPUs:     2,
				DiskSize: "10G",
				WorkDir:  tmpDir,
				OVMFCode: ovmfCode,
				OVMFVars: ovmfVars,
			},
			mode:        "install",
			expectedErr: ErrISONotFound,
		},
		{
			name: "boot mode - disk not found",
			config: &Config{
				DiskPath: filepath.Join(tmpDir, "nonexistent.qcow2"),
				Memory:   4096,
				CPUs:     2,
				DiskSize: "10G",
				WorkDir:  tmpDir,
				OVMFCode: ovmfCode,
				OVMFVars: ovmfVars,
			},
			mode:        "boot",
			expectedErr: ErrDiskNotFound,
		},
		{
			name: "pxe mode - network disabled",
			config: &Config{
				DiskPath:    filepath.Join(tmpDir, "test.qcow2"),
				Memory:      4096,
				CPUs:        2,
				DiskSize:    "10G",
				WorkDir:     tmpDir,
				OVMFCode:    ovmfCode,
				OVMFVars:    ovmfVars,
				NetworkMode: "none",
			},
			mode:        "pxe",
			expectedErr: ErrPXENetworkRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vm, err := NewVM(tt.config, logging.DefaultLogger())
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			err = vm.Start(ctx, tt.mode)
			assert.Error(t, err)
			if tt.expectedErr != nil {
				assert.ErrorIs(t, err, tt.expectedErr)
			}
		})
	}
}

func TestVMStartPXEMode(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	nvramDir := filepath.Join(tmpDir, "nvram")
	diskPath := filepath.Join(tmpDir, "test.qcow2")

	// Create mock files
	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))
	require.NoError(t, os.MkdirAll(nvramDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(nvramDir, "OVMF_VARS.fd"), []byte("mock"), 0644))

	config := &Config{
		DiskPath:    diskPath,
		Memory:      2048,
		CPUs:        2,
		DiskSize:    "1G",
		WorkDir:     tmpDir,
		OVMFCode:    ovmfCode,
		OVMFVars:    ovmfVars,
		NetworkMode: "user",
		PXEEnabled:  true,
		PXEServerIP: "192.168.1.100",
		Debug:       true,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	ctx := context.Background()
	cmd, err := vm.buildQEMUCommand(ctx, BootModePXE)
	require.NoError(t, err)

	// Verify PXE boot arguments
	var foundNetworkBoot bool
	for i, arg := range cmd.Args {
		if arg == "-boot" && i+1 < len(cmd.Args) {
			// Should contain "order=n" for network boot
			assert.Contains(t, cmd.Args[i+1], "order=n")
			foundNetworkBoot = true
			break
		}
	}
	assert.True(t, foundNetworkBoot, "Network boot argument not found")

	// Verify network device is configured
	var foundNetdev bool
	for i, arg := range cmd.Args {
		if arg == "-netdev" && i+1 < len(cmd.Args) {
			foundNetdev = true
			break
		}
	}
	assert.True(t, foundNetdev, "Network device not configured for PXE boot")
}

func TestVMStopNotRunning(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	config := &Config{
		DiskPath: filepath.Join(tmpDir, "test.qcow2"),
		Memory:   4096,
		CPUs:     2,
		DiskSize: "10G",
		WorkDir:  tmpDir,
		OVMFCode: ovmfCode,
		OVMFVars: ovmfVars,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	err = vm.Stop()
	assert.ErrorIs(t, err, ErrVMNotRunning)
}

func TestVMWaitNotRunning(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	config := &Config{
		DiskPath: filepath.Join(tmpDir, "test.qcow2"),
		Memory:   4096,
		CPUs:     2,
		DiskSize: "10G",
		WorkDir:  tmpDir,
		OVMFCode: ovmfCode,
		OVMFVars: ovmfVars,
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	err = vm.Wait()
	assert.ErrorIs(t, err, ErrVMNotRunning)
}

// A QEMU that exits with an error explains why on stderr (here: no KVM);
// Wait carries that reason in its error so the exit can be reported.
func TestVMWaitCarriesStderr(t *testing.T) {
	vm := startFakeQEMU(t, "#!/bin/sh\necho 'qemu-system-x86_64: failed to initialize kvm: No such file or directory' >&2\nexit 1\n")

	err := vm.Wait()

	require.ErrorIs(t, err, ErrQEMUFailed)
	assert.Contains(t, err.Error(), "exit status 1")
	assert.Contains(t, err.Error(), "failed to initialize kvm: No such file or directory")
	assert.False(t, vm.IsRunning())
}

func TestVMWaitCleanExitIsNil(t *testing.T) {
	vm := startFakeQEMU(t, "#!/bin/sh\nexit 0\n")

	require.NoError(t, vm.Wait())
	assert.False(t, vm.IsRunning())
}

// startFakeQEMU starts a VM whose QEMU binary is the given shell script.
func startFakeQEMU(t *testing.T, script string) *VM {
	t.Helper()
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	disk := filepath.Join(tmpDir, "test.qcow2")
	qemuBinary := filepath.Join(tmpDir, "qemu-system-x86_64")
	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(disk, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(qemuBinary, []byte(script), 0755))

	vm, err := NewVM(&Config{
		DiskPath:    disk,
		Memory:      4096,
		CPUs:        2,
		DiskSize:    "10G",
		WorkDir:     tmpDir,
		OVMFCode:    ovmfCode,
		OVMFVars:    ovmfVars,
		QEMUBinary:  qemuBinary,
		NetworkMode: "none",
	}, logging.DefaultLogger())
	require.NoError(t, err)
	require.NoError(t, vm.Start(context.Background(), string(BootModeBoot)))
	return vm
}

func TestBuildFIDO2Args(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")

	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))

	tests := []struct {
		name        string
		fido2Config *FIDO2Config
		wantErr     bool
		wantArgs    bool
		checkArgs   func([]string) bool
	}{
		{
			name:        "nil FIDO2 config",
			fido2Config: nil,
			wantErr:     false,
			wantArgs:    false,
		},
		{
			name: "FIDO2 disabled",
			fido2Config: &FIDO2Config{
				Enable: false,
				Mode:   "canokey",
			},
			wantErr:  false,
			wantArgs: false,
		},
		{
			name: "CanoKey mode default",
			fido2Config: &FIDO2Config{
				Enable: true,
				Mode:   "canokey",
			},
			wantErr:  false,
			wantArgs: true,
			checkArgs: func(args []string) bool {
				// Should contain -usb and -device canokey,...
				hasUSB := false
				hasCanoKey := false
				for i, arg := range args {
					if arg == "-usb" {
						hasUSB = true
					}
					if arg == "-device" && i+1 < len(args) && len(args[i+1]) > 7 && args[i+1][:7] == "canokey" {
						hasCanoKey = true
					}
				}
				return hasUSB && hasCanoKey
			},
		},
		{
			name: "CanoKey mode with pcap",
			fido2Config: &FIDO2Config{
				Enable:      true,
				Mode:        "canokey",
				CanoKeyPcap: "/tmp/fido2.pcap",
			},
			wantErr:  false,
			wantArgs: true,
			checkArgs: func(args []string) bool {
				for _, arg := range args {
					if len(arg) > 7 && arg[:7] == "canokey" {
						return true
					}
				}
				return false
			},
		},
		{
			name: "U2F emulated mode",
			fido2Config: &FIDO2Config{
				Enable: true,
				Mode:   "u2f-emulated",
			},
			wantErr:  false,
			wantArgs: true,
			checkArgs: func(args []string) bool {
				for _, arg := range args {
					if arg == "u2f-emulated" {
						return true
					}
				}
				return false
			},
		},
		{
			name: "U2F passthrough mode",
			fido2Config: &FIDO2Config{
				Enable: true,
				Mode:   "u2f-passthru",
			},
			wantErr:  false,
			wantArgs: true,
			checkArgs: func(args []string) bool {
				for _, arg := range args {
					if arg == "u2f-passthru" {
						return true
					}
				}
				return false
			},
		},
		{
			name: "U2F passthrough mode with device",
			fido2Config: &FIDO2Config{
				Enable:         true,
				Mode:           "u2f-passthru",
				PassthruDevice: "/dev/hidraw0",
			},
			wantErr:  false,
			wantArgs: true,
			checkArgs: func(args []string) bool {
				for _, arg := range args {
					if arg == "u2f-passthru,hidraw=/dev/hidraw0" {
						return true
					}
				}
				return false
			},
		},
		{
			name: "Invalid FIDO2 mode",
			fido2Config: &FIDO2Config{
				Enable: true,
				Mode:   "invalid-mode",
			},
			wantErr:  true,
			wantArgs: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				DiskPath: filepath.Join(tmpDir, "test.qcow2"),
				Memory:   4096,
				CPUs:     2,
				DiskSize: "10G",
				WorkDir:  tmpDir,
				OVMFCode: ovmfCode,
				OVMFVars: ovmfVars,
				FIDO2:    tt.fido2Config,
			}

			vm, err := NewVM(config, logging.DefaultLogger())
			require.NoError(t, err)

			args, err := vm.buildFIDO2Args()

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.wantArgs {
					assert.NotEmpty(t, args)
					if tt.checkArgs != nil {
						assert.True(t, tt.checkArgs(args), "Args check failed for: %v", args)
					}
				} else {
					assert.Empty(t, args)
				}
			}
		})
	}
}

func TestPortForwardString(t *testing.T) {
	tests := []struct {
		name     string
		pf       PortForward
		expected string
	}{
		{
			name: "TCP port forward with default protocol",
			pf: PortForward{
				HostPort:  8443,
				GuestPort: 8443,
			},
			expected: "hostfwd=tcp::8443-:8443",
		},
		{
			name: "TCP port forward with explicit protocol",
			pf: PortForward{
				HostPort:  8080,
				GuestPort: 80,
				Protocol:  "tcp",
			},
			expected: "hostfwd=tcp::8080-:80",
		},
		{
			name: "UDP port forward",
			pf: PortForward{
				HostPort:  8053,
				GuestPort: 53,
				Protocol:  "udp",
			},
			expected: "hostfwd=udp::8053-:53",
		},
		{
			name: "port forward with host address",
			pf: PortForward{
				HostPort:  8443,
				GuestPort: 443,
				Protocol:  "tcp",
				HostAddr:  "127.0.0.1",
			},
			expected: "hostfwd=tcp:127.0.0.1:8443-:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.pf.String())
		})
	}
}

func TestDefaultPortForwards(t *testing.T) {
	pfs := DefaultPortForwards()

	// Verify we have all the expected port forwards
	assert.NotEmpty(t, pfs)

	// Check for required ports
	ports := make(map[string]bool)
	for _, pf := range pfs {
		key := pf.Protocol + ":" + string(rune(pf.HostPort))
		ports[key] = true
	}

	// Verify expected ports are present by checking the slice
	foundPorts := make(map[int]map[string]bool)
	for _, pf := range pfs {
		if foundPorts[pf.HostPort] == nil {
			foundPorts[pf.HostPort] = make(map[string]bool)
		}
		foundPorts[pf.HostPort][pf.Protocol] = true
	}

	// Server public HTTP/HTTPS (8xxx range)
	assert.True(t, foundPorts[8080]["tcp"], "Missing TCP 8080 (server public HTTP)")
	assert.True(t, foundPorts[8443]["tcp"], "Missing TCP 8443 (server public HTTPS)")

	// Server internal HTTP/HTTPS (9xxx range)
	assert.True(t, foundPorts[9080]["tcp"], "Missing TCP 9080 (server internal HTTP)")
	assert.True(t, foundPorts[9443]["tcp"], "Missing TCP 9443 (server internal HTTPS)")

	// DNS - both TCP and UDP
	assert.True(t, foundPorts[8053]["tcp"], "Missing TCP 8053 (public DNS)")
	assert.True(t, foundPorts[8053]["udp"], "Missing UDP 8053 (public DNS)")
	assert.True(t, foundPorts[9053]["tcp"], "Missing TCP 9053 (internal DNS)")
	assert.True(t, foundPorts[9053]["udp"], "Missing UDP 9053 (internal DNS)")
}

func TestGetCanoKeyFilePath(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected string
	}{
		{
			name: "nil FIDO2 config",
			config: &Config{
				WorkDir: "/test/work",
			},
			expected: "",
		},
		{
			name: "custom CanoKey file",
			config: &Config{
				WorkDir: "/test/work",
				FIDO2: &FIDO2Config{
					CanoKeyFile: "/custom/canokey.state",
				},
			},
			expected: "/custom/canokey.state",
		},
		{
			name: "default CanoKey file",
			config: &Config{
				WorkDir: "/test/work",
				FIDO2:   &FIDO2Config{},
			},
			expected: "/test/work/canokey/canokey.state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vm := &VM{
				config: tt.config,
				logger: logging.DefaultLogger(),
			}
			assert.Equal(t, tt.expected, vm.GetCanoKeyFilePath())
		})
	}
}

func TestVMBuildQEMUCommandWithPortForwarding(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	nvramDir := filepath.Join(tmpDir, "nvram")
	diskPath := filepath.Join(tmpDir, "test.qcow2")

	// Create mock files
	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))
	require.NoError(t, os.MkdirAll(nvramDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(nvramDir, "OVMF_VARS.fd"), []byte("mock"), 0644))

	config := &Config{
		DiskPath:    diskPath,
		Memory:      2048,
		CPUs:        2,
		DiskSize:    "1G",
		WorkDir:     tmpDir,
		OVMFCode:    ovmfCode,
		OVMFVars:    ovmfVars,
		NetworkMode: "user",
		Debug:       true,
		PortForwards: []PortForward{
			{HostPort: 8443, GuestPort: 8443, Protocol: "tcp"},
			{HostPort: 8080, GuestPort: 8080, Protocol: "tcp"},
			{HostPort: 8053, GuestPort: 8053, Protocol: "udp"},
			{HostPort: 2222, GuestPort: 22, Protocol: "tcp"},
		},
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	ctx := context.Background()
	cmd, err := vm.buildQEMUCommand(ctx, BootModeBoot)
	require.NoError(t, err)

	// Find the netdev argument
	var netdevArg string
	for i, arg := range cmd.Args {
		if arg == "-netdev" && i+1 < len(cmd.Args) {
			netdevArg = cmd.Args[i+1]
			break
		}
	}

	require.NotEmpty(t, netdevArg, "netdev argument not found")

	// Verify the netdev argument contains port forwarding
	assert.Contains(t, netdevArg, "user,id=net0")
	assert.Contains(t, netdevArg, "hostfwd=tcp::8443-:8443")
	assert.Contains(t, netdevArg, "hostfwd=tcp::8080-:8080")
	assert.Contains(t, netdevArg, "hostfwd=udp::8053-:8053")
	assert.Contains(t, netdevArg, "hostfwd=tcp::2222-:22")
}

func TestVMBuildQEMUCommandWithoutPortForwarding(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	nvramDir := filepath.Join(tmpDir, "nvram")
	diskPath := filepath.Join(tmpDir, "test.qcow2")

	// Create mock files
	require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
	require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))
	require.NoError(t, os.MkdirAll(nvramDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(nvramDir, "OVMF_VARS.fd"), []byte("mock"), 0644))

	config := &Config{
		DiskPath:    diskPath,
		Memory:      2048,
		CPUs:        2,
		DiskSize:    "1G",
		WorkDir:     tmpDir,
		OVMFCode:    ovmfCode,
		OVMFVars:    ovmfVars,
		NetworkMode: "user",
		Debug:       true,
		// No PortForwards configured
	}

	vm, err := NewVM(config, logging.DefaultLogger())
	require.NoError(t, err)

	ctx := context.Background()
	cmd, err := vm.buildQEMUCommand(ctx, BootModeBoot)
	require.NoError(t, err)

	// Find the netdev argument
	var netdevArg string
	for i, arg := range cmd.Args {
		if arg == "-netdev" && i+1 < len(cmd.Args) {
			netdevArg = cmd.Args[i+1]
			break
		}
	}

	require.NotEmpty(t, netdevArg, "netdev argument not found")

	// Verify basic user networking without port forwarding
	assert.Equal(t, "user,id=net0", netdevArg)
	assert.NotContains(t, netdevArg, "hostfwd")
}

func TestOVSEnabled(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{
			name:     "nil OVS config",
			config:   &Config{},
			expected: false,
		},
		{
			name: "OVS disabled",
			config: &Config{
				OVS: &OVSConfig{
					Enable: false,
				},
			},
			expected: false,
		},
		{
			name: "OVS enabled",
			config: &Config{
				OVS: &OVSConfig{
					Enable: true,
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.config.OVSEnabled())
		})
	}
}

func TestGetOVSBridgeName(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected string
	}{
		{
			name:     "nil OVS config returns default",
			config:   &Config{},
			expected: DefaultBridgeName,
		},
		{
			name: "empty bridge name returns default",
			config: &Config{
				OVS: &OVSConfig{
					Enable: true,
				},
			},
			expected: DefaultBridgeName,
		},
		{
			name: "custom bridge name",
			config: &Config{
				OVS: &OVSConfig{
					Enable:     true,
					BridgeName: "br-tenant1",
				},
			},
			expected: "br-tenant1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.config.GetOVSBridgeName())
		})
	}
}

func TestGetOVSSocketPath(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected string
	}{
		{
			name:     "nil OVS config returns default",
			config:   &Config{},
			expected: DefaultOVSSocketPath,
		},
		{
			name: "empty socket path returns default",
			config: &Config{
				OVS: &OVSConfig{
					Enable: true,
				},
			},
			expected: DefaultOVSSocketPath,
		},
		{
			name: "custom socket path",
			config: &Config{
				OVS: &OVSConfig{
					Enable:     true,
					SocketPath: "/custom/ovsdb.sock",
				},
			},
			expected: "/custom/ovsdb.sock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.config.GetOVSSocketPath())
		})
	}
}

func TestOVSConfig(t *testing.T) {
	t.Run("full OVS config", func(t *testing.T) {
		config := &Config{
			OVS: &OVSConfig{
				Enable:     true,
				BridgeName: "br-int",
				SocketPath: "/var/run/openvswitch/db.sock",
				PortName:   "vm-port-1",
				VLAN:       100,
				Trunks:     []uint16{100, 200, 300},
				VLANMode:   "trunk",
				QoS: &OVSQoSConfig{
					MaxRate:  1000000000, // 1 Gbps
					MinRate:  100000000,  // 100 Mbps
					Burst:    10000,
					Priority: 5,
				},
				ExternalIDs: map[string]string{
					"vm-id":     "test-vm-1",
					"tenant-id": "tenant-1",
				},
			},
		}

		assert.True(t, config.OVSEnabled())
		assert.Equal(t, "br-int", config.GetOVSBridgeName())
		assert.Equal(t, "/var/run/openvswitch/db.sock", config.GetOVSSocketPath())
		assert.Equal(t, "vm-port-1", config.OVS.PortName)
		assert.Equal(t, uint16(100), config.OVS.VLAN)
		assert.Equal(t, []uint16{100, 200, 300}, config.OVS.Trunks)
		assert.Equal(t, "trunk", config.OVS.VLANMode)
		assert.NotNil(t, config.OVS.QoS)
		assert.Equal(t, int64(1000000000), config.OVS.QoS.MaxRate)
		assert.Equal(t, "test-vm-1", config.OVS.ExternalIDs["vm-id"])
	})
}

func TestOVSQoSConfig(t *testing.T) {
	qos := &OVSQoSConfig{
		MaxRate:  1000000000,
		MinRate:  100000000,
		Burst:    10000,
		Priority: 7,
	}

	assert.Equal(t, int64(1000000000), qos.MaxRate)
	assert.Equal(t, int64(100000000), qos.MinRate)
	assert.Equal(t, int64(10000), qos.Burst)
	assert.Equal(t, 7, qos.Priority)
}

// TestVMBuildQEMUCommandDiskCacheModes asserts the -drive cache= argument
// follows Config.DiskCache, defaulting to writethrough when unset (#49).
func TestVMBuildQEMUCommandDiskCacheModes(t *testing.T) {
	cases := []struct {
		name      string
		diskCache string
		want      string
	}{
		{"default is writethrough", "", "cache=writethrough"},
		{"explicit writethrough", "writethrough", "cache=writethrough"},
		{"unsafe for nested-virt hosts", "unsafe", "cache=unsafe"},
		{"writeback", "writeback", "cache=writeback"},
		{"none (direct host I/O)", "none", "cache=none"},
		{"directsync", "directsync", "cache=directsync"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
			ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
			nvramDir := filepath.Join(tmpDir, "nvram")
			require.NoError(t, os.WriteFile(ovmfCode, []byte("mock"), 0644))
			require.NoError(t, os.WriteFile(ovmfVars, []byte("mock"), 0644))
			require.NoError(t, os.MkdirAll(nvramDir, 0755))
			require.NoError(t, os.WriteFile(filepath.Join(nvramDir, "OVMF_VARS.fd"), []byte("mock"), 0644))

			config := &Config{
				DiskPath:    filepath.Join(tmpDir, "test.qcow2"),
				Memory:      2048,
				CPUs:        2,
				DiskSize:    "1G",
				DiskCache:   tc.diskCache,
				WorkDir:     tmpDir,
				OVMFCode:    ovmfCode,
				OVMFVars:    ovmfVars,
				NetworkMode: "user",
			}

			vm, err := NewVM(config, logging.DefaultLogger())
			require.NoError(t, err)

			cmd, err := vm.buildQEMUCommand(context.Background(), BootModeBoot)
			require.NoError(t, err)

			var driveArg string
			for i, arg := range cmd.Args {
				if arg == "-drive" && i+1 < len(cmd.Args) {
					driveArg = cmd.Args[i+1]
					break
				}
			}
			require.NotEmpty(t, driveArg, "drive argument not found")
			assert.Contains(t, driveArg, tc.want)
		})
	}
}

// TestConfigValidate_InvalidDiskCache asserts an unknown cache mode is a
// typed validation error rather than being passed through to QEMU.
func TestConfigValidate_InvalidDiskCache(t *testing.T) {
	config := DefaultConfig()
	config.DiskPath = "/tmp/x.qcow2"
	config.DiskCache = "turbo"

	err := config.Validate()
	require.Error(t, err)
	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	assert.Contains(t, msgErr.Error(), "invalid disk cache mode")
}
