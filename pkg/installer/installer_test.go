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
	"github.com/jeremyhahn/go-trusted-platform/pkg/quirks"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/nbd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/disklessroot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock implementations for testing

type MockDiskManager struct {
	mock.Mock
}

func (m *MockDiskManager) CreatePartitionTable(ctx context.Context, table PartitionTable) error {
	args := m.Called(ctx, table)
	return args.Error(0)
}

func (m *MockDiskManager) CreateEFIPartition(ctx context.Context, sizeMB int) error {
	args := m.Called(ctx, sizeMB)
	return args.Error(0)
}

func (m *MockDiskManager) CreateRootPartition(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockDiskManager) SetupLUKS(ctx context.Context, partition string, config *EncryptionConfig) (string, error) {
	args := m.Called(ctx, partition, config)
	return args.String(0), args.Error(1)
}

func (m *MockDiskManager) FormatFilesystem(ctx context.Context, device, fsType, label string) error {
	args := m.Called(ctx, device, fsType, label)
	return args.Error(0)
}

func (m *MockDiskManager) Mount(ctx context.Context, device, mountpoint, fsType string, flags uintptr) error {
	args := m.Called(ctx, device, mountpoint, fsType, flags)
	return args.Error(0)
}

func (m *MockDiskManager) Unmount(ctx context.Context, mountpoint string) error {
	args := m.Called(ctx, mountpoint)
	return args.Error(0)
}

func (m *MockDiskManager) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDiskManager) EnsureDeviceNode(ctx context.Context, device string, maxWait time.Duration) error {
	args := m.Called(ctx, device, maxWait)
	return args.Error(0)
}

func (m *MockDiskManager) CreateLVMPhysicalVolume(ctx context.Context, device string) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}

func (m *MockDiskManager) CreateLVMVolumeGroup(ctx context.Context, vgName string, pvDevices []string) error {
	args := m.Called(ctx, vgName, pvDevices)
	return args.Error(0)
}

func (m *MockDiskManager) CreateLVMLogicalVolume(ctx context.Context, vgName, lvName string, size string) (string, error) {
	args := m.Called(ctx, vgName, lvName, size)
	return args.String(0), args.Error(1)
}

type MockOSInstaller struct {
	mock.Mock
}

func (m *MockOSInstaller) InstallBase(ctx context.Context, rootPath string) error {
	args := m.Called(ctx, rootPath)
	return args.Error(0)
}

func (m *MockOSInstaller) ConfigureSystem(ctx context.Context, rootPath string, diskInfo *DiskInfo) error {
	args := m.Called(ctx, rootPath, diskInfo)
	return args.Error(0)
}

func (m *MockOSInstaller) InstallKernel(ctx context.Context, rootPath string) error {
	args := m.Called(ctx, rootPath)
	return args.Error(0)
}

func (m *MockOSInstaller) SetRootPassword(ctx context.Context, rootPath, password string) error {
	args := m.Called(ctx, rootPath, password)
	return args.Error(0)
}

func (m *MockOSInstaller) Name() OperatingSystem {
	args := m.Called()
	return args.Get(0).(OperatingSystem)
}

func (m *MockOSInstaller) EnableServices(ctx context.Context, rootPath string) error {
	args := m.Called(ctx, rootPath)
	return args.Error(0)
}

func (m *MockOSInstaller) InstallPackages(ctx context.Context, rootPath string) error {
	args := m.Called(ctx, rootPath)
	return args.Error(0)
}

func (m *MockOSInstaller) ExecutePostInstall(ctx context.Context, rootPath string) error {
	args := m.Called(ctx, rootPath)
	return args.Error(0)
}

func (m *MockOSInstaller) ConfigureNetwork(ctx context.Context, rootPath string, netConfig *NetworkConfig, plan *netplan.Plan) error {
	args := m.Called(ctx, rootPath, netConfig, plan)
	return args.Error(0)
}

type MockUKIBuilder struct {
	mock.Mock
}

func (m *MockUKIBuilder) BuildUKI(ctx context.Context, config *UKIConfig, output io.Writer) error {
	args := m.Called(ctx, config, output)
	return args.Error(0)
}

// Helper functions

func createTestLogger() *logging.Logger {
	logger := logging.DefaultLogger()
	return logger
}

func createTestConfig() *Config {
	return &Config{
		Disk: &DiskConfig{
			Device:         "/dev/sda",
			PartitionTable: PartitionTableGPT,
			Encryption: &EncryptionConfig{
				Password: "test123",
			},
		},
		OS: &OSConfig{
			OS:           OSAlpine,
			Version:      "3.19",
			RootPassword: "root123",
		},
		// Note: UKI config is nil for unit tests to avoid filesystem access
		// UKI building requires real filesystem access and is tested separately
	}
}

// Tests

func TestNewInstaller(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid config",
			config:  createTestConfig(),
			wantErr: false,
		},
		{
			name: "missing disk config",
			config: &Config{
				OS: &OSConfig{
					OS: OSAlpine,
				},
				UKI: &UKIConfig{
					Cmdline: "root=/dev/sda2",
				},
			},
			wantErr: true,
			errMsg:  "disk configuration is required",
		},
		{
			name: "missing disk device",
			config: &Config{
				Disk: &DiskConfig{
					PartitionTable: PartitionTableGPT,
				},
				OS: &OSConfig{
					OS: OSAlpine,
				},
				UKI: &UKIConfig{
					Cmdline: "root=/dev/sda2",
				},
			},
			wantErr: true,
			errMsg:  "disk device is required",
		},
		{
			name: "unsupported OS",
			config: &Config{
				Disk: &DiskConfig{
					Device:         "/dev/sda",
					PartitionTable: PartitionTableGPT,
				},
				OS: &OSConfig{
					OS: "unsupported",
				},
				UKI: &UKIConfig{
					Cmdline: "root=/dev/sda2",
				},
			},
			wantErr: true,
			errMsg:  "unsupported OS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := createTestLogger()
			_, err := NewInstaller(logger, tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestInstaller_Install_DiskSetupFailure(t *testing.T) {
	withoutHostTPM(t)
	mockDisk := new(MockDiskManager)
	mockOS := new(MockOSInstaller)
	mockUKI := new(MockUKIBuilder)

	ctx := context.Background()

	// Disk setup fails
	mockDisk.On("CreatePartitionTable", ctx, PartitionTableGPT).
		Return(errors.New("disk error"))

	inst := &installer{
		config:      createTestConfig(),
		logger:      createTestLogger(),
		diskManager: mockDisk,
		osInstaller: mockOS,
		ukiBuilder:  mockUKI,
	}

	err := inst.Install(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disk setup failed")
	mockDisk.AssertExpectations(t)
}

func TestInstaller_Close(t *testing.T) {
	tests := []struct {
		name       string
		setupMocks func(*MockDiskManager)
		wantErr    bool
	}{
		{
			name: "successful close",
			setupMocks: func(m *MockDiskManager) {
				m.On("Close").Return(nil)
			},
			wantErr: false,
		},
		{
			name: "close with error",
			setupMocks: func(m *MockDiskManager) {
				m.On("Close").Return(errors.New("cleanup failed"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDisk := new(MockDiskManager)
			tt.setupMocks(mockDisk)

			inst := &installer{
				config:      createTestConfig(),
				logger:      createTestLogger(),
				diskManager: mockDisk,
			}

			err := inst.Close()

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			mockDisk.AssertExpectations(t)
		})
	}
}

func TestInstaller_SetupDisk(t *testing.T) {
	tests := []struct {
		name       string
		config     *Config
		setupMocks func(*MockDiskManager)
		wantErr    bool
		errMsg     string
	}{
		{
			name:   "successful disk setup with encryption",
			config: createTestConfig(),
			setupMocks: func(m *MockDiskManager) {
				ctx := context.Background()
				m.On("CreatePartitionTable", ctx, PartitionTableGPT).Return(nil)
				m.On("CreateEFIPartition", ctx, 0).Return(nil)
				m.On("CreateRootPartition", ctx).Return(nil)
				m.On("SetupLUKS", ctx, "", mock.AnythingOfType("*installer.EncryptionConfig")).
					Return("/dev/mapper/cryptroot", nil)
				// LVM setup expectations (default when no filesystem type is specified)
				m.On("CreateLVMPhysicalVolume", ctx, "/dev/mapper/cryptroot").Return(nil)
				m.On("CreateLVMVolumeGroup", ctx, "vg0", []string{"/dev/mapper/cryptroot"}).Return(nil)
				m.On("CreateLVMLogicalVolume", ctx, "vg0", "root", "100%FREE").Return("/dev/mapper/vg0-root", nil)
				m.On("FormatFilesystem", ctx, "/dev/mapper/vg0-root", "ext4", "root").Return(nil)
				m.On("Mount", ctx, "/dev/mapper/vg0-root", "/mnt", "ext4", uintptr(0)).Return(nil)
				m.On("EnsureDeviceNode", ctx, "/dev/sda1", mock.AnythingOfType("time.Duration")).Return(nil)
				m.On("Mount", ctx, "/dev/sda1", "/mnt/boot/efi", "vfat", uintptr(0)).Return(nil)
			},
			wantErr: false,
		},
		{
			name: "partition table creation fails",
			config: &Config{
				Disk: &DiskConfig{
					Device:         "/dev/sda",
					PartitionTable: PartitionTableGPT,
				},
				OS:  &OSConfig{OS: OSAlpine},
				UKI: &UKIConfig{Cmdline: "root=/dev/sda2"},
			},
			setupMocks: func(m *MockDiskManager) {
				ctx := context.Background()
				m.On("CreatePartitionTable", ctx, PartitionTableGPT).
					Return(errors.New("device not found"))
			},
			wantErr: true,
			errMsg:  "failed to create partition table",
		},
		{
			name:   "LUKS setup fails",
			config: createTestConfig(),
			setupMocks: func(m *MockDiskManager) {
				ctx := context.Background()
				m.On("CreatePartitionTable", ctx, PartitionTableGPT).Return(nil)
				m.On("CreateEFIPartition", ctx, 0).Return(nil)
				m.On("CreateRootPartition", ctx).Return(nil)
				m.On("SetupLUKS", ctx, "", mock.AnythingOfType("*installer.EncryptionConfig")).
					Return("", errors.New("cryptsetup failed"))
			},
			wantErr: true,
			errMsg:  "failed to setup LUKS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDisk := new(MockDiskManager)
			tt.setupMocks(mockDisk)

			inst := &installer{
				config:      tt.config,
				logger:      createTestLogger(),
				diskManager: mockDisk,
			}

			diskInfo, err := inst.setupDisk(context.Background())

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, diskInfo)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, diskInfo)
				assert.Equal(t, tt.config.Disk.Device, diskInfo.Device)
			}

			mockDisk.AssertExpectations(t)
		})
	}
}

func TestInstaller_SetupDisk_EFIPartitionFails(t *testing.T) {
	mockDisk := new(MockDiskManager)
	ctx := context.Background()

	mockDisk.On("CreatePartitionTable", ctx, PartitionTableGPT).Return(nil)
	mockDisk.On("CreateEFIPartition", ctx, 0).Return(errors.New("no space"))

	inst := &installer{
		config:      createTestConfig(),
		logger:      createTestLogger(),
		diskManager: mockDisk,
	}

	_, err := inst.setupDisk(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create EFI partition")
	mockDisk.AssertExpectations(t)
}

func TestInstaller_SetupDisk_RootPartitionFails(t *testing.T) {
	mockDisk := new(MockDiskManager)
	ctx := context.Background()

	mockDisk.On("CreatePartitionTable", ctx, PartitionTableGPT).Return(nil)
	mockDisk.On("CreateEFIPartition", ctx, 0).Return(nil)
	mockDisk.On("CreateRootPartition", ctx).Return(errors.New("no space"))

	inst := &installer{
		config:      createTestConfig(),
		logger:      createTestLogger(),
		diskManager: mockDisk,
	}

	_, err := inst.setupDisk(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create root partition")
	mockDisk.AssertExpectations(t)
}

func TestInstaller_SetupDisk_LVMPhysicalVolumeFails(t *testing.T) {
	mockDisk := new(MockDiskManager)
	ctx := context.Background()

	mockDisk.On("CreatePartitionTable", ctx, PartitionTableGPT).Return(nil)
	mockDisk.On("CreateEFIPartition", ctx, 0).Return(nil)
	mockDisk.On("CreateRootPartition", ctx).Return(nil)
	mockDisk.On("SetupLUKS", ctx, "", mock.AnythingOfType("*installer.EncryptionConfig")).
		Return("/dev/mapper/cryptroot", nil)
	mockDisk.On("CreateLVMPhysicalVolume", ctx, "/dev/mapper/cryptroot").Return(errors.New("pvcreate failed"))

	inst := &installer{
		config:      createTestConfig(),
		logger:      createTestLogger(),
		diskManager: mockDisk,
	}

	_, err := inst.setupDisk(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create LVM physical volume")
	mockDisk.AssertExpectations(t)
}

func TestInstaller_SetupDisk_LVMVolumeGroupFails(t *testing.T) {
	mockDisk := new(MockDiskManager)
	ctx := context.Background()

	mockDisk.On("CreatePartitionTable", ctx, PartitionTableGPT).Return(nil)
	mockDisk.On("CreateEFIPartition", ctx, 0).Return(nil)
	mockDisk.On("CreateRootPartition", ctx).Return(nil)
	mockDisk.On("SetupLUKS", ctx, "", mock.AnythingOfType("*installer.EncryptionConfig")).
		Return("/dev/mapper/cryptroot", nil)
	mockDisk.On("CreateLVMPhysicalVolume", ctx, "/dev/mapper/cryptroot").Return(nil)
	mockDisk.On("CreateLVMVolumeGroup", ctx, "vg0", []string{"/dev/mapper/cryptroot"}).Return(errors.New("vgcreate failed"))

	inst := &installer{
		config:      createTestConfig(),
		logger:      createTestLogger(),
		diskManager: mockDisk,
	}

	_, err := inst.setupDisk(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create LVM volume group")
	mockDisk.AssertExpectations(t)
}

func TestInstaller_SetupDisk_LVMLogicalVolumeFails(t *testing.T) {
	mockDisk := new(MockDiskManager)
	ctx := context.Background()

	mockDisk.On("CreatePartitionTable", ctx, PartitionTableGPT).Return(nil)
	mockDisk.On("CreateEFIPartition", ctx, 0).Return(nil)
	mockDisk.On("CreateRootPartition", ctx).Return(nil)
	mockDisk.On("SetupLUKS", ctx, "", mock.AnythingOfType("*installer.EncryptionConfig")).
		Return("/dev/mapper/cryptroot", nil)
	mockDisk.On("CreateLVMPhysicalVolume", ctx, "/dev/mapper/cryptroot").Return(nil)
	mockDisk.On("CreateLVMVolumeGroup", ctx, "vg0", []string{"/dev/mapper/cryptroot"}).Return(nil)
	mockDisk.On("CreateLVMLogicalVolume", ctx, "vg0", "root", "100%FREE").Return("", errors.New("lvcreate failed"))

	inst := &installer{
		config:      createTestConfig(),
		logger:      createTestLogger(),
		diskManager: mockDisk,
	}

	_, err := inst.setupDisk(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create LVM logical volume")
	mockDisk.AssertExpectations(t)
}

func TestInstaller_SetupDisk_FormatFilesystemFails(t *testing.T) {
	mockDisk := new(MockDiskManager)
	ctx := context.Background()

	mockDisk.On("CreatePartitionTable", ctx, PartitionTableGPT).Return(nil)
	mockDisk.On("CreateEFIPartition", ctx, 0).Return(nil)
	mockDisk.On("CreateRootPartition", ctx).Return(nil)
	mockDisk.On("SetupLUKS", ctx, "", mock.AnythingOfType("*installer.EncryptionConfig")).
		Return("/dev/mapper/cryptroot", nil)
	mockDisk.On("CreateLVMPhysicalVolume", ctx, "/dev/mapper/cryptroot").Return(nil)
	mockDisk.On("CreateLVMVolumeGroup", ctx, "vg0", []string{"/dev/mapper/cryptroot"}).Return(nil)
	mockDisk.On("CreateLVMLogicalVolume", ctx, "vg0", "root", "100%FREE").Return("/dev/mapper/vg0-root", nil)
	mockDisk.On("FormatFilesystem", ctx, "/dev/mapper/vg0-root", "ext4", "root").Return(errors.New("mkfs failed"))

	inst := &installer{
		config:      createTestConfig(),
		logger:      createTestLogger(),
		diskManager: mockDisk,
	}

	_, err := inst.setupDisk(ctx)

	assert.Error(t, err)
	// The test config uses LVM, so the error message is "failed to format LVM logical volume"
	assert.Contains(t, err.Error(), "failed to format LVM logical volume")
	mockDisk.AssertExpectations(t)
}

func TestInstaller_SetupDisk_MountRootFails(t *testing.T) {
	mockDisk := new(MockDiskManager)
	ctx := context.Background()

	mockDisk.On("CreatePartitionTable", ctx, PartitionTableGPT).Return(nil)
	mockDisk.On("CreateEFIPartition", ctx, 0).Return(nil)
	mockDisk.On("CreateRootPartition", ctx).Return(nil)
	mockDisk.On("SetupLUKS", ctx, "", mock.AnythingOfType("*installer.EncryptionConfig")).
		Return("/dev/mapper/cryptroot", nil)
	mockDisk.On("CreateLVMPhysicalVolume", ctx, "/dev/mapper/cryptroot").Return(nil)
	mockDisk.On("CreateLVMVolumeGroup", ctx, "vg0", []string{"/dev/mapper/cryptroot"}).Return(nil)
	mockDisk.On("CreateLVMLogicalVolume", ctx, "vg0", "root", "100%FREE").Return("/dev/mapper/vg0-root", nil)
	mockDisk.On("FormatFilesystem", ctx, "/dev/mapper/vg0-root", "ext4", "root").Return(nil)
	mockDisk.On("Mount", ctx, "/dev/mapper/vg0-root", "/mnt", "ext4", uintptr(0)).Return(errors.New("mount failed"))

	inst := &installer{
		config:      createTestConfig(),
		logger:      createTestLogger(),
		diskManager: mockDisk,
	}

	_, err := inst.setupDisk(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to mount root filesystem")
	mockDisk.AssertExpectations(t)
}

func TestInstaller_SetupDisk_EnsureDeviceNodeFails(t *testing.T) {
	mockDisk := new(MockDiskManager)
	ctx := context.Background()

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
	mockDisk.On("EnsureDeviceNode", ctx, "/dev/sda1", mock.AnythingOfType("time.Duration")).Return(errors.New("device not found"))

	inst := &installer{
		config:      createTestConfig(),
		logger:      createTestLogger(),
		diskManager: mockDisk,
	}

	_, err := inst.setupDisk(ctx)

	assert.Error(t, err)
	// The actual error from the code is "EFI partition device node not ready"
	assert.Contains(t, err.Error(), "EFI partition device")
	mockDisk.AssertExpectations(t)
}

func TestInstaller_SetupDisk_MountEFIFails(t *testing.T) {
	mockDisk := new(MockDiskManager)
	ctx := context.Background()

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
	mockDisk.On("Mount", ctx, "/dev/sda1", "/mnt/boot/efi", "vfat", uintptr(0)).Return(errors.New("mount failed"))

	inst := &installer{
		config:      createTestConfig(),
		logger:      createTestLogger(),
		diskManager: mockDisk,
	}

	_, err := inst.setupDisk(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to mount EFI partition")
	mockDisk.AssertExpectations(t)
}

// TestInstaller_ResolveHardwareQuirk verifies the UKI cmdline source: with
// the mini-fleet identity (placeholder Model, board named by part number)
// the X10SDV entry's cmdline is used, ending in console=ttyS0 so SOL is
// /dev/console; without the part number only the manufacturer-wide entry
// is reachable, and with no identity at all the generic default applies.
func TestInstaller_ResolveHardwareQuirk(t *testing.T) {
	logger := createTestLogger()
	newInst := func(mfr, model, pn string) *installer {
		inst, err := NewInstaller(logger, &Config{
			Disk:                 &DiskConfig{Device: "/dev/sda", PartitionTable: PartitionTableGPT},
			OS:                   &OSConfig{OS: OSAlpine},
			HardwareManufacturer: mfr,
			HardwareModel:        model,
			HardwarePartNumber:   pn,
		})
		require.NoError(t, err)
		return inst.(*installer)
	}

	q := newInst("Supermicro", "Super Server", "SYS-5018D-FN8T-AS001").resolveHardwareQuirk()
	assert.Equal(t, "supermicro/x10sdv", q.Key)
	lastConsole := ""
	for _, p := range q.KernelCmdline {
		if strings.HasPrefix(p, "console=") {
			lastConsole = p
		}
	}
	assert.Equal(t, "console=ttyS0,115200n8", lastConsole, "the last console= wins as /dev/console")
	assert.Equal(t, "ttyS0", q.SOLPort)

	q = newInst("Supermicro", "Super Server", "").resolveHardwareQuirk()
	assert.Equal(t, "supermicro", q.Key, "without the part number the placeholder model names nothing")

	q = newInst("", "", "").resolveHardwareQuirk()
	assert.Equal(t, quirks.Default(), q, "no identity resolves the generic default")
}

// TestNewInstaller_HardwareIdentityPropagation verifies all three identity
// fields reach the OSConfig, so the OS installer resolves the same quirk
// entry the BMC clients do — the mini-fleet firmware names its board only
// by part number.
func TestNewInstaller_HardwareIdentityPropagation(t *testing.T) {
	logger := createTestLogger()
	config := &Config{
		Disk: &DiskConfig{
			Device:         "/dev/sda",
			PartitionTable: PartitionTableGPT,
		},
		OS: &OSConfig{
			OS: OSAlpine,
		},
		HardwareManufacturer: "Supermicro",
		HardwareModel:        "Super Server",
		HardwarePartNumber:   "SYS-5018D-FN8T-AS001",
	}

	inst, err := NewInstaller(logger, config)
	require.NoError(t, err)
	require.NotNil(t, inst)

	assert.Equal(t, "Supermicro", config.OS.HardwareManufacturer)
	assert.Equal(t, "Super Server", config.OS.HardwareModel)
	assert.Equal(t, "SYS-5018D-FN8T-AS001", config.OS.HardwarePartNumber)
	assert.Equal(t, "supermicro/x10sdv", quirks.ResolveIdentity(config.OS.hardwareIdentity()).Key)
}

// TestNewAlpineInstaller_QuirkFromPartNumber verifies the Alpine installer
// resolves the board-specific entry from the part number alone (positive)
// and only the manufacturer-wide entry without it (negative).
func TestNewAlpineInstaller_QuirkFromPartNumber(t *testing.T) {
	logger := createTestLogger()

	withPN := &OSConfig{OS: OSAlpine, HardwareManufacturer: "Supermicro", HardwareModel: "Super Server", HardwarePartNumber: "SYS-5018D-FN8T-AS001"}
	inst, err := newAlpineInstaller(logger, withPN)
	require.NoError(t, err)
	assert.Equal(t, "supermicro/x10sdv", inst.(*alpineInstaller).quirk.Key)

	withoutPN := &OSConfig{OS: OSAlpine, HardwareManufacturer: "Supermicro", HardwareModel: "Super Server"}
	inst, err = newAlpineInstaller(logger, withoutPN)
	require.NoError(t, err)
	assert.Equal(t, "supermicro", inst.(*alpineInstaller).quirk.Key)

	empty := &OSConfig{OS: OSAlpine}
	inst, err = newAlpineInstaller(logger, empty)
	require.NoError(t, err)
	assert.Equal(t, "default", inst.(*alpineInstaller).quirk.Key)
}

func TestHostUKICmdlineParamsCarriesOnlyTheDebugSink(t *testing.T) {
	live := strings.Join([]string{
		"BOOT_IMAGE=/vmlinuz-lts",
		"platform_debug_sink=192.0.2.10:514",
		"platform_boot_model=diskless",
		"platform_rootfs_url=http://192.0.2.10/rootfs.squashfs",
		"platform_roothash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"roothash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}, " ")

	assert.Equal(t, []string{"platform_debug=1", "platform_debug_sink=192.0.2.10:514"}, hostUKICmdlineParams(live, true),
		"the live command line never names a root")
	assert.Empty(t, hostUKICmdlineParams(live, false))
	assert.Equal(t, []string{"platform_debug=1"}, hostUKICmdlineParams("BOOT_IMAGE=/vmlinuz-lts", true))
}

// A diskless-nbd node's NBD server address reaches the signed UKI only as a
// signed value, never from the live command line the boot server wrote.
func TestHostUKICmdlineParamsDropsTheNBDServer(t *testing.T) {
	live := strings.Join([]string{
		"BOOT_IMAGE=/vmlinuz-lts",
		"platform_debug_sink=192.0.2.10:514",
		disklessroot.ParamBootModel + "=" + nbd.BootModel,
		nbd.ParamServer + "=192.0.2.66:10809",
	}, " ")

	assert.Equal(t, []string{"platform_debug=1", "platform_debug_sink=192.0.2.10:514"}, hostUKICmdlineParams(live, true),
		"the live command line never names the NBD server")
	assert.Empty(t, hostUKICmdlineParams(live, false))
}
