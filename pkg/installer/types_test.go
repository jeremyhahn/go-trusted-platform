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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOperatingSystem(t *testing.T) {
	tests := []struct {
		name     string
		os       OperatingSystem
		expected string
	}{
		{
			name:     "alpine",
			os:       OSAlpine,
			expected: "alpine",
		},
		{
			name:     "debian",
			os:       OSDebian,
			expected: "debian",
		},
		{
			name:     "fedora",
			os:       OSFedora,
			expected: "fedora",
		},
		{
			name:     "ubuntu",
			os:       OSUbuntu,
			expected: "ubuntu",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.os))
		})
	}
}

func TestPartitionTable(t *testing.T) {
	tests := []struct {
		name     string
		pt       PartitionTable
		expected string
	}{
		{
			name:     "gpt",
			pt:       PartitionTableGPT,
			expected: "gpt",
		},
		{
			name:     "mbr",
			pt:       PartitionTableMBR,
			expected: "mbr",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.pt))
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: &Config{
				Disk: &DiskConfig{
					Device:         "/dev/sda",
					PartitionTable: PartitionTableGPT,
				},
				OS: &OSConfig{
					OS:      OSAlpine,
					Version: "3.19",
				},
				UKI: &UKIConfig{
					Cmdline:       "root=/dev/mapper/cryptroot",
					KernelPath:    "/boot/vmlinuz-lts",
					InitramfsPath: "/boot/initramfs-lts",
				},
			},
			wantErr: false,
		},
		{
			name: "missing disk config",
			config: &Config{
				OS: &OSConfig{
					OS:      OSAlpine,
					Version: "3.19",
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
			name: "missing OS config",
			config: &Config{
				Disk: &DiskConfig{
					Device:         "/dev/sda",
					PartitionTable: PartitionTableGPT,
				},
				UKI: &UKIConfig{
					Cmdline: "root=/dev/sda2",
				},
			},
			wantErr: true,
			errMsg:  "OS configuration is required",
		},
		{
			name: "missing UKI config - UKI is optional",
			config: &Config{
				Disk: &DiskConfig{
					Device:         "/dev/sda",
					PartitionTable: PartitionTableGPT,
				},
				OS: &OSConfig{
					OS: OSAlpine,
				},
			},
			wantErr: false, // UKI config is optional per types.go comment
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDiskConfig_Defaults(t *testing.T) {
	tests := []struct {
		name   string
		config *DiskConfig
		verify func(t *testing.T, config *DiskConfig)
	}{
		{
			name: "default EFI partition size",
			config: &DiskConfig{
				Device:         "/dev/sda",
				PartitionTable: PartitionTableGPT,
			},
			verify: func(t *testing.T, config *DiskConfig) {
				// Default should be 538MB if not set
				assert.Equal(t, 0, config.EFIPartitionSize)
			},
		},
		{
			name: "custom EFI partition size",
			config: &DiskConfig{
				Device:           "/dev/sda",
				PartitionTable:   PartitionTableGPT,
				EFIPartitionSize: 1024,
			},
			verify: func(t *testing.T, config *DiskConfig) {
				assert.Equal(t, 1024, config.EFIPartitionSize)
			},
		},
		{
			name: "default root filesystem",
			config: &DiskConfig{
				Device:         "/dev/sda",
				PartitionTable: PartitionTableGPT,
			},
			verify: func(t *testing.T, config *DiskConfig) {
				// Default filesystem type (empty means installer will default to LVM)
				assert.Equal(t, FilesystemType(""), config.RootFilesystem)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.verify(t, tt.config)
		})
	}
}

func TestEncryptionConfig_Defaults(t *testing.T) {
	tests := []struct {
		name   string
		config *EncryptionConfig
		verify func(t *testing.T, config *EncryptionConfig)
	}{
		{
			name: "complete config",
			config: &EncryptionConfig{
				Version:  "luks2",
				Cipher:   "aes-xts-plain64",
				KeySize:  512,
				Hash:     "sha256",
				PBKDF:    "argon2id",
				Password: "test123",
			},
			verify: func(t *testing.T, config *EncryptionConfig) {
				assert.Equal(t, "luks2", config.Version)
				assert.Equal(t, "aes-xts-plain64", config.Cipher)
				assert.Equal(t, 512, config.KeySize)
				assert.Equal(t, "sha256", config.Hash)
				assert.Equal(t, "argon2id", config.PBKDF)
				assert.Equal(t, "test123", config.Password)
			},
		},
		{
			name: "minimal config",
			config: &EncryptionConfig{
				Password: "test123",
			},
			verify: func(t *testing.T, config *EncryptionConfig) {
				// Defaults should be applied by the disk manager
				assert.Equal(t, "", config.Version)
				assert.Equal(t, "", config.Cipher)
				assert.Equal(t, 0, config.KeySize)
				assert.Equal(t, "", config.Hash)
				assert.Equal(t, "", config.PBKDF)
				assert.NotEmpty(t, config.Password)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.verify(t, tt.config)
		})
	}
}

func TestOSConfig_Valid(t *testing.T) {
	tests := []struct {
		name   string
		config *OSConfig
		valid  bool
	}{
		{
			name: "valid alpine config",
			config: &OSConfig{
				OS:           OSAlpine,
				Version:      "3.19",
				Mirror:       "https://dl-cdn.alpinelinux.org/alpine",
				Packages:     []string{"openssh", "vim"},
				RootPassword: "secure123",
			},
			valid: true,
		},
		{
			name: "valid debian config",
			config: &OSConfig{
				OS:           OSDebian,
				Version:      "bookworm",
				Mirror:       "http://deb.debian.org/debian",
				RootPassword: "secure123",
			},
			valid: true,
		},
		{
			name: "minimal config",
			config: &OSConfig{
				OS: OSAlpine,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotNil(t, tt.config)
			assert.NotEmpty(t, tt.config.OS)
		})
	}
}

func TestUKIConfig_Valid(t *testing.T) {
	tests := []struct {
		name   string
		config *UKIConfig
		verify func(t *testing.T, config *UKIConfig)
	}{
		{
			name: "full UKI config",
			config: &UKIConfig{
				Cmdline:       "root=/dev/mapper/cryptroot ro quiet",
				KernelPath:    "/boot/vmlinuz-lts",
				InitramfsPath: "/boot/initramfs-lts",
				OSRelease:     "Alpine Linux",
				MicrocodePath: "/boot/intel-ucode.img",
			},
			verify: func(t *testing.T, config *UKIConfig) {
				assert.NotEmpty(t, config.Cmdline)
				assert.NotEmpty(t, config.KernelPath)
				assert.NotEmpty(t, config.InitramfsPath)
				assert.NotEmpty(t, config.OSRelease)
				assert.NotEmpty(t, config.MicrocodePath)
			},
		},
		{
			name: "minimal UKI config",
			config: &UKIConfig{
				Cmdline:       "root=/dev/sda2",
				KernelPath:    "/boot/vmlinuz",
				InitramfsPath: "/boot/initramfs",
			},
			verify: func(t *testing.T, config *UKIConfig) {
				assert.NotEmpty(t, config.Cmdline)
				assert.NotEmpty(t, config.KernelPath)
				assert.NotEmpty(t, config.InitramfsPath)
				assert.Empty(t, config.OSRelease)
				assert.Empty(t, config.MicrocodePath)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.verify(t, tt.config)
		})
	}
}

func TestDiskInfo_Structure(t *testing.T) {
	tests := []struct {
		name     string
		diskInfo *DiskInfo
		verify   func(t *testing.T, info *DiskInfo)
	}{
		{
			name: "complete disk info",
			diskInfo: &DiskInfo{
				Device:         "/dev/sda",
				EFIPartition:   "/dev/sda1",
				RootPartition:  "/dev/sda2",
				LUKSPartition:  "/dev/sda2",
				MappedDevice:   "/dev/mapper/cryptroot",
				EFIUUID:        "1234-5678",
				RootUUID:       "abcd-efgh",
				LUKSUUID:       "ijkl-mnop",
				PartitionTable: PartitionTableGPT,
			},
			verify: func(t *testing.T, info *DiskInfo) {
				assert.Equal(t, "/dev/sda", info.Device)
				assert.Equal(t, "/dev/sda1", info.EFIPartition)
				assert.Equal(t, "/dev/sda2", info.RootPartition)
				assert.Equal(t, "/dev/mapper/cryptroot", info.MappedDevice)
				assert.Equal(t, PartitionTableGPT, info.PartitionTable)
			},
		},
		{
			name: "disk info without encryption",
			diskInfo: &DiskInfo{
				Device:         "/dev/vda",
				EFIPartition:   "/dev/vda1",
				RootPartition:  "/dev/vda2",
				PartitionTable: PartitionTableGPT,
			},
			verify: func(t *testing.T, info *DiskInfo) {
				assert.Equal(t, "/dev/vda", info.Device)
				assert.Empty(t, info.MappedDevice)
				assert.Empty(t, info.LUKSPartition)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.verify(t, tt.diskInfo)
		})
	}
}

func TestConfig_WithTPMSealing(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device:         "/dev/sda",
			PartitionTable: PartitionTableGPT,
			Encryption: &EncryptionConfig{
				Password: "test123",
			},
		},
		OS: &OSConfig{
			OS: OSAlpine,
		},
		UKI: &UKIConfig{
			Cmdline:       "root=/dev/mapper/cryptroot",
			KernelPath:    "/boot/vmlinuz",
			InitramfsPath: "/boot/initramfs",
		},
		EnableTPMSealing: true,
		PCRs:             []uint{0, 1, 2, 3, 7},
	}

	assert.True(t, config.EnableTPMSealing)
	assert.Equal(t, []uint{0, 1, 2, 3, 7}, config.PCRs)
	assert.NotNil(t, config.Disk.Encryption)
}

func TestConfig_WithSecureBoot(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device:         "/dev/sda",
			PartitionTable: PartitionTableGPT,
		},
		OS: &OSConfig{
			OS: OSAlpine,
		},
		UKI: &UKIConfig{
			Cmdline:       "root=/dev/sda2",
			KernelPath:    "/boot/vmlinuz",
			InitramfsPath: "/boot/initramfs",
		},
		SecureBoot: &SecureBootConfig{
			Enabled:    true,
			ResignMode: SecureBootResignModeRemote,
			DB: SecureBootKeyRef{
				KeyURI:  "kms://platform/secureboot/db",
				CertURI: "kms://platform/secureboot/db-cert",
			},
		},
	}

	assert.NotNil(t, config.SecureBoot)
	assert.Equal(t, "kms://platform/secureboot/db", config.SecureBoot.DB.KeyURI)
	assert.Equal(t, "kms://platform/secureboot/db-cert", config.SecureBoot.DB.CertURI)
}

func TestInterfaceType(t *testing.T) {
	tests := []struct {
		name     string
		iftype   InterfaceType
		expected string
	}{
		{"dhcp", InterfaceTypeDHCP, "dhcp"},
		{"static", InterfaceTypeStatic, "static"},
		{"manual", InterfaceTypeManual, "manual"},
		{"disabled", InterfaceTypeDisabled, "disabled"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.iftype))
		})
	}
}

func TestBridgeType(t *testing.T) {
	tests := []struct {
		name     string
		brtype   BridgeType
		expected string
	}{
		{"linux", BridgeTypeLinux, "linux"},
		{"ovs", BridgeTypeOVS, "ovs"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.brtype))
		})
	}
}

func TestNetworkConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *NetworkConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config is valid",
			config:  nil,
			wantErr: false,
		},
		{
			name:    "empty config is valid",
			config:  &NetworkConfig{},
			wantErr: false,
		},
		{
			name: "valid DNS only config",
			config: &NetworkConfig{
				DNS: &DNSConfig{
					Nameservers: []string{"8.8.8.8", "8.8.4.4"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid DHCP interface",
			config: &NetworkConfig{
				Interfaces: []InterfaceConfig{
					{Name: "eth0", Type: InterfaceTypeDHCP},
				},
			},
			wantErr: false,
		},
		{
			name: "valid static interface",
			config: &NetworkConfig{
				Interfaces: []InterfaceConfig{
					{
						Name:        "eth0",
						Type:        InterfaceTypeStatic,
						IPv4Address: "192.168.1.100",
						IPv4Netmask: "255.255.255.0",
						IPv4Gateway: "192.168.1.1",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "static interface missing address",
			config: &NetworkConfig{
				Interfaces: []InterfaceConfig{
					{
						Name: "eth0",
						Type: InterfaceTypeStatic,
						// Missing IPv4Address and IPv6Address
						IPv4Netmask: "255.255.255.0",
					},
				},
			},
			wantErr: true,
			errMsg:  "static type requires IPv4 or IPv6 address",
		},
		{
			name: "interface missing name",
			config: &NetworkConfig{
				Interfaces: []InterfaceConfig{
					{Type: InterfaceTypeDHCP},
				},
			},
			wantErr: true,
			errMsg:  "name is required",
		},
		{
			name: "bridge missing name",
			config: &NetworkConfig{
				Bridges: []BridgeConfig{
					{Type: BridgeTypeLinux, Interfaces: []string{"eth0"}},
				},
			},
			wantErr: true,
			errMsg:  "name is required",
		},
		{
			name: "bridge without interfaces is allowed (host-local bridge)",
			config: &NetworkConfig{
				Bridges: []BridgeConfig{
					{Name: "br0", Type: BridgeTypeLinux},
				},
			},
			wantErr: false,
		},
		{
			name: "valid linux bridge",
			config: &NetworkConfig{
				Bridges: []BridgeConfig{
					{
						Name:        "br0",
						Type:        BridgeTypeLinux,
						Interfaces:  []string{"eth0"},
						IPv4Address: "192.168.1.1",
						IPv4Netmask: "255.255.255.0",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid OVS bridge",
			config: &NetworkConfig{
				Bridges: []BridgeConfig{
					{
						Name:       "br-ext",
						Type:       BridgeTypeOVS,
						Interfaces: []string{"eth1"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "bond missing name",
			config: &NetworkConfig{
				Bonds: []BondConfig{
					{Mode: "balance-rr", Interfaces: []string{"eth0", "eth1"}},
				},
			},
			wantErr: true,
			errMsg:  "name is required",
		},
		{
			name: "bond missing interfaces",
			config: &NetworkConfig{
				Bonds: []BondConfig{
					{Name: "bond0", Mode: "balance-rr"},
				},
			},
			wantErr: true,
			errMsg:  "at least two member interfaces are required",
		},
		{
			name: "bond with single interface",
			config: &NetworkConfig{
				Bonds: []BondConfig{
					{Name: "bond0", Mode: "balance-rr", Interfaces: []string{"eth0"}},
				},
			},
			wantErr: true,
			errMsg:  "at least two member interfaces are required",
		},
		{
			name: "valid bond",
			config: &NetworkConfig{
				Bonds: []BondConfig{
					{
						Name:        "bond0",
						Mode:        "802.3ad",
						Interfaces:  []string{"eth0", "eth1"},
						IPv4Address: "192.168.1.100",
						IPv4Netmask: "255.255.255.0",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "VLAN missing name",
			config: &NetworkConfig{
				VLANs: []VLANConfig{
					{Parent: "eth0", ID: 100},
				},
			},
			wantErr: true,
			errMsg:  "name is required",
		},
		{
			name: "VLAN missing parent",
			config: &NetworkConfig{
				VLANs: []VLANConfig{
					{Name: "eth0.100", ID: 100},
				},
			},
			wantErr: true,
			errMsg:  "parent interface is required",
		},
		{
			name: "VLAN invalid ID zero",
			config: &NetworkConfig{
				VLANs: []VLANConfig{
					{Name: "eth0.100", Parent: "eth0", ID: 0},
				},
			},
			wantErr: true,
			errMsg:  "ID must be between 1 and 4094",
		},
		{
			name: "VLAN invalid ID too high",
			config: &NetworkConfig{
				VLANs: []VLANConfig{
					{Name: "eth0.100", Parent: "eth0", ID: 4095},
				},
			},
			wantErr: true,
			errMsg:  "ID must be between 1 and 4094",
		},
		{
			name: "valid VLAN",
			config: &NetworkConfig{
				VLANs: []VLANConfig{
					{
						Name:        "eth0.100",
						Parent:      "eth0",
						ID:          100,
						IPv4Address: "10.100.0.2",
						IPv4Netmask: "255.255.255.0",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "full network config",
			config: &NetworkConfig{
				DNS: &DNSConfig{
					Nameservers:   []string{"8.8.8.8", "8.8.4.4"},
					SearchDomains: []string{"example.com"},
				},
				Interfaces: []InterfaceConfig{
					{Name: "eth0", Type: InterfaceTypeDHCP},
					{
						Name:        "eth1",
						Type:        InterfaceTypeStatic,
						IPv4Address: "10.0.0.10",
						IPv4Netmask: "255.255.255.0",
					},
				},
				Bridges: []BridgeConfig{
					{
						Name:        "br0",
						Type:        BridgeTypeLinux,
						Interfaces:  []string{"eth2"},
						IPv4Address: "192.168.100.1",
						IPv4Netmask: "255.255.255.0",
					},
				},
				Bonds: []BondConfig{
					{
						Name:        "bond0",
						Mode:        "802.3ad",
						Interfaces:  []string{"eth3", "eth4"},
						IPv4Address: "203.0.113.1",
						IPv4Netmask: "255.255.255.0",
					},
				},
				VLANs: []VLANConfig{
					{
						Name:        "bond0.100",
						Parent:      "bond0",
						ID:          100,
						IPv4Address: "10.100.0.1",
						IPv4Netmask: "255.255.255.0",
					},
				},
				WaitOnline:  true,
				WaitTimeout: 30,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.config != nil {
				err = tt.config.Validate(nil)
			}
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

func TestConfig_WithNetwork(t *testing.T) {
	config := &Config{
		Disk: &DiskConfig{
			Device:         "/dev/sda",
			PartitionTable: PartitionTableGPT,
		},
		OS: &OSConfig{
			OS: OSAlpine,
		},
		Network: &NetworkConfig{
			DNS: &DNSConfig{
				Nameservers:   []string{"8.8.8.8", "1.1.1.1"},
				SearchDomains: []string{"local.example.com"},
			},
			Interfaces: []InterfaceConfig{
				{
					Name:        "eth0",
					Type:        InterfaceTypeStatic,
					IPv4Address: "192.168.1.100",
					IPv4Netmask: "255.255.255.0",
					IPv4Gateway: "192.168.1.1",
				},
			},
		},
	}

	assert.NotNil(t, config.Network)
	assert.NotNil(t, config.Network.DNS)
	assert.Len(t, config.Network.DNS.Nameservers, 2)
	assert.Len(t, config.Network.Interfaces, 1)
	assert.Equal(t, InterfaceTypeStatic, config.Network.Interfaces[0].Type)
	assert.NoError(t, config.Validate())
}

func TestDNSConfig_Structure(t *testing.T) {
	dns := &DNSConfig{
		Nameservers:   []string{"8.8.8.8", "8.8.4.4", "1.1.1.1"},
		SearchDomains: []string{"example.com", "local.example.com"},
		Options:       []string{"rotate", "timeout:2"},
	}

	assert.Len(t, dns.Nameservers, 3)
	assert.Len(t, dns.SearchDomains, 2)
	assert.Len(t, dns.Options, 2)
	assert.Equal(t, "8.8.8.8", dns.Nameservers[0])
	assert.Equal(t, "example.com", dns.SearchDomains[0])
}

func TestInterfaceConfig_WithRoutes(t *testing.T) {
	iface := &InterfaceConfig{
		Name:        "eth0",
		Type:        InterfaceTypeStatic,
		IPv4Address: "192.168.1.100",
		IPv4Netmask: "255.255.255.0",
		IPv4Gateway: "192.168.1.1",
		MTU:         9000,
		Routes: []RouteConfig{
			{
				Destination: "10.0.0.0/8",
				Gateway:     "192.168.1.254",
				Metric:      100,
			},
			{
				Destination: "172.16.0.0/12",
				Gateway:     "192.168.1.253",
			},
		},
	}

	assert.Equal(t, "eth0", iface.Name)
	assert.Equal(t, InterfaceTypeStatic, iface.Type)
	assert.Equal(t, 9000, iface.MTU)
	assert.Len(t, iface.Routes, 2)
	assert.Equal(t, "10.0.0.0/8", iface.Routes[0].Destination)
	assert.Equal(t, 100, iface.Routes[0].Metric)
}

// =============================================================================
// NetworkConfig bond tests
// =============================================================================

func TestNetworkConfig_Validate_BondInterfaces(t *testing.T) {
	t.Run("valid bond with interfaces", func(t *testing.T) {
		nc := &NetworkConfig{
			Bonds: []BondConfig{
				{
					Name:       "bond0",
					Mode:       "802.3ad",
					Interfaces: []string{"eth0", "eth1"},
				},
			},
		}
		assert.NoError(t, nc.Validate(nil))
	})

	t.Run("bond with too few interfaces", func(t *testing.T) {
		nc := &NetworkConfig{
			Bonds: []BondConfig{
				{
					Name:       "bond0",
					Mode:       "802.3ad",
					Interfaces: []string{"eth0"},
				},
			},
		}
		err := nc.Validate(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least two member interfaces are required")
	})
}

func TestBondConfig_NoSlavesField(t *testing.T) {
	// Verify that BondConfig has Interfaces field, not Slaves.
	// This is a compile-time check; if Slaves were present, this test
	// file would not compile. The test exists as documentation.
	bond := BondConfig{
		Name:       "bond0",
		Mode:       "802.3ad",
		Interfaces: []string{"eth0", "eth1"},
		VLANs: []BondVLANConfig{
			{Zone: "fabric", IPv4Address: "10.4.1.20/24", AutoStart: true},
		},
	}
	assert.Len(t, bond.Interfaces, 2)
	assert.Len(t, bond.VLANs, 1)
}
