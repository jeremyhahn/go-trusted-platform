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

package device

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStaticProfileService_AddAndGet(t *testing.T) {
	service := NewStaticProfileService()

	profile := &ProfileResponse{
		SerialNumber: "TEST-SERIAL-001",
		AdmittedNetwork: NetworkConfig{
			VLAN:    100,
			UseDHCP: true,
		},
	}

	service.AddProfile("TEST-SERIAL-001", profile)

	retrieved, err := service.GetBySerial("TEST-SERIAL-001")
	require.NoError(t, err)
	assert.Equal(t, "TEST-SERIAL-001", retrieved.SerialNumber)
	assert.Equal(t, uint16(100), retrieved.AdmittedNetwork.VLAN)
}

func TestStaticProfileService_GetNotFound(t *testing.T) {
	service := NewStaticProfileService()

	_, err := service.GetBySerial("NON-EXISTENT")
	assert.ErrorIs(t, err, ErrProfileNotFoundBySerial)
}

func TestStaticProfileService_Remove(t *testing.T) {
	service := NewStaticProfileService()

	profile := &ProfileResponse{
		SerialNumber: "TEST-SERIAL-001",
	}

	service.AddProfile("TEST-SERIAL-001", profile)

	// Verify it exists
	_, err := service.GetBySerial("TEST-SERIAL-001")
	require.NoError(t, err)

	// Remove it
	service.RemoveProfile("TEST-SERIAL-001")

	// Verify it's gone
	_, err = service.GetBySerial("TEST-SERIAL-001")
	assert.ErrorIs(t, err, ErrProfileNotFoundBySerial)
}

func TestStaticProfileService_ConcurrentAccess(t *testing.T) {
	service := NewStaticProfileService()

	// Add initial profiles
	for i := 0; i < 10; i++ {
		serial := "SERIAL-" + string(rune('A'+i))
		service.AddProfile(serial, &ProfileResponse{SerialNumber: serial})
	}

	// Concurrent reads
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			serial := "SERIAL-" + string(rune('A'+n))
			_, _ = service.GetBySerial(serial)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestDefaultAdmittedProfile(t *testing.T) {
	profile := DefaultAdmittedProfile("TEST-DEVICE-001")

	assert.Equal(t, "TEST-DEVICE-001", profile.SerialNumber)
	assert.Equal(t, uint16(200), profile.AdmittedNetwork.VLAN)
	assert.True(t, profile.AdmittedNetwork.UseDHCP)
	assert.Len(t, profile.ACLs, 2)
	assert.Equal(t, "allow-https", profile.ACLs[0].Name)
	assert.Equal(t, "allow-dns", profile.ACLs[1].Name)
}

func TestProfileFromDeviceProfile_Nil(t *testing.T) {
	result := ProfileFromDeviceProfile(nil, "TEST-SERIAL")
	assert.Nil(t, result)
}

func TestProfileFromDeviceProfile_NilAdmittedNetwork(t *testing.T) {
	dp := &entities.DeviceProfile{
		ID:   1,
		Name: "test-profile",
	}

	result := ProfileFromDeviceProfile(dp, "TEST-SERIAL")
	require.NotNil(t, result)
	assert.Equal(t, "TEST-SERIAL", result.SerialNumber)
	assert.Equal(t, uint16(0), result.AdmittedNetwork.VLAN)
	assert.False(t, result.AdmittedNetwork.UseDHCP)
	assert.Empty(t, result.ACLs)
}

func TestProfileFromDeviceProfile_FullProfile(t *testing.T) {
	dp := &entities.DeviceProfile{
		ID:   1,
		Name: "production-profile",
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN:     200,
				DHCP:     true,
				StaticIP: "10.100.1.50",
				Gateway:  "10.100.1.1",
				DNS:      []string{"10.100.1.2", "8.8.8.8"},
				ACLs: []entities.ACLConfig{
					{
						Priority: 100,
						Protocol: "tcp",
						SrcIP:    "10.0.0.0/8",
						DstIP:    "10.100.1.50",
						SrcPort:  0,
						DstPort:  443,
						Action:   "allow",
					},
					{
						Priority: 90,
						Protocol: "udp",
						DstPort:  53,
						Action:   "allow",
					},
				},
			},
		},
	}

	result := ProfileFromDeviceProfile(dp, "DEVICE-001")
	require.NotNil(t, result)

	// Verify basic fields
	assert.Equal(t, "DEVICE-001", result.SerialNumber)
	assert.Equal(t, uint16(200), result.AdmittedNetwork.VLAN)
	assert.True(t, result.AdmittedNetwork.UseDHCP)
	assert.Equal(t, "10.100.1.50", result.AdmittedNetwork.StaticIP)
	assert.Equal(t, "10.100.1.1", result.AdmittedNetwork.Gateway)
	assert.Equal(t, []string{"10.100.1.2", "8.8.8.8"}, result.AdmittedNetwork.DNS)

	// Verify ACLs
	require.Len(t, result.ACLs, 2)

	// First ACL
	assert.Equal(t, "acl-0", result.ACLs[0].Name)
	assert.Equal(t, 100, result.ACLs[0].Priority)
	assert.Equal(t, "allow", result.ACLs[0].Action)
	assert.Equal(t, "tcp", result.ACLs[0].Match["protocol"])
	assert.Equal(t, "10.0.0.0/8", result.ACLs[0].Match["src_ip"])
	assert.Equal(t, "10.100.1.50", result.ACLs[0].Match["dst_ip"])
	assert.Equal(t, "443", result.ACLs[0].Match["dst_port"])

	// Second ACL
	assert.Equal(t, "acl-1", result.ACLs[1].Name)
	assert.Equal(t, 90, result.ACLs[1].Priority)
	assert.Equal(t, "allow", result.ACLs[1].Action)
	assert.Equal(t, "udp", result.ACLs[1].Match["protocol"])
	assert.Equal(t, "53", result.ACLs[1].Match["dst_port"])
}

func TestProfileFromDeviceProfile_ACLWithAnyProtocol(t *testing.T) {
	dp := &entities.DeviceProfile{
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN: 100,
				ACLs: []entities.ACLConfig{
					{
						Priority: 50,
						Protocol: "any",
						Action:   "deny",
					},
				},
			},
		},
	}

	result := ProfileFromDeviceProfile(dp, "SERIAL-123")
	require.NotNil(t, result)
	require.Len(t, result.ACLs, 1)

	// "any" protocol should not be added to match map
	_, hasProtocol := result.ACLs[0].Match["protocol"]
	assert.False(t, hasProtocol, "protocol 'any' should not be in match map")
	assert.Equal(t, "deny", result.ACLs[0].Action)
}

func TestProfileFromDeviceProfile_ACLWithEmptyProtocol(t *testing.T) {
	dp := &entities.DeviceProfile{
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN: 100,
				ACLs: []entities.ACLConfig{
					{
						Priority: 50,
						Protocol: "",
						DstPort:  80,
						Action:   "allow",
					},
				},
			},
		},
	}

	result := ProfileFromDeviceProfile(dp, "SERIAL-456")
	require.NotNil(t, result)
	require.Len(t, result.ACLs, 1)

	// Empty protocol should not be added to match map
	_, hasProtocol := result.ACLs[0].Match["protocol"]
	assert.False(t, hasProtocol, "empty protocol should not be in match map")
	assert.Equal(t, "80", result.ACLs[0].Match["dst_port"])
	assert.Equal(t, "allow", result.ACLs[0].Action)
}

func TestProfileFromDeviceProfile_ACLWithSourcePort(t *testing.T) {
	dp := &entities.DeviceProfile{
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN: 100,
				ACLs: []entities.ACLConfig{
					{
						Priority: 75,
						Protocol: "tcp",
						SrcPort:  8080,
						DstPort:  443,
						Action:   "allow",
					},
				},
			},
		},
	}

	result := ProfileFromDeviceProfile(dp, "SERIAL-789")
	require.NotNil(t, result)
	require.Len(t, result.ACLs, 1)

	assert.Equal(t, "tcp", result.ACLs[0].Match["protocol"])
	assert.Equal(t, "8080", result.ACLs[0].Match["src_port"])
	assert.Equal(t, "443", result.ACLs[0].Match["dst_port"])
}

func TestProfileFromDeviceProfile_ACLWithOnlySourceIP(t *testing.T) {
	dp := &entities.DeviceProfile{
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN: 100,
				ACLs: []entities.ACLConfig{
					{
						Priority: 60,
						Protocol: "icmp",
						SrcIP:    "192.168.1.0/24",
						Action:   "allow",
					},
				},
			},
		},
	}

	result := ProfileFromDeviceProfile(dp, "SERIAL-ICMP")
	require.NotNil(t, result)
	require.Len(t, result.ACLs, 1)

	assert.Equal(t, "icmp", result.ACLs[0].Match["protocol"])
	assert.Equal(t, "192.168.1.0/24", result.ACLs[0].Match["src_ip"])
	_, hasDstIP := result.ACLs[0].Match["dst_ip"]
	assert.False(t, hasDstIP)
}

func TestProfileFromDeviceProfile_ACLWithOnlyDestIP(t *testing.T) {
	dp := &entities.DeviceProfile{
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN: 100,
				ACLs: []entities.ACLConfig{
					{
						Priority: 65,
						Protocol: "tcp",
						DstIP:    "8.8.8.8",
						Action:   "deny",
					},
				},
			},
		},
	}

	result := ProfileFromDeviceProfile(dp, "SERIAL-DEST")
	require.NotNil(t, result)
	require.Len(t, result.ACLs, 1)

	assert.Equal(t, "tcp", result.ACLs[0].Match["protocol"])
	assert.Equal(t, "8.8.8.8", result.ACLs[0].Match["dst_ip"])
	_, hasSrcIP := result.ACLs[0].Match["src_ip"]
	assert.False(t, hasSrcIP)
}

func TestProfileFromDeviceProfile_MultipleACLs(t *testing.T) {
	dp := &entities.DeviceProfile{
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN: 100,
				ACLs: []entities.ACLConfig{
					{
						Priority: 100,
						Protocol: "tcp",
						DstPort:  443,
						Action:   "allow",
					},
					{
						Priority: 90,
						Protocol: "tcp",
						DstPort:  80,
						Action:   "allow",
					},
					{
						Priority: 10,
						Protocol: "any",
						Action:   "deny",
					},
				},
			},
		},
	}

	result := ProfileFromDeviceProfile(dp, "SERIAL-MULTI")
	require.NotNil(t, result)
	require.Len(t, result.ACLs, 3)

	// Verify ACL names are generated correctly
	assert.Equal(t, "acl-0", result.ACLs[0].Name)
	assert.Equal(t, "acl-1", result.ACLs[1].Name)
	assert.Equal(t, "acl-2", result.ACLs[2].Name)

	// Verify priorities
	assert.Equal(t, 100, result.ACLs[0].Priority)
	assert.Equal(t, 90, result.ACLs[1].Priority)
	assert.Equal(t, 10, result.ACLs[2].Priority)
}

func TestStaticProfileService_OverwriteProfile(t *testing.T) {
	service := NewStaticProfileService()

	profile1 := &ProfileResponse{
		SerialNumber: "TEST-001",
		AdmittedNetwork: NetworkConfig{
			VLAN: 100,
		},
	}

	profile2 := &ProfileResponse{
		SerialNumber: "TEST-001",
		AdmittedNetwork: NetworkConfig{
			VLAN: 200,
		},
	}

	service.AddProfile("TEST-001", profile1)
	retrieved, err := service.GetBySerial("TEST-001")
	require.NoError(t, err)
	assert.Equal(t, uint16(100), retrieved.AdmittedNetwork.VLAN)

	// Overwrite with new profile
	service.AddProfile("TEST-001", profile2)
	retrieved, err = service.GetBySerial("TEST-001")
	require.NoError(t, err)
	assert.Equal(t, uint16(200), retrieved.AdmittedNetwork.VLAN)
}

func TestStaticProfileService_RemoveNonExistent(t *testing.T) {
	service := NewStaticProfileService()

	// Should not panic when removing non-existent profile
	service.RemoveProfile("NON-EXISTENT")

	_, err := service.GetBySerial("NON-EXISTENT")
	assert.ErrorIs(t, err, ErrProfileNotFoundBySerial)
}

func TestProfileFromDeviceProfile_ACLWithZeroPorts(t *testing.T) {
	dp := &entities.DeviceProfile{
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN: 100,
				ACLs: []entities.ACLConfig{
					{
						Priority: 50,
						Protocol: "tcp",
						SrcPort:  0,
						DstPort:  0,
						Action:   "allow",
					},
				},
			},
		},
	}

	result := ProfileFromDeviceProfile(dp, "SERIAL-ZERO-PORTS")
	require.NotNil(t, result)
	require.Len(t, result.ACLs, 1)

	// Zero ports should not be added to match map
	_, hasSrcPort := result.ACLs[0].Match["src_port"]
	_, hasDstPort := result.ACLs[0].Match["dst_port"]
	assert.False(t, hasSrcPort, "zero src_port should not be in match map")
	assert.False(t, hasDstPort, "zero dst_port should not be in match map")
	assert.Equal(t, "tcp", result.ACLs[0].Match["protocol"])
}
