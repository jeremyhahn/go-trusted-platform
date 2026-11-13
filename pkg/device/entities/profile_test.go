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

package entities

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

func TestDeviceProfile_EntityID(t *testing.T) {
	tests := []struct {
		name     string
		profile  *DeviceProfile
		expected uint64
	}{
		{
			name: "returns correct entity ID",
			profile: &DeviceProfile{
				ID: 54321,
			},
			expected: 54321,
		},
		{
			name: "returns zero for uninitialized ID",
			profile: &DeviceProfile{
				ID: 0,
			},
			expected: 0,
		},
		{
			name: "returns max uint64",
			profile: &DeviceProfile{
				ID: ^uint64(0),
			},
			expected: ^uint64(0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.profile.EntityID()
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestDeviceProfile_SetEntityID(t *testing.T) {
	tests := []struct {
		name     string
		profile  *DeviceProfile
		newID    uint64
		expected uint64
	}{
		{
			name:     "sets entity ID correctly",
			profile:  &DeviceProfile{ID: 0},
			newID:    88888,
			expected: 88888,
		},
		{
			name:     "updates existing ID",
			profile:  &DeviceProfile{ID: 11111},
			newID:    22222,
			expected: 22222,
		},
		{
			name:     "sets zero ID",
			profile:  &DeviceProfile{ID: 11111},
			newID:    0,
			expected: 0,
		},
		{
			name:     "sets max uint64",
			profile:  &DeviceProfile{ID: 0},
			newID:    ^uint64(0),
			expected: ^uint64(0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.profile.SetEntityID(tt.newID)
			assert.Equal(t, tt.expected, tt.profile.ID)
			assert.Equal(t, tt.expected, tt.profile.EntityID())
		})
	}
}

func TestDeviceProfile_FieldValues(t *testing.T) {
	eventLog := []byte("profile-event-log-data")
	profile := &DeviceProfile{
		ID:       67890,
		Name:     "Test Profile",
		Model:    "ProfileModel123",
		Role:     DeviceRoleServer,
		EventLog: eventLog,
	}

	assert.Equal(t, uint64(67890), profile.ID)
	assert.Equal(t, "Test Profile", profile.Name)
	assert.Equal(t, "ProfileModel123", profile.Model)
	assert.Equal(t, DeviceRoleServer, profile.Role)
	assert.Equal(t, eventLog, profile.EventLog)
}

func TestDeviceProfile_EmptyProfile(t *testing.T) {
	profile := &DeviceProfile{}

	assert.Equal(t, uint64(0), profile.ID)
	assert.Equal(t, "", profile.Name)
	assert.Equal(t, "", profile.Model)
	assert.Equal(t, DeviceRole(""), profile.Role)
	assert.Nil(t, profile.EventLog)
	assert.Nil(t, profile.GetEnrollmentNetworkConfig())
	assert.Nil(t, profile.GetPostEnrollmentNetworkConfig())
	assert.Nil(t, profile.GetFailureNetworkConfig())
	assert.Nil(t, profile.PlatformdConfig)
	assert.Nil(t, profile.MatchRules)
}

func TestDeviceProfile_NilEventLog(t *testing.T) {
	profile := &DeviceProfile{
		ID:       12345,
		Model:    "TestModel",
		EventLog: nil,
	}

	assert.Nil(t, profile.EventLog)
	assert.Equal(t, "TestModel", profile.Model)
}

func TestDeviceProfile_EmptyEventLog(t *testing.T) {
	profile := &DeviceProfile{
		ID:       12345,
		Model:    "TestModel",
		EventLog: []byte{},
	}

	require.NotNil(t, profile.EventLog)
	assert.Len(t, profile.EventLog, 0)
}

func TestDeviceProfile_LargeEventLog(t *testing.T) {
	largeLog := make([]byte, 2*1024*1024) // 2MB
	for i := range largeLog {
		largeLog[i] = byte(i % 256)
	}

	profile := &DeviceProfile{
		ID:       12345,
		Model:    "HighThroughputDevice",
		EventLog: largeLog,
	}

	assert.Len(t, profile.EventLog, 2*1024*1024)
	assert.Equal(t, largeLog, profile.EventLog)
	assert.Equal(t, "HighThroughputDevice", profile.Model)
}

func TestDeviceProfile_MultipleIDOperations(t *testing.T) {
	profile := &DeviceProfile{}

	assert.Equal(t, uint64(0), profile.EntityID())

	profile.SetEntityID(1000)
	assert.Equal(t, uint64(1000), profile.EntityID())
	assert.Equal(t, uint64(1000), profile.ID)

	profile.SetEntityID(2000)
	assert.Equal(t, uint64(2000), profile.EntityID())
	assert.Equal(t, uint64(2000), profile.ID)

	profile.ID = 3000
	assert.Equal(t, uint64(3000), profile.EntityID())
}

func TestDeviceProfile_ModelVariations(t *testing.T) {
	tests := []struct {
		name  string
		model string
	}{
		{
			name:  "simple model name",
			model: "Model123",
		},
		{
			name:  "model with spaces",
			model: "Model Name With Spaces",
		},
		{
			name:  "model with special characters",
			model: "Model-2000_v1.5",
		},
		{
			name:  "empty model",
			model: "",
		},
		{
			name:  "long model name",
			model: "ThisIsAVeryLongModelNameThatExceedsNormalLengthsButShouldStillBeHandledCorrectly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := &DeviceProfile{
				ID:    12345,
				Model: tt.model,
			}

			assert.Equal(t, tt.model, profile.Model)
		})
	}
}

func TestDeviceRole_Values(t *testing.T) {
	tests := []struct {
		name string
		role DeviceRole
		str  string
	}{
		{
			name: "unknown role",
			role: DeviceRoleUnknown,
			str:  "unknown",
		},
		{
			name: "server role",
			role: DeviceRoleServer,
			str:  "server",
		},
		{
			name: "workstation role",
			role: DeviceRoleWorkstation,
			str:  "workstation",
		},
		{
			name: "edge role",
			role: DeviceRoleEdge,
			str:  "edge",
		},
		{
			name: "iot role",
			role: DeviceRoleIoT,
			str:  "iot",
		},
		{
			name: "gateway role",
			role: DeviceRoleGateway,
			str:  "gateway",
		},
		{
			name: "load-balancer role",
			role: DeviceRoleLoadBalancer,
			str:  "load-balancer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.str, string(tt.role))
		})
	}
}

func TestDeviceProfile_NetworkConfiguration(t *testing.T) {
	vlan := 100
	profile := &DeviceProfile{
		ID:   12345,
		Name: "Network Test Profile",
		Role: DeviceRoleServer,
		Networks: map[string]*NetworkPhaseConfig{
			DefaultEnrollmentNetwork: {
				VLAN:       uint16(vlan),
				Subnet:     "10.0.1.0/24",
				Gateway:    "10.0.1.1",
				DNSServers: []string{"8.8.8.8", "8.8.4.4"},
				DHCP:       true,
				Zone:       "provisioning",
			},
			DefaultPostEnrollmentNetwork: {
				VLAN:       0,
				Subnet:     "10.0.2.0/24",
				Gateway:    "10.0.2.1",
				DNSServers: []string{"10.0.2.53"},
				DHCP:       false,
				StaticIP:   "10.0.2.100",
				Zone:       "production",
			},
		},
	}

	require.NotNil(t, profile.GetEnrollmentNetworkConfig())
	assert.Equal(t, uint16(vlan), profile.GetEnrollmentNetworkConfig().VLAN)
	assert.Equal(t, "10.0.1.0/24", profile.GetEnrollmentNetworkConfig().Subnet)
	assert.Equal(t, "10.0.1.1", profile.GetEnrollmentNetworkConfig().Gateway)
	assert.Equal(t, []string{"8.8.8.8", "8.8.4.4"}, profile.GetEnrollmentNetworkConfig().DNSServers)
	assert.True(t, profile.GetEnrollmentNetworkConfig().DHCP)
	assert.Equal(t, "provisioning", profile.GetEnrollmentNetworkConfig().Zone)

	require.NotNil(t, profile.GetPostEnrollmentNetworkConfig())
	assert.Equal(t, uint16(0), profile.GetPostEnrollmentNetworkConfig().VLAN)
	assert.Equal(t, "10.0.2.0/24", profile.GetPostEnrollmentNetworkConfig().Subnet)
	assert.Equal(t, "10.0.2.1", profile.GetPostEnrollmentNetworkConfig().Gateway)
	assert.Equal(t, []string{"10.0.2.53"}, profile.GetPostEnrollmentNetworkConfig().DNSServers)
	assert.False(t, profile.GetPostEnrollmentNetworkConfig().DHCP)
	assert.Equal(t, "10.0.2.100", profile.GetPostEnrollmentNetworkConfig().StaticIP)
	assert.Equal(t, "production", profile.GetPostEnrollmentNetworkConfig().Zone)

	assert.Nil(t, profile.GetFailureNetworkConfig())
}

func TestDeviceProfile_NilNetworkConfiguration(t *testing.T) {
	profile := &DeviceProfile{
		ID:   12345,
		Name: "No Network Profile",
	}

	assert.Nil(t, profile.GetEnrollmentNetworkConfig())
	assert.Nil(t, profile.GetPostEnrollmentNetworkConfig())
	assert.Nil(t, profile.GetFailureNetworkConfig())
}

func TestDeviceProfile_NilPlatformdConfig(t *testing.T) {
	profile := &DeviceProfile{
		ID:              12345,
		PlatformdConfig: nil,
	}

	assert.Nil(t, profile.PlatformdConfig)
}

func TestDeviceProfile_NilMatchRules(t *testing.T) {
	profile := &DeviceProfile{
		ID:         12345,
		MatchRules: nil,
	}

	assert.Nil(t, profile.MatchRules)
}

func TestDeviceProfile_EmptyMatchRulesMap(t *testing.T) {
	profile := &DeviceProfile{
		ID: 12345,
		MatchRules: &ProfileMatchRules{
			CustomAttributes: map[string]string{},
		},
	}

	require.NotNil(t, profile.MatchRules)
	assert.Empty(t, profile.MatchRules.CustomAttributes)
}

func TestDeviceProfile_YAMLSerialization(t *testing.T) {
	vlan := 200
	original := &DeviceProfile{
		ID:    12345,
		Name:  "YAML Test Profile",
		Model: "TestModel-2000",
		Role:  DeviceRoleGateway,
		Networks: map[string]*NetworkPhaseConfig{
			DefaultEnrollmentNetwork: {
				VLAN:       uint16(vlan),
				Subnet:     "192.168.1.0/24",
				Gateway:    "192.168.1.1",
				DNSServers: []string{"192.168.1.53"},
				DHCP:       true,
				Zone:       "provisioning",
			},
		},
		PlatformdConfig: &PlatformdConfigRef{
			ConfigName: "gateway-config",
			ConfigPath: "/etc/platformd/gateway.yaml",
			Version:    "2.0.0",
		},
		MatchRules: &ProfileMatchRules{
			ModelPattern: "^TestModel-.*$",
			TPMVendor:    "NTC",
		},
	}

	data, err := yaml.Marshal(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var decoded DeviceProfile
	err = yaml.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.ID, decoded.ID)
	assert.Equal(t, original.Name, decoded.Name)
	assert.Equal(t, original.Model, decoded.Model)
	assert.Equal(t, original.Role, decoded.Role)

	require.NotNil(t, decoded.GetEnrollmentNetworkConfig())

	assert.Equal(t, uint16(vlan), decoded.GetEnrollmentNetworkConfig().VLAN)
	assert.Equal(t, original.GetEnrollmentNetworkConfig().Subnet, decoded.GetEnrollmentNetworkConfig().Subnet)
	assert.Equal(t, original.GetEnrollmentNetworkConfig().Gateway, decoded.GetEnrollmentNetworkConfig().Gateway)
	assert.Equal(t, original.GetEnrollmentNetworkConfig().DNSServers, decoded.GetEnrollmentNetworkConfig().DNSServers)

	require.NotNil(t, decoded.PlatformdConfig)
	assert.Equal(t, original.PlatformdConfig.ConfigName, decoded.PlatformdConfig.ConfigName)
	assert.Equal(t, original.PlatformdConfig.ConfigPath, decoded.PlatformdConfig.ConfigPath)
	assert.Equal(t, original.PlatformdConfig.Version, decoded.PlatformdConfig.Version)

	require.NotNil(t, decoded.MatchRules)
	assert.Equal(t, original.MatchRules.ModelPattern, decoded.MatchRules.ModelPattern)
	assert.Equal(t, original.MatchRules.TPMVendor, decoded.MatchRules.TPMVendor)
}

func TestDeviceProfile_JSONSerialization(t *testing.T) {
	vlan := 300
	original := &DeviceProfile{
		ID:    54321,
		Name:  "JSON Test Profile",
		Model: "JSONModel-3000",
		Role:  DeviceRoleEdge,
		Networks: map[string]*NetworkPhaseConfig{
			DefaultPostEnrollmentNetwork: {
				VLAN:       uint16(vlan),
				Subnet:     "172.16.0.0/16",
				Gateway:    "172.16.0.1",
				DNSServers: []string{"172.16.0.53", "172.16.0.54"},
				DHCP:       false,
				StaticIP:   "172.16.10.50",
				Zone:       "production",
			},
			DefaultFailureNetwork: {
				VLAN:       0,
				Subnet:     "192.168.99.0/24",
				Gateway:    "192.168.99.1",
				DNSServers: []string{"192.168.99.53"},
				DHCP:       true,
				Zone:       "quarantine",
			},
		},
		PlatformdConfig: &PlatformdConfigRef{
			ConfigName: "edge-config",
		},
		MatchRules: &ProfileMatchRules{
			SerialPattern: "^EDGE[0-9]{8}$",
			CustomAttributes: map[string]string{
				"location": "remote-site-1",
			},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var decoded DeviceProfile
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.ID, decoded.ID)
	assert.Equal(t, original.Name, decoded.Name)
	assert.Equal(t, original.Model, decoded.Model)
	assert.Equal(t, original.Role, decoded.Role)

	require.NotNil(t, decoded.GetPostEnrollmentNetworkConfig())

	assert.Equal(t, uint16(vlan), decoded.GetPostEnrollmentNetworkConfig().VLAN)
	assert.Equal(t, original.GetPostEnrollmentNetworkConfig().Subnet, decoded.GetPostEnrollmentNetworkConfig().Subnet)
	assert.Equal(t, original.GetPostEnrollmentNetworkConfig().StaticIP, decoded.GetPostEnrollmentNetworkConfig().StaticIP)

	require.NotNil(t, decoded.GetFailureNetworkConfig())
	assert.Equal(t, uint16(0), decoded.GetFailureNetworkConfig().VLAN)
	assert.Equal(t, original.GetFailureNetworkConfig().Subnet, decoded.GetFailureNetworkConfig().Subnet)
	assert.Equal(t, original.GetFailureNetworkConfig().Zone, decoded.GetFailureNetworkConfig().Zone)

	require.NotNil(t, decoded.PlatformdConfig)
	assert.Equal(t, original.PlatformdConfig.ConfigName, decoded.PlatformdConfig.ConfigName)

	require.NotNil(t, decoded.MatchRules)
	assert.Equal(t, original.MatchRules.SerialPattern, decoded.MatchRules.SerialPattern)
	assert.Equal(t, original.MatchRules.CustomAttributes["location"], decoded.MatchRules.CustomAttributes["location"])
}

func TestDeviceProfile_YAMLOmitEmpty(t *testing.T) {
	profile := &DeviceProfile{
		ID:    12345,
		Name:  "Minimal Profile",
		Model: "MinModel",
		Role:  DeviceRoleUnknown,
	}

	data, err := yaml.Marshal(profile)
	require.NoError(t, err)

	dataStr := string(data)
	assert.Contains(t, dataStr, "id:")
	assert.Contains(t, dataStr, "name:")
	assert.Contains(t, dataStr, "model:")
	assert.Contains(t, dataStr, "role:")
	assert.NotContains(t, dataStr, "networks:")
	assert.NotContains(t, dataStr, "platformd:")
	assert.NotContains(t, dataStr, "match-rules:")
}

func TestDeviceProfile_JSONOmitEmpty(t *testing.T) {
	profile := &DeviceProfile{
		ID:    12345,
		Name:  "Minimal Profile",
		Model: "MinModel",
		Role:  DeviceRoleWorkstation,
	}

	data, err := json.Marshal(profile)
	require.NoError(t, err)

	dataStr := string(data)
	assert.Contains(t, dataStr, `"id"`)
	assert.Contains(t, dataStr, `"name"`)
	assert.Contains(t, dataStr, `"model"`)
	assert.Contains(t, dataStr, `"role"`)
	assert.NotContains(t, dataStr, `"networks"`)
	assert.NotContains(t, dataStr, `"platformd"`)
	assert.NotContains(t, dataStr, `"match_rules"`)
}

func TestDeviceProfile_CompleteConfiguration(t *testing.T) {
	vlan1 := 100
	vlan2 := 200
	vlan3 := 999

	profile := &DeviceProfile{
		ID:       99999,
		Name:     "Complete Test Profile",
		Model:    "CompleteModel-5000",
		Role:     DeviceRoleLoadBalancer,
		EventLog: []byte("complete-event-log"),
		Networks: map[string]*NetworkPhaseConfig{
			DefaultEnrollmentNetwork: {
				VLAN:       uint16(vlan1),
				Subnet:     "10.1.0.0/16",
				Gateway:    "10.1.0.1",
				DNSServers: []string{"10.1.0.53"},
				DHCP:       true,
				Zone:       "provision",
			},
			DefaultPostEnrollmentNetwork: {
				VLAN:       uint16(vlan2),
				Subnet:     "10.2.0.0/16",
				Gateway:    "10.2.0.1",
				DNSServers: []string{"10.2.0.53", "10.2.0.54"},
				DHCP:       false,
				StaticIP:   "10.2.100.100",
				Zone:       "prod",
			},
			DefaultFailureNetwork: {
				VLAN:       uint16(vlan3),
				Subnet:     "10.99.0.0/16",
				Gateway:    "10.99.0.1",
				DNSServers: []string{"10.99.0.53"},
				DHCP:       true,
				Zone:       "quarantine",
			},
		},
		PlatformdConfig: &PlatformdConfigRef{
			ConfigName: "lb-production",
			ConfigPath: "/etc/platformd/lb-prod.yaml",
			Version:    "3.1.4",
		},
		MatchRules: &ProfileMatchRules{
			ModelPattern:      "^CompleteModel-.*$",
			SerialPattern:     "^LB[0-9]{10}$",
			ManufacturerMatch: "HPE",
			TPMVendor:         "STM",
			CustomAttributes: map[string]string{
				"environment": "production",
				"criticality": "high",
				"compliance":  "pci-dss",
			},
		},
	}

	assert.Equal(t, uint64(99999), profile.ID)
	assert.Equal(t, "Complete Test Profile", profile.Name)
	assert.Equal(t, "CompleteModel-5000", profile.Model)
	assert.Equal(t, DeviceRoleLoadBalancer, profile.Role)
	assert.Equal(t, []byte("complete-event-log"), profile.EventLog)

	require.NotNil(t, profile.GetEnrollmentNetworkConfig())
	require.NotNil(t, profile.GetPostEnrollmentNetworkConfig())
	require.NotNil(t, profile.GetFailureNetworkConfig())
	require.NotNil(t, profile.PlatformdConfig)
	require.NotNil(t, profile.MatchRules)

	assert.Equal(t, uint16(vlan1), profile.GetEnrollmentNetworkConfig().VLAN)
	assert.Equal(t, uint16(vlan2), profile.GetPostEnrollmentNetworkConfig().VLAN)
	assert.Equal(t, uint16(vlan3), profile.GetFailureNetworkConfig().VLAN)

	assert.Len(t, profile.MatchRules.CustomAttributes, 3)
	assert.Equal(t, "production", profile.MatchRules.CustomAttributes["environment"])
}

func TestNetworkPhaseConfig_EmptyConfiguration(t *testing.T) {
	config := &NetworkPhaseConfig{}

	assert.Equal(t, uint16(0), config.VLAN)
	assert.Empty(t, config.Subnet)
	assert.Empty(t, config.Gateway)
	assert.Nil(t, config.DNSServers)
	assert.False(t, config.DHCP)
	assert.Empty(t, config.StaticIP)
	assert.Empty(t, config.Zone)
}

func TestPlatformdConfigRef_EmptyConfiguration(t *testing.T) {
	config := &PlatformdConfigRef{}

	assert.Empty(t, config.ConfigName)
	assert.Empty(t, config.ConfigPath)
	assert.Empty(t, config.Version)
}

func TestProfileMatchRules_EmptyConfiguration(t *testing.T) {
	rules := &ProfileMatchRules{}

	assert.Empty(t, rules.ModelPattern)
	assert.Empty(t, rules.SerialPattern)
	assert.Empty(t, rules.ManufacturerMatch)
	assert.Empty(t, rules.TPMVendor)
	assert.Nil(t, rules.CustomAttributes)
}

func TestDeviceProfile_RoundTripYAMLWithComplexData(t *testing.T) {
	vlan := 777
	original := &DeviceProfile{
		ID:       88888,
		Name:     "RoundTrip Profile",
		Model:    "RT-2000",
		Role:     DeviceRoleIoT,
		EventLog: []byte("roundtrip-event-data"),
		Networks: map[string]*NetworkPhaseConfig{
			DefaultEnrollmentNetwork: {
				VLAN:    uint16(vlan),
				Subnet:  "192.168.100.0/24",
				Gateway: "192.168.100.1",
				DNSServers: []string{
					"192.168.100.53",
					"8.8.8.8",
				},
				DHCP: true,
				Zone: "iot-provision",
			},
		},
		PlatformdConfig: &PlatformdConfigRef{
			ConfigName: "iot-minimal",
			Version:    "0.5.0",
		},
		MatchRules: &ProfileMatchRules{
			ModelPattern: "^RT-[0-9]+$",
			TPMVendor:    "IOT",
			CustomAttributes: map[string]string{
				"sensor-type": "temperature",
			},
		},
	}

	yamlData, err := yaml.Marshal(original)
	require.NoError(t, err)

	var decoded DeviceProfile
	err = yaml.Unmarshal(yamlData, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.ID, decoded.ID)
	assert.Equal(t, original.Name, decoded.Name)
	assert.Equal(t, original.Model, decoded.Model)
	assert.Equal(t, original.Role, decoded.Role)
	assert.Equal(t, original.EventLog, decoded.EventLog)

	require.NotNil(t, decoded.GetEnrollmentNetworkConfig())
	assert.Equal(t, original.GetEnrollmentNetworkConfig().VLAN, decoded.GetEnrollmentNetworkConfig().VLAN)
	assert.Equal(t, original.GetEnrollmentNetworkConfig().DNSServers, decoded.GetEnrollmentNetworkConfig().DNSServers)

	require.NotNil(t, decoded.PlatformdConfig)
	assert.Equal(t, original.PlatformdConfig.ConfigName, decoded.PlatformdConfig.ConfigName)

	require.NotNil(t, decoded.MatchRules)
	assert.Equal(t, original.MatchRules.CustomAttributes["sensor-type"], decoded.MatchRules.CustomAttributes["sensor-type"])
}

func TestDeviceProfile_RoundTripJSONWithComplexData(t *testing.T) {
	vlan := 555
	original := &DeviceProfile{
		ID:       77777,
		Name:     "JSON RoundTrip",
		Model:    "JRT-3000",
		Role:     DeviceRoleServer,
		EventLog: []byte("json-roundtrip-event"),
		Networks: map[string]*NetworkPhaseConfig{
			DefaultPostEnrollmentNetwork: {
				VLAN:       uint16(vlan),
				Subnet:     "172.31.0.0/16",
				Gateway:    "172.31.0.1",
				DNSServers: []string{"172.31.0.53"},
				DHCP:       false,
				StaticIP:   "172.31.50.100",
				Zone:       "secure-prod",
			},
		},
		PlatformdConfig: &PlatformdConfigRef{
			ConfigName: "server-high-security",
			ConfigPath: "/etc/platformd/hs-server.yaml",
			Version:    "2.5.1",
		},
		MatchRules: &ProfileMatchRules{
			ModelPattern:      "^JRT-.*$",
			SerialPattern:     "^HS[0-9]{12}$",
			ManufacturerMatch: "SecureSystems",
			TPMVendor:         "SEC",
			CustomAttributes: map[string]string{
				"security-level": "high",
				"compliance":     "fedramp",
			},
		},
	}

	jsonData, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded DeviceProfile
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.ID, decoded.ID)
	assert.Equal(t, original.Name, decoded.Name)
	assert.Equal(t, original.Model, decoded.Model)
	assert.Equal(t, original.Role, decoded.Role)
	assert.Equal(t, original.EventLog, decoded.EventLog)

	require.NotNil(t, decoded.GetPostEnrollmentNetworkConfig())
	assert.Equal(t, original.GetPostEnrollmentNetworkConfig().VLAN, decoded.GetPostEnrollmentNetworkConfig().VLAN)
	assert.Equal(t, original.GetPostEnrollmentNetworkConfig().StaticIP, decoded.GetPostEnrollmentNetworkConfig().StaticIP)

	require.NotNil(t, decoded.PlatformdConfig)
	assert.Equal(t, original.PlatformdConfig.ConfigPath, decoded.PlatformdConfig.ConfigPath)

	require.NotNil(t, decoded.MatchRules)
	assert.Equal(t, original.MatchRules.ManufacturerMatch, decoded.MatchRules.ManufacturerMatch)
	assert.Equal(t, original.MatchRules.CustomAttributes["security-level"], decoded.MatchRules.CustomAttributes["security-level"])
}
func TestDeviceRole_String(t *testing.T) {
	tests := []struct {
		name string
		role DeviceRole
		want string
	}{
		{
			name: "server role",
			role: DeviceRoleServer,
			want: "server",
		},
		{
			name: "client role",
			role: DeviceRoleClient,
			want: "client",
		},
		{
			name: "gateway role",
			role: DeviceRoleGateway,
			want: "gateway",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.role.String())
		})
	}
}

func TestDeviceRole_IsValid(t *testing.T) {
	tests := []struct {
		name string
		role DeviceRole
		want bool
	}{
		{
			name: "valid server role",
			role: DeviceRoleServer,
			want: true,
		},
		{
			name: "valid client role",
			role: DeviceRoleClient,
			want: true,
		},
		{
			name: "valid gateway role",
			role: DeviceRoleGateway,
			want: true,
		},
		{name: "valid workstation role", role: DeviceRoleWorkstation, want: true},
		{name: "valid edge role", role: DeviceRoleEdge, want: true},
		{name: "valid iot role", role: DeviceRoleIoT, want: true},
		{name: "valid load-balancer role", role: DeviceRoleLoadBalancer, want: true},
		{name: "valid unknown role", role: DeviceRoleUnknown, want: true},
		{
			name: "invalid role",
			role: DeviceRole("invalid"),
			want: false,
		},
		{
			name: "empty role",
			role: DeviceRole(""),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.role.IsValid())
		})
	}
}

func TestAuthMethod_String(t *testing.T) {
	tests := []struct {
		name   string
		method AuthMethod
		want   string
	}{
		{
			name:   "none auth method",
			method: AuthMethodNone,
			want:   "none",
		},
		{
			name:   "802.1x auth method",
			method: AuthMethod802_1X,
			want:   "802.1x",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.method.String())
		})
	}
}

func TestAuthMethod_IsValid(t *testing.T) {
	tests := []struct {
		name   string
		method AuthMethod
		want   bool
	}{
		{
			name:   "valid none method",
			method: AuthMethodNone,
			want:   true,
		},
		{
			name:   "valid 802.1x method",
			method: AuthMethod802_1X,
			want:   true,
		},
		{
			name:   "invalid method",
			method: AuthMethod("invalid"),
			want:   false,
		},
		{
			name:   "empty method",
			method: AuthMethod(""),
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.method.IsValid())
		})
	}
}

func TestACLConfig_IsValid(t *testing.T) {
	tests := []struct {
		name string
		acl  *ACLConfig
		want bool
	}{
		{
			name: "valid TCP ACL",
			acl: &ACLConfig{
				Priority: 100,
				Protocol: "tcp",
				SrcIP:    "192.168.1.0/24",
				DstIP:    "10.0.0.1",
				SrcPort:  0,
				DstPort:  443,
				Action:   "allow",
			},
			want: true,
		},
		{
			name: "valid UDP ACL",
			acl: &ACLConfig{
				Priority: 200,
				Protocol: "udp",
				SrcIP:    "0.0.0.0/0",
				DstIP:    "192.168.1.1",
				DstPort:  53,
				Action:   "allow",
			},
			want: true,
		},
		{
			name: "valid ICMP ACL",
			acl: &ACLConfig{
				Priority: 50,
				Protocol: "icmp",
				SrcIP:    "192.168.1.0/24",
				DstIP:    "0.0.0.0/0",
				Action:   "allow",
			},
			want: true,
		},
		{
			name: "valid any protocol ACL",
			acl: &ACLConfig{
				Priority: 1000,
				Protocol: "any",
				SrcIP:    "0.0.0.0/0",
				DstIP:    "0.0.0.0/0",
				Action:   "deny",
			},
			want: true,
		},
		{
			name: "invalid protocol",
			acl: &ACLConfig{
				Priority: 100,
				Protocol: "invalid",
				SrcIP:    "192.168.1.0/24",
				DstIP:    "10.0.0.1",
				Action:   "allow",
			},
			want: false,
		},
		{
			name: "invalid action",
			acl: &ACLConfig{
				Priority: 100,
				Protocol: "tcp",
				SrcIP:    "192.168.1.0/24",
				DstIP:    "10.0.0.1",
				Action:   "invalid",
			},
			want: false,
		},
		{
			name: "nil ACL",
			acl:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.acl.IsValid())
		})
	}
}

func TestPlatformdConfigRef_IsValid(t *testing.T) {
	tests := []struct {
		name   string
		config *PlatformdConfigRef
		want   bool
	}{
		{
			name: "valid inline config",
			config: &PlatformdConfigRef{
				ConfigType: "inline",
				Inline:     map[string]interface{}{"key": "value"},
			},
			want: true,
		},
		{
			name: "valid reference config",
			config: &PlatformdConfigRef{
				ConfigType: "reference",
				Reference:  "/path/to/config.yaml",
			},
			want: true,
		},
		{
			name: "legacy config with ConfigName",
			config: &PlatformdConfigRef{
				ConfigName: "legacy-config",
			},
			want: true,
		},
		{
			name: "legacy config with ConfigPath",
			config: &PlatformdConfigRef{
				ConfigPath: "/path/to/legacy.yaml",
			},
			want: true,
		},
		{
			name: "invalid config type",
			config: &PlatformdConfigRef{
				ConfigType: "invalid",
			},
			want: false,
		},
		{
			name: "inline config without data",
			config: &PlatformdConfigRef{
				ConfigType: "inline",
			},
			want: false,
		},
		{
			name: "reference config without path",
			config: &PlatformdConfigRef{
				ConfigType: "reference",
			},
			want: false,
		},
		{
			name:   "nil config",
			config: nil,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.config.IsValid())
		})
	}
}

func TestProfileMatchRules_IsEmpty(t *testing.T) {
	tests := []struct {
		name  string
		rules *ProfileMatchRules
		want  bool
	}{
		{
			name:  "empty rules",
			rules: &ProfileMatchRules{},
			want:  true,
		},
		{
			name: "rules with MAC prefix",
			rules: &ProfileMatchRules{
				MACPrefix: "52:54:00",
			},
			want: false,
		},
		{
			name: "rules with serial prefix",
			rules: &ProfileMatchRules{
				SerialPrefix: "SN-",
			},
			want: false,
		},
		{
			name: "rules with model",
			rules: &ProfileMatchRules{
				Model: "Server-X1000",
			},
			want: false,
		},
		{
			name: "rules with legacy ModelPattern",
			rules: &ProfileMatchRules{
				ModelPattern: "^Server.*$",
			},
			want: false,
		},
		{
			name:  "nil rules",
			rules: nil,
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.rules.IsEmpty())
		})
	}
}

func TestProfileMatchRules_Matches(t *testing.T) {
	tests := []struct {
		name    string
		rules   *ProfileMatchRules
		macAddr string
		serial  string
		model   string
		want    bool
	}{
		{
			name: "matches MAC prefix",
			rules: &ProfileMatchRules{
				MACPrefix: "52:54:00",
			},
			macAddr: "52:54:00:12:34:56",
			serial:  "SN-123",
			model:   "Server-X1000",
			want:    true,
		},
		{
			name: "matches serial prefix",
			rules: &ProfileMatchRules{
				SerialPrefix: "SN-",
			},
			macAddr: "52:54:00:12:34:56",
			serial:  "SN-123",
			model:   "Server-X1000",
			want:    true,
		},
		{
			name: "matches model",
			rules: &ProfileMatchRules{
				Model: "Server-X1000",
			},
			macAddr: "52:54:00:12:34:56",
			serial:  "SN-123",
			model:   "Server-X1000",
			want:    true,
		},
		{
			name: "matches multiple rules",
			rules: &ProfileMatchRules{
				MACPrefix:    "52:54:00",
				SerialPrefix: "SN-",
				Model:        "Server-X1000",
			},
			macAddr: "52:54:00:12:34:56",
			serial:  "SN-123",
			model:   "Server-X1000",
			want:    true,
		},
		{
			name: "matches legacy ModelPattern",
			rules: &ProfileMatchRules{
				ModelPattern: "Server-X1000",
			},
			macAddr: "52:54:00:12:34:56",
			serial:  "SN-123",
			model:   "Server-X1000",
			want:    true,
		},
		{
			name: "matches legacy SerialPattern",
			rules: &ProfileMatchRules{
				SerialPattern: "SN-",
			},
			macAddr: "52:54:00:12:34:56",
			serial:  "SN-123",
			model:   "Server-X1000",
			want:    true,
		},
		{
			name: "does not match MAC prefix",
			rules: &ProfileMatchRules{
				MACPrefix: "52:54:00",
			},
			macAddr: "aa:bb:cc:12:34:56",
			serial:  "SN-123",
			model:   "Server-X1000",
			want:    false,
		},
		{
			name: "does not match serial prefix",
			rules: &ProfileMatchRules{
				SerialPrefix: "SN-",
			},
			macAddr: "52:54:00:12:34:56",
			serial:  "XYZ-123",
			model:   "Server-X1000",
			want:    false,
		},
		{
			name: "does not match model",
			rules: &ProfileMatchRules{
				Model: "Server-X1000",
			},
			macAddr: "52:54:00:12:34:56",
			serial:  "SN-123",
			model:   "Client-Y2000",
			want:    false,
		},
		{
			name:    "empty rules do not match",
			rules:   &ProfileMatchRules{},
			macAddr: "52:54:00:12:34:56",
			serial:  "SN-123",
			model:   "Server-X1000",
			want:    false,
		},
		{
			name:    "nil rules do not match",
			rules:   nil,
			macAddr: "52:54:00:12:34:56",
			serial:  "SN-123",
			model:   "Server-X1000",
			want:    false,
		},
		{
			name: "partial match MAC only",
			rules: &ProfileMatchRules{
				MACPrefix:    "52:54:00",
				SerialPrefix: "XYZ-",
			},
			macAddr: "52:54:00:12:34:56",
			serial:  "SN-123",
			model:   "Server-X1000",
			want:    true,
		},
		{
			name: "partial match serial only",
			rules: &ProfileMatchRules{
				MACPrefix:    "aa:bb:cc",
				SerialPrefix: "SN-",
			},
			macAddr: "52:54:00:12:34:56",
			serial:  "SN-123",
			model:   "Server-X1000",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.rules.Matches(tt.macAddr, tt.serial, tt.model))
		})
	}
}

func TestDHCPPoolConfig_JSON(t *testing.T) {
	tests := []struct {
		name    string
		config  *DHCPPoolConfig
		wantErr bool
	}{
		{
			name: "valid DHCP pool config",
			config: &DHCPPoolConfig{
				Network:    "192.168.1.0/24",
				RangeStart: "192.168.1.100",
				RangeEnd:   "192.168.1.200",
				LeaseTime:  3600,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			var decoded DHCPPoolConfig
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.config.Network, decoded.Network)
			assert.Equal(t, tt.config.RangeStart, decoded.RangeStart)
			assert.Equal(t, tt.config.RangeEnd, decoded.RangeEnd)
			assert.Equal(t, tt.config.LeaseTime, decoded.LeaseTime)
		})
	}
}

func TestNetworkPhaseConfig_NewFields_YAML(t *testing.T) {
	tests := []struct {
		name    string
		config  *NetworkPhaseConfig
		wantErr bool
	}{
		{
			name: "valid network phase config with new fields",
			config: &NetworkPhaseConfig{
				VLAN: 100,
				DHCPPool: &DHCPPoolConfig{
					Network:    "192.168.1.0/24",
					RangeStart: "192.168.1.100",
					RangeEnd:   "192.168.1.200",
					LeaseTime:  3600,
				},
				Gateway:    "192.168.1.1",
				DNS:        []string{"8.8.8.8", "8.8.4.4"},
				AuthMethod: AuthMethodNone,
				ACLs: []ACLConfig{
					{
						Priority: 100,
						Protocol: "tcp",
						SrcIP:    "192.168.1.0/24",
						DstIP:    "0.0.0.0/0",
						DstPort:  443,
						Action:   "allow",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "config with static IP and 802.1X auth",
			config: &NetworkPhaseConfig{
				VLAN:       200,
				StaticIP:   "10.0.0.5/24",
				Gateway:    "10.0.0.1",
				DNS:        []string{"1.1.1.1"},
				AuthMethod: AuthMethod802_1X,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := yaml.Marshal(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("yaml.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			var decoded NetworkPhaseConfig
			err = yaml.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.config.VLAN, decoded.VLAN)
			assert.Equal(t, tt.config.Gateway, decoded.Gateway)
			assert.Equal(t, tt.config.AuthMethod, decoded.AuthMethod)
		})
	}
}

func TestACLConfig_JSON_Serialization(t *testing.T) {
	tests := []struct {
		name    string
		acl     *ACLConfig
		wantErr bool
	}{
		{
			name: "valid ACL with all fields",
			acl: &ACLConfig{
				Priority: 100,
				Protocol: "tcp",
				SrcIP:    "192.168.1.0/24",
				DstIP:    "10.0.0.1",
				SrcPort:  8080,
				DstPort:  443,
				Action:   "allow",
			},
			wantErr: false,
		},
		{
			name: "ACL without ports",
			acl: &ACLConfig{
				Priority: 50,
				Protocol: "icmp",
				SrcIP:    "0.0.0.0/0",
				DstIP:    "192.168.1.0/24",
				Action:   "deny",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.acl)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			var decoded ACLConfig
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.acl.Priority, decoded.Priority)
			assert.Equal(t, tt.acl.Protocol, decoded.Protocol)
			assert.Equal(t, tt.acl.Action, decoded.Action)
		})
	}
}

func TestPlatformdConfigRef_NewFields_JSON(t *testing.T) {
	tests := []struct {
		name    string
		config  *PlatformdConfigRef
		wantErr bool
	}{
		{
			name: "inline config",
			config: &PlatformdConfigRef{
				ConfigType: "inline",
				Inline:     map[string]interface{}{"server": "localhost", "port": 8080},
			},
			wantErr: false,
		},
		{
			name: "reference config",
			config: &PlatformdConfigRef{
				ConfigType: "reference",
				Reference:  "/etc/platformd/config.yaml",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("json.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			var decoded PlatformdConfigRef
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.config.ConfigType, decoded.ConfigType)
		})
	}
}

func TestProfileMatchRules_NewFields_YAML(t *testing.T) {
	tests := []struct {
		name    string
		rules   *ProfileMatchRules
		wantErr bool
	}{
		{
			name: "new-style fields populated",
			rules: &ProfileMatchRules{
				MACPrefix:    "52:54:00",
				SerialPrefix: "SN-",
				Model:        "Server-X1000",
			},
			wantErr: false,
		},
		{
			name: "legacy fields populated",
			rules: &ProfileMatchRules{
				ModelPattern:  "^Server.*$",
				SerialPattern: "^SN-.*$",
			},
			wantErr: false,
		},
		{
			name: "mixed new and legacy fields",
			rules: &ProfileMatchRules{
				MACPrefix:     "52:54:00",
				ModelPattern:  "^Server.*$",
				SerialPattern: "^SN-.*$",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := yaml.Marshal(tt.rules)
			if (err != nil) != tt.wantErr {
				t.Errorf("yaml.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			var decoded ProfileMatchRules
			err = yaml.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.rules.MACPrefix, decoded.MACPrefix)
			assert.Equal(t, tt.rules.SerialPrefix, decoded.SerialPrefix)
			assert.Equal(t, tt.rules.Model, decoded.Model)
		})
	}
}

// TestParseDeviceRole_BootstrapVocabulary verifies the three role strings the
// bootstrap configuration assigns to nodes resolve to first-class roles, and
// that aliases and case are normalised to the canonical value.
func TestParseDeviceRole_BootstrapVocabulary(t *testing.T) {
	tests := []struct {
		in   string
		want DeviceRole
	}{
		{in: "control-plane", want: DeviceRoleControlPlane},
		{in: "gateway", want: DeviceRoleGateway},
		{in: "worker", want: DeviceRoleWorker},
		{in: "Control-Plane", want: DeviceRoleControlPlane},
		{in: "loadbalancer", want: DeviceRoleLoadBalancer},
		{in: "load-balancer", want: DeviceRoleLoadBalancer},
		{in: "server", want: DeviceRoleServer},
		{in: "unknown", want: DeviceRoleUnknown},
		{in: "", want: DeviceRoleUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseDeviceRole(tt.in)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.True(t, got.IsValid())
		})
	}
}

// TestParseDeviceRole_Unknown verifies a role string outside the vocabulary
// is a typed error rather than a silent DeviceRoleUnknown.
func TestParseDeviceRole_Unknown(t *testing.T) {
	for _, in := range []string{"compute", "master", "control_plane", " worker"} {
		t.Run(in, func(t *testing.T) {
			got, err := ParseDeviceRole(in)
			var unknown ErrUnknownDeviceRole
			require.ErrorAs(t, err, &unknown)
			assert.Equal(t, in, unknown.Role)
			assert.Contains(t, err.Error(), in)
			assert.Equal(t, DeviceRoleUnknown, got)
		})
	}
}

// TestDeviceRole_IsValid_AliasIsNotCanonical verifies an alias spelling is
// accepted by the parser but is not itself a valid stored value.
func TestDeviceRole_IsValid_AliasIsNotCanonical(t *testing.T) {
	assert.False(t, DeviceRole("loadbalancer").IsValid())
	assert.False(t, DeviceRole("Worker").IsValid())
	assert.True(t, DeviceRoleControlPlane.IsValid())
	assert.True(t, DeviceRoleWorker.IsValid())
}

// TestDeviceRole_PortClass pins the role → port-class mapping: gateways get
// the gateway trunk, control-plane and worker nodes the hypervisor trunk.
func TestDeviceRole_PortClass(t *testing.T) {
	cases := map[DeviceRole]zone.PortClass{
		DeviceRoleGateway:      zone.PortClassGateway,
		DeviceRoleControlPlane: zone.PortClassHypervisor,
		DeviceRoleWorker:       zone.PortClassHypervisor,
	}
	for role, want := range cases {
		got, err := role.PortClass()
		if err != nil || got != want {
			t.Errorf("%s.PortClass() = %q, %v; want %q", role, got, err, want)
		}
	}
}

// TestDeviceRole_PortClass_FailsClosed refuses every role without a class.
func TestDeviceRole_PortClass_FailsClosed(t *testing.T) {
	for _, role := range []DeviceRole{DeviceRoleUnknown, DeviceRoleServer, DeviceRoleClient, DeviceRoleWorkstation, DeviceRoleEdge, DeviceRoleIoT, DeviceRoleLoadBalancer, ""} {
		_, err := role.PortClass()
		var target ErrNoPortClassForRole
		if !errors.As(err, &target) || target.Role != role {
			t.Errorf("%q: want ErrNoPortClassForRole, got %v", role, err)
		}
	}
	if msg := (ErrNoPortClassForRole{Role: DeviceRoleIoT}).Error(); !strings.Contains(msg, `"iot"`) {
		t.Errorf("message %q", msg)
	}
}
